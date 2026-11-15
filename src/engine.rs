//! Klien DNS upstream: DoQ (RFC 9250), DoH3, dan DoH/2 sebagai fallback.
//!
//! Semua koneksi selalu diarahkan ke IP bootstrap yang di-hardcode, sementara
//! SNI tetap nama host resolver. Dengan begitu tidak ada resolusi DNS yang
//! dibutuhkan untuk menghubungi resolver — penting karena adapter sudah
//! menunjuk ke proxy kita sendiri.

use crate::providers::{Proto, Provider};
use bytes::{Buf, Bytes};
use rustls::pki_types::ServerName;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc, oneshot};

const CONNECT_TIMEOUT: Duration = Duration::from_millis(2500);
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
/// Setelah protokol gagal dua kali, ia dilewati selama ini sebelum dicoba lagi.
const FAILURE_COOLDOWN: Duration = Duration::from_secs(60);
const MAX_MESSAGE: usize = 65_535;

fn tls_config(alpn: &[&str]) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
    Arc::new(cfg)
}

fn quic_client_config(alpn: &str) -> Result<quinn::ClientConfig, String> {
    let idle: quinn::IdleTimeout = Duration::from_secs(25)
        .try_into()
        .map_err(|_| "idle timeout tidak valid".to_string())?;
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(idle));
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from((*tls_config(&[alpn])).clone())
        .map_err(|e| format!("konfigurasi TLS: {e}"))?;
    let mut cfg = quinn::ClientConfig::new(Arc::new(crypto));
    cfg.transport_config(Arc::new(transport));
    Ok(cfg)
}

fn url_host(url: &str) -> &str {
    let rest = url.split("://").nth(1).unwrap_or(url);
    rest.split('/').next().unwrap_or(rest)
}

fn boots(prov: &Provider, port: u16) -> Vec<SocketAddr> {
    prov.boot
        .iter()
        .filter_map(|ip| ip.parse::<std::net::IpAddr>().ok())
        .map(|ip| SocketAddr::new(ip, port))
        .collect()
}

/// Satu pekerjaan untuk worker HTTP/3 (yang memiliki koneksi + driver-nya).
type Job = (Vec<u8>, oneshot::Sender<Result<Vec<u8>, String>>);

pub struct Engine {
    ep: quinn::Endpoint,
    prov: &'static Provider,
    doq: Mutex<Option<quinn::Connection>>,
    h3: Mutex<Option<mpsc::Sender<Job>>>,
    h2: Mutex<Option<h2::client::SendRequest<Bytes>>>,
    preferred: std::sync::Mutex<Option<Proto>>,
    /// Berapa kali sebuah protokol gagal berturut-turut dan kapan terakhir.
    /// Setelah dua kali, protokol itu dilewati sementara supaya fallback tidak
    /// membuang waktu tiap query.
    failures: Mutex<HashMap<Proto, (u8, Instant)>>,
}

impl Engine {
    pub fn new(prov: &'static Provider) -> Result<Arc<Self>, String> {
        let ep = quinn::Endpoint::client(SocketAddr::from(([0u8, 0, 0, 0], 0)))
            .map_err(|e| format!("tidak bisa membuka socket QUIC: {e}"))?;
        Ok(Arc::new(Self {
            ep,
            prov,
            doq: Mutex::new(None),
            h3: Mutex::new(None),
            h2: Mutex::new(None),
            preferred: std::sync::Mutex::new(None),
            failures: Mutex::new(HashMap::new()),
        }))
    }

    /// Kirim satu query dan kembalikan (respons, protokol yang dipakai).
    /// Urutan percobaan: protokol yang terakhir berhasil, lalu DoQ → DoH3 → DoH2.
    pub async fn resolve(&self, query: &[u8]) -> Result<(Vec<u8>, Proto), String> {
        let mut order = self.prov.protos();
        {
            let failures = self.failures.lock().await;
            let filtered: Vec<Proto> = order
                .iter()
                .copied()
                .filter(|p| match failures.get(p) {
                    // Dilewati hanya sementara: gangguan jaringan sesaat tidak
                    // boleh mematikan DoQ untuk seluruh sesi.
                    Some((count, when)) => *count < 2 || when.elapsed() > FAILURE_COOLDOWN,
                    None => true,
                })
                .collect();
            if !filtered.is_empty() {
                order = filtered;
            }
        }
        if let Ok(guard) = self.preferred.lock()
            && let Some(last) = *guard
            && let Some(pos) = order.iter().position(|p| *p == last)
        {
            let p = order.remove(pos);
            order.insert(0, p);
        }
        if order.is_empty() {
            return Err("provider tidak punya protokol yang didukung".to_string());
        }

        let mut errors = Vec::new();
        for proto in order {
            match self.query_proto(proto, query).await {
                Ok(resp) if resp.len() >= 12 => {
                    if let Ok(mut guard) = self.preferred.lock() {
                        *guard = Some(proto);
                    }
                    self.failures.lock().await.remove(&proto);
                    return Ok((resp, proto));
                }
                // Respons kosong dan error diperlakukan sama: protokol dicatat
                // gagal, lalu query lanjut ke protokol berikutnya.
                Ok(_) => {
                    self.note_failure(proto).await;
                    errors.push(format!("{}: respons kosong", proto.label()));
                }
                Err(e) => {
                    self.note_failure(proto).await;
                    errors.push(format!("{}: {e}", proto.label()));
                }
            }
        }
        Err(errors.join("; "))
    }

    pub async fn query_proto(&self, proto: Proto, query: &[u8]) -> Result<Vec<u8>, String> {
        match proto {
            Proto::DoQ => self.doq_query(query).await,
            Proto::DoH3 => self.doh3_query(query).await,
            Proto::DoH2 => self.doh2_query(query).await,
        }
    }

    /// Putuskan koneksi protokol ini dan catat kegagalannya.
    /// Hitungannya dijenuhkan (bukan `+= 1`) supaya protokol yang gagal terus-
    /// menerus — mis. QUIC diblokir jaringan — tidak pernah mengalami overflow.
    async fn note_failure(&self, proto: Proto) {
        self.invalidate(proto).await;
        let mut failures = self.failures.lock().await;
        let entry = failures.entry(proto).or_insert((0, Instant::now()));
        entry.0 = entry.0.saturating_add(1);
        entry.1 = Instant::now();
    }

    async fn invalidate(&self, proto: Proto) {
        match proto {
            Proto::DoQ => {
                *self.doq.lock().await = None;
            }
            Proto::DoH3 => {
                // Menjatuhkan sender membuat worker melihat channel tertutup lalu keluar.
                let _ = self.h3.lock().await.take();
            }
            Proto::DoH2 => {
                *self.h2.lock().await = None;
            }
        }
    }

    // ---------- DoQ ----------

    async fn doq_conn(&self) -> Result<quinn::Connection, String> {
        let mut guard = self.doq.lock().await;
        if let Some(conn) = guard.as_ref()
            && conn.close_reason().is_none()
        {
            return Ok(conn.clone());
        }
        let (host, port) = self
            .prov
            .doq
            .ok_or_else(|| "provider tidak mendukung DoQ".to_string())?;
        let cfg = quic_client_config("doq")?;
        let mut last = String::from("tidak ada IP bootstrap");
        for addr in boots(self.prov, port) {
            let connecting = match self.ep.connect_with(cfg.clone(), addr, host) {
                Ok(c) => c,
                Err(e) => {
                    last = format!("{addr}: {e}");
                    continue;
                }
            };
            match tokio::time::timeout(CONNECT_TIMEOUT, connecting).await {
                Ok(Ok(conn)) => {
                    *guard = Some(conn.clone());
                    return Ok(conn);
                }
                Ok(Err(e)) => last = format!("{addr}: {e}"),
                Err(_) => last = format!("{addr}: timeout handshake"),
            }
        }
        Err(format!("DoQ {host}: {last}"))
    }

    async fn doq_query(&self, query: &[u8]) -> Result<Vec<u8>, String> {
        let conn = self.doq_conn().await?;
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| format!("buka stream: {e}"))?;

        let mut framed = Vec::with_capacity(query.len() + 2);
        framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
        framed.extend_from_slice(query);
        send.write_all(&framed)
            .await
            .map_err(|e| format!("kirim: {e}"))?;
        let _ = send.finish();

        let raw = tokio::time::timeout(QUERY_TIMEOUT, recv.read_to_end(MAX_MESSAGE))
            .await
            .map_err(|_| "timeout".to_string())?
            .map_err(|e| format!("baca: {e}"))?;
        if raw.len() < 2 {
            return Err("respons terlalu pendek".to_string());
        }
        let len = u16::from_be_bytes([raw[0], raw[1]]) as usize;
        if raw.len() < 2 + len {
            return Err("respons terpotong".to_string());
        }
        Ok(raw[2..2 + len].to_vec())
    }

    // ---------- DoH3 ----------

    async fn h3_sender(&self) -> Result<mpsc::Sender<Job>, String> {
        let mut guard = self.h3.lock().await;
        if let Some(tx) = guard.as_ref()
            && !tx.is_closed()
        {
            return Ok(tx.clone());
        }
        let (tx, rx) = mpsc::channel::<Job>(64);
        let ep = self.ep.clone();
        let prov = self.prov;
        let cfg = quic_client_config("h3")?;
        tokio::spawn(async move { h3_worker(ep, cfg, prov, rx).await });
        *guard = Some(tx.clone());
        Ok(tx)
    }

    async fn doh3_query(&self, query: &[u8]) -> Result<Vec<u8>, String> {
        let tx = self.h3_sender().await?;
        let (otx, orx) = oneshot::channel();
        tx.send((query.to_vec(), otx))
            .await
            .map_err(|_| "worker HTTP/3 tidak berjalan".to_string())?;
        match tokio::time::timeout(QUERY_TIMEOUT, orx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err("worker HTTP/3 berhenti".to_string()),
            Err(_) => Err("timeout".to_string()),
        }
    }

    // ---------- DoH/2 ----------

    async fn h2_connect(&self) -> Result<h2::client::SendRequest<Bytes>, String> {
        let url = self
            .prov
            .doh
            .ok_or_else(|| "provider tidak punya endpoint DoH".to_string())?;
        let host = url_host(url).to_string();
        let connector = tokio_rustls::TlsConnector::from(tls_config(&["h2"]));
        let mut last = String::from("tidak ada IP bootstrap");

        for addr in boots(self.prov, 443) {
            let tcp = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    last = format!("{addr}: {e}");
                    continue;
                }
                Err(_) => {
                    last = format!("{addr}: timeout TCP");
                    continue;
                }
            };
            let name = ServerName::try_from(host.clone())
                .map_err(|_| format!("nama server tidak valid: {host}"))?;
            let stream =
                match tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(name, tcp)).await {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        last = format!("{addr}: TLS {e}");
                        continue;
                    }
                    Err(_) => {
                        last = format!("{addr}: timeout TLS");
                        continue;
                    }
                };
            let (send, conn) = tokio::time::timeout(CONNECT_TIMEOUT, h2::client::handshake(stream))
                .await
                .map_err(|_| "timeout handshake HTTP/2".to_string())?
                .map_err(|e| format!("HTTP/2 {e}"))?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            return Ok(send);
        }
        Err(format!("DoH {host}: {last}"))
    }

    async fn doh2_query(&self, query: &[u8]) -> Result<Vec<u8>, String> {
        let mut guard = self.h2.lock().await;
        if guard.is_none() {
            *guard = Some(self.h2_connect().await?);
        }
        let url = self
            .prov
            .doh
            .ok_or_else(|| "provider tidak punya endpoint DoH".to_string())?;
        let send = guard.as_mut().expect("baru saja diisi");

        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri(url)
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .header("content-length", query.len().to_string())
            .body(())
            .map_err(|e| format!("request: {e}"))?;

        let (future, mut body) = match send.send_request(req, false) {
            Ok(v) => v,
            Err(e) => {
                *guard = None;
                return Err(format!("kirim HTTP/2: {e}"));
            }
        };
        body.send_data(Bytes::copy_from_slice(query), true)
            .map_err(|e| format!("body: {e}"))?;

        let response = match tokio::time::timeout(QUERY_TIMEOUT, future).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                *guard = None;
                return Err(format!("respons HTTP/2: {e}"));
            }
            Err(_) => {
                *guard = None;
                return Err("timeout".to_string());
            }
        };
        if !response.status().is_success() {
            return Err(format!("HTTP {}", response.status().as_u16()));
        }
        let mut recv = response.into_body();
        let mut out = Vec::new();
        while let Some(chunk) = recv.data().await {
            let mut chunk = chunk.map_err(|e| format!("baca body: {e}"))?;
            let n = chunk.remaining();
            out.extend_from_slice(&chunk.copy_to_bytes(n));
            if out.len() > MAX_MESSAGE {
                break;
            }
        }
        Ok(out)
    }

    /// Ukur latensi satu protokol (dipakai `mydns test`).
    pub async fn bench(
        &self,
        proto: Proto,
        query: &[u8],
        rounds: usize,
    ) -> Result<(u128, String), String> {
        let mut best = u128::MAX;
        let mut summary = String::new();
        for _ in 0..rounds.max(1) {
            let started = Instant::now();
            let resp = self.query_proto(proto, query).await?;
            best = best.min(started.elapsed().as_millis());
            summary = crate::engine::describe(&resp);
        }
        Ok((best, summary))
    }
}

/// Ringkas bagian penting dari respons DNS untuk ditampilkan ke pengguna.
pub fn describe(resp: &[u8]) -> String {
    use hickory_proto::op::Message;
    let Ok(msg) = Message::from_vec(resp) else {
        return "respons tidak bisa diparse".to_string();
    };
    let first = msg
        .answers
        .first()
        .map(|r| format!("{} ttl={}", r.data, r.ttl))
        .unwrap_or_else(|| "tanpa jawaban".to_string());
    format!(
        "{} jawaban, {:?}, {}",
        msg.answers.len(),
        msg.metadata.response_code,
        first
    )
}

pub fn build_query(domain: &str) -> Vec<u8> {
    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::{Name, RecordType};
    let mut msg = Message::query();
    // Resolver publik menolak query tanpa bit RD (recursion desired).
    msg.metadata.recursion_desired = true;
    if let Ok(name) = Name::from_ascii(domain) {
        msg.add_query(Query::query(name, RecordType::A));
    }
    msg.to_vec().unwrap_or_default()
}

// ---------- worker HTTP/3 ----------

async fn h3_worker(
    ep: quinn::Endpoint,
    cfg: quinn::ClientConfig,
    prov: &'static Provider,
    mut rx: mpsc::Receiver<Job>,
) {
    let Some(url) = prov.doh else {
        drain(&mut rx, "provider tidak mendukung DoH").await;
        return;
    };
    let host = url_host(url).to_string();

    let mut connection = None;
    let mut last = String::from("tidak ada IP bootstrap");
    for addr in boots(prov, 443) {
        let Ok(connecting) = ep.connect_with(cfg.clone(), addr, &host) else {
            continue;
        };
        match tokio::time::timeout(CONNECT_TIMEOUT, connecting).await {
            Ok(Ok(conn)) => {
                connection = Some(conn);
                break;
            }
            Ok(Err(e)) => last = format!("{addr}: {e}"),
            Err(_) => last = format!("{addr}: timeout handshake"),
        }
    }
    let Some(conn) = connection else {
        drain(&mut rx, &format!("DoH3 {host}: {last}")).await;
        return;
    };

    let (mut driver, mut send) = match h3::client::new(h3_quinn::Connection::new(conn)).await {
        Ok(pair) => pair,
        Err(e) => {
            drain(&mut rx, &format!("DoH3 handshake HTTP/3: {e}")).await;
            return;
        }
    };

    // Driver wajib dipoll terus-menerus; tanpa ini koneksi HTTP/3 tidak jalan.
    tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    });

    while let Some((query, reply)) = rx.recv().await {
        let result = h3_roundtrip(&mut send, url, Bytes::from(query)).await;
        let failed = result.is_err();
        let _ = reply.send(result);
        if failed {
            break;
        }
    }
}

async fn drain(rx: &mut mpsc::Receiver<Job>, reason: &str) {
    while let Some((_, reply)) = rx.recv().await {
        let _ = reply.send(Err(reason.to_string()));
    }
}

async fn h3_roundtrip<O>(
    send: &mut h3::client::SendRequest<O, Bytes>,
    url: &str,
    body: Bytes,
) -> Result<Vec<u8>, String>
where
    O: h3::quic::OpenStreams<Bytes>,
{
    let req = http::Request::builder()
        .method(http::Method::POST)
        .uri(url)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .header("content-length", body.len().to_string())
        .body(())
        .map_err(|e| format!("request: {e}"))?;

    let mut stream = send
        .send_request(req)
        .await
        .map_err(|e| format!("buka stream: {e}"))?;
    stream
        .send_data(body)
        .await
        .map_err(|e| format!("kirim: {e}"))?;
    stream.finish().await.map_err(|e| format!("finish: {e}"))?;

    let response = stream
        .recv_response()
        .await
        .map_err(|e| format!("respons: {e}"))?;
    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status().as_u16()));
    }

    let mut out = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.map_err(|e| format!("baca: {e}"))? {
        let n = chunk.remaining();
        out.extend_from_slice(&chunk.copy_to_bytes(n));
        if out.len() > MAX_MESSAGE {
            break;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_query_meminta_rekursi() {
        let query = build_query("example.com");
        assert_eq!(query[2] & 0x01, 0x01, "bit RD wajib diset");
        assert_eq!(&query[4..6], &[0x00, 0x01], "QDCOUNT harus 1");
    }

    #[test]
    fn url_host_mengambil_nama_host() {
        assert_eq!(url_host("https://dns.quad9.net/dns-query"), "dns.quad9.net");
        assert_eq!(url_host("dns.quad9.net"), "dns.quad9.net");
    }

    #[test]
    fn describe_membaca_header_tanpa_jawaban() {
        let header = [0x12, 0x34, 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 0];
        let text = describe(&header);
        assert!(text.contains("0 jawaban"), "{text}");
        assert!(text.contains("NoError"), "{text}");
    }

    #[test]
    fn describe_menolak_paket_yang_bukan_dns() {
        assert!(describe(&[0xFF; 4]).contains("tidak bisa diparse"));
    }
}
