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
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc, oneshot};

const CONNECT_TIMEOUT: Duration = Duration::from_millis(2500);
/// Batas satu query ke upstream. Sengaja di bawah batas kesabaran klien
/// Windows (~1-2 s sebelum mengirim ulang): query yang kita terus-terusan
/// tahan hanya memakan slot dan memicu retry, sementara protokol pengganti
/// sudah menunggu di `resolve`.
const QUERY_TIMEOUT: Duration = Duration::from_secs(3);
/// Jeda sebelum query yang sama dikirim paralel lewat protokol cadangan.
/// Cukup untuk memberi protokol utama kesempatan menyala, tapi tidak sampai
/// membuat query pertama terasa menggantung.
const HEDGE_DELAY: Duration = Duration::from_millis(300);
/// Setelah protokol gagal dua kali, ia dilewati selama ini sebelum dicoba lagi.
const FAILURE_COOLDOWN: Duration = Duration::from_secs(60);
const MAX_MESSAGE: usize = 65_535;
/// Berapa query yang boleh menunggu di worker DoH3. Kecil supaya "sedang
/// sibuk" cepat terdeteksi dan query berikutnya bisa dilayani DoH2 yang
/// mendukung banyak request paralel.
const H3_QUEUE: usize = 4;

/// Kunci untuk state kecil yang tidak pernah menunggu I/O. Poison diabaikan:
/// isinya tetap konsisten, dan satu panic tidak boleh mematikan resolver.
fn guard<T>(lock: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
    lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Konfigurasi TLS per ALPN dirakit sekali saja: root store WebPKI berisi
/// ratusan sertifikat dan tidak perlu dibangun ulang tiap koneksi dipulihkan.
fn tls_config(alpn: &'static str) -> Arc<rustls::ClientConfig> {
    static DOQ: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    static H3: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    static H2: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();

    let slot = match alpn {
        "doq" => &DOQ,
        "h3" => &H3,
        _ => &H2,
    };
    slot.get_or_init(|| {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![alpn.as_bytes().to_vec()];
        Arc::new(cfg)
    })
    .clone()
}

fn quic_client_config(alpn: &'static str) -> Result<quinn::ClientConfig, String> {
    let idle: quinn::IdleTimeout = Duration::from_secs(25)
        .try_into()
        .map_err(|_| "idle timeout tidak valid".to_string())?;
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(idle));
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from((*tls_config(alpn)).clone())
        .map_err(|e| format!("konfigurasi TLS: {e}"))?;
    let mut cfg = quinn::ClientConfig::new(Arc::new(crypto));
    cfg.transport_config(Arc::new(transport));
    Ok(cfg)
}

fn url_host(url: &str) -> &str {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let authority = rest.split('/').next().unwrap_or(rest);
    // Buang userinfo (`user@host`) dan port; SNI hanya menerima nama host.
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    if let Some(inner) = authority.strip_prefix('[') {
        return inner.split(']').next().unwrap_or(inner);
    }
    authority.split(':').next().unwrap_or(authority)
}

fn url_port(url: &str) -> u16 {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let authority = rest.split('/').next().unwrap_or(rest);
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    if authority.starts_with('[') {
        return authority
            .split_once("]:")
            .and_then(|(_, port)| port.parse().ok())
            .unwrap_or(443);
    }
    authority
        .split_once(':')
        .and_then(|(_, port)| port.parse().ok())
        .unwrap_or(443)
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
    /// Socket terpisah untuk tujuan IPv6. Kalau mesin tidak punya IPv6, ini
    /// `None` dan alamat v6 dilewati tanpa mengganggu jalur IPv4.
    ep6: Option<quinn::Endpoint>,
    prov: &'static Provider,
    /// Satu-satunya kunci async: guard-nya dipegang selama handshake QUIC.
    doq: Mutex<Option<quinn::Connection>>,
    /// Kunci connect per protokol. Dipakai saat slot masih kosong: query yang
    /// datang bersamaan menunggu di sini, bukan ikut membuka koneksi kedua yang
    /// langsung jadi sampah. Isinya selalu `Some`, jadi lock-nya tidak pernah
    /// gagal — hanya antrean.
    h2_connect: Mutex<()>,
    h3_connect: StdMutex<()>,
    h3: StdMutex<Option<mpsc::Sender<Job>>>,
    h2: StdMutex<Option<h2::client::SendRequest<Bytes>>>,
    /// Tunnel WARP dibuka sekali saat pertama dipakai, lalu dipakai ulang.
    warp: Mutex<Option<Arc<crate::warp::Tunnel>>>,
    /// Kunci handshake WARP; isinya selalu `Some`, hanya antrean.
    warp_connect: Mutex<()>,
    preferred: StdMutex<Option<Proto>>,
    /// Berapa kali sebuah protokol gagal berturut-turut dan kapan terakhir.
    /// Setelah dua kali, protokol itu dilewati sementara supaya fallback tidak
    /// membuang waktu tiap query.
    failures: StdMutex<HashMap<Proto, (u8, Instant)>>,
}

impl Engine {
    pub fn new(prov: &'static Provider) -> Result<Arc<Self>, String> {
        let ep = quinn::Endpoint::client(SocketAddr::from(([0u8, 0, 0, 0], 0)))
            .map_err(|e| format!("tidak bisa membuka socket QUIC: {e}"))?;
        let ep6 = quinn::Endpoint::client(SocketAddr::from(([0u16; 8], 0))).ok();
        Ok(Arc::new(Self {
            ep,
            ep6,
            prov,
            doq: Mutex::new(None),
            h2_connect: Mutex::new(()),
            h3_connect: StdMutex::new(()),
            h3: StdMutex::new(None),
            h2: StdMutex::new(None),
            warp: Mutex::new(None),
            warp_connect: Mutex::new(()),
            preferred: StdMutex::new(None),
            failures: StdMutex::new(HashMap::new()),
        }))
    }

    /// Kirim satu query dan kembalikan (respons, protokol yang dipakai).
    /// Urutan percobaan: protokol yang terakhir berhasil, lalu DoQ → DoH3 → DoH2.
    pub async fn resolve(&self, query: &[u8]) -> Result<(Vec<u8>, Proto), String> {
        let mut order = self.prov.protos();
        order.retain(|p| self.usable_proto(*p));
        // Kalau semua protokol sedang dikarantina, tetap coba semuanya
        // daripada gagal tanpa satu percobaan pun.
        if order.is_empty() {
            order = self.prov.protos();
        }
        if let Some(last) = *guard(&self.preferred)
            && let Some(pos) = order.iter().position(|p| *p == last)
        {
            let last_used = order.remove(pos);
            order.insert(0, last_used);
        }
        // Worker DoH3 hanya melayani satu query pada satu waktu. Saat antreannya
        // penuh, DoH2 (satu koneksi multiplex) jauh lebih baik daripada ikut
        // mengantre, jadi protokol itu didahulukan untuk query ini.
        order = hedge_doh3(order, self.h3_busy());
        if order.is_empty() {
            return Err("provider tidak punya protokol yang didukung".to_string());
        }

        let mut errors = Vec::new();
        for proto in order {
            match self.query_hedged(proto, query).await {
                Ok((resp, used)) => {
                    *guard(&self.preferred) = Some(used);
                    guard(&self.failures).remove(&used);
                    return Ok((resp, used));
                }
                // Cabang yang benar-benar gagal yang dicatat, bukan proto utama.
                Err((failed, message)) => {
                    self.note_failure(failed).await;
                    errors.push(message);
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
            Proto::Warp => self.warp_query(query).await,
        }
    }

    /// True kalau protokol belum dikarantina oleh failure cooldown.
    fn usable_proto(&self, proto: Proto) -> bool {
        match guard(&self.failures).get(&proto) {
            // Dilewati hanya sementara: gangguan jaringan sesaat tidak
            // boleh mematikan DoQ untuk seluruh sesi.
            Some((count, when)) => *count < 2 || when.elapsed() > FAILURE_COOLDOWN,
            None => true,
        }
    }

    /// Satu percobaan dengan hedging: kalau protokol utama belum menjawab
    /// dalam `HEDGE_DELAY`, protokol cadangan dijalankan bersamaan. Yang
    /// pertama menjawab dipakai, yang kalah dibuang. Ini menghilangkan
    /// sentuhan pertama yang lambat pada query pertama tiap sesi.
    async fn query_hedged(
        &self,
        proto: Proto,
        query: &[u8],
    ) -> Result<(Vec<u8>, Proto), (Proto, String)> {
        let mut others = self.prov.protos();
        others.retain(|p| *p != proto && self.usable_proto(*p));
        // Worker DoH3 melayani satu query sekali jalan; saat sibuk ia bukan
        // cadangan yang baik.
        if self.h3_busy() {
            others.retain(|p| *p != Proto::DoH3);
        }
        let backup = others.first().copied();
        let Some(backup) = backup.filter(|_| !matches!(proto, Proto::DoH2)) else {
            let resp = self
                .query_proto(proto, query)
                .await
                .map_err(|e| (proto, e))?;
            if !response_matches(query, &resp) {
                return Err((
                    proto,
                    format!("{}: respons tidak cocok dengan query", proto.label()),
                ));
            }
            return Ok((resp, proto));
        };

        let primary = self.query_proto(proto, query);
        let hedge = async {
            tokio::time::sleep(HEDGE_DELAY).await;
            self.query_proto(backup, query).await
        };
        tokio::pin!(primary);
        tokio::pin!(hedge);

        // Pilih jawaban pertama yang cocok dengan query. Kalau yang datang
        // lebih dulu tidak cocok (mis. tunnel WARP yang keliru menjawab),
        // tunggu yang satu lagi — jangan langsung melaporkan gagal.
        //
        // Penting: cabang yang menang HARUS menunggu future yang kalah.
        // Mem-poll ulang future yang sudah selesai akan memicu panic
        // "`async fn` resumed after completion".
        let primary_error: (Proto, String);
        let hedge_error: (Proto, String);
        tokio::select! {
            result = &mut primary => {
                match result {
                    Ok(resp) if response_matches(query, &resp) => return Ok((resp, proto)),
                    Ok(_) => primary_error = (proto, format!("{}: respons tidak cocok dengan query", proto.label())),
                    Err(e) => primary_error = (proto, format!("{}: {e}", proto.label())),
                }
                match tokio::time::timeout(QUERY_TIMEOUT, &mut hedge).await {
                    Ok(Ok(resp)) if response_matches(query, &resp) => Ok((resp, backup)),
                    Ok(Ok(_)) => Err((backup, format!("{}: respons tidak cocok dengan query", backup.label()))),
                    Ok(Err(e)) => Err((backup, format!("{}: {e}", backup.label()))),
                    Err(_) => Err(primary_error),
                }
            }
            result = &mut hedge => {
                match result {
                    Ok(resp) if response_matches(query, &resp) => return Ok((resp, backup)),
                    Ok(_) => hedge_error = (backup, format!("{}: respons tidak cocok dengan query", backup.label())),
                    Err(e) => hedge_error = (backup, format!("{}: {e}", backup.label())),
                }
                match tokio::time::timeout(QUERY_TIMEOUT, &mut primary).await {
                    Ok(Ok(resp)) if response_matches(query, &resp) => Ok((resp, proto)),
                    Ok(Ok(_)) => Err((proto, format!("{}: respons tidak cocok dengan query", proto.label()))),
                    Ok(Err(e)) => Err((proto, format!("{}: {e}", proto.label()))),
                    Err(_) => Err(hedge_error),
                }
            }
        }
    }

    async fn warp_query(&self, query: &[u8]) -> Result<Vec<u8>, String> {
        self.warp_tunnel().await?.resolve(query).await
    }

    /// Ambil tunnel WARP yang sudah terbuka, atau buka yang baru.
    ///
    /// Slot hanya dikunci sebentar untuk membaca/mengisi. Handshake WARP bisa
    /// memakan beberapa detik, dan `warp_connect` menjaga agar hanya satu query
    /// yang mengerjakannya — yang lain menunggu lalu memakai hasilnya.
    async fn warp_tunnel(&self) -> Result<Arc<crate::warp::Tunnel>, String> {
        if let Some(tunnel) = self.warp.lock().await.as_ref() {
            return Ok(tunnel.clone());
        }
        let _gate = self.warp_connect.lock().await;
        // Cek ulang: tunnel mungkin sudah dibuat query yang menunggu di depan.
        if let Some(tunnel) = self.warp.lock().await.as_ref() {
            return Ok(tunnel.clone());
        }
        // `ensure` mendaftarkan perangkat sendiri kalau belum ada, jadi
        // memilih provider WARP tidak memerlukan perintah tambahan.
        let config = crate::warp::ensure().await?;
        let tunnel = crate::warp::Tunnel::connect(&config).await?;
        *self.warp.lock().await = Some(tunnel.clone());
        Ok(tunnel)
    }

    /// Putuskan koneksi protokol ini dan catat kegagalannya.
    /// Hitungannya dijenuhkan (bukan `+= 1`) supaya protokol yang gagal terus-
    /// menerus — mis. QUIC diblokir jaringan — tidak pernah mengalami overflow.
    async fn note_failure(&self, proto: Proto) {
        self.invalidate(proto).await;
        let now = Instant::now();
        let mut failures = guard(&self.failures);
        let entry = failures.entry(proto).or_insert((0, now));
        entry.0 = entry.0.saturating_add(1);
        entry.1 = now;
    }

    async fn invalidate(&self, proto: Proto) {
        match proto {
            Proto::DoQ => {
                *self.doq.lock().await = None;
            }
            // Menjatuhkan sender membuat worker melihat channel tertutup lalu keluar.
            Proto::DoH3 => {
                let _ = guard(&self.h3).take();
            }
            Proto::DoH2 => self.h2_forget(),
            Proto::Warp => {
                *self.warp.lock().await = None;
            }
        }
    }

    /// True kalau antrean worker DoH3 sudah penuh.
    fn h3_busy(&self) -> bool {
        guard(&self.h3)
            .as_ref()
            .is_some_and(|tx| tx.capacity() == 0)
    }

    /// Endpoint QUIC sesuai keluarga alamat tujuan. Endpoint IPv6 dibuat saat
    /// Engine lahir, dan `None` berarti mesin ini tidak bisa membuka socket v6.
    fn endpoint_for(&self, addr: SocketAddr) -> Option<quinn::Endpoint> {
        if addr.is_ipv6() {
            self.ep6.clone()
        } else {
            Some(self.ep.clone())
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
            let Some(endpoint) = self.endpoint_for(addr) else {
                last = format!("{addr}: socket IPv6 tidak tersedia");
                continue;
            };
            let connecting = match endpoint.connect_with(cfg.clone(), addr, host) {
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
        let raw = tokio::time::timeout(QUERY_TIMEOUT, async {
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

            recv.read_to_end(MAX_MESSAGE)
                .await
                .map_err(|e| format!("baca: {e}"))
        })
        .await
        .map_err(|_| "timeout".to_string())??;
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

    /// Ambil koneksi HTTP/3 yang ada, atau buka yang baru.
    ///
    /// Saat slot kosong, kunci `h3_connect` dipegang selama worker dibuat
    /// supaya query yang datang bersamaan tidak sama-sama membuat worker
    /// (dan koneksi QUIC) yang salah satunya langsung jadi sampah.
    fn h3_sender(&self) -> Result<mpsc::Sender<Job>, String> {
        // Jalur cepat tanpa kunci: hampir semua query sesudah yang pertama
        // berakhir di sini.
        if let Some(tx) = guard(&self.h3).as_ref().filter(|tx| !tx.is_closed()) {
            return Ok(tx.clone());
        }
        let _gate = guard(&self.h3_connect);
        // Cek ulang setelah dapat kunci: worker mungkin sudah dibuat query lain
        // yang menunggu di depan kita.
        if let Some(tx) = guard(&self.h3).as_ref().filter(|tx| !tx.is_closed()) {
            return Ok(tx.clone());
        }
        let (tx, rx) = mpsc::channel::<Job>(H3_QUEUE);
        let ep = self.ep.clone();
        let ep6 = self.ep6.clone();
        let prov = self.prov;
        let cfg = quic_client_config("h3")?;
        tokio::spawn(async move { h3_worker(ep, ep6, cfg, prov, rx).await });
        *guard(&self.h3) = Some(tx.clone());
        Ok(tx)
    }

    async fn doh3_query(&self, query: &[u8]) -> Result<Vec<u8>, String> {
        let tx = self.h3_sender()?;
        let (otx, orx) = oneshot::channel();
        tokio::time::timeout(QUERY_TIMEOUT, tx.send((query.to_vec(), otx)))
            .await
            .map_err(|_| "timeout".to_string())?
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
        let port = url_port(url);
        let connector = tokio_rustls::TlsConnector::from(tls_config("h2"));
        let mut last = String::from("tidak ada IP bootstrap");

        for addr in boots(self.prov, port) {
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

    /// Ambil koneksi HTTP/2 yang ada, atau buka yang baru.
    ///
    /// Satu koneksi HTTP/2 melayani banyak request sekaligus, jadi slot hanya
    /// dipegang sebentar. Saat kosong, `h2_connect` dipegang selama handshake
    /// supaya query yang datang bersamaan tidak sama-sama membuka koneksi —
    /// yang kedua akan menggantikan yang pertama dan membuang socket hangatnya.
    async fn h2_sender(&self) -> Result<h2::client::SendRequest<Bytes>, String> {
        if let Some(send) = guard(&self.h2).as_ref() {
            return Ok(send.clone());
        }
        let _gate = self.h2_connect.lock().await;
        // Cek ulang: koneksi mungkin sudah dibuat query yang menunggu di depan.
        if let Some(send) = guard(&self.h2).as_ref() {
            return Ok(send.clone());
        }
        let send = self.h2_connect().await?;
        *guard(&self.h2) = Some(send.clone());
        Ok(send)
    }

    /// Lupakan koneksi HTTP/2 yang sudah tidak bisa dipakai.
    fn h2_forget(&self) {
        *guard(&self.h2) = None;
    }

    async fn doh2_query(&self, query: &[u8]) -> Result<Vec<u8>, String> {
        let mut send = self.h2_sender().await?;
        let url = self
            .prov
            .doh
            .ok_or_else(|| "provider tidak punya endpoint DoH".to_string())?;

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
                self.h2_forget();
                return Err(format!("kirim HTTP/2: {e}"));
            }
        };
        body.send_data(Bytes::copy_from_slice(query), true)
            .map_err(|e| format!("body: {e}"))?;

        let response = match tokio::time::timeout(QUERY_TIMEOUT, future).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                self.h2_forget();
                return Err(format!("respons HTTP/2: {e}"));
            }
            Err(_) => {
                self.h2_forget();
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
            if out.len() + n > MAX_MESSAGE {
                // Kapasitas sudah dikreditkan oleh `recv.data()`: kembalikan
                // sebelum keluar supaya window koneksi tidak menyusut permanen.
                let _ = recv.flow_control().release_capacity(n);
                return Err("respons DoH melebihi batas".to_string());
            }
            out.extend_from_slice(&chunk.copy_to_bytes(n));
            // h2 mewajibkan kapasitas dikembalikan; tanpa ini receive window
            // habis dan koneksi panjang macet setelah beberapa puluh KiB.
            recv.flow_control()
                .release_capacity(n)
                .map_err(|e| format!("release flow control: {e}"))?;
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
            if !response_matches(query, &resp) {
                return Err("jawaban tidak cocok dengan query".to_string());
            }
            best = best.min(started.elapsed().as_millis());
            summary = describe(&resp);
        }
        Ok((best, summary))
    }
}

/// Pastikan respons benar-benar menjawab query yang kita kirim: tipe pesan
/// Response, ID sama, dan pertanyaannya identik (nama tanpa beda huruf besar/
/// kecil, tipe, dan kelas). Tanpa ini jalur seperti WARP — yang mencocokkan
/// jawaban hanya lewat port lokal — bisa meneruskan paket milik query lain.
fn response_matches(query: &[u8], response: &[u8]) -> bool {
    use hickory_proto::op::{Message, MessageType};

    if response.len() < 12 {
        return false;
    }
    let (Ok(query), Ok(response)) = (Message::from_vec(query), Message::from_vec(response)) else {
        return false;
    };
    if response.metadata.message_type != MessageType::Response
        || response.metadata.id != query.metadata.id
    {
        return false;
    }
    let (Some(asked), Some(answered)) = (query.queries.first(), response.queries.first()) else {
        return false;
    };
    asked.query_type() == answered.query_type()
        && asked.query_class() == answered.query_class()
        && asked
            .name()
            .to_ascii()
            .eq_ignore_ascii_case(&answered.name().to_ascii())
}

/// Saat jalur DoH3 sibuk, pindahkan DoH2 ke depan urutan percobaan. DoH2 bisa
/// melayani banyak request sekaligus, sementara worker DoH3 hanya satu per satu.
fn hedge_doh3(mut order: Vec<Proto>, h3_busy: bool) -> Vec<Proto> {
    if h3_busy && let Some(pos) = order.iter().position(|proto| *proto == Proto::DoH2) {
        let doh2 = order.remove(pos);
        order.insert(0, doh2);
    }
    order
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

/// Satu worker = satu koneksi HTTP/3. Job diproses berurutan karena `h3` 0.0.8
/// berhenti menjawab untuk sebagian server kalau satu `SendRequest` dipakai
/// bersamaan.
async fn h3_worker(
    ep: quinn::Endpoint,
    ep6: Option<quinn::Endpoint>,
    cfg: quinn::ClientConfig,
    prov: &'static Provider,
    mut rx: mpsc::Receiver<Job>,
) {
    let Some(url) = prov.doh else {
        return;
    };
    let host = url_host(url).to_string();

    // Koneksi dibuka sebelum job pertama diambil, lengkap dengan satu poll
    // driver (lihat `connect_h3`). Kalau gagal, worker keluar dan receiver
    // ikut di-drop: job yang menunggu langsung mendapat error, dan query
    // berikutnya membuat worker/koneksi baru.
    let Ok(mut sender) = connect_h3(&ep, ep6.as_ref(), &cfg, prov, &host).await else {
        return;
    };

    while let Some((query, reply)) = rx.recv().await {
        let result = tokio::time::timeout(
            QUERY_TIMEOUT,
            h3_roundtrip(&mut sender, url, Bytes::from(query)),
        )
        .await
        .map_err(|_| "timeout".to_string())
        .and_then(|r| r);
        let failed = result.is_err();
        let _ = reply.send(result);
        // Koneksi yang sudah error tidak dipakai lagi: worker keluar, dan
        // koneksi pengganti dibuat saat query berikutnya tiba.
        if failed {
            break;
        }
    }
}

async fn connect_h3(
    ep: &quinn::Endpoint,
    ep6: Option<&quinn::Endpoint>,
    cfg: &quinn::ClientConfig,
    prov: &'static Provider,
    host: &str,
) -> Result<h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>, String> {
    let mut connection = None;
    let mut last = String::from("tidak ada IP bootstrap");
    let port = prov.doh.map(url_port).unwrap_or(443);
    for addr in boots(prov, port) {
        let endpoint = if addr.is_ipv6() { ep6 } else { Some(ep) };
        let Some(endpoint) = endpoint else {
            last = format!("{addr}: socket IPv6 tidak tersedia");
            continue;
        };
        let Ok(connecting) = endpoint.connect_with(cfg.clone(), addr, host) else {
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
        return Err(format!("DoH3 {host}: {last}"));
    };

    let (mut driver, sender) = h3::client::new(h3_quinn::Connection::new(conn))
        .await
        .map_err(|e| format!("DoH3 handshake HTTP/3: {e}"))?;

    // Poll driver sekali secara sinkron sebelum request pertama. Kalau tidak,
    // request bisa terkirim sebelum driver sempat mengirim SETTINGS/stream
    // kontrol, dan sebagian server (Cloudflare, Quad9) tidak pernah menjawab.
    let _ = std::future::poll_fn(|cx| std::task::Poll::Ready(driver.poll_close(cx))).await;

    // Driver wajib dipoll terus-menerus; tanpa ini koneksi HTTP/3 tidak jalan.
    tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    });
    Ok(sender)
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
        if out.len() + n > MAX_MESSAGE {
            return Err("respons DoH3 melebihi batas".into());
        }
        out.extend_from_slice(&chunk.copy_to_bytes(n));
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

    #[test]
    fn hedge_doh3_mendahulukan_doh2_saat_sibuk() {
        let order = vec![Proto::DoQ, Proto::DoH3, Proto::DoH2];
        assert_eq!(
            hedge_doh3(order.clone(), false),
            vec![Proto::DoQ, Proto::DoH3, Proto::DoH2]
        );
        assert_eq!(
            hedge_doh3(order, true),
            vec![Proto::DoH2, Proto::DoQ, Proto::DoH3]
        );
        // Provider tanpa DoH2 tidak berubah.
        assert_eq!(hedge_doh3(vec![Proto::DoH3], true), vec![Proto::DoH3]);
    }

    #[test]
    fn respons_tidak_cocok_dengan_query_ditolak() {
        use hickory_proto::op::{Message, MessageType, OpCode, Query};
        use hickory_proto::rr::{Name, RecordType};

        let query = build_query("example.com.");
        let id = u16::from_be_bytes([query[0], query[1]]);

        let mut wrong_name = Message::new(id, MessageType::Response, OpCode::Query);
        wrong_name.add_query(Query::query(
            Name::from_ascii("example.org.").unwrap(),
            RecordType::A,
        ));
        assert!(
            !response_matches(&query, &wrong_name.to_vec().unwrap()),
            "nama yang berbeda harus ditolak"
        );

        let mut wrong_id = Message::new(id.wrapping_add(1), MessageType::Response, OpCode::Query);
        wrong_id.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        assert!(!response_matches(&query, &wrong_id.to_vec().unwrap()));

        let mut good = Message::new(id, MessageType::Response, OpCode::Query);
        good.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        assert!(response_matches(&query, &good.to_vec().unwrap()));
    }
}
