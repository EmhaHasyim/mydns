//! Proxy DNS lokal di 127.0.0.1:53 dan [::1]:53.
//!
//! Menerima query polos dari Windows, meneruskannya ke engine QUIC, dan
//! menyimpan hasilnya sebentar di cache supaya pertanyaan berulang tidak
//! perlu menyeberang jaringan lagi.

use crate::engine::Engine;
use crate::log::Log;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::RecordType;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Mutex, watch};

pub const ADDR_V4: &str = "127.0.0.1:53";
pub const ADDR_V6: &str = "[::1]:53";

/// Batas umur cache. Sengaja pendek supaya TTL yang kita kembalikan ke klien
/// (masih TTL asli) tidak membuat data basi terlalu lama.
const MAX_CACHE_SECS: u32 = 60;
const MAX_CACHE_ITEMS: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Key {
    name: String,
    qtype: u16,
    qclass: u16,
}

struct Entry {
    bytes: Vec<u8>,
    expires: Instant,
}

/// Kunci cache: nama tanpa titik akhir dan tanpa beda huruf besar/kecil,
/// supaya `Example.COM.` dan `example.com` tidak disimpan sebagai dua entri.
fn cache_key(question: &hickory_proto::op::Query) -> Key {
    Key {
        name: question
            .name()
            .to_ascii()
            .trim_end_matches('.')
            .to_lowercase(),
        qtype: u16::from(question.query_type()),
        qclass: u16::from(question.query_class()),
    }
}

pub struct Proxy {
    engine: Arc<Engine>,
    log: Arc<Log>,
    cache: Mutex<HashMap<Key, Entry>>,
    hits: AtomicU64,
    misses: AtomicU64,
    forwards: AtomicU64,
}

impl Proxy {
    pub fn new(engine: Arc<Engine>, log: Arc<Log>) -> Arc<Self> {
        Arc::new(Self {
            engine,
            log,
            cache: Mutex::new(HashMap::new()),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            forwards: AtomicU64::new(0),
        })
    }

    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    pub fn misses(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }

    pub fn forwards(&self) -> u64 {
        self.forwards.load(Ordering::Relaxed)
    }

    /// Satu baris per query untuk panel log: nama, tipe, jalur, dan latensi.
    fn log_query(&self, name: &str, qtype: RecordType, via: &str, ms: u128) {
        let qtype = format!("{qtype:?}");
        self.log
            .push(format!("{name:<30} {qtype:<6} {via:<6} {ms}ms"));
    }

    /// Proses satu paket query dan kembalikan paket jawaban.
    pub async fn handle(self: &Arc<Self>, request: &[u8], over_tcp: bool) -> Option<Vec<u8>> {
        if request.len() < 12 {
            return None;
        }
        let id = [request[0], request[1]];

        let parsed = match Message::from_vec(request) {
            Ok(m) => m,
            Err(_) => return Some(servfail(request)),
        };
        let Some(question) = parsed.queries.first() else {
            return Some(servfail(request));
        };
        let key = cache_key(question);

        // Hanya query biasa (bukan AXFR/dynamic update) yang kita cache.
        let cacheable = parsed.queries.len() == 1
            && !matches!(question.query_type(), RecordType::AXFR | RecordType::IXFR);

        if cacheable {
            let cache = self.cache.lock().await;
            if let Some(entry) = cache.get(&key)
                && entry.expires > Instant::now()
            {
                self.hits.fetch_add(1, Ordering::Relaxed);
                let mut bytes = entry.bytes.clone();
                bytes[0] = id[0];
                bytes[1] = id[1];
                drop(cache);
                self.log_query(&key.name, question.query_type(), "cache", 0);
                return Some(fit_udp(bytes, &parsed, over_tcp));
            }
        }

        self.misses.fetch_add(1, Ordering::Relaxed);
        self.forwards.fetch_add(1, Ordering::Relaxed);

        let started = Instant::now();
        let response = match self.engine.resolve(request).await {
            Ok((resp, proto)) => {
                self.log_query(
                    &key.name,
                    question.query_type(),
                    proto.label(),
                    started.elapsed().as_millis(),
                );
                resp
            }
            Err(e) => {
                self.log.push(format!(
                    "gagal meneruskan {} ({:?}): {}",
                    key.name,
                    question.query_type(),
                    e
                ));
                return Some(servfail(request));
            }
        };

        if cacheable && let Ok(resp_msg) = Message::from_vec(&response) {
            let ttl = resp_msg.answers.iter().map(|r| r.ttl).min().unwrap_or(0);
            if ttl > 0 && resp_msg.metadata.response_code == ResponseCode::NoError {
                let lifetime = Duration::from_secs(u64::from(ttl.min(MAX_CACHE_SECS)));
                let mut cache = self.cache.lock().await;
                if cache.len() >= MAX_CACHE_ITEMS {
                    // Buang yang sudah kedaluwarsa lebih dulu; kosongkan semua
                    // hanya kalau entri yang tersisa memang masih segar semua.
                    let now = Instant::now();
                    cache.retain(|_, entry| entry.expires > now);
                    if cache.len() >= MAX_CACHE_ITEMS {
                        cache.clear();
                    }
                }
                cache.insert(
                    key,
                    Entry {
                        bytes: response.clone(),
                        expires: Instant::now() + lifetime,
                    },
                );
            }
        }

        Some(fit_udp(response, &parsed, over_tcp))
    }
}

/// Jawaban yang tidak dibungkus dalam batas payload UDP klien harus dipotong
/// dengan bit TC supaya klien mengulang lewat TCP.
fn fit_udp(response: Vec<u8>, request: &Message, over_tcp: bool) -> Vec<u8> {
    if over_tcp {
        return response;
    }
    let limit = usize::from(request.max_payload()).max(512);
    if response.len() <= limit {
        return response;
    }
    match Message::from_vec(&response) {
        Ok(msg) => msg.truncate().to_vec().unwrap_or(response),
        Err(_) => response,
    }
}

fn servfail(request: &[u8]) -> Vec<u8> {
    let mut out = request.to_vec();
    if out.len() < 12 {
        return out;
    }
    out[2] = (out[2] & 0x01) | 0x80; // QR = 1
    out[3] = (out[3] & 0xF0) | 0x02; // RCODE = SERVFAIL
    for byte in out.iter_mut().take(12).skip(6) {
        *byte = 0; // kosongkan hitungan AN/NS/AR
    }
    out
}

/// Kirim satu query lewat listener lokal dan periksa jawabannya. Dipakai untuk
/// memastikan proxy benar-benar melayani query sebelum (dan sesudah) DNS adapter
/// diubah, sehingga kita tidak pernah menunjuk adapter ke port yang mati.
pub async fn probe() -> Result<String, String> {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("tidak bisa membuka socket probe: {e}"))?;
    let query = crate::engine::build_query("example.com.");
    let expect = [query[0], query[1]];

    socket
        .send_to(&query, ADDR_V4)
        .await
        .map_err(|e| format!("tidak bisa mengirim probe: {e}"))?;

    let mut buf = [0u8; 4096];
    let (n, _) =
        match tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut buf)).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return Err(format!("probe gagal: {e}")),
            Err(_) => return Err("proxy lokal tidak menjawab dalam 3 detik".to_string()),
        };
    let response = &buf[..n];
    if response.len() < 12 || response[0..2] != expect {
        return Err("jawaban proxy tidak cocok dengan query".to_string());
    }

    let msg =
        Message::from_vec(response).map_err(|e| format!("jawaban tidak bisa diparse: {e}"))?;
    if msg.metadata.response_code != ResponseCode::NoError {
        return Err(format!(
            "resolver menjawab {:?}",
            msg.metadata.response_code
        ));
    }
    if msg.answers.is_empty() {
        return Err("resolver menjawab tanpa data".to_string());
    }
    Ok(crate::engine::describe(response))
}

/// Socket yang sudah terikat, siap dijalankan.
pub struct Bound {
    pub proxy: Arc<Proxy>,
    v4_udp: Arc<UdpSocket>,
    v4_tcp: Arc<TcpListener>,
    v6_udp: Option<Arc<UdpSocket>>,
    v6_tcp: Option<Arc<TcpListener>>,
}

/// Ikat port 53 di loopback. Gagal di sini berarti port sudah dipakai proses
/// lain (Docker, AdGuard Home, VPN) — lebih baik tahu sebelum DNS diubah.
pub async fn bind(engine: Arc<Engine>, log: Arc<Log>) -> Result<Bound, String> {
    let proxy = Proxy::new(engine, log.clone());

    let v4_udp = UdpSocket::bind(ADDR_V4).await.map_err(|e| {
        format!("tidak bisa bind UDP {ADDR_V4} — port 53 mungkin dipakai proses lain ({e})")
    })?;
    let v4_tcp = TcpListener::bind(ADDR_V4).await.map_err(|e| {
        format!("tidak bisa bind TCP {ADDR_V4} — port 53 mungkin dipakai proses lain ({e})")
    })?;

    let v6_udp = UdpSocket::bind(ADDR_V6).await.ok().inspect(|_| {
        log.push("listener IPv6 aktif di [::1]:53");
    });
    let v6_tcp = TcpListener::bind(ADDR_V6).await.ok();

    Ok(Bound {
        proxy,
        v4_udp: Arc::new(v4_udp),
        v4_tcp: Arc::new(v4_tcp),
        v6_udp: v6_udp.map(Arc::new),
        v6_tcp: v6_tcp.map(Arc::new),
    })
}

impl Bound {
    pub async fn serve(self, stop: watch::Receiver<bool>) {
        let mut tasks = Vec::new();

        tasks.push(tokio::spawn(udp_loop(
            self.v4_udp.clone(),
            self.proxy.clone(),
            stop.clone(),
        )));
        if let Some(sock) = self.v6_udp.clone() {
            tasks.push(tokio::spawn(udp_loop(
                sock,
                self.proxy.clone(),
                stop.clone(),
            )));
        }
        tasks.push(tokio::spawn(tcp_loop(
            self.v4_tcp.clone(),
            self.proxy.clone(),
            stop.clone(),
        )));
        if let Some(listener) = self.v6_tcp.clone() {
            tasks.push(tokio::spawn(tcp_loop(
                listener,
                self.proxy.clone(),
                stop.clone(),
            )));
        }

        for task in tasks {
            let _ = task.await;
        }
    }
}

async fn udp_loop(sock: Arc<UdpSocket>, proxy: Arc<Proxy>, mut stop: watch::Receiver<bool>) {
    let mut buf = vec![0u8; 4096];
    loop {
        tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() { break; }
            }
            received = sock.recv_from(&mut buf) => {
                let (n, peer) = match received {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let request = buf[..n].to_vec();
                let proxy = proxy.clone();
                let sock = sock.clone();
                tokio::spawn(async move {
                    if let Some(response) = proxy.handle(&request, false).await {
                        let _ = sock.send_to(&response, peer).await;
                    }
                });
            }
        }
    }
}

async fn tcp_loop(listener: Arc<TcpListener>, proxy: Arc<Proxy>, mut stop: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() { break; }
            }
            accepted = listener.accept() => {
                let Ok((stream, _peer)) = accepted else { continue };
                let proxy = proxy.clone();
                tokio::spawn(async move { serve_tcp(stream, proxy).await });
            }
        }
    }
}

async fn serve_tcp(mut stream: TcpStream, proxy: Arc<Proxy>) {
    loop {
        let mut len_buf = [0u8; 2];
        match tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => {}
            _ => return,
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 {
            return;
        }
        let mut request = vec![0u8; len];
        if tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut request))
            .await
            .is_err()
        {
            return;
        }
        let Some(response) = proxy.handle(&request, true).await else {
            return;
        };
        if response.len() > u16::MAX as usize {
            return;
        }
        let mut framed = Vec::with_capacity(response.len() + 2);
        framed.extend_from_slice(&(response.len() as u16).to_be_bytes());
        framed.extend_from_slice(&response);
        if stream.write_all(&framed).await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::build_query;

    /// Respons TXT berukuran 639 byte: lebih besar dari batas 512 byte yang
    /// dipakai klien tanpa EDNS, jadi jalur truncation benar-benar teruji.
    fn big_response() -> Vec<u8> {
        let mut out = vec![
            0x12, 0x34, 0x81, 0x80, // id, QR + RD + RA, NoError
            0x00, 0x01, 0x00, 0x01, // qdcount 1, ancount 1
            0x00, 0x00, 0x00, 0x00, // nscount 0, arcount 0
        ];
        out.extend_from_slice(b"\x07example\x03com\x00");
        out.extend_from_slice(&[0x00, 0x10, 0x00, 0x01]); // TXT IN
        out.extend_from_slice(&[0xC0, 0x0C]); // nama: pointer ke pertanyaan
        out.extend_from_slice(&[0x00, 0x10, 0x00, 0x01]); // TXT IN
        out.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // ttl 60
        out.extend_from_slice(&[0x02, 0x58]); // rdlength 600
        for _ in 0..6 {
            out.push(99);
            out.extend_from_slice(&[b'a'; 99]);
        }
        out
    }

    #[test]
    fn cache_key_menormalkan_nama() {
        let upper = Message::from_vec(&build_query("Example.COM.")).unwrap();
        let lower = Message::from_vec(&build_query("example.com")).unwrap();
        let a = cache_key(upper.queries.first().unwrap());
        let b = cache_key(lower.queries.first().unwrap());
        assert_eq!(a, b);
        assert_eq!(a.name, "example.com");
        assert_eq!(a.qtype, u16::from(RecordType::A));
    }

    #[test]
    fn fit_udp_memotong_paket_besar_dengan_bit_tc() {
        let response = big_response();
        assert!(
            Message::from_vec(&response).is_ok(),
            "paket uji harus valid"
        );
        let request = Message::from_vec(&build_query("example.com.")).unwrap();

        let udp = fit_udp(response.clone(), &request, false);
        assert!(udp.len() < response.len());
        assert!(udp.len() <= 512, "hasil harus muat di batas 512 byte");
        assert_eq!(udp[2] & 0x02, 0x02, "bit TC harus diset");
        assert_eq!(&udp[0..2], &response[0..2], "ID harus tetap");
    }

    #[test]
    fn fit_udp_membiarkan_tcp_dan_paket_kecil() {
        let request = Message::from_vec(&build_query("example.com.")).unwrap();
        let response = big_response();
        assert_eq!(fit_udp(response.clone(), &request, true), response);

        let small = vec![0x12, 0x34, 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(fit_udp(small.clone(), &request, false), small);
    }

    #[test]
    fn servfail_mempertahankan_id_dan_menandai_rcode() {
        let query = build_query("example.com.");
        let out = servfail(&query);
        assert_eq!(
            &out[0..2],
            &query[0..2],
            "ID harus sama supaya klien menerimanya"
        );
        assert_eq!(out[2] & 0x80, 0x80, "QR harus 1");
        assert_eq!(out[3] & 0x0F, 0x02, "RCODE harus SERVFAIL");
        assert_eq!(
            &out[6..12],
            &[0, 0, 0, 0, 0, 0],
            "hitungan record dikosongkan"
        );
    }

    #[test]
    fn servfail_mengembalikan_paket_terlalu_pendek_apa_adanya() {
        let out = servfail(&[0x01, 0x02]);
        assert_eq!(out, vec![0x01, 0x02]);
    }
}
