//! Proxy DNS lokal di 127.0.0.1:53 dan [::1]:53.
//!
//! Menerima query polos dari Windows, meneruskannya ke engine QUIC, dan
//! menyimpan hasilnya sebentar di cache supaya pertanyaan berulang tidak
//! perlu menyeberang jaringan lagi.

use crate::engine::{Engine, build_query, describe};
use crate::log::Log;
use hickory_proto::op::{Message, OpCode, ResponseCode};
use hickory_proto::rr::RecordType;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
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
/// Jawaban besar (mis. DNSSEC penuh) tidak layak disimpan: 4096 entri × 64 KiB
/// bisa memakan ratusan MB. Jawaban normal hampir selalu jauh di bawah ini.
const MAX_CACHE_ENTRY_BYTES: usize = 16 * 1024;
/// Batas menunggu gerbang single-flight. Kalau pemegangnya macet (mis. upstream
/// menggantung), query lain diteruskan sendiri daripada ikut menunggu sampai
/// klien kehabisan waktu.
const GATE_WAIT: Duration = Duration::from_secs(3);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Key {
    name: String,
    qtype: u16,
    qclass: u16,
    /// DO bit: jawaban DNSSEC (RRSIG) hanya boleh dilayani ke klien yang
    /// memintanya. Tanpa pemisahan ini, klien yang meminta DNSSEC bisa
    /// menerima jawaban tanpa RRSIG sehingga validasinya gagal.
    dnssec_ok: bool,
    /// CD bit: klien yang mematikan pemeriksaan bisa menerima data berbeda
    /// dari klien biasa, jadi tidak boleh berbagi entri cache.
    checking_disabled: bool,
}

struct Entry {
    /// Jawaban mentah. `Arc` supaya cache hit tidak mengalokasikan ulang
    /// salinan paket — yang dikirim ke klien hanya 2 byte ID di header.
    bytes: Arc<[u8]>,
    expires: Instant,
}

/// Kunci cache: nama tanpa titik akhir dan tanpa beda huruf besar/kecil,
/// supaya `Example.COM.` dan `example.com` tidak disimpan sebagai dua entri,
/// ditambah bit yang mengubah isi jawaban (DO dan CD).
fn cache_key(question: &hickory_proto::op::Query, message: &Message) -> Key {
    Key {
        name: question
            .name()
            .to_ascii()
            .trim_end_matches('.')
            .to_lowercase(),
        qtype: u16::from(question.query_type()),
        qclass: u16::from(question.query_class()),
        dnssec_ok: message
            .edns
            .as_ref()
            .is_some_and(|edns| edns.flags().dnssec_ok),
        checking_disabled: message.metadata.checking_disabled,
    }
}

/// Hanya query DNS biasa yang boleh masuk cache. Opcode lain (UPDATE, NOTIFY),
/// transfer zona, TSIG, dan query yang membawa opsi EDNS (COOKIE, ECS, …)
/// jawabannya bergantung pada pengirim atau izin, jadi tidak boleh dibagikan.
fn is_cacheable(message: &Message, question: &hickory_proto::op::Query) -> bool {
    message.metadata.op_code == OpCode::Query
        && message.metadata.recursion_desired
        && message.queries.len() == 1
        && message.signature.is_none()
        && !matches!(question.query_type(), RecordType::AXFR | RecordType::IXFR)
        && message
            .edns
            .as_ref()
            .is_none_or(|edns| edns.options().options.is_empty())
}

pub struct Proxy {
    engine: Arc<Engine>,
    log: Arc<Log>,
    cache: Mutex<HashMap<Key, Entry>>,
    /// Gerbang per kunci untuk menggabungkan query identik yang datang
    /// bersamaan. Hanya `Weak` yang disimpan: entri hilang sendiri begitu
    /// tidak ada query yang memegangnya.
    inflight: Mutex<HashMap<Key, Weak<Mutex<()>>>>,
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
            inflight: Mutex::new(HashMap::new()),
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
        let key = cache_key(question, &parsed);
        let name = key.name.clone();
        let qtype = question.query_type();
        let cacheable = is_cacheable(&parsed, question);

        if cacheable && let Some((bytes, remaining)) = self.cache_get(&key).await {
            self.hits.fetch_add(1, Ordering::Relaxed);
            self.log_query(&name, qtype, "cache", 0);
            return Some(fit_udp(
                cached_response(&bytes, id, remaining, question),
                &parsed,
                over_tcp,
            ));
        }
        self.misses.fetch_add(1, Ordering::Relaxed);

        if !cacheable {
            let response = self.forward(request, &key, &name, qtype).await;
            return Some(fit_udp(response, &parsed, over_tcp));
        }

        // Query identik yang datang bersamaan cukup diteruskan sekali. Yang
        // lain menunggu gerbang ini lalu mengambil hasilnya dari cache.
        let gate = self.join_flight(&key).await;
        let guard = tokio::time::timeout(GATE_WAIT, Arc::clone(&gate).lock_owned())
            .await
            .ok();
        let response = match self.cache_get(&key).await {
            Some((bytes, remaining)) => {
                self.log_query(&name, qtype, "gabung", 0);
                cached_response(&bytes, id, remaining, question)
            }
            None => self.forward(request, &key, &name, qtype).await,
        };
        drop(guard);
        self.leave_flight(&key, &gate).await;
        Some(fit_udp(response, &parsed, over_tcp))
    }

    /// Teruskan query ke upstream, catat log, dan simpan hasilnya di cache.
    async fn forward(&self, request: &[u8], key: &Key, name: &str, qtype: RecordType) -> Vec<u8> {
        self.forwards.fetch_add(1, Ordering::Relaxed);
        let started = Instant::now();
        match self.engine.resolve(request).await {
            Ok((response, proto)) => {
                self.log_query(name, qtype, proto.label(), started.elapsed().as_millis());
                self.store_cache(key, &response).await;
                response
            }
            Err(e) => {
                self.log
                    .push(format!("gagal meneruskan {name} ({qtype:?}): {e}"));
                servfail(request)
            }
        }
    }

    /// Ambil entri cache yang masih hidup beserta sisa umurnya dalam detik.
    /// Sisa umur dipakai untuk menurunkan TTL yang dikirim ke klien, supaya
    /// klien tidak menyimpan rekaman lebih lama daripada cache kita.
    ///
    /// Yang dikembalikan adalah `Arc` dari paket asli: tidak ada alokasi ulang
    /// di jalur cache hit.
    async fn cache_get(&self, key: &Key) -> Option<(Arc<[u8]>, u32)> {
        let cache = self.cache.lock().await;
        let entry = cache.get(key)?;
        let left = entry.expires.checked_duration_since(Instant::now())?;
        let remaining = u32::try_from(left.as_millis().div_ceil(1000))
            .unwrap_or(u32::MAX)
            .max(1);
        Some((entry.bytes.clone(), remaining))
    }

    async fn store_cache(&self, key: &Key, response: &[u8]) {
        if response.len() > MAX_CACHE_ENTRY_BYTES {
            return;
        }
        let Ok(message) = Message::from_vec(response) else {
            return;
        };
        // Umur cache harus mengikuti TTL paling pendek di seluruh pesan:
        // authority (mis. SOA negatif) dan additional juga bisa kedaluwarsa
        // lebih dulu daripada answer.
        let ttl = message
            .answers
            .iter()
            .chain(message.authorities.iter())
            .chain(message.additionals.iter())
            .map(|r| r.ttl)
            .min()
            .unwrap_or(0);
        if ttl == 0 || message.metadata.response_code != ResponseCode::NoError {
            return;
        }
        let lifetime = Duration::from_secs(u64::from(ttl.min(MAX_CACHE_SECS)));
        let mut cache = self.cache.lock().await;
        if cache.len() >= MAX_CACHE_ITEMS {
            make_room(&mut cache);
        }
        cache.insert(
            key.clone(),
            Entry {
                bytes: Arc::from(response),
                expires: Instant::now() + lifetime,
            },
        );
    }

    /// Gerbang untuk satu kunci. Yang pertama membuat gerbang baru; yang lain
    /// memakai gerbang yang sama sehingga query-nya tidak ikut diteruskan.
    async fn join_flight(&self, key: &Key) -> Arc<Mutex<()>> {
        let mut map = self.inflight.lock().await;
        if let Some(gate) = map.get(key).and_then(Weak::upgrade) {
            return gate;
        }
        let gate = Arc::new(Mutex::new(()));
        map.insert(key.clone(), Arc::downgrade(&gate));
        gate
    }

    /// Hapus entri gerbang kalau tidak ada lagi query yang memegangnya.
    /// Waiter terakhir yang membersihkan, jadi map tidak tumbuh tanpa batas
    /// walau ribuan nama berbeda pernah di-query.
    async fn leave_flight(&self, key: &Key, gate: &Arc<Mutex<()>>) {
        let mut map = self.inflight.lock().await;
        let ours = map
            .get(key)
            .is_some_and(|weak| std::ptr::eq(weak.as_ptr(), Arc::as_ptr(gate)));
        if ours && Arc::strong_count(gate) == 1 {
            map.remove(key);
        }
    }
}

/// Buang entri kedaluwarsa, lalu entri yang paling cepat kedaluwarsa, sampai
/// ada ruang. Versi lama mengosongkan seluruh cache saat penuh, yang membuat
/// semua query berikutnya harus keluar jaringan sekaligus.
///
/// Pemilihan korban hanya satu kali `min_by_key`: versi sebelumnya memanggilnya
/// berulang di dalam loop sehingga jadi O(n²) di jalur panas.
fn make_room(cache: &mut HashMap<Key, Entry>) {
    let now = Instant::now();
    cache.retain(|_, entry| entry.expires > now);
    if cache.len() < MAX_CACHE_ITEMS {
        return;
    }
    // Satu korban cukup per insert. `min_by_key` O(n) tanpa meng-clone seluruh
    // key, berbeda dengan sort O(n log n) yang sebelumnya berjalan di bawah
    // lock cache pada setiap insert saat penuh.
    if let Some(key) = cache
        .iter()
        .min_by_key(|(_, entry)| entry.expires)
        .map(|(key, _)| key.clone())
    {
        cache.remove(&key);
    }
}

/// Siapkan jawaban cache untuk klien tertentu: ID query klien dipasang kembali
/// dan TTL semua record diturunkan ke sisa umur cache (RFC 2181 §5.3), supaya
/// klien tidak menyimpan rekaman lebih lama daripada yang kita anggap segar.
fn cached_response(
    bytes: &[u8],
    id: [u8; 2],
    remaining: u32,
    question: &hickory_proto::op::Query,
) -> Vec<u8> {
    let mut out = match Message::from_vec(bytes) {
        Ok(mut message) => {
            // Cache key menormalkan huruf besar/kecil. Kembalikan pertanyaan
            // persis seperti yang dikirim klien (termasuk 0x20 case
            // randomization) supaya klien tidak menolak jawaban.
            message.queries.clear();
            message.queries.push(question.clone());
            for record in message
                .answers
                .iter_mut()
                .chain(message.authorities.iter_mut())
                .chain(message.additionals.iter_mut())
            {
                record.ttl = record.ttl.min(remaining);
            }
            message.to_vec().unwrap_or_else(|_| bytes.to_vec())
        }
        Err(_) => bytes.to_vec(),
    };
    if out.len() >= 2 {
        out[0] = id[0];
        out[1] = id[1];
    }
    out
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
    let query = build_query("example.com.");
    let expect = *query
        .first_chunk::<2>()
        .ok_or_else(|| "query probe tidak terbentuk".to_string())?;

    socket
        .send_to(&query, ADDR_V4)
        .await
        .map_err(|e| format!("tidak bisa mengirim probe: {e}"))?;

    let mut buf = [0u8; 4096];
    let (n, from) =
        match tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut buf)).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return Err(format!("probe gagal: {e}")),
            Err(_) => return Err("proxy lokal tidak menjawab dalam 3 detik".to_string()),
        };
    if from.to_string() != ADDR_V4 {
        return Err(format!(
            "jawaban probe datang dari {from}, bukan proxy lokal"
        ));
    }
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
    Ok(describe(response))
}

/// Socket yang sudah terikat, siap dijalankan.
pub struct Bound {
    pub proxy: Arc<Proxy>,
    /// True kalau listener `[::1]:53` benar-benar aktif. Dipakai sebelum
    /// memasang `::1` sebagai DNS adapter.
    pub v6: bool,
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
    let v6 = v6_udp.is_some() && v6_tcp.is_some();

    Ok(Bound {
        proxy,
        v6,
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
        if tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut len_buf))
            .await
            .is_err()
        {
            return;
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 {
            return;
        }
        // Alokasi satu buffer per query; hindari `Vec` perantara `framed` saat
        // mengirim jawaban.
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
        // Tulis header langsung ke stream, lalu paketnya: tidak ada salinan
        // perantara `framed` untuk request besar.
        if response.len() > u16::MAX as usize {
            return;
        }
        let header = (response.len() as u16).to_be_bytes();
        if stream.write_all(&header).await.is_err() {
            return;
        }
        if stream.write_all(&response).await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let a = cache_key(upper.queries.first().unwrap(), &upper);
        let b = cache_key(lower.queries.first().unwrap(), &lower);
        assert_eq!(a, b);
        assert_eq!(a.name, "example.com");
        assert_eq!(a.qtype, u16::from(RecordType::A));
    }

    #[test]
    fn cache_key_memisahkan_dnssec_dan_cd() {
        use hickory_proto::op::{Edns, Query};
        use hickory_proto::rr::Name;

        let plain = Message::from_vec(&build_query("example.com.")).unwrap();
        let a = cache_key(plain.queries.first().unwrap(), &plain);

        let mut signed = Message::query();
        signed.metadata.recursion_desired = true;
        signed.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        let mut edns = Edns::new();
        edns.set_dnssec_ok(true);
        signed.set_edns(edns);
        let b = cache_key(signed.queries.first().unwrap(), &signed);

        assert_ne!(a, b, "DO bit harus memisahkan entri cache");
        assert!(b.dnssec_ok);

        signed.metadata.checking_disabled = true;
        let c = cache_key(signed.queries.first().unwrap(), &signed);
        assert_ne!(b, c, "CD bit harus memisahkan entri cache");
    }

    #[test]
    fn cache_hit_menurunkan_ttl_dan_mengganti_id() {
        let response = big_response();
        let question = Message::from_vec(&response).unwrap().queries[0].clone();
        let served = cached_response(&response, [0xAB, 0xCD], 7, &question);
        let message = Message::from_vec(&served).unwrap();
        assert_eq!(message.metadata.id, 0xABCD);
        assert!(
            message.answers.iter().all(|record| record.ttl <= 7),
            "TTL yang dikirim ke klien tidak boleh melebihi sisa umur cache"
        );
    }

    #[test]
    fn cache_hit_mempertahankan_case_pertanyaan_klien() {
        use hickory_proto::rr::Name;

        let response = big_response();
        let mut query = Message::from_vec(&response).unwrap().queries[0].clone();
        query.set_name(Name::from_ascii("ExAmPlE.CoM.").unwrap());
        let served = cached_response(&response, [0xAB, 0xCD], 7, &query);
        let message = Message::from_vec(&served).unwrap();
        assert_eq!(message.queries[0].name().to_ascii(), "ExAmPlE.CoM.");
    }

    #[test]
    fn opcode_bukan_query_tidak_dicache() {
        use hickory_proto::op::{MessageType, Query};
        use hickory_proto::rr::Name;

        let mut message = Message::new(0, MessageType::Query, OpCode::Update);
        message.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        assert!(!is_cacheable(&message, message.queries.first().unwrap()));
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

    #[test]
    fn cache_penuh_membuang_entri_paling_tua() {
        let key = |name: String| Key {
            name,
            qtype: 1,
            qclass: 1,
            dnssec_ok: false,
            checking_disabled: false,
        };
        let now = Instant::now();
        let mut cache = HashMap::new();
        for i in 0..MAX_CACHE_ITEMS {
            cache.insert(
                key(format!("n{i}")),
                Entry {
                    bytes: Arc::from(vec![0]),
                    expires: now + Duration::from_secs(60 + i as u64),
                },
            );
        }

        make_room(&mut cache);

        assert_eq!(cache.len(), MAX_CACHE_ITEMS - 1);
        assert!(!cache.contains_key(&key("n0".to_string())));
        assert!(cache.contains_key(&key(format!("n{}", MAX_CACHE_ITEMS - 1))));
    }
}
