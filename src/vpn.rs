//! Mode VPN penuh: seluruh trafik IPv4 dan IPv6 dibawa lewat tunnel WARP MASQUE.
//!
//! Transport-nya sama dengan jalur DNS di `warp.rs` — CONNECT-IP (RFC 9484) di
//! atas HTTP/3. Bedanya hanya sumber paketnya: bukan query DNS yang dibungkus
//! sendiri, tetapi paket IP utuh dari adapter TUN.
//!
//! Tidak ada userspace TCP/IP stack di sini. WARP menyalurkan paket IP
//! end-to-end, jadi TCP state tetap di ujung masing-masing; modul ini hanya
//! memindahkan byte antara adapter Wintun dan HTTP Datagram.
//!
//! Urutan aman yang dipakai [`Vpn::up`]: tunnel dulu, adapter, rute, baru
//! verifikasi. Kalau verifikasi gagal, rute dicabut lagi sebelum error
//! dilaporkan — mesin tidak boleh ditinggal tanpa internet.

use crate::warp::{self, Tunnel};
use crate::win;
use rustls::pki_types::ServerName;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use wintun::{Adapter, Session, Wintun};

/// Nama adapter yang muncul di Network Connections.
pub const ADAPTER_NAME: &str = "MyDNS";
/// Ring buffer Wintun 4 MiB: cukup untuk burst tanpa membuat driver menunggu.
const RING_CAPACITY: u32 = 0x40_0000;
/// MTU WARP.
const MTU_MAX: usize = 1280;
/// Alamat yang dipakai membuktikan tunnel benar-benar meneruskan trafik.
/// Keduanya literal, tidak butuh DNS yang sedang dialihkan ke proxy lokal.
const PROBE_ADDR: &str = "1.1.1.1:443";
const PROBE_HOST: &str = "1.1.1.1";
const PROBE_ADDR_V6: &str = "[2606:4700:4700::1111]:443";
const PROBE_HOST_V6: &str = "2606:4700:4700::1111";
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
/// Batas waktu menunggu task pembaca paket berhenti saat tunnel dimatikan.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(3);
/// Batas respons `/cdn-cgi/trace`; jawaban normal hanya ratusan byte.
const MAX_TRACE_BYTES: usize = 64 * 1024;

#[derive(Default)]
pub struct Stats {
    pub up: AtomicU64,
    pub down: AtomicU64,
}

pub struct Vpn {
    stop: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
    session: Arc<Session>,
    /// Dipegang supaya koneksi QUIC tetap hidup selama VPN menyala.
    _tunnel: Arc<Tunnel>,
    routes: win::SavedVpn,
    stats: Arc<Stats>,
    _wintun: Wintun,
    /// Rute IPv6 ikut dipasang hanya kalau WARP memberi alamat v6.
    has_v6: bool,
    pub mtu: usize,
}

async fn tcp_probe(addr: &str) -> Result<(), String> {
    match tokio::time::timeout(Duration::from_secs(2), tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("timeout".to_string()),
    }
}

/// Alamat IPv6 dari konfigurasi WARP. API bisa mengembalikan alamat polos atau
/// dengan prefiks `/128`; keduanya diterima.
fn tunnel_ipv6(raw: &str) -> Option<String> {
    raw.trim()
        .split('/')
        .next()?
        .parse::<Ipv6Addr>()
        .ok()
        .map(|ip| ip.to_string())
}

impl Vpn {
    /// Nyalakan full tunnel. Rute hanya dipasang setelah tunnel menjawab, dan
    /// dicabut lagi kalau verifikasi gagal.
    pub async fn up() -> Result<Self, String> {
        win::require_admin()?;
        // `ensure` mendaftarkan perangkat WARP sendiri kalau belum ada, jadi
        // tiap user Windows langsung punya perangkat sendiri tanpa langkah
        // pendaftaran manual.
        let config = warp::ensure().await?;
        let wintun = load_wintun()?;

        let tunnel = Tunnel::connect(&config).await?;
        let ipv6 = tunnel_ipv6(&config.ipv6);
        // IPv6 mensyaratkan MTU minimal 1280; jangan pernah mengatur adapter
        // lebih kecil kalau rute v6 ikut dipasang.
        let mtu = tunnel
            .max_datagram()
            .saturating_sub(8)
            .clamp(if ipv6.is_some() { 1280 } else { 576 }, MTU_MAX);
        let ip: Ipv4Addr = config
            .ipv4
            .parse()
            .map_err(|_| format!("alamat tunnel IPv4 tidak valid: {}", config.ipv4))?;

        let adapter = match create_adapter(&wintun) {
            Ok(adapter) => adapter,
            Err(e) => return Err(e),
        };
        let index = adapter
            .get_adapter_index()
            .map_err(|e| format!("adapter TUN tidak punya index: {e}"))?;
        // Sesi harus hidup lebih dulu: tanpa itu driver melaporkan adapter
        // tanpa link, dan rute yang dipasang ke sana langsung tidak terpakai.
        let session = match adapter.start_session(RING_CAPACITY) {
            Ok(session) => Arc::new(session),
            Err(e) => {
                delete_adapter(&wintun);
                return Err(format!("tidak bisa memulai sesi Wintun: {e}"));
            }
        };
        if let Err(e) = configure_adapter(&adapter, ip, mtu) {
            let _ = session.shutdown();
            delete_adapter(&wintun);
            return Err(e);
        }
        if let Some(ipv6) = ipv6.as_deref()
            && let Err(e) = win::adapter_set_ipv6(index, ipv6)
        {
            let _ = session.shutdown();
            delete_adapter(&wintun);
            return Err(e);
        }

        let endpoint = tunnel.endpoint_ip().map(|ip| ip.to_string());
        let routes = match win::vpn_install_routes(
            ADAPTER_NAME,
            index,
            endpoint.as_deref(),
            ipv6.as_deref(),
        ) {
            Ok(routes) => routes,
            Err(e) => {
                let _ = session.shutdown();
                delete_adapter(&wintun);
                return Err(e);
            }
        };

        debug_dump("setelah rute dipasang", index, &routes).await;
        // Rute baru belum langsung dipakai stack: tunggu sampai Windows sendiri
        // memilih adapter ini untuk alamat tujuan, baru trafik diuji. Tanpa
        // langkah ini probe bisa gagal dengan "unreachable host" walau
        // rutenya benar.
        wait_route_active(index, PROBE_HOST).await;
        if ipv6.is_some() {
            wait_route_active(index, PROBE_HOST_V6).await;
        }

        let (stop_tx, _) = watch::channel(false);
        let stats = Arc::new(Stats::default());
        let tasks = vec![
            spawn_writer(&session, &tunnel, &stats, &stop_tx),
            spawn_reader(&session, &tunnel, &stats),
        ];

        let vpn = Self {
            stop: stop_tx,
            tasks,
            session,
            _tunnel: tunnel,
            routes,
            stats,
            _wintun: wintun,
            has_v6: ipv6.is_some(),
            mtu,
        };

        if let Err(e) = vpn.verify().await {
            let _ = vpn.down().await;
            return Err(e);
        }
        Ok(vpn)
    }

    /// Buktikan paket benar-benar keluar-masuk tunnel: satu koneksi TCP ke
    /// alamat publik. DNS tidak dipakai di sini karena resolver sistem masih
    /// menunjuk proxy lokal pada tahap ini.
    async fn verify(&self) -> Result<(), String> {
        let deadline = tokio::time::Instant::now() + PROBE_TIMEOUT;
        let mut last = "timeout".to_string();
        while tokio::time::Instant::now() < deadline {
            if let Err(e) = tcp_probe(PROBE_ADDR).await {
                last = e;
            } else if self.has_v6
                && let Err(e) = tcp_probe(PROBE_ADDR_V6).await
            {
                last = format!("IPv6: {e}");
            } else {
                return Ok(());
            }
            // Percobaan pertama bisa kalah cepat dari pembaruan tabel rute;
            // ulangi selama masih ada waktu.
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        Err(format!(
            "tunnel tidak meneruskan trafik ({PROBE_ADDR}: {last}) — rute VPN dicabut"
        ))
    }

    pub fn counters(&self) -> (u64, u64) {
        (
            self.stats.up.load(Ordering::Relaxed),
            self.stats.down.load(Ordering::Relaxed),
        )
    }

    pub fn routes(&self) -> &win::SavedVpn {
        &self.routes
    }

    /// Matikan tunnel dengan urutan yang sama pentingnya: hentikan aliran
    /// paket, cabut rute, baru hapus adapter.
    pub async fn down(self) -> Result<String, String> {
        let _ = self.stop.send(true);
        let _ = self.session.shutdown();
        for task in self.tasks {
            let _ = tokio::time::timeout(SHUTDOWN_GRACE, task).await;
        }
        win::vpn_remove_routes(&self.routes)?;
        win::vpn_clear_state();
        delete_adapter(&self._wintun);
        Ok(format!(
            "VPN dimatikan — {} rute dicabut",
            self.routes.routes.len()
        ))
    }
}

/// Matikan VPN berdasarkan catatan di disk. Dipakai `mydns vpn off`, watchdog,
/// dan pemulihan saat logon — jalur yang tidak punya objek [`Vpn`] hidup.
pub fn down_persisted() -> Result<String, String> {
    let saved = win::vpn_saved();
    // Adapter dihapus lebih dulu: rute yang menempel padanya ikut hilang, lalu
    // sisa rute eksplisit dibersihkan.
    if let Ok(wintun) = load_wintun() {
        delete_adapter(&wintun);
    }
    match saved {
        Some(saved) => {
            win::vpn_remove_routes(&saved)?;
            win::vpn_clear_state();
            Ok(format!(
                "rute VPN dicabut ({} rute, adapter {})",
                saved.routes.len(),
                saved.adapter
            ))
        }
        None => Ok("VPN tidak sedang aktif".to_string()),
    }
}

/// Hasil `/cdn-cgi/trace`: IP keluar yang dilihat internet, kode PoP Cloudflare
/// yang melayani jalur itu (`colo`, mis. `SIN`), dan negara yang Cloudflare
/// kaitkan dengan IP tersebut (`loc`, mis. `SG`).
///
/// `colo` dan `loc` penting karena WARP tidak punya pemilih lokasi: hanya angka
/// ini yang bisa menjelaskan ke pengguna di mana trafiknya keluar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitInfo {
    pub ip: String,
    pub colo: String,
    pub loc: String,
}

impl ExitInfo {
    /// Satu baris untuk CLI dan panel status.
    pub fn label(&self) -> String {
        match (self.colo.is_empty(), self.loc.is_empty()) {
            (true, true) => self.ip.clone(),
            (false, true) => format!("{} · PoP {}", self.ip, self.colo),
            (true, false) => format!("{} · {}", self.ip, self.loc),
            (false, false) => format!("{} · PoP {} ({})", self.ip, self.colo, self.loc),
        }
    }
}

/// IP publik dan lokasi PoP yang terlihat oleh internet saat ini. Dipakai untuk
/// membuktikan tunnel benar-benar mengubah jalur keluar: kalau IP-nya sama
/// sebelum dan sesudah VPN, yang berubah hanya rute di tabel, bukan trafiknya.
///
/// `https://1.1.1.1/cdn-cgi/trace` dipilih karena tidak butuh DNS (alamatnya
/// literal) dan jawabannya baris `ip=...`, `colo=...`, `loc=...`.
pub async fn exit_info() -> Result<ExitInfo, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

    let tcp = tokio::time::timeout(
        Duration::from_secs(6),
        tokio::net::TcpStream::connect("1.1.1.1:443"),
    )
    .await
    .map_err(|_| "timeout koneksi trace".to_string())?
    .map_err(|e| format!("koneksi trace gagal: {e}"))?;
    let name = ServerName::try_from("1.1.1.1").map_err(|_| "nama trace tidak valid".to_string())?;
    let mut tls = tokio::time::timeout(Duration::from_secs(6), connector.connect(name, tcp))
        .await
        .map_err(|_| "timeout TLS trace".to_string())?
        .map_err(|e| format!("TLS trace gagal: {e}"))?;

    tls.write_all(b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n")
        .await
        .map_err(|e| format!("gagal mengirim permintaan trace: {e}"))?;

    let mut raw = Vec::new();
    // Baca satu byte lebih dari batas supaya respons kepanjangan terdeteksi.
    tokio::time::timeout(
        Duration::from_secs(6),
        (&mut tls)
            .take(MAX_TRACE_BYTES as u64 + 1)
            .read_to_end(&mut raw),
    )
    .await
    .map_err(|_| "timeout menunggu trace".to_string())?
    .map_err(|e| format!("gagal membaca trace: {e}"))?;
    if raw.len() > MAX_TRACE_BYTES {
        return Err("respons trace melebihi batas".to_string());
    }

    let text = String::from_utf8_lossy(&raw);
    let ip = trace_field(&text, "ip");
    if ip.is_empty() {
        return Err("jawaban trace tidak memuat ip=".to_string());
    }
    Ok(ExitInfo {
        ip,
        colo: trace_field(&text, "colo"),
        loc: trace_field(&text, "loc"),
    })
}

/// Ambil nilai satu baris `kunci=nilai` dari respons trace. `colo`/`loc` bisa
/// saja tidak dikirim (mis. jalur tanpa WARP), jadi hasil kosong bukan error.
fn trace_field(text: &str, key: &str) -> String {
    let prefix = format!("{key}=");
    text.lines()
        .find_map(|line| line.trim().strip_prefix(prefix.as_str()))
        .map(|value| value.trim().to_string())
        .unwrap_or_default()
}

/// Versi aman untuk watchdog dan pemulihan saat logon: rutevpn dicabut kalau
/// catatan masih ada, terlepas dari siapa yang memakai port 53 — rute mati
/// harus dibersihkan walau resolver lain sedang aktif.
pub fn down_if_stale() -> Result<Option<String>, String> {
    if win::vpn_saved().is_none() {
        return Ok(None);
    }
    down_persisted().map(Some)
}

/// Ringkasan untuk `mydns vpn status` dan `mydns doctor`.
pub fn status() -> String {
    match win::vpn_saved() {
        Some(saved) => {
            let endpoint = if saved.endpoint.is_empty() {
                "-".to_string()
            } else {
                saved.endpoint.clone()
            };
            format!(
                "aktif — adapter {}, {} rute, endpoint {}",
                saved.adapter,
                saved.routes.len(),
                endpoint
            )
        }
        None => "tidak aktif".to_string(),
    }
}

fn spawn_writer(
    session: &Arc<Session>,
    tunnel: &Arc<Tunnel>,
    stats: &Arc<Stats>,
    stop: &watch::Sender<bool>,
) -> JoinHandle<()> {
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1024);
    tunnel.set_raw_sink(tx);
    let session = Arc::clone(session);
    let stats = Arc::clone(stats);
    let mut stop_rx = stop.subscribe();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                changed = stop_rx.changed() => {
                    if changed.is_err() || *stop_rx.borrow() {
                        break;
                    }
                }
                packet = rx.recv() => {
                    let Some(bytes) = packet else { break };
                    if bytes.is_empty() || bytes.len() > u16::MAX as usize {
                        continue;
                    }
                    // Paket yang gagal dialokasikan dibuang; Wintun akan
                    // meminta retransmisi lewat TCP di ujung sana.
                    if let Ok(mut packet) = session.allocate_send_packet(bytes.len() as u16) {
                        packet.bytes_mut().copy_from_slice(&bytes);
                        session.send_packet(packet);
                        stats.down.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
    })
}

fn spawn_reader(
    session: &Arc<Session>,
    tunnel: &Arc<Tunnel>,
    stats: &Arc<Stats>,
) -> JoinHandle<()> {
    let session = Arc::clone(session);
    let tunnel = Arc::clone(tunnel);
    let stats = Arc::clone(stats);
    // `receive_blocking` menahan thread OS, bukan thread async: satu blocking
    // task jauh lebih murah daripada polling ring buffer.
    tokio::task::spawn_blocking(move || {
        // `shutdown()` membuat panggilan ini kembali dengan error.
        while let Ok(packet) = session.receive_blocking() {
            if tunnel.send_ip(packet.bytes()).is_ok() {
                stats.up.fetch_add(1, Ordering::Relaxed);
            }
        }
    })
}

fn create_adapter(wintun: &Wintun) -> Result<Arc<Adapter>, String> {
    // Sisa sesi sebelumnya (mis. crash) dihapus dulu supaya tidak menumpuk
    // adapter dengan nama sama.
    if let Ok(stale) = Adapter::open(wintun, ADAPTER_NAME)
        && let Some(stale) = Arc::into_inner(stale)
    {
        let _ = stale.delete();
    }
    Adapter::create(wintun, ADAPTER_NAME, "MyDNS", None)
        .map_err(|e| format!("gagal membuat adapter TUN: {e}"))
}

fn configure_adapter(adapter: &Arc<Adapter>, ip: Ipv4Addr, mtu: usize) -> Result<(), String> {
    adapter
        .set_address(ip)
        .map_err(|e| format!("gagal memasang alamat tunnel: {e}"))?;
    // Prefix /32: alamat tunnel adalah titik ujung, bukan subnet.
    adapter
        .set_netmask(Ipv4Addr::new(255, 255, 255, 255))
        .map_err(|e| format!("gagal memasang netmask: {e}"))?;
    adapter
        .set_mtu(mtu)
        .map_err(|e| format!("gagal memasang MTU: {e}"))?;
    Ok(())
}

/// Tunggu sampai stack Windows benar-benar memilih adapter kita untuk alamat
/// tujuan. `Find-NetRoute` membaca tabel rute yang sama dengan yang dipakai
/// pengiriman paket, jadi ini bukti yang tepat — bukan sekadar status adapter.
async fn wait_route_active(index: u32, host: &str) {
    for _ in 0..20 {
        let script = format!(
            "$r = Find-NetRoute -RemoteIPAddress {host} -ErrorAction SilentlyContinue | Select-Object -First 1; if ($r) {{ \"$($r.InterfaceIndex)\" }} else {{ '0' }}"
        );
        // `run_ps` mem-block: jalankan di thread blocking supaya worker Tokio
        // tidak macet selama PowerShell hidup.
        let result = tokio::task::spawn_blocking(move || win::run_ps(&script)).await;
        if let Ok(Ok(text)) = result
            && text.trim().parse::<u32>() == Ok(index)
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Diagnostik untuk mengurai kegagalan rute di mesin nyata (`MYDNS_VPN_DEBUG=1`).
async fn debug_dump(label: &str, index: u32, routes: &win::SavedVpn) {
    if std::env::var("MYDNS_VPN_DEBUG").is_err() {
        return;
    }
    println!("--- {label} (adapter index {index}) ---");
    for route in &routes.routes {
        println!(
            "rute {} via ifIndex {} nexthop {}",
            route.dest, route.iface, route.nexthop
        );
    }
    let script = format!(
        "Get-NetAdapter -InterfaceIndex {index} | Select-Object Name,Status,ifIndex,InterfaceDescription | Format-List
Get-NetIPAddress -InterfaceIndex {index} | Select-Object IPAddress,PrefixLength | Format-Table
Get-NetRoute -InterfaceIndex {index} | Select-Object DestinationPrefix,NextHop,RouteMetric | Format-Table
Get-NetIPInterface -InterfaceIndex {index} | Select-Object NlMtu,InterfaceMetric,ConnectionState | Format-Table"
    );
    // Sama seperti `wait_route_active`: PowerShell dipindah ke thread blocking.
    match tokio::task::spawn_blocking(move || win::run_ps(&script)).await {
        Ok(Ok(text)) => println!("{text}"),
        Ok(Err(e)) => println!("diagnostik gagal: {e}"),
        Err(e) => println!("diagnostik gagal: {e}"),
    }
}

fn delete_adapter(wintun: &Wintun) {
    // `Adapter::delete` memakan nilai, sedangkan `open` mengembalikan Arc.
    // Kalau Arc-nya masih dipakai di tempat lain, adapter memang tidak boleh
    // dihapus dari sini.
    if let Ok(adapter) = Adapter::open(wintun, ADAPTER_NAME)
        && let Some(adapter) = Arc::into_inner(adapter)
    {
        let _ = adapter.delete();
    }
}

/// SHA-256 dari `assets/wintun.dll` yang dibundel. Memuat DLL dari folder yang
/// bisa ditulis user tanpa pin hash berarti user lokal bisa menanam DLL dan
/// mendapat eksekusi kode saat VPN dinyalakan elevated.
const WINTUN_SHA256: &str = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce";

fn verify_wintun(path: &std::path::Path) -> Result<(), String> {
    let bytes =
        std::fs::read(path).map_err(|e| format!("tidak bisa membaca {}: {e}", path.display()))?;
    let digest = ring::digest::digest(&ring::digest::SHA256, &bytes);
    let actual = digest
        .as_ref()
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            use std::fmt::Write;
            let _ = write!(out, "{byte:02x}");
            out
        });
    if actual != WINTUN_SHA256 {
        return Err(format!(
            "{} bukan wintun.dll yang dibundel (sha256 {actual})",
            path.display()
        ));
    }
    Ok(())
}

/// Wintun adalah driver pihak ketiga, jadi DLL-nya dicari berurutan: di samping
/// `mydns.exe`, di subfolder `assets`, lalu folder proyek saat dijalankan lewat
/// `cargo run`.
fn load_wintun() -> Result<Wintun, String> {
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        candidates.push(dir.join("wintun.dll"));
        candidates.push(dir.join("assets").join("wintun.dll"));
    }
    candidates.push(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("assets")
            .join("wintun.dll"),
    );

    for path in candidates {
        if !path.exists() {
            continue;
        }
        // shortcut: hash diverifikasi dari path lalu path dibuka ulang (TOCTOU); upgrade: verifikasi handle yang sudah terbuka / muat dari folder non-user-writable.
        verify_wintun(&path)?;
        return unsafe { wintun::load_from_path(&path) }
            .map_err(|e| format!("gagal memuat {}: {e}", path.display()));
    }
    Err("wintun.dll tidak ditemukan — letakkan di folder yang sama dengan mydns.exe".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_membaca_ip_colo_dan_loc() {
        let raw = "HTTP/1.1 200 OK\r\nserver: cloudflare\r\n\r\nip=104.28.215.130\nloc=ID\ncolo=CGK\nwarp=on\n";
        assert_eq!(trace_field(raw, "ip"), "104.28.215.130");
        assert_eq!(trace_field(raw, "colo"), "CGK");
        assert_eq!(trace_field(raw, "loc"), "ID");
        assert_eq!(trace_field(raw, "warp"), "on");
    }

    #[test]
    fn label_exit_info_menyertakan_pop_dan_negara() {
        let full = ExitInfo {
            ip: "104.28.215.130".to_string(),
            colo: "SIN".to_string(),
            loc: "SG".to_string(),
        };
        assert_eq!(full.label(), "104.28.215.130 · PoP SIN (SG)");
        let ip_only = ExitInfo {
            ip: "104.28.215.130".to_string(),
            colo: String::new(),
            loc: String::new(),
        };
        assert_eq!(ip_only.label(), "104.28.215.130");
    }

    #[test]
    fn alamat_ipv6_warp_menerima_prefiks() {
        assert_eq!(
            tunnel_ipv6("2606:4700:110:8a1b::1/128").as_deref(),
            Some("2606:4700:110:8a1b::1")
        );
        assert_eq!(
            tunnel_ipv6(" 2606:4700:110::2 ").as_deref(),
            Some("2606:4700:110::2")
        );
        assert_eq!(tunnel_ipv6(""), None);
        assert_eq!(tunnel_ipv6("1.2.3.4"), None);
    }
}
