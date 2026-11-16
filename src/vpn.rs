//! Mode VPN penuh: seluruh trafik IPv4 dibawa lewat tunnel WARP MASQUE.
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
use std::net::Ipv4Addr;
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
const PROBE_ADDR: &str = "1.1.1.1:443";
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
/// Batas waktu menunggu task pembaca paket berhenti saat tunnel dimatikan.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(3);

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
    pub mtu: usize,
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
        let mtu = tunnel.max_datagram().saturating_sub(8).clamp(576, MTU_MAX);
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

        let routes = match win::vpn_install_routes(
            ADAPTER_NAME,
            index,
            tunnel
                .endpoint_ip()
                .as_ref()
                .map(|ip| ip.to_string())
                .as_deref(),
        ) {
            Ok(routes) => routes,
            Err(e) => {
                let _ = session.shutdown();
                delete_adapter(&wintun);
                return Err(e);
            }
        };

        debug_dump("setelah rute dipasang", index, &routes);
        // Rute baru belum langsung dipakai stack: tunggu sampai Windows sendiri
        // memilih adapter ini untuk alamat tujuan, baru trafik diuji. Tanpa
        // langkah ini probe bisa gagal dengan "unreachable host" walau
        // rutenya benar.
        wait_route_active(index, PROBE_ADDR).await;

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
            match tokio::time::timeout(
                Duration::from_secs(2),
                tokio::net::TcpStream::connect(PROBE_ADDR),
            )
            .await
            {
                Ok(Ok(_)) => return Ok(()),
                Ok(Err(e)) => last = e.to_string(),
                Err(_) => last = "timeout".to_string(),
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
        win::vpn_remove_routes(&self.routes);
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
            win::vpn_remove_routes(&saved);
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

/// IP publik yang terlihat oleh internet saat ini. Dipakai untuk membuktikan
/// tunnel benar-benar mengubah jalur keluar: kalau angkanya sama sebelum dan
/// sesudah VPN, yang berubah hanya rute di tabel, bukan trafiknya.
///
/// `https://1.1.1.1/cdn-cgi/trace` dipilih karena tidak butuh DNS (alamatnya
/// literal) dan jawabannya satu baris `ip=...`.
pub async fn exit_ip() -> Result<String, String> {
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
    tokio::time::timeout(Duration::from_secs(6), tls.read_to_end(&mut raw))
        .await
        .map_err(|_| "timeout menunggu trace".to_string())?
        .map_err(|e| format!("gagal membaca trace: {e}"))?;

    let text = String::from_utf8_lossy(&raw);
    text.lines()
        .find_map(|line| line.trim().strip_prefix("ip="))
        .map(|ip| ip.trim().to_string())
        .ok_or_else(|| "jawaban trace tidak memuat ip=".to_string())
}

/// Versi aman untuk watchdog dan pemulihan saat logon: hanya membersihkan
/// kalau catatan VPN ada **dan** tidak ada proxy yang sedang melayani port 53.
/// Sesi yang masih hidup tidak boleh diganggu.
pub fn down_if_stale() -> Result<Option<String>, String> {
    if win::vpn_saved().is_none() || !win::port53_free() {
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
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
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
async fn wait_route_active(index: u32, destination: &str) {
    let host = destination
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(destination);
    for _ in 0..20 {
        let script = format!(
            "$r = Find-NetRoute -RemoteIPAddress {host} -ErrorAction SilentlyContinue | Select-Object -First 1; if ($r) {{ \"$($r.InterfaceIndex)\" }} else {{ '0' }}"
        );
        if let Ok(text) = win::run_ps(&script)
            && text.trim().parse::<u32>() == Ok(index)
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Diagnostik untuk mengurai kegagalan rute di mesin nyata (`MYDNS_VPN_DEBUG=1`).
fn debug_dump(label: &str, index: u32, routes: &win::SavedVpn) {
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
    match win::run_ps(&script) {
        Ok(text) => println!("{text}"),
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
        // Aman: berkas yang dimuat adalah DLL yang disertakan bersama program.
        return unsafe { wintun::load_from_path(&path) }
            .map_err(|e| format!("gagal memuat {}: {e}", path.display()));
    }
    Err("wintun.dll tidak ditemukan — letakkan di folder yang sama dengan mydns.exe".to_string())
}
