//! Integrasi DNS Windows: deteksi adapter, set/reset server DNS, elevasi UAC.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

/// Proses anak (powershell, ipconfig, schtasks) tidak boleh memunculkan jendela
/// hitam, terutama kalau kita sendiri sudah tidak punya konsol.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
/// Dipakai watchdog: lepas total dari konsol induk supaya tidak ikut mati saat
/// jendela terminal ditutup atau proses induk dibunuh.
const DETACHED_PROCESS: u32 = 0x0000_0008;
/// Nama Scheduled Task yang memulihkan DNS setelah reboot.
const TASK_NAME: &str = "MyDNS DNS Recovery";

/// Adapter yang punya default route (artinya adapter yang dipakai internet).
#[derive(Clone, Debug)]
pub struct Adapter {
    pub index: u32,
    pub name: String,
    pub v4: Vec<String>,
    pub v6: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SavedIface {
    pub name: String,
    pub v4: Vec<String>,
    pub v6: Vec<String>,
}

/// Kondisi DNS asli sebelum kita menimpanya. Disimpan ke disk supaya
/// "Clear DNS" (atau crash) tetap bisa mengembalikan setelan sebenarnya.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Saved {
    pub provider: String,
    pub saved_at: u64,
    pub ifaces: BTreeMap<String, SavedIface>,
}

pub fn state_path() -> PathBuf {
    let base = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
    PathBuf::from(base).join("MyDns").join("state.json")
}

pub fn load_state() -> Option<Saved> {
    let raw = std::fs::read_to_string(state_path()).ok()?;
    serde_json::from_str(&raw).ok()
}

pub fn save_state(s: &Saved) -> Result<(), String> {
    let path = state_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("gagal membuat {}: {e}", dir.display()))?;
    }
    let raw = serde_json::to_string_pretty(s).map_err(|e| e.to_string())?;
    std::fs::write(&path, raw).map_err(|e| format!("gagal menulis {}: {e}", path.display()))
}

pub fn clear_state() {
    let _ = std::fs::remove_file(state_path());
}

fn run_ps(script: &str) -> Result<String, String> {
    // Paksa UTF-8 supaya nama adapter non-ASCII tidak muncul sebagai mojibake.
    let full = format!("$OutputEncoding=[Console]::OutputEncoding=[Text.Encoding]::UTF8\n{script}");
    let out = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
        ])
        .arg("-Command")
        .arg(&full)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("tidak bisa menjalankan powershell: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!("powershell gagal: {}", err.trim()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

// Tiga cmdlet untuk semua adapter sekaligus (bukan 2xN). Setiap pemanggilan
// PowerShell mahal (~0,5 s), jadi jumlahnya dijaga minimum.
const LIST_SCRIPT: &str = r#"
$rt = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0','::/0' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ifIndex -Unique)
$adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })
$dns = @(Get-DnsClientServerAddress -ErrorAction SilentlyContinue)
$out = @()
foreach ($ix in $rt) {
  $a = $adapters | Where-Object { $_.ifIndex -eq $ix } | Select-Object -First 1
  if (-not $a) { continue }
  $v4 = @($dns | Where-Object { $_.InterfaceIndex -eq $ix -and [int]$_.AddressFamily -eq 2 } | ForEach-Object { $_.ServerAddresses })
  $v6 = @($dns | Where-Object { $_.InterfaceIndex -eq $ix -and [int]$_.AddressFamily -eq 23 } | ForEach-Object { $_.ServerAddresses })
  $out += [pscustomobject]@{ index = "$ix"; name = $a.Name; v4 = ($v4 -join '|'); v6 = ($v6 -join '|') }
}
@($out) | ConvertTo-Json -Compress -Depth 3
"#;

/// Daftar adapter aktif beserta DNS-nya sekarang.
///
/// Jalur utama memakai IP Helper API (satu panggilan, ~1 ms). Jalur PowerShell
/// dipertahankan sebagai cadangan kalau API itu tidak memberi hasil.
pub fn list_adapters() -> Result<Vec<Adapter>, String> {
    if let Some(mut adapters) = list_adapters_fast() {
        adapters.sort_by_key(|a| a.index);
        return Ok(adapters);
    }
    list_adapters_slow()
}

/// Baca adapter langsung dari `GetAdaptersAddresses`: adapter yang Up dan punya
/// gateway (jadi jalur internet), lengkap dengan daftar DNS-nya.
fn list_adapters_fast() -> Option<Vec<Adapter>> {
    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST,
        GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;

    const AF_UNSPEC: u32 = 0;
    const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_INCLUDE_GATEWAYS;

    let mut size: u32 = 32 * 1024;
    // Vec<u64> menjamin penyelarasan 8 byte yang diminta struct Windows.
    let mut buffer: Vec<u64> = Vec::new();
    let mut filled = false;
    for _ in 0..4 {
        buffer.resize((size as usize).div_ceil(8), 0);
        let code = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC,
                flags,
                std::ptr::null(),
                buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut size,
            )
        };
        if code == NO_ERROR {
            filled = true;
            break;
        }
        if code != ERROR_BUFFER_OVERFLOW {
            return None;
        }
    }
    if !filled {
        return None;
    }

    let mut adapters = Vec::new();
    let mut cursor = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !cursor.is_null() {
        // SAFETY: GetAdaptersAddresses mengisi daftar bertautan di buffer kita.
        let info = unsafe { &*cursor };
        let usable = info.OperStatus == IfOperStatusUp
            && !info.FirstGatewayAddress.is_null()
            && info.IfType != IF_TYPE_SOFTWARE_LOOPBACK;
        if usable {
            let mut v4 = Vec::new();
            let mut v6 = Vec::new();
            let mut entry = info.FirstDnsServerAddress;
            while !entry.is_null() {
                // SAFETY: setiap node dalam daftar diisi oleh API yang sama.
                let node = unsafe { &*entry };
                if let Some(ip) = unsafe { sockaddr_ip(node.Address.lpSockaddr) } {
                    match ip {
                        IpAddr::V4(addr) => v4.push(addr.to_string()),
                        IpAddr::V6(addr) => {
                            if !addr.is_unicast_link_local() {
                                v6.push(addr.to_string());
                            }
                        }
                    }
                }
                entry = node.Next;
            }
            adapters.push(Adapter {
                index: unsafe { info.Anonymous1.Anonymous.IfIndex },
                name: unsafe { wide_string(info.FriendlyName) },
                v4,
                v6,
            });
        }
        cursor = info.Next;
    }

    if adapters.is_empty() {
        None
    } else {
        Some(adapters)
    }
}

/// Baca string UTF-16 berakhiran NUL dari pointer Windows.
unsafe fn wide_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
        if len > 4096 {
            break;
        }
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    String::from_utf16_lossy(slice)
}

/// Terjemahkan `sockaddr` (IPv4/IPv6) jadi `IpAddr`.
/// Offset dibaca langsung dari memori karena layout sockaddr dijamin ABIs Winsock:
/// IPv4 → alamat di byte 4..8, IPv6 → alamat di byte 8..24.
unsafe fn sockaddr_ip(
    sa: *const windows_sys::Win32::Networking::WinSock::SOCKADDR,
) -> Option<IpAddr> {
    if sa.is_null() {
        return None;
    }
    let base = sa as *const u8;
    match unsafe { (*sa).sa_family } {
        2 => {
            let mut octets = [0u8; 4];
            unsafe { std::ptr::copy_nonoverlapping(base.add(4), octets.as_mut_ptr(), 4) };
            Some(IpAddr::V4(octets.into()))
        }
        23 => {
            let mut octets = [0u8; 16];
            unsafe { std::ptr::copy_nonoverlapping(base.add(8), octets.as_mut_ptr(), 16) };
            Some(IpAddr::V6(octets.into()))
        }
        _ => None,
    }
}

fn list_adapters_slow() -> Result<Vec<Adapter>, String> {
    let raw = run_ps(LIST_SCRIPT)?;
    if raw.is_empty() || raw == "null" {
        return Ok(Vec::new());
    }
    let value: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("gagal membaca output PowerShell: {e}"))?;
    let items = match value {
        serde_json::Value::Array(a) => a,
        other => vec![other],
    };
    let mut out = Vec::new();
    for item in items {
        let index = item
            .get("index")
            .and_then(|v| v.as_str())
            .and_then(|s| s.trim().parse::<u32>().ok());
        let Some(index) = index else { continue };
        let name = item
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string();
        out.push(Adapter {
            index,
            name,
            v4: split_list(item.get("v4")),
            v6: split_list(item.get("v6")),
        });
    }
    Ok(out)
}

/// Alamat IPv6 link-local tidak pernah berguna sebagai resolver, dan Windows
/// melaporkannya untuk hampir setiap adapter. Jalur FFI sudah membuangnya, dan
/// jalur PowerShell harus memakai aturan yang sama persis.
fn is_link_local(server: &str) -> bool {
    match server.parse::<IpAddr>() {
        Ok(IpAddr::V6(addr)) => addr.is_unicast_link_local(),
        Ok(IpAddr::V4(_)) => false,
        // PowerShell kadang menambahkan zone id (`fe80::1%12`) yang tidak bisa
        // diparse sebagai IpAddr.
        Err(_) => server.to_ascii_lowercase().starts_with("fe80:"),
    }
}

/// Baca daftar DNS dari keluaran JSON PowerShell. Sebagian versi mengirim array,
/// sebagian lagi satu string bergabung dengan `|`.
fn split_list(value: Option<&serde_json::Value>) -> Vec<String> {
    let Some(value) = value else {
        return Vec::new();
    };
    let raw: Vec<&str> = match value {
        serde_json::Value::String(text) => text.split('|').collect(),
        serde_json::Value::Array(items) => items.iter().filter_map(|v| v.as_str()).collect(),
        _ => Vec::new(),
    };
    raw.iter()
        .map(|server| server.trim())
        .filter(|server| !server.is_empty() && !is_link_local(server))
        .map(str::to_string)
        .collect()
}

fn quote_list(values: &[String]) -> String {
    values
        .iter()
        .map(|v| format!("'{v}'"))
        .collect::<Vec<_>>()
        .join(",")
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Arahkan DNS semua adapter aktif ke proxy lokal kita.
/// DNS asli dicatat lebih dulu; pencatatan lama tidak ditimpa supaya
/// mengklik provider dua kali tidak menghapus setelan asli.
pub fn apply(provider_id: &str) -> Result<Vec<Adapter>, String> {
    require_admin()?;
    let adapters = list_adapters()?;
    if adapters.is_empty() {
        return Err("tidak menemukan adapter jaringan yang aktif".to_string());
    }

    let mut saved = load_state().unwrap_or_default();
    saved.provider = provider_id.to_string();
    saved.saved_at = now_secs();
    for a in &adapters {
        saved
            .ifaces
            .entry(a.index.to_string())
            .or_insert_with(|| SavedIface {
                name: a.name.clone(),
                v4: a.v4.clone(),
                v6: a.v6.clone(),
            });
    }
    save_state(&saved)?;

    let mut script = String::from("$ok=@(); $bad=@()\n");
    for a in &adapters {
        script.push_str(&format!(
            "try {{ Set-DnsClientServerAddress -InterfaceIndex {} -ServerAddresses '127.0.0.1' -ErrorAction Stop; $ok += '{}' }} catch {{ $bad += \"{}: $($_.Exception.Message)\" }}\n",
            a.index, a.index, a.index
        ));
        script.push_str(&format!(
            "try {{ Set-DnsClientServerAddress -InterfaceIndex {} -ServerAddresses '::1' -ErrorAction Stop }} catch {{ }}\n",
            a.index
        ));
    }
    script.push_str("@{ok=$ok; bad=$bad} | ConvertTo-Json -Compress\n");

    let raw = run_ps(&script)?;
    let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap_or_default();
    // ConvertTo-Json bisa menghasilkan array atau nilai tunggal tergantung
    // jumlah adapter, jadi keduanya harus diterima.
    let ok_count = match parsed.get("ok") {
        Some(serde_json::Value::Array(items)) => items.len(),
        Some(serde_json::Value::String(text)) if !text.is_empty() => 1,
        Some(serde_json::Value::Number(_)) => 1,
        _ => 0,
    };
    if ok_count == 0 {
        let bad = raw;
        return Err(format!("gagal mengubah DNS adapter: {bad}"));
    }

    flush_dns();
    Ok(adapters)
}

/// Kembalikan DNS ke kondisi asli (DHCP atau server statis sebelumnya).
pub fn restore() -> Result<String, String> {
    require_admin()?;
    let saved = load_state();
    let adapters = list_adapters()?;

    let mut script = String::new();
    let mut touched = 0usize;

    match &saved {
        Some(s) if !s.ifaces.is_empty() => {
            for (index, iface) in &s.ifaces {
                let has_v4 = !iface.v4.is_empty();
                let has_v6 = !iface.v6.is_empty();
                // Reset ke DHCP hanya perlu kalau aslinya memang DHCP, atau kalau
                // salah satu family kosong (supaya sisa 127.0.0.1 / ::1 hilang).
                // Kalau dua-duanya statis, cukup ditimpa — lebih tepat ke aslinya.
                if (!has_v4 && !has_v6) || (has_v4 != has_v6) {
                    script.push_str(&format!(
                        "Set-DnsClientServerAddress -InterfaceIndex {index} -ResetServerAddresses -ErrorAction SilentlyContinue\n"
                    ));
                }
                if has_v4 {
                    script.push_str(&format!(
                        "Set-DnsClientServerAddress -InterfaceIndex {index} -ServerAddresses {} -ErrorAction SilentlyContinue\n",
                        quote_list(&iface.v4)
                    ));
                }
                if has_v6 {
                    script.push_str(&format!(
                        "Set-DnsClientServerAddress -InterfaceIndex {index} -ServerAddresses {} -ErrorAction SilentlyContinue\n",
                        quote_list(&iface.v6)
                    ));
                }
                touched += 1;
            }
            script.push_str("'ok'\n");
        }
        _ => {
            // Tidak ada catatan: reset semua adapter yang masih menunjuk loopback.
            for a in &adapters {
                if a.v4.iter().any(|s| s == "127.0.0.1") || a.v6.iter().any(|s| s == "::1") {
                    script.push_str(&format!(
                        "Set-DnsClientServerAddress -InterfaceIndex {} -ResetServerAddresses -ErrorAction SilentlyContinue\n",
                        a.index
                    ));
                    touched += 1;
                }
            }
            script.push_str("'ok'\n");
        }
    }

    if touched == 0 {
        clear_state();
        return Ok(
            "DNS sudah kembali ke setelan default (tidak ada yang perlu diubah)".to_string(),
        );
    }

    run_ps(&script)?;
    flush_dns();
    clear_state();
    Ok(format!("DNS dipulihkan pada {touched} adapter"))
}

/// True kalau ada adapter aktif yang DNS-nya tidak lagi menunjuk proxy lokal.
/// Ini yang terjadi setelah pindah Wi-Fi/VPN atau bangun dari sleep: DHCP
/// menimpa setelan kita, dan tanpa ini query akan diam-diam melewati filter.
pub fn loopback_missing() -> bool {
    match list_adapters() {
        Ok(adapters) => adapters
            .iter()
            .any(|a| !a.v4.iter().any(|server| server == "127.0.0.1")),
        Err(_) => false,
    }
}

/// Port 53 loopback bebas berarti tidak ada proxy MyDNS yang sedang melayani.
pub fn port53_free() -> bool {
    let Ok(udp) = std::net::UdpSocket::bind("127.0.0.1:53") else {
        return false;
    };
    drop(udp);
    std::net::TcpListener::bind("127.0.0.1:53").is_ok()
}

/// Pulihkan hanya kalau catatan masih ada **dan** tidak ada yang melayani
/// port 53. Dipakai saat logon dan oleh watchdog: kalau pengguna sudah membuka
/// sesi baru, DNS milik sesi itu tidak boleh ditimpa.
pub fn restore_if_stale() -> Result<Option<String>, String> {
    if load_state().is_none() || !port53_free() {
        return Ok(None);
    }
    restore().map(Some)
}

/// Tunggu proses lain benar-benar selesai. `false` kalau prosesnya sudah tidak
/// ada saat hendak dibuka.
pub fn wait_for_process(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{OpenProcess, WaitForSingleObject};

    // Hak akses standar untuk menunggu handle (tidak diekspor windows-sys di
    // modul Foundation, jadi ditulis langsung).
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const INFINITE: u32 = 0xFFFF_FFFF;
    unsafe {
        let handle = OpenProcess(SYNCHRONIZE, 0, pid);
        if handle.is_null() {
            return false;
        }
        let code = WaitForSingleObject(handle, INFINITE);
        CloseHandle(handle);
        code == WAIT_OBJECT_0
    }
}

/// Jalankan pendamping kecil yang memulihkan DNS kalau proses induk mati tanpa
/// sempat membersihkan (Task Manager, crash, listrik putus). Proses ini tidak
/// pernah memunculkan jendela dan tidak pernah mengubah apa pun selama induk
/// masih hidup.
pub fn spawn_watchdog() {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let _ = Command::new(exe)
        .arg("--watchdog")
        .arg(std::process::id().to_string())
        .creation_flags(DETACHED_PROCESS)
        .spawn();
}

/// Pastikan resolver sistem benar-benar menjawab setelah DNS diubah. Dipakai
/// untuk membatalkan penerapan secara otomatis kalau hasilnya tidak terpakai.
///
/// Jalur cepatnya `getaddrinfo` Windows lewat `to_socket_addrs` — jalur yang
/// sama dengan yang dipakai aplikasi lain, dan selesai dalam milidetik, bukan
/// ~0,6 detik seperti memanggil PowerShell. Kalau itu gagal, hasilnya
/// dikonfirmasi ulang dengan `Resolve-DnsName` sebelum DNS dinyatakan rusak:
/// memulihkan DNS padahal hanya ada gangguan sesaat jauh lebih merugikan
/// daripada satu pemeriksaan tambahan di jalur kegagalan.
pub fn verify_resolution() -> Result<(), String> {
    if system_resolves("example.com") {
        return Ok(());
    }
    run_ps("$null = Resolve-DnsName example.com -Type A -ErrorAction Stop; 'ok'")
        .map(|_| ())
        .map_err(|e| format!("getaddrinfo gagal, lalu {e}"))
}

/// Resolusi lewat tumpukan resolver Windows (termasuk DNS Client cache), tanpa
/// proses tambahan. Port 443 hanya pilihan bebas; yang dipakai hanya alamatnya.
fn system_resolves(host: &str) -> bool {
    use std::net::ToSocketAddrs;
    (host, 443u16)
        .to_socket_addrs()
        .map(|mut addrs| addrs.next().is_some())
        .unwrap_or(false)
}

/// Apakah pemulihan otomatis saat logon sudah terdaftar.
pub fn autostart_enabled() -> bool {
    Command::new("schtasks")
        .args(["/Query", "/TN", TASK_NAME])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

/// Apakah task pemulihan masih menunjuk berkas exe yang sekarang berjalan.
/// `None` kalau XML-nya tidak bisa dibaca, supaya doctor tidak memberi
/// peringatan palsu hanya karena format keluaran schtasks berbeda.
pub fn autostart_target_valid() -> Option<bool> {
    let exe = std::env::current_exe().ok()?.to_string_lossy().to_string();
    let out = Command::new("schtasks")
        .args(["/Query", "/TN", TASK_NAME, "/XML"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let xml = decode_console(&out.stdout);
    if xml.is_empty() {
        return None;
    }
    Some(xml.contains(&exe))
}

/// Keluaran alat konsol Windows bisa UTF-16LE atau UTF-8 tergantung versi.
fn decode_console(bytes: &[u8]) -> String {
    let utf16 = bytes.len() > 4 && bytes[1] == 0 && bytes[3] == 0;
    if utf16 {
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(bytes).to_string()
    }
}

/// Daftarkan/lepaskan Scheduled Task yang menjalankan `restore --if-stale`
/// setiap logon. Berjalan dengan hak tertinggi, jadi tidak memunculkan UAC.
pub fn autostart_set(enabled: bool) -> Result<String, String> {
    require_admin()?;
    let output = if enabled {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let action = format!("\"{}\" restore --if-stale", exe.display());
        Command::new("schtasks")
            .args([
                "/Create", "/F", "/SC", "ONLOGON", "/RL", "HIGHEST", "/DELAY", "0000:15", "/TN",
                TASK_NAME, "/TR", &action,
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
    } else {
        Command::new("schtasks")
            .args(["/Delete", "/F", "/TN", TASK_NAME])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
    };

    let output = output.map_err(|e| format!("tidak bisa menjalankan schtasks: {e}"))?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(format!("schtasks gagal: {}", err.trim()));
    }
    Ok(if enabled {
        "pemulihan saat logon aktif — DNS yang tertinggal akan dikembalikan otomatis".to_string()
    } else {
        "pemulihan saat logon dimatikan".to_string()
    })
}

pub fn flush_dns() {
    let _ = Command::new("ipconfig")
        .arg("/flushdns")
        .creation_flags(CREATE_NO_WINDOW)
        .output();
}

/// Ringkasan singkat DNS yang sedang dipakai, untuk header TUI / `status`.
pub fn summary() -> String {
    match list_adapters() {
        Ok(adapters) if !adapters.is_empty() => adapters
            .iter()
            .map(|a| {
                let servers = if a.v4.is_empty() {
                    "DHCP".to_string()
                } else {
                    a.v4.join(", ")
                };
                format!("{} → {}", a.name, servers)
            })
            .collect::<Vec<_>>()
            .join("  |  "),
        Ok(_) => "tidak ada adapter aktif".to_string(),
        Err(e) => e,
    }
}

/// Tanpa hak admin, perintah PowerShell akan gagal diam-diam; lebih baik
/// menolak terang-terangan daripada melaporkan "berhasil" palsu.
fn require_admin() -> Result<(), String> {
    if is_elevated() {
        Ok(())
    } else {
        Err(
            "perubahan DNS butuh hak administrator — jalankan dari terminal yang elevated"
                .to_string(),
        )
    }
}

pub fn is_elevated() -> bool {
    unsafe {
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
        use windows_sys::Win32::Security::{
            GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
        let mut len: u32 = 0;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut core::ffi::c_void,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

/// Dipanggil Windows saat jendela konsol ditutup, logoff, atau Ctrl+C.
/// Tanpa ini, menutup terminal bisa meninggalkan DNS menunjuk ke proxy mati.
unsafe extern "system" fn exit_handler(_ctrl_type: u32) -> i32 {
    if load_state().is_some() {
        let _ = restore();
    }
    1
}

pub fn install_exit_guard() {
    unsafe {
        use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
        SetConsoleCtrlHandler(Some(exit_handler), 1);
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Jalankan ulang aplikasi lewat prompt UAC.
pub fn relaunch_elevated(args: &[String]) -> Result<(), String> {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let params = args
        .iter()
        .map(|a| {
            if a.contains(' ') {
                format!("\"{a}\"")
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ");

    let file = wide(&exe.to_string_lossy());
    let params = wide(&params);
    let verb = wide("runas");

    let ret = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            params.as_ptr(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    // ShellExecuteW mengembalikan nilai > 32 kalau berhasil.
    if ret as isize <= 32 {
        return Err("UAC dibatalkan atau gagal menaikkan hak akses".to_string());
    }
    Ok(())
}
