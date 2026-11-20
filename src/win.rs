//! Integrasi DNS Windows: deteksi adapter, set/reset server DNS, elevasi UAC.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

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
    /// Rute dan adapter tunnel yang sedang dipasang. Ikut disimpan supaya
    /// setelah crash/reboot internet bisa dipulihkan tanpa menebak-nebak.
    #[serde(default)]
    pub vpn: Option<SavedVpn>,
}

/// Satu rute yang dipasang mode VPN penuh.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SavedRoute {
    pub dest: String,
    pub iface: u32,
    pub nexthop: String,
}

/// Keadaan tunnel VPN yang perlu dicabut kembali.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct SavedVpn {
    pub adapter: String,
    pub endpoint: String,
    pub routes: Vec<SavedRoute>,
    /// Alamat IPv6 yang dipasang di adapter. Kosong kalau WARP tidak memberi
    /// alamat v6 atau jalur v6 tidak tersedia.
    #[serde(default)]
    pub ipv6: String,
}

/// Folder state. `SHGetKnownFolderPath` tidak bisa dibelokkan lewat environment
/// seperti `%ProgramData%`, jadi user lokal tidak bisa mengarahkan state ke
/// folder miliknya sebelum proses elevated menulis.
fn program_data() -> PathBuf {
    static CACHE: OnceLock<PathBuf> = OnceLock::new();
    CACHE
        .get_or_init(|| {
            use windows_sys::Win32::System::Com::CoTaskMemFree;
            use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath};

            let mut ptr: *mut u16 = std::ptr::null_mut();
            let hr = unsafe {
                SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, std::ptr::null_mut(), &mut ptr)
            };
            if hr >= 0 && !ptr.is_null() {
                let path = unsafe { wide_string(ptr) };
                unsafe { CoTaskMemFree(ptr as *const std::ffi::c_void) };
                if !path.is_empty() {
                    return PathBuf::from(path);
                }
            }
            let base =
                std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
            PathBuf::from(base)
        })
        .clone()
}

pub fn state_path() -> PathBuf {
    program_data().join("MyDns").join("state.json")
}

/// State hanya boleh berisi alamat IP yang valid. Ini pertahanan kedua setelah
/// escaping: nilai aneh tidak pernah mencapai skrip PowerShell elevated.
fn state_valid(s: &Saved) -> bool {
    let ifaces_ok = s.ifaces.values().all(|iface| {
        iface
            .v4
            .iter()
            .chain(iface.v6.iter())
            .all(|server| server.parse::<IpAddr>().is_ok())
    });
    let vpn_ok = s.vpn.as_ref().is_none_or(|vpn| {
        vpn.routes.iter().all(|route| {
            let Some((ip, prefix)) = route.dest.split_once('/') else {
                return false;
            };
            let (Ok(ip), Ok(prefix)) = (ip.parse::<IpAddr>(), prefix.parse::<u8>()) else {
                return false;
            };
            let max = if ip.is_ipv4() { 32 } else { 128 };
            prefix <= max && route.nexthop.parse::<IpAddr>().is_ok()
        })
    });
    ifaces_ok && vpn_ok
}

pub fn load_state() -> Option<Saved> {
    let raw = std::fs::read_to_string(state_path()).ok()?;
    let saved: Saved = serde_json::from_str(&raw).ok()?;
    if !state_valid(&saved) {
        crate::log::event("state.json berisi nilai yang tidak valid — diabaikan");
        return None;
    }
    Some(saved)
}

/// Buat direktori state hanya bisa ditulis SYSTEM/Administrators. Authenticated
/// Users tetap bisa membaca untuk `mydns status`, tetapi tidak bisa menanam
/// state palsu yang nanti dijalankan proses elevated.
fn harden_state_dir(dir: &Path) -> Result<(), String> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, SetFileSecurityW,
    };

    const SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;AU)";
    let mut sd: *mut std::ffi::c_void = std::ptr::null_mut();
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide(SDDL).as_ptr(),
            1,
            &mut sd,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(format!(
            "tidak bisa menyusun ACL state: {}",
            std::io::Error::last_os_error()
        ));
    }
    let ok = unsafe {
        SetFileSecurityW(
            wide_os(dir.as_os_str()).as_ptr(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            sd,
        )
    };
    unsafe { LocalFree(sd) };
    if ok == 0 {
        return Err(format!(
            "tidak bisa mengamankan {}: {}",
            dir.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn wide_os(value: &std::ffi::OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn move_replace(from: &Path, to: &Path) -> Result<(), String> {
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };
    let ok = unsafe {
        MoveFileExW(
            wide_os(from.as_os_str()).as_ptr(),
            wide_os(to.as_os_str()).as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        Err(format!(
            "tidak bisa mengganti {}: {}",
            to.display(),
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}

pub fn save_state(s: &Saved) -> Result<(), String> {
    let path = state_path();
    let dir = path
        .parent()
        .ok_or_else(|| "path state tidak valid".to_string())?;
    std::fs::create_dir_all(dir).map_err(|e| format!("gagal membuat {}: {e}", dir.display()))?;
    harden_state_dir(dir)?;
    let raw = serde_json::to_string_pretty(s).map_err(|e| e.to_string())?;
    // Tulis ke file sementara di direktori yang sama, fsync, lalu ganti secara
    // atomik. Crash di tengah penulisan tidak boleh meninggalkan JSON korup
    // yang membuat restore melewati pemulihan DNS.
    // Sertakan PID supaya dua proses yang menulis bersamaan tidak memakai
    // file sementara yang sama.
    let tmp = path.with_extension(format!("json.tmp.{}", std::process::id()));
    let mut file =
        std::fs::File::create(&tmp).map_err(|e| format!("gagal menulis {}: {e}", tmp.display()))?;
    use std::io::Write;
    file.write_all(raw.as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|e| format!("gagal menulis {}: {e}", tmp.display()))?;
    drop(file);
    if let Err(e) = move_replace(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

pub fn clear_state() {
    let _ = std::fs::remove_file(state_path());
}

/// Path executable sistem tanpa bergantung pada PATH/current directory.
/// Proses ini sering berjalan elevated; `Command::new("powershell")` bisa
/// menemukan file yang ditanam di folder aplikasi atau CWD.
pub(crate) fn system32_exe(name: &str) -> PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
        let mut buf = vec![0u16; 1024];
        let len = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) };
        if len == 0 || len as usize >= buf.len() {
            return PathBuf::from(r"C:\Windows\System32");
        }
        PathBuf::from(String::from_utf16_lossy(&buf[..len as usize]))
    })
    .join(name)
}

pub(crate) fn run_ps(script: &str) -> Result<String, String> {
    // Paksa UTF-8 supaya nama adapter non-ASCII tidak muncul sebagai mojibake.
    let full = format!("$OutputEncoding=[Console]::OutputEncoding=[Text.Encoding]::UTF8\n{script}");
    let out = Command::new(system32_exe(r"WindowsPowerShell\v1.0\powershell.exe"))
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
                if let Some(ip) = unsafe { sockaddr_ip(&node.Address) } {
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
    sa: &windows_sys::Win32::Networking::WinSock::SOCKET_ADDRESS,
) -> Option<IpAddr> {
    if sa.lpSockaddr.is_null() || sa.iSockaddrLength < 2 {
        return None;
    }
    let base = sa.lpSockaddr as *const u8;
    match unsafe { (*sa.lpSockaddr).sa_family } {
        2 if sa.iSockaddrLength >= 8 => {
            let mut octets = [0u8; 4];
            unsafe { std::ptr::copy_nonoverlapping(base.add(4), octets.as_mut_ptr(), 4) };
            Some(IpAddr::V4(octets.into()))
        }
        23 if sa.iSockaddrLength >= 24 => {
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
        // diparse sebagai IpAddr. Buang zone-nya lalu cek numerik blok fe80::/10.
        Err(_) => server
            .split('%')
            .next()
            .and_then(|s| s.parse::<std::net::Ipv6Addr>().ok())
            .is_some_and(|addr| addr.segments()[0] & 0xFFC0 == 0xFE80),
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
        .map(|v| ps_quote(v))
        .collect::<Vec<_>>()
        .join(",")
}

fn json_count(value: Option<&serde_json::Value>) -> usize {
    match value {
        Some(serde_json::Value::Array(items)) => items.len(),
        Some(serde_json::Value::String(text)) if !text.is_empty() => 1,
        Some(serde_json::Value::Number(_)) => 1,
        _ => 0,
    }
}

fn verify_applied(adapters: &[Adapter], listen_v6: bool) -> Result<(), String> {
    let mut last = String::new();
    for attempt in 0..3 {
        match list_adapters() {
            Ok(now) => {
                if let Some(missing) = adapters.iter().find(|saved| {
                    let need_v6 = listen_v6 && !saved.v6.is_empty();
                    now.iter().find(|a| a.index == saved.index).is_none_or(|a| {
                        !a.v4.iter().any(|server| server == "127.0.0.1")
                            || (need_v6 && !a.v6.iter().any(|server| server == "::1"))
                    })
                }) {
                    let need_v6 = listen_v6 && !missing.v6.is_empty();
                    let actual = now.iter().find(|a| a.index == missing.index);
                    last = format!(
                        "adapter {} belum memakai proxy loopback (v4 {:?}, v6 {:?}, butuh_v6 {need_v6}, listen_v6 {listen_v6})",
                        missing.index,
                        actual.map(|a| &a.v4),
                        actual.map(|a| &a.v6),
                    );
                } else {
                    return Ok(());
                }
            }
            Err(e) => last = e,
        }
        if attempt < 2 {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
    Err(format!("verifikasi DNS gagal: {last}"))
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
///
/// `listen_v6` menandakan proxy benar-benar punya listener di `[::1]:53`.
/// Kalau tidak, `::1` tidak dipasang: DNS IPv6 yang menunjuk port mati akan
/// memutus resolusi IPv6 tanpa alasan.
/// Susun skrip PowerShell pengalih DNS. Satu adapter cukup satu panggilan
/// `Set-DnsClientServerAddress`, karena cmdlet itu mengganti seluruh daftar.
fn apply_script(adapters: &[Adapter], listen_v6: bool) -> String {
    let mut script = String::from("$ok=@(); $bad=@()\n");
    for a in adapters {
        // `::1` hanya dipasang kalau adapter ini sebelumnya memang punya DNS
        // IPv6. Adapter tanpa IPv6 (mis. Ethernet IPv4-only) menolak/mengabaikan
        // `::1`, dan verifikasi tidak boleh menagihnya.
        let servers = if listen_v6 && !a.v6.is_empty() {
            "'127.0.0.1','::1'"
        } else {
            "'127.0.0.1'"
        };
        script.push_str(&format!(
            "try {{ Set-DnsClientServerAddress -InterfaceIndex {} -ServerAddresses {servers} -ErrorAction Stop; $ok += '{}' }} catch {{ $bad += \"{}: $($_.Exception.Message)\" }}\n",
            a.index, a.index, a.index
        ));
    }
    script.push_str("@{ok=$ok; bad=$bad} | ConvertTo-Json -Compress\n");
    script
}

pub fn apply(provider_id: &str, listen_v6: bool) -> Result<Vec<Adapter>, String> {
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

    let script = apply_script(&adapters, listen_v6);
    let raw = match run_ps(&script) {
        Ok(raw) => raw,
        Err(e) => {
            // PowerShell bisa gagal setelah mengubah sebagian adapter. Pakai
            // catatan yang baru disimpan untuk memutar perubahan itu kembali.
            let rollback = restore_plan(Some(&saved), &adapters);
            if rollback.1 > 0 {
                let _ = run_ps(&rollback.0);
            }
            return Err(e);
        }
    };
    let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap_or_default();
    let ok_count = json_count(parsed.get("ok"));
    let bad_count = json_count(parsed.get("bad"));
    if ok_count != adapters.len() || bad_count > 0 {
        let rollback = restore_plan(Some(&saved), &adapters);
        if rollback.1 > 0 {
            let _ = run_ps(&rollback.0);
        }
        return Err(format!(
            "gagal mengubah DNS pada {} adapter (berhasil {}, gagal {}): {raw}",
            adapters.len(),
            ok_count,
            bad_count
        ));
    }
    if let Err(e) = verify_applied(&adapters, listen_v6) {
        let rollback = restore_plan(Some(&saved), &adapters);
        if rollback.1 > 0 {
            let _ = run_ps(&rollback.0);
        }
        return Err(e);
    }

    flush_dns();
    Ok(adapters)
}

/// Rakit skrip PowerShell untuk mengembalikan DNS, tanpa menjalankannya.
///
/// Index adapter bisa berubah setelah reboot atau reinstall driver, jadi nama
/// adapter dipakai sebagai cadangan: kalau index lama sudah tidak ada, adapter
/// dengan nama yang sama tetap dipulihkan. Adapter yang benar-benar hilang
/// dilewati, bukan dipaksa ke index yang sekarang mungkin milik adapter lain.
fn restore_plan(saved: Option<&Saved>, adapters: &[Adapter]) -> (String, usize) {
    let mut script = String::new();
    let mut touched = 0usize;

    match saved {
        Some(s) if !s.ifaces.is_empty() => {
            let by_index: BTreeMap<u32, &Adapter> = adapters.iter().map(|a| (a.index, a)).collect();
            let by_name: BTreeMap<&str, u32> = adapters
                .iter()
                .map(|a| (a.name.as_str(), a.index))
                .collect();

            for (saved_index, iface) in &s.ifaces {
                let index = saved_index
                    .parse::<u32>()
                    .ok()
                    .filter(|index| {
                        by_index
                            .get(index)
                            .is_some_and(|adapter| adapter.name == iface.name)
                    })
                    .or_else(|| by_name.get(iface.name.as_str()).copied());
                let Some(index) = index else { continue };

                let has_v4 = !iface.v4.is_empty();
                let has_v6 = !iface.v6.is_empty();
                if has_v4 && has_v6 {
                    // Cmdlet mengganti seluruh daftar: kirim v4 + v6 sekaligus.
                    let mut all = iface.v4.clone();
                    all.extend(iface.v6.iter().cloned());
                    script.push_str(&format!(
                        "Set-DnsClientServerAddress -InterfaceIndex {index} -ServerAddresses {} -ErrorAction SilentlyContinue\n",
                        quote_list(&all)
                    ));
                } else {
                    // Salah satu family kosong: reset dulu supaya sisa
                    // 127.0.0.1 / ::1 ikut hilang sebelum family lain ditulis.
                    script.push_str(&format!(
                        "Set-DnsClientServerAddress -InterfaceIndex {index} -ResetServerAddresses -ErrorAction SilentlyContinue\n"
                    ));
                    if has_v4 {
                        script.push_str(&format!(
                            "Set-DnsClientServerAddress -InterfaceIndex {index} -ServerAddresses {} -ErrorAction SilentlyContinue\n",
                            quote_list(&iface.v4)
                        ));
                    } else if has_v6 {
                        script.push_str(&format!(
                            "Set-DnsClientServerAddress -InterfaceIndex {index} -ServerAddresses {} -ErrorAction SilentlyContinue\n",
                            quote_list(&iface.v6)
                        ));
                    }
                }
                touched += 1;
            }
            script.push_str("'ok'\n");
        }
        _ => {
            // Tidak ada catatan: reset semua adapter yang masih menunjuk loopback.
            for a in adapters {
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

    (script, touched)
}

/// Kembalikan DNS ke kondisi asli (DHCP atau server statis sebelumnya).
pub fn restore() -> Result<String, String> {
    require_admin()?;
    let saved = load_state();
    let adapters = list_adapters()?;
    let (script, touched) = restore_plan(saved.as_ref(), &adapters);
    // Kalau state ada tetapi tidak ada adapter yang cocok (index/nama berubah),
    // jangan menyerah: reset adapter yang masih menunjuk loopback.
    let (script, touched) = if touched == 0 {
        restore_plan(None, &adapters)
    } else {
        (script, touched)
    };

    if touched == 0 {
        // Tanpa adapter yang cocok (jaringan sedang mati / index berubah) state
        // tetap disimpan: menghapusnya akan menghilangkan satu-satunya catatan
        // DNS asli. Hanya hapus kalau memang tidak ada state sejak awal.
        if saved.is_some() {
            return Err("Restore gagal: tidak ada adapter yang cocok ditemukan".to_string());
        }
        clear_state();
        return Ok(
            "DNS sudah kembali ke setelan default (tidak ada yang perlu diubah)".to_string(),
        );
    }

    let targets = script_indices(&script);
    run_ps(&script)?;
    flush_dns();
    // Jangan hapus state kalau verifikasi gagal: ini satu-satunya catatan
    // untuk mencoba lagi.
    verify_restored(&targets)?;
    clear_state();
    Ok(format!("DNS dipulihkan pada {touched} adapter"))
}

/// Index yang benar-benar disentuh skrip restore — hanya ini yang boleh
/// diverifikasi, supaya adapter lain yang kebetulan memakai loopback tidak
/// membuat restore gagal palsu.
fn script_indices(script: &str) -> Vec<u32> {
    const KEY: &str = "-InterfaceIndex ";
    script
        .match_indices(KEY)
        .filter_map(|(at, _)| {
            script[at + KEY.len()..]
                .split(|c: char| !c.is_ascii_digit())
                .next()?
                .parse()
                .ok()
        })
        .collect()
}

fn verify_restored(targets: &[u32]) -> Result<(), String> {
    // Sama seperti verify_applied: tulisan PowerShell butuh waktu sebelum
    // terbaca lewat GetAdaptersAddresses. Coba beberapa kali sebelum gagal.
    let mut last = String::new();
    for attempt in 0..3 {
        match list_adapters() {
            Ok(adapters) => {
                if let Some(stuck) = adapters.iter().find(|a| {
                    targets.contains(&a.index)
                        && (a.v4.iter().any(|s| s == "127.0.0.1")
                            || a.v6.iter().any(|s| s == "::1"))
                }) {
                    last = format!(
                        "DNS adapter {} masih menunjuk loopback setelah restore",
                        stuck.index
                    );
                } else {
                    return Ok(());
                }
            }
            Err(e) => last = e,
        }
        if attempt < 2 {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
    Err(format!("verifikasi restore gagal: {last}"))
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

/// Sama untuk loopback IPv6; dipakai `doctor` supaya konflik port terlihat
/// sebelum adapter diarahkan ke `::1`.
pub fn port53_v6_free() -> bool {
    let Ok(udp) = std::net::UdpSocket::bind("[::1]:53") else {
        return false;
    };
    drop(udp);
    std::net::TcpListener::bind("[::1]:53").is_ok()
}

/// Pulihkan hanya kalau catatan masih ada **dan** tidak ada yang melayani
/// port 53. Dipakai saat logon dan oleh watchdog: kalau pengguna sudah membuka
/// sesi baru, DNS milik sesi itu tidak boleh ditimpa.
pub fn restore_if_stale() -> Result<Option<String>, String> {
    if !port53_free() {
        return Ok(None);
    }
    // State hilang/korup bukan alasan untuk meninggalkan adapter di loopback:
    // restore_plan(None) mereset adapter yang masih menunjuk 127.0.0.1/::1.
    restore().map(Some)
}

// ── rute VPN (full tunnel) ──────────────────────────────────────────────

/// Gateway IPv4 default yang sedang dipakai, dipakai untuk membuat host route
/// ke endpoint WARP supaya koneksi QUIC tidak masuk ke tunnel sendiri.
pub fn default_route() -> Result<(u32, String), String> {
    let raw = run_ps(
        r#"$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Where-Object { $_.NextHop -ne '0.0.0.0' } | Sort-Object RouteMetric | Select-Object -First 1
if ($r) { [pscustomobject]@{ iface = "$($r.ifIndex)"; hop = "$($r.NextHop)" } | ConvertTo-Json -Compress } else { '{}' }"#,
    )?;
    let value: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("gateway default tidak terbaca: {e}"))?;
    let iface = value
        .get("iface")
        .and_then(|v| v.as_str())
        .and_then(|s| s.trim().parse::<u32>().ok())
        .ok_or_else(|| "tidak ada gateway IPv4 default yang aktif".to_string())?;
    let hop = value
        .get("hop")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    Ok((iface, hop))
}

/// Gateway IPv6 default yang sedang dipakai. Sama seperti `default_route`, tapi
/// diperlukan kalau endpoint QUIC WARP yang dipilih beralamat IPv6 — paket ke
/// endpoint itu tidak boleh ikut masuk tunnel.
pub fn default_route_v6() -> Result<(u32, String), String> {
    let raw = run_ps(
        r#"$r = Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -ErrorAction SilentlyContinue | Where-Object { $_.NextHop -ne '::' } | Sort-Object RouteMetric | Select-Object -First 1
if ($r) { [pscustomobject]@{ iface = "$($r.ifIndex)"; hop = "$($r.NextHop)" } | ConvertTo-Json -Compress } else { '{}' }"#,
    )?;
    let value: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| format!("gateway IPv6 default tidak terbaca: {e}"))?;
    let iface = value
        .get("iface")
        .and_then(|v| v.as_str())
        .and_then(|s| s.trim().parse::<u32>().ok())
        .ok_or_else(|| "tidak ada gateway IPv6 default yang aktif".to_string())?;
    let hop = value
        .get("hop")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    // PowerShell bisa mengembalikan `fe80::1%12` (zone id). `New-NetRoute`
    // sudah menerima interface lewat `-InterfaceIndex`, jadi buang suffix-nya
    // — kalau tidak, validasi state.json menolak rute ini.
    let hop = hop.split('%').next().unwrap_or(&hop).to_string();
    if hop.is_empty() {
        return Err("gateway IPv6 default tidak punya next-hop".to_string());
    }
    Ok((iface, hop))
}

/// Pasang alamat IPv6 WARP pada adapter TUN. Wintun crate hanya mengatur IPv4,
/// jadi ini lewat cmdlet bawaan Windows. Prefix /128 karena alamat tunnel
/// adalah titik ujung, bukan subnet.
pub fn adapter_set_ipv6(index: u32, ip: &str) -> Result<(), String> {
    let script = format!(
        "New-NetIPAddress -InterfaceIndex {index} -IPAddress {} -PrefixLength 128 -AddressFamily IPv6 -ErrorAction Stop | Out-Null",
        ps_quote(ip)
    );
    run_ps(&script)?;
    Ok(())
}

/// Rute yang membentuk full tunnel, dipisah dari eksekusi supaya isinya bisa
/// diuji tanpa menyentuh tabel rute Windows.
///
/// Endpoint WARP **harus** punya host route lewat gateway asli: tanpa itu paket
/// QUIC ke endpoint ikut masuk tunnel dan seluruh koneksi berputar di tempat.
pub fn vpn_route_plan(
    index: u32,
    endpoint: Option<&str>,
    physical: Option<(u32, String)>,
    ipv6: Option<&str>,
) -> Result<Vec<SavedRoute>, String> {
    let mut routes = Vec::new();
    if let Some(ip) = endpoint.map(str::trim).filter(|ip| !ip.is_empty()) {
        let parsed: IpAddr = ip
            .parse()
            .map_err(|_| format!("endpoint VPN tidak valid: {ip}"))?;
        let family = if parsed.is_ipv4() { "IPv4" } else { "IPv6" };
        let (phys_index, hop) =
            physical.ok_or_else(|| format!("tidak ada gateway {family} default yang aktif"))?;
        let prefix = if parsed.is_ipv4() { 32 } else { 128 };
        routes.push(SavedRoute {
            dest: format!("{ip}/{prefix}"),
            iface: phys_index,
            nexthop: hop,
        });
    }
    for dest in ["0.0.0.0/1", "128.0.0.0/1"] {
        routes.push(SavedRoute {
            dest: dest.to_string(),
            iface: index,
            nexthop: "0.0.0.0".to_string(),
        });
    }
    if ipv6.is_some_and(|ip| !ip.trim().is_empty()) {
        for dest in ["::/1", "8000::/1"] {
            routes.push(SavedRoute {
                dest: dest.to_string(),
                iface: index,
                nexthop: "::".to_string(),
            });
        }
    }
    Ok(routes)
}

fn ps_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// Pasang rute full tunnel: dua rute `/1` lebih spesifik dari default route,
/// ditambah host route ke endpoint WARP lewat gateway asli.
///
/// Rencananya disimpan **sebelum** rute dipasang, jadi kalau proses mati di
/// tengah jalan masih jelas rute mana yang harus dicabut.
pub fn vpn_install_routes(
    adapter: &str,
    index: u32,
    endpoint: Option<&str>,
    ipv6: Option<&str>,
) -> Result<SavedVpn, String> {
    require_admin()?;
    // Gateway asli dibutuhkan kalau endpoint WARP harus dikeluarkan dari
    // tunnel. Keluarganya (v4/v6) mengikuti alamat endpoint yang dipakai QUIC.
    let physical = if endpoint.is_some_and(|ip| !ip.trim().is_empty()) {
        let is_v6 = endpoint
            .and_then(|ip| ip.trim().parse::<IpAddr>().ok())
            .is_some_and(|ip| ip.is_ipv6());
        Some(if is_v6 {
            default_route_v6()?
        } else {
            default_route()?
        })
    } else {
        None
    };
    let routes = vpn_route_plan(index, endpoint, physical, ipv6)?;

    let saved = SavedVpn {
        adapter: adapter.to_string(),
        endpoint: endpoint.unwrap_or("").to_string(),
        ipv6: ipv6.unwrap_or("").to_string(),
        routes: routes.clone(),
    };
    let mut state = load_state().unwrap_or_default();
    state.vpn = Some(saved.clone());
    save_state(&state)?;

    let mut script = String::from("$ErrorActionPreference='Stop'\n");
    for route in &routes {
        script.push_str(&format!(
            "New-NetRoute -DestinationPrefix {} -InterfaceIndex {} -NextHop {} -RouteMetric 1 | Out-Null\n",
            ps_quote(&route.dest),
            route.iface,
            ps_quote(&route.nexthop)
        ));
    }
    script.push_str("'ok'\n");

    if let Err(e) = run_ps(&script) {
        let _ = vpn_remove_routes(&saved);
        vpn_clear_state();
        return Err(format!("gagal memasang rute VPN: {e}"));
    }
    Ok(saved)
}

/// Cabut rute yang pernah dipasang. Semua rute tetap dicoba walau ada yang
/// gagal, lalu kegagalan dikembalikan supaya state tidak dihapus: state adalah
/// satu-satunya catatan untuk mencoba lagi.
pub fn vpn_remove_routes(saved: &SavedVpn) -> Result<(), String> {
    let mut script = String::new();
    for route in &saved.routes {
        script.push_str(&format!(
            "Remove-NetRoute -DestinationPrefix {} -InterfaceIndex {} -Confirm:$false -ErrorAction SilentlyContinue\n",
            ps_quote(&route.dest),
            route.iface
        ));
    }
    run_ps(&script).map(|_| ())
}

pub fn vpn_saved() -> Option<SavedVpn> {
    load_state().and_then(|state| state.vpn)
}

/// Hapus catatan VPN tanpa menyentuh catatan DNS: Clear DNS masih memerlukannya.
pub fn vpn_clear_state() {
    let Some(mut state) = load_state() else {
        return;
    };
    state.vpn = None;
    if state.ifaces.is_empty() && state.provider.is_empty() {
        clear_state();
    } else {
        let _ = save_state(&state);
    }
}

/// Identitas proses induk yang dikirim ke watchdog: PID saja tidak cukup
/// karena PID bisa dipakai ulang setelah induk keluar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub start_time: u64,
}

pub fn process_identity() -> ProcessIdentity {
    ProcessIdentity {
        pid: std::process::id(),
        start_time: process_start_time().unwrap_or(0),
    }
}

/// `pid:start_time`, format yang stabil untuk argumen baris perintah.
pub fn format_process_identity(identity: ProcessIdentity) -> String {
    format!("{}:{}", identity.pid, identity.start_time)
}

pub fn parse_process_identity(text: &str) -> Option<ProcessIdentity> {
    let (pid, start_time) = text.split_once(':')?;
    Some(ProcessIdentity {
        pid: pid.parse().ok()?,
        start_time: start_time.parse().ok()?,
    })
}

fn process_start_time() -> Option<u64> {
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};
    let mut creation = FILETIME_ZERO;
    let mut exit = FILETIME_ZERO;
    let mut kernel = FILETIME_ZERO;
    let mut user = FILETIME_ZERO;
    let ok = unsafe {
        GetProcessTimes(
            GetCurrentProcess(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    };
    if ok == 0 {
        return None;
    }
    Some(((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64)
}

const FILETIME_ZERO: windows_sys::Win32::Foundation::FILETIME =
    windows_sys::Win32::Foundation::FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };

/// Tunggu sampai proses dengan identitas itu benar-benar pergi. Kalau PID
/// dipakai ulang, waktu mulai tidak cocok dan dianggap sudah pergi.
pub fn wait_for_process(pid: u32, start_time: u64) -> bool {
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_INVALID_PARAMETER, ERROR_NOT_FOUND, GetLastError, WAIT_OBJECT_0,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, WaitForSingleObject,
    };

    // Hak akses standar untuk menunggu handle (tidak diekspor windows-sys di
    // modul Foundation, jadi ditulis langsung).
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const INFINITE: u32 = 0xFFFF_FFFF;
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, pid);
        if handle.is_null() {
            let err = GetLastError();
            return err != ERROR_INVALID_PARAMETER && err != ERROR_NOT_FOUND;
        }
        if start_time != 0
            && let Some(found) = process_start_time_for(handle)
            && found != start_time
        {
            CloseHandle(handle);
            return false;
        }
        let code = WaitForSingleObject(handle, INFINITE);
        CloseHandle(handle);
        code == WAIT_OBJECT_0
    }
}

fn process_start_time_for(handle: windows_sys::Win32::Foundation::HANDLE) -> Option<u64> {
    use windows_sys::Win32::System::Threading::GetProcessTimes;
    let mut creation = FILETIME_ZERO;
    let mut exit = FILETIME_ZERO;
    let mut kernel = FILETIME_ZERO;
    let mut user = FILETIME_ZERO;
    if unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) } == 0 {
        return None;
    }
    Some(((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64)
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
        .arg(format_process_identity(process_identity()))
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
    // Buang jawaban lama dari cache Windows sebelum mengukur; tanpa ini
    // `example.com` yang sudah di-cache membuat verifikasi lulus palsu.
    flush_dns();
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
    Command::new(system32_exe("schtasks.exe"))
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
    let out = Command::new(system32_exe("schtasks.exe"))
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
    // XML keluaran schtasks meng-escape karakter path yang umum.
    let xml = xml
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">");
    Some(xml.contains(&exe))
}

/// Keluaran alat konsol Windows bisa UTF-16LE atau UTF-8 tergantung versi.
fn decode_console(bytes: &[u8]) -> String {
    // BOM UTF-16LE (FF FE) lebih pasti daripada heuristik byte nol.
    let bom = bytes.starts_with(&[0xFF, 0xFE]);
    let utf16 = bom || (bytes.len() > 4 && bytes[1] == 0 && bytes[3] == 0);
    if utf16 {
        let payload = if bom { &bytes[2..] } else { bytes };
        let (pairs, _) = payload.as_chunks::<2>();
        let units: Vec<u16> = pairs.iter().map(|pair| u16::from_le_bytes(*pair)).collect();
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
        Command::new(system32_exe("schtasks.exe"))
            .args([
                "/Create", "/F", "/SC", "ONLOGON", "/RL", "HIGHEST", "/DELAY", "0000:15", "/TN",
                TASK_NAME, "/TR", &action,
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
    } else {
        Command::new(system32_exe("schtasks.exe"))
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
    let _ = Command::new(system32_exe("ipconfig.exe"))
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
pub(crate) fn require_admin() -> Result<(), String> {
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
/// Restore blocking tidak boleh dijalankan di handler: Windows hanya memberi
/// beberapa detik sebelum mematikan proses. Jalankan proses restore terpisah.
static EXIT_RESTORE_STARTED: AtomicBool = AtomicBool::new(false);

unsafe extern "system" fn exit_handler(_ctrl_type: u32) -> i32 {
    if EXIT_RESTORE_STARTED.swap(true, Ordering::SeqCst) {
        return 1;
    }
    if load_state().is_some()
        && let Ok(exe) = std::env::current_exe()
    {
        let _ = Command::new(exe)
            .args(["restore", "--if-stale"])
            .creation_flags(DETACHED_PROCESS)
            .spawn();
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

/// Kutip argumen argv Windows: backslash sebelum tanda kutip (juga sebelum
/// tanda kutip penutup) digandakan, tanda kutip itu sendiri di-escape.
fn quote_arg(a: &str) -> String {
    let mut out = String::with_capacity(a.len() + 2);
    out.push('"');
    let mut slashes = 0usize;
    for c in a.chars() {
        match c {
            '\\' => slashes += 1,
            '"' => {
                out.push_str(&"\\".repeat(slashes * 2 + 1));
                out.push('"');
                slashes = 0;
            }
            _ => {
                out.push_str(&"\\".repeat(slashes));
                out.push(c);
                slashes = 0;
            }
        }
    }
    out.push_str(&"\\".repeat(slashes * 2));
    out.push('"');
    out
}

/// Jalankan ulang aplikasi lewat prompt UAC.
pub fn relaunch_elevated(args: &[String]) -> Result<(), String> {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let params = args
        .iter()
        .map(|a| quote_arg(a))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_menulis_v4_dan_v6_dalam_satu_perintah() {
        let adapters = [Adapter {
            index: 18,
            name: "Ethernet".to_string(),
            v4: vec!["94.140.14.14".to_string()],
            v6: vec!["2620:fe::fe".to_string()],
        }];
        let script = apply_script(&adapters, true);
        let set_lines: Vec<&str> = script
            .lines()
            .filter(|line| line.contains("Set-DnsClientServerAddress"))
            .collect();
        assert_eq!(set_lines.len(), 1, "satu adapter = satu perintah: {script}");
        assert!(set_lines[0].contains("'127.0.0.1'"), "{script}");
        assert!(set_lines[0].contains("'::1'"), "{script}");
    }

    #[test]
    fn adapter_tanpa_ipv6_tidak_ditagih_loopback_v6() {
        let adapters = [Adapter {
            index: 18,
            name: "Ethernet".to_string(),
            v4: vec!["94.140.14.14".to_string()],
            v6: Vec::new(),
        }];
        let script = apply_script(&adapters, true);
        assert!(script.contains("'127.0.0.1'"), "{script}");
        assert!(!script.contains("'::1'"), "{script}");
    }

    #[test]
    fn restore_menulis_v4_dan_v6_dalam_satu_perintah() {
        let adapters = [Adapter {
            index: 18,
            name: "Ethernet".to_string(),
            v4: vec!["127.0.0.1".to_string()],
            v6: vec!["::1".to_string()],
        }];
        let mut saved = Saved::default();
        saved.ifaces.insert(
            "18".to_string(),
            SavedIface {
                name: "Ethernet".to_string(),
                v4: vec!["94.140.14.14".to_string()],
                v6: vec!["2620:fe::fe".to_string()],
            },
        );
        let (script, _) = restore_plan(Some(&saved), &adapters);
        let set_lines: Vec<&str> = script
            .lines()
            .filter(|line| {
                line.contains("Set-DnsClientServerAddress") && line.contains("-ServerAddresses")
            })
            .collect();
        assert_eq!(set_lines.len(), 1, "satu adapter = satu perintah: {script}");
        assert!(set_lines[0].contains("94.140.14.14"), "{script}");
        assert!(set_lines[0].contains("2620:fe::fe"), "{script}");
    }

    #[test]
    fn acl_direktori_state_bisa_dipasang() {
        let dir = std::env::temp_dir().join(format!("mydns-acl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let result = harden_state_dir(&dir);
        // Kembalikan ACL turunan sebelum menghapus: direktori ini sengaja
        // dibuat tidak bisa dihapus oleh user biasa setelah diperketat.
        let _ = Command::new(system32_exe("icacls.exe"))
            .args([dir.as_os_str(), std::ffi::OsStr::new("/reset")])
            .arg("/T")
            .arg("/C")
            .creation_flags(CREATE_NO_WINDOW)
            .output();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn state_menerima_rute_ipv6() {
        let state = Saved {
            vpn: Some(SavedVpn {
                adapter: "MyDNS".to_string(),
                endpoint: "2606:4700:103::1".to_string(),
                ipv6: "2606:4700:110::1".to_string(),
                routes: vec![
                    SavedRoute {
                        dest: "::/1".to_string(),
                        iface: 5,
                        nexthop: "::".to_string(),
                    },
                    SavedRoute {
                        dest: "2606:4700:103::1/128".to_string(),
                        iface: 3,
                        nexthop: "fe80::1".to_string(),
                    },
                ],
            }),
            ..Saved::default()
        };
        assert!(state_valid(&state));
    }

    fn adapter(index: u32, name: &str, v4: &[&str], v6: &[&str]) -> Adapter {
        Adapter {
            index,
            name: name.to_string(),
            v4: v4.iter().map(|ip| ip.to_string()).collect(),
            v6: v6.iter().map(|ip| ip.to_string()).collect(),
        }
    }

    #[test]
    fn rencana_rute_vpn_mengeluarkan_endpoint_dari_tunnel() {
        let routes = vpn_route_plan(
            49,
            Some("162.159.198.2"),
            Some((18, "192.168.1.1".to_string())),
            None,
        )
        .unwrap();
        assert_eq!(routes.len(), 3);
        assert_eq!(
            routes[0],
            SavedRoute {
                dest: "162.159.198.2/32".to_string(),
                iface: 18,
                nexthop: "192.168.1.1".to_string(),
            }
        );
        assert_eq!(routes[1].dest, "0.0.0.0/1");
        assert_eq!(routes[1].iface, 49);
        assert_eq!(routes[2].dest, "128.0.0.0/1");
        assert!(routes[1..].iter().all(|route| route.iface == 49));
    }

    #[test]
    fn rencana_rute_vpn_tanpa_endpoint() {
        let routes = vpn_route_plan(7, None, None, None).unwrap();
        assert_eq!(routes.len(), 2);
        assert!(routes.iter().all(|route| route.iface == 7));
    }

    #[test]
    fn rencana_rute_vpn_butuh_gateway_untuk_endpoint() {
        // Tanpa gateway asli, host route ke endpoint tidak bisa dipasang —
        // dan full tunnel tanpa itu akan memutar koneksi QUIC ke dirinya sendiri.
        assert!(vpn_route_plan(7, Some("162.159.198.2"), None, None).is_err());
    }

    #[test]
    fn rencana_rute_vpn_ipv6_mengeluarkan_endpoint_lewat_gateway_v6() {
        let routes = vpn_route_plan(
            12,
            Some("2606:4700:103::1"),
            Some((9, "fe80::1".to_string())),
            Some("2606:4700:110:8a1b::1"),
        )
        .unwrap();
        assert_eq!(routes.len(), 5);
        assert_eq!(
            routes[0],
            SavedRoute {
                dest: "2606:4700:103::1/128".to_string(),
                iface: 9,
                nexthop: "fe80::1".to_string(),
            }
        );
        assert_eq!(routes[3].dest, "::/1");
        assert_eq!(routes[4].dest, "8000::/1");
        assert!(routes[3..].iter().all(|route| route.iface == 12));
        assert!(routes[3..].iter().all(|route| route.nexthop == "::"));
    }

    fn saved(index: &str, name: &str, v4: &[&str]) -> Saved {
        let mut ifaces = BTreeMap::new();
        ifaces.insert(
            index.to_string(),
            SavedIface {
                name: name.to_string(),
                v4: v4.iter().map(|ip| ip.to_string()).collect(),
                v6: Vec::new(),
            },
        );
        Saved {
            provider: "quad9".to_string(),
            saved_at: 0,
            ifaces,
            vpn: None,
        }
    }

    #[test]
    fn restore_memakai_nama_saat_index_berubah() {
        let saved = saved("99", "Ethernet", &["9.9.9.9"]);
        let adapters = vec![adapter(5, "Ethernet", &["127.0.0.1"], &[])];

        let (script, touched) = restore_plan(Some(&saved), &adapters);

        assert_eq!(touched, 1);
        assert!(script.contains("-InterfaceIndex 5"), "{script}");
        assert!(!script.contains("99"), "{script}");
        assert!(script.contains("'9.9.9.9'"), "{script}");
    }

    #[test]
    fn restore_melewati_adapter_yang_sudah_hilang() {
        let saved = saved("99", "Ethernet", &["9.9.9.9"]);
        let adapters = vec![adapter(5, "Wi-Fi", &["127.0.0.1"], &[])];

        let (script, touched) = restore_plan(Some(&saved), &adapters);

        assert_eq!(touched, 0);
        assert!(!script.contains("-InterfaceIndex"), "{script}");
    }

    #[test]
    fn indeks_skrip_restore_hanya_yang_disentuh() {
        let script = "Set-DnsClientServerAddress -InterfaceIndex 12 -ServerAddresses '1.1.1.1'\nSet-DnsClientServerAddress -InterfaceIndex 7 -ResetServerAddresses\n'ok'\n";
        assert_eq!(script_indices(script), vec![12, 7]);
    }

    #[test]
    fn identitas_proses_tahan_satu_putaran_parse() {
        let identity = ProcessIdentity {
            pid: 1234,
            start_time: u64::MAX,
        };
        assert_eq!(
            parse_process_identity(&format_process_identity(identity)),
            Some(identity)
        );
        assert_eq!(parse_process_identity("12:tidak-angka"), None);
    }

    #[test]
    fn restore_tanpa_catatan_mereset_loopback() {
        let adapters = vec![
            adapter(5, "Wi-Fi", &["127.0.0.1"], &["::1"]),
            adapter(7, "Ethernet", &["9.9.9.9"], &[]),
        ];

        let (script, touched) = restore_plan(None, &adapters);

        assert_eq!(touched, 1);
        assert!(script.contains("-InterfaceIndex 5"), "{script}");
        assert!(!script.contains("-InterfaceIndex 7"), "{script}");
    }
}
