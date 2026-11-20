//! Pemeriksa versi rilis dan cache hasil pengecekan update.
//
// API ini dipakai oleh tugas berikutnya untuk pengecekan update GitHub.
#![allow(dead_code)]

use serde::Deserialize;
use serde_json::Value;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

const CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

pub fn current() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Tag GitHub yang diterima: `v` diikuti tiga bilangan desimal.
pub fn valid_tag(tag: &str) -> bool {
    tag.strip_prefix('v')
        .is_some_and(|rest| parse_version(rest).is_some())
}

/// Bandingkan tiga komponen versi; tag diawali `v`, versi lokal tidak.
pub fn is_newer(tag: &str, current: &str) -> bool {
    let Some(latest) = tag.strip_prefix('v').and_then(parse_version) else {
        return false;
    };
    let Some(running) = parse_version(current) else {
        return false;
    };
    latest > running
}

fn parse_version(text: &str) -> Option<[u64; 3]> {
    let mut nums = [0u64; 3];
    let mut parts = text.split('.');
    for num in &mut nums {
        let part = parts.next()?;
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        *num = part.parse().ok()?;
    }
    parts.next().is_none().then_some(nums)
}

pub fn cache_path() -> PathBuf {
    let base = std::env::var("LOCALAPPDATA")
        .or_else(|_| std::env::var("APPDATA"))
        .unwrap_or_else(|_| r"C:\ProgramData".to_string());
    cache_file(base)
}

fn cache_file(base: impl AsRef<Path>) -> PathBuf {
    base.as_ref().join("MyDns").join("update-check.json")
}

/// Hasil cache yang korup, tidak ada, atau sudah 24 jam tidak dianggap.
pub fn latest_cached(now: SystemTime) -> Option<String> {
    read_cached(&cache_path(), now)
}

pub fn save_cached(tag: &str, now: SystemTime) -> Result<(), String> {
    write_cached(&cache_path(), tag, now)
}

fn latest_from_json(body: &str) -> Option<String> {
    let releases = serde_json::from_str::<Value>(body)
        .ok()?
        .as_array()?
        .clone();
    releases
        .iter()
        .filter_map(|r| r.get("tag_name")?.as_str())
        .find(|tag| valid_tag(tag))
        .map(str::to_string)
}

fn tag_from_output(body: &str) -> Option<String> {
    let text = body.trim();
    if valid_tag(text) {
        return Some(text.to_string());
    }
    latest_from_json(text)
}

pub fn check_now() -> Result<String, String> {
    let script = "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; (Invoke-RestMethod -Uri 'https://api.github.com/repos/EmhaHasyim/mydns/releases/latest' -Headers @{'User-Agent'='mydns-update'}).tag_name";
    let out = Command::new(crate::win::system32_exe(
        r"WindowsPowerShell\v1.0\powershell.exe",
    ))
    .args(["-NoProfile", "-NonInteractive", "-Command", script])
    .creation_flags(CREATE_NO_WINDOW)
    .output()
    .map_err(|e| format!("tidak bisa mengecek rilis GitHub: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let detail = format!("{stdout} {stderr}");
    if !out.status.success()
        || detail.to_ascii_lowercase().contains("rate limit")
        || detail.to_ascii_lowercase().contains("exception")
    {
        return Err(format!(
            "tidak bisa mengecek rilis GitHub: {}",
            detail.trim()
        ));
    }
    let tag = tag_from_output(&stdout).ok_or("rilis GitHub belum tersedia")?;
    // Cache hanya untuk pengingat: gagal tulis (misalnya fallback ProgramData
    // tanpa izin) tidak boleh menggagalkan update yang sudah lolos pengecekan.
    let _ = save_cached(&tag, SystemTime::now());
    Ok(tag)
}

#[derive(Deserialize)]
struct CacheEntry {
    checked_at: u64,
    latest: String,
}

fn read_cached(path: &Path, now: SystemTime) -> Option<String> {
    let raw = std::fs::read_to_string(path).ok()?;
    let entry: CacheEntry = serde_json::from_str(&raw).ok()?;
    let secs = unix_secs(now);
    if secs.saturating_sub(entry.checked_at) >= CACHE_TTL.as_secs() {
        return None;
    }
    Some(entry.latest)
}

fn write_cached(path: &Path, tag: &str, now: SystemTime) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("gagal membuat {}: {e}", dir.display()))?;
    }
    let latest = serde_json::to_string(tag).map_err(|e| e.to_string())?;
    let raw = format!(
        r#"{{"checked_at": {}, "latest": {latest}}}"#,
        unix_secs(now)
    );
    std::fs::write(path, raw).map_err(|e| format!("gagal menulis {}: {e}", path.display()))
}

fn unix_secs(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_terbaru_diambil_dari_json() {
        assert_eq!(
            latest_from_json(r#"[{"tag_name":"v0.2.0"},{"tag_name":"v0.1.0"}]"#).as_deref(),
            Some("v0.2.0")
        );
        assert_eq!(
            latest_from_json(r#"{"message":"API rate limit exceeded"}"#).as_deref(),
            None
        );
    }

    #[test]
    fn tag_output_powershell_diterima() {
        assert_eq!(tag_from_output("v0.2.0\r\n").as_deref(), Some("v0.2.0"));
        assert_eq!(tag_from_output("v1.2.3; calc").as_deref(), None);
    }

    #[test]
    fn membandingkan_versi_dan_tag() {
        assert!(is_newer("v0.2.0", "0.1.0"));
        assert!(!is_newer("v0.1.0", "0.1.0"));
        assert!(!is_newer("v0.0.9", "0.1.0"));
        assert!(valid_tag("v1.2.3"));
        assert!(!valid_tag("v1.2.3; calc"));
        assert!(cache_path().ends_with("MyDns/update-check.json"));
    }

    #[test]
    fn cache_ditulis_dan_kadaluarsa() {
        let unique = unix_secs(SystemTime::now());
        let base =
            std::env::temp_dir().join(format!("mydns-updater-{unique}-{}", std::process::id()));
        let path = cache_file(&base);
        let _ = std::fs::remove_dir_all(&base);

        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);
        write_cached(&path, "v1.2.3", now).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            r#"{"checked_at": 1000000, "latest": "v1.2.3"}"#
        );
        assert_eq!(read_cached(&path, now).as_deref(), Some("v1.2.3"));
        assert_eq!(
            read_cached(&path, now + CACHE_TTL - Duration::from_secs(1)).as_deref(),
            Some("v1.2.3")
        );
        assert_eq!(read_cached(&path, now + CACHE_TTL), None);

        std::fs::write(&path, "{").unwrap();
        assert_eq!(read_cached(&path, now), None);
        let _ = std::fs::remove_dir_all(&base);
    }
}
