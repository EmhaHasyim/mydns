//! Buffer log kecil yang bisa dibaca UI tanpa channel, plus log berkas untuk
//! peristiwa penting (apply, restore, registrasi WARP).

use std::collections::VecDeque;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_LINES: usize = 200;

pub struct Log {
    buf: Mutex<VecDeque<String>>,
}

impl Log {
    pub fn new() -> Self {
        Self {
            buf: Mutex::new(VecDeque::new()),
        }
    }

    /// Poison diabaikan: buffer hanya berisi teks, dan log tidak boleh ikut
    /// membuat proses panik saat dibaca.
    fn lines(&self) -> std::sync::MutexGuard<'_, VecDeque<String>> {
        self.buf
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn push(&self, line: impl Into<String>) {
        let mut buf = self.lines();
        buf.push_back(line.into());
        while buf.len() > MAX_LINES {
            buf.pop_front();
        }
    }

    /// Salinan baris terlama → terbaru, untuk panel log di TUI.
    pub fn snapshot(&self) -> Vec<String> {
        self.lines().iter().cloned().collect()
    }
}

impl Default for Log {
    fn default() -> Self {
        Self::new()
    }
}

pub fn log_path() -> PathBuf {
    let base = std::env::var("LOCALAPPDATA")
        .or_else(|_| std::env::var("APPDATA"))
        .unwrap_or_else(|_| r"C:\ProgramData".to_string());
    PathBuf::from(base).join("MyDns").join("mydns.log")
}

/// Catat peristiwa penting ke berkas. Kegagalan menulis sengaja diabaikan:
/// DNS tidak boleh ikut gagal hanya karena log tidak bisa ditulis.
pub fn event(text: &str) {
    let _ = append_event(text);
}

fn append_event(text: &str) -> Result<(), String> {
    let path = log_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| e.to_string())?;
    writeln!(file, "{} {}", timestamp(), text).map_err(|e| e.to_string())
}

/// Baris terakhir dari berkas log, terlama → terbaru.
pub fn tail(count: usize) -> Result<Vec<String>, String> {
    let path = log_path();
    let raw = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let lines: Vec<&str> = raw.lines().collect();
    let start = lines.len().saturating_sub(count);
    Ok(lines[start..].iter().map(|line| line.to_string()).collect())
}

fn timestamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Tanggal kalender dari jumlah hari sejak 1970-01-01 (algoritma Howard Hinnant).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    (y + if m <= 2 { 1 } else { 0 }, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_berbentuk_iso() {
        let text = timestamp();
        assert_eq!(text.len(), 20, "{text}");
        assert!(text.ends_with('Z'), "{text}");
        assert_eq!(&text[4..5], "-", "{text}");
    }
}
