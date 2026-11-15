//! Buffer log kecil yang bisa dibaca UI tanpa channel.

use std::collections::VecDeque;
use std::sync::Mutex;

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
