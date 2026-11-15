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

    pub fn push(&self, line: impl Into<String>) {
        let mut buf = match self.buf.lock() {
            Ok(b) => b,
            Err(p) => p.into_inner(),
        };
        buf.push_back(line.into());
        while buf.len() > MAX_LINES {
            buf.pop_front();
        }
    }

    /// Salinan baris terlama → terbaru, untuk panel log di TUI.
    pub fn snapshot(&self) -> Vec<String> {
        let buf = match self.buf.lock() {
            Ok(b) => b,
            Err(p) => p.into_inner(),
        };
        buf.iter().cloned().collect()
    }
}

impl Default for Log {
    fn default() -> Self {
        Self::new()
    }
}
