//! TUI pemilih resolver: pilih provider → proxy lokal hidup → adapter diarahkan
//! ke 127.0.0.1. Saat keluar, DNS dikembalikan supaya internet tidak terputus.
//!
//! Tata letak mengikuti pola 4 zona yang lazim di TUI yang mudah dipakai:
//! header (konteks) · konten (daftar + detail) · status bar (umpan balik) ·
//! footer (tombol). Warna dipakai secara semantik, bukan hiasan.

use crate::engine::{Engine, build_query};
use crate::log::Log;
use crate::providers::{Proto, providers};
use crate::server;
use crate::win;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::prelude::*;
use ratatui::widgets::{
    Block, BorderType, Borders, Cell, Clear, Padding, Paragraph, Row, Table, TableState, Wrap,
};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio::sync::{Mutex, watch};
use tokio::task::JoinHandle;

// ── palet: dark + cyan, semua peran semantik ────────────────────────────
const BG: Color = Color::Rgb(13, 17, 23);
const SURFACE: Color = Color::Rgb(19, 24, 31);
const SURFACE_ALT: Color = Color::Rgb(26, 36, 46);
const BORDER: Color = Color::Rgb(44, 55, 68);
const TEXT: Color = Color::Rgb(226, 232, 240);
const MUTED: Color = Color::Rgb(132, 145, 160);
const ACCENT: Color = Color::Rgb(34, 211, 238);
const ACCENT_DIM: Color = Color::Rgb(14, 116, 144);
const OK: Color = Color::Rgb(52, 211, 153);
const WARN: Color = Color::Rgb(251, 191, 36);
const ERR: Color = Color::Rgb(248, 113, 113);

const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

// ── ukuran tata letak ──────────────────────────────────────────────────
const MIN_WIDTH: u16 = 60;
const MIN_HEIGHT: u16 = 16;
/// Lebar minimum sebelum panel detail ikut ditampilkan.
const DETAIL_MIN_WIDTH: u16 = 92;
const DETAIL_WIDTH: u16 = 36;
const HELP_WIDTH: u16 = 58;
const HELP_HEIGHT: u16 = 12;

const HELP_KEYS: [(&str, &str); 8] = [
    ("↑ ↓ / j k", "pindah pilihan"),
    ("1 – 9", "lompat ke baris"),
    ("enter", "terapkan resolver (DNS saja)"),
    ("v", "VPN: seluruh trafik lewat WARP"),
    ("c", "Clear DNS (pulihkan)"),
    ("l", "log query terakhir"),
    ("?", "tutup bantuan ini"),
    ("q / x / esc", "keluar (DNS dipulihkan)"),
];

// ── pembentuk gaya: semua span dan blok di bawah memakai ini ────────────

fn fg(color: Color) -> Style {
    Style::new().fg(color)
}

fn bg(color: Color) -> Style {
    Style::new().bg(color)
}

fn bold(color: Color) -> Style {
    fg(color).add_modifier(Modifier::BOLD)
}

/// Satu baris teks satu warna.
fn text(content: impl Into<String>, style: Style) -> Line<'static> {
    Line::from(Span::styled(content.into(), style))
}

/// Label bagian di dalam panel detail.
fn heading(title: &'static str) -> Line<'static> {
    text(title, bold(ACCENT_DIM))
}

/// Panel standar: sudut membulat, latar SURFACE, judul kecil di border.
fn panel(title: &'static str, border: Color, title_color: Color) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(fg(border))
        .style(bg(SURFACE))
        .title(text(title, bold(title_color)))
}

pub enum Msg {
    Working(String),
    Applied {
        index: usize,
        proto: Proto,
        ms: u128,
        adapters: usize,
    },
    Cleared(String),
    Failed(String),
    Stats {
        hits: u64,
        misses: u64,
    },
    Status(String),
}

pub struct Session {
    stop: watch::Sender<bool>,
    proxy_task: JoinHandle<()>,
    stats_task: JoinHandle<()>,
    drift_task: JoinHandle<()>,
    /// Ada isinya kalau sesi ini berjalan sebagai VPN penuh.
    vpn: Option<crate::vpn::Vpn>,
}

struct Active {
    index: usize,
    proto: Proto,
    ms: u128,
}

pub struct App {
    rt: tokio::runtime::Handle,
    tx: UnboundedSender<Msg>,
    session: Arc<Mutex<Option<Session>>>,
    log: Arc<Log>,
    cursor: usize,
    active: Option<Active>,
    status: String,
    dns_now: String,
    is_error: bool,
    busy: bool,
    quit: bool,
    show_help: bool,
    show_log: bool,
    hits: u64,
    misses: u64,
    tick: u64,
    /// Pilihan biner yang diminta pengguna: dengan VPN, atau DNS saja.
    vpn: bool,
    /// Latensi beberapa query terakhir per provider (maks 20), untuk p50 di
    /// panel detail.
    latencies: Vec<Vec<u128>>,
}

fn item_count() -> usize {
    providers().len() + 1 // + Clear DNS
}

impl App {
    fn on_key(&mut self, key: KeyEvent) {
        // Di raw mode Ctrl+C datang sebagai key event, bukan sinyal.
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            if key.code == KeyCode::Char('c') {
                self.quit = true;
            }
            return;
        }

        if self.show_help {
            // Saat bantuan terbuka, tutup dulu sebelum aksi lain.
            match key.code {
                KeyCode::Char('q') | KeyCode::Char('x') => self.quit = true,
                _ => self.show_help = false,
            }
            return;
        }

        if self.show_log {
            match key.code {
                KeyCode::Char('q') | KeyCode::Char('x') => self.quit = true,
                _ => self.show_log = false,
            }
            return;
        }

        match key.code {
            // Keluar selalu memulihkan DNS (lihat blok cleanup di `run`).
            KeyCode::Char('q') | KeyCode::Char('x') | KeyCode::Esc => self.quit = true,
            KeyCode::Char('?') | KeyCode::Char('h') => self.show_help = true,
            KeyCode::Char('l') => self.show_log = true,
            KeyCode::Up | KeyCode::Char('k') => {
                self.cursor = (self.cursor + item_count() - 1) % item_count();
            }
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                self.cursor = (self.cursor + 1) % item_count();
            }
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = item_count() - 1,
            KeyCode::Enter => self.activate(),
            KeyCode::Char('v') => self.toggle_vpn(),
            KeyCode::Char('c') => self.clear_dns(),
            KeyCode::Char(d @ '1'..='9') => {
                // Angka 1–9 langsung menuju baris, tanpa menerapkan apa pun.
                let index = d as usize - '0' as usize;
                if (1..=item_count()).contains(&index) {
                    self.cursor = index - 1;
                }
            }
            _ => {}
        }
    }

    /// Kunci input selama pekerjaan berjalan; `false` kalau masih sibuk.
    fn begin(&mut self, status: String) -> bool {
        if self.busy {
            return false;
        }
        self.busy = true;
        self.is_error = false;
        self.status = status;
        true
    }

    fn idle(&mut self) {
        self.busy = false;
        self.is_error = false;
    }

    fn activate(&mut self) {
        if self.cursor == providers().len() {
            self.clear_dns();
            return;
        }
        let index = self.cursor;
        if !self.begin(format!("menyiapkan {}…", providers()[index].name)) {
            return;
        }

        let rt = self.rt.clone();
        let tx = self.tx.clone();
        let session = self.session.clone();
        let log = self.log.clone();
        // Saat VPN menyala, resolver yang dipakai adalah WARP: seluruh query
        // ikut tunnel, tidak ada jalur DNS yang keluar sendiri.
        let vpn = self.vpn;
        rt.spawn(async move {
            apply_flow(index, vpn, session, log, tx).await;
        });
    }

    /// Satu tombol untuk pilihan biner: dengan VPN, atau DNS saja.
    fn toggle_vpn(&mut self) {
        if self.vpn {
            self.vpn = false;
            self.clear_dns();
            self.status = "VPN dimatikan · tekan enter untuk DNS saja".to_string();
            return;
        }

        let Some(index) = providers().iter().position(|p| p.id == "warp") else {
            self.is_error = true;
            self.status = "resolver WARP tidak tersedia".to_string();
            return;
        };
        if !self.begin("menyalakan VPN — seluruh trafik lewat WARP…".to_string()) {
            return;
        }
        self.vpn = true;

        let rt = self.rt.clone();
        let tx = self.tx.clone();
        let session = self.session.clone();
        let log = self.log.clone();
        rt.spawn(async move {
            apply_flow(index, true, session, log, tx).await;
        });
    }

    fn clear_dns(&mut self) {
        if !self.begin("mengembalikan DNS ke setelan awal…".to_string()) {
            return;
        }

        let rt = self.rt.clone();
        let tx = self.tx.clone();
        let session = self.session.clone();
        rt.spawn(async move {
            stop_session(&session).await;
            // Sisa rute dari sesi yang tidak sempat membersihkan diri juga
            // dicabut, supaya "Clear DNS" benar-benar mengembalikan semuanya.
            let _ = tokio::task::spawn_blocking(crate::vpn::down_persisted).await;
            let outcome = tokio::task::spawn_blocking(win::restore).await;
            let message = match outcome {
                Ok(Ok(msg)) => Msg::Cleared(msg),
                Ok(Err(e)) => Msg::Failed(e),
                Err(e) => Msg::Failed(format!("gagal menjalankan pemulihan: {e}")),
            };
            let _ = tx.send(message);
        });
    }

    fn on_msg(&mut self, msg: Msg) {
        match msg {
            Msg::Working(text) => self.status = text,
            Msg::Applied {
                index,
                proto,
                ms,
                adapters,
            } => {
                self.idle();
                self.active = Some(Active { index, proto, ms });
                self.status = format!(
                    "aktif · {} lewat {} · {} ms",
                    providers()[index].name,
                    proto.label(),
                    ms
                );
                self.dns_now = format!("{adapters} adapter → 127.0.0.1  ·  proxy lokal :53");
                if let Some(samples) = self.latencies.get_mut(index) {
                    samples.push(ms);
                    if samples.len() > 20 {
                        samples.remove(0);
                    }
                }
                crate::log::event(&format!(
                    "aktif: {} lewat {} ({} ms, {} adapter)",
                    providers()[index].name,
                    proto.label(),
                    ms,
                    adapters
                ));
            }
            Msg::Cleared(text) => {
                self.idle();
                self.active = None;
                self.hits = 0;
                self.misses = 0;
                self.dns_now = "setelan DNS asli dipulihkan".to_string();
                crate::log::event(&format!("restore: {text}"));
                self.status = text;
            }
            Msg::Failed(error) => {
                self.idle();
                self.is_error = true;
                self.active = None;
                // Gagal berarti tidak ada tunnel yang tersisa: jangan biarkan
                // header mengaku VPN menyala.
                self.vpn = false;
                crate::log::event(&format!("gagal: {error}"));
                self.status = error;
            }
            Msg::Stats { hits, misses } => {
                self.hits = hits;
                self.misses = misses;
            }
            Msg::Status(summary) => self.dns_now = format_status(&summary),
        }
    }

    // ── gambar ──────────────────────────────────────────────────────────

    fn draw(&self, frame: &mut Frame) {
        let area = frame.area();
        frame.render_widget(Block::default().style(fg(TEXT).bg(BG)), area);

        if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
            self.draw_too_small(frame, area);
            return;
        }

        let [header, body, status, footer] = Layout::vertical([
            Constraint::Length(3),
            Constraint::Min(6),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .areas(area);

        self.draw_header(frame, header);
        self.draw_body(frame, body);
        self.draw_status(frame, status);
        self.draw_footer(frame, footer);

        if self.show_help {
            self.draw_help(frame, area);
        } else if self.show_log {
            self.draw_log(frame, area);
        }
    }

    fn draw_too_small(&self, frame: &mut Frame, area: Rect) {
        let hint = Paragraph::new(vec![
            text("terminal terlalu kecil", bold(WARN)),
            text(
                format!(
                    "butuh minimal {MIN_WIDTH}×{MIN_HEIGHT}, sekarang {}×{}",
                    area.width, area.height
                ),
                fg(MUTED),
            ),
        ])
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(fg(BORDER)),
        );
        let popup = area.centered(Constraint::Length(44), Constraint::Length(5));
        frame.render_widget(hint, popup);
    }

    fn draw_header(&self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::BOTTOM)
            .border_style(fg(BORDER))
            .style(bg(SURFACE))
            .padding(Padding::horizontal(1));
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let [title_area, badge_area] =
            Layout::horizontal([Constraint::Min(20), Constraint::Length(34)]).areas(inner);

        let dns_color = if self.dns_now.contains("127.0.0.1") {
            WARN
        } else {
            MUTED
        };
        let title = Paragraph::new(vec![
            Line::from(vec![
                Span::styled("◆ ", fg(ACCENT)),
                Span::styled("MyDNS", bold(TEXT)),
                Span::styled("   DNS over QUIC · HTTP/3", fg(MUTED)),
            ]),
            Line::from(vec![
                Span::styled("DNS ", fg(ACCENT_DIM)),
                Span::styled(self.dns_now.as_str(), fg(dns_color)),
            ]),
        ])
        .style(bg(SURFACE));
        frame.render_widget(title, title_area);

        let (dot, label, color) = match &self.active {
            Some(active) => (
                "●",
                format!(
                    "{} · {}",
                    providers()[active.index].name,
                    active.proto.label()
                ),
                OK,
            ),
            None => ("○", "tidak aktif".to_string(), MUTED),
        };
        let badge = Paragraph::new(Line::from(vec![
            Span::styled(format!("{dot} "), fg(color)),
            Span::styled(label, fg(color)),
        ]))
        .alignment(Alignment::Right)
        .style(bg(SURFACE));
        frame.render_widget(badge, badge_area);
    }

    fn draw_body(&self, frame: &mut Frame, area: Rect) {
        if area.width >= DETAIL_MIN_WIDTH {
            let [list, detail] =
                Layout::horizontal([Constraint::Min(50), Constraint::Length(DETAIL_WIDTH)])
                    .spacing(1)
                    .areas(area);
            self.draw_table(frame, list);
            self.draw_detail(frame, detail);
        } else {
            self.draw_table(frame, area);
        }
    }

    fn draw_table(&self, frame: &mut Frame, area: Rect) {
        let mut rows: Vec<Row> = providers()
            .iter()
            .enumerate()
            .map(|(index, provider)| {
                let marker = if self.active.as_ref().is_some_and(|a| a.index == index) {
                    Span::styled("● ", fg(OK))
                } else {
                    Span::raw("  ")
                };
                Row::new(vec![
                    Cell::from(Line::from(vec![
                        marker,
                        Span::styled(provider.name, bold(TEXT)),
                    ])),
                    Cell::from(text(provider.badges(), fg(ACCENT))),
                    Cell::from(text(provider.note, fg(MUTED))),
                ])
            })
            .collect();

        // Baris terakhir: pulihkan DNS. Kuning = aksi "kembali", bukan destruktif.
        rows.push(Row::new(vec![
            Cell::from(Line::from(vec![
                Span::raw("  "),
                Span::styled("Clear DNS", bold(WARN)),
            ])),
            Cell::from(text("—", fg(MUTED))),
            Cell::from(text("kembalikan ke DNS asli", fg(MUTED))),
        ]));

        let table = Table::new(
            rows,
            [
                Constraint::Length(17),
                Constraint::Length(10),
                Constraint::Min(14),
            ],
        )
        .header(Row::new(vec!["RESOLVER", "PROTOKOL", "KETERANGAN"]).style(bold(ACCENT_DIM)))
        .block(panel(" resolver ", BORDER, ACCENT_DIM).padding(Padding::horizontal(1)))
        .column_spacing(1)
        .highlight_symbol("▌ ")
        .row_highlight_style(fg(ACCENT).bg(SURFACE_ALT).add_modifier(Modifier::BOLD));

        let mut state = TableState::default();
        state.select(Some(self.cursor));
        frame.render_stateful_widget(table, area, &mut state);
    }

    fn draw_detail(&self, frame: &mut Frame, area: Rect) {
        let detail = Paragraph::new(self.detail_lines())
            .wrap(Wrap { trim: false })
            .block(panel(" detail ", BORDER, ACCENT_DIM).padding(Padding::horizontal(1)));
        frame.render_widget(detail, area);
    }

    /// Ringkasan latensi query terakhir untuk satu provider.
    fn latency_summary(&self, index: usize) -> Option<String> {
        let samples = self.latencies.get(index)?;
        if samples.is_empty() {
            return None;
        }
        let mut sorted = samples.clone();
        sorted.sort_unstable();
        let p50 = sorted[sorted.len() / 2];
        Some(format!("p50 {p50} ms · {} query", samples.len()))
    }

    fn detail_lines(&self) -> Vec<Line<'static>> {
        let Some(provider) = providers().get(self.cursor) else {
            return self.clear_detail_lines();
        };

        // WARP tidak punya endpoint DoQ/DoH statis, jadi panel detailnya
        // menampilkan status perangkat, bukan URL resolver.
        if provider.warp {
            let mut lines = vec![
                text(provider.name, bold(ACCENT)),
                text(provider.note, fg(MUTED)),
                Line::default(),
                text("MASQUE  ·  CONNECT-IP", bold(ACCENT_DIM)),
                text("HTTP/3 + QUIC datagram", fg(TEXT)),
                Line::default(),
                heading("PERANGKAT"),
            ];
            match crate::warp::load() {
                Ok(config) => {
                    lines.push(text(config.device_id.clone(), fg(TEXT)));
                    lines.push(text(config.endpoint_v4, fg(MUTED)));
                }
                Err(_) => lines.push(text("didaftarkan otomatis saat WARP dipakai", fg(MUTED))),
            }
            if let Some(active) = self.active.as_ref().filter(|a| a.index == self.cursor) {
                lines.push(Line::default());
                lines.push(Line::from(vec![
                    Span::styled("● aktif ", fg(OK)),
                    Span::styled(
                        format!("· {} · {} ms", active.proto.label(), active.ms),
                        fg(MUTED),
                    ),
                ]));
                if let Some(summary) = self.latency_summary(active.index) {
                    lines.push(text(summary, fg(MUTED)));
                }
            }
            return lines;
        }

        // Judul memakai port yang benar-benar dipakai provider, supaya resolver
        // kustom dengan port lain tidak ditampilkan seolah-olah 853.
        let doq_title = match provider.doq {
            Some((_, port)) => format!("DOQ  ·  UDP {port}"),
            None => "DOQ  ·  UDP 853".to_string(),
        };
        let mut lines = vec![
            text(provider.name, bold(ACCENT)),
            text(provider.note, fg(MUTED)),
            Line::default(),
            text(doq_title, bold(ACCENT_DIM)),
        ];
        lines.push(match provider.doq {
            Some((host, port)) => text(format!("{host}:{port}"), fg(TEXT)),
            None => text("tidak tersedia", fg(MUTED)),
        });
        lines.push(Line::default());

        lines.push(heading("DOH  ·  HTTPS 443"));
        lines.push(match provider.doh {
            Some(url) => text(url, fg(TEXT)),
            None => text("tidak tersedia", fg(MUTED)),
        });
        lines.push(Line::default());

        lines.push(heading("BOOTSTRAP IP"));
        lines.push(text(provider.boot.join(", "), fg(MUTED)));

        if let Some(active) = self.active.as_ref().filter(|a| a.index == self.cursor) {
            lines.push(Line::default());
            lines.push(Line::from(vec![
                Span::styled("● aktif ", fg(OK)),
                Span::styled(
                    format!("· {} · {} ms", active.proto.label(), active.ms),
                    fg(MUTED),
                ),
            ]));
        }

        lines
    }

    /// Isi panel detail saat baris "Clear DNS" yang dipilih.
    fn clear_detail_lines(&self) -> Vec<Line<'static>> {
        vec![
            text("Clear DNS", bold(WARN)),
            Line::default(),
            text(
                "Kembalikan DNS ke kondisi sebelum MyDNS menimpanya: DHCP, atau daftar \
                 server statis yang dicatat saat provider diterapkan.",
                fg(MUTED),
            ),
            Line::default(),
            Line::from(vec![
                Span::styled("Tekan ", fg(MUTED)),
                Span::styled("enter", fg(ACCENT)),
                Span::styled(" atau ", fg(MUTED)),
                Span::styled("c", fg(ACCENT)),
                Span::styled(" untuk memulihkan.", fg(MUTED)),
            ]),
        ]
    }

    fn draw_status(&self, frame: &mut Frame, area: Rect) {
        let (symbol, color) = if self.is_error {
            ("✕", ERR)
        } else if self.busy {
            (SPINNER[self.tick as usize % SPINNER.len()], WARN)
        } else if self.active.is_some() {
            ("●", OK)
        } else {
            ("·", MUTED)
        };

        let status = Paragraph::new(Line::from(vec![
            Span::styled(format!(" {symbol} "), fg(color)),
            Span::styled(
                self.status.as_str(),
                fg(if self.is_error { ERR } else { TEXT }),
            ),
        ]))
        .style(bg(SURFACE));
        frame.render_widget(status, area);
    }

    fn draw_footer(&self, frame: &mut Frame, area: Rect) {
        let [keys_area, cache_area] =
            Layout::horizontal([Constraint::Min(30), Constraint::Length(32)]).areas(area);

        let key = |k: &'static str| Span::styled(k, fg(ACCENT));
        let hint = |t: &'static str| Span::styled(t, fg(MUTED));
        let keys = Paragraph::new(Line::from(vec![
            Span::raw(" "),
            key("↑↓"),
            hint(" pilih   "),
            key("enter"),
            hint(" terapkan   "),
            key("c"),
            hint(" clear   "),
            key("?"),
            hint(" bantuan   "),
            key("q"),
            hint(" keluar"),
        ]))
        .style(bg(SURFACE));
        frame.render_widget(keys, keys_area);

        let cache = if self.active.is_some() {
            format!(
                "{} hit · {} miss ",
                compact(self.hits),
                compact(self.misses)
            )
        } else {
            "cache —  ".to_string()
        };
        let cache_widget = Paragraph::new(Span::styled(cache, fg(MUTED)))
            .alignment(Alignment::Right)
            .style(bg(SURFACE));
        frame.render_widget(cache_widget, cache_area);
    }

    /// Panel log: query terakhir, terbaru di baris paling bawah.
    fn draw_log(&self, frame: &mut Frame, area: Rect) {
        let width = area.width.saturating_sub(4).min(110);
        let height = area.height.saturating_sub(4);
        let popup = area.centered(Constraint::Length(width), Constraint::Length(height));
        frame.render_widget(Clear, popup);

        let rows = usize::from(popup.height.saturating_sub(2));
        let entries = self.log.snapshot();
        let mut lines: Vec<Line<'static>> = Vec::with_capacity(rows);
        if entries.is_empty() {
            lines.resize(rows.saturating_sub(1), Line::default());
            lines.push(text("belum ada query", fg(MUTED)));
        } else {
            let visible = entries.len().min(rows);
            lines.resize(rows - visible, Line::default());
            for entry in &entries[entries.len() - visible..] {
                lines.push(text(entry.clone(), fg(MUTED)));
            }
        }

        let log = Paragraph::new(lines).block(
            panel(" log · l atau esc menutup ", BORDER, ACCENT_DIM).padding(Padding::horizontal(1)),
        );
        frame.render_widget(log, popup);
    }

    fn draw_help(&self, frame: &mut Frame, area: Rect) {
        let popup = area.centered(
            Constraint::Length(HELP_WIDTH),
            Constraint::Length(HELP_HEIGHT),
        );
        frame.render_widget(Clear, popup);

        let mut lines = vec![Line::default()];
        lines.extend(HELP_KEYS.map(|(key, desc)| {
            Line::from(vec![
                Span::styled(format!("  {key:<12}"), fg(ACCENT)),
                Span::styled(desc, fg(TEXT)),
            ])
        }));
        lines.push(Line::default());
        lines.push(text(
            "  Aksi apa pun yang butuh hak admin akan memunculkan UAC.",
            fg(MUTED),
        ));

        let help = Paragraph::new(lines).block(panel(" bantuan ", ACCENT_DIM, ACCENT));
        frame.render_widget(help, popup);
    }
}

/// Angka ringkas untuk footer: 1200 → "1.2k", 3_400_000 → "3.4M".
fn compact(value: u64) -> String {
    if value >= 1_000_000 {
        format!("{:.1}M", value as f64 / 1_000_000.0)
    } else if value >= 1_000 {
        format!("{:.1}k", value as f64 / 1_000.0)
    } else {
        value.to_string()
    }
}

fn format_status(summary: &str) -> String {
    if summary.contains("127.0.0.1") {
        format!(
            "DNS masih menunjuk 127.0.0.1 dari sesi sebelumnya — pilih Clear DNS atau resolver baru ({summary})"
        )
    } else {
        summary.to_string()
    }
}

/// Hentikan proxy yang sudah berjalan lalu laporkan kegagalan. Semua jalur
/// gagal di alur terapkan memakai ini supaya urutannya selalu sama: hentikan
/// listener, tunggu task-nya, baru kirim pesan.
async fn abort(
    stop: watch::Sender<bool>,
    proxy_task: JoinHandle<()>,
    tx: UnboundedSender<Msg>,
    message: String,
) {
    let _ = stop.send(true);
    let _ = proxy_task.await;
    let _ = tx.send(Msg::Failed(message));
}

async fn stop_session(session: &Arc<Mutex<Option<Session>>>) {
    let taken = { session.lock().await.take() };
    if let Some(session) = taken {
        let Session {
            stop,
            proxy_task,
            stats_task,
            drift_task,
            vpn,
        } = session;
        let _ = stop.send(true);
        let _ = proxy_task.await;
        let _ = stats_task.await;
        let _ = drift_task.await;
        // Proxy berhenti dulu, baru tunnel: pengguna tidak pernah kehilangan
        // resolver selama rute masih dialihkan.
        if let Some(vpn) = vpn {
            let _ = vpn.down().await;
        }
    }
}

async fn apply_flow(
    index: usize,
    vpn_mode: bool,
    session: Arc<Mutex<Option<Session>>>,
    log: Arc<Log>,
    tx: UnboundedSender<Msg>,
) {
    let provider = &providers()[index];

    stop_session(&session).await;
    let _ = tx.send(Msg::Working(format!(
        "menghubungi {} lewat QUIC…",
        provider.name
    )));

    // 1. Engine + listener disiapkan lebih dulu: kalau port 53 dipakai proses
    //    lain, kita gagal sebelum menyentuh setelan DNS pengguna.
    let engine = match Engine::new(provider) {
        Ok(engine) => engine,
        Err(e) => {
            let _ = tx.send(Msg::Failed(e));
            return;
        }
    };
    let watch_log = log.clone();
    let bound = match server::bind(engine.clone(), log).await {
        Ok(bound) => bound,
        Err(e) => {
            let _ = tx.send(Msg::Failed(e));
            return;
        }
    };

    // Hanya pasang `::1` sebagai DNS kalau listener IPv6 benar-benar terikat.
    let listen_v6 = bound.v6;
    let (stop_tx, _) = watch::channel(false);
    let proxy = bound.proxy.clone();
    let stop_rx = stop_tx.subscribe();
    let proxy_task = tokio::spawn(async move { bound.serve(stop_rx).await });

    // 2. Warm-up: membuka koneksi QUIC dan mengukur latensi nyata.
    let started = Instant::now();
    let query = build_query("example.com.");
    let proto = match engine.resolve(&query).await {
        Ok((_, proto)) => proto,
        Err(e) => {
            abort(
                stop_tx,
                proxy_task,
                tx,
                format!("tidak bisa menghubungi {}: {e}", provider.name),
            )
            .await;
            return;
        }
    };
    let ms = started.elapsed().as_millis();

    // 3. Buktikan listener lokal benar-benar melayani query sebelum DNS
    //    pengguna disentuh. Kalau tidak, gagal di sini — bukan setelah adapter
    //    sudah diarahkan ke port yang mati.
    if let Err(e) = server::probe().await {
        abort(
            stop_tx,
            proxy_task,
            tx,
            format!("proxy lokal tidak melayani query: {e}"),
        )
        .await;
        return;
    }

    // 3b. Mode VPN: seluruh trafik dialihkan lewat tunnel WARP. Rute dipasang
    //     sebelum DNS disentuh, dan `Vpn::up` mencabutnya sendiri kalau tunnel
    //     ternyata tidak meneruskan trafik.
    let mut vpn = if vpn_mode {
        let _ = tx.send(Msg::Working(
            "membuka tunnel WARP untuk seluruh trafik…".to_string(),
        ));
        match crate::vpn::Vpn::up().await {
            Ok(tunnel) => Some(tunnel),
            Err(e) => {
                abort(stop_tx, proxy_task, tx, e).await;
                return;
            }
        }
    } else {
        None
    };

    // 4. Baru arahkan adapter ke loopback.
    let id = provider.id;
    let applied = tokio::task::spawn_blocking(move || win::apply(id, listen_v6)).await;
    let adapters = match applied {
        Ok(Ok(adapters)) => adapters,
        Ok(Err(e)) => {
            if let Some(vpn) = vpn.take() {
                let _ = vpn.down().await;
            }
            abort(stop_tx, proxy_task, tx, e).await;
            return;
        }
        Err(e) => {
            if let Some(vpn) = vpn.take() {
                let _ = vpn.down().await;
            }
            abort(
                stop_tx,
                proxy_task,
                tx,
                format!("gagal menerapkan DNS: {e}"),
            )
            .await;
            return;
        }
    };

    // 5. Verifikasi lewat resolver sistem (bukan lewat engine kita sendiri).
    //    Kalau Windows tetap tidak bisa resolve, DNS dikembalikan otomatis
    //    supaya pengguna tidak ditinggal tanpa internet.
    let verified = tokio::task::spawn_blocking(win::verify_resolution).await;
    let verdict = match verified {
        Ok(result) => result,
        Err(e) => Err(format!("tugas verifikasi gagal: {e}")),
    };
    if let Err(e) = verdict {
        if let Some(vpn) = vpn.take() {
            let _ = vpn.down().await;
        }
        let _ = tokio::task::spawn_blocking(win::restore).await;
        abort(
            stop_tx,
            proxy_task,
            tx,
            format!("DNS dikembalikan otomatis — resolver sistem tidak menjawab setelah pengalihan ({e})"),
        )
        .await;
        return;
    }

    // 6. Statistik cache untuk footer.
    let mut stop_stats = stop_tx.subscribe();
    let stats_tx = tx.clone();
    let stats_proxy = proxy.clone();
    let stats_task = tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                changed = stop_stats.changed() => {
                    if changed.is_err() || *stop_stats.borrow() { break; }
                }
                _ = tick.tick() => {
                    let msg = Msg::Stats {
                        hits: stats_proxy.hits(),
                        misses: stats_proxy.misses(),
                    };
                    if stats_tx.send(msg).is_err() { break; }
                }
            }
        }
    });

    // 7. Jaga perubahan jaringan. Pindah Wi-Fi/VPN atau bangun dari sleep bisa
    //    membuat DHCP menimpa DNS adapter; selama sesi ini hidup, adapter yang
    //    tidak lagi menunjuk proxy dikembalikan (dan tetap tercatat di state,
    //    jadi Clear DNS tetap mengembalikan setelan aslinya).
    let mut drift_stop = stop_tx.subscribe();
    let drift_tx = tx.clone();
    let drift_id = provider.id;
    let drift_v6 = listen_v6;
    let drift_task = tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(3));
        let mut last_failure: Option<Instant> = None;
        loop {
            tokio::select! {
                changed = drift_stop.changed() => {
                    if changed.is_err() || *drift_stop.borrow() { break; }
                }
                _ = tick.tick() => {
                    // Jangan menghajar PowerShell tiap 3 detik kalau hak admin
                    // ternyata tidak ada.
                    if last_failure.is_some_and(|t| t.elapsed() < Duration::from_secs(60)) {
                        continue;
                    }
                    let drifted = tokio::task::spawn_blocking(win::loopback_missing).await;
                    if !matches!(drifted, Ok(true)) {
                        continue;
                    }
                    let applied =
                        tokio::task::spawn_blocking(move || win::apply(drift_id, drift_v6)).await;
                    match applied {
                        Ok(Ok(_)) => {
                            last_failure = None;
                            watch_log.push("adapter dikembalikan ke proxy setelah jaringan berubah");
                            let _ = drift_tx.send(Msg::Working(
                                "jaringan berubah — DNS adapter dikembalikan ke proxy".to_string(),
                            ));
                        }
                        _ => last_failure = Some(Instant::now()),
                    }
                }
            }
        }
    });

    *session.lock().await = Some(Session {
        stop: stop_tx,
        proxy_task,
        stats_task,
        drift_task,
        vpn: vpn.take(),
    });

    let _ = tx.send(Msg::Working(format!(
        "{} adapter diarahkan ke 127.0.0.1",
        adapters.len()
    )));
    let _ = tx.send(Msg::Applied {
        index,
        proto,
        ms,
        adapters: adapters.len(),
    });
}

pub fn run(
    rt: tokio::runtime::Handle,
    session: Arc<Mutex<Option<Session>>>,
) -> std::io::Result<()> {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut app = App {
        rt,
        tx,
        session: session.clone(),
        log: Arc::new(Log::new()),
        cursor: 0,
        active: None,
        status: "siap · pilih resolver lalu tekan enter".to_string(),
        dns_now: "membaca setelan DNS…".to_string(),
        is_error: false,
        busy: false,
        quit: false,
        show_help: false,
        show_log: false,
        hits: 0,
        misses: 0,
        tick: 0,
        vpn: false,
        latencies: vec![Vec::new(); providers().len()],
    };

    // Baca DNS aktif di latar belakang supaya frame pertama tidak tertahan.
    {
        let tx = app.tx.clone();
        app.rt.spawn(async move {
            if let Ok(summary) = tokio::task::spawn_blocking(win::summary).await {
                let _ = tx.send(Msg::Status(summary));
            }
        });
    }

    let mut terminal = ratatui::init();
    let outcome = (|| -> std::io::Result<()> {
        // Frame hanya digambar saat ada yang berubah (tombol, pesan, ukuran
        // jendela, atau spinner yang sedang berjalan). TUI yang menganggur
        // tidak membakar CPU untuk menggambar layar yang sama.
        let mut dirty = true;
        loop {
            if dirty {
                app.tick = app.tick.wrapping_add(1);
                terminal.draw(|frame| app.draw(frame))?;
                dirty = false;
            }
            if event::poll(Duration::from_millis(100))? {
                match event::read()? {
                    // Jendela diubah ukurannya: isi layar lama sudah tidak sah,
                    // wajib digambar ulang walau tidak ada tombol yang ditekan.
                    Event::Resize(_, _) => dirty = true,
                    Event::Key(key) if key.kind == KeyEventKind::Press => {
                        app.on_key(key);
                        dirty = true;
                    }
                    // Event lain (fokus, mouse, key repeat/release) diabaikan.
                    _ => {}
                }
            }
            while let Ok(msg) = rx.try_recv() {
                app.on_msg(msg);
                dirty = true;
            }
            if app.quit {
                break;
            }
            // Spinner butuh frame baru selama pekerjaan berjalan.
            dirty |= app.busy;
        }
        Ok(())
    })();
    ratatui::restore();

    // Apa pun cara keluarnya (q / x / Esc / Ctrl+C), DNS dikembalikan ke setelan
    // semula. Catatan dari sesi sebelumnya juga dibersihkan, supaya tidak ada
    // DNS yang tertinggal menunjuk proxy yang sudah mati.
    let session_for_cleanup = session.clone();
    app.rt.block_on(async move {
        stop_session(&session_for_cleanup).await;
        // Sisa rute dari sesi lama (mis. setelah crash) juga dicabut di sini.
        let _ = tokio::task::spawn_blocking(crate::vpn::down_persisted).await;
        if win::load_state().is_some() {
            let _ = tokio::task::spawn_blocking(win::restore).await;
        }
    });

    outcome
}
