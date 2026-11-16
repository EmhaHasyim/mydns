//! Mode daemon: proxy tanpa TUI yang bisa dikendalikan lewat named pipe.
//!
//! Ini bagian dari mode layanan yang tidak butuh hak admin untuk berjalan:
//! proxy, status, dan kontrol tetap hidup tanpa terminal TUI. Pengalihan DNS
//! memakai jalur yang sama dengan TUI, jadi kalau proses dijalankan tanpa hak
//! admin, DNS tidak diubah dan itu dilaporkan dengan jelas.

use crate::log::{self, Log};
use crate::providers;
use crate::server::{self, Proxy};
use crate::{engine, win};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};
use tokio::sync::{mpsc, watch};

/// Nama pipe. Satu daemon per sesi pengguna.
pub const PIPE: &str = r"\\.\pipe\mydns-daemon";

#[derive(Debug)]
enum Command {
    Restore,
    Stop,
}

/// Jalankan daemon sampai Ctrl+C atau perintah `stop` lewat pipe.
pub fn run(provider_id: &str) -> Result<(), String> {
    let Some(provider) = providers::find(provider_id) else {
        return Err(format!(
            "provider tidak dikenal: {provider_id} (pilihan: {})",
            providers::providers()
                .iter()
                .map(|p| p.id)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    };

    let rt = crate::runtime();
    rt.block_on(serve(provider))
}

/// Kirim satu perintah ke daemon dan cetak balasannya.
pub fn control(command: &str) -> Result<String, String> {
    let command = command.trim();
    if !matches!(command, "status" | "restore" | "stop") {
        return Err(format!(
            "perintah kontrol tidak dikenal: {command} (pilihan: status, restore, stop)"
        ));
    }

    let rt = crate::runtime();
    rt.block_on(async move {
        let mut client = ClientOptions::new().open(PIPE).map_err(|_| {
            "daemon tidak berjalan (jalankan `mydns daemon <provider>` dulu)".to_string()
        })?;
        client
            .write_all(format!("{command}\n").as_bytes())
            .await
            .map_err(|e| format!("gagal mengirim perintah: {e}"))?;
        client.flush().await.map_err(|e| e.to_string())?;

        let mut reader = BufReader::new(client);
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
            .await
            .map_err(|_| "daemon tidak menjawab dalam 5 detik".to_string())?
            .map_err(|e| format!("gagal membaca balasan: {e}"))?;
        Ok(line.trim_end().to_string())
    })
}

async fn serve(provider: &'static providers::Provider) -> Result<(), String> {
    // Instance pertama dipegang terus: nama pipe tetap terpakai selama daemon
    // hidup, sehingga daemon kedua ditolak alih-alih berebut port 53.
    let first = match ServerOptions::new().first_pipe_instance(true).create(PIPE) {
        Ok(server) => server,
        Err(e) => {
            return Err(format!(
                "daemon lain sudah berjalan (pipe {} tidak bisa dibuat: {e})",
                PIPE
            ));
        }
    };

    let log = Arc::new(Log::new());
    let engine = engine::Engine::new(provider)?;
    let bound = server::bind(engine, log.clone()).await?;
    let v6 = bound.v6;
    let proxy = bound.proxy.clone();
    let (stop_tx, stop_rx) = watch::channel(false);
    tokio::spawn(async move { bound.serve(stop_rx).await });

    let (cmd_tx, mut cmd_rx) = mpsc::channel::<Command>(8);
    let started = Instant::now();
    let name = provider.name.to_string();
    tokio::spawn(pipe_loop(
        Some(first),
        cmd_tx,
        proxy.clone(),
        name.clone(),
        started,
    ));

    println!(
        "Daemon {} siap di {} dan {}",
        name,
        server::ADDR_V4,
        server::ADDR_V6
    );
    let id = provider.id.to_string();
    let mut applied = false;
    match tokio::task::spawn_blocking(move || win::apply(&id, v6)).await {
        Ok(Ok(adapters)) => {
            applied = true;
            println!("DNS dialihkan ke proxy pada {} adapter.", adapters.len());
            log::event(&format!("daemon: DNS dialihkan ke {name}"));
        }
        Ok(Err(e)) => {
            println!("DNS tidak diubah: {e}");
            println!("Proxy tetap berjalan; jalankan sebagai admin agar DNS ikut dialihkan.");
            log::event(&format!("daemon: DNS tidak diubah: {e}"));
        }
        Err(e) => println!("DNS tidak diubah: tugas apply gagal: {e}"),
    }
    println!("Kontrol: mydns control status | restore | stop\n");

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("berhenti");
                break;
            }
            command = cmd_rx.recv() => {
                match command {
                    Some(Command::Restore) => {
                        println!("memulihkan DNS…");
                        match tokio::task::spawn_blocking(win::restore).await {
                            Ok(Ok(message)) => {
                                applied = false;
                                println!("{message}");
                                log::event(&format!("daemon: {message}"));
                            }
                            Ok(Err(e)) => println!("DNS tidak dipulihkan: {e}"),
                            Err(e) => println!("DNS tidak dipulihkan: {e}"),
                        }
                    }
                    Some(Command::Stop) | None => break,
                }
            }
        }
    }

    drop(stop_tx);
    if applied {
        println!("memulihkan DNS sebelum keluar…");
        match tokio::task::spawn_blocking(win::restore).await {
            Ok(Ok(message)) => log::event(&format!("daemon berhenti: {message}")),
            Ok(Err(e)) => log::event(&format!("daemon berhenti, DNS tidak dipulihkan: {e}")),
            Err(e) => log::event(&format!("daemon berhenti, DNS tidak dipulihkan: {e}")),
        }
    } else {
        log::event("daemon berhenti");
    }
    // Beri listener waktu melepas port 53 sebelum proses keluar.
    tokio::time::sleep(Duration::from_millis(150)).await;
    Ok(())
}

/// Terima satu koneksi pada satu waktu; perintah `status` dijawab langsung.
async fn pipe_loop(
    first: Option<NamedPipeServer>,
    tx: mpsc::Sender<Command>,
    proxy: Arc<Proxy>,
    provider: String,
    started: Instant,
) {
    let mut next = first;
    loop {
        let mut server = match next.take() {
            Some(server) => server,
            None => match ServerOptions::new().create(PIPE) {
                Ok(server) => server,
                Err(e) => {
                    eprintln!("pipe: tidak bisa membuat instance: {e}");
                    return;
                }
            },
        };
        if server.connect().await.is_err() {
            continue;
        }

        let mut line = String::new();
        let read = tokio::time::timeout(Duration::from_secs(2), async {
            let mut reader = BufReader::new(&mut server);
            reader.read_line(&mut line).await
        })
        .await;
        let command = match read {
            Ok(Ok(_)) => line.trim().to_string(),
            // Klien yang pergi atau tidak mengirim apa pun tidak mematikan daemon.
            _ => continue,
        };

        let reply = match command.as_str() {
            "status" => format!(
                "daemon aktif · provider={} · uptime={}s · cache={} hit / {} miss · {} diteruskan · {} + {}",
                provider,
                started.elapsed().as_secs(),
                proxy.hits(),
                proxy.misses(),
                proxy.forwards(),
                server::ADDR_V4,
                server::ADDR_V6
            ),
            "restore" => match tx.try_send(Command::Restore) {
                Ok(()) => "permintaan pulihkan diterima".to_string(),
                Err(_) => "daemon sedang sibuk; coba lagi".to_string(),
            },
            "stop" => match tx.try_send(Command::Stop) {
                Ok(()) => "daemon berhenti".to_string(),
                Err(_) => "daemon sedang sibuk; coba lagi".to_string(),
            },
            "" => "perintah kosong".to_string(),
            other => format!("perintah tidak dikenal: {other} (pilihan: status, restore, stop)"),
        };

        let _ = server.write_all(format!("{reply}\n").as_bytes()).await;
        let _ = server.flush().await;
    }
}
