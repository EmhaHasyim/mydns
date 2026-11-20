//! MyDNS — pengalih DNS Windows 11 ke DoQ / DoH3 (QUIC) lewat proxy loopback.

mod daemon;
mod engine;
mod log;
mod providers;
mod server;
mod ui;
mod updater;
mod vpn;
mod warp;
mod win;

use crate::log::Log;
use crate::providers::{config_path, providers as resolver_list, read_config};
use crate::win::{ProcessIdentity, parse_process_identity};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn main() {
    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();

    if args
        .iter()
        .any(|a| a == "-h" || a == "--help" || a == "help")
    {
        help();
        return;
    }

    // Pendamping pemulihan (lihat win::spawn_watchdog). Tidak pernah
    // mengubah apa pun selama induknya masih hidup.
    if let Some(pos) = args.iter().position(|a| a == "--watchdog")
        && let Some(ProcessIdentity { pid, start_time }) =
            args.get(pos + 1).and_then(|p| parse_process_identity(p))
    {
        cmd_watchdog(pid, start_time);
        return;
    }

    let command = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .map(|s| s.as_str())
        .unwrap_or("");
    let positional: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();

    match command {
        "" | "tui" => cmd_tui(&args),
        "status" => cmd_status(),
        "restore" | "clear" => cmd_restore(&args),
        "test" => cmd_test(),
        "providers" => cmd_providers(),
        "doctor" => cmd_doctor(),
        "log" => cmd_log(
            positional
                .get(1)
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(40),
        ),
        "autostart" => cmd_autostart(
            &args,
            positional.get(1).map(|s| s.as_str()).unwrap_or("status"),
        ),
        "serve" => cmd_serve(positional.get(1).map(|s| s.as_str()).unwrap_or("adguard")),
        "daemon" => cmd_daemon(
            positional
                .get(1)
                .map(|s| s.as_str())
                .unwrap_or("cloudflare"),
        ),
        "control" => cmd_control(positional.get(1).map(|s| s.as_str()).unwrap_or("status")),
        "warp" => cmd_warp(positional.get(1).map(|s| s.as_str()).unwrap_or("status")),
        "vpn" => cmd_vpn(
            &args,
            positional.get(1).map(|s| s.as_str()).unwrap_or("status"),
            positional.get(2).map(|s| s.as_str()),
        ),
        other => {
            eprintln!("perintah tidak dikenal: {other}\n");
            help();
            std::process::exit(2);
        }
    }
}

fn runtime() -> tokio::runtime::Runtime {
    // Pilih provider kripto secara eksplisit: quinn dan rustls bisa menarik
    // lebih dari satu backend, dan tanpa ini pemilihan default bisa ambigu.
    let _ = rustls::crypto::ring::default_provider().install_default();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("gagal membuat runtime tokio")
}

fn need_admin(args: &[String]) {
    if win::is_elevated() {
        return;
    }
    if args.iter().any(|a| a == "--no-elevate") || std::env::var("MYDNS_NO_ELEVATE").is_ok() {
        eprintln!("peringatan: jalan tanpa hak admin, perubahan DNS akan gagal");
        return;
    }
    println!("MyDNS butuh hak administrator. Membuka prompt UAC…");
    let mut pass: Vec<String> = args
        .iter()
        .filter(|a| a.as_str() != "--elevated")
        .cloned()
        .collect();
    pass.push("--elevated".to_string());
    match win::relaunch_elevated(&pass) {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

fn cmd_tui(args: &[String]) {
    need_admin(args);
    win::install_exit_guard();
    // Backstop untuk kasus yang tidak bisa ditangkap handler: proses dibunuh,
    // panic, atau listrik putus. Watchdog memulihkan DNS setelah induk hilang.
    win::spawn_watchdog();

    let rt = runtime();
    let handle = rt.handle().clone();
    let session = Arc::new(tokio::sync::Mutex::new(None));
    if let Err(e) = ui::run(handle, session) {
        eprintln!("TUI berhenti: {e}");
        std::process::exit(1);
    }
    // Runtime harus hidup lebih lama dari TUI: task proxy, statistik, dan
    // pengawas jaringan berjalan di atasnya sampai pembersihan selesai.
    drop(rt);
}

fn cmd_status() {
    println!("DNS adapter aktif:");
    println!("  {}", win::summary());
    match win::load_state() {
        Some(state) => {
            println!(
                "\nCatatan MyDNS: provider = {}, {} adapter tercatat",
                provider_label(&state.provider),
                state.ifaces.len()
            );
            println!("  state file: {}", win::state_path().display());
        }
        None => println!("\nTidak ada catatan MyDNS (DNS belum pernah diubah aplikasi ini)"),
    }
}

fn cmd_restore(args: &[String]) {
    // --if-stale dipakai Scheduled Task saat logon: hanya memulihkan kalau
    // catatan lama ada dan benar-benar tidak ada proxy yang melayaninya.
    let stale_only = args.iter().any(|a| a == "--if-stale");
    need_admin(args);
    let rt = runtime();
    let (warning, result) = rt.block_on(async {
        // Rute VPN dicabut dulu: internet kembali lewat jalur asli sebelum
        // DNS dipulihkan, jadi tidak ada jendela tanpa koneksi.
        let vpn_error = if stale_only {
            tokio::task::spawn_blocking(vpn::down_if_stale)
                .await
                .map(|r| r.err())
        } else {
            tokio::task::spawn_blocking(vpn::down_persisted)
                .await
                .map(|r| r.err())
        };
        let warning = match vpn_error {
            Ok(Some(e)) => {
                crate::log::event(&format!("restore: rute VPN tidak dicabut: {e}"));
                Some(format!("peringatan: rute VPN tidak berhasil dicabut: {e}"))
            }
            Ok(None) => None,
            Err(e) => {
                crate::log::event(&format!("restore: tugas cabut rute VPN gagal: {e}"));
                Some(format!("peringatan: tugas cabut rute VPN gagal: {e}"))
            }
        };
        let restored = if stale_only {
            tokio::task::spawn_blocking(win::restore_if_stale).await
        } else {
            tokio::task::spawn_blocking(win::restore)
                .await
                .map(|r| r.map(Some))
        };
        (warning, restored)
    });
    match result {
        Ok(Ok(Some(message))) => match &warning {
            Some(w) => println!("{message}\n{w}"),
            None => println!("{message}"),
        },
        Ok(Ok(None)) => match &warning {
            Some(w) => println!("tidak ada yang perlu dipulihkan\n{w}"),
            None => println!("tidak ada yang perlu dipulihkan"),
        },
        Ok(Err(e)) => {
            eprintln!("gagal: {e}");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("gagal menjalankan pemulihan: {e}");
            std::process::exit(1);
        }
    }
}

/// Dipanggil anak pendamping: tunggu induk selesai, lalu bersihkan kalau induk
/// tidak sempat melakukannya sendiri.
fn cmd_watchdog(pid: u32, start_time: u64) {
    // `wait_for_process` menunggu sampai induk benar-benar pergi. Kalau induk
    // sudah hilang saat dibuka, ia mengembalikan false — tapi pemulihan tetap
    // wajib dijalankan (restore_if_stale aman dan idempoten).
    let _ = win::wait_for_process(pid, start_time);
    // Urutan sama dengan pemulihan manual: rute VPN dulu, baru DNS.
    let _ = vpn::down_if_stale();
    let _ = win::restore_if_stale();
}

fn cmd_doctor() {
    println!("MyDNS doctor\n");

    let rt = runtime();
    let mut problems = 0u32;

    if win::is_elevated() {
        okay("hak administrator");
    } else {
        warn("jalan tanpa hak admin — apply/restore akan meminta UAC");
    }

    let dns = win::summary();
    info(&format!("DNS adapter: {dns}"));

    let port_free = win::port53_free();
    if port_free {
        info("port 53 loopback bebas");
    } else {
        info("port 53 loopback sedang dipakai");
    }
    if win::port53_v6_free() {
        info("port 53 IPv6 loopback bebas");
    } else {
        info("port 53 IPv6 loopback sedang dipakai");
    }

    let proxy_ok = match rt.block_on(server::probe()) {
        Ok(detail) => {
            okay(&format!("proxy lokal menjawab — {detail}"));
            true
        }
        Err(_) => {
            info("proxy lokal tidak berjalan");
            false
        }
    };

    info(&format!("VPN: {}", vpn::status()));

    let points_to_us = dns.contains("127.0.0.1");
    match win::load_state() {
        Some(state) => {
            info(&format!(
                "catatan MyDNS: provider {}, {} adapter",
                provider_label(&state.provider),
                state.ifaces.len()
            ));
            if !proxy_ok {
                fail(
                    "catatan masih ada tetapi tidak ada proxy di port 53 — jalankan `mydns restore`",
                );
                problems += 1;
            } else {
                okay("DNS dialihkan ke proxy lokal yang aktif");
            }
        }
        None => {
            if points_to_us {
                fail(
                    "adapter menunjuk 127.0.0.1 tetapi MyDNS tidak punya catatan — jalankan `mydns restore`",
                );
                problems += 1;
            } else {
                okay("DNS tidak menunjuk MyDNS");
            }
        }
    }

    if win::autostart_enabled() {
        match win::autostart_target_valid() {
            Some(false) => warn(
                "pemulihan saat logon menunjuk exe di lokasi lain — jalankan `mydns autostart on` lagi setelah mydns.exe dipindahkan",
            ),
            _ => okay("pemulihan saat logon aktif"),
        }
    } else {
        warn(
            "pemulihan saat logon belum aktif — jalankan `mydns autostart on` supaya DNS tidak tertinggal rusak setelah reboot",
        );
    }

    let config = read_config();
    if config.errors.is_empty() {
        if config.entries.is_empty() {
            info("resolver kustom: tidak ada");
        } else {
            okay(&format!(
                "resolver kustom: {} entri terbaca",
                config.entries.len()
            ));
        }
    } else {
        fail(&format!(
            "{} baris bermasalah di {}",
            config.errors.len(),
            config_path().display()
        ));
        problems += 1;
        for error in config.errors.iter().take(3) {
            println!("         {error}");
        }
    }

    println!();
    if problems == 0 {
        println!("tidak ada masalah yang menghalangi.");
    } else {
        println!("{problems} masalah ditemukan — lihat baris bertanda [fail].");
        std::process::exit(1);
    }
}

fn cmd_log(count: usize) {
    let count = count.clamp(1, 500);
    println!("Log: {}\n", log::log_path().display());
    match log::tail(count) {
        Ok(lines) if lines.is_empty() => println!("(belum ada catatan)"),
        Ok(lines) => {
            for line in lines {
                println!("{line}");
            }
        }
        Err(e) => {
            eprintln!("belum ada log: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_providers() {
    let list = resolver_list();
    println!("Resolver yang tersedia ({}):\n", list.len());
    for provider in list {
        println!("  {:<12} {}", provider.id, provider.name);
        println!("  {:<12} catatan : {}", "", provider.note);
        if let Some((host, port)) = provider.doq {
            println!("  {:<12} DoQ     {host}:{port}", "");
        }
        if let Some(url) = provider.doh {
            println!("  {:<12} DoH     {url}", "");
        }
        if provider.warp {
            println!("  {:<12} MASQUE  tunnel CONNECT-IP Cloudflare", "");
        }
        if !provider.boot.is_empty() {
            println!("  {:<12} IP      {}", "", provider.boot.join(", "));
        }
        println!();
    }

    let config = read_config();
    println!("Berkas kustom: {}", config_path().display());
    if !config.errors.is_empty() {
        for error in &config.errors {
            println!("  masalah: {error}");
        }
    } else if config.entries.is_empty() {
        println!("  (belum ada resolver kustom)");
    } else {
        println!("  {} entri terbaca", config.entries.len());
    }
}

fn cmd_autostart(args: &[String], mode: &str) {
    // Hanya mode yang menyentuh Task Scheduler yang butuh hak admin.
    if matches!(mode, "on" | "enable" | "off" | "disable") {
        need_admin(args);
    }
    match mode {
        "status" => {
            if win::autostart_enabled() {
                println!("pemulihan saat logon: aktif");
            } else {
                println!(
                    "pemulihan saat logon: tidak aktif\n\nTanpa ini, DNS yang ditinggalkan menunjuk 127.0.0.1 karena crash/reboot\ntidak dipulihkan sampai Anda menjalankan `mydns restore`.\nAktifkan dengan: mydns autostart on"
                );
            }
        }
        "on" | "enable" => match win::autostart_set(true) {
            Ok(message) => println!("{message}"),
            Err(e) => {
                eprintln!("gagal: {e}");
                std::process::exit(1);
            }
        },
        "off" | "disable" => match win::autostart_set(false) {
            Ok(message) => println!("{message}"),
            Err(e) => {
                eprintln!("gagal: {e}");
                std::process::exit(1);
            }
        },
        other => {
            eprintln!("mode tidak dikenal: {other} (pakai on, off, atau status)");
            std::process::exit(2);
        }
    }
}

/// Nama provider untuk ditampilkan; "-" kalau catatan lama tidak menyebutkannya.
fn provider_label(id: &str) -> &str {
    if id.is_empty() { "-" } else { id }
}

fn okay(text: &str) {
    println!("  [ok]   {text}");
}

fn info(text: &str) {
    println!("  [info] {text}");
}

fn warn(text: &str) {
    println!("  [warn] {text}");
}

fn fail(text: &str) {
    println!("  [fail] {text}");
}

fn cmd_test() {
    let rt = runtime();
    rt.block_on(async {
        println!("Menguji setiap protokol per provider (query example.com/A, 3 putaran)\n");
        println!("{:<15} {:<6} {:<8} jawaban", "provider", "proto", "latensi");
        println!("{}", "-".repeat(78));
        for provider in resolver_list() {
            let engine = match engine::Engine::new(provider) {
                Ok(engine) => engine,
                Err(e) => {
                    println!("{:<15} engine gagal: {e}", provider.name);
                    continue;
                }
            };
            let query = engine::build_query("example.com.");
            for proto in provider.protos() {
                match engine.bench(proto, &query, 3).await {
                    Ok((ms, summary)) => println!(
                        "{:<15} {:<6} {:>5} ms  {}",
                        provider.name,
                        proto.label(),
                        ms,
                        summary
                    ),
                    Err(e) => println!("{:<15} {:<6} gagal    {}", provider.name, proto.label(), e),
                }
            }
        }
    });
}

fn cmd_warp(mode: &str) {
    match mode {
        "register" | "daftar" => {
            let rt = runtime();
            println!("Mendaftarkan perangkat WARP baru (mode MASQUE)…\n");
            match rt.block_on(warp::register()) {
                Ok(config) => {
                    println!("WARP siap dipakai.\n");
                    println!("  perangkat : {}", config.device_id);
                    println!("  endpoint  : {}", config.endpoint_v4);
                    println!("  tunnel IP : {}", config.ipv4);
                    println!("  berkas    : {}", warp::config_path().display());
                    println!(
                        "\nPilih \"Cloudflare WARP\" di TUI. Perangkat ini juga dibuat\n\n \
                         otomatis saat WARP pertama kali dipakai."
                    );
                }
                Err(e) => {
                    eprintln!("gagal mendaftar: {e}");
                    std::process::exit(1);
                }
            }
        }
        "status" => match warp::load() {
            Ok(config) => {
                println!("WARP terdaftar:\n");
                println!("  perangkat : {}", config.device_id);
                println!("  endpoint  : {}", config.endpoint_v4);
                if !config.endpoint_v6.is_empty() {
                    println!("  endpoint6 : {}", config.endpoint_v6);
                }
                println!("  tunnel IP : {}", config.ipv4);
                println!("  SNI       : {}", config.sni);
                println!("  berkas    : {}", warp::config_path().display());
            }
            Err(_) => println!(
                "WARP belum terdaftar — perangkat dibuat otomatis saat \"Cloudflare WARP\" dipilih atau `mydns warp test` dijalankan."
            ),
        },
        "test" | "uji" => {
            let rt = runtime();
            let outcome: Result<(), String> = rt.block_on(async {
                if !warp::config_path().exists() {
                    println!("Perangkat WARP belum ada — mendaftar otomatis…");
                }
                let config = warp::ensure().await?;
                let started = Instant::now();
                let tunnel = warp::Tunnel::connect(&config).await?;
                println!(
                    "tunnel    : siap dalam {} ms",
                    started.elapsed().as_millis()
                );

                let query = engine::build_query("example.com.");
                let started = Instant::now();
                let answer = tunnel.resolve(&query).await?;
                println!(
                    "example.com/A : {} ms — {}",
                    started.elapsed().as_millis(),
                    engine::describe(&answer)
                );
                Ok(())
            });
            if let Err(e) = outcome {
                eprintln!("gagal: {e}");
                std::process::exit(1);
            }
        }
        other => {
            eprintln!("mode tidak dikenal: {other} (pakai register, status, atau test)");
            std::process::exit(2);
        }
    }
}

fn cmd_serve(provider_id: &str) {
    let Some(provider) = providers::find(provider_id) else {
        eprintln!(
            "provider tidak dikenal: {provider_id} (pilihan: {})",
            resolver_list()
                .iter()
                .map(|p| p.id)
                .collect::<Vec<_>>()
                .join(", ")
        );
        std::process::exit(2);
    };

    let rt = runtime();
    let outcome: Result<(), String> = rt.block_on(async {
        let log = Arc::new(Log::new());
        let engine = engine::Engine::new(provider)?;
        let bound = server::bind(engine, log).await?;
        let proxy = bound.proxy.clone();
        println!(
            "Proxy {} ({}) siap di {} dan {}",
            provider.name,
            provider.badges(),
            server::ADDR_V4,
            server::ADDR_V6
        );
        println!("Tekan Ctrl+C untuk berhenti.\n");

        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let proxy_task = tokio::spawn(async move { bound.serve(stop_rx).await });
        tokio::spawn(async move {
            match proxy_task.await {
                Ok(()) => crate::log::event("serve: proxy listener berhenti"),
                Err(e) => crate::log::event(&format!("serve: proxy task panic: {e}")),
            }
        });
        // Sender harus tetap hidup selama proxy berjalan: kalau ia di-drop,
        // `changed()` mengembalikan error dan semua loop listener berhenti.
        let _keepalive = stop_tx;

        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            println!(
                "cache: {} hit / {} miss · {} query diteruskan",
                proxy.hits(),
                proxy.misses(),
                proxy.forwards()
            );
        }
    });

    if let Err(e) = outcome {
        eprintln!("gagal: {e}");
        std::process::exit(1);
    }
}

fn cmd_daemon(provider_id: &str) {
    if let Err(e) = daemon::run(provider_id) {
        eprintln!("gagal: {e}");
        std::process::exit(1);
    }
}

fn cmd_control(command: &str) {
    match daemon::control(command) {
        Ok(reply) => println!("{reply}"),
        Err(e) => {
            eprintln!("gagal: {e}");
            std::process::exit(1);
        }
    }
}

/// `mydns vpn on` berjalan di depan sampai Ctrl+C: tunnel hanya hidup selama
/// proses ini hidup, dan rutenya dicabut saat keluar.
fn cmd_vpn(args: &[String], mode: &str, dns_provider: Option<&str>) {
    match mode {
        "status" => {
            println!("VPN: {}", vpn::status());
            // Lokasi egress hanya bisa dibaca lewat jaringan, jadi hanya
            // ditanyakan kalau tunnel memang tercatat aktif.
            if win::vpn_saved().is_some() {
                let rt = runtime();
                match rt.block_on(vpn::exit_info()) {
                    Ok(info) => println!("IP keluar: {}", info.label()),
                    Err(e) => println!("IP keluar: tidak terbaca ({e})"),
                }
            }
        }
        "off" | "matikan" => {
            need_admin(args);
            let rt = runtime();
            match rt.block_on(tokio::task::spawn_blocking(vpn::down_persisted)) {
                Ok(Ok(message)) => println!("{message}"),
                Ok(Err(e)) => {
                    eprintln!("gagal: {e}");
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("gagal menjalankan pembersihan: {e}");
                    std::process::exit(1);
                }
            }
        }
        "on" | "nyalakan" => {
            need_admin(args);
            win::install_exit_guard();
            win::spawn_watchdog();
            let rt = runtime();
            let outcome: Result<(), String> = rt.block_on(async {
                let before = vpn::exit_info().await.ok();
                let tunnel = vpn::Vpn::up().await?;
                let families = if tunnel.routes().ipv6.is_empty() {
                    "IPv4"
                } else {
                    "IPv4 + IPv6"
                };
                println!(
                    "VPN aktif — seluruh trafik {families} lewat WARP (MTU {}, {} rute)",
                    tunnel.mtu,
                    tunnel.routes().routes.len()
                );
                let before = before.map(|info| info.label()).unwrap_or_default();
                let before = if before.is_empty() {
                    "-"
                } else {
                    before.as_str()
                };
                match vpn::exit_info().await {
                    Ok(after) => println!("IP keluar: {before} → {}", after.label()),
                    Err(e) => println!("IP keluar: {before} → tidak terbaca ({e})"),
                }
                println!("Tekan Ctrl+C untuk mematikan.\n");
                loop {
                    tokio::select! {
                        _ = tokio::signal::ctrl_c() => break,
                        _ = tokio::time::sleep(Duration::from_secs(10)) => {
                            let (up, down) = tunnel.counters();
                            println!("{up} paket keluar · {down} paket masuk");
                        }
                    }
                }
                println!("{}", tunnel.down().await?);
                Ok(())
            });
            if let Err(e) = outcome {
                // Rute yang mungkin sudah terpasang tetap dicabut.
                let _ = rt.block_on(tokio::task::spawn_blocking(vpn::down_persisted));
                eprintln!("gagal: {e}");
                std::process::exit(1);
            }
        }
        "test" | "uji" => {
            need_admin(args);
            let rt = runtime();
            let outcome: Result<(), String> = rt.block_on(async {
                let started = Instant::now();
                let before = vpn::exit_info().await.ok();
                let tunnel = vpn::Vpn::up().await?;
                println!(
                    "tunnel siap dan trafik terverifikasi dalam {} ms (MTU {})",
                    started.elapsed().as_millis(),
                    tunnel.mtu
                );
                let before_ip = before.as_ref().map(|info| info.ip.clone());
                let before = before.map(|info| info.label()).unwrap_or_default();
                let before = if before.is_empty() {
                    "-"
                } else {
                    before.as_str()
                };
                match vpn::exit_info().await {
                    Ok(after) if Some(&after.ip) == before_ip.as_ref() => println!(
                        "IP keluar: {before} → {} (TIDAK berubah — tunnel belum dipakai)",
                        after.label()
                    ),
                    Ok(after) => println!("IP keluar: {before} → {}", after.label()),
                    Err(e) => println!("IP keluar: {before} → tidak terbaca ({e})"),
                }
                // Bukti tambahan: resolver pilihan pengguna tetap dipakai walau
                // seluruh trafik lewat tunnel — Quad9 + VPN, bukan salah satu.
                if let Some(id) = dns_provider {
                    match providers::find(id) {
                        Some(provider) => {
                            let engine = engine::Engine::new(provider)?;
                            let query = engine::build_query("example.com.");
                            let started = Instant::now();
                            match engine.resolve(&query).await {
                                Ok((answer, proto)) => println!(
                                    "DNS {} lewat {} di dalam tunnel: {} ms — {}",
                                    provider.name,
                                    proto.label(),
                                    started.elapsed().as_millis(),
                                    engine::describe(&answer)
                                ),
                                Err(e) => println!("DNS {} gagal lewat tunnel: {e}", provider.name),
                            }
                        }
                        None => println!("provider tidak dikenal: {id}"),
                    }
                }
                println!("{}", tunnel.down().await?);
                Ok(())
            });
            if let Err(e) = outcome {
                // Sama seperti cabang `on`: rute yang sudah terpasang tetap
                // dicabut walau kegagalan terjadi setelah Vpn::up().
                let _ = rt.block_on(tokio::task::spawn_blocking(vpn::down_persisted));
                eprintln!("gagal: {e}");
                std::process::exit(1);
            }
        }
        other => {
            eprintln!("mode tidak dikenal: {other} (pakai on, off, status, atau test)");
            std::process::exit(2);
        }
    }
}

fn help() {
    println!(
        "MyDNS — DNS over QUIC / HTTP-3 untuk Windows 11

PEMAKAIAN
  mydns                 buka TUI pemilih resolver
  mydns status          tampilkan DNS adapter yang aktif sekarang
  mydns restore         kembalikan DNS ke setelan asli (DHCP / statis)
  mydns doctor          periksa kesehatan pengalihan DNS (tanpa mengubah apa pun)
  mydns log [n]         tampilkan n baris terakhir log peristiwa
  mydns autostart on    pulihkan DNS otomatis setiap logon (disarankan)
  mydns autostart off   lepaskan pemulihan otomatis itu
  mydns providers       daftar resolver aktif + berkas kustom yang dibaca
  mydns test            uji DoQ, DoH3, DoH2 ke semua provider + latensi
  mydns serve <id>      jalankan proxy saja tanpa TUI (untuk debug)
  mydns daemon [id]     proxy tanpa TUI + kontrol lewat named pipe
  mydns control <cmd>   status / restore / stop untuk daemon yang berjalan
  mydns vpn on          nyalakan VPN penuh (seluruh trafik lewat WARP)
  mydns vpn off         matikan VPN dan cabut rutenya
  mydns vpn status      keadaan tunnel VPN yang tercatat
  mydns vpn test        buka tunnel, buktikan trafik lewat, lalu tutup
  mydns warp register   buat ulang perangkat WARP (normalnya otomatis)
  mydns warp status     tampilkan data perangkat WARP yang tersimpan
  mydns warp test       buka tunnel WARP dan uji satu query DNS
  mydns help            pesan ini

PROVIDER
  cloudflare, quad9, adguard, controld (Hagezi Ultimate)

CATATAN
  • DNS Windows hanya mendukung DoH/HTTP-2, jadi QUIC dipakai lewat proxy
    lokal di 127.0.0.1:53; adapter diarahkan ke alamat itu.
  • Saat TUI ditutup, DNS otomatis dipulihkan agar internet tidak terputus.
  • Kalau prosesnya dibunuh atau mesin mati mendadak, pendamping kecil yang
    dijalankan TUI akan memulihkan DNS; `mydns autostart on` menutup kasus
    reboot dengan menjalankan pemulihan saat logon.
  • Perubahan adapter butuh hak administrator (prompt UAC). Daemon tetap
    bisa melayani proxy tanpa admin; DNS-nya saja yang tidak diubah.
  • Kalau port 53 sudah dipakai proses lain (Docker, AdGuard Home, VPN),
    aplikasi menolak mengubah DNS dan menampilkan error.
  • DNS baru dianggap berhasil setelah resolver sistem benar-benar menjawab;
    kalau tidak, DNS dikembalikan otomatis.
  • Resolver tambahan (mis. profil Control D pribadi) atau IP bootstrap baru
    bisa ditulis di %APPDATA%\\MyDns\\resolvers.txt — lihat `mydns providers`.
  • Saat jaringan berganti, adapter yang DNS-nya ditimpa DHCP dikembalikan
    otomatis selama sesi berjalan."
    );
}
