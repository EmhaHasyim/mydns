//! MyDNS — pengalih DNS Windows 11 ke DoQ / DoH3 (QUIC) lewat proxy loopback.

mod daemon;
mod engine;
mod log;
mod providers;
mod server;
mod ui;
mod warp;
mod win;

use crate::log::Log;
use crate::providers::{config_path, providers as resolver_list, read_config};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // Pendamping pemulihan (lihat win::spawn_watchdog). Tidak pernah
    // mengubah apa pun selama induknya masih hidup.
    if let Some(pos) = args.iter().position(|a| a == "--watchdog")
        && let Some(pid) = args.get(pos + 1).and_then(|p| p.parse::<u32>().ok())
    {
        cmd_watchdog(pid);
        return;
    }

    if args
        .iter()
        .any(|a| a == "-h" || a == "--help" || a == "help")
    {
        help();
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
    let result = rt.block_on(async {
        if stale_only {
            tokio::task::spawn_blocking(win::restore_if_stale).await
        } else {
            tokio::task::spawn_blocking(win::restore)
                .await
                .map(|r| r.map(Some))
        }
    });
    match result {
        Ok(Ok(Some(message))) => println!("{message}"),
        Ok(Ok(None)) => println!("tidak ada yang perlu dipulihkan"),
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
fn cmd_watchdog(pid: u32) {
    if !win::wait_for_process(pid) {
        return;
    }
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

    match rt.block_on(server::probe()) {
        Ok(detail) => okay(&format!("proxy lokal menjawab — {detail}")),
        Err(_) => info("proxy lokal tidak berjalan"),
    }

    let points_to_us = dns.contains("127.0.0.1");
    match win::load_state() {
        Some(state) => {
            info(&format!(
                "catatan MyDNS: provider {}, {} adapter",
                provider_label(&state.provider),
                state.ifaces.len()
            ));
            if port_free {
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
                        "\nPilih \"Cloudflare WARP\" di TUI, atau cek dulu dengan `mydns warp test`."
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
            Err(e) => println!("WARP belum siap: {e}"),
        },
        "test" | "uji" => {
            let rt = runtime();
            let outcome: Result<(), String> = rt.block_on(async {
                let config = warp::load()?;
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
        tokio::spawn(async move { bound.serve(stop_rx).await });
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
  mydns warp register   daftarkan perangkat Cloudflare WARP (mode MASQUE)
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
