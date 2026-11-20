# Desain: installer sekali klik, versi, dan pembaruan MyDNS

## Intent

Pengguna Windows harus bisa memasang MyDNS dengan satu perintah PowerShell seperti
`irm https://raw.githubusercontent.com/EmhaHasyim/mydns/master/install.ps1 | iex`,
memakai `mydns -v`, lalu memperbaruinya dengan `mydns update` / `mydns upgrade`.
Pengguna juga diberi tahu kalau ada versi baru tanpa harus membuka GitHub setiap hari.

## Goals

- Satu perintah PowerShell di branch `master` memasang `mydns.exe` dan `wintun.dll` ke `%LOCALAPPDATA%\MyDns\bin`, lalu menambahkan folder itu ke PATH user.
- `mydns -v` dan `mydns --version` ditangani sebelum dispatch perintah apa pun dan sebelum `need_admin()`, lalu mencetak versi biner tanpa meminta UAC.
- `mydns update` dan `mydns upgrade`: cek rilis GitHub terbaru, unduh ZIP rilis, verifikasi SHA-256, ganti `mydns.exe` dan `wintun.dll`, laporkan hasilnya. Installer dipanggil lewat `system32_exe(r"WindowsPowerShell\v1.0\powershell.exe")` dengan argumen vektor, `-NoProfile -NonInteractive -ExecutionPolicy Bypass`, dan `CREATE_NO_WINDOW` — bukan `Command::new("powershell")`.
- Pengingat versi muncul di satu baris khusus di TUI (zona tersendiri supaya tidak menimpa teks DNS pada terminal 60×16) dan di `mydns status` / `mydns doctor` bila rilis baru sudah keluar.

## Non-goals / anti-goals

- Tidak membuat domain/bun.sh sendiri; URL resmi memakai `raw.githubusercontent.com`.
- Tidak ada dependency Rust atau installer framework baru; semua memakai PowerShell + `std`/`tokio` yang sudah ada.
- Tidak auto-update diam-diam, tidak mengganti biner saat sesi DNS/VPN masih aktif.
- Tidak membuat uninstaller; penghapusan manual cukup untuk sekarang.
- Tidak memaksa migrasi instalasi repo (`dns.cmd`) ke folder `%LOCALAPPDATA%\MyDns\bin`; keduanya hidup berdampingan. Autostart lama tidak diubah.

## Status keputusan owner (2026-11-20)

- Sumber bootstrap: branch `master`.
- Rilis pertama: tag `v0.1.0` mengikuti `Cargo.toml` versi `0.1.0`; tag dibuat owner setelah alur rilis terbukti.
- Target: x86-64 Windows saja; ARM tidak masuk rilis pertama.
- Alur repo tanpa install (`dns.cmd`) tetap dipertahankan.

## Constraints

- Windows 10/11 x86-64, PowerShell 5.1 ke atas, akun user tanpa admin boleh install (folder user + PATH user).
- Mode VPN tetap butuh `wintun.dll` di folder yang sama dengan `mydns.exe`.
- Rilis GitHub satu per tag `v<semver>`; aset: `mydns-x86_64-pc-windows-msvc.zip`, `SHA256SUMS`, `install.ps1`. `install.ps1` juga masuk branch `master` sebelum rilis pertama.
- Versi biner berasal dari `env!("CARGO_PKG_VERSION")` (saat ini `0.1.0`).
- Aturan repo: tidak ada dependency baru, root-cause, diff terkecil, satu check untuk logika non-trivial.

## Implementation approaches yang dipertimbangkan

1. **Installer + self-update dari GitHub Release (dipilih).** Release membawa ZIP + checksum; installer dipakai ulang oleh `mydns update`. Cocok untuk pengguna umum; biayanya CI perlu izin `contents: write`.
2. **Artifact CI sebagai sumber update.** Tanpa tag, tapi artefak butuh login GitHub dan terhapus otomatis; ditolak karena pengguna umum tidak punya akses.
3. **Hanya pengingat, update manual.** Paling kecil, tapi tidak memenuhi permintaan "tinggal update".

Keputusan: **pendekatan 1**.

## Desain

### Instalasi

`install.ps1` di root repo:

- Param `-Version` opsional; default tag rilis terbaru dari GitHub API.
- Paksa TLS 1.2, tangani rate limit/offline dengan pesan berbeda dari "sudah versi terbaru".
- Unduh ZIP dan `SHA256SUMS` dari rilis itu ke temp, verifikasi hash dengan `Get-FileHash`, gagal keras bila beda.
- Ekstrak ke `%LOCALAPPDATA%\MyDns\bin`; tambahkan folder itu ke PATH tingkat user bila belum ada, tanpa menyentuh PATH sistem.
- Kalau sudah terpasang, mode repair/update mengganti `mydns.exe` dan `wintun.dll` setelah mengecek tidak ada sesi aktif.
- Mode `-Update` dipakai `mydns update`; pesan dan exit code disesuaikan untuk CLI.

### Update dari dalam aplikasi

Modul baru `src/updater.rs`:

- `pub fn current() -> &'static str` = `env!("CARGO_PKG_VERSION")`.
- `pub fn latest_cached() -> Option<String>` membaca `%LOCALAPPDATA%\MyDns\update-check.json` (isi: `checked_at`, `latest`); basi setelah 24 jam.
- `pub fn check_now() -> Result<String, String>` memanggil GitHub API lewat `system32_exe(r"WindowsPowerShell\v1.0\powershell.exe")`, `-NoProfile -NonInteractive`, `CREATE_NO_WINDOW`, paksa TLS 1.2, menyimpan hasil ke cache, mengembalikan tag yang cocok `^v\d+\.\d+\.\d+$`.
- `pub fn is_newer(latest: &str, current: &str) -> bool` membandingkan angka versi `v1.2.3`; prerelease diabaikan. Diuji dengan unit test.
- `notify()` dipakai TUI lewat `spawn_blocking` saat startup; update check tidak memblokir render.
- `mydns status` dan `mydns doctor` mencetak baris pengingat yang sama dari cache.
- `mydns update` / `mydns upgrade`: cek versi; bila terbaru, cetak dan selesai; bila ada yang lebih baru, validasi tag, lalu panggil PowerShell System32 lewat vektor argumen (tanpa `cmd.exe`/interpolasi) dengan `-File <install.ps1> -Update -Version <tag>` dan `CREATE_NO_WINDOW`.
- Guard: tolak bila sesi MyDNS benar-benar aktif (TUI/daemon berjalan atau port `127.0.0.1:53` dipegang proses MyDNS yang dikenal), bukan sekadar file state yang dipertahankan untuk autostart/watchdog. Pesan: "tutup MyDNS / jalankan `mydns restore` dulu".
- `update-check.json` sengaja di `%LOCALAPPDATA%\MyDns` mengikuti log (`src/log.rs:50-57`); resolvers/WARP tetap di `%APPDATA%\MyDns`. README menyebut keduanya.

### CI / rilis

- `ci.yml` tetap menjalankan fmt/clippy/test/build pada push biasa dan mengunggah artefak Windows.
- Pekerjaan release punya `if: startsWith(github.ref, 'refs/tags/v')` eksplisit, bergantung pada build Windows, dengan `permissions: contents: write` hanya di pekerjaan itu.
- Release membuat ZIP berisi `mydns.exe` + `wintun.dll` dari hasil build yang sama, menghitung `SHA256SUMS`, mengunggah `install.ps1` dari checkout tag, lalu `gh release create`. Jika `assets/wintun.dll` tidak ada di checkout bersih, rilis gagal jelas — tanpa path diam-diam ke DLL lokal.

## File yang akan disentuh

- `install.ps1` (baru) — instalasi/update + verifikasi checksum + PATH user.
- `src/updater.rs` (baru) — versi, cache, cek rilis, pembanding versi.
- `src/main.rs` — flag `-v`/`--version`, `update`/`upgrade`, pengingat di `status`/`doctor`.
- `src/ui.rs` — satu baris pengingat versi di zona tersendiri.
- `.github/workflows/ci.yml` — pekerjaan rilis + izin + aset.
- `README.md` — cara install, update, versi, lokasi file, dan hubungan dengan `dns.cmd`.

## Rencana verifikasi

- `cargo test`: unit test `is_newer`, validasi tag, pembacaan cache.
- `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, `cargo build --release`, `git diff --check`.
- Uji manual Windows oleh owner: `irm|iex`, PowerShell baru, `mydns -v`, `mydns status`, `mydns update` saat terbaru dan saat ada rilis baru.
- Tidak bisa diuji agent: GitHub Release sungguhan, PATH/UAC mesin target, dan DLL Wintun di runner CI.

## Risk

- `irm … | iex` menjalankan skrip dari GitHub; HTTPS + SHA-256 menjamin integritas unduhan, bukan keaslian penerbit. Akar kepercayaan adalah repo GitHub + TLS; untuk menghapus risiko ini perlu domain sendiri + code signing.
- Update menolak saat sesi aktif; pengguna menutup MyDNS dulu agar DNS tidak tertinggal mengarah ke biner lama.
- Rilis pertama tidak bisa diuji end-to-end sebelum tag `v0.1.0` dibuat; sampai saat itu `mydns update` hanya kembali "sudah versi terbaru" atau error rilis belum ada.
