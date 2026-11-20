# Rencana Implementasi Installer, Versi, dan Pembaruan MyDNS

> **Untuk agen pelaksana:** sub-skill wajib: gunakan `subagent-driven-development` (disarankan) atau `executing-plans` untuk mengerjakan rencana ini per task. Centang tiap langkah dengan `- [x]`.

**Tujuan:** satu perintah PowerShell memasang MyDNS (exe + Wintun DLL + PATH user), `mydns -v` menunjukkan versi, dan `mydns update` / `upgrade` serta TUI/status/doctor mengingatkan dan mengunduh rilis GitHub terbaru.

**Arsitektur:** `install.ps1` di root repo menangani bootstrap dan pembaruan dengan verifikasi checksum ZIP. Modul Rust `src/updater.rs` hanya membaca versi, membandingkan tag, cache, dan memanggil PowerShell System32 dengan argumen vektor. `main.rs` menambahkan flag/perintah sebelum dispatch; `ui.rs` menerima satu `Msg::UpdateNotice` untuk baris pengingat. CI menambahkan job rilis bertag dengan aset ZIP + SHA256SUMS + install.ps1.

**Stack:** Rust 2024/tokio/serde_json yang sudah ada, PowerShell 5.1, GitHub Actions + GitHub Release, tanpa dependency baru.

**Spesifikasi:** `docs/superpowers/specs/2026-11-20-install-update-design.md` (baca bersama rencana ini).

## Global constraints

- Branch `master`; bootstrap URL `https://raw.githubusercontent.com/EmhaHasyim/mydns/master/install.ps1`.
- Rilis pertama tag `v0.1.0` sesuai `Cargo.toml` versi `0.1.0`; tag dibuat owner setelah alur rilis terverifikasi.
- Windows 10/11 x86-64; PowerShell 5.1+; user tanpa admin boleh install ke `%LOCALAPPDATA%\MyDns\bin`.
- Tanpa dependency Rust baru; `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, `cargo build --release`, `git diff --check` harus lulus.
- Jalankan PowerShell hanya lewat `win::system32_exe(r"WindowsPowerShell\v1.0\powershell.exe")`, `-NoProfile -NonInteractive`, `CREATE_NO_WINDOW`; jangan `Command::new("powershell")`.
- Validasi tag rilis dengan `^v\d+\.\d+\.\d+$` sebelum dipakai sebagai argumen.
- Template file rencana memakai `docs/superpowers/plans/YYYY-MM-DD-<fitur>.md` dan tiap task diakhiri commit.
- Alur `dns.cmd` tanpa install tetap didukung; installer tidak menghapus/mengubahnya.
- Perubahan yang menyentuh output/CLI/TUI disertai satu tes kecil; verifikasi build adalah check untuk kode yang hanya menjalankan PowerShell.

## Review focus

1. Tag rilis jahat seperti `v1.2.3; calc` — harus ditolak sebelum dipanggil PowerShell; diuji di Task 2.
2. `mydns -v` saat TUI biasa meminta UAC — harus keluar dengan kode 0 tanpa `need_admin()`; diuji dengan struktur dispatch di Task 3 dan verifikasi manual.
3. Update saat sesi TUI/daemon masih aktif — harus menolak, bukan menimpa exe yang dipakai; tes guard di Task 5.
4. Hash ZIP berbeda — installer harus membatalkan dan tidak menimpa file; diuji manual dengan checksum palsu di Task 6.
5. TUI 60×16 — baris pengingat tidak boleh menimpa/status bertabrakan; tes render di Task 4.

---

### Task 1: Modul `updater.rs` — versi, tag, dan cache

**File:**
- Buat: `src/updater.rs`
- Modul didaftarkan di `src/main.rs:7` (`mod updater;`).

- [ ] **Step 1: Tulis tes gagal untuk pembanding versi dan validasi tag**

Di `src/updater.rs` bagian `#[cfg(test)]`, buat tes:

```rust
#[test]
fn membandingkan_versi_dan_tag() {
    assert!(is_newer("v0.2.0", "0.1.0"));
    assert!(!is_newer("v0.1.0", "0.1.0"));
    assert!(!is_newer("v0.0.9", "0.1.0"));
    assert!(valid_tag("v1.2.3"));
    assert!(!valid_tag("v1.2.3; calc"));
    assert!(cache_path().ends_with("MyDns/update-check.json"));
}
```

- [ ] **Step 2: Jalankan dan pastikan gagal**

Run: `cargo test --quiet membandingkan_versi_dan_tag`
Expected: gagal karena `is_newer` / `valid_tag` / `cache_path` belum ada.

- [ ] **Step 3: Implementasi minimum**

Di `src/updater.rs`, tentukan API persis:

```rust
pub fn current() -> &'static str;                  // env!("CARGO_PKG_VERSION")
pub fn valid_tag(tag: &str) -> bool;               // ^v\d+\.\d+\.\d+$
pub fn is_newer(tag: &str, current: &str) -> bool; // bandingkan tiga angka; tag diawali 'v'
pub fn cache_path() -> std::path::PathBuf;         // LOCALAPPDATA/APPDATA/ProgramData + MyDns/update-check.json
pub fn latest_cached(now: std::time::SystemTime) -> Option<String>; // basi setelah 24 jam
pub fn save_cached(tag: &str, now: std::time::SystemTime) -> Result<(), String>;
```

Tidak ada dependency regex; validasi dan parsing cukup dengan `split`, `chars`, dan `parse::<u64>()`. `latest_cached()` mengabaikan file korup/basi tanpa error. `save_cached()` menulis JSON `{"checked_at": <unix detik>, "latest": "<tag>"}` ke folder yang dibuat dengan `create_dir_all`. Uji cache memakai variabel lingkungan path sementara atau helper path yang bisa diuji tanpa menimpa file user; jangan mengubah path produksi.

- [ ] **Step 4: Jalankan tes sampai lulus**

Run: `cargo test --quiet membandingkan_versi_dan_tag`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/main.rs src/updater.rs
git commit -m "feat: tambah pembanding versi dan cache update MyDNS"
```

### Task 2: Pengecekan rilis GitHub tanpa dependency baru

**File:**
- Modifikasi: `src/updater.rs`

- [ ] **Step 1: Tulis tes gagal untuk parsing respons API**

Tambahkan:

```rust
#[test]
fn tag_terbaru_diambil_dari_json() {
    assert_eq!(latest_from_json(r#"[{"tag_name":"v0.2.0"},{"tag_name":"v0.1.0"}]"#).as_deref(), Some("v0.2.0"));
    assert_eq!(latest_from_json(r#"{"message":"API rate limit exceeded"}"#).as_deref(), None);
}
```

- [ ] **Step 2: Jalankan dan pastikan gagal**

Run: `cargo test --quiet tag_terbaru_diambil_dari_json`
Expected: gagal karena `latest_from_json` belum ada.

- [ ] **Step 3: Implementasi `latest_from_json` dan `check_now`**

Tentukan API persis:

```rust
fn latest_from_json(body: &str) -> Option<String>; // serde_json::Value array, first valid tag
pub fn check_now() -> Result<String, String>;
```

`check_now()`:
- Bangun script PowerShell: `[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; (Invoke-RestMethod -Uri 'https://api.github.com/repos/EmhaHasyim/mydns/releases/latest' -Headers @{'User-Agent'='mydns-update'}).tag_name`.
- Jalankan lewat `crate::win::system32_exe(r"WindowsPowerShell\v1.0\powershell.exe")`, argumen `["-NoProfile","-NonInteractive","-Command", &script]`, `.creation_flags(CREATE_NO_WINDOW)`.
- Bedakan error: `rate limit` / gagal jaringan → `Err("tidak bisa mengecek rilis GitHub: ...")`; respons bukan tag valid → `Err("rilis GitHub belum tersedia")`.
- Simpan tag valid via `save_cached(tag, SystemTime::now())`; kembalikan tag.

- [ ] **Step 4: Jalankan tes sampai lulus**

Run: `cargo test --quiet tag_terbaru_diambil_dari_json`

- [ ] **Step 5: Commit**

```bash
git add src/updater.rs
git commit -m "feat: cek rilis GitHub terbaru dari MyDNS"
```

### Task 3: Flag `-v` dan perintah `update`/`upgrade`

**File:**
- Modifikasi: `src/main.rs:14-68` (dispatch), `src/main.rs:775-800` (`help`).

- [ ] **Step 1: Tulis tes gagal untuk urutan dispatch versi**

Tambahkan di `src/main.rs` test module (atau buat jika belum ada):

```rust
#[test]
fn opsi_versi_dikenali_sebelum_perintah() {
    assert!(is_version_flag("--version"));
    assert!(is_version_flag("-v"));
    assert!(!is_version_flag("status"));
}
```

- [ ] **Step 2: Jalankan dan pastikan gagal**

Run: `cargo test --quiet opsi_versi_dikenali_sebelum_perintah`

- [ ] **Step 3: Implementasi dispatch**

Tentukan API: `fn is_version_flag(arg: &str) -> bool` (benar hanya untuk `-v` / `--version`).

Di `main()`, tepat setelah blok `--help`, sebelum watchdog dan sebelum `command`/`need_admin()`:

```rust
if args.iter().any(|a| is_version_flag(a)) {
    println!("mydns {}", updater::current());
    return;
}
```

Agar `-v` tidak tertangkap sebagai nama perintah, `find` untuk `command` juga harus mengabaikan argumen yang memanggil `is_version_flag`.

Tambahkan `mod updater;` di dekat deklarasi mod lain dan cabang `"update" | "upgrade" => cmd_update(),` di `match command`. `cmd_update()` memanggil `updater::check_now()`; bila `is_newer(tag, current())`, panggil `cmd_install_update(tag)` dari Task 5; jika tidak, cetak "sudah versi terbaru". Update help untuk mencantumkan `-v`, `--version`, `update`, `upgrade`.

- [ ] **Step 4: Jalankan tes sampai lulus**

Run: `cargo test --quiet opsi_versi_dikenali_sebelum_perintah`

- [ ] **Step 5: Commit**

```bash
git add src/main.rs
git commit -m "feat: flag versi dan perintah update MyDNS"
```

### Task 4: Pengingat versi di TUI

**File:**
- Modifikasi: `src/ui.rs` (enum `Msg`, `App`, `on_msg`, `draw_header`/`draw_status`, `run()`).

- [ ] **Step 1: Tulis tes render yang gagal**

Tambahkan tes di modul test `src/ui.rs`:

```rust
#[test]
fn pengingat_update_muat_di_terminal_kecil() {
    let mut app = app();
    app.on_msg(Msg::UpdateNotice("v0.2.0 tersedia — jalankan mydns update".into()));
    let screen = screen(&app, 60, 16).join("\n");
    assert!(screen.contains("update"), "layar: {screen}");
}
```

- [ ] **Step 2: Jalankan dan pastikan gagal**

Run: `cargo test --quiet pengingat_update_muat_di_terminal_kecil`

- [ ] **Step 3: Implementasi**

Tambah `Msg::UpdateNotice(String)` dan field `update_notice: Option<String>` di `App` (including dua initializer di `run()` dan `app()`). `on_msg` menyimpan nilai. Tampilkan di baris status dua baris yang sudah ada (`src/ui.rs:803`): bila `update_notice` ada dan `status` bukan error, pakai baris pertama untuk notifikasi dan baris kedua untuk status biasa; kalau terlalu panjang, potong dengan elipsis. Di `run()`, setelah blok pembacaan DNS latar belakang, spawn satu `spawn_blocking` yang memanggil `updater::latest_cached(SystemTime::now())`, bandingkan dengan `updater::current()`, lalu kirim `Msg::UpdateNotice(format!("update tersedia: {tag} — jalankan mydns update"))` bila lebih baru — jangan panggil `check_now()` di TUI (jangan memblokir render dengan jaringan). Baris ini tidak mengubah tinggi layout tetap 2 baris.

- [ ] **Step 4: Jalankan tes sampai lulus**

Run: `cargo test --quiet pengingat_update_muat_di_terminal_kecil`

- [ ] **Step 5: Commit**

```bash
git add src/ui.rs
git commit -m "feat: tampilkan pengingat update di TUI"
```

### Task 5: Eksekusi update dengan guard sesi aktif

**File:**
- Modifikasi: `src/main.rs` (fungsi `cmd_update` / `cmd_install_update`).

- [ ] **Step 1: Tulis tes gagal untuk keputusan guard**

Tambahkan di test module `src/main.rs`:

```rust
#[test]
fn update_ditolak_saat_sesi_aktif() {
    assert!(!boleh_update(true, false));
    assert!(!boleh_update(false, true));
    assert!(boleh_update(false, false));
}
```

- [ ] **Step 2: Jalankan dan pastikan gagal**

Run: `cargo test --quiet update_ditolak_saat_sesi_aktif`

- [ ] **Step 3: Implementasi**

Tentukan API: `fn boleh_update(session_aktif: bool, port_dipakai_mydns: bool) -> bool` = `!session_aktif && !port_dipakai_mydns`.

`session_aktif`: jalankan `daemon::control("status")` lewat `std::thread::spawn` (karena `control()` membuat runtime sendiri) dengan batas 5 detik; balasan sukses berarti daemon aktif. TUI aktif juga terdeteksi bila `server::probe()` berhasil — jadi satu `rt.block_on(server::probe())` di `cmd_update` cukup untuk menandai `port_dipakai_mydns = true` dan sekaligus menolak saat TUI/daemon menyala. Jangan hanya melihat `win::load_state()`, karena state sengaja dipertahankan untuk autostart; jangan pula menolak hanya karena port 53 dipakai resolver lain — `probe()` harus menjawab dengan format MyDNS.

`cmd_install_update(tag: &str)`:
- Tolak bila `!updater::valid_tag(tag)`.
- Tolak bila `!boleh_update(...)` dengan pesan "tutup MyDNS / jalankan `mydns restore` dulu".
- Cari `install.ps1`: `std::env::current_exe()?.parent()?.join("install.ps1")`; bila tidak ada, cetak petunjuk menjalankan installer dari repo.
- Jalankan `win::system32_exe(r"WindowsPowerShell\v1.0\powershell.exe")` dengan `.args(["-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-File", script, "-Update","-Version", tag])`, `.creation_flags(CREATE_NO_WINDOW)`, status harus sukses; laporkan stdout/stderr.
- `mydns status` dan `mydns doctor` memanggil `updater::latest_cached()` dan mencetak `[warn] update tersedia: <tag> — jalankan mydns update` bila lebih baru. `cmd_update` juga memanggil `check_now()` sebelum memutuskan.

- [ ] **Step 4: Jalankan tes sampai lulus**

Run: `cargo test --quiet update_ditolak_saat_sesi_aktif`

- [ ] **Step 5: Commit**

```bash
git add src/main.rs
git commit -m "feat: jalankan installer update dengan guard sesi aktif"
```

### Task 6: `install.ps1`

**File:**
- Buat: `install.ps1` di root repo.

- [ ] **Step 1: Tulis skrip**

`install.ps1` menerima `-Version` opsional dan `-Update` switch. Tetapkan `ErrorActionPreference='Stop'`, paksa TLS 1.2. Tanpa `-Version`, ambil tag terbaru via GitHub API; validasi `^v\d+\.\d+\.\d+$`. Unduh ke temp:
- `https://github.com/EmhaHasyim/mydns/releases/download/<tag>/mydns-x86_64-pc-windows-msvc.zip`
- `.../SHA256SUMS`

Verifikasi `Get-FileHash -Algorithm SHA256` ZIP terhadap baris SHA256SUMS untuk nama ZIP tersebut; gagal keras bila beda. Cetak pesan berbeda untuk error `rate limit` / jaringan versus "rilis GitHub belum tersedia" sesuai kontrak `updater::check_now()`. Ekstrak ke temp, salin `mydns.exe` dan `wintun.dll` ke `%LOCALAPPDATA%\MyDns\bin` (buat folder); jangan menimpa biner yang sedang dipakai bila guard Rust sudah meloloskan update — bila `Move-Item` gagal karena file terkunci, beri pesan "tutup MyDNS dulu". Tambahkan folder ke `User` PATH via `[Environment]::SetEnvironmentVariable('Path', ..., 'User')` bila belum ada. Salin juga `install.ps1` ini ke folder instalasi supaya `mydns update` berikutnya punya skrip. Cetak versi terpasang dan path; exit 0 sukses, 1 gagal.

- [ ] **Step 2: Periksa sintaks tanpa menjalankan jaringan**

Run (PowerShell): `$ErrorActionPreference='Stop'; $tokens=$null; $errors=$null; [void][System.Management.Automation.Language.Parser]::ParseFile('install.ps1',[ref]$tokens,[ref]$errors); if ($errors) { $errors | ForEach-Object { Write-Error $_ } }`
Expected: tidak ada error parse. Script parser tidak mengabaikan `$null` cast.

- [ ] **Step 3: Uji kegagalan checksum di mesin Windows (manual oleh owner)**

Run: `powershell -ExecutionPolicy Bypass -File install.ps1 -Version v0.1.0` dengan SHA256SUMS sengaja diubah (atau hook jaringan).
Expected: gagal sebelum ekstrak, file di `%LOCALAPPDATA%\MyDns\bin` tidak berubah.

- [ ] **Step 4: Commit**

```bash
git add install.ps1
git commit -m "feat: installer PowerShell MyDNS dengan verifikasi checksum"
```

### Task 7: CI job rilis

**File:**
- Modifikasi: `.github/workflows/ci.yml`.

- [ ] **Step 1: Tambah job release**

Syarattepat:
```yaml
  release:
    if: startsWith(github.ref, 'refs/tags/v')
    needs: windows
    permissions:
      contents: write
    runs-on: windows-latest
```

Download artifact `mydns-windows` dari job `windows` (`actions/download-artifact@v4`), ZIP dengan PowerShell `Compress-Archive` menjadi `mydns-x86_64-pc-windows-msvc.zip` berisi `mydns.exe` + `wintun.dll`, buat `SHA256SUMS` berisi `<hash>  mydns-x86_64-pc-windows-msvc.zip`, unggah `install.ps1` dari checkout tag, lalu `gh release create "${{ github.ref_name }}" ... --title "MyDNS ${{ github.ref_name }}" --generate-notes`. Job rilis tidak boleh diam-diam memakai `assets/wintun.dll` dari mesin lokal; bila DLL tidak ada di artefak, job gagal dengan pesan jelas.

- [ ] **Step 2: Verifikasi YAML dan alur lokal**

Run: `git diff --check` dan `python -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"` bila PyYAML tersedia.
Expected: tidak ada error.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: terbitkan rilis GitHub saat push tag v*"
```

### Task 8: Dokumentasi dan verifikasi akhir

**File:**
- Modifikasi: `README.md`.

- [ ] **Step 1: Perbarui README**

Tambahkan bagian "Install & Update" sebelum "Cara pakai":

```powershell
powershell -c "irm https://raw.githubusercontent.com/EmhaHasyim/mydns/master/install.ps1 | iex"
mydns -v
mydns update    # alias: mydns upgrade
```

Jelaskan: butuh PowerShell baru setelah install; file di `%LOCALAPPDATA%\MyDns\bin`; `dns.cmd` dari repo masih bisa dipakai; update menolak saat MyDNS aktif; pengingat muncul di TUI/status/doctor; konfigurasi WARP/resolver di `%APPDATA%\MyDns`, cache update dan log di `%LOCALAPPDATA%\MyDns`. Perbarui klaim "satu file .exe" menjadi "exe + wintun.dll saat pakai VPN".

- [ ] **Step 2: Verifikasi lengkap**

Run:
```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --quiet
cargo build --release
git diff --check
```
Expected: semua lulus. Uji manual Windows: `irm|iex`, PowerShell baru, `mydns -v`, `mydns status`, `mydns update` saat belum ada rilis (harus lapor "rilis GitHub belum tersedia" atau "sudah versi terbaru").

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: cara install, versi, dan update MyDNS"
```
