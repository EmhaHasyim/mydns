# MyDNS

Pengalih DNS Windows 11 ke **DoQ (DNS over QUIC)** / **DoH3 (DNS over HTTPS/3)**
lewat proxy lokal. Satu file `.exe`, tanpa runtime, tanpa layanan latar belakang.

```
 mydns
 ─────────────────────────────────────────────
  ▸ Cloudflare     DoH3         1.1.1.1, tanpa filter
    Quad9          DoQ · DoH3   blokir malware, DNSSEC
    AdGuard DNS    DoQ · DoH3   blokir iklan + tracker
    Control D      DoQ · DoH3   Hagezi Ultimate
    WARP (MASQUE)               DNS lewat tunnel Cloudflare WARP
    Clear DNS                   kembalikan ke DHCP / server asli
```

## Mengapa perlu proxy

Windows 11 hanya punya klien **DoH/HTTP-2** dan DoT. Tidak ada DoH3 maupun DoQ
di resolver bawaan Windows. Supaya QUIC benar-benar dipakai, MyDNS:

1. membuka listener DNS di `127.0.0.1:53` dan `[::1]:53`,
2. meneruskan query ke resolver lewat QUIC (DoQ dulu, lalu DoH3, lalu DoH2),
3. mengarahkan DNS adapter ke loopback,
4. mengembalikan DNS asli saat aplikasi ditutup.

Koneksi ke resolver selalu memakai **IP bootstrap yang di-hardcode** dengan SNI
nama host. Tanpa ini, resolusi untuk alamat resolver akan memutar balik ke proxy
sendiri (loop).

## Build

```powershell
cargo build --release
```

Hasil: `target\release\mydns.exe` (± 3,5 MB).

## Menjalankan

Cara tercepat, dari folder proyek:

```powershell
.\dns.cmd
```

Supaya cukup mengetik `dns` di PowerShell mana pun:

```powershell
# sekali saja, untuk sesi terminal ini
$env:Path += ";C:\Users\xorex\Code\MyDns"

# permanen (jalankan sekali)
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\Users\xorex\Code\MyDns", "User")
```

Lalu:

```powershell
dns
```

Karena mengubah DNS adapter butuh hak administrator, aplikasi memunculkan prompt
UAC sendiri. Tombol:

| Tombol | Fungsi |
|---|---|
| `↑` `↓` / `j` `k` | pindah pilihan |
| `1` – `9` | lompat ke baris |
| `Enter` | terapkan resolver yang dipilih |
| `c` | Clear DNS (pulihkan, tetap di TUI) |
| `l` | log query terakhir (jalur + latensi) |
| `?` | bantuan |
| `q`, `x`, `Esc`, `Ctrl+C` | keluar — DNS **otomatis** dipulihkan |

## Tampilan

Tema gelap dengan aksen cyan (`#22d3ee`), mengikuti pola empat zona yang lazim
di TUI yang mudah dipakai:

```
 ◆ MyDNS   DNS over QUIC · HTTP/3                        ● Cloudflare · DoH3
 DNS Ethernet → 94.140.14.14, 94.140.15.15
 ────────────────────────────────────────────────────────────────────────
 ┌ resolver ──────────────────────┐  ┌ detail ─────────────────┐
 │  RESOLVER      PROTOKOL  KET.  │  │ Cloudflare              │
 │ ▌ Cloudflare   DoH3     1.1.1… │  │ 1.1.1.1, tanpa filter   │
 │   Quad9        DoQ·DoH3 …      │  │                         │
 │   AdGuard DNS  DoQ·DoH3 …      │  │ DOQ · UDP 853           │
 │   Control D    DoQ·DoH3 …      │  │ tidak tersedia          │
 │   Clear DNS    —        …      │  │ DOH · HTTPS 443         │
 └────────────────────────────────┘  │ https://cloudflare-…    │
 · siap · pilih resolver lalu enter   └─────────────────────────┘
 ↑↓ pilih  enter terapkan  c clear  ? bantuan  q keluar   cache —
```

- **Header** selalu menampilkan konteks: versi protokol, DNS yang sedang aktif,
  dan status provider aktif.
- **Panel detail** muncul otomatis saat lebar terminal ≥ 92 kolom; di bawah itu
  daftar memakai lebar penuh. Di bawah 60×16 muncul peringatan agar terminal
  diperbesar.
- **Warna semantik**: cyan = aksen/pilihan, hijau = aktif, kuning = aksi
  pemulihan/menunggu, merah = gagal. Ikon (`●` `○` `▌` `✕`) ikut membawa makna,
  jadi tampilan tetap terbaca tanpa warna.
- **Progressive disclosure**: footer hanya memuat 5 tombol terpenting, `?`
  membuka daftar lengkap.
- **Panel log** (`l`) menampilkan query terakhir, terbaru di baris paling bawah:

  ```
  example.com                    A      DoQ    24ms
  doubleclick.net                A      cache  0ms
  gagal meneruskan contoh.invalid (A): DoQ: timeout; DoH3: timeout
  ```

  `cache` berarti dijawab dari cache lokal, selain itu nama protokol yang benar-
  benar dipakai ke upstream. Log disimpan di memori (200 baris terakhir).

### Perintah lain

| Perintah | Fungsi |
|---|---|
| `mydns` | TUI pemilih resolver |
| `mydns status` | DNS adapter aktif sekarang + catatan MyDNS |
| `mydns restore` | pulihkan DNS asli tanpa TUI |
| `mydns providers` | daftar resolver aktif + berkas kustom yang dibaca |
| `mydns doctor` | periksa kesehatan pengalihan DNS (tanpa mengubah apa pun) |
| `mydns log [n]` | tampilkan n baris terakhir log peristiwa |
| `mydns autostart on` | pulihkan DNS otomatis setiap logon (disarankan) |
| `mydns autostart off` | lepaskan pemulihan otomatis itu |
| `mydns test` | uji DoQ / DoH3 / DoH2 ke semua provider + latensi |
| `mydns serve adguard` | jalankan proxy saja (debug), tanpa mengubah DNS |
| `mydns warp register` | daftarkan perangkat Cloudflare WARP (sekali saja) |
| `mydns warp status` | tampilkan data perangkat WARP yang tersimpan |
| `mydns warp test` | buka tunnel WARP dan uji satu query DNS |

`mydns test` dan `mydns serve` **tidak** butuh admin dan tidak mengubah setelan DNS.

Peristiwa penting (apply, restore, registrasi WARP, kegagalan) ditulis ke
`%LOCALAPPDATA%\MyDns\mydns.log` dan bisa dibaca dengan `mydns log`. Log tidak
pernah menggagalkan DNS: kalau berkasnya tidak bisa ditulis, aplikasi lanjut.

## Pengaman: DNS tidak pernah tertinggal rusak

Kesalahan paling mahal untuk tool seperti ini bukan tampilan, tapi DNS yang
tetap menunjuk `127.0.0.1` padahal tidak ada yang mendengarkan di sana — hasilnya
sama dengan tidak punya internet. Empat lapis menjaga itu:

1. **Keluar normal** (`q` / `x` / `Esc` / `Ctrl+C` / jendela ditutup) — handler
   `SetConsoleCtrlHandler` memulihkan DNS sebelum proses berakhir.
2. **Proses dibunuh, crash, atau listrik putus** — TUI menjalankan pendamping
   kecil yang tidak terlihat (`mydns --watchdog <pid>`). Pendamping itu hanya
   menunggu proses induk berakhir, lalu memulihkan DNS kalau catatannya masih
   ada. Tidak ada jendela, tidak ada proses yatim: ia keluar sendiri begitu
   induknya beres.
3. **Reboot** — `mydns autostart on` mendaftarkan Scheduled Task yang berjalan
   saat logon (hak tertinggi, jadi tanpa UAC) dan menjalankan
   `mydns restore --if-stale`. Mode itu hanya memulihkan kalau catatan lama
   masih ada **dan** port 53 tidak dilayani siapa pun — jadi sesi baru tidak
   pernah ditimpa.
4. **DNS diterapkan tapi tidak berfungsi** — penerapan bersifat transaksional:
   listener lokal diuji dulu (query sungguhan lewat `127.0.0.1:53`), baru
   adapter diarahkan, lalu resolver sistem diuji sekali lagi. Kalau Windows
   tetap tidak bisa resolve, DNS dikembalikan otomatis dan TUI menampilkan
   alasannya.

5. **Jaringan berganti atau bangun dari sleep** — selama sesi berjalan, setiap
   3 detik adapter yang DNS-nya ditimpa DHCP dikembalikan ke proxy. Adapter
   baru ikut dicatat, jadi Clear DNS tetap memulihkan setelan aslinya.

`mydns doctor` merangkum semuanya dalam satu perintah: hak admin, isi port 53,
proxy lokal, DNS adapter, catatan yang mungkin basi, status pemulihan logon,
dan validitas berkas resolver kustom.

```
$ mydns doctor

  [ok]   hak administrator
  [info] DNS adapter: Ethernet → 94.140.14.14, 94.140.15.15
  [info] port 53 loopback bebas
  [info] proxy lokal tidak berjalan
  [ok]   DNS tidak menunjuk MyDNS
  [warn] pemulihan saat logon belum aktif — jalankan `mydns autostart on`

tidak ada masalah yang menghalangi.
```

## Hasil uji nyata

Dari mesin ini (Windows 11, `mydns test`, 3 putaran, query `example.com/A`):

| Provider | DoQ | DoH3 | DoH2 |
|---|---|---|---|
| Cloudflare | — (tidak ada DoQ publik) | ✅ 40 ms | ✅ 37 ms |
| Quad9 | ✅ 21 ms | ✅ 24 ms | ✅ 23 ms |
| AdGuard DNS | ✅ 33 ms | ✅ 36 ms | ✅ 36 ms |
| Control D (Hagezi Ultimate) | ✅ 37 ms | ✅ 37 ms | ✅ 37 ms |

Control D memakai profil **x-hagezi-ultimate**
(`https://freedns.controld.com/x-hagezi-ultimate`,
DoQ `x-hagezi-ultimate.freedns.controld.com`). Hostname itu mengarah ke anycast
`76.76.2.11`; IP `76.76.2.45` / `76.76.10.45` tidak membuka 443/853 dari jaringan
ini, jadi keduanya hanya dipakai sebagai cadangan.

Uji filter lewat proxy Control D: `doubleclick.net`, `ad.doubleclick.net`, dan
`google-analytics.com` → `::` (diblokir), sementara `wikipedia.org` resolve normal.

## Resolver kustom (tanpa rebuild)

Empat resolver bawaan bisa ditimpa, dan resolver baru bisa ditambahkan, dengan
berkas teks:

```
%APPDATA%\MyDns\resolvers.txt
```

Satu baris per resolver, dipisah `|`, baris `#` adalah komentar:

```
id | nama | catatan | doq:host:port | doh:url | boot:ip,ip
```

Hanya `id` dan `nama` yang wajib; endpoint yang tidak dipakai boleh `-`.
Contoh sungguhan — profil Control D sendiri, plus IP bootstrap tambahan untuk
Cloudflare:

```
profil | Control D (saya) | Hagezi Pro | x-abc123.freedns.controld.com:853 | https://freedns.controld.com/x-abc123 | 76.76.2.11
cloudflare | Cloudflare | 1.1.1.1, tanpa filter | - | https://cloudflare-dns.com/dns-query | 1.1.1.1, 1.0.0.1, 1.1.1.2
```

- `id` yang sudah ada **menimpa** field yang diisi saja (cara memperbarui IP
  bootstrap tanpa menunggu rilis baru).
- `id` baru ditambahkan ke daftar, tepat sebelum Clear DNS.
- Baris yang salah tidak menghentikan aplikasi: kesalahannya dilaporkan dengan
  nomor baris, dan `mydns doctor` menandainya sebagai masalah.
- `mydns providers` menampilkan semua resolver aktif, endpoint-nya, dan berkas
  konfigurasi yang dipakai. Untuk pengujian, arahkan `MYDNS_RESOLVERS` ke berkas
  lain.

## Cloudflare WARP (mode MASQUE)

Resolver kelima: query DNS dikirim **di dalam tunnel MASQUE Cloudflare WARP**
(`CONNECT-IP`, RFC 9484 di atas HTTP/3), bukan lewat DoQ/DoH3. Yang menyeberang
hanya query DNS — tidak ada adapter TUN dan tidak ada route yang diubah, jadi
sisa trafik tetap memakai koneksi biasa.

Sekali saja, daftarkan perangkat:

```powershell
mydns warp register
```

Perintah itu memanggil API Cloudflare (buat perangkat WireGuard, lalu tukar
kuncinya ke kunci P-256 untuk mode MASQUE) dan menyimpan hasilnya di
`%APPDATA%\MyDns\warp.json`. Sesudah itu baris **WARP (MASQUE)** di TUI bisa
dipilih seperti resolver lain.

Periksa dan uji kapan saja:

```powershell
mydns warp status
mydns warp test
```

`warp test` membuka tunnel lalu mengirim satu query `example.com/A` ke
`1.1.1.1:53` di dalam tunnel:

```
tunnel        : siap dalam 470 ms
example.com/A : 40 ms — 2 jawaban, NoError, 104.20.23.154 ttl=171
```

Yang perlu diketahui:

- **Autentikasi memakai mTLS**: sertifikat P-256 yang dibuat sendiri saat
  registrasi, dan identitas server diverifikasi dengan *pinning* public key dari
  respons registrasi — endpoint WARP memang tidak punya nama di WebPKI.
- **Tanpa TUN, tanpa route baru.** Tunnel hanya membawa paket IPv4/UDP ke
  resolver WARP; aplikasi ini tidak bisa dipakai meneruskan trafik lain.
- **Header `CONNECT-IP` disusun sendiri.** `h3` hanya mengenal `connect-udp` dan
  `webtransport` pada `:protocol`, sedangkan WARP memakai nama Cloudflare
  `cf-connect-ip`, jadi field section QPACK-nya dirakit langsung.
- `warp.json` berisi kunci privat perangkat, tetapi disimpan **terenkripsi
  DPAPI** sehingga hanya user Windows yang sama di mesin ini yang bisa
  membukanya. Berkas lama berisi base64 biasa tetap dibaca, lalu dienkripsi saat
  disimpan lagi. `mydns warp register` ulang akan membuat perangkat baru.

## Tes

```powershell
cargo test
```

Tiga puluh empat tes menutupi jalur yang memproses byte dari jaringan dan berkas
konfigurasi, yang tidak bisa diperiksa dengan mata. CI Windows menjalankan
`cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, dan `cargo test`:

| Tes | Yang dijaga |
|---|---|
| `cache_key_menormalkan_nama` | `Example.COM.` dan `example.com` memakai entri cache yang sama |
| `cache_key_memisahkan_dnssec_dan_cd` | klien DO/CD tidak berbagi entri dengan klien biasa |
| `cache_hit_menurunkan_ttl_dan_mengganti_id` | TTL yang dikirim ke klien tidak melebihi sisa umur cache; ID query dipasang kembali |
| `opcode_bukan_query_tidak_dicache` | UPDATE/NOTIFY tidak pernah masuk cache |
| `respons_tidak_cocok_dengan_query_ditolak` | ID atau pertanyaan yang berbeda ditolak, bukan diteruskan |
| `cache_penuh_membuang_entri_paling_tua` | cache penuh membuang entri tertua, bukan mengosongkan semuanya |
| `hedge_doh3_mendahulukan_doh2_saat_sibuk` | antrean DoH3 penuh memindahkan DoH2 ke depan |
| `restore_memakai_nama_saat_index_berubah` | index adapter berubah, setelan asli tetap dipulihkan lewat nama |
| `restore_melewati_adapter_yang_sudah_hilang` | adapter yang sudah tidak ada tidak dipaksa ke index lain |
| `kunci_privat_bolak_balik_lewat_dpapi` | kunci privat WARP terenkripsi dan bisa dibuka kembali |
| `timestamp_berbentuk_iso` | baris log memakai tanggal UTC yang konsisten |
| `fit_udp_memotong_paket_besar_dengan_bit_tc` | respons TXT 639 byte dipotong ≤ 512 byte, TC diset, ID utuh |
| `fit_udp_membiarkan_tcp_dan_paket_kecil` | TCP tidak dipotong, paket kecil lewat utuh |
| `servfail_*` | SERVFAIL mempertahankan ID, menandai QR + RCODE, mengosongkan hitungan |
| `build_query_meminta_rekursi` | bit RD dan QDCOUNT=1 (tanpa RD, resolver publik menolak) |
| `url_host_mengambil_nama_host` | SNI diambil benar dari URL DoH |
| `describe_*` | ringkasan respons, termasuk input yang bukan DNS |
| `baris_lengkap_terbaca`, `komentar_dan_baris_kosong_diabaikan`, `port_default_853` | format `resolvers.txt` terbaca sesuai dokumentasi |
| `baris_bermasalah_dilaporkan_bukan_dipaksa` | id kosong/id ilegal/tanpa endpoint/IP salah dilaporkan dengan nomor baris |
| `bawaan_tetap_ada_dan_urutannya_stabil` | urutan bawaan tidak berubah dan setiap resolver punya IP bootstrap |
| `checksum_header_dan_udp_benar`, `paket_udp_putar_balik` | paket IPv4+UDP yang dibangun untuk tunnel bisa diurai kembali, checksum benar |
| `sertifikat_bisa_dibaca_kembali` | sertifikat P-256 self-signed hasil DER buatan sendiri valid |
| `spki_menempel_pada_titik_p256`, `public_key_pem_dan_base64_sama_saja` | kunci publik diekstrak dari PKCS#8; jawaban PEM maupun base64 diperlakukan sama |
| `varint_menyandikan_semua_ukuran` | QUIC varint bolak-balik di semua lebar |
| `endpoint_port_nol_menjadi_443`, `base64_bolak_balik`, `udp_to_port_menolak_paket_lain` | normalisasi endpoint, base64 tanpa padding, dan penyaringan datagram asing |

## Kinerja terukur

| Metrik | Hasil |
|---|---|
| Ukuran binary | 3,5 MB, satu file, tanpa runtime |
| `mydns status` | 0,05 s (sebelum optimasi: 2,16 s) |
| Membaca DNS adapter | `GetAdaptersAddresses` (~1 ms); PowerShell hanya cadangan |
| Latensi query ke resolver | 22–50 ms lewat DoQ / DoH3 |
| Query dari cache | < 1 ms (loopback) |
| 20 query identik bersamaan | 1 kali diteruskan (3–4 ms total), sisanya ikut hasil yang sama |
| 20 query paralel nama berbeda | 281 ms (sebelum hedge DoH3: 863 ms) |
| Jawaban cache | TTL diturunkan sesuai sisa umur (maks 60 detik) |
| Build | `cargo build --release`: 0 warning, `cargo clippy` bersih |
| Uji 25 query paralel | selesai tanpa error |
| IP bootstrap IPv6 | Cloudflare/Quad9/AdGuard punya jalur v6, dipakai setelah v4 gagal |

Yang dihitung hanya adapter berstatus **Up** dan punya gateway. Adapter yang
sedang Disconnected (mis. Wi-Fi saat memakai kabel) sengaja tidak disentuh,
supaya DNS-nya tidak tertinggal menunjuk proxy mati saat nanti tersambung.

## Batasan yang perlu diketahui

- **DNS hanya aktif selama aplikasi berjalan.** Kalau terminal ditutup, Windows
  kehilangan resolver — karena itu MyDNS memulihkan DNS saat keluar, lewat
  watchdog saat proses dibunuh/crash, dan lewat Scheduled Task saat logon
  berikutnya (kalau `mydns autostart on` pernah dijalankan).
- **Port 53 harus kosong.** Kalau Docker Desktop, AdGuard Home, atau VPN sudah
  memakai `127.0.0.1:53`, aplikasi menolak mengubah DNS dan menampilkan error.
- **DNS IPv6 hanya dipasang kalau listener `[::1]:53` benar-benar aktif.** Kalau
  bind IPv6 gagal, adapter tidak diarahkan ke `::1`, supaya resolusi IPv6 tidak
  menunjuk port yang mati.
- **Berkas kustom dibaca sekali saat start.** Setelah mengedit
  `resolvers.txt`, buka ulang TUI (atau jalankan perintah lain) agar terbaca.
- **Cache lokal dibatasi 60 detik** meskipun TTL dari upstream lebih panjang.
  TTL pada jawaban cache ikut diturunkan ke sisa umurnya, jadi klien tidak
  menyimpan rekaman lebih lama daripada cache kita. Entri dipisahkan per bit
  DNSSEC-OK dan CD, sehingga klien DNSSEC tidak pernah menerima jawaban tanpa
  RRSIG dari cache. Query yang membawa opsi EDNS (COOKIE, ECS) tidak dicache.
- **DoH3 masih berurutan per koneksi.** Satu koneksi HTTP/3 melayani satu query
  pada satu waktu. Percobaan memakai banyak request sekaligus di satu koneksi
  membuat sebagian server (Quad9) berhenti menjawab, dan beberapa koneksi QUIC
  yang dibuka serentak ke IP bootstrap yang sama sering ditolak jaringan ini.
  Karena itu, begitu antrean DoH3 penuh, query dialihkan ke DoH2 yang mendukung
  banyak request paralel (20 query paralel: 281 ms, dari 863 ms sebelumnya).
  DoQ (satu stream per query) juga tetap paralel.
- **Query identik yang datang bersamaan diteruskan sekali.** Sisanya menunggu
  lalu mengambil hasil dari cache, jadi lonjakan query yang sama tidak
  menggandakan trafik ke resolver.
- **Belum ada mode Windows service**, jadi filter DNS belum bisa "set once,
  jalan terus" tanpa terminal terbuka; yang dijamin hanya pemulihan otomatis,
  bukan proxy yang hidup terus.

## Struktur

| File | Isi |
|---|---|
| `src/main.rs` | CLI, elevasi UAC, subperintah |
| `src/providers.rs` | katalog resolver, `resolvers.txt`, endpoint DoQ/DoH, IP bootstrap |
| `src/engine.rs` | klien DoQ (quinn), DoH3 (h3), DoH2 (h2), rantai fallback |
| `src/warp.rs` | registrasi WARP, mTLS + pinning SPKI, tunnel CONNECT-IP, paket IPv4/UDP |
| `src/server.rs` | listener UDP/TCP di loopback, cache TTL, truncation |
| `src/ui.rs` | TUI ratatui + alur terapkan/pulihkan |
| `src/win.rs` | deteksi adapter, `Set-DnsClientServerAddress`, state file, watchdog, autostart |
| `src/log.rs` | buffer log internal, log berkas, timestamp UTC |
