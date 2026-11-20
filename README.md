# MyDNS

Ganti DNS Windows 11 ke **DoQ / DoH3** (DNS lewat QUIC) supaya lebih cepat dan
lebih privat. Windows belum bisa memakai dua protokol ini.

MyDNS terdiri dari `mydns.exe` dan `wintun.dll` saat memakai VPN; tidak
menyisakan layanan. Bisa dipakai langsung dari repo atau dipasang dengan
installer.

## Install & Update

```powershell
powershell -c "irm https://raw.githubusercontent.com/EmhaHasyim/mydns/master/install.ps1 | iex"
mydns -v
mydns update    # alias: mydns upgrade
```

Installer menaruh biner di `%LOCALAPPDATA%\MyDns\bin` dan menambahkan folder
itu ke `PATH` user. Buka PowerShell baru setelah install agar `PATH` terbaru
terbaca; `mydns -v` menampilkan versi yang terpasang. `dns.cmd` dari repo juga
masih bisa dipakai untuk menjalankan biner hasil build lokal.

`mydns update` mengecek rilis GitHub terbaru. Update ditolak saat MyDNS masih
aktif — tutup MyDNS atau jalankan `mydns restore` dulu. Pengingat update muncul
di TUI, `mydns status`, dan `mydns doctor`. Instalasi dan update memerlukan
rilis GitHub yang sudah dipublikasikan; kalau belum ada, perintah melaporkan
`rilis GitHub belum tersedia`.

Konfigurasi WARP dan resolver ada di `%APPDATA%\MyDns`, sedangkan cache
pengecekan update dan log ada di `%LOCALAPPDATA%\MyDns`.

## Cara pakai

Jalankan dari folder proyek:

```powershell
.\dns.cmd
```

Atau ketik `mydns` kalau folder proyek sudah masuk `PATH`.

Akan muncul izin administrator (UAC) — itu wajar, karena mengubah DNS butuh hak
admin. Pilih resolver dengan `↑` `↓`, lalu tekan `Enter`.

Saat Anda keluar, DNS **dikembalikan otomatis** ke setelan asli. Kalau program
mati mendadak atau komputer restart, pemulihan juga tetap jalan (jalankan
`mydns autostart on` sekali untuk pemulihan saat logon).

## Tombol

| Tombol | Fungsi |
|---|---|
| `↑` `↓` | pilih resolver |
| `Enter` | pakai resolver terpilih (DNS saja) |
| `v` | nyalakan/matikan VPN lewat WARP |
| `c` | kembalikan DNS ke setelan asli |
| `l` | lihat log query |
| `?` | bantuan |
| `q` | keluar |

## Pilihan resolver

- **Cloudflare** — cepat, tanpa filter
- **Quad9** — memblokir malware
- **AdGuard DNS** — memblokir iklan & tracker
- **Control D** — memblokir iklan lebih banyak
- **WARP** — DNS lewat tunnel Cloudflare
- **Clear DNS** — kembali ke DNS asli

## Perintah lain

```powershell
mydns status      # lihat DNS yang sedang dipakai
mydns doctor      # cek apakah semuanya sehat
mydns restore     # kembalikan DNS sekarang
mydns test        # uji kecepatan semua resolver
mydns log 20      # lihat 20 baris log terakhir
mydns autostart on  # pulihkan DNS otomatis saat komputer nyala
```

## Yang perlu diketahui

- Port 53 harus kosong (jangan bentrok dengan Docker atau AdGuard Home).
- Mode VPN butuh hak admin dan file `wintun.dll` yang disertakan.
- DNS aktif selama program berjalan.

Variabel lingkungan opsional:

- `MYDNS_RESOLVERS` — path ke berkas konfigurasi resolver kustom.
- `MYDNS_WARP` — path ke berkas konfigurasi WARP (`warp.json`).
- `MYDNS_NO_ELEVATE` — lewati permintaan UAC (DNS tidak akan diubah).

## Untuk pengembang

```powershell
cargo build --release
cargo test
```
