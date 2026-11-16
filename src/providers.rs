//! Katalog resolver yang didukung MyDNS.
//!
//! Setiap provider menyimpan endpoint per protokol plus daftar IP *bootstrap*.
//! Bootstrap dipakai supaya kita tidak pernah perlu melakukan resolusi DNS
//! untuk menghubungi resolver: begitu adapter diarahkan ke 127.0.0.1,
//! resolusi sistem akan memutar balik ke proxy kita sendiri (loop).
//!
//! Empat resolver bawaan bisa ditimpa, dan resolver baru bisa ditambahkan,
//! lewat berkas teks `%APPDATA%\MyDns\resolvers.txt`. Dengan begitu profil
//! Control D pribadi atau IP bootstrap yang berubah tidak memerlukan rebuild.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::OnceLock;

/// Protokol transport ke resolver.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Proto {
    /// DNS over QUIC, RFC 9250. Satu stream QUIC per query.
    DoQ,
    /// DNS over HTTPS di atas HTTP/3.
    DoH3,
    /// DNS over HTTPS di atas HTTP/2 (jalur fallback terakhir).
    DoH2,
    /// Query DNS dibawa tunnel Cloudflare WARP (MASQUE / CONNECT-IP).
    Warp,
}

impl Proto {
    pub fn label(self) -> &'static str {
        match self {
            Proto::DoQ => "DoQ",
            Proto::DoH3 => "DoH3",
            Proto::DoH2 => "DoH2",
            Proto::Warp => "WARP",
        }
    }
}

#[derive(Clone, Copy)]
pub struct Provider {
    pub id: &'static str,
    pub name: &'static str,
    pub note: &'static str,
    /// (hostname, port) untuk DoQ; hostname sekaligus dipakai sebagai SNI.
    pub doq: Option<(&'static str, u16)>,
    /// URL lengkap DoH (dipakai untuk HTTP/3 maupun HTTP/2).
    pub doh: Option<&'static str>,
    /// IP unicast yang dipakai sebagai tujuan koneksi (SNI tetap hostname).
    pub boot: &'static [&'static str],
    /// Resolver ini diakses lewat tunnel MASQUE, bukan DoQ/DoH langsung.
    pub warp: bool,
}

impl Provider {
    /// Protokol yang tersedia, dari yang paling ringan ke paling kompatibel.
    pub fn protos(&self) -> Vec<Proto> {
        let mut v = Vec::with_capacity(3);
        if self.doq.is_some() {
            v.push(Proto::DoQ);
        }
        if self.doh.is_some() {
            v.push(Proto::DoH3);
            v.push(Proto::DoH2);
        }
        if self.warp {
            v.push(Proto::Warp);
        }
        v
    }

    /// Hanya protokol berbasis QUIC — dipakai untuk label kapabilitas di TUI.
    pub fn quic_protos(&self) -> Vec<Proto> {
        self.protos()
            .into_iter()
            .filter(|p| matches!(p, Proto::DoQ | Proto::DoH3 | Proto::Warp))
            .collect()
    }

    pub fn badges(&self) -> String {
        self.quic_protos()
            .iter()
            .map(|p| p.label())
            .collect::<Vec<_>>()
            .join(" · ")
    }
}

/// Resolver bawaan. Urutan ini yang tampil di TUI sebelum Clear DNS.
const BUILTINS: &[Provider] = &[
    Provider {
        id: "cloudflare",
        name: "Cloudflare",
        note: "1.1.1.1, tanpa filter",
        // Cloudflare tidak menjalankan DoQ publik; DoH-nya mendukung HTTP/3.
        doq: None,
        doh: Some("https://cloudflare-dns.com/dns-query"),
        boot: &[
            "1.1.1.1",
            "1.0.0.1",
            "2606:4700:4700::1111",
            "2606:4700:4700::1001",
        ],
        warp: false,
    },
    Provider {
        id: "quad9",
        name: "Quad9",
        note: "blokir malware, DNSSEC",
        doq: Some(("dns.quad9.net", 853)),
        doh: Some("https://dns.quad9.net/dns-query"),
        boot: &["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"],
        warp: false,
    },
    Provider {
        id: "adguard",
        name: "AdGuard DNS",
        note: "blokir iklan + tracker",
        doq: Some(("dns.adguard-dns.com", 853)),
        doh: Some("https://dns.adguard-dns.com/dns-query"),
        boot: &[
            "94.140.14.14",
            "94.140.15.15",
            "2a10:50c0::ad1:ff",
            "2a10:50c0::ad2:ff",
        ],
        warp: false,
    },
    Provider {
        id: "controld",
        name: "Control D",
        note: "Hagezi Ultimate",
        doq: Some(("x-hagezi-ultimate.freedns.controld.com", 853)),
        doh: Some("https://freedns.controld.com/x-hagezi-ultimate"),
        // 76.76.2.11 adalah anycast yang benar-benar menjawab DoH/DoQ untuk
        // hostname ini (terlihat dari hasil resolusi x-hagezi-ultimate...).
        // Dua IP lain tetap disimpan sebagai cadangan jaringan lain.
        boot: &["76.76.2.11", "76.76.2.45", "76.76.10.45"],
        warp: false,
    },
    Provider {
        id: "warp",
        name: "Cloudflare WARP",
        note: "MASQUE, query DNS di dalam tunnel",
        doq: None,
        doh: None,
        // Endpoint WARP datang dari hasil registrasi, bukan dari katalog.
        boot: &[],
        warp: true,
    },
];

// ── berkas konfigurasi pengguna ─────────────────────────────────────────

/// Satu baris `resolvers.txt`:
///
/// ```text
/// id | nama | catatan | doq:host:port | doh:url | boot:ip,ip
/// ```
///
/// Hanya `id` dan `nama` yang wajib; endpoint boleh `-` atau dikosongkan.
/// Baris berawalan `#` adalah komentar.
pub struct Entry {
    pub id: String,
    pub name: String,
    pub note: String,
    pub doq: Option<(String, u16)>,
    pub doh: Option<String>,
    pub boot: Vec<String>,
}

#[derive(Default)]
pub struct Config {
    pub entries: Vec<Entry>,
    pub errors: Vec<String>,
}

pub fn config_path() -> PathBuf {
    if let Ok(path) = std::env::var("MYDNS_RESOLVERS") {
        return PathBuf::from(path);
    }
    let base = std::env::var("APPDATA").unwrap_or_else(|_| r"C:\ProgramData".to_string());
    PathBuf::from(base).join("MyDns").join("resolvers.txt")
}

pub fn read_config() -> Config {
    match std::fs::read_to_string(config_path()) {
        Ok(text) => parse(&text),
        Err(_) => Config::default(),
    }
}

pub fn parse(text: &str) -> Config {
    let mut config = Config::default();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match parse_line(line) {
            Ok(entry) => config.entries.push(entry),
            Err(e) => config.errors.push(format!("baris {}: {e}", index + 1)),
        }
    }
    config
}

fn parse_line(line: &str) -> Result<Entry, String> {
    let mut parts = line.split('|').map(str::trim);

    let id = parts.next().unwrap_or("").to_ascii_lowercase();
    if id.is_empty() {
        return Err("id kosong".to_string());
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(format!("id '{id}' hanya boleh huruf, angka, '-' dan '_'"));
    }

    let name = parts.next().unwrap_or("").to_string();
    let name = if name.is_empty() { id.clone() } else { name };
    let note = parts.next().unwrap_or("").to_string();

    let doq_field = parts.next().unwrap_or("");
    let doq = match doq_field {
        "" | "-" => None,
        value => {
            let (host, port) = match value.rsplit_once(':') {
                Some((host, port)) => {
                    let port = port
                        .parse::<u16>()
                        .map_err(|_| format!("port DoQ tidak valid: {port}"))?;
                    (host.trim(), port)
                }
                None => (value, 853),
            };
            if host.is_empty() {
                return Err("host DoQ kosong".to_string());
            }
            Some((host.to_string(), port))
        }
    };

    let doh_field = parts.next().unwrap_or("");
    let doh = match doh_field {
        "" | "-" => None,
        value if value.starts_with("https://") => Some(value.to_string()),
        value => return Err(format!("URL DoH harus dimulai https:// ({value})")),
    };

    let boot_field = parts.next().unwrap_or("");
    let mut boot = Vec::new();
    for ip in boot_field.split(',').map(str::trim) {
        if ip.is_empty() {
            continue;
        }
        if ip.parse::<IpAddr>().is_err() {
            return Err(format!("IP bootstrap tidak valid: {ip}"));
        }
        boot.push(ip.to_string());
    }

    if doq.is_none() && doh.is_none() {
        return Err("butuh minimal satu endpoint DoQ atau DoH".to_string());
    }

    Ok(Entry {
        id,
        name,
        note,
        doq,
        doh,
        boot,
    })
}

/// Daftar resolver aktif: bawaan + tambahan/timpaan dari berkas kustom.
///
/// String dari berkas konfigurasi di-*leak* sekali saat start supaya seluruh
/// kode lain tetap memakai `&'static str`. Jumlahnya dibatasi isi berkas, jadi
/// pertumbuhannya tidak berarti apa-apa untuk proses berumur jam-an.
pub fn providers() -> &'static [Provider] {
    static LIST: OnceLock<Vec<Provider>> = OnceLock::new();
    LIST.get_or_init(build).as_slice()
}

pub fn find(id: &str) -> Option<&'static Provider> {
    providers().iter().find(|p| p.id == id)
}

fn build() -> Vec<Provider> {
    let config = read_config();
    let mut list: Vec<Provider> = BUILTINS.to_vec();
    for entry in config.entries {
        match list.iter().position(|p| p.id == entry.id.as_str()) {
            // id yang sudah ada: hanya field yang diisi yang menimpa.
            Some(index) => {
                let slot = &mut list[index];
                if !entry.name.is_empty() {
                    slot.name = leak(entry.name);
                }
                if !entry.note.is_empty() {
                    slot.note = leak(entry.note);
                }
                if let Some((host, port)) = entry.doq {
                    slot.doq = Some((leak(host), port));
                }
                if let Some(doh) = entry.doh {
                    slot.doh = Some(leak(doh));
                }
                if !entry.boot.is_empty() {
                    slot.boot = leak_boot(entry.boot);
                }
            }
            None => list.push(entry.into_provider()),
        }
    }
    list
}

impl Entry {
    fn into_provider(self) -> Provider {
        Provider {
            id: leak(self.id),
            name: leak(self.name),
            note: leak(self.note),
            doq: self.doq.map(|(host, port)| (leak(host), port)),
            doh: self.doh.map(leak),
            boot: leak_boot(self.boot),
            warp: false,
        }
    }
}

fn leak(value: String) -> &'static str {
    Box::leak(value.into_boxed_str())
}

fn leak_boot(ips: Vec<String>) -> &'static [&'static str] {
    Box::leak(
        ips.into_iter()
            .map(leak)
            .collect::<Vec<_>>()
            .into_boxed_slice(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baris_lengkap_terbaca() {
        let config = parse(
            "profil | Control D saya | Hagezi Pro | x-abc.freedns.controld.com:853 | https://freedns.controld.com/x-abc | 76.76.2.11, 76.76.2.45",
        );
        assert!(config.errors.is_empty(), "{:?}", config.errors);
        let entry = &config.entries[0];
        assert_eq!(entry.id, "profil");
        assert_eq!(entry.name, "Control D saya");
        assert_eq!(entry.note, "Hagezi Pro");
        assert_eq!(
            entry.doq,
            Some(("x-abc.freedns.controld.com".to_string(), 853))
        );
        assert_eq!(
            entry.doh.as_deref(),
            Some("https://freedns.controld.com/x-abc")
        );
        assert_eq!(entry.boot, vec!["76.76.2.11", "76.76.2.45"]);
    }

    #[test]
    fn komentar_dan_baris_kosong_diabaikan() {
        let config = parse("# contoh\n\n   \nkustom | Nama | catatan | dns.x:8853 | - | 1.2.3.4");
        assert!(config.errors.is_empty());
        assert_eq!(config.entries.len(), 1);
        assert_eq!(config.entries[0].doq, Some(("dns.x".to_string(), 8853)));
        assert!(config.entries[0].doh.is_none());
    }

    #[test]
    fn port_default_853() {
        let config = parse("k | N | c | dns.kunci.net | https://dns.kunci.net/dns-query | 9.9.9.9");
        assert_eq!(
            config.entries[0].doq,
            Some(("dns.kunci.net".to_string(), 853))
        );
    }

    #[test]
    fn baris_bermasalah_dilaporkan_bukan_dipaksa() {
        let config = parse(
            "k | N | c | dns.x | - | 1.2.3.4\n\
             | tanpa id | c | dns.x | - | 1.2.3.4\n\
             bad id | N | c | dns.x | - | 1.2.3.4\n\
             tanpa-endpoint | N | c | - | - | 1.2.3.4\n\
             ip-salah | N | c | dns.x | - | 999.1.1.1\n\
             doh-plain | N | c | - | http://x/dns | -",
        );
        assert_eq!(config.entries.len(), 1);
        assert_eq!(config.errors.len(), 5, "{:?}", config.errors);
        assert!(config.errors[0].starts_with("baris 2:"));
        assert!(config.errors.iter().any(|e| e.contains("https://")));
        assert!(config.errors.iter().any(|e| e.contains("999.1.1.1")));
    }

    #[test]
    fn bawaan_tetap_ada_dan_urutannya_stabil() {
        let list = providers();
        let ids: Vec<&str> = list.iter().map(|p| p.id).collect();
        assert!(ids.starts_with(&["cloudflare", "quad9", "adguard", "controld"]));
        assert!(list.iter().all(|p| !p.protos().is_empty()));
        // Setiap provider harus punya IP bootstrap: tanpa itu koneksi akan
        // memutar balik ke proxy sendiri. Pengecualian: WARP, yang endpoint-nya
        // baru diketahui setelah registrasi.
        assert!(list.iter().all(|p| !p.boot.is_empty() || p.warp));
        assert!(list.iter().any(|p| p.warp), "provider WARP harus ada");
        // Tiga resolver utama harus punya jalur IPv6 supaya jaringan v6-only
        // tetap bisa dipakai.
        for id in ["cloudflare", "quad9", "adguard"] {
            let provider = list.iter().find(|p| p.id == id).unwrap();
            assert!(
                provider
                    .boot
                    .iter()
                    .any(|ip| ip.parse::<IpAddr>().is_ok_and(|ip| ip.is_ipv6())),
                "{id} harus punya IP bootstrap IPv6"
            );
        }
    }
}
