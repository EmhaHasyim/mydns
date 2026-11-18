//! Cloudflare WARP mode MASQUE (CONNECT-IP, RFC 9484) sebagai transport DNS.
//!
//! Berbeda dari resolver lain di MyDNS, WARP tidak punya nama host yang bisa
//! dipakai untuk DoQ/DoH. Alurnya:
//!
//! 1. Registrasi perangkat ke API Cloudflare (dua langkah: buat perangkat
//!    WireGuard lalu tukar kuncinya ke kunci P-256 untuk mode MASQUE).
//! 2. Buka satu koneksi HTTP/3 ke endpoint WARP dengan **mTLS** memakai kunci
//!    P-256 itu, dan verifikasi server dengan *pinning* public key dari respons
//!    registrasi (bukan PKI publik — endpoint WARP memang tidak memakai nama
//!    yang ada di WebPKI).
//! 3. Kirim `CONNECT` dengan `:protocol: cf-connect-ip`. Field section QPACK-nya
//!    disusun sendiri karena `h3` hanya mengenal `connect-udp` dan
//!    `webtransport` pada pseudo-header itu.
//! 4. Paket IP dibawa sebagai HTTP Datagram: `quarter-stream-id` + `context-id`
//!    + paket IP, dengan quarter-stream-id berasal dari stream request CONNECT.
//!
//! Query DNS lalu dibungkus IPv4 + UDP ke 1.1.1.1:53 **di dalam** tunnel. Tidak
//! ada adapter TUN, tidak ada perubahan route: hanya query DNS yang menyeberang
//! lewat WARP.

use bytes::Bytes;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc, oneshot};
use zeroize::{Zeroize, Zeroizing};

const API_HOST: &str = "api.cloudflareclient.com";
const API_VERSION: &str = "v0a4471";
const CLIENT_VERSION: &str = "a-6.35-4471";
const DEFAULT_SNI: &str = "zt-masque.cloudflareclient.com";
const DEFAULT_AUTHORITY: &str = "cloudflareaccess.com";
/// Resolver yang dipakai di dalam tunnel WARP.
const TUNNEL_DNS: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
/// MTU WARP. Paket IP yang lebih besar tidak akan muat di satu datagram.
const TUNNEL_MTU: usize = 1280;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(6);
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
/// Batas respons API registrasi. Jawaban normal hanya beberapa KB; tanpa batas
/// server (atau MITM) bisa membuat proses kehabisan memori.
const MAX_API_BYTES: usize = 256 * 1024;
/// Penanda nilai yang dienkripsi DPAPI di `warp.json`.
const SECRET_PREFIX: &str = "dpapi:";

/// Port lokal → (ID transaksi DNS, penunggu jawaban).
type Pending = Arc<Mutex<HashMap<u16, (u16, oneshot::Sender<Vec<u8>>)>>>;

// ── berkas konfigurasi ──────────────────────────────────────────────────

/// Hasil registrasi + enrollment, disimpan supaya tidak perlu daftar ulang.
#[derive(Clone, Serialize, Deserialize)]
pub struct Config {
    pub device_id: String,
    pub token: String,
    /// Kunci privat P-256 dalam PKCS#8 DER, base64.
    pub private_key: String,
    /// Public key server WARP (SPKI DER, base64) untuk pinning.
    pub peer_public_key: String,
    /// Endpoint WARP, sudah berbentuk `ip:port`.
    pub endpoint_v4: String,
    pub endpoint_v6: String,
    pub ipv4: String,
    pub ipv6: String,
    #[serde(default = "default_sni")]
    pub sni: String,
    #[serde(default = "default_authority")]
    pub authority: String,
    pub registered_at: u64,
    /// Kunci privat di berkas disimpan terenkripsi DPAPI. Berkas lama tanpa
    /// field ini berisi base64 biasa dan tetap bisa dibaca.
    #[serde(default)]
    pub protected: bool,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Token dan kunci privat sudah terdekripsi di memori: jangan pernah
        // tercetak lewat `{:?}` (log, panic, atau diagnostik).
        f.debug_struct("Config")
            .field("device_id", &self.device_id)
            .field("token", &"<redacted>")
            .field("private_key", &"<redacted>")
            .field("peer_public_key", &self.peer_public_key)
            .field("endpoint_v4", &self.endpoint_v4)
            .field("endpoint_v6", &self.endpoint_v6)
            .field("ipv4", &self.ipv4)
            .field("ipv6", &self.ipv6)
            .field("sni", &self.sni)
            .field("authority", &self.authority)
            .field("registered_at", &self.registered_at)
            .field("protected", &self.protected)
            .finish()
    }
}

fn default_sni() -> String {
    DEFAULT_SNI.to_string()
}

fn default_authority() -> String {
    DEFAULT_AUTHORITY.to_string()
}

pub fn config_path() -> PathBuf {
    if let Ok(path) = std::env::var("MYDNS_WARP") {
        return PathBuf::from(path);
    }
    let base = std::env::var("APPDATA").unwrap_or_else(|_| r"C:\ProgramData".to_string());
    PathBuf::from(base).join("MyDns").join("warp.json")
}

pub fn load() -> Result<Config, String> {
    let path = config_path();
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| format!("belum terdaftar ({}): {e}", path.display()))?;
    let mut config: Config =
        serde_json::from_str(&raw).map_err(|e| format!("{} rusak: {e}", path.display()))?;
    if config.protected {
        config.private_key = unprotect_secret(&config.private_key)?;
        // Di memori kuncinya sudah berbentuk asli; `save` akan mengenkripsi
        // ulang kalau nilainya ditulis kembali.
        config.protected = false;
    }
    if config.token.starts_with(SECRET_PREFIX) {
        let encoded = config.token[SECRET_PREFIX.len()..].to_string();
        config.token = unprotect_secret(&encoded)?;
    } else if !config.token.is_empty() {
        // Berkas lama menyimpan token polos. Tulis ulang sekali supaya token
        // ikut terenkripsi. Kegagalan menulis tidak boleh memblokir `load`.
        let _ = save(&config);
    }
    Ok(config)
}

/// Ringkasan perangkat untuk panel detail: `(device_id, endpoint)`.
///
/// Ditulis sebagai fungsi tersendiri supaya UI bisa memanggilnya sekali dan
/// menyimpan hasilnya — `load` membuka kunci DPAPI, terlalu mahal untuk
/// dipanggil pada setiap frame.
pub fn device_summary() -> Option<(String, String)> {
    load()
        .ok()
        .map(|config| (config.device_id, config.endpoint_v4))
}

/// Konfigurasi siap pakai: pakai yang tersimpan, atau daftarkan perangkat
/// baru otomatis lalu simpan. Inilah jalur yang dipakai runtime, sehingga
/// memilih "Cloudflare WARP" sudah cukup — pengguna tidak perlu tahu ada
/// langkah registrasi. Berkas yang ada tetapi rusak tidak ditimpa: lebih baik
/// melaporkan errornya daripada diam-diam membuat perangkat baru.
pub async fn ensure() -> Result<Config, String> {
    let path = config_path();
    if path.exists() {
        return load();
    }
    let config = register().await?;
    save(&config)?;
    crate::log::event(&format!(
        "warp: perangkat didaftarkan otomatis ({})",
        config.device_id
    ));
    Ok(config)
}

pub fn save(config: &Config) -> Result<(), String> {
    let path = config_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("gagal membuat {}: {e}", dir.display()))?;
    }
    // Salinan ini yang ditulis ke disk; struct di pemanggil tetap berisi kunci
    // asli supaya bisa langsung dipakai membuka tunnel.
    let mut stored = config.clone();
    if !stored.protected {
        stored.private_key = protect_secret(&stored.private_key)?;
        stored.protected = true;
    }
    // Token juga rahasia (bearer untuk API akun); berkas lama menyimpannya
    // polos, jadi penanda prefix dipakai alih-alih field baru.
    if !stored.token.is_empty() && !stored.token.starts_with(SECRET_PREFIX) {
        stored.token = format!("{SECRET_PREFIX}{}", protect_secret(&stored.token)?);
    }
    let raw = serde_json::to_string_pretty(&stored).map_err(|e| e.to_string())?;
    std::fs::write(&path, raw).map_err(|e| format!("gagal menulis {}: {e}", path.display()))
}

// ── kunci privat terenkripsi (DPAPI) ─────────────────────────────────

/// Enkripsi DPAPI: hasilnya hanya bisa dibuka oleh user Windows yang sama di
/// mesin ini. `warp.json` tetap berisi kunci privat, tetapi salinan berkas itu
/// tidak bisa langsung dipakai di mesin lain.
fn protect_secret(plain: &str) -> Result<String, String> {
    Ok(b64::encode(&dpapi(plain.as_bytes(), true)?))
}

fn unprotect_secret(encoded: &str) -> Result<String, String> {
    let raw = b64::decode(encoded)?;
    let plain = dpapi(&raw, false)?;
    String::from_utf8(plain).map_err(|_| "kunci privat hasil dekripsi bukan UTF-8".to_string())
}

fn dpapi(data: &[u8], protect: bool) -> Result<Vec<u8>, String> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    };

    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(data.len()).map_err(|_| "data terlalu besar".to_string())?,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    let ok = unsafe {
        if protect {
            CryptProtectData(
                &input,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        }
    };
    if ok == 0 {
        return Err(format!("DPAPI gagal: {}", std::io::Error::last_os_error()));
    }

    if output.pbData.is_null() || output.cbData == 0 {
        if !output.pbData.is_null() {
            unsafe {
                LocalFree(output.pbData as *mut core::ffi::c_void);
            }
        }
        return Ok(Vec::new());
    }

    let bytes = unsafe {
        let plain = std::slice::from_raw_parts_mut(output.pbData, output.cbData as usize);
        let copied = plain.to_vec();
        plain.zeroize(); // salinan plaintext milik DPAPI dihapus sebelum dibebaskan
        copied
    };
    unsafe {
        LocalFree(output.pbData as *mut core::ffi::c_void);
    }
    Ok(bytes)
}

impl Config {
    /// Alamat endpoint yang dicoba lebih dulu: IPv4, lalu IPv6.
    fn endpoints(&self) -> Vec<SocketAddr> {
        [&self.endpoint_v4, &self.endpoint_v6]
            .iter()
            .filter_map(|raw| raw.parse::<SocketAddr>().ok())
            .collect()
    }

    fn tunnel_ipv4(&self) -> Result<Ipv4Addr, String> {
        self.ipv4
            .parse()
            .map_err(|_| format!("alamat tunnel IPv4 tidak valid: {}", self.ipv4))
    }
}

// ── registrasi ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct AccountData {
    id: String,
    #[serde(default)]
    token: Option<String>,
    config: AccountConfig,
}

#[derive(Debug, Deserialize)]
struct AccountConfig {
    peers: Vec<Peer>,
    interface: Interface,
}

#[derive(Debug, Deserialize)]
struct Peer {
    /// SPKI DER dalam base64.
    public_key: String,
    endpoint: Endpoint,
}

#[derive(Debug, Deserialize)]
struct Endpoint {
    v4: String,
    v6: String,
}

#[derive(Debug, Deserialize)]
struct Interface {
    addresses: Addresses,
}

#[derive(Debug, Deserialize)]
struct Addresses {
    v4: String,
    v6: String,
}

/// Daftarkan perangkat WARP baru dan langsung tukar ke mode MASQUE.
pub async fn register() -> Result<Config, String> {
    let rng = ring::rand::SystemRandom::new();

    // Langkah 1: buat perangkat WireGuard dengan kunci curve25519 acak. Kunci
    // ini tidak pernah dipakai; Cloudflare hanya butuh bentuk permintaan yang
    // dikenalnya sebelum perangkat boleh ditukar ke MASQUE.
    let mut wg_key = [0u8; 32];
    ring::rand::SecureRandom::fill(&rng, &mut wg_key).map_err(|_| "RNG gagal".to_string())?;

    let body = serde_json::json!({
        "key": b64::encode(&wg_key),
        "install_id": "",
        "fcm_token": "",
        "tos": timestamp_iso8601(),
        "model": "PC",
        "serial_number": hex(&random_bytes(&rng, 8)?),
        "os_version": "",
        "key_type": "curve25519",
        "tunnel_type": "wireguard",
        "locale": "en_US",
    })
    .to_string();

    let text = https_json("POST", "/reg", None, &body).await?;
    let account: AccountData = serde_json::from_str(&text)
        .map_err(|e| format!("respons registrasi tidak bisa dibaca: {e}"))?;
    let token = account
        .token
        .clone()
        .ok_or_else(|| "registrasi tidak mengembalikan token".to_string())?;

    // Langkah 2: kunci P-256 yang akan dipakai untuk mTLS tunnel.
    let (pkcs8, spki) = generate_masque_key(&rng)?;

    let body = serde_json::json!({
        "key": b64::encode(&spki),
        "key_type": "secp256r1",
        "tunnel_type": "masque",
    })
    .to_string();

    let text = https_json(
        "PATCH",
        &format!("/reg/{}", account.id),
        Some(&token),
        &body,
    )
    .await?;
    let enrolled: AccountData = serde_json::from_str(&text)
        .map_err(|e| format!("respons enrollment tidak bisa dibaca: {e}"))?;

    let peer = enrolled
        .config
        .peers
        .first()
        .ok_or_else(|| "Cloudflare tidak mengembalikan endpoint WARP".to_string())?;

    // API mengembalikan port 0 ("162.159.198.1:0"): artinya pakai 443.
    let endpoint_v4 = normalize_endpoint(&peer.endpoint.v4).unwrap_or_default();
    let endpoint_v6 = normalize_endpoint(&peer.endpoint.v6).unwrap_or_default();
    if endpoint_v4.is_empty() && endpoint_v6.is_empty() {
        return Err("endpoint WARP kosong di respons registrasi".to_string());
    }

    let config = Config {
        device_id: enrolled.id,
        token,
        private_key: b64::encode(pkcs8.as_ref()),
        peer_public_key: peer.public_key.clone(),
        endpoint_v4,
        endpoint_v6,
        ipv4: enrolled.config.interface.addresses.v4,
        ipv6: enrolled.config.interface.addresses.v6,
        sni: default_sni(),
        authority: default_authority(),
        registered_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        protected: false,
    };
    save(&config)?;
    Ok(config)
}

/// `"162.159.198.1:0"` → `"162.159.198.1:443"`, `"[2606::1]:0"` → `"[2606::1]:443"`.
fn normalize_endpoint(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let (host, port) = match raw.rsplit_once(':') {
        Some((host, port)) => (host, port.parse::<u16>().unwrap_or(0)),
        None => (raw, 0),
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let ip: IpAddr = host.parse().ok()?;
    Some(SocketAddr::new(ip, if port == 0 { 443 } else { port }).to_string())
}

fn random_bytes(rng: &ring::rand::SystemRandom, len: usize) -> Result<Vec<u8>, String> {
    let mut out = vec![0u8; len];
    ring::rand::SecureRandom::fill(rng, &mut out).map_err(|_| "RNG gagal".to_string())?;
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Buat pasangan kunci P-256 dan kembalikan (PKCS#8 DER, SPKI DER).
fn generate_masque_key(
    rng: &ring::rand::SystemRandom,
) -> Result<(ring::pkcs8::Document, Vec<u8>), String> {
    let algo = &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING;
    let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(algo, rng)
        .map_err(|_| "gagal membuat kunci P-256".to_string())?;
    let spki = spki_der(&ec_public_point(pkcs8.as_ref())?)?;
    Ok((pkcs8, spki))
}

/// `ring` tidak mengekspos public key dari `EcdsaKeyPair`, jadi titik P-256
/// diambil langsung dari PKCS#8: `PrivateKeyInfo` → OCTET STRING berisi
/// `ECPrivateKey` → `[1] publicKey BIT STRING`.
fn ec_public_point(pkcs8: &[u8]) -> Result<Vec<u8>, String> {
    let (tag, start, end, _) =
        der_tlv(pkcs8, 0).ok_or_else(|| "PKCS#8 tidak terbaca".to_string())?;
    if tag != 0x30 {
        return Err("PKCS#8 bukan SEQUENCE".to_string());
    }

    let ec_key = {
        let mut pos = start;
        let mut found = None;
        while pos < end {
            let (tag, field_start, field_end, next) =
                der_tlv(pkcs8, pos).ok_or_else(|| "PKCS#8 terpotong".to_string())?;
            if tag == 0x04 {
                found = Some(&pkcs8[field_start..field_end]);
                break;
            }
            pos = next;
        }
        found.ok_or_else(|| "PKCS#8 tidak berisi kunci privat EC".to_string())?
    };

    let (tag, start, end, _) =
        der_tlv(ec_key, 0).ok_or_else(|| "ECPrivateKey tidak terbaca".to_string())?;
    if tag != 0x30 {
        return Err("ECPrivateKey bukan SEQUENCE".to_string());
    }
    let mut pos = start;
    while pos < end {
        let (tag, field_start, field_end, next) =
            der_tlv(ec_key, pos).ok_or_else(|| "ECPrivateKey terpotong".to_string())?;
        if tag == 0x81 || tag == 0xA1 {
            let mut bits = &ec_key[field_start..field_end];
            if tag == 0xA1 {
                // Bentuk constructed: di dalamnya ada BIT STRING biasa.
                let (inner, inner_start, inner_end, _) =
                    der_tlv(bits, 0).ok_or_else(|| "publicKey EC tidak terbaca".to_string())?;
                if inner != 0x03 {
                    return Err("publicKey EC bukan BIT STRING".to_string());
                }
                bits = &bits[inner_start..inner_end];
            }
            if bits.len() != 66 || bits[0] != 0x00 {
                return Err("publicKey EC bukan titik P-256 tanpa kompresi".to_string());
            }
            return Ok(bits[1..].to_vec());
        }
        pos = next;
    }
    Err("PKCS#8 tidak memuat public key".to_string())
}

/// SPKI DER untuk P-256 publik tanpa kompresi (`0x04 || X || Y`).
fn spki_der(point: &[u8]) -> Result<Vec<u8>, String> {
    const PREFIX: [u8; 26] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08,
        0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    if point.len() != 65 || point[0] != 0x04 {
        return Err("public key P-256 tidak berbentuk titik tanpa kompresi".to_string());
    }
    let mut out = PREFIX.to_vec();
    out.extend_from_slice(point);
    Ok(out)
}

// ── HTTP kecil untuk API registrasi ─────────────────────────────────────

/// Permintaan HTTPS/1.1 sederhana ke API Cloudflare. Tidak memakai klien HTTP
/// penuh karena hanya dua endpoint yang dibutuhkan.
async fn https_json(
    method: &str,
    path: &str,
    auth: Option<&str>,
    body: &str,
) -> Result<String, String> {
    let addrs: Vec<_> = tokio::net::lookup_host((API_HOST, 443))
        .await
        .map_err(|e| format!("tidak bisa me-resolve {API_HOST}: {e}"))?
        .collect();
    let mut tcp = None;
    let mut last = format!("{API_HOST} tidak punya alamat");
    for addr in addrs {
        match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                tcp = Some(stream);
                break;
            }
            Ok(Err(e)) => last = format!("koneksi ke {addr} gagal: {e}"),
            Err(_) => last = format!("timeout koneksi ke {addr}"),
        }
    }
    let tcp = tcp.ok_or(last)?;

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];

    let name = ServerName::try_from(API_HOST.to_string())
        .map_err(|_| "nama server API tidak valid".to_string())?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls));
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(name, tcp))
        .await
        .map_err(|_| format!("timeout TLS ke {API_HOST}"))?
        .map_err(|e| format!("TLS ke {API_HOST} gagal: {e}"))?;

    let mut request = format!(
        "{method} /{API_VERSION}{path} HTTP/1.1\r\n\
         Host: {API_HOST}\r\n\
         User-Agent: WARP for Android\r\n\
         CF-Client-Version: {CLIENT_VERSION}\r\n\
         Content-Type: application/json; charset=UTF-8\r\n\
         Accept: application/json\r\n\
         Connection: close\r\n\
         Content-Length: {}\r\n",
        body.len()
    );
    if let Some(token) = auth {
        request.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(body);

    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("gagal mengirim permintaan: {e}"))?;
    stream.flush().await.ok();

    let mut raw = Vec::new();
    // Baca paling banyak satu byte lebih dari batas supaya respons kepanjangan
    // terdeteksi, bukan diam-diam terpotong.
    tokio::time::timeout(
        Duration::from_secs(15),
        (&mut stream)
            .take(MAX_API_BYTES as u64 + 1)
            .read_to_end(&mut raw),
    )
    .await
    .map_err(|_| "timeout menunggu respons API".to_string())?
    .map_err(|e| format!("gagal membaca respons API: {e}"))?;
    if raw.len() > MAX_API_BYTES {
        return Err("respons API melebihi batas".to_string());
    }

    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "respons API tidak punya header yang lengkap".to_string())?;
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let mut tail = raw[split + 4..].to_vec();

    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| "status HTTP tidak terbaca".to_string())?;

    if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        tail = dechunk(&tail)?;
    }

    let text = String::from_utf8_lossy(&tail).to_string();
    if !(200..300).contains(&status) {
        return Err(format!("API Cloudflare menolak (HTTP {status}): {text}"));
    }
    // Jawaban sukses harus JSON. Tanpa pemeriksaan ini, halaman captive portal
    // atau proxy TLS bisa lolos dan gagal jauh kemudian saat field dibaca.
    if !head
        .to_ascii_lowercase()
        .contains("content-type: application/json")
    {
        return Err(format!("respons API bukan JSON (HTTP {status})"));
    }
    Ok(text)
}

fn dechunk(raw: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < raw.len() {
        let line_end = raw[pos..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| "chunk tanpa akhir baris".to_string())?;
        let header_end = pos
            .checked_add(line_end)
            .ok_or_else(|| "header chunk meluap".to_string())?;
        let size_text = String::from_utf8_lossy(&raw[pos..header_end]);
        let size = usize::from_str_radix(size_text.trim(), 16)
            .map_err(|_| format!("ukuran chunk tidak valid: {size_text}"))?;
        pos = pos
            .checked_add(line_end)
            .and_then(|p| p.checked_add(2))
            .ok_or_else(|| "posisi chunk meluap".to_string())?;
        if size == 0 {
            break;
        }
        let end = pos
            .checked_add(size)
            .ok_or_else(|| "ukuran chunk meluap".to_string())?;
        out.extend_from_slice(&raw[pos..end.min(raw.len())]);
        pos = pos
            .checked_add(size)
            .and_then(|p| p.checked_add(2))
            .ok_or_else(|| "posisi chunk meluap".to_string())?;
    }
    Ok(out)
}

// ── TLS tunnel: mTLS + pinning ──────────────────────────────────────────

/// Verifier yang menerima sertifikat server hanya kalau SPKI-nya sama dengan
/// kunci yang tercatat saat registrasi. Endpoint WARP tidak punya nama host
/// publik, jadi rantai WebPKI tidak bisa dipakai dan pinning adalah pilihan
/// yang benar.
struct PinnedKey {
    expected: Vec<u8>,
    provider: rustls::crypto::CryptoProvider,
}

impl std::fmt::Debug for PinnedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PinnedKey")
    }
}

impl ServerCertVerifier for PinnedKey {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let got = cert_spki(end_entity.as_ref()).ok_or_else(|| {
            rustls::Error::General("sertifikat server WARP tidak bisa diparse".into())
        })?;
        if got != self.expected {
            return Err(rustls::Error::General(
                "public key endpoint WARP berbeda dari hasil registrasi".into(),
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Bangun konfigurasi TLS untuk tunnel: sertifikat klien self-signed dari kunci
/// yang sudah di-enroll, dan verifikasi server dengan pinning.
fn tunnel_tls(config: &Config) -> Result<rustls::ClientConfig, String> {
    let rng = ring::rand::SystemRandom::new();
    // Kunci privat plaintext dihapus dari memori saat fungsi keluar, termasuk
    // lewat jalur error.
    let pkcs8 = Zeroizing::new(b64::decode(&config.private_key)?);
    let algo = &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING;
    let pair = ring::signature::EcdsaKeyPair::from_pkcs8(algo, pkcs8.as_slice(), &rng)
        .map_err(|_| "kunci privat P-256 di warp.json tidak valid".to_string())?;
    let spki = spki_der(&ec_public_point(pkcs8.as_slice())?)?;
    let (cert, _) = self_signed_cert(&pair, &spki, "mydns", &rng)?;

    let expected = decode_spki(&config.peer_public_key)?;
    let provider = rustls::crypto::ring::default_provider();
    let verifier = Arc::new(PinnedKey {
        expected,
        provider: provider.clone(),
    });

    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("konfigurasi TLS: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(
            vec![CertificateDer::from(cert)],
            // `PrivatePkcs8KeyDer` butuh Vec owning; titik terakhir sebelum
            // kunci diserahkan ke rustls.
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.to_vec())),
        )
        .map_err(|e| format!("sertifikat klien tidak valid: {e}"))?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    Ok(tls)
}

/// API mengembalikan public key endpoint sebagai PEM; terima juga base64 polos
/// supaya berkas yang diedit tangan tetap bisa dipakai.
fn decode_spki(raw: &str) -> Result<Vec<u8>, String> {
    let body: String = raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("-----"))
        .collect();
    if body.is_empty() {
        return Err("public key endpoint WARP kosong".to_string());
    }
    b64::decode(&body)
}

/// Sertifikat X.509 v3 self-signed minimal (CN saja) yang ditandatangani
/// dengan kunci P-256 perangkat. Cloudflare memetakan identitas lewat public
/// key yang sudah di-enroll, bukan lewat nama di sertifikat.
fn self_signed_cert(
    key: &ring::signature::EcdsaKeyPair,
    spki: &[u8],
    common_name: &str,
    rng: &ring::rand::SystemRandom,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let serial = random_bytes(rng, 8)?;
    let alg = der_seq(&[&ECDSA_SHA256_OID]);
    let name = der_seq(&[&der(
        0x31,
        &der_seq(&[&COMMON_NAME_OID, &der(0x0C, common_name.as_bytes())]),
    )]);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let validity = der_seq(&[
        &der(0x17, utc_time(now.saturating_sub(86_400))?.as_bytes()),
        &der(0x17, utc_time(now + 10 * 365 * 86_400)?.as_bytes()),
    ]);

    let tbs = der_seq(&[
        &der(0xA0, &der(0x02, &[0x02])),
        &der_uint(&serial),
        &alg,
        &name,
        &validity,
        &name,
        spki,
    ]);

    let signature = key
        .sign(rng, &tbs)
        .map_err(|_| "gagal menandatangani sertifikat klien".to_string())?;
    let mut bit_string = Vec::with_capacity(signature.as_ref().len() + 1);
    bit_string.push(0x00);
    bit_string.extend_from_slice(signature.as_ref());

    let cert = der_seq(&[&tbs, &alg, &der(0x03, &bit_string)]);
    Ok((cert, spki.to_vec()))
}

const ECDSA_SHA256_OID: [u8; 10] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
const COMMON_NAME_OID: [u8; 5] = [0x06, 0x03, 0x55, 0x04, 0x03];

fn der_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let first = bytes
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(bytes.len() - 1);
        let significant = &bytes[first..];
        out.push(0x80 | significant.len() as u8);
        out.extend_from_slice(significant);
    }
}

fn der(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 4);
    out.push(tag);
    der_len(&mut out, body.len());
    out.extend_from_slice(body);
    out
}

fn der_seq(parts: &[&[u8]]) -> Vec<u8> {
    let mut body = Vec::new();
    for part in parts {
        body.extend_from_slice(part);
    }
    der(0x30, &body)
}

fn der_uint(bytes: &[u8]) -> Vec<u8> {
    let mut value = bytes;
    while value.len() > 1 && value[0] == 0 {
        value = &value[1..];
    }
    let mut body = Vec::with_capacity(value.len() + 1);
    if value.first().is_some_and(|b| b & 0x80 != 0) {
        body.push(0);
    }
    body.extend_from_slice(value);
    der(0x02, &body)
}

/// `(tag, awal_isidari_TLV, akhir_TLV, posisi_berikutnya)`.
fn der_tlv(buf: &[u8], pos: usize) -> Option<(u8, usize, usize, usize)> {
    let tag = *buf.get(pos)?;
    let first = *buf.get(pos + 1)?;
    let (len, header) = if first < 0x80 {
        (first as usize, 2)
    } else {
        let count = (first & 0x7F) as usize;
        if count == 0 || count > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..count {
            len = (len << 8) | *buf.get(pos + 2 + i)? as usize;
        }
        (len, 2 + count)
    };
    let start = pos + header;
    let end = start.checked_add(len)?;
    if end > buf.len() {
        return None;
    }
    Some((tag, start, end, end))
}

/// Ambil SPKI (SubjectPublicKeyInfo) utuh dari sertifikat DER.
fn cert_spki(cert: &[u8]) -> Option<Vec<u8>> {
    let (tag, start, _end, _) = der_tlv(cert, 0)?;
    if tag != 0x30 {
        return None;
    }
    let (inner_tag, inner_start, inner_end, _) = der_tlv(cert, start)?;
    if inner_tag != 0x30 {
        return None;
    }

    let mut fields: Vec<(u8, usize, usize)> = Vec::new();
    let mut pos = inner_start;
    while pos < inner_end {
        let (tag, field_start, field_end, next) = der_tlv(cert, pos)?;
        fields.push((tag, pos, next));
        let _ = (field_start, field_end);
        pos = next;
    }
    // v3 diawali [0] EXPLICIT version; SPKI ada di indeks 6, tanpa version di 5.
    let index = if fields.first().map(|f| f.0) == Some(0xA0) {
        6
    } else {
        5
    };
    let (_, start, end) = *fields.get(index)?;
    Some(cert[start..end].to_vec())
}

fn utc_time(secs: u64) -> Result<String, String> {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (year, month, day) = crate::log::civil_from_days(days);
    if !(1950..=2049).contains(&year) {
        return Err("tahun sertifikat di luar jangkauan UTCTime".to_string());
    }
    Ok(format!(
        "{:02}{:02}{:02}{:02}{:02}{:02}Z",
        year % 100,
        month,
        day,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    ))
}

fn timestamp_iso8601() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (year, month, day) = crate::log::civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.000+00:00",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

// ── tunnel MASQUE ───────────────────────────────────────────────────────

/// Satu koneksi CONNECT-IP yang membawa query DNS.
pub struct Tunnel {
    /// Endpoint QUIC harus tetap hidup selama koneksi dipakai.
    _endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    /// HTTP/3 tetap dipegang supaya SETTINGS dan kanal QPACK koneksi ini hidup.
    _h3: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    /// Quarter stream ID dari request CONNECT-IP, dipakai sebagai awalan setiap
    /// HTTP Datagram (RFC 9297).
    quarter: u64,
    src: Ipv4Addr,
    /// Port lokal → (ID transaksi DNS, penunggu jawaban).
    pending: Pending,
    next_port: AtomicU16,
    /// Penerima paket IP mentah, dipakai mode VPN penuh. Tanpa penerima,
    /// paket selain jawaban DNS dibuang seperti sebelumnya.
    raw: Arc<std::sync::Mutex<Option<mpsc::Sender<Vec<u8>>>>>,
}

impl Tunnel {
    pub async fn connect(config: &Config) -> Result<Arc<Self>, String> {
        let src = config.tunnel_ipv4()?;
        let endpoints = config.endpoints();
        if endpoints.is_empty() {
            return Err("warp.json tidak punya endpoint yang bisa dipakai".to_string());
        }

        let mut errors: Vec<String> = Vec::new();
        for addr in endpoints {
            match Self::connect_addr(config, addr).await {
                Ok((endpoint, conn, h3, quarter)) => {
                    let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
                    let raw = Arc::new(std::sync::Mutex::new(None));

                    spawn_reader(conn.clone(), Arc::clone(&pending), Arc::clone(&raw));

                    return Ok(Arc::new(Self {
                        _endpoint: endpoint,
                        conn,
                        _h3: h3,
                        quarter,
                        src,
                        pending,
                        next_port: AtomicU16::new(40_000),
                        raw,
                    }));
                }
                Err(e) => errors.push(format!("{addr}: {e}")),
            }
        }
        Err(format!(
            "tidak bisa membuka tunnel WARP — {}",
            errors.join("; ")
        ))
    }

    async fn connect_addr(
        config: &Config,
        addr: SocketAddr,
    ) -> Result<
        (
            quinn::Endpoint,
            quinn::Connection,
            h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
            u64,
        ),
        String,
    > {
        let tls = tunnel_tls(config)?;
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .map_err(|e| format!("konfigurasi QUIC: {e}"))?;

        let mut transport = quinn::TransportConfig::default();
        let idle: quinn::IdleTimeout = Duration::from_secs(30)
            .try_into()
            .map_err(|_| "idle timeout tidak valid".to_string())?;
        transport.max_idle_timeout(Some(idle));
        transport.keep_alive_interval(Some(Duration::from_secs(10)));
        // HTTP Datagram (RFC 9297) berjalan di atas QUIC DATAGRAM.
        transport.datagram_receive_buffer_size(Some(1 << 16));
        // MTU awal 1200 membuat datagram maksimum hanya ~1150 byte, sehingga
        // adapter TUN di mode VPN penuh jatuh di bawah 1200 — batas minimum
        // paket QUIC. Akibatnya QUIC di dalam tunnel (DoQ/DoH3) gagal dan
        // setiap query jatuh ke DoH2. 1472 memberi ruang MTU tunnel 1280;
        // penemuan MTU quinn tetap menurunkannya kalau jalurnya lebih kecil.
        transport.initial_mtu(1472);

        let mut quic = quinn::ClientConfig::new(Arc::new(crypto));
        quic.transport_config(Arc::new(transport));

        let bind = if addr.is_ipv6() {
            SocketAddr::from(([0u16; 8], 0))
        } else {
            SocketAddr::from(([0u8; 4], 0))
        };
        let mut endpoint =
            quinn::Endpoint::client(bind).map_err(|e| format!("socket QUIC: {e}"))?;
        endpoint.set_default_client_config(quic);

        let connecting = endpoint
            .connect(addr, &config.sni)
            .map_err(|e| format!("dial QUIC: {e}"))?;
        let conn = tokio::time::timeout(CONNECT_TIMEOUT, connecting)
            .await
            .map_err(|_| "timeout handshake QUIC".to_string())?
            .map_err(|e| format!("handshake QUIC: {e}"))?;

        let quic_conn = h3_quinn::Connection::new(conn.clone());
        let mut builder = h3::client::builder();
        builder.enable_datagram(true);
        builder.enable_extended_connect(true);
        let (mut driver, send) = builder
            .build::<_, _, Bytes>(quic_conn)
            .await
            .map_err(|e| format!("handshake HTTP/3: {e}"))?;

        // Driver wajib dipoll terus-menerus; tanpa ini koneksi HTTP/3 diam.
        tokio::spawn(async move {
            let _ = driver.wait_idle().await;
        });

        let quarter = open_connect_ip(&conn, &config.authority).await?;
        Ok((endpoint, conn, send, quarter))
    }

    /// Kirim satu query DNS lewat tunnel dan kembalikan jawabannya.
    pub async fn resolve(&self, query: &[u8]) -> Result<Vec<u8>, String> {
        if query.len() > TUNNEL_MTU - 28 {
            return Err("query lebih besar dari MTU tunnel".to_string());
        }

        let port = self.allocate_port().await;
        // ID transaksi ikut disimpan supaya jawaban terlambat dari query lama
        // tidak disalahserahkan ke query baru yang memakai port yang sama.
        let id = u16::from_be_bytes(
            *query
                .first_chunk::<2>()
                .ok_or_else(|| "query DNS terlalu pendek".to_string())?,
        );
        let packet = ipv4_udp_packet(self.src, TUNNEL_DNS, port, 53, query);

        let mut datagram = Vec::with_capacity(packet.len() + 2);
        put_varint(&mut datagram, self.quarter);
        put_varint(&mut datagram, 0); // context id CONNECT-IP
        datagram.extend_from_slice(&packet);

        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(port, (id, tx));

        if let Err(e) = self.conn.send_datagram(Bytes::from(datagram)) {
            self.pending.lock().await.remove(&port);
            return Err(format!("kirim datagram: {e}"));
        }

        match tokio::time::timeout(QUERY_TIMEOUT, rx).await {
            Ok(Ok(answer)) => Ok(answer),
            Ok(Err(_)) => Err("tunnel WARP tertutup sebelum menjawab".to_string()),
            Err(_) => {
                self.pending.lock().await.remove(&port);
                Err("timeout menunggu jawaban lewat WARP".to_string())
            }
        }
    }

    async fn allocate_port(&self) -> u16 {
        loop {
            let port = self.next_port.fetch_add(1, Ordering::Relaxed);
            let port = if port < 40_000 { 40_000 } else { port };
            if !self.pending.lock().await.contains_key(&port) {
                return port;
            }
        }
    }

    /// Ukuran datagram terbesar yang diterima QUIC. MTU adapter TUN harus lebih
    /// kecil dari ini setelah dikurangi awalan quarter-stream-id + context id.
    pub fn max_datagram(&self) -> usize {
        self.conn.max_datagram_size().unwrap_or(TUNNEL_MTU)
    }

    /// Alamat IP endpoint WARP (tanpa port), dipakai untuk host route supaya
    /// koneksi QUIC-nya tidak masuk ke tunnel sendiri.
    pub fn endpoint_ip(&self) -> Option<IpAddr> {
        Some(self.conn.remote_address().ip())
    }

    /// Paket IP mentah yang datang dari WARP dikirim ke sini (mode VPN penuh).
    pub fn set_raw_sink(&self, sink: mpsc::Sender<Vec<u8>>) {
        if let Ok(mut slot) = self.raw.lock() {
            *slot = Some(sink);
        }
    }

    /// Bungkus satu paket IP utuh sebagai HTTP Datagram CONNECT-IP.
    pub fn send_ip(&self, packet: &[u8]) -> Result<(), String> {
        if packet.len() + 8 > self.max_datagram() {
            return Err("paket lebih besar dari MTU tunnel".to_string());
        }
        let mut datagram = Vec::with_capacity(packet.len() + 8);
        put_varint(&mut datagram, self.quarter);
        put_varint(&mut datagram, 0); // context id CONNECT-IP
        datagram.extend_from_slice(packet);
        self.conn
            .send_datagram(Bytes::from(datagram))
            .map_err(|e| format!("kirim datagram: {e}"))
    }
}

/// Kirim request `CONNECT` dengan `:protocol: cf-connect-ip` lalu pastikan
/// server menjawab 200. Mengembalikan quarter stream ID untuk datagram.
///
/// `h3` 0.0.8 hanya mengenal `webtransport` dan `connect-udp` sebagai nilai
/// `:protocol`, sedangkan WARP memakai nama khusus Cloudflare `cf-connect-ip`.
/// Karena itu field section QPACK disusun sendiri (hanya tabel statis, tanpa
/// tabel dinamis) dan dikirim sebagai frame HEADERS pada stream bidi baru.
/// Koneksi, SETTINGS, dan kanal QPACK tetap dikelola `h3`.
async fn open_connect_ip(conn: &quinn::Connection, authority: &str) -> Result<u64, String> {
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| format!("buka stream CONNECT: {e}"))?;
    let quarter = send.id().index();

    let block = qpack_connect_block(authority);
    let mut frame = Vec::with_capacity(block.len() + 4);
    put_varint(&mut frame, 0x01); // frame HEADERS
    put_varint(&mut frame, block.len() as u64);
    frame.extend_from_slice(&block);
    send.write_all(&frame)
        .await
        .map_err(|e| format!("kirim CONNECT: {e}"))?;
    send.flush().await.ok();

    let mut buf: Vec<u8> = Vec::new();
    let deadline = tokio::time::Instant::now() + CONNECT_TIMEOUT;
    let status = loop {
        if let Some(code) = response_status(&buf) {
            break Some(code);
        }
        let mut chunk = [0u8; 2048];
        match tokio::time::timeout_at(deadline, recv.read(&mut chunk)).await {
            Ok(Ok(Some(n))) => buf.extend_from_slice(&chunk[..n]),
            Ok(Ok(None)) => break None,
            Ok(Err(e)) => return Err(format!("baca respons CONNECT: {e}")),
            Err(_) => break None,
        }
    };

    match status {
        Some(200) => {}
        Some(403) => {
            return Err(
                "ditolak Cloudflare (403) — perangkat belum di-enroll, coba `mydns warp register` lagi"
                    .to_string(),
            );
        }
        Some(code) => return Err(format!("WARP menolak CONNECT dengan HTTP {code}")),
        None => {
            return Err(format!(
                "respons CONNECT tidak terbaca ({} byte diterima)",
                buf.len()
            ));
        }
    }

    // Capsule kontrol (alamat/route) tidak dipakai — alamat tunnel sudah ada di
    // warp.json — tetapi stream tetap dibaca supaya flow control tidak macet.
    tokio::spawn(async move {
        let mut sink = [0u8; 2048];
        while let Ok(Some(_)) = recv.read(&mut sink).await {}
    });
    Ok(quarter)
}

/// QPACK statis untuk request CONNECT-IP. Indeks diambil dari RFC 9204
/// Lampiran A: 15 `:method CONNECT`, 23 `:scheme https`, 0 `:authority`,
/// 1 `:path /`.
fn qpack_connect_block(authority: &str) -> Vec<u8> {
    let mut block = vec![0x00, 0x00]; // Required Insert Count = 0, Delta Base = 0
    block.push(0xCF); // :method CONNECT (indeks statis 15)
    block.push(0xD7); // :scheme https   (indeks statis 23)
    block.push(0x50); // literal nama statis 0: :authority
    qpack_push_string(&mut block, authority);
    block.push(0xC1); // :path / (indeks statis 1)
    qpack_literal(&mut block, ":protocol", "cf-connect-ip");
    qpack_literal(&mut block, "capsule-protocol", "?1");
    qpack_literal(&mut block, "user-agent", "");
    block
}

/// Integer QPACK/H QPACK dengan prefiks N bit.
fn qpack_push_int(out: &mut Vec<u8>, mut value: u64, prefix_bits: u8, mask: u8) {
    let max = (1u64 << prefix_bits) - 1;
    if value < max {
        out.push(mask | value as u8);
        return;
    }
    out.push(mask | max as u8);
    value -= max;
    while value >= 0x80 {
        out.push((value as u8 & 0x7F) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn qpack_push_string(out: &mut Vec<u8>, value: &str) {
    // H = 0: string tidak di-Huffman.
    qpack_push_int(out, value.len() as u64, 7, 0x00);
    out.extend_from_slice(value.as_bytes());
}

/// Field line "literal dengan nama literal" (001) lalu pasangan nama/nilai.
fn qpack_literal(out: &mut Vec<u8>, name: &str, value: &str) {
    qpack_push_int(out, name.len() as u64, 3, 0x20);
    out.extend_from_slice(name.as_bytes());
    qpack_push_string(out, value);
}

fn quic_int(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let (value, rest) = get_varint(buf.get(*pos..)?)?;
    *pos = buf.len() - rest.len();
    Some(value)
}

fn qpack_int(buf: &[u8], pos: &mut usize, prefix_bits: u8) -> Option<u64> {
    let first = *buf.get(*pos)?;
    let max = (1u64 << prefix_bits) - 1;
    let mut value = (first as u64) & max;
    *pos += 1;
    if value < max {
        return Some(value);
    }
    let mut shift = 0;
    loop {
        let byte = *buf.get(*pos)?;
        *pos += 1;
        value += ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
        if shift > 56 {
            return None;
        }
    }
}

fn qpack_string(buf: &[u8], pos: &mut usize) -> Option<Option<String>> {
    let first = *buf.get(*pos)?;
    let huffman = first & 0x80 != 0;
    let len = qpack_int(buf, pos, 7)? as usize;
    if buf.len() < *pos + len {
        return None;
    }
    let bytes = &buf[*pos..*pos + len];
    *pos += len;
    if huffman {
        Some(None)
    } else {
        Some(Some(String::from_utf8_lossy(bytes).to_string()))
    }
}

/// Status HTTP dari frame HEADERS pada respons CONNECT-IP.
///
/// Cloudflare menyisipkan blok "grease" acak (~17 byte) sebelum frame
/// pertamanya, jadi setiap offset dicoba sampai ada blok QPACK yang benar-benar
/// berisi `:status`. Selain itu data frame lain dilewati berdasarkan panjangnya.
fn response_status(buf: &[u8]) -> Option<u16> {
    for start in 0..buf.len() {
        if let Some(code) = status_at(buf, start) {
            return Some(code);
        }
    }
    None
}

fn status_at(buf: &[u8], start: usize) -> Option<u16> {
    let mut pos = start;
    loop {
        // Tipe dan panjang frame HTTP/3 memakai QUIC varint, bukan integer
        // berprefiks gaya QPACK yang dipakai di dalam field section.
        let kind = quic_int(buf, &mut pos)?;
        let len = quic_int(buf, &mut pos)? as usize;
        if buf.len() < pos.checked_add(len)? {
            return None; // frame belum lengkap
        }
        let payload = &buf[pos..pos + len];
        pos += len;
        if kind == 0x01 {
            return qpack_status(payload);
        }
    }
}

fn qpack_status(payload: &[u8]) -> Option<u16> {
    let mut pos = 0;
    qpack_int(payload, &mut pos, 8)?; // Required Insert Count
    qpack_int(payload, &mut pos, 7)?; // Delta Base (bit tanda diabaikan)

    while pos < payload.len() {
        let first = payload[pos];
        if first & 0x80 != 0 {
            // Indexed field line.
            let statis = first & 0x40 != 0;
            let index = qpack_int(payload, &mut pos, 6)?;
            if statis && let Some(code) = static_status(index) {
                return Some(code);
            }
        } else if first & 0xC0 == 0x40 {
            // Literal dengan referensi nama.
            let statis = first & 0x10 != 0;
            let index = qpack_int(payload, &mut pos, 4)?;
            let value = qpack_string(payload, &mut pos)?;
            if statis
                && index == 24
                && let Some(text) = value
            {
                return text.trim().parse::<u16>().ok();
            }
        } else if first & 0xE0 == 0x20 {
            // Literal dengan nama literal.
            let name = qpack_string(payload, &mut pos)?;
            let value = qpack_string(payload, &mut pos)?;
            if name.as_deref() == Some(":status")
                && let Some(text) = value
            {
                return text.trim().parse::<u16>().ok();
            }
        } else {
            // Post-base / bentuk lain: menyerah, biarkan query yang menentukan.
            return None;
        }
    }
    None
}

/// Indeks statis RFC 9204 untuk `:status`.
fn static_status(index: u64) -> Option<u16> {
    match index {
        25 => Some(200),
        26 => Some(204),
        27 => Some(206),
        28 => Some(304),
        29 => Some(400),
        30 => Some(404),
        31 => Some(500),
        _ => None,
    }
}

/// Baca datagram masuk: jawaban DNS diberikan ke penunggunya, paket lain
/// (mode VPN penuh) diteruskan ke adapter TUN lewat `raw`.
fn spawn_reader(
    conn: quinn::Connection,
    pending: Pending,
    raw: Arc<std::sync::Mutex<Option<mpsc::Sender<Vec<u8>>>>>,
) {
    tokio::spawn(async move {
        loop {
            let datagram = match conn.read_datagram().await {
                Ok(datagram) => datagram,
                Err(_) => break,
            };
            let Some((_, rest)) = get_varint(&datagram) else {
                continue;
            };
            let Some((_, packet)) = get_varint(rest) else {
                continue;
            };
            if let Some((port, dns)) = udp_to_port(packet, 53) {
                let mut map = pending.lock().await;
                let expected = map.get(&port).map(|(id, _)| *id);
                let cocok = expected.is_some_and(|id| {
                    dns.first_chunk::<2>()
                        .is_some_and(|got| u16::from_be_bytes(*got) == id)
                });
                if cocok && let Some((_, tx)) = map.remove(&port) {
                    let _ = tx.send(dns.to_vec());
                    continue;
                }
                // Jawaban yang tidak cocok (mis. terlambat) jatuh ke TUN seperti
                // paket UDP lainnya, dan tidak menimpa penunggu port tersebut.
            }
            // Paket IPv4 dan IPv6 ditulis ke adapter TUN. Rute v6 hanya ada
            // kalau WARP memberi alamat v6, jadi paket v6 tanpa rute tidak akan
            // sampai ke sini.
            if packet.len() >= 20
                && (packet[0] >> 4 == 4 || (packet[0] >> 4 == 6 && packet.len() >= 40))
                && let Ok(slot) = raw.lock()
                && let Some(sink) = slot.as_ref()
            {
                // Channel terbatas: paket dibuang saat konsumen Wintun tertinggal.
                // UDP memang boleh loss; TCP di ujung sana akan retransmisi.
                let _ = sink.try_send(packet.to_vec());
            }
        }
    });
}

// ── paket IP/UDP dan varint ─────────────────────────────────────────────

/// Bungkus payload DNS dalam paket IPv4 + UDP.
fn ipv4_udp_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total = 20 + 8 + payload.len();
    let mut packet = vec![0u8; total];

    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
    packet[8] = 64;
    packet[9] = 17; // UDP
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());

    let header_checksum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());

    let udp_len = (8 + payload.len()) as u16;
    packet[20..22].copy_from_slice(&sport.to_be_bytes());
    packet[22..24].copy_from_slice(&dport.to_be_bytes());
    packet[24..26].copy_from_slice(&udp_len.to_be_bytes());
    packet[28..].copy_from_slice(payload);

    // Checksum UDP wajib benar untuk IPv4 di banyak stack; pseudo-header
    // berisi alamat sumber/tujuan, protokol, dan panjang UDP.
    let mut pseudo = Vec::with_capacity(12 + 8 + payload.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(17);
    pseudo.extend_from_slice(&udp_len.to_be_bytes());
    pseudo.extend_from_slice(&packet[20..20 + udp_len as usize]);
    let udp_checksum = match checksum(&pseudo) {
        0 => 0xFFFF,
        value => value,
    };
    packet[26..28].copy_from_slice(&udp_checksum.to_be_bytes());

    packet
}

/// Ambil payload UDP dari paket IPv4 yang datang dari port sumber tertentu.
/// Nilai yang dikembalikan adalah port **tujuan** (port lokal kita), dipakai
/// untuk mencocokkan jawaban dengan query yang menunggu.
fn udp_to_port(packet: &[u8], expect_src: u16) -> Option<(u16, &[u8])> {
    if packet.len() < 28 || packet[0] >> 4 != 4 {
        return None;
    }
    let header_len = ((packet[0] & 0x0F) as usize) * 4;
    if header_len < 20 || packet.len() < header_len + 8 {
        return None;
    }
    if packet[9] != 17 {
        return None;
    }
    // Fragmen tidak didukung: DNS lewat WARP selalu satu datagram utuh.
    if u16::from_be_bytes([packet[6], packet[7]]) & 0x3FFF != 0 {
        return None;
    }

    let src = u16::from_be_bytes([packet[header_len], packet[header_len + 1]]);
    let dst = u16::from_be_bytes([packet[header_len + 2], packet[header_len + 3]]);
    let len = u16::from_be_bytes([packet[header_len + 4], packet[header_len + 5]]) as usize;
    if src != expect_src || len < 8 || header_len + len > packet.len() {
        return None;
    }
    Some((dst, &packet[header_len + 8..header_len + len]))
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let (chunks, remainder) = data.as_chunks::<2>();
    for chunk in chunks {
        sum += u16::from_be_bytes(*chunk) as u32;
    }
    if let [last] = remainder {
        sum += (*last as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn put_varint(out: &mut Vec<u8>, value: u64) {
    if value < 0x40 {
        out.push(value as u8);
    } else if value < 0x4000 {
        out.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
    } else if value < 0x4000_0000 {
        out.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(value | 0xC000_0000_0000_0000).to_be_bytes());
    }
}

fn get_varint(buf: &[u8]) -> Option<(u64, &[u8])> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mut value = (first & 0x3F) as u64;
    for byte in &buf[1..len] {
        value = (value << 8) | *byte as u64;
    }
    Some((value, &buf[len..]))
}

// ── base64 ──────────────────────────────────────────────────────────────

mod b64 {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub fn encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
        for chunk in bytes.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            out.push(ALPHABET[(n >> 18) as usize & 63] as char);
            out.push(ALPHABET[(n >> 12) as usize & 63] as char);
            out.push(if chunk.len() > 1 {
                ALPHABET[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                ALPHABET[n as usize & 63] as char
            } else {
                '='
            });
        }
        out
    }

    pub fn decode(text: &str) -> Result<Vec<u8>, String> {
        let mut out = Vec::with_capacity(text.len() / 4 * 3);
        let mut acc = 0u32;
        let mut bits = 0u32;
        for ch in text.bytes() {
            let value = match ch {
                b'A'..=b'Z' => ch - b'A',
                b'a'..=b'z' => ch - b'a' + 26,
                b'0'..=b'9' => ch - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' | b'\r' | b'\n' | b' ' | b'\t' => continue,
                other => return Err(format!("karakter base64 tidak valid: {}", other as char)),
            } as u32;
            acc = (acc << 6) | value;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_bolak_balik() {
        for sample in [
            &b""[..],
            b"a",
            b"ab",
            b"abc",
            b"hello world",
            &[0, 255, 128, 1],
        ] {
            assert_eq!(b64::decode(&b64::encode(sample)).unwrap(), sample);
        }
    }

    #[test]
    fn dechunk_menolak_ukuran_meluap() {
        let raw = format!("{:x}\r\nx", usize::MAX);
        assert!(dechunk(raw.as_bytes()).is_err());
    }

    #[test]
    fn varint_menyandikan_semua_ukuran() {
        for value in [0u64, 63, 64, 16_383, 16_384, 1_073_741_823, 1_073_741_824] {
            let mut buf = Vec::new();
            put_varint(&mut buf, value);
            let (decoded, rest) = get_varint(&buf).unwrap();
            assert_eq!(decoded, value);
            assert!(rest.is_empty());
        }
    }

    #[test]
    fn paket_udp_putar_balik() {
        let payload = b"\x12\x34 pertanyaan dns";
        // Arah jawaban: dari 1.1.1.1:53 ke port lokal kita.
        let packet = ipv4_udp_packet(
            TUNNEL_DNS,
            Ipv4Addr::new(100, 96, 0, 2),
            53,
            40_000,
            payload,
        );
        assert_eq!(packet[0], 0x45);
        assert_eq!(packet[9], 17);
        let (port, got) = udp_to_port(&packet, 53).unwrap();
        assert_eq!(port, 40_000);
        assert_eq!(got, payload);
    }

    #[test]
    fn checksum_header_dan_udp_benar() {
        // Header IPv4 dengan checksum yang benar harus menghasilkan 0 saat
        // dijumlahkan ulang (properti ones' complement).
        let packet = ipv4_udp_packet(Ipv4Addr::new(100, 96, 0, 2), TUNNEL_DNS, 1234, 53, b"x");
        let header_sum = checksum(&packet[..20]);
        assert_eq!(header_sum, 0);
    }

    #[test]
    fn udp_to_port_menolak_paket_lain() {
        let packet = ipv4_udp_packet(Ipv4Addr::new(100, 96, 0, 2), TUNNEL_DNS, 1234, 53, b"x");
        assert!(udp_to_port(&packet, 9999).is_none());
        assert!(udp_to_port(&[0u8; 10], 53).is_none());
    }

    #[test]
    fn endpoint_port_nol_menjadi_443() {
        assert_eq!(
            normalize_endpoint("162.159.198.1:0").unwrap(),
            "162.159.198.1:443"
        );
        assert_eq!(
            normalize_endpoint("[2606:4700:103::]:0").unwrap(),
            "[2606:4700:103::]:443"
        );
        assert_eq!(normalize_endpoint("").map(|v| v.is_empty()), None);
    }

    #[test]
    fn kunci_privat_bolak_balik_lewat_dpapi() {
        let plain = "kunci-privat-uji-123";
        let protected = protect_secret(plain).unwrap();
        assert_ne!(protected, b64::encode(plain.as_bytes()));
        assert_eq!(unprotect_secret(&protected).unwrap(), plain);
    }

    #[test]
    fn public_key_pem_dan_base64_sama_saja() {
        let raw = [0u8; 91];
        let plain = b64::encode(&raw);
        let pem = format!("-----BEGIN PUBLIC KEY-----\n{plain}\n-----END PUBLIC KEY-----\n");
        assert_eq!(decode_spki(&pem).unwrap(), raw.to_vec());
        assert_eq!(decode_spki(&plain).unwrap(), raw.to_vec());
    }

    #[test]
    fn spki_menempel_pada_titik_p256() {
        let point = [0x04u8; 65];
        let spki = spki_der(&point).unwrap();
        assert_eq!(spki.len(), 91);
        assert_eq!(&spki[..4], &[0x30, 0x59, 0x30, 0x13]);
    }

    #[test]
    fn sertifikat_bisa_dibaca_kembali() {
        let rng = ring::rand::SystemRandom::new();
        let (pkcs8, spki) = generate_masque_key(&rng).unwrap();
        let algo = &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING;
        let pair = ring::signature::EcdsaKeyPair::from_pkcs8(algo, pkcs8.as_ref(), &rng).unwrap();
        assert_eq!(
            spki_der(&ec_public_point(pkcs8.as_ref()).unwrap()).unwrap(),
            spki
        );
        let (cert, _) = self_signed_cert(&pair, &spki, "mydns", &rng).unwrap();
        assert_eq!(cert_spki(&cert).unwrap(), spki);
    }
}
