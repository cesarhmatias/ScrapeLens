//! Self-signed **test CA** and leaf certificate generation/loading.
//!
//! These files are for the local reference servers only. Nothing here touches
//! the system keychain: a browser is expected to pin the leaf SPKI with
//! `--ignore-certificate-errors-spki-list` (see `spki-sha256-base64.txt`), and
//! CLI clients trust the explicit CA file (`scrapelens-test-ca.crt.pem`).
//!
//! Layout in `fixtures/tls/`:
//! * `scrapelens-test-ca.crt.pem`            — test-only CA (trust anchor)
//! * `scrapelens-test-ca.key.pem`            — CA key (test-only!)
//! * `scrapelens-test-localhost.crt.pem`     — leaf for localhost/127.0.0.1/::1
//! * `scrapelens-test-localhost.crt.der`     — same leaf, DER
//! * `scrapelens-test-localhost.key.pem`     — leaf key
//! * `spki-sha256-base64.txt`                — pin for the leaf SPKI
//! * `README.txt`

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine as _;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};
use sha2::{Digest, Sha256};

pub const CERT_PEM: &str = "scrapelens-test-localhost.crt.pem";
pub const KEY_PEM: &str = "scrapelens-test-localhost.key.pem";
pub const CERT_DER: &str = "scrapelens-test-localhost.crt.der";
pub const CA_PEM: &str = "scrapelens-test-ca.crt.pem";
pub const CA_KEY_PEM: &str = "scrapelens-test-ca.key.pem";
pub const SPKI_TXT: &str = "spki-sha256-base64.txt";

#[derive(Debug, Clone)]
pub struct TlsFiles {
    pub dir: PathBuf,
    pub cert_pem: PathBuf,
    pub key_pem: PathBuf,
    pub cert_der: PathBuf,
    pub ca_pem: PathBuf,
    pub ca_key_pem: PathBuf,
    /// base64(sha256(leaf SubjectPublicKeyInfo)) — Chrome pin.
    pub spki_sha256_b64: String,
}

impl TlsFiles {
    pub fn summary(&self) -> String {
        format!(
            "cert={}\nkey={}\nca={}\nspki_sha256_b64={}",
            self.cert_pem.display(),
            self.key_pem.display(),
            self.ca_pem.display(),
            self.spki_sha256_b64
        )
    }
}

/// Returns the certificate files, generating them when absent.
pub fn ensure(dir: &Path, force: bool) -> Result<TlsFiles, Box<dyn std::error::Error>> {
    fs::create_dir_all(dir)?;
    let cert_pem = dir.join(CERT_PEM);
    let key_pem = dir.join(KEY_PEM);
    let cert_der = dir.join(CERT_DER);
    let ca_pem = dir.join(CA_PEM);
    let ca_key_pem = dir.join(CA_KEY_PEM);
    let spki_txt = dir.join(SPKI_TXT);

    if force || !cert_pem.exists() || !key_pem.exists() || !ca_pem.exists() || !spki_txt.exists() {
        generate(dir)?;
    }

    let spki = fs::read_to_string(&spki_txt)?
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .unwrap_or_default()
        .to_string();
    Ok(TlsFiles {
        dir: dir.to_path_buf(),
        cert_pem,
        key_pem,
        cert_der,
        ca_pem,
        ca_key_pem,
        spki_sha256_b64: spki,
    })
}

/// Test-time certificates: generated once per test process in the system temp folder,
/// never in the repository. Used by the integration tests instead of `fixtures/tls/`.
pub fn test_tls() -> TlsFiles {
    static TLS: std::sync::OnceLock<TlsFiles> = std::sync::OnceLock::new();
    TLS.get_or_init(|| {
        init_crypto();
        let dir = std::env::temp_dir().join(format!("scrapelens-testserver-tls-{}", std::process::id()));
        ensure(&dir, false).expect("test certificate")
    })
    .clone()
}

fn generate(dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    // --- test CA -----------------------------------------------------------
    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "ScrapeLens local test CA (synthetic)");
    ca_params.distinguished_name.push(
        DnType::OrganizationName,
        "ScrapeLens test fixtures — not for production",
    );
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    ca_params.not_before = rcgen::date_time_ymd(2026, 1, 1);
    ca_params.not_after = rcgen::date_time_ymd(2036, 1, 1);
    let ca_cert = ca_params.self_signed(&ca_key)?;

    // --- leaf for the local servers ---------------------------------------
    let leaf_key = KeyPair::generate()?;
    let mut params =
        CertificateParams::new(vec!["localhost".to_string(), "scrapelens.test".to_string()])?;
    params
        .distinguished_name
        .push(DnType::CommonName, "ScrapeLens local test server");
    params.distinguished_name.push(
        DnType::OrganizationName,
        "ScrapeLens test fixtures — not for production",
    );
    params
        .subject_alt_names
        .push(SanType::IpAddress("127.0.0.1".parse()?));
    params
        .subject_alt_names
        .push(SanType::IpAddress("::1".parse()?));
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.not_before = rcgen::date_time_ymd(2026, 1, 1);
    params.not_after = rcgen::date_time_ymd(2036, 1, 1);

    let issuer = Issuer::from_params(&ca_params, &ca_key);
    let leaf = params.signed_by(&leaf_key, &issuer)?;

    fs::write(dir.join(CA_PEM), ca_cert.pem())?;
    fs::write(dir.join(CA_KEY_PEM), ca_key.serialize_pem())?;
    fs::write(dir.join(CERT_PEM), leaf.pem())?;
    fs::write(dir.join(KEY_PEM), leaf_key.serialize_pem())?;
    fs::write(dir.join(CERT_DER), leaf.der())?;

    let spki_der = pem_body(&leaf_key.public_key_pem())?;
    let hash = Sha256::digest(&spki_der);
    let b64 = base64::engine::general_purpose::STANDARD.encode(hash);
    fs::write(
        dir.join(SPKI_TXT),
        format!(
            "{b64}\n# base64(sha256(SubjectPublicKeyInfo DER)) of the leaf cert {CERT_PEM}\n# use: --ignore-certificate-errors-spki-list={b64}\n",
        ),
    )?;
    fs::write(
        dir.join("README.txt"),
        "Synthetic local test PKI for the ScrapeLens reference test servers.\n\
         \n\
         Files:\n\
         \x20 scrapelens-test-ca.crt.pem         test-only CA (trust anchor for CLI clients)\n\
         \x20 scrapelens-test-ca.key.pem         test-only CA key (never use outside this repo)\n\
         \x20 scrapelens-test-localhost.crt.pem  leaf for localhost, 127.0.0.1, ::1\n\
         \x20 scrapelens-test-localhost.key.pem  leaf key\n\
         \x20 scrapelens-test-localhost.crt.der  leaf DER\n\
         \x20 spki-sha256-base64.txt             Chrome SPKI pin for the leaf\n\
         \n\
         Use:\n\
         \x20 curl --cacert scrapelens-test-ca.crt.pem https://127.0.0.1:8782/...\n\
         \x20 Chrome: --ignore-certificate-errors-spki-list=<pin from spki-sha256-base64.txt>\n\
         \n\
         Do NOT install the CA in the system keychain. The CA is valid 2026-01-01..2036-01-01\n\
         and exists only so the servers can be trusted explicitly by the test harness.\n\
         Regenerate (new keys, new pin):\n\
         \x20 cargo run -p scrapelens-testserver -- gen-cert --force\n",
    )?;
    Ok(())
}

fn pem_body(pem: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    Ok(base64::engine::general_purpose::STANDARD.decode(body.trim())?)
}

/// rustls server config for h2 with ALPN `h2` only; the same leaf cert serves
/// h3 (quiche reads the PEM files directly).
pub fn rustls_server_config(
    files: &TlsFiles,
) -> Result<Arc<rustls::ServerConfig>, Box<dyn std::error::Error>> {
    let mut cert_reader = std::io::BufReader::new(fs::File::open(&files.cert_pem)?);
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_reader).collect::<Result<_, _>>()?;
    let mut key_reader = std::io::BufReader::new(fs::File::open(&files.key_pem)?);
    let key = rustls_pemfile::private_key(&mut key_reader)?.ok_or("no private key in key PEM")?;

    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(Arc::new(config))
}

/// rustls client config for the h2 test client (trusts the fixture CA only).
pub fn rustls_client_config(
    files: &TlsFiles,
) -> Result<Arc<rustls::ClientConfig>, Box<dyn std::error::Error>> {
    let mut roots = rustls::RootCertStore::empty();
    let mut reader = std::io::BufReader::new(fs::File::open(&files.ca_pem)?);
    for cert in rustls_pemfile::certs(&mut reader) {
        roots.add(cert?)?;
    }
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(Arc::new(config))
}

/// Install the process-wide crypto provider exactly once (ring backend).
pub fn init_crypto() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}
