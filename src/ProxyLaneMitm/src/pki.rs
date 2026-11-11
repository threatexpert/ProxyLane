use base64::{engine::general_purpose::STANDARD, Engine};
use fs2::FileExt;
use rcgen::*;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    sign::CertifiedKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};
use time::OffsetDateTime;
use zeroize::Zeroizing;

pub type Result<T> = std::result::Result<T, String>;
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

#[derive(Serialize, Deserialize)]
struct Stored {
    certificate: String,
    protected_key: String,
    crl_port: u16,
}

pub struct Authority {
    pub directory: PathBuf,
    pub der: CertificateDer<'static>,
    pub id: String,
    /// Persisted preference only. Never advertise it before a successful bind.
    pub port: u16,
    issuer: Certificate,
    key: KeyPair,
    leaves: Mutex<VecDeque<CachedLeaf>>,
}

struct CachedLeaf {
    name: String,
    port: u16,
    expires: OffsetDateTime,
    cert: Arc<CertifiedKey>,
}

/// Owned by the process TLS Context, not by the monitor or enable checkbox.
pub struct CrlServer {
    port: u16,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}
impl CrlServer {
    pub fn port(&self) -> u16 {
        self.port
    }
}
impl Drop for CrlServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

pub fn directory() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("PROXYLANE_MITM_HOME") {
        return Ok(PathBuf::from(path));
    }
    let directory =
        PathBuf::from(std::env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA is missing")?)
            .join("ProxyLane");
    migrate_legacy(&directory)?;
    Ok(directory)
}

// Preserve the existing CA identity/trust when upgrading the default location.
// Explicit PROXYLANE_MITM_HOME directories never participate in migration.
pub(crate) fn migrate_legacy(directory: &Path) -> Result<()> {
    let legacy = directory.join("mitm");
    if directory.join("ca.json").exists() || !legacy.join("ca.json").exists() {
        return Ok(());
    }
    let lock = |path: &Path| -> Result<File> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path.join("ca.lock"))
            .map_err(err)?;
        file.lock_exclusive().map_err(err)?;
        Ok(file)
    };
    let _new_lock = lock(directory)?;
    let _old_lock = lock(&legacy)?;
    if !directory.join("ca.json").exists() && legacy.join("ca.json").exists() {
        // Same volume, atomic move: failures must never silently generate another CA.
        fs::rename(legacy.join("ca.json"), directory.join("ca.json")).map_err(err)?;
    }
    // The public certificate is exported again by Authority::load from ca.json.
    Ok(())
}

fn serial() -> Result<SerialNumber> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(err)?;
    bytes[0] &= 0x7f;
    Ok(SerialNumber::from_slice(&bytes))
}

impl Authority {
    pub fn load(directory: &Path, create: bool) -> Result<Self> {
        if create {
            fs::create_dir_all(directory).map_err(err)?;
        }
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(directory.join("ca.lock"))
            .map_err(err)?;
        lock.lock_exclusive().map_err(err)?;
        let path = directory.join("ca.json");
        if !path.exists() {
            if !create {
                return Err("CA not initialized; run proxylane-mitm init".into());
            }
            let key = KeyPair::generate().map_err(err)?;
            let mut p = CertificateParams::default();
            p.distinguished_name
                .push(DnType::CommonName, "ProxyLane CA");
            p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
            p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            p.serial_number = Some(serial()?);
            p.not_before = OffsetDateTime::now_utc() - time::Duration::days(1);
            p.not_after = OffsetDateTime::now_utc() + time::Duration::days(3650);
            let cert = p.self_signed(&key).map_err(err)?;
            let private = Zeroizing::new(key.serialize_der());
            let port = std::env::var("PROXYLANE_MITM_CRL_PORT")
                .unwrap_or_else(|_| "18767".into())
                .parse::<u16>()
                .map_err(err)?;
            if port == 0 {
                return Err("Preferred CRL port must be nonzero".into());
            }
            let stored = Stored {
                certificate: STANDARD.encode(cert.der()),
                protected_key: STANDARD.encode(crate::windows::protect(&private, false)?),
                crl_port: port,
            };
            let temp = directory.join("ca.json.new");
            let mut output = File::create(&temp).map_err(err)?;
            output
                .write_all(&serde_json::to_vec(&stored).map_err(err)?)
                .map_err(err)?;
            output.sync_all().map_err(err)?;
            drop(output);
            fs::rename(temp, &path).map_err(err)?;
        }
        let stored: Stored = serde_json::from_slice(&fs::read(path).map_err(err)?).map_err(err)?;
        let der: CertificateDer<'static> = STANDARD.decode(stored.certificate).map_err(err)?.into();
        let private = Zeroizing::new(crate::windows::protect(
            &STANDARD.decode(stored.protected_key).map_err(err)?,
            true,
        )?);
        let key = KeyPair::try_from(private.as_slice()).map_err(err)?;
        let params = CertificateParams::from_ca_cert_der(&der).map_err(err)?;
        if params.not_after <= OffsetDateTime::now_utc() + time::Duration::days(1) {
            return Err("CA expired or expires within one day".into());
        }
        let issuer = params.self_signed(&key).map_err(err)?;
        // A re-sign has different ECDSA signature bytes. Always export/trust the ORIGINAL DER.
        let id = format!("{:x}", Sha256::digest(&der));
        fs::write(directory.join("proxylane-ca.cer"), &der).map_err(err)?;
        Ok(Self {
            directory: directory.into(),
            der,
            id,
            port: stored.crl_port,
            issuer,
            key,
            leaves: Mutex::new(VecDeque::new()),
        })
    }

    pub fn leaf(&self, name: &str, crl_port: u16) -> Result<Arc<CertifiedKey>> {
        if crl_port == 0 {
            return Err("CRL listener must be bound before issuing a certificate".into());
        }
        let name = name.to_ascii_lowercase();
        let now = OffsetDateTime::now_utc();
        let mut cache = self.leaves.lock().map_err(err)?;
        cache.retain(|entry| entry.expires > now + time::Duration::minutes(5));
        if let Some(entry) = cache
            .iter()
            .find(|entry| entry.name == name && entry.port == crl_port)
        {
            return Ok(entry.cert.clone());
        }
        let key = KeyPair::generate().map_err(err)?;
        let mut p = CertificateParams::new(vec![name.clone()]).map_err(err)?;
        p.distinguished_name.push(DnType::CommonName, name.clone());
        // rcgen 0.13 ExplicitNoCa encodes the DEFAULT FALSE boolean explicitly,
        // which strict DER readers reject. Empty SEQUENCE means the same CA=false.
        p.is_ca = IsCa::NoCa;
        let mut constraints = CustomExtension::from_oid_content(&[2, 5, 29, 19], vec![0x30, 0x00]);
        constraints.set_criticality(true);
        p.custom_extensions.push(constraints);
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        p.use_authority_key_identifier_extension = true;
        p.serial_number = Some(serial()?);
        p.not_before = now - time::Duration::minutes(5);
        let expiry = (now + time::Duration::days(14)).min(self.issuer.params().not_after);
        p.not_after = expiry;
        p.crl_distribution_points = vec![CrlDistributionPoint {
            uris: vec![format!("http://127.0.0.1:{}/pki/{}.crl", crl_port, self.id)],
        }];
        let cert = p.signed_by(&key, &self.issuer, &self.key).map_err(err)?;
        let private = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let certified = Arc::new(
            CertifiedKey::from_der(
                vec![cert.der().clone()],
                private,
                &rustls::crypto::ring::default_provider(),
            )
            .map_err(err)?,
        );
        if cache.len() >= 256 {
            cache.pop_front();
        }
        cache.push_back(CachedLeaf {
            name,
            port: crl_port,
            expires: expiry,
            cert: certified.clone(),
        });
        Ok(certified)
    }

    pub fn crl(&self) -> Result<Vec<u8>> {
        let now = OffsetDateTime::now_utc();
        // The prototype has no per-leaf revocation operation; removing trust revokes the CA.
        let crl = CertificateRevocationListParams {
            this_update: now - time::Duration::minutes(5),
            next_update: now + time::Duration::days(1),
            crl_number: (now.unix_timestamp() as u64).into(),
            issuing_distribution_point: None,
            revoked_certs: vec![],
            key_identifier_method: KeyIdMethod::Sha256,
        }
        .signed_by(&self.issuer, &self.key)
        .map_err(err)?;
        Ok(crl.der().to_vec())
    }

    pub fn serve_crl(self: &Arc<Self>) -> Result<CrlServer> {
        // Bind port 0 directly; probing a free port then rebinding is racy.
        // No port is written back to the shared CA file.
        let listener = TcpListener::bind(("127.0.0.1", self.port))
            .or_else(|e| {
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::AddrInUse | std::io::ErrorKind::PermissionDenied
                ) {
                    TcpListener::bind(("127.0.0.1", 0))
                } else {
                    Err(e)
                }
            })
            .map_err(|e| {
                format!(
                    "Cannot start local CRL listener (preferred port {}): {e}",
                    self.port
                )
            })?;
        let port = listener.local_addr().map_err(err)?.port();
        listener.set_nonblocking(true).map_err(err)?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let ca = self.clone();
        let worker = std::thread::Builder::new().name("ProxyLane CRL".into()).spawn(move || {
            let path = format!("/pki/{}.crl", ca.id);
            while !stopped.load(Ordering::Acquire) {
                let (mut stream, _) = match listener.accept() {
                    Ok(stream) => stream,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(20)); continue;
                    }
                    Err(_) => break,
                };
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                let deadline = Instant::now() + Duration::from_secs(2);
                let mut request = Vec::new();
                let mut chunk = [0u8; 1024];
                while request.len() < 8192 && !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() || stopped.load(Ordering::Acquire) { break; }
                    let _ = stream.set_read_timeout(Some(remaining));
                    match stream.read(&mut chunk) { Ok(0) | Err(_) => break, Ok(n) => request.extend_from_slice(&chunk[..n]) }
                }
                let first = String::from_utf8_lossy(&request);
                let valid = first.lines().next().map(|l| l.starts_with(&format!("GET {path} HTTP/1."))).unwrap_or(false);
                let (status, body) = if valid {
                    match ca.crl() { Ok(b) => ("200 OK", b), Err(_) => ("503 Service Unavailable", vec![]) }
                } else { ("404 Not Found", vec![]) };
                let header = format!("HTTP/1.1 {status}\r\nContent-Type: application/pkix-crl\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                let _ = stream.write_all(header.as_bytes()).and_then(|_| stream.write_all(&body));
            }
        }).map_err(err)?;
        Ok(CrlServer {
            port,
            stop,
            worker: Some(worker),
        })
    }
}
