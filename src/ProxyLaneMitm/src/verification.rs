//! Shared upstream trust for TCP TLS and QUIC. Extra roots are application-local;
//! no certificates or policies are installed into Windows by this module.
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, Error, SignatureScheme,
};
use std::sync::{atomic::{AtomicUsize, Ordering}, Arc};

#[derive(Debug)]
struct PlatformVerifier(rustls_platform_verifier::Verifier);
static VERIFYING: AtomicUsize = AtomicUsize::new(0);
const MAX_VERIFYING: usize = 32;
struct Permit;
impl Permit {
    fn acquire() -> Result<Self, Error> {
        VERIFYING.fetch_update(Ordering::AcqRel, Ordering::Acquire,
            |n| (n < MAX_VERIFYING).then_some(n + 1))
            .map(|_| Self).map_err(|_| Error::General("upstream certificate verification capacity reached".into()))
    }
}
impl Drop for Permit {
    fn drop(&mut self) { VERIFYING.fetch_sub(1, Ordering::Release); }
}

pub fn platform() -> Result<Arc<dyn ServerCertVerifier>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = rustls_platform_verifier::Verifier::new_with_extra_roots(
        webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter().cloned(), provider)
        .map_err(|e| e.to_string())?;
    Ok(Arc::new(PlatformVerifier(verifier)))
}

impl ServerCertVerifier for PlatformVerifier {
    fn verify_server_cert(&self, leaf: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>],
        name: &ServerName<'_>, ocsp: &[u8], now: UnixTime) -> Result<ServerCertVerified, Error> {
        // QUIC calls this synchronous rustls API on a multi-thread Tokio runtime.
        // Let Tokio replace this worker while Windows performs potentially slow I/O.
        // TCP calls it only from the bounded handshake worker pool below.
        let _permit = Permit::acquire()?;
        let verify = || self.0.verify_server_cert(leaf, intermediates, name, ocsp, now);
        match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread =>
                tokio::task::block_in_place(verify),
            _ => verify(),
        }
    }
    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        self.0.verify_tls12_signature(message, cert, dss)
    }
    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        self.0.verify_tls13_signature(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> { self.0.supported_verify_schemes() }
}

// Only upstream handshake flights are moved off the PRC thread. Application
// plaintext, capture callbacks, and established-connection forwarding stay on
// their original thread. Dropping a session never joins a Windows network call.
use std::{io::Cursor, sync::{mpsc, Mutex, OnceLock}};
type Work = Box<dyn FnOnce() + Send>;
fn workers() -> Result<&'static mpsc::SyncSender<Work>, String> {
    static POOL: OnceLock<Result<mpsc::SyncSender<Work>, String>> = OnceLock::new();
    POOL.get_or_init(|| {
        let (tx, rx) = mpsc::sync_channel::<Work>(128);
        let rx = Arc::new(Mutex::new(rx));
        for n in 0..8 {
            let rx = rx.clone();
            std::thread::Builder::new().name(format!("tls-handshake-{n}")).spawn(move || loop {
                let work = match rx.lock() { Ok(rx) => rx.recv(), Err(_) => return };
                match work {
                    Ok(work) => { let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work)); }
                    Err(_) => return,
                }
            }).map_err(|e| e.to_string())?;
        }
        Ok(tx)
    }).as_ref().map_err(Clone::clone)
}

pub struct Flight {
    pub connection: rustls::Connection,
    pub closed: bool,
    pub remainder: Vec<u8>,
}
pub struct HandshakeJob {
    result: mpsc::Receiver<Result<Flight, String>>,
    cancelled: Arc<std::sync::atomic::AtomicBool>,
}
impl Drop for HandshakeJob {
    fn drop(&mut self) { self.cancelled.store(true, Ordering::Release); }
}
impl HandshakeJob {
    pub fn start(mut connection: rustls::Connection, data: Vec<u8>) -> Result<Self, String> {
        let (tx, result) = mpsc::sync_channel(1);
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stopped = cancelled.clone();
        workers()?.try_send(Box::new(move || {
            if stopped.load(Ordering::Acquire) { return; }
            let outcome = (|| {
                let mut input = Cursor::new(data);
                if connection.read_tls(&mut input).map_err(|e| e.to_string())? == 0 {
                    return Err("TLS input made no progress".into());
                }
                let closed = connection.process_new_packets().map_err(|e| e.to_string())?.peer_has_closed();
                let used = input.position() as usize;
                let remainder = input.into_inner().split_off(used);
                Ok(Flight { connection, closed, remainder })
            })();
            // The receiver owns no page or socket pointer. A late result is
            // simply destroyed if the connection was cancelled or timed out.
            let _ = tx.send(outcome);
        })).map_err(|_| "upstream handshake queue full or unavailable".to_string())?;
        Ok(Self { result, cancelled })
    }
    pub fn poll(&self) -> Result<Option<Flight>, String> {
        match self.result.try_recv() {
            Ok(result) => result.map(Some),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(_) => Err("upstream handshake worker stopped".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DistinguishedName, DnType, IsCa, BasicConstraints, KeyPair};

    fn ca() -> (rcgen::Certificate,KeyPair) {
        let key=KeyPair::generate().unwrap();
        let mut p=CertificateParams::default();
        p.is_ca=IsCa::Ca(BasicConstraints::Unconstrained);
        p.distinguished_name=DistinguishedName::new();
        p.distinguished_name.push(DnType::CommonName,"ProxyLane in-memory trust regression");
        (p.self_signed(&key).unwrap(),key)
    }
    #[test]
    fn platform_extra_roots_keep_name_time_signature_and_issuer_checks() {
        let (root,key)=ca();
        let verifier=PlatformVerifier(rustls_platform_verifier::Verifier::new_with_extra_roots(
            [root.der().clone()], Arc::new(rustls::crypto::ring::default_provider())).unwrap());
        let mut p=CertificateParams::new(vec!["test.invalid".into()]).unwrap();
        p.extended_key_usages=vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let leaf_key=KeyPair::generate().unwrap();
        let leaf=p.clone().signed_by(&leaf_key,&root,&key).unwrap();
        let name=ServerName::try_from("test.invalid").unwrap();
        assert!(verifier.verify_server_cert(leaf.der(),&[],&name,&[],UnixTime::now()).is_ok());
        assert!(verifier.verify_server_cert(leaf.der(),&[],&ServerName::try_from("wrong.invalid").unwrap(),&[],UnixTime::now()).is_err());
        p.not_before=rcgen::date_time_ymd(2000,1,1);p.not_after=rcgen::date_time_ymd(2001,1,1);
        let expired=p.signed_by(&leaf_key,&root,&key).unwrap();
        assert!(verifier.verify_server_cert(expired.der(),&[],&name,&[],UnixTime::now()).is_err());
        let mut corrupt=leaf.der().to_vec();let last=corrupt.len()-1;corrupt[last]^=1;
        assert!(verifier.verify_server_cert(&CertificateDer::from(corrupt),&[],&name,&[],UnixTime::now()).is_err());
        assert!(platform().unwrap().verify_server_cert(leaf.der(),&[],&name,&[],UnixTime::now()).is_err());
    }

    #[test]
    fn windows_extra_roots_do_not_override_explicit_distrust() {
        // A unique test certificate is placed ONLY in CurrentUser Disallowed,
        // never in a trusted store. RAII removes it even if an assertion fails.
        use windows_sys::Win32::Security::Cryptography::*;
        struct Denied(*mut CERT_CONTEXT,HCERTSTORE);
        impl Drop for Denied {
            fn drop(&mut self) {unsafe {CertDeleteCertificateFromStore(self.0);CertCloseStore(self.1,0);}}
        }
        let (root,key)=ca();
        let store_name:Vec<u16>="Disallowed\0".encode_utf16().collect();
        let store=unsafe {CertOpenStore(CERT_STORE_PROV_SYSTEM_W,0,0,CERT_SYSTEM_STORE_CURRENT_USER,store_name.as_ptr().cast())};
        assert!(!store.is_null(),"open test disallowed store");
        let mut stored=std::ptr::null_mut();
        let added=unsafe {CertAddEncodedCertificateToStore(store,X509_ASN_ENCODING,root.der().as_ptr(),
            root.der().len() as u32,CERT_STORE_ADD_NEW,&mut stored)};
        if added==0 {unsafe {CertCloseStore(store,0);}panic!("add unique test disallowed certificate");}
        let _denied=Denied(stored,store);
        let verifier=PlatformVerifier(rustls_platform_verifier::Verifier::new_with_extra_roots(
            [root.der().clone()],Arc::new(rustls::crypto::ring::default_provider())).unwrap());
        let p=CertificateParams::new(vec!["denied.invalid".into()]).unwrap();
        let leaf=p.signed_by(&KeyPair::generate().unwrap(),&root,&key).unwrap();
        assert!(verifier.verify_server_cert(leaf.der(),&[],&ServerName::try_from("denied.invalid").unwrap(),&[],UnixTime::now()).is_err(),
            "bundled roots must not bypass explicit system distrust");
    }

    #[test]
    fn platform_rejects_revoked_leaf_with_bundled_root() {
        use std::{io::{Read,Write},time::{Duration,Instant},net::TcpListener};
        let (root,key)=ca();
        let listener=TcpListener::bind(("127.0.0.1",0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let url=format!("http://127.0.0.1:{}/revoked.crl",listener.local_addr().unwrap().port());
        let mut p=CertificateParams::new(vec!["revoked.invalid".into()]).unwrap();
        p.serial_number=Some(42u64.into());
        p.crl_distribution_points=vec![rcgen::CrlDistributionPoint {uris:vec![url]}];
        let leaf=p.signed_by(&KeyPair::generate().unwrap(),&root,&key).unwrap();
        let now=time::OffsetDateTime::now_utc();
        let crl=rcgen::CertificateRevocationListParams {
            this_update:now-time::Duration::hours(1),next_update:now+time::Duration::days(1),
            crl_number:1u64.into(),issuing_distribution_point:None,key_identifier_method:rcgen::KeyIdMethod::Sha256,
            revoked_certs:vec![rcgen::RevokedCertParams {serial_number:42u64.into(),revocation_time:now-time::Duration::minutes(1),
                reason_code:Some(rcgen::RevocationReason::KeyCompromise),invalidity_date:None}],
        }.signed_by(&root,&key).unwrap().der().to_vec();
        let done=Arc::new(std::sync::atomic::AtomicBool::new(false));let stopped=done.clone();
        let server=std::thread::spawn(move || {
            let until=Instant::now()+Duration::from_secs(12);
            while !stopped.load(Ordering::Acquire) && Instant::now()<until {
                if let Ok((mut s,_))=listener.accept() {
                    s.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
                    s.set_write_timeout(Some(Duration::from_secs(1))).unwrap();
                    let mut buf=[0;4096];let _=s.read(&mut buf);
                    let _=write!(s,"HTTP/1.1 200 OK\r\nContent-Type: application/pkix-crl\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",crl.len());
                    let _=s.write_all(&crl);
                } else {std::thread::sleep(Duration::from_millis(5));}
            }
        });
        let verifier=PlatformVerifier(rustls_platform_verifier::Verifier::new_with_extra_roots(
            [root.der().clone()],Arc::new(rustls::crypto::ring::default_provider())).unwrap());
        let result=verifier.verify_server_cert(leaf.der(),&[],&ServerName::try_from("revoked.invalid").unwrap(),&[],UnixTime::now());
        done.store(true,Ordering::Release);server.join().unwrap();
        assert!(matches!(result,Err(Error::InvalidCertificate(rustls::CertificateError::Revoked))),"{result:?}");
    }
}
