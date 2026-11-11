use crate::pki::{Authority, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use rustls::{
    client::ClientConfig,
    pki_types::ServerName,
    server::{Accepted, Acceptor, ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
    ClientConnection, Connection, ServerConfig, ServerConnection,
};
use serde_json::{json, Value};
use std::{
    collections::VecDeque,
    fs::{File, OpenOptions},
    io::{Cursor, Read, Write},
    sync::Arc,
    time::{Duration, Instant},
};

pub const HIGH_WATER: usize = 256 * 1024;
const HELLO_LIMIT: usize = 64 * 1024;
const CAPTURE_LIMIT: usize = 16 * 1024 * 1024;

// Only certificate trust/name/time checks are bypassed. TLS handshake signatures remain verified.
#[derive(Debug)]
pub(crate) struct SkipCertificateTrust;
impl rustls::client::danger::ServerCertVerifier for SkipCertificateTrust {
    fn verify_server_cert(&self, _: &rustls::pki_types::CertificateDer<'_>, _: &[rustls::pki_types::CertificateDer<'_>],
        _: &ServerName<'_>, _: &[u8], _: rustls::pki_types::UnixTime)
        -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, message: &[u8], cert: &rustls::pki_types::CertificateDer<'_>, dss: &rustls::DigitallySignedStruct)
        -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &rustls::crypto::ring::default_provider().signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, message: &[u8], cert: &rustls::pki_types::CertificateDer<'_>, dss: &rustls::DigitallySignedStruct)
        -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &rustls::crypto::ring::default_provider().signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

pub struct Context {
    pub ca: Arc<Authority>,
    pub verifier: Arc<dyn rustls::client::danger::ServerCertVerifier>,
    pub async_handshake: bool,
    #[cfg(test)]
    pub roots: Arc<rustls::RootCertStore>,
    pub crl: crate::pki::CrlServer,
}
impl Context {
    pub fn open() -> Result<Arc<Self>> {
        let ca = Arc::new(Authority::load(&crate::pki::directory()?, true)?);
        let verifier = crate::verification::platform()?;
        let crl = ca.serve_crl()?;
        Ok(Arc::new(Self {
            ca,
            verifier,
            async_handshake: true,
            #[cfg(test)]
            roots: Arc::new(rustls::RootCertStore::empty()),
            crl,
        }))
    }
}

#[derive(Debug)]
struct Leaf(Arc<CertifiedKey>);
impl ResolvesServerCert for Leaf {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.0
            .key
            .choose_scheme(hello.signature_schemes())
            .map(|_| self.0.clone())
    }
}

struct Capture {
    file: File,
    bytes: usize,
    truncated: bool,
}
impl Capture {
    fn event(&mut self, value: Value) -> Result<()> {
        serde_json::to_writer(&mut self.file, &value).map_err(|e| e.to_string())?;
        self.file.write_all(b"\n").map_err(|e| e.to_string())
    }
    fn data(&mut self, side: usize, data: &[u8]) -> Result<()> {
        if self.truncated {
            return Ok(());
        }
        if self.bytes + data.len() > CAPTURE_LIMIT {
            self.truncated = true;
            return self.event(json!({"event":"capture_truncated", "limit":CAPTURE_LIMIT}));
        }
        self.bytes += data.len();
        self.event(json!({"event":"plaintext", "from":if side == 0 {"application"} else {"upstream"}, "time_us":time::OffsetDateTime::now_utc().unix_timestamp_nanos()/1000, "base64":STANDARD.encode(data)}))
    }
}

pub type Observer = extern "C" fn(usize, u32, *const u8, usize);
pub struct Session {
    pub observer: Option<(Observer, usize)>,
    context: Arc<Context>,
    host: String,
    skip_upstream_verify: bool,
    handshake_seconds: u64,
    lifecycle: Option<(Arc<crate::protocol::Runtime>, proxylane_protocol::Connection)>,
    last_status: String,
    capture_epoch: u64,
    // 0 sniffing, 1 passthrough, 2 collecting hello, 3 upstream TLS, 4 downstream TLS/active.
    pub state: u8,
    sniff: Vec<u8>,
    hello_bytes: usize,
    acceptor: Option<Acceptor>,
    accepted: Option<Accepted>,
    deferred: Vec<u8>,
    connections: [Option<Connection>; 2],
    handshake: Option<crate::verification::HandshakeJob>,
    output: [VecDeque<u8>; 2],
    plaintext: [VecDeque<u8>; 2],
    capture_pending: Option<(usize,Vec<u8>)>,
    encrypted_pending: [Vec<u8>;2],
    pub eof: [bool; 2],
    close_sent: [bool; 2],
    started: Instant,
    pub error: String,
    drain_error: String,
    ech_rejected: bool,
    transport_end: String,
    capture: Option<Capture>,
    protocol_source: Option<(
        Arc<crate::protocol::Runtime>,
        proxylane_protocol::Connection,
    )>,
    protocol: Option<crate::protocol::Tap>,
}

impl Session {
    pub fn new(
        context: Arc<Context>,
        host: String,
        metadata: Value,
        capture: bool,
    ) -> Result<Self> {
        let mut log = None;
        if capture {
            std::fs::create_dir_all(context.ca.directory.join("captures"))
                .map_err(|e| e.to_string())?;
            let mut random = [0u8; 16];
            getrandom::getrandom(&mut random).map_err(|e| e.to_string())?;
            let id = format!("{:032x}", u128::from_le_bytes(random));
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(
                    context
                        .ca
                        .directory
                        .join("captures")
                        .join(format!("{id}.jsonl")),
                )
                .map_err(|e| e.to_string())?;
            let mut c = Capture {
                file,
                bytes: 0,
                truncated: false,
            };
            c.event(json!({"event":"connection", "id":id, "metadata":metadata, "host":host, "ca":context.ca.id}))?;
            log = Some(c);
        }
        Ok(Self {
            observer: None,
            context,
            host,
            skip_upstream_verify: crate::SKIP_UPSTREAM_VERIFY.load(std::sync::atomic::Ordering::Acquire),
            handshake_seconds: crate::options::current().handshake_seconds,
            lifecycle: None,
            last_status: String::new(),
            capture_epoch: 0,
            state: 0,
            sniff: vec![],
            hello_bytes: 0,
            acceptor: None,
            accepted: None,
            deferred: vec![],
            connections: [None, None],
            handshake: None,
            output: Default::default(),
            plaintext: Default::default(),
            capture_pending:None,
            encrypted_pending:Default::default(),
            eof: [false; 2],
            close_sent: [false; 2],
            started: Instant::now(),
            error: String::new(),
            drain_error: String::new(),
            ech_rejected: false,
            transport_end: String::new(),
            capture: log,
            protocol_source: None,
            protocol: None,
        })
    }

    pub fn enable_protocol(
        &mut self,
        runtime: Arc<crate::protocol::Runtime>,
        identity: proxylane_protocol::Connection,
    ) {
        let epoch = runtime.capture_epoch();
        self.enable_protocol_at(runtime, identity, epoch);
    }
    pub fn enable_protocol_at(&mut self, runtime: Arc<crate::protocol::Runtime>,
        mut identity: proxylane_protocol::Connection, epoch: u64) {
        // This connection may turn out to be SSH or another passthrough stream.
        // Record certificate bypass only after entering the upstream TLS path.
        identity.upstream_verification_skipped = false;
        self.capture_epoch = epoch;
        self.lifecycle = Some((runtime.clone(), identity.clone()));
        self.protocol_source = Some((runtime, identity));
        self.status("Connecting", "");
    }

    #[cfg(test)]
    pub(crate) fn skip_verification_for_test(&mut self) { self.skip_upstream_verify = true; }
    pub fn transport_result(&mut self, error: usize) {
        if error == 0 { if self.state == 0 { self.status("Established", ""); } }
        else { self.fail(format!("TCP connection failed: {error}")); }
    }
    pub fn transport_closed(&mut self,side:usize,error:usize) {
        self.transport_end=format!("{} TCP transport closed (socket error {error})",Self::side_name(side));
        if let Some(t)=&self.protocol {t.transport_closed(side,error);}
        if self.error.is_empty() && self.drain_error.is_empty() {self.status(if self.ready(){"Closed"}else{"Failed"},&self.transport_end.clone());}
    }
    pub fn reported_error(&self)->&str {
        if self.ech_rejected {"ECH negotiation rejected; application may retry without ECH."}else{&self.error}
    }
    fn status(&mut self, state: &str, problem: &str) {
        let (state, problem) = if self.ech_rejected {
            ("Closed", "ECH negotiation rejected; application may retry without ECH.")
        } else if problem.starts_with("TLS truncated: upstream TCP EOF without close_notify (") && !problem.ends_with("(during handshake)") {
            ("Closed",problem) // Preserve truncation on individual incomplete messages.
        } else if Self::quiet_application_close(problem) {
            ("Closed", "")
        } else { (state, problem) };
        if state == self.last_status { return; }
        self.last_status = state.into();
        if let Some((runtime, identity)) = &mut self.lifecycle {
            identity.server_name = self.host.clone();
            identity.decrypted = self.state >= 2;
            identity.upstream_verification_skipped = self.skip_upstream_verify && self.state >= 3;
            let alpn = self.connections[1].as_ref().and_then(|c| c.alpn_protocol());
            let protocol = if self.state < 2 { "tcp" } else { match alpn { Some(b"h2") => "h2", Some(b"http/1.1") => "http1", _ => "tls_stream" } };
            runtime.lifecycle(self.capture_epoch, identity, state, protocol, problem, identity.upstream_verification_skipped);
        }
    }
    fn passthrough_data(&mut self, side: usize, bytes: &[u8]) {
        self.status("Established", "");
        if let Some((runtime, identity)) = self.protocol_source.take() {
            self.protocol = runtime.tap_at(self.capture_epoch, identity, None, false);
        }
        if let Some(tap) = &mut self.protocol { tap.data(side, bytes); }
    }

    fn event(&mut self, value: Value) -> Result<()> {
        if value["event"] == "error"
            && value["message"].as_str().map(Self::quiet_application_close).unwrap_or(false) {
            return Ok(());
        }
        // The simple monitor shows useful data and one error, not TLS internals.
        // In particular, Drop must not duplicate a previously reported error.
        if value["event"] == "error" {
            if let Some(message) = value["message"].as_str() {
                self.observe(0, message.as_bytes());
            }
        }
        if let Some(c) = &mut self.capture {
            c.event(value)?;
        }
        Ok(())
    }
    fn observe(&self, kind: u32, data: &[u8]) {
        if let Some((callback, user)) = self.observer {
            callback(user, kind, data.as_ptr(), data.len());
        }
    }
    pub fn fail(&mut self, error: String) {
        if self.error.is_empty() {
            self.finish_pending_capture();
            // Close means capture stopped, never fabricate a clean TLS EOF.
            self.status("Failed", &error);
            if let Some(t)=&self.protocol {t.close_reason(if self.ech_rejected {
                "ECH negotiation rejected; application may retry without ECH.".into()
            }else{format!("TLS transport failed: {error}")});}
            self.protocol.take();
            let _ = self.event(json!({"event":if self.ech_rejected {"ech_rejected"}else{"error"}, "message":error}));
            self.error = error;
        }
    }
    fn finish_pending_capture(&mut self) {
        if let Some((side,bytes))=self.capture_pending.take() {
            if let Some(t)=&mut self.protocol {t.data(side,&bytes);}
        }
        // A cancelled socket can still have authenticated plaintext buffered
        // inside rustls. Retain that prefix before retiring its capture.
        if let Some(t)=&mut self.protocol {
            for side in 0..2 {
                if let Some(c)=self.connections[side].as_mut() {
                    let mut buf=[0u8;16384];
                    while let Ok(n)=c.reader().read(&mut buf) {
                        if n==0 {break;}t.data(side,&buf[..n]);
                    }
                }
            }
        }
    }
    fn quiet_application_close(error: &str) -> bool {
        // Presentation only: preserve unclean EOF and draining internally.
        error.starts_with("TLS truncated: application TCP EOF without close_notify (")
            && (error.ends_with("(during transfer)")
                || error.ends_with("(opposite peer already sent close_notify)"))
    }
    pub fn can_read(&self) -> bool {
        self.can_read_side(0) && self.can_read_side(1)
    }
    pub fn can_read_side(&self, side: usize) -> bool {
        self.error.is_empty() && self.drain_error.is_empty() && !self.eof[side]
            && self.capture_pending.is_none() && self.encrypted_pending.iter().all(Vec::is_empty)
            && !(side == 1 && self.handshake.is_some())
            && self.output[1 - side].len() < HIGH_WATER
            && self.plaintext[1 - side].len() < HIGH_WATER
    }
    pub fn ready(&self) -> bool {
        self.state == 1
            || (self.state == 4
                && self
                    .connections
                    .iter()
                    .all(|c| c.as_ref().map(|c| !c.is_handshaking()).unwrap_or(false)))
    }
    pub fn handshake_pending(&self) -> bool { self.handshake.is_some() }
    pub fn recording_pending(&self)->bool {self.capture_pending.is_some() || self.encrypted_pending.iter().any(|b|!b.is_empty())}
    pub fn tick(&mut self) -> Result<()> {
        if !self.error.is_empty() {
            return Err(self.error.clone());
        }
        // Keep authenticated output readable after an unclean TCP EOF. Only
        // fail the host once it has sent every queued byte; never forge TLS EOF.
        if !self.drain_error.is_empty()
            && self.output.iter().all(|q| q.is_empty())
            && self.plaintext.iter().all(|q| q.is_empty())
            && self.connections.iter().flatten().all(|c| !c.wants_write()) {
            return Err(self.drain_error.clone());
        }
        // Idle/server-first protocols are allowed. Only a partial handshake has a deadline.
        if !self.ready()
            && (self.state != 0 || !self.sniff.is_empty())
            && self.started.elapsed() > Duration::from_secs(self.handshake_seconds)
        {
            return Err(format!("TLS detection/handshake exceeded {} seconds",self.handshake_seconds));
        }
        Ok(())
    }

    pub fn feed(&mut self, side: usize, data: &[u8]) -> Result<()> {
        self.tick()?;
        if self.eof[side] {
            return Err("data received after EOF".into());
        }
        if data.len() > 16384 || !self.can_read_side(side) {
            return Err("MITM input exceeds bounded buffer capacity".into());
        }
        if self.state == 0 {
            if self.sniff.is_empty() {
                self.started = Instant::now();
            }
            if side == 1 {
                if !self.sniff.is_empty() {
                    return Err("upstream spoke during partial TLS detection".into());
                }
                self.state = 1;
            } else {
                self.sniff.extend_from_slice(data);
                let plausible = self.sniff[0] == 0x16
                    && (self.sniff.len() < 2 || self.sniff[1] == 3)
                    && (self.sniff.len() < 3 || self.sniff[2] <= 3);
                if !plausible {
                    self.state = 1;
                    let bytes = std::mem::take(&mut self.sniff);
                    self.passthrough_data(0, &bytes);
                    self.observe(3, &bytes);
                    self.output[1].extend(bytes);
                    self.event(json!({"event":"passthrough"}))?;
                    return Ok(());
                }
                if self.sniff.len() < 3 {
                    return Ok(());
                }
                self.state = 2;
                self.status("TLS handshaking", "");
                self.acceptor = Some(Acceptor::default());
                let bytes = std::mem::take(&mut self.sniff);
                return self.hello(&bytes);
            }
        }
        if self.state == 1 {
            self.passthrough_data(side, data);
            self.observe(side as u32 + 3, data);
            self.output[1 - side].extend(data);
            return Ok(());
        }
        if self.state == 2 {
            if side != 0 {
                return Err("unexpected upstream bytes before TLS ClientHello".into());
            }
            return self.hello(data);
        }
        if side == 0 && self.connections[0].is_none() {
            if self.deferred.len() + data.len() > HELLO_LIMIT {
                return Err("too much data before downstream handshake".into());
            }
            self.deferred.extend_from_slice(data);
            return Ok(());
        }
        self.feed_tls(side, data)
            .map_err(|e| format!("{} TLS: {e}", Self::side_name(side)))?;
        self.pump()
    }

    fn hello(&mut self, data: &[u8]) -> Result<()> {
        self.hello_bytes += data.len();
        if self.hello_bytes > HELLO_LIMIT {
            return Err("ClientHello exceeds 64 KiB".into());
        }
        let acceptor = self.acceptor.as_mut().unwrap();
        let mut input = Cursor::new(data);
        while (input.position() as usize) < data.len() {
            if acceptor.read_tls(&mut input).map_err(|e| e.to_string())? == 0 {
                return Err("ClientHello made no progress".into());
            }
        }
        let Some(accepted) = acceptor.accept().map_err(|(e, _)| e.to_string())? else {
            return Ok(());
        };
        let hello = accepted.client_hello();
        if let Some(sni) = hello.server_name() {
            self.host = sni.to_string();
        }
        let server_name = ServerName::try_from(self.host.clone()).map_err(|e| e.to_string())?;
        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(|e| e.to_string())?
                .dangerous()
                .with_custom_certificate_verifier(self.context.verifier.clone())
                .with_no_client_auth();
        if self.skip_upstream_verify { config.dangerous().set_certificate_verifier(Arc::new(SkipCertificateTrust)); }
        config.alpn_protocols = hello
            .alpn()
            .map(|p| p.map(|p| p.to_vec()).collect())
            .unwrap_or_default();
        config.enable_early_data = false;
        let mut upstream =
            ClientConnection::new(Arc::new(config), server_name).map_err(|e| e.to_string())?;
        upstream.set_buffer_limit(Some(HIGH_WATER));
        self.connections[1] = Some(Connection::Client(upstream));
        self.accepted = Some(accepted);
        self.acceptor = None;
        self.state = 3;
        self.event(json!({"event":"client_hello", "server_name":self.host}))?;
        self.pump()
    }

    fn finish_upstream(&mut self) -> Result<()> {
        let upstream = self.connections[1].as_ref().unwrap();
        let alpn = upstream.alpn_protocol().map(|p| p.to_vec());
        let version = format!("{:?}", upstream.protocol_version());
        let leaf = self.context.ca.leaf(&self.host, self.context.crl.port())?;
        let mut config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(|e| e.to_string())?
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(Leaf(leaf)));
        config.alpn_protocols = alpn.clone().into_iter().collect();
        // No early data or cross-connection resumption in the validation version.
        config.max_early_data_size = 0;
        let mut server: ServerConnection = self
            .accepted
            .take()
            .unwrap()
            .into_connection(Arc::new(config))
            .map_err(|(e, _)| e.to_string())?;
        server.set_buffer_limit(Some(HIGH_WATER));
        self.connections[0] = Some(Connection::Server(server));
        self.state = 4;
        if let Some((runtime, mut identity)) = self.protocol_source.take() {
            identity.server_name = self.host.clone();
            identity.upstream_verification_skipped = self.skip_upstream_verify;
            self.protocol = runtime.tap_at(self.capture_epoch, identity, alpn.clone(), true);
        }
        self.event(json!({"event":if self.skip_upstream_verify {"upstream_verification_skipped"} else {"upstream_verified"}, "tls":version, "alpn":alpn.map(|p| String::from_utf8_lossy(&p).to_string()), "server_name":self.host}))?;
        let deferred = std::mem::take(&mut self.deferred);
        if !deferred.is_empty() {
            self.feed_tls(0, &deferred)?;
        }
        Ok(())
    }

    fn feed_tls(&mut self, side: usize, data: &[u8]) -> Result<()> {
        if self.capture_pending.is_some() {
            if self.encrypted_pending[side].len()+data.len()>HIGH_WATER {return Err("TLS input while recording paused".into());}
            self.encrypted_pending[side].extend_from_slice(data);return Ok(());
        }
        if side == 1 && self.state == 3 && self.context.async_handshake {
            let connection = self.connections[1].take().ok_or("missing upstream TLS endpoint")?;
            self.handshake = Some(crate::verification::HandshakeJob::start(connection, data.to_vec())?);
            return Ok(());
        }
        let mut input = Cursor::new(data);
        while (input.position() as usize) < data.len() {
            let state = {
                let connection = self.connections[side]
                    .as_mut()
                    .ok_or("missing TLS endpoint")?;
                if connection.read_tls(&mut input).map_err(|e| e.to_string())? == 0 {
                    return Err("TLS input made no progress".into());
                }
                match connection.process_new_packets() {
                    Ok(state)=>state,
                    Err(e)=>{
                        // The ECH rejection alert may follow the client's Finished
                        // record, so is_handshaking() is not a reliable discriminator.
                        // Match the exact typed alert, never a generic certificate error.
                        // This does not claim that a subsequent retry succeeded.
                        self.ech_rejected=side==0
                            && matches!(e,rustls::Error::AlertReceived(rustls::AlertDescription::EncryptedClientHelloRequired));
                        return Err(e.to_string());
                    }
                }
            };
            if state.peer_has_closed() {
                if let Some(t)=&self.protocol {t.close_reason(format!("{} TLS close_notify",Self::side_name(side)));}
                self.eof[side] = true;
            }
            // read_tls may consume only a prefix of this socket read. Drain
            // each decoded flight before feeding the remainder: mixed short
            // and full records can fill rustls's 16 KiB plaintext buffer even
            // when the socket read itself is only 4 KiB.
            self.pump()?;
            if self.capture_pending.is_some() {
                self.encrypted_pending[side].extend_from_slice(&data[input.position() as usize..]);
                return Ok(());
            }
        }
        Ok(())
    }

    pub fn pump(&mut self) -> Result<()> {
        if let Some((side,bytes))=self.capture_pending.take() {
            if self.protocol.as_mut().is_some_and(|t|!t.try_data(side,&bytes)) {
                self.capture_pending=Some((side,bytes));return Ok(());
            }
            if let Some((callback,user))=self.observer {callback(user,side as u32+1,bytes.as_ptr(),bytes.len());}
            if let Some(log)=&mut self.capture {log.data(side,&bytes)?;}
            self.plaintext[1-side].extend(bytes);
        }
        for side in 0..2 {
            if !self.encrypted_pending[side].is_empty() {
                let bytes=std::mem::take(&mut self.encrypted_pending[side]);
                self.feed_tls(side,&bytes)?;
                if self.capture_pending.is_some() {return Ok(());}
            }
        }
        if let Some(job) = &self.handshake {
            let Some(flight) = job.poll().map_err(|e| format!("upstream TLS: {e}"))? else { return Ok(()); };
            self.handshake = None;
            self.connections[1] = Some(flight.connection);
            if flight.closed { self.eof[1] = true; }
            // Drain this flight before reading more records, including a
            // handshake coalesced with the first application data.
            self.pump()?;
            if !flight.remainder.is_empty() { self.feed_tls(1, &flight.remainder)?; }
            return Ok(());
        }
        if self.state < 3 {
            return Ok(());
        }
        // A final upstream handshake flight may already contain HTTP/2 SETTINGS.
        // Establish the downstream TLS endpoint and analysis tap BEFORE draining
        // any plaintext, including when pump is called from inside feed_tls.
        if self.state == 3 && !self.connections[1].as_ref().unwrap().is_handshaking() {
            self.finish_upstream()?;
        }
        if self.ready() { self.status("Established", ""); }
        for side in 0..2 {
            if self.capture_pending.is_some() {break;}
            if let Some(c) = self.connections[side].as_mut() {
                let mut buf = [0u8; 16384];
                // can_read() applies backpressure before accepting more input.
                // Finish draining the already accepted, bounded TLS flight,
                // even if it crosses the high-water mark by a record. Leaving
                // plaintext in rustls can reject the rest of the current input
                // and can send close_notify before those bytes are forwarded.
                loop {
                    match c.reader().read(&mut buf) {
                        Ok(0) => {
                            // rustls Reader returns 0 only after buffered plaintext
                            // has been drained and authenticated close_notify seen.
                            if let Some(tap) = &mut self.protocol {
                                tap.eof(side, true);
                            }
                            break;
                        }
                        Ok(n) => {
                            if let Some(tap) = &mut self.protocol {
                                if !tap.try_data(side,&buf[..n]) {
                                    self.capture_pending=Some((side,buf[..n].to_vec()));break;
                                }
                            }
                            if let Some((callback, user)) = self.observer {
                                callback(user, side as u32 + 1, buf.as_ptr(), n);
                            }
                            if let Some(log) = &mut self.capture {
                                log.data(side, &buf[..n])?;
                            }
                            self.plaintext[1 - side].extend(&buf[..n]);
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) => return Err(e.to_string()),
                    }
                }
            }
        }
        if self.ready() { self.status("Established", ""); }
        for side in 0..2 {
            if let Some(c) = self.connections[side].as_mut() {
                if !c.is_handshaking() {
                    while !self.plaintext[side].is_empty() {
                        let bytes = self.plaintext[side].make_contiguous();
                        let n = c.writer().write(bytes).map_err(|e| e.to_string())?;
                        if n == 0 {
                            break;
                        }
                        self.plaintext[side].drain(..n);
                    }
                    if self.eof[1 - side]
                        && self.drain_error.is_empty()
                        && self.capture_pending.is_none()
                        && self.encrypted_pending.iter().all(Vec::is_empty)
                        && self.plaintext[side].is_empty()
                        && !self.close_sent[side]
                    {
                        c.send_close_notify();
                        self.close_sent[side] = true;
                    }
                }
                while c.wants_write() && self.output[side].len() < HIGH_WATER {
                    if c.write_tls(&mut self.output[side])
                        .map_err(|e| e.to_string())?
                        == 0
                    {
                        break;
                    }
                }
            }
        }
        Ok(())
    }
    pub fn peek(&mut self, side: usize, buf: &mut [u8]) -> Result<usize> {
        self.pump()?;
        let n = buf.len().min(self.output[side].len());
        for (dst, src) in buf[..n].iter_mut().zip(self.output[side].iter()) {
            *dst = *src;
        }
        Ok(n)
    }
    pub fn consume(&mut self, side: usize, n: usize) -> Result<()> {
        if n > self.output[side].len() {
            return Err("invalid output consumption".into());
        }
        self.output[side].drain(..n);
        self.pump()
    }
    pub fn input_eof(&mut self, side: usize) -> Result<()> {
        if self.state == 0 {
            if !self.sniff.is_empty() {
                return Err(format!("{} EOF within TLS prefix", Self::side_name(side)));
            }
            self.state = 1;
        }
        if self.state != 1 && !self.eof[side] {
            if let Some(tap) = &mut self.protocol {
                tap.close_reason(format!("{} TCP EOF without TLS close_notify",Self::side_name(side)));
                tap.eof(side, false);
            }
            let error = format!(
                "TLS truncated: {} TCP EOF without close_notify ({})",
                Self::side_name(side),
                if self.eof[1 - side] {
                    "opposite peer already sent close_notify"
                } else if !self.ready() {
                    "during handshake"
                } else {
                    "during transfer"
                }
            );
            if !self.ready() { return Err(error); }
            self.pump()?;
            self.drain_error = error;
            self.eof[side] = true;
            self.status("Failed", &self.drain_error.clone());
            self.protocol.take();
            return Ok(());
        }
        if self.state == 1 {
            if let Some(tap) = &mut self.protocol {
                tap.close_reason(format!("{} TCP EOF",Self::side_name(side)));tap.eof(side, true);
            }
        }
        self.eof[side] = true;
        self.pump()
    }
    fn side_name(side: usize) -> &'static str {
        if side == 0 {
            "application"
        } else {
            "upstream"
        }
    }
    pub fn shutdown_output(&self, side: usize) -> bool {
        self.drain_error.is_empty() && self.eof[1 - side]
            && !self.recording_pending()
            && self.output[side].is_empty()
            && self.plaintext[side].is_empty()
            && (self.state == 1
                || (self.close_sent[side]
                    && self.connections[side]
                        .as_ref()
                        .map(|c| !c.wants_write())
                        .unwrap_or(false)))
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        // Teardown must not discard a decoded fragment waiting for recording.
        self.finish_pending_capture();
        if let Some(t)=&self.protocol {
            t.close_reason(if !self.transport_end.is_empty(){self.transport_end.clone()}
                else if self.eof==[true,true]{"Both TCP directions ended".into()}
                else {"TCP forwarding task released before both directions ended".into()});
        }
        if self.error.is_empty() && self.drain_error.is_empty() { self.status("Closed", &self.transport_end.clone()); }
        let error = if Self::quiet_application_close(&self.error) { "" } else { &self.error };
        let _ = self.event(json!({"event":"closed", "state":self.state, "error":error}));
    }
}
