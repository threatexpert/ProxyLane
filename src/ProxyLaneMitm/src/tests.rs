use super::*;
use crate::session::{Context, Session};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};
use serde_json::json;
use std::{
    io::{Cursor, Read, Write},
    sync::Arc,
};

#[path = "tests_ech.rs"]
mod ech;

#[test]
fn analysis_panic_preserves_established_tls_forwarding() {
    for retained in [false,true] {
        let f=Fixture::new();
        let runtime=protocol::Runtime::new(proxylane_protocol::cache::CacheConfig {
            root:f.path.join("panic-cache"),
            recording:retained.then_some(proxylane_protocol::recording::RecordingConfig{total_bytes:16*1024*1024,min_free_bytes:0}),
            ..Default::default()
        }).unwrap();
        let mut m=f.session();
        m.enable_protocol(runtime.clone(),proxylane_protocol::Connection{id:"panic-forward".into(),..Default::default()});
        let (mut app,mut origin)=f.endpoints(false,true);
        for _ in 0..30 {exchange(&mut m,&mut app,&mut origin,4096).unwrap();}
        app.writer().write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        for _ in 0..4 {exchange(&mut m,&mut app,&mut origin,4096).unwrap();}
        let _=origin.reader().read_to_end(&mut Vec::new());
        runtime.query(&json!({"type":"stats"})).unwrap();runtime.panic_worker();
        // More than the TLS high-water mark, both directions, same connection.
        for n in 0..64 {
            let bytes=vec![n;16384];
            app.writer().write_all(&bytes).unwrap();origin.writer().write_all(&bytes).unwrap();
            for _ in 0..3 {exchange(&mut m,&mut app,&mut origin,4096).unwrap();}
            let mut upstream=Vec::new();let _=origin.reader().read_to_end(&mut upstream);
            let mut downstream=Vec::new();let _=app.reader().read_to_end(&mut downstream);
            assert_eq!(upstream,bytes);assert_eq!(downstream,bytes);
        }
        assert!(runtime.stop_capture().unwrap_err().contains("injected analysis panic"));
        drop(m);runtime.shutdown().unwrap();
    }
}

#[test]
fn plaintext_mitm_reset_preserves_bytes_and_transport_close_cause() {
    let f=Fixture::new();
    let runtime=protocol::Runtime::new(proxylane_protocol::cache::CacheConfig {
        root:f.path.join("reset-cause"),recording:Some(proxylane_protocol::recording::RecordingConfig {
            total_bytes:16*1024*1024,min_free_bytes:0}),..Default::default()
    }).unwrap();
    let mut m=f.session();m.enable_protocol(runtime.clone(),proxylane_protocol::Connection{id:"reset".into(),..Default::default()});
    m.feed(0,b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
    m.feed(1,b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nretained-prefix").unwrap();
    m.input_eof(0).unwrap();
    m.transport_closed(1,10054);drop(m);
    runtime.stop_capture().unwrap();
    let root=std::path::PathBuf::from(runtime.recording_status()["directory"].as_str().unwrap());
    let events=std::fs::read_to_string(root.join("events-000001.jsonl")).unwrap();
    assert!(events.contains("upstream TCP transport closed (socket error 10054)"));
    assert!(!events.contains("transport close cause unavailable"));
    let row:serde_json::Value=std::fs::read_dir(root.join("payload/000000")).unwrap()
        .map(|e|e.unwrap().path()).filter(|p|p.extension().is_some_and(|e|e=="json") && !p.to_string_lossy().ends_with(".cache.json"))
        .map(|p|serde_json::from_slice::<serde_json::Value>(&std::fs::read(p).unwrap()).unwrap())
        .find(|v|v["type"]=="exchange").unwrap();
    assert!(row["exchange"]["problem"].as_str().unwrap().contains("socket error 10054"));
    assert_eq!(std::fs::read(root.join("payload/000000").join(row["payloads"]["response"]["file"].as_str().unwrap())).unwrap(),b"retained-prefix");
    runtime.shutdown().unwrap();
}
#[test]
fn recording_tls_full_queue_resumes_and_stop_releases_pending_transport() {
    use std::time::{Duration,Instant};
    for (stop,size) in [(false,512),(false,1024*1024),(true,1024*1024)] {
        let f=Fixture::new();
        let runtime=protocol::Runtime::test_small_queue(proxylane_protocol::cache::CacheConfig {
            root:f.path.join("recording-pressure"),
            recording:Some(proxylane_protocol::recording::RecordingConfig {total_bytes:16*1024*1024,min_free_bytes:0}),
            queue_chunks:2,..Default::default()
        });
        let mut m=f.session();
        m.enable_protocol(runtime.clone(),proxylane_protocol::Connection{id:"pressure".into(),..Default::default()});
        let (mut app,mut origin)=f.endpoints(false,true);
        for _ in 0..30 {exchange(&mut m,&mut app,&mut origin,4096).unwrap();}
        app.writer().write_all(b"GET /pressure HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        for _ in 0..4 {exchange(&mut m,&mut app,&mut origin,4096).unwrap();}
        let _=origin.reader().read_to_end(&mut Vec::new());
        let release=runtime.pause_worker();
        if size==512 {runtime.fill_paused_queue();}
        let body:Vec<u8>=(0..size).map(|n|(n%251) as u8).collect();
        let mut expected=format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",body.len()).into_bytes();
        expected.extend(&body);
        origin.set_buffer_limit(None);origin.writer().write_all(&expected).unwrap();
        origin.send_close_notify();
        let mut wire=Vec::new();while origin.wants_write() {origin.write_tls(&mut wire).unwrap();}
        let mut at=0;
        let start=Instant::now();
        while !m.recording_pending() {
            let end=(at+4096).min(wire.len());
            assert!(end>at);m.feed(1,&wire[at..end]).unwrap();at=end;
        }
        assert!(start.elapsed()<Duration::from_secs(1),"TLS PRC producer must not block on a full recording queue");
        assert!(!m.can_read_side(1));
        let stopper=if stop {
            let r=runtime.clone();Some(std::thread::spawn(move||r.stop_capture().unwrap()))
        }else{None};
        if stop {
            let deadline=Instant::now()+Duration::from_secs(2);
            while runtime.capture_epoch()%2!=0 {assert!(Instant::now()<deadline);std::thread::yield_now();}
        }
        release.send(()).unwrap();
        if let Some(job)=stopper {job.join().unwrap();}
        let mut received=Vec::new();
        let deadline=Instant::now()+Duration::from_secs(15);
        while received.len()<expected.len() {
            assert!(Instant::now()<deadline,"recording backpressure failed to resume");
            m.pump().unwrap();
            if at<wire.len() && m.can_read_side(1) {
                let end=(at+4096).min(wire.len());m.feed(1,&wire[at..end]).unwrap();at=end;
            }
            let mut bytes=[0u8;16384];let n=m.peek(0,&mut bytes).unwrap();
            if n!=0 {
                let mut input=Cursor::new(&bytes[..n]);
                while input.position()<n as u64 {
                    assert!(app.read_tls(&mut input).unwrap()>0);app.process_new_packets().unwrap();
                    let _=app.reader().read_to_end(&mut received);
                }
                m.consume(0,n).unwrap();
            }
            let _=app.reader().read_to_end(&mut received);
            if n==0 {std::thread::yield_now();}
        }
        assert_eq!(received,expected);
        if !stop {runtime.stop_capture().unwrap();}
        let status=runtime.recording_status();
        assert_eq!(status["quality"]["gap_count"],0);assert_eq!(status["stopped"],false);
        let root=std::path::PathBuf::from(status["directory"].as_str().unwrap());
        let events=std::fs::read_to_string(root.join("events-000001.jsonl")).unwrap();
        let id=events.lines().map(|s|serde_json::from_str::<serde_json::Value>(s).unwrap())
            .find(|v|v["type"]=="message_head" && v["side"]==1).unwrap()["cache_id"].as_u64().unwrap();
        let saved=std::fs::read(root.join(proxylane_protocol::recording::payload_relative(id,1))).unwrap();
        if stop {assert!(saved.len()<body.len());assert_eq!(saved,body[..saved.len()]);}
        else {assert_eq!(saved,body);}
        drop(m);runtime.shutdown().unwrap();
    }
}

struct Fixture {
    path: std::path::PathBuf,
    context: Arc<Context>,
}
impl Fixture {
    fn new() -> Self {
        let mut random = [0u8; 8];
        getrandom::getrandom(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "proxylane-mitm-test-{}",
            u64::from_le_bytes(random)
        ));
        let ca = Arc::new(pki::Authority::load(&path, true).unwrap());
        let mut roots = RootCertStore::empty();
        roots.add(ca.der.clone()).unwrap();
        let roots = Arc::new(roots);
        let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
            roots.clone(), Arc::new(rustls::crypto::ring::default_provider())).build().unwrap();
        Self {
            path,
            context: Arc::new(Context {
                crl: ca.serve_crl().unwrap(),
                ca,
                roots,
                verifier,
                async_handshake: false,
            }),
        }
    }
    fn session(&self) -> Session {
        Session::new(
            self.context.clone(),
            "localhost".into(),
            json!({"pid":123}),
            false,
        )
        .unwrap()
    }
    fn endpoints(&self, tls12: bool, valid: bool) -> (ClientConnection, ServerConnection) {
        self.endpoints_alpn(tls12, valid, b"http/1.1")
    }
    fn endpoints_alpn(
        &self,
        tls12: bool,
        valid: bool,
        alpn: &[u8],
    ) -> (ClientConnection, ServerConnection) {
        let versions = if tls12 {
            vec![&rustls::version::TLS12]
        } else {
            vec![&rustls::version::TLS13]
        };
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&versions)
            .unwrap()
            .with_root_certificates(self.context.roots.clone())
            .with_no_client_auth();
        config.alpn_protocols = vec![alpn.to_vec()];
        let mut client =
            ClientConnection::new(Arc::new(config), ServerName::try_from("localhost").unwrap())
                .unwrap();
        client.set_buffer_limit(Some(256 * 1024));
        let cert = self
            .context
            .ca
            .leaf(
                if valid { "localhost" } else { "wrong.test" },
                self.context.crl.port(),
            )
            .unwrap();
        #[derive(Debug)]
        struct Resolver(Arc<rustls::sign::CertifiedKey>);
        impl rustls::server::ResolvesServerCert for Resolver {
            fn resolve(
                &self,
                _: rustls::server::ClientHello<'_>,
            ) -> Option<Arc<rustls::sign::CertifiedKey>> {
                Some(self.0.clone())
            }
        }
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&versions)
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Resolver(cert)));
        config.alpn_protocols = vec![alpn.to_vec()];
        (client, ServerConnection::new(Arc::new(config)).unwrap())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn exchange(
    m: &mut Session,
    app: &mut ClientConnection,
    origin: &mut ServerConnection,
    fragment: usize,
) -> Result<(), String> {
    // Sending each handshake fragment separately exercises sniffing and rustls Acceptor state.
    for side in 0..2 {
        let mut bytes = Vec::new();
        if side == 0 {
            app.write_tls(&mut bytes).unwrap();
        } else {
            origin.write_tls(&mut bytes).unwrap();
        }
        for chunk in bytes.chunks(fragment) {
            wait_handshake(m)?;
            assert!(m.can_read_side(side));
            m.feed(side, chunk)?;
        }
        wait_handshake(m)?;
        let mut bytes = [0u8; 4096];
        loop {
            let n = m.peek(side, &mut bytes)?;
            if n == 0 {
                break;
            }
            // Deliberately consume only a fraction of peek: models short socket sends.
            let n = n.min(fragment);
            let mut input = Cursor::new(&bytes[..n]);
            if side == 0 {
                while input.position() < n as u64 {
                    assert!(app.read_tls(&mut input).unwrap() > 0);
                    app.process_new_packets().map_err(|e| e.to_string())?;
                }
            } else {
                while input.position() < n as u64 {
                    assert!(origin.read_tls(&mut input).unwrap() > 0);
                    origin.process_new_packets().map_err(|e| e.to_string())?;
                }
            }
            m.consume(side, n)?;
        }
    }
    Ok(())
}

fn wait_handshake(m: &mut Session) -> Result<(), String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while m.handshake_pending() {
        m.pump()?;
        assert!(std::time::Instant::now() < deadline, "handshake worker stalled");
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    Ok(())
}

#[test]
fn asynchronous_upstream_handshake_transfers_and_cancels_without_blocking() {
    use rustls::client::danger::{ServerCertVerifier, ServerCertVerified, HandshakeSignatureValid};
    use rustls::pki_types::{CertificateDer, UnixTime};
    use std::time::{Instant, Duration};
    #[derive(Debug)]
    struct Slow(Arc<dyn ServerCertVerifier>, Arc<std::sync::atomic::AtomicBool>);
    impl ServerCertVerifier for Slow {
        fn verify_server_cert(&self, c: &CertificateDer<'_>, chain: &[CertificateDer<'_>],
            n: &ServerName<'_>, o: &[u8], t: UnixTime) -> Result<ServerCertVerified,rustls::Error> {
            self.1.store(true,std::sync::atomic::Ordering::Release);
            std::thread::sleep(Duration::from_millis(500));
            self.0.verify_server_cert(c,chain,n,o,t)
        }
        fn verify_tls12_signature(&self,m:&[u8],c:&CertificateDer<'_>,s:&rustls::DigitallySignedStruct)
            -> Result<HandshakeSignatureValid,rustls::Error> {self.0.verify_tls12_signature(m,c,s)}
        fn verify_tls13_signature(&self,m:&[u8],c:&CertificateDer<'_>,s:&rustls::DigitallySignedStruct)
            -> Result<HandshakeSignatureValid,rustls::Error> {self.0.verify_tls13_signature(m,c,s)}
        fn supported_verify_schemes(&self)->Vec<rustls::SignatureScheme> {self.0.supported_verify_schemes()}
    }
    let mut f = Fixture::new();
    Arc::get_mut(&mut f.context).unwrap().async_handshake = true;
    let mut normal = f.session();
    let (mut app,mut origin) = f.endpoints(false,true);
    for _ in 0..30 { exchange(&mut normal,&mut app,&mut origin,4096).unwrap(); }
    assert!(normal.ready());
    let body=vec![0x5a;2*1024*1024];
    let mut received=Vec::new();
    for chunk in body.chunks(8192) {
        origin.writer().write_all(chunk).unwrap();
        exchange(&mut normal,&mut app,&mut origin,4096).unwrap();
        let mut buf=[0;16384];
        while let Ok(n)=app.reader().read(&mut buf) {if n==0{break;}received.extend_from_slice(&buf[..n]);}
    }
    exchange(&mut normal,&mut app,&mut origin,4096).unwrap();
    let mut tail=[0;16384];
    while let Ok(n)=app.reader().read(&mut tail) {if n==0{break;}received.extend_from_slice(&tail[..n]);}
    assert_eq!(received.len(),body.len());
    assert!(received==body);

    let entered=Arc::new(std::sync::atomic::AtomicBool::new(false));
    let slow_context=Arc::new(Context {ca:f.context.ca.clone(),crl:f.context.ca.serve_crl().unwrap(),
        roots:f.context.roots.clone(),verifier:Arc::new(Slow(f.context.verifier.clone(),entered.clone())),
        async_handshake:true});
    let mut slow=Session::new(slow_context,"localhost".into(),json!({}),false).unwrap();
    let (mut client,mut server)=f.endpoints(false,true);
    let mut hello=Vec::new();client.write_tls(&mut hello).unwrap();slow.feed(0,&hello).unwrap();
    let mut buf=[0;16384];let n=slow.peek(1,&mut buf).unwrap();
    server.read_tls(&mut Cursor::new(&buf[..n])).unwrap();server.process_new_packets().unwrap();slow.consume(1,n).unwrap();
    let mut flight=Vec::new();server.write_tls(&mut flight).unwrap();
    let start=Instant::now();slow.feed(1,&flight).unwrap();
    assert!(start.elapsed()<Duration::from_millis(100));
    let deadline=Instant::now()+Duration::from_secs(2);
    while !entered.load(std::sync::atomic::Ordering::Acquire) {
        slow.pump().unwrap();assert!(Instant::now()<deadline);std::thread::sleep(Duration::from_millis(1));
    }
    // A different connection continues forwarding while one verifier sleeps.
    origin.writer().write_all(b"unrelated connection remains live").unwrap();
    let start=Instant::now();
    for _ in 0..2 {exchange(&mut normal,&mut app,&mut origin,4096).unwrap();}
    let n=app.reader().read(&mut buf).unwrap();assert_eq!(&buf[..n],b"unrelated connection remains live");
    assert!(start.elapsed()<Duration::from_millis(100));
    let start=Instant::now();drop(slow);assert!(start.elapsed()<Duration::from_millis(100));
}

extern "C" fn observe(user: usize, kind: u32, data: *const u8, length: usize) {
    unsafe {
        let records = &mut *(user as *mut Vec<(u32, Vec<u8>)>);
        records.push((kind, std::slice::from_raw_parts(data, length).to_vec()));
    }
}

#[test]
fn tls_large_response_drains_plaintext_between_record_reads() {
    for (tls12, fragment) in [(false, 4096), (true, 4096), (false, 16384), (true, 16384)] {
        let f = Fixture::new();
        let mut m = f.session();
        let (mut app, mut origin) = f.endpoints(tls12, true);
        for _ in 0..30 { exchange(&mut m, &mut app, &mut origin, 4096).unwrap(); }
        assert!(m.ready());
        let payload: Vec<u8> = (0..2 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
        origin.set_buffer_limit(None);
        // Mix full records with short header/frame writes, like real HTTP/2
        // servers. Uniform 16 KiB records alone do not expose this failure.
        let mut at = 0;
        for size in [16384, 47, 16384, 123, 3000, 16384, 16000, 1024].into_iter().cycle() {
            let end = (at + size).min(payload.len());
            origin.writer().write_all(&payload[at..end]).unwrap();
            at = end;
            if at == payload.len() { break; }
        }
        origin.send_close_notify();
        let mut wire = Vec::new();
        while origin.wants_write() { origin.write_tls(&mut wire).unwrap(); }
        let mut position = 0;
        let mut received = Vec::new();
        let mut saw_backpressure = false;
        let mut clean_eof = false;
        for step in 0..200_000 {
            if position < wire.len() && m.can_read_side(1) {
                // PRC recv and maximum FFI input sizes, unaligned to TLS records.
                let end = (position + fragment).min(wire.len());
                m.feed(1, &wire[position..end]).unwrap();
                position = end;
            }
            saw_backpressure |= !m.can_read();
            // Slow downstream consumer builds pressure on all intermediate buffers.
            if step % 3 == 0 || position == wire.len() {
                let mut bytes = [0u8; 2048];
                let n = m.peek(0, &mut bytes).unwrap();
                if n != 0 {
                    let mut input = Cursor::new(&bytes[..n]);
                    while input.position() < n as u64 {
                        assert!(app.read_tls(&mut input).unwrap() > 0);
                        app.process_new_packets().unwrap();
                        let mut plain = [0u8; 16384];
                        loop {
                            match app.reader().read(&mut plain) {
                                Ok(0) => { clean_eof = true; break; },
                                Ok(n) => received.extend_from_slice(&plain[..n]),
                                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                                Err(e) => panic!("{e}"),
                            }
                        }
                    }
                    m.consume(0, n).unwrap();
                }
            }
            if m.shutdown_output(0) { break; }
        }
        assert_eq!(position, wire.len());
        assert!(saw_backpressure && clean_eof);
        assert_eq!(received.len(), payload.len());
        assert_eq!(received, payload);
        assert!(m.shutdown_output(0));
    }
}

#[test]
fn tls_backpressure_is_directional_and_unclean_eof_drains_authenticated_bytes() {
    for tls12 in [true, false] {
        let f = Fixture::new();
        let mut m = f.session();
        let (mut app, mut origin) = f.endpoints(tls12, true);
        for _ in 0..30 { exchange(&mut m, &mut app, &mut origin, 4096).unwrap(); }
        let mut uploaded = 0;
        while m.can_read_side(0) {
            app.writer().write_all(&[b'x'; 1024]).unwrap();
            let mut wire = Vec::new(); app.write_tls(&mut wire).unwrap();
            for chunk in wire.chunks(4096) { m.feed(0, chunk).unwrap(); }
            uploaded += 1024;
            assert!(uploaded < 2 * session::HIGH_WATER);
        }
        assert!(m.can_read_side(1), "a blocked upload must not block its early response");
        let response = b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n";
        origin.writer().write_all(response).unwrap();
        let mut wire = Vec::new(); origin.write_tls(&mut wire).unwrap();
        for chunk in wire.chunks(4096) { m.feed(1, chunk).unwrap(); }
        let mut bytes = [0u8; 4096];
        loop {
            let n = m.peek(0, &mut bytes).unwrap(); if n == 0 { break; }
            app.read_tls(&mut Cursor::new(&bytes[..n])).unwrap();
            app.process_new_packets().unwrap(); m.consume(0, n).unwrap();
        }
        let mut received = Vec::new(); let _ = app.reader().read_to_end(&mut received);
        assert_eq!(received, response);

        // Model a slow receiving socket: withhold output until TCP EOF arrives.
        let mut m = f.session();
        let (mut app, mut origin) = f.endpoints(tls12, true);
        for _ in 0..30 { exchange(&mut m, &mut app, &mut origin, 4096).unwrap(); }
        let body: Vec<u8> = (0..128 * 1024).map(|i| (i % 251) as u8).collect();
        origin.set_buffer_limit(None); origin.writer().write_all(&body).unwrap();
        let mut wire = Vec::new(); origin.write_tls(&mut wire).unwrap();
        for chunk in wire.chunks(4096) { m.feed(1, chunk).unwrap(); }
        m.input_eof(1).unwrap();
        assert!(!m.can_read_side(0) && !m.can_read_side(1));
        let mut received = Vec::new();
        loop {
            let n = m.peek(0, &mut bytes).unwrap(); if n == 0 { break; }
            let mut input = Cursor::new(&bytes[..n]);
            while input.position() < n as u64 {
                assert!(app.read_tls(&mut input).unwrap() > 0);
                let state = app.process_new_packets().unwrap();
                assert!(!state.peer_has_closed(), "do not fabricate close_notify");
                let _ = app.reader().read_to_end(&mut received);
            }
            m.consume(0, n).unwrap();
        }
        assert_eq!(received, body);
        assert!(!m.shutdown_output(0));
        assert!(m.tick().unwrap_err().contains("upstream TCP EOF without close_notify"));
    }
}

#[test]
fn persistent_ca_and_signed_leaf() {
    let f = Fixture::new();
    let reloaded = pki::Authority::load(&f.path, false).unwrap();
    assert_eq!(reloaded.der, f.context.ca.der);
    assert_eq!(reloaded.id, f.context.ca.id);
    let params = rcgen::CertificateParams::from_ca_cert_der(&reloaded.der).unwrap();
    assert_eq!(
        params.distinguished_name.get(&rcgen::DnType::CommonName),
        Some(&rcgen::DnValue::Utf8String("ProxyLane CA".into()))
    );
    assert_eq!(
        reloaded
            .leaf("localhost", f.context.crl.port())
            .unwrap()
            .cert
            .len(),
        1
    );
    assert!(!std::fs::read_to_string(f.path.join("ca.json"))
        .unwrap()
        .contains("PRIVATE KEY"));
    let leaf = reloaded.leaf("validity.test", f.context.crl.port()).unwrap();
    let cert = rcgen::CertificateParams::from_ca_cert_der(&leaf.cert[0]).unwrap();
    let remaining = cert.not_after.unix_timestamp() - time::OffsetDateTime::now_utc().unix_timestamp();
    assert!((14 * 86400 - 10..=14 * 86400).contains(&remaining));
    assert!(!reloaded.crl().unwrap().is_empty());
}

#[test]
fn crl_port_fallback_certificate_cache_and_independent_lifetimes() {
    use std::net::{TcpListener, TcpStream};
    let f = Fixture::new();
    let saved = std::fs::read(f.path.join("ca.json")).unwrap();
    let blocker = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let preferred = blocker.local_addr().unwrap().port();
    let mut ca = pki::Authority::load(&f.path, false).unwrap();
    ca.port = preferred;
    let ca = Arc::new(ca);
    let first = ca.serve_crl().unwrap();
    let second = ca.serve_crl().unwrap();
    assert_ne!(first.port(), preferred);
    assert_ne!(first.port(), second.port());
    let a = ca.leaf("localhost", first.port()).unwrap();
    let b = ca.leaf("localhost", second.port()).unwrap();
    assert_ne!(a.cert[0], b.cert[0]);
    assert!(Arc::ptr_eq(
        &a,
        &ca.leaf("localhost", first.port()).unwrap()
    ));
    assert!(Arc::ptr_eq(
        &b,
        &ca.leaf("localhost", second.port()).unwrap()
    ));
    for (cert, port) in [(&a, first.port()), (&b, second.port())] {
        let url = format!("http://127.0.0.1:{port}/pki/{}.crl", ca.id);
        assert!(cert.cert[0].windows(url.len()).any(|w| w == url.as_bytes()));
    }
    let get = |port: u16| {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .unwrap();
        write!(
            stream,
            "GET /pki/{}.crl HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            ca.id
        )
        .unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).unwrap();
        assert!(bytes.starts_with(b"HTTP/1.1 200 OK\r\n"));
        let body = bytes.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        assert!(!bytes[body..].is_empty());
    };
    get(first.port());
    get(second.port());
    let port = first.port();
    drop(first);
    assert!(TcpStream::connect(("127.0.0.1", port)).is_err());
    get(second.port());
    drop(blocker);
    let third = ca.serve_crl().unwrap();
    assert_eq!(third.port(), preferred);
    get(third.port());
    assert_eq!(std::fs::read(f.path.join("ca.json")).unwrap(), saved);
    assert_eq!(ca.der, f.context.ca.der);
    assert!(ca.leaf("localhost", 0).is_err());
}

#[test]
fn passthrough_fragmentation_server_first_and_half_close() {
    let f = Fixture::new();
    let mut records: Vec<(u32, Vec<u8>)> = Vec::new();
    let mut m = f.session();
    m.observer = Some((observe, &mut records as *mut _ as usize));
    m.feed(0, &[0x16]).unwrap();
    assert!(
        records.is_empty(),
        "do not display unclassified TLS prefixes"
    );
    m.feed(0, b"ordinary data").unwrap();
    let mut buf = [0u8; 128];
    let n = m.peek(1, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"\x16ordinary data");
    m.input_eof(0).unwrap();
    assert!(!m.shutdown_output(1));
    m.consume(1, n).unwrap();
    assert!(m.shutdown_output(1));
    m.feed(1, b"reply after FIN").unwrap();
    assert_eq!(m.peek(0, &mut buf).unwrap(), 15);
    assert_eq!(
        records,
        vec![
            (3, b"\x16ordinary data".to_vec()),
            (4, b"reply after FIN".to_vec())
        ]
    );
    records.clear();
    let mut m = f.session();
    m.observer = Some((observe, &mut records as *mut _ as usize));
    m.feed(1, b"220 server first\r\n").unwrap();
    assert_eq!(m.peek(0, &mut buf).unwrap(), 18);
    assert_eq!(records, vec![(4, b"220 server first\r\n".to_vec())]);
}

#[test]
fn legacy_ca_location_migrates_without_replacing_identity_or_new_ca() {
    let f = Fixture::new();
    let legacy = f.path.join("mitm");
    std::fs::create_dir(&legacy).unwrap();
    std::fs::rename(f.path.join("ca.json"), legacy.join("ca.json")).unwrap();
    pki::migrate_legacy(&f.path).unwrap();
    assert!(!legacy.join("ca.json").exists());
    assert_eq!(
        pki::Authority::load(&f.path, false).unwrap().der,
        f.context.ca.der
    );
    // Even a stale/different legacy file must not replace an existing root CA.
    std::fs::write(legacy.join("ca.json"), b"obsolete").unwrap();
    pki::migrate_legacy(&f.path).unwrap();
    assert_eq!(
        pki::Authority::load(&f.path, false).unwrap().der,
        f.context.ca.der
    );
}

#[test]
fn bounded_passthrough_preserves_bytes() {
    let f = Fixture::new();
    let mut m = f.session();
    let data = [b'x'; 16384];
    let mut total = 0;
    while m.can_read() {
        m.feed(0, &data).unwrap();
        total += data.len();
    }
    assert!(total <= session::HIGH_WATER);
    let mut count = 0;
    let mut buf = [0u8; 997];
    loop {
        let n = m.peek(1, &mut buf).unwrap();
        if n == 0 {
            break;
        }
        assert!(buf[..n].iter().all(|&b| b == b'x'));
        m.consume(1, n).unwrap();
        count += n;
    }
    assert_eq!(total, count);
    assert!(m.can_read());
}

#[test]
fn tls12_tls13_fragmented_hello_alpn_payload_close() {
    for tls12 in [true, false] {
        let f = Fixture::new();
        let mut records: Vec<(u32, Vec<u8>)> = Vec::new();
        // An unusable capture path must not affect TLS or observer delivery.
        let blocked_capture_path = f.path.join("captures");
        std::fs::write(&blocked_capture_path, b"not a directory").unwrap();
        let mut m = f.session();
        unsafe {
            plm_observe(&mut m, observe, &mut records as *mut _ as usize);
        }
        let (mut app, mut origin) = f.endpoints(tls12, true);
        for _ in 0..30 {
            exchange(&mut m, &mut app, &mut origin, 1).unwrap();
            if m.ready() && !app.is_handshaking() {
                break;
            }
        }
        assert!(m.ready());
        assert!(!app.is_handshaking());
        assert_eq!(app.alpn_protocol(), Some(b"http/1.1".as_slice()));
        assert_eq!(origin.alpn_protocol(), app.alpn_protocol());
        let data = vec![b'Z'; 128 * 1024];
        let mut actual = vec![];
        for chunk in data.chunks(8192) {
            app.writer().write_all(chunk).unwrap();
            exchange(&mut m, &mut app, &mut origin, 4096).unwrap();
            let _ = origin.reader().read_to_end(&mut actual);
        }
        assert_eq!(actual, data);
        origin.writer().write_all(b"response").unwrap();
        origin.send_close_notify();
        for _ in 0..8 {
            exchange(&mut m, &mut app, &mut origin, 17).unwrap();
        }
        let mut response = vec![];
        app.reader().read_to_end(&mut response).unwrap();
        assert_eq!(response, b"response");
        app.send_close_notify();
        for _ in 0..8 {
            exchange(&mut m, &mut app, &mut origin, 17).unwrap();
        }
        assert!(m.shutdown_output(0));
        assert!(m.shutdown_output(1));
        let captured: Vec<u8> = records
            .iter()
            .filter(|r| r.0 == 1)
            .flat_map(|r| r.1.clone())
            .collect();
        let reply: Vec<u8> = records
            .iter()
            .filter(|r| r.0 == 2)
            .flat_map(|r| r.1.clone())
            .collect();
        assert_eq!(captured, data, "observer must preserve all plaintext bytes");
        assert_eq!(reply, b"response");
        assert_eq!(
            std::fs::read(&blocked_capture_path).unwrap(),
            b"not a directory"
        );
        m.input_eof(0).unwrap();
        m.input_eof(1).unwrap();
        drop(m);
        assert!(
            records.iter().all(|r| r.0 == 1 || r.0 == 2),
            "TLS monitor must contain only plaintext, without handshake/closed JSON or ciphertext"
        );
    }
}

#[test]
fn realtime_tls_protocol_without_monitor_observer_and_authenticated_eof() {
    for clean in [true, false] {
        let f = Fixture::new();
        let runtime = crate::protocol::Runtime::new(proxylane_protocol::cache::CacheConfig {
            root: f.path.join("payload"),
            ..Default::default()
        })
        .unwrap();
        let directory = f.path.join("payload");
        let mut m = f.session();
        m.enable_protocol(
            runtime.clone(),
            proxylane_protocol::Connection {
                id: "123/456".into(),
                pid: 123,
                socket: 456,
                generation: 7,
                process_start: 987,
                destination: "localhost:8443".into(),
                ..Default::default()
            },
        );
        assert!(m.observer.is_none()); // GUI monitoring is off.
        let (mut app, mut origin) = f.endpoints(false, true);
        for _ in 0..30 {
            exchange(&mut m, &mut app, &mut origin, 3).unwrap();
        }
        app.writer()
            .write_all(b"GET /eof HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        for _ in 0..4 {
            exchange(&mut m, &mut app, &mut origin, 17).unwrap();
        }
        let mut received = Vec::new();
        let _ = origin.reader().read_to_end(&mut received);
        assert!(received.starts_with(b"GET /eof"));
        origin
            .writer()
            .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nplaintext")
            .unwrap();
        if clean {
            origin.send_close_notify();
        }
        for _ in 0..8 {
            exchange(&mut m, &mut app, &mut origin, 7).unwrap();
        }
        if !clean {
            m.input_eof(1).unwrap();
        }
        drop(m);
        let result = runtime.query(&json!({"type":"poll"})).unwrap();
        let records = result["records"].as_array().unwrap();
        let flow = records.iter().find(|r| r["type"] == "exchange").unwrap();
        assert_eq!(flow["connection"]["process_start"], 987);
        assert_eq!(flow["exchange"]["response"]["complete"], clean, "{result}");
        assert_eq!(flow["exchange"]["response"]["body_bytes"], 9);
        runtime.shutdown().unwrap();
        assert_eq!(std::fs::read_dir(directory).unwrap().count(), 1); // manager.lock only
    }
}

#[test]
fn realtime_h2_alpn_hpack_interleaved_streams_and_cached_decode() {
    use base64::Engine;
    let f = Fixture::new();
    let runtime = crate::protocol::Runtime::new(proxylane_protocol::cache::CacheConfig {
        root: f.path.join("payload"),
        ..Default::default()
    })
    .unwrap();
    let mut m = f.session();
    m.enable_protocol(
        runtime.clone(),
        proxylane_protocol::Connection {
            id: "h2".into(),
            pid: 123,
            generation: 8,
            ..Default::default()
        },
    );
    let (mut app, mut origin) = f.endpoints_alpn(false, true, b"h2");
    for _ in 0..30 {
        exchange(&mut m, &mut app, &mut origin, 3).unwrap();
    }
    assert_eq!(app.alpn_protocol(), Some(b"h2".as_slice()));
    // Fixture generated by Python's independent h2/HPACK implementation.
    for line in include_str!("../../ProxyLaneProtocol/fixtures/demo.jsonl").lines() {
        let event: serde_json::Value = serde_json::from_str(line).unwrap();
        if event["connection_id"] != "fixture-h2" || event["type"] != "data" {
            continue;
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(event["data_base64"].as_str().unwrap())
            .unwrap();
        if event["direction"] == "client" {
            app.writer().write_all(&bytes).unwrap();
        } else {
            origin.writer().write_all(&bytes).unwrap();
        }
        for _ in 0..4 {
            exchange(&mut m, &mut app, &mut origin, 11).unwrap();
        }
        let _ = app.reader().read_to_end(&mut Vec::new());
        let _ = origin.reader().read_to_end(&mut Vec::new());
    }
    drop(m);
    let result = runtime.query(&json!({"type":"poll"})).unwrap();
    let records: Vec<_> = result["records"].as_array().unwrap().iter().filter(|r|r["type"]=="exchange").collect();
    assert_eq!(records.len(), 2, "{result}");
    assert_eq!(records[0]["exchange"]["id"], 3);
    assert_eq!(records[1]["exchange"]["id"], 1);
    for flow in records {
        assert_eq!(flow["protocol"], "h2");
        assert_eq!(flow["exchange"]["response"]["complete"], true);
        assert_eq!(flow["exchange"]["response"]["decoding"], "ok");
        let payload = runtime
            .query(&json!({"type":"cache_decode", "run_id":runtime.run_id,
            "cache_id":flow["exchange"]["cache"]["id"], "direction":"server"}))
            .unwrap();
        assert_eq!(
            payload["payload"]["data_base64"],
            flow["exchange"]["response"]["decoded_base64"]
        );
    }
    runtime.shutdown().unwrap();
}

#[test]
fn h2_settings_in_the_tls_handshake_flight_are_captured_before_ack() {
    fn frame(kind:u8,flags:u8,id:u32,payload:&[u8])->Vec<u8> {
        let mut bytes=(payload.len() as u32).to_be_bytes()[1..].to_vec();
        bytes.extend([kind,flags]);bytes.extend(id.to_be_bytes());bytes.extend(payload);bytes
    }
    for tls12 in [false,true] {
        let f=Fixture::new();
        let runtime=crate::protocol::Runtime::new(proxylane_protocol::cache::CacheConfig {
            root:f.path.join("recording"),recording:Some(proxylane_protocol::recording::RecordingConfig{total_bytes:8*1024*1024,min_free_bytes:0}),..Default::default()
        }).unwrap();
        let mut m=f.session();m.enable_protocol(runtime.clone(),proxylane_protocol::Connection{id:"early-h2".into(),..Default::default()});
        let (mut app,mut origin)=f.endpoints_alpn(tls12,true,b"h2");
        // The server sends its SETTINGS immediately, bundled with the final handshake flight.
        let settings=frame(4,0,0,&[0,1,0,0,0,0]);origin.writer().write_all(&settings).unwrap();
        for _ in 0..30 {exchange(&mut m,&mut app,&mut origin,65536).unwrap();}
        let mut received=Vec::new();let _=app.reader().read_to_end(&mut received);assert_eq!(received,settings);
        let mut request=b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();request.extend(frame(4,0,0,&[]));
        request.extend(frame(4,1,0,&[]));request.extend(frame(1,5,1,&[0x82,0x87,0x84]));app.writer().write_all(&request).unwrap();
        for _ in 0..4 {exchange(&mut m,&mut app,&mut origin,65536).unwrap();}
        let mut response=frame(4,1,0,&[]);response.extend(frame(1,4,1,&[0x88]));response.extend(frame(0,1,1,b"hello"));origin.writer().write_all(&response).unwrap();
        for _ in 0..4 {exchange(&mut m,&mut app,&mut origin,65536).unwrap();}
        let result=runtime.query(&json!({"type":"poll"})).unwrap();
        assert!(!runtime.recording_failed(),"{result}");
        assert!(result["records"].as_array().unwrap().iter().any(|r|r["type"]=="exchange" && r["exchange"]["response"]["body_bytes"]==5),"{result}");
        runtime.stop_capture().unwrap();runtime.shutdown().unwrap();
    }
}

#[test]
fn abrupt_tls_eof_silences_application_close_but_never_fakes_clean_close() {
    for tls12 in [true, false] {
        for side in 0..2 {
            let f = Fixture::new();
            let runtime = crate::protocol::Runtime::new(proxylane_protocol::cache::CacheConfig {
                root: f.path.join("close-status"), ..Default::default()
            }).unwrap();
            let mut records: Vec<(u32, Vec<u8>)> = Vec::new();
            let mut m = f.session();
            m.enable_protocol(runtime.clone(), proxylane_protocol::Connection {
                id: "abrupt-close".into(), ..Default::default()
            });
            m.observer = Some((observe, &mut records as *mut _ as usize));
            let (mut app, mut origin) = f.endpoints(tls12, true);
            for _ in 0..30 {
                exchange(&mut m, &mut app, &mut origin, 7).unwrap();
                if m.ready() && !app.is_handshaking() {
                    break;
                }
            }
            assert!(m.ready());
            origin.writer().write_all(b"partial response").unwrap();
            exchange(&mut m, &mut app, &mut origin, 17).unwrap();
            m.input_eof(side).unwrap();
            let mut pending = [0u8; 16384];
            for output in 0..2 {
                loop {
                    let n = m.peek(output, &mut pending).unwrap();
                    if n == 0 { break; }
                    m.consume(output, n).unwrap();
                }
            }
            let error = m.tick().unwrap_err();
            assert!(error.contains(if side == 0 {
                "application TCP EOF"
            } else {
                "upstream TCP EOF"
            }));
            assert!(
                !m.shutdown_output(1 - side),
                "truncation must not become authenticated TLS EOF"
            );
            m.fail(error.clone());
            m.fail(error.clone());
            drop(m);
            let errors: Vec<_> = records.iter().filter(|r| r.0 == 0).collect();
            if side == 0 {
                assert!(errors.is_empty(), "routine application close must not report an error");
            } else {
                assert_eq!(errors.len(), 1);
                assert_eq!(errors[0].1, error.as_bytes());
            }
            let result = runtime.query(&json!({"type":"poll"})).unwrap();
            let statuses = result["records"].as_array().unwrap();
            if side == 0 {
                assert!(statuses.iter().any(|r| r["status"] == "Closed"), "{result}");
                assert!(!statuses.iter().any(|r| r["status"] == "Failed"), "{result}");
            } else {
                assert!(statuses.iter().any(|r| r["status"] == "Closed" && r["detail"].as_str().is_some_and(|s|s.contains("upstream TCP EOF"))), "{result}");
                assert!(!statuses.iter().any(|r| r["status"] == "Failed"), "{result}");
            }
            runtime.shutdown().unwrap();
        }
    }
}

#[test]
fn application_tls_record_errors_are_still_reported() {
    for tls12 in [true, false] {
        let f = Fixture::new();
        let mut records: Vec<(u32, Vec<u8>)> = Vec::new();
        let mut m = f.session();
        m.observer = Some((observe, &mut records as *mut _ as usize));
        let (mut app, mut origin) = f.endpoints(tls12, true);
        for _ in 0..30 { exchange(&mut m, &mut app, &mut origin, 65536).unwrap(); }
        assert!(m.ready());
        app.writer().write_all(b"damaged application record").unwrap();
        let mut wire = Vec::new();
        while app.wants_write() { app.write_tls(&mut wire).unwrap(); }
        *wire.last_mut().unwrap() ^= 1;
        let error = m.feed(0, &wire).unwrap_err();
        m.fail(error.clone());
        drop(m);
        let errors: Vec<_> = records.iter().filter(|r| r.0 == 0).collect();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].1, error.as_bytes());
    }
}

#[test]
fn invalid_upstream_identity_fails_before_client_certificate() {
    let f = Fixture::new();
    let mut m = f.session();
    let (mut app, mut origin) = f.endpoints(false, false);
    let mut error = None;
    for _ in 0..30 {
        if let Err(e) = exchange(&mut m, &mut app, &mut origin, 7) {
            error = Some(e);
            break;
        }
    }
    let error = error.unwrap();
    assert!(error.contains("not valid for name"), "{error}");
    assert!(app.peer_certificates().is_none());
}

#[test]
fn malformed_tls_never_falls_back_and_truncated_tls_fails() {
    let f = Fixture::new();
    let mut m = f.session();
    assert!(m.feed(0, &[0x16, 3, 3, 0, 4, 0xff, 0, 0, 0]).is_err());
    assert_ne!(m.state, 1);
    let mut m = f.session();
    m.feed(0, &[0x16, 3]).unwrap();
    assert!(m.input_eof(0).is_err());
}

#[test]
fn ip_san_without_sni_and_untrusted_issuer() {
    let f = Fixture::new();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(f.context.roots.clone())
        .with_no_client_auth();
    let mut app =
        ClientConnection::new(Arc::new(config), ServerName::try_from("127.0.0.1").unwrap())
            .unwrap();
    #[derive(Debug)]
    struct Resolver(Arc<rustls::sign::CertifiedKey>);
    impl rustls::server::ResolvesServerCert for Resolver {
        fn resolve(
            &self,
            _: rustls::server::ClientHello<'_>,
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            Some(self.0.clone())
        }
    }
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Resolver(
            f.context
                .ca
                .leaf("127.0.0.1", f.context.crl.port())
                .unwrap(),
        )));
    let mut origin = ServerConnection::new(Arc::new(config)).unwrap();
    let mut m = Session::new(f.context.clone(), "127.0.0.1".into(), json!({}), false).unwrap();
    for _ in 0..30 {
        exchange(&mut m, &mut app, &mut origin, 3).unwrap();
        if m.ready() && !app.is_handshaking() {
            break;
        }
    }
    assert!(m.ready());
    assert!(!app.is_handshaking());

    let unrelated = rcgen::generate_simple_self_signed(vec!["unrelated.invalid".into()]).unwrap();
    let mut unrelated_roots = RootCertStore::empty();
    unrelated_roots.add(unrelated.cert.der().clone()).unwrap();
    let untrusted = Arc::new(Context {
        crl: f.context.ca.serve_crl().unwrap(),
        ca: f.context.ca.clone(),
        roots: Arc::new(RootCertStore::empty()),
        verifier: rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(unrelated_roots), Arc::new(rustls::crypto::ring::default_provider())).build().unwrap(),
        async_handshake: false,
    });
    let mut m = Session::new(untrusted, "localhost".into(), json!({}), false).unwrap();
    let (mut app, mut origin) = f.endpoints(false, true);
    let mut error = None;
    for _ in 0..30 {
        if let Err(e) = exchange(&mut m, &mut app, &mut origin, 11) {
            error = Some(e);
            break;
        }
    }
    assert!(error.unwrap().contains("UnknownIssuer"));
    assert!(app.peer_certificates().is_none());
}

#[test]
fn opaque_tls_and_passthrough_use_the_shared_stream_cache() {
    use base64::Engine;
    let f = Fixture::new();
    for (tls, bypass) in [(false, false), (false, true), (true, false), (true, true)] {
        let runtime = crate::protocol::Runtime::new(proxylane_protocol::cache::CacheConfig {
            root: f.path.join("streams"), ..Default::default()
        }).unwrap();
        let mut m = f.session();
        if bypass { m.skip_verification_for_test(); }
        m.enable_protocol(runtime.clone(), proxylane_protocol::Connection { id: "opaque".into(), ..Default::default() });
        if tls {
            let (mut app, mut origin) = f.endpoints_alpn(false, true, b"mqtt");
            for _ in 0..30 { exchange(&mut m, &mut app, &mut origin, 3).unwrap(); }
            assert_eq!(app.alpn_protocol(), Some(b"mqtt".as_slice()));
            app.writer().write_all(b"\x00PING").unwrap();
            origin.writer().write_all(b"\x00PONG").unwrap();
            for _ in 0..8 { exchange(&mut m, &mut app, &mut origin, 7).unwrap(); }
            app.send_close_notify(); origin.send_close_notify();
            for _ in 0..8 { exchange(&mut m, &mut app, &mut origin, 7).unwrap(); }
        } else {
            m.feed(0, b"\x00PING").unwrap(); m.feed(1, b"\x00PONG").unwrap();
            m.input_eof(0).unwrap(); m.input_eof(1).unwrap();
        }
        drop(m);
        let result = runtime.query(&json!({"type":"poll","limit":64})).unwrap();
        let last = result["records"].as_array().unwrap().iter().rev().find(|r|r["type"]=="stream").unwrap();
        assert_eq!(last["type"], "stream");
        assert_eq!(last["protocol"], if tls {"tls_stream"} else {"tcp"});
        assert_eq!(last["connection"]["upstream_verification_skipped"], tls && bypass);
        if !tls {
            for row in result["records"].as_array().unwrap() {
                assert_ne!(row["upstream_verification_skipped"], true);
                assert_ne!(row["connection"]["upstream_verification_skipped"], true);
            }
        }
        assert_eq!(last["stream"]["complete"], true);
        for (side, expected) in [("client", b"\x00PING"), ("server", b"\x00PONG")] {
            let reply = runtime.query(&json!({"type":"cache_read","run_id":runtime.run_id,
                "cache_id":last["stream"]["cache"]["id"], "direction":side,"length":65536})).unwrap();
            assert_eq!(base64::engine::general_purpose::STANDARD.decode(reply["payload"]["data_base64"].as_str().unwrap()).unwrap(), expected);
        }
        runtime.shutdown().unwrap();
    }
}

#[test]
fn certificate_bypass_is_session_scoped_and_idle_tls_has_lifecycle() {
    let f = Fixture::new();
    let untrusted = Fixture::new();
    for tls12 in [false, true] {
        let runtime = crate::protocol::Runtime::new(proxylane_protocol::cache::CacheConfig {
            root:f.path.join("lifecycle"), ..Default::default()
        }).unwrap();
        let mut session = f.session();
        session.skip_verification_for_test();
        session.enable_protocol(runtime.clone(), proxylane_protocol::Connection {id:"idle".into(), ..Default::default()});
        let initial=runtime.query(&json!({"type":"poll"})).unwrap();
        assert_eq!(initial["records"][0]["status"],"Connecting");
        let (mut app, _) = f.endpoints(tls12,true);
        let (_, mut origin) = untrusted.endpoints(tls12,false); // both untrusted issuer and wrong hostname
        for _ in 0..40 { exchange(&mut session,&mut app,&mut origin,7).unwrap(); }
        assert!(session.ready());
        let idle=runtime.query(&json!({"type":"poll","after":initial["next"]})).unwrap();
        let established=idle["records"].as_array().unwrap().iter().find(|r|r["status"]=="Established").unwrap();
        assert_eq!(established["protocol"],"http1");
        assert_eq!(established["upstream_verification_skipped"],true);
        assert!(idle["records"].as_array().unwrap().iter().all(|r|r["type"]=="connection"));
        assert_eq!(runtime.query(&json!({"type":"stats"})).unwrap()["cache"]["retained_bytes"].as_u64().unwrap_or(0),0);
        drop(session);
        assert!(runtime.query(&json!({"type":"poll","after":idle["next"]})).unwrap()["records"].as_array().unwrap().iter().any(|r|r["status"]=="Closed"));
        let mut strict=f.session(); // bypass did not change other/new sessions
        strict.enable_protocol(runtime.clone(),proxylane_protocol::Connection {id:"failed".into(),..Default::default()});
        let (mut app,_)=f.endpoints(tls12,true);let (_,mut origin)=untrusted.endpoints(tls12,false);
        let error=(0..40).find_map(|_|exchange(&mut strict,&mut app,&mut origin,7).err()).expect("strict verification must reject");
        strict.fail(error);drop(strict);
        let result=runtime.query(&json!({"type":"poll","limit":64})).unwrap();
        assert!(result["records"].as_array().unwrap().iter().any(|r|r["connection"]["id"]=="failed" && r["status"]=="Failed"));
        runtime.shutdown().unwrap();
    }
}

#[test]
fn realtime_tls_h2_doh_get_post_and_gzip() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let f=Fixture::new();
    let runtime=crate::protocol::Runtime::new(proxylane_protocol::cache::CacheConfig {
        root:f.path.join("doh-h2"),..Default::default()
    }).unwrap();
    let mut m=f.session();
    m.enable_protocol(runtime.clone(),proxylane_protocol::Connection {id:"doh-h2".into(),pid:123,..Default::default()});
    let (mut app,mut origin)=f.endpoints_alpn(false,true,b"h2");
    for _ in 0..30 {exchange(&mut m,&mut app,&mut origin,7).unwrap();}
    // Independent Python hyper-h2/HPACK fixture; includes GET, POST and gzip replies.
    for line in include_str!("../testdata/doh-http2.jsonl").lines() {
        let event:serde_json::Value=serde_json::from_str(line).unwrap();
        let bytes=STANDARD.decode(event["data"].as_str().unwrap()).unwrap();
        if event["side"]==0 {app.writer().write_all(&bytes).unwrap();}else{origin.writer().write_all(&bytes).unwrap();}
        for _ in 0..4 {exchange(&mut m,&mut app,&mut origin,11).unwrap();}
        let _=app.reader().read_to_end(&mut Vec::new());let _=origin.reader().read_to_end(&mut Vec::new());
    }
    let result=runtime.query(&json!({"type":"poll","limit":64})).unwrap();
    let rows:Vec<_>=result["records"].as_array().unwrap().iter().filter(|r|r["type"]=="exchange").collect();
    assert_eq!(rows.len(),2);
    for row in rows {
        assert_eq!(row["protocol"],"h2");assert_eq!(row["connection"]["pid"],123);assert!(row.get("doh").is_some());
        let reply=runtime.query(&json!({"type":"doh_read","run_id":runtime.run_id,"cache_id":row["exchange"]["cache"]["id"],"direction":"server"})).unwrap();
        assert!(reply["text"].as_str().unwrap().contains("1.2.3.4"));
        if row["exchange"]["request"]["method"]=="GET" {assert!(row["doh"]["request_get"].as_str().unwrap().contains("a."));}
    }
    drop(m);runtime.shutdown().unwrap();
}

#[test]
fn stopping_monitor_preserves_tls_transport_and_freezes_capture() {
    for tls12 in [false, true] {
        for alpn in [b"http/1.1".as_slice(), b"h2".as_slice()] {
            let f = Fixture::new();
            let runtime = protocol::Runtime::new(proxylane_protocol::cache::CacheConfig {
                root: f.path.join("stop-cache"), ..Default::default()
            }).unwrap();
            let mut m = f.session();
            m.enable_protocol(runtime.clone(), proxylane_protocol::Connection { id:"stop-test".into(), ..Default::default() });
            // Also cover a connection whose ClientHello has not arrived at stop.
            let mut delayed = f.session();
            delayed.enable_protocol(runtime.clone(), proxylane_protocol::Connection { id:"delayed".into(), ..Default::default() });
            let (mut app, mut origin) = f.endpoints_alpn(tls12, true, alpn);
            for _ in 0..30 { exchange(&mut m, &mut app, &mut origin, 17).unwrap(); }
            assert!(m.ready());
            let request = if alpn==b"h2" { b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".as_slice() }
                else { b"POST /before HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\nbefore".as_slice() };
            app.writer().write_all(request).unwrap();
            for _ in 0..4 { exchange(&mut m, &mut app, &mut origin, 17).unwrap(); }
            let mut received=Vec::new(); let _=origin.reader().read_to_end(&mut received);
            assert_eq!(received,request);
            runtime.stop_capture().unwrap();
            let snapshot=runtime.query(&json!({"type":"stats"})).unwrap();
            assert_eq!(snapshot["active_connections"],0);
            let records=runtime.query(&json!({"type":"poll","limit":64})).unwrap();
            for resume in [false,true] {
                if resume { runtime.start_capture(); }
                // More than the TLS high-water limit in total, on the SAME TLS connection.
                for _ in 0..40 {
                    let bytes=vec![0x65;16384];
                    app.writer().write_all(&bytes).unwrap(); origin.writer().write_all(&bytes).unwrap();
                    for _ in 0..3 { exchange(&mut m,&mut app,&mut origin,4096).unwrap(); }
                    let mut upstream=Vec::new();let _=origin.reader().read_to_end(&mut upstream);
                    let mut downstream=Vec::new();let _=app.reader().read_to_end(&mut downstream);
                    assert_eq!(upstream,bytes);assert_eq!(downstream,bytes);
                }
                assert_eq!(runtime.query(&json!({"type":"stats"})).unwrap(),snapshot);
                assert_eq!(runtime.query(&json!({"type":"poll","limit":64})).unwrap(),records);
            }
            let (mut later_app,mut later_origin)=f.endpoints_alpn(tls12,true,alpn);
            for _ in 0..30 {exchange(&mut delayed,&mut later_app,&mut later_origin,17).unwrap();}
            assert!(delayed.ready());
            assert_eq!(runtime.query(&json!({"type":"stats"})).unwrap(),snapshot);
            drop(delayed);drop(m);
            assert_eq!(runtime.query(&json!({"type":"stats"})).unwrap(),snapshot);
            assert!(runtime.tap(Default::default(),None).is_some(),"new captures can start after resuming");
            runtime.shutdown().unwrap();
        }
    }
}
