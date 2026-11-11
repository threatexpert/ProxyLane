//! Isolated feasibility probe, NOT a shipping transparent QUIC proxy.
//! All test output is selected by the runner under build/qa. No trust changes.
use bytes::{Buf, Bytes};
use proxylane_mitm::{pki::Authority, windows};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::{
    net::{SocketAddr, ToSocketAddrs},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
mod route_socket;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const BODY_LIMIT: usize = 8 * 1024 * 1024; // Probe only; production must stream bodies.
struct AbortDriver(tokio::task::JoinHandle<h3::error::ConnectionError>);
impl Drop for AbortDriver {
    fn drop(&mut self) {
        self.0.abort();
    }
}
struct CloseConnection(quinn::Connection);
impl Drop for CloseConnection {
    fn drop(&mut self) {
        self.0.close(0u32.into(), b"probe connection finished");
    }
}

#[derive(Clone, Deserialize)]
struct Config {
    role: String,
    listen: SocketAddr,
    ca_directory: PathBuf,
    name: String,
    upstream: Option<String>,
    upstream_ca: Option<PathBuf>,
    ready: PathBuf,
    stop: PathBuf,
    // Test-only override: bootstrap still uses the trusted ProxyLane certificate.
    // This allows negative QUIC certificate cases without bypassing TCP trust.
    quic_certificate: Option<PathBuf>,
    quic_key: Option<PathBuf>,
    close_connections: Option<PathBuf>,
}

#[derive(Debug)]
struct Leaf {
    cert: Arc<CertifiedKey>,
    name: String,
}
impl ResolvesServerCert for Leaf {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // A single explicitly configured test origin. Never sign arbitrary hosts.
        (hello.server_name() == Some(self.name.as_str())).then(|| self.cert.clone())
    }
}

fn transport() -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    t.max_concurrent_bidi_streams(32u32.into());
    t.max_concurrent_uni_streams(8u32.into());
    t.max_idle_timeout(Some(Duration::from_secs(12).try_into().unwrap()));
    t.stream_receive_window((256 * 1024u32).into());
    t.receive_window((1024 * 1024u32).into());
    t.send_window(1024 * 1024);
    t.datagram_receive_buffer_size(None);
    t.enable_segmentation_offload(false);
    t.mtu_discovery_config(None);
    Arc::new(t)
}

fn client(root: &PathBuf, address: SocketAddr) -> Result<quinn::Endpoint> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from(std::fs::read(
        root,
    )?))?;
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.enable_early_data = false;
    let mut config = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
    config.transport_config(transport());
    config.version(1);
    let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        route_socket::RouteSocket::bind(address)?,
        Arc::new(quinn::TokioRuntime),
    )?;
    endpoint.set_default_client_config(config);
    Ok(endpoint)
}

async fn serve(config: Config) -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let ca = Arc::new(Authority::load(
        &config.ca_directory,
        config.role == "origin",
    )?);
    let crl = ca.serve_crl()?;
    let leaf = ca.leaf(&config.name, crl.port())?;
    let bootstrap_hash = format!("{:x}", Sha256::digest(leaf.cert[0].as_ref()));
    let selected = if let Some(path) = &config.quic_certificate {
        Arc::new(CertifiedKey::from_der(
            vec![rustls::pki_types::CertificateDer::from(std::fs::read(path)?)],
            rustls::pki_types::PrivateKeyDer::Pkcs8(
                rustls::pki_types::PrivatePkcs8KeyDer::from(std::fs::read(config.quic_key.as_ref().ok_or("missing override key")?)?)),
            &rustls::crypto::ring::default_provider())?)
    } else { leaf.clone() };
    let leaf_hash = format!("{:x}", Sha256::digest(selected.cert[0].as_ref()));
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Leaf {
            cert: selected,
            name: config.name.clone(),
        }));
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.max_early_data_size = 0;
    tls.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    tls.send_tls13_tickets = 0;
    // A TCP HTTPS bootstrap on the same test port advertises Alt-Svc. This lets
    // browsers discover h3 naturally, WITHOUT --origin-to-force-quic-on, which
    // also changes Chromium's unknown-root policy and would invalidate that test.
    let mut bootstrap_tls = tls.clone();
    bootstrap_tls.cert_resolver = Arc::new(Leaf { cert: leaf, name: config.name.clone() });
    bootstrap_tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let bootstrap_tls = Arc::new(bootstrap_tls);
    let bootstrap = std::net::TcpListener::bind(config.listen)?;
    bootstrap.set_nonblocking(true)?;
    let stop = config.stop.clone();
    let port = config.listen.port();
    std::thread::spawn(move || {
        while !stop.exists() {
            let Ok((socket, _)) = bootstrap.accept() else {
                std::thread::sleep(Duration::from_millis(20));
                continue;
            };
            // Test browser requests only; synchronous per-connection deadlines.
            socket.set_nonblocking(false).ok();
            socket.set_read_timeout(Some(Duration::from_secs(2))).ok();
            socket.set_write_timeout(Some(Duration::from_secs(2))).ok();
            let Ok(tls) = rustls::ServerConnection::new(bootstrap_tls.clone()) else {
                continue;
            };
            let mut stream = rustls::StreamOwned::new(tls, socket);
            let mut head = [0u8; 8192];
            if let Ok(n) = stream.read(&mut head) {
                let line = String::from_utf8_lossy(&head[..n])
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_string();
                println!("{}", json!({"event":"tcp_bootstrap", "request":line}));
                let body = b"<!doctype html><title>QUIC probe</title><script>async function run(){for(let i=0;i<16;i++){await new Promise(r=>setTimeout(r,500));try{let r=await fetch('/browser-probe?i='+i,{cache:'no-store'});document.title='probe '+i+' '+await r.text()}catch(e){document.title=String(e)}}}run()</script>";
                let head = format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nAlt-Svc: h3=\":{}\"; ma=60\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",body.len(),port);
                let _ = stream
                    .write_all(head.as_bytes())
                    .and_then(|_| stream.write_all(body));
                stream.conn.send_close_notify();
                stream.flush().ok();
            }
        }
    });
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    server.transport_config(transport());
    server.migration(false);
    let mut endpoint_config = quinn::EndpointConfig::default();
    endpoint_config.supported_versions(vec![1]);
    let socket = std::net::UdpSocket::bind(config.listen)?;
    let endpoint = quinn::Endpoint::new(
        endpoint_config,
        Some(server),
        socket,
        Arc::new(quinn::TokioRuntime),
    )?;
    let upstream = if let Some(root) = config.upstream_ca.as_ref() {
        let address = config
            .upstream
            .as_ref()
            .ok_or("missing upstream")?
            .to_socket_addrs()?
            .find(SocketAddr::is_ipv4)
            .ok_or("missing IPv4 route")?;
        Some((client(root, address)?, address))
    } else {
        None
    };
    let metadata = json!({"event":"ready", "role":config.role, "listen":endpoint.local_addr()?.to_string(),
        "pid":std::process::id(), "current_user_trust": windows::trust(&ca.der,"status")?,
        "certificate_sha256":leaf_hash, "bootstrap_sha256":bootstrap_hash, "ca_sha256":ca.id, "alpn":"h3", "quic_version":1});
    std::fs::write(&config.ready, serde_json::to_vec_pretty(&metadata)?)?;
    println!("{metadata}");
    let config = Arc::new(config);
    let slots = Arc::new(tokio::sync::Semaphore::new(8));
    let request_slots = Arc::new(tokio::sync::Semaphore::new(8));
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let Ok(permit) = slots.clone().try_acquire_owned() else { incoming.refuse(); continue };
                let config = config.clone();
                let upstream = upstream.clone();
                let request_slots = request_slots.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let result = tokio::time::timeout(Duration::from_secs(60), handle(incoming,config,upstream,request_slots)).await;
                    match result {
                        Ok(Ok(())) => (),
                        other => eprintln!("CONNECTION_END {other:?}"),
                    }
                });
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                if config.stop.exists() { break }
            }
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                if let Err(e) = result { eprintln!("TASK_ERROR {e}"); }
            }
        }
    }
    // Runner shutdown only. Not an implementation of the GUI's stop-monitoring contract.
    endpoint.close(0u32.into(), b"probe finished");
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    endpoint.wait_idle().await;
    Ok(())
}

async fn handle(
    incoming: quinn::Incoming,
    config: Arc<Config>,
    upstream: Option<(quinn::Endpoint, SocketAddr)>,
    request_slots: Arc<tokio::sync::Semaphore>,
) -> Result<()> {
    let conn = incoming.await?;
    let connection_id = conn.stable_id();
    if let Some(path) = config.close_connections.clone() {
        let target = conn.clone();
        tokio::spawn(async move {
            loop {
                if path.exists() { target.close(0u32.into(), b"test reconnect"); break; }
                if target.close_reason().is_some() { break; }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });
    }
    let _close = CloseConnection(conn.clone());
    println!(
        "{}",
        json!({"event":"downstream_handshake","connection_id":connection_id,"peer":conn.remote_address().to_string(),"role":config.role,"alpn":"h3"})
    );
    // Resolve through Winsock: with the native test host this exercises the real
    // Hook dummy-DNS + CUdpProxyTask + SOCKS5 UDP domain route, not a Rust SOCKS clone.
    let mut sender = None;
    let mut upstream_connection = None;
    let mut driver_task = None;
    if let Some((endpoint, address)) = upstream {
        let up = tokio::time::timeout(
            Duration::from_secs(8),
            endpoint.connect(address, &config.name)?,
        )
        .await??;
        println!(
            "{}",
            json!({"event":"upstream_handshake","address":address.to_string(),"alpn":"h3"})
        );
        let (mut driver, send) = h3::client::builder()
            .max_field_section_size(16384)
            .build(h3_quinn::Connection::new(up.clone()))
            .await?;
        driver_task = Some(AbortDriver(tokio::spawn(async move {
            std::future::poll_fn(|cx| driver.poll_close(cx)).await
        })));
        upstream_connection = Some(CloseConnection(up));
        sender = Some(send);
    }
    let mut h3 = h3::server::builder()
        .max_field_section_size(16384)
        .build(h3_quinn::Connection::new(conn.clone()))
        .await?;
    let mut requests = tokio::task::JoinSet::new();
    let end = async {
        while let Some(resolver) = h3.accept().await? {
            let sender = sender.clone();
            let role = config.role.clone();
            let request_slots = request_slots.clone();
            // Transport already bounds open streams. Join completed tasks so a
            // long connection cannot accumulate unlimited completed task records.
            while requests.try_join_next().is_some() {}
            requests.spawn(async move {
                let result: Result<()> = async {
                    let _permit = request_slots.acquire_owned().await?;
                    let (request, mut stream) = resolver.resolve_request().await?;
                    let method = request.method().to_string();
                    let uri = request.uri().to_string();
                    println!(
                        "{}",
                        json!({"event":"request_headers","role":role,"uri":uri})
                    );
                    let mut body = Vec::new();
                    while let Some(mut part) = stream.recv_data().await? {
                        if body.len() + part.remaining() > BODY_LIMIT {
                            return Err("probe request cap".into());
                        }
                        body.extend_from_slice(&part.copy_to_bytes(part.remaining()));
                    }
                    if stream.recv_trailers().await?.is_some() {
                        return Err("trailers not supported by probe".into());
                    }
                    let sent = body.len();
                    println!(
                        "{}",
                        json!({"event":"request_body","role":role,"uri":uri,"bytes":sent})
                    );
                    let (response, reply) = if let Some(mut send) = sender {
                        let mut upstream = send.send_request(request).await?;
                        println!("{}", json!({"event":"upstream_request_headers","uri":uri}));
                        if !body.is_empty() {
                            upstream.send_data(Bytes::from(body)).await?;
                        }
                        upstream.finish().await?;
                        println!("{}", json!({"event":"upstream_request_finished","uri":uri}));
                        let response = upstream.recv_response().await?;
                        let mut reply = Vec::new();
                        while let Some(mut part) = upstream.recv_data().await? {
                            if reply.len() + part.remaining() > BODY_LIMIT {
                                return Err("probe response cap".into());
                            }
                            reply.extend_from_slice(&part.copy_to_bytes(part.remaining()));
                        }
                        if upstream.recv_trailers().await?.is_some() {
                            return Err("trailers not supported by probe".into());
                        }
                        (response, reply)
                    } else {
                        let reply = if method == "POST" {
                            body
                        } else {
                            b"ProxyLane QUIC MITM HTTP/3 verified\n".to_vec()
                        };
                        (
                            http::Response::builder()
                                .status(200)
                                .header("content-type", "text/plain")
                                .header("x-proxylane-origin", "quic-probe")
                                .header("content-length", reply.len())
                                .body(())?,
                            reply,
                        )
                    };
                    println!(
                        "{}",
                        json!({"event":"request","connection_id":connection_id,"role":role,"method":method,"uri":uri,
                        "status":response.status().as_u16(),"sent":sent,"received":reply.len(),
                        "response_sha256":format!("{:x}",Sha256::digest(&reply))})
                    );
                    stream.send_response(response).await?;
                    // Bound send chunks; the probe body cap is NOT production caching.
                    for chunk in reply.chunks(32 * 1024) {
                        stream.send_data(Bytes::copy_from_slice(chunk)).await?;
                    }
                    stream.finish().await?;
                    Ok(())
                }
                .await;
                if let Err(e) = result {
                    eprintln!("REQUEST_ERROR {e}");
                }
            });
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;
    while requests.join_next().await.is_some() {}
    drop(upstream_connection);
    drop(driver_task);
    end
}

#[tokio::main]
async fn main() -> Result<()> {
    let config: Config = serde_json::from_slice(&std::fs::read(
        std::env::args()
            .nth(1)
            .ok_or("configuration JSON required")?,
    )?)?;
    if config.role != "origin" && config.role != "mitm" {
        return Err("role must be origin or mitm".into());
    }
    serve(config).await
}
