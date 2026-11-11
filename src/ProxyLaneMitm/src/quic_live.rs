//! In-process QUIC/HTTP3 termination. All datagrams use the host's existing route.
//! No socket/DNS bypass; bounded queues and streaming bodies independent of capture.
use crate::{
    protocol::{H3Part, Runtime, Tap},
    session,
};
use bytes::{Buf, Bytes};
use h3::error::{Code, StreamError};
use proxylane_protocol::{Connection, Headers, Message};
use quinn::{
    udp::{RecvMeta, Transmit},
    AsyncUdpSocket, UdpPoller,
};
use std::{
    collections::VecDeque,
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll, Waker},
    time::Duration,
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
#[derive(Debug)]
pub(crate) struct TransportEnd {side:&'static str,error:quinn::ConnectionError}
impl std::fmt::Display for TransportEnd {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {write!(f,"QUIC {} connection ended: {}",self.side,self.error)}
}
impl std::error::Error for TransportEnd {}
pub(crate) fn transport_end(side:&'static str,error:quinn::ConnectionError)->Box<dyn std::error::Error+Send+Sync> {
    Box::new(TransportEnd {side,error})
}
fn terminal_status(established:bool,error:Option<&(dyn std::error::Error+Send+Sync+'static)>)->&'static str {
    match error {
        None=>"Closed",
        Some(e) if established && e.downcast_ref::<TransportEnd>().is_some_and(|e|matches!(e.error,quinn::ConnectionError::TimedOut))=>"Closed",
        _=>"Failed",
    }
}
const QUEUE_BYTES: usize = 512 * 1024;
pub type Notify = extern "C" fn(usize);
#[derive(Default, Debug)]
struct Queue {
    input: VecDeque<Vec<u8>>,
    output: VecDeque<Vec<u8>>,
    input_bytes: usize,
    output_bytes: usize,
    read: Option<Waker>,
    write: Option<Waker>,
    closed: bool,
}
struct Pipe {
    queue: Mutex<Queue>,
    detached: AtomicBool,
    notify: Notify,
    user: usize,
    remote: SocketAddr,
}
impl std::fmt::Debug for Pipe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PRC QUIC pipe")
    }
}
struct Poller(Arc<Pipe>);
impl std::fmt::Debug for Poller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PRC poller")
    }
}
impl UdpPoller for Poller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut q = self.0.queue.lock().unwrap();
        if q.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if q.output_bytes + 65536 <= QUEUE_BYTES {
            Poll::Ready(Ok(()))
        } else {
            q.write = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}
impl AsyncUdpSocket for Pipe {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Poller(self))
    }
    fn try_send(&self, t: &Transmit<'_>) -> io::Result<()> {
        let mut q = self.queue.lock().unwrap();
        if q.closed {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        if t.destination != self.remote || t.segment_size.is_some() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        if q.output_bytes + t.contents.len() > QUEUE_BYTES {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let empty = q.output.is_empty();
        q.output_bytes += t.contents.len();
        q.output.push_back(t.contents.to_vec());
        if empty {
            (self.notify)(self.user);
        }
        Ok(())
    }
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut q = self.queue.lock().unwrap();
        if q.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if let Some(b) = q.input.pop_front() {
            q.input_bytes -= b.len();
            if bufs.is_empty() || meta.is_empty() || bufs[0].len() < b.len() {
                return Poll::Ready(Err(io::ErrorKind::InvalidInput.into()));
            }
            bufs[0][..b.len()].copy_from_slice(&b);
            meta[0] = RecvMeta {
                addr: self.remote,
                len: b.len(),
                stride: b.len(),
                ecn: None,
                dst_ip: None,
            };
            Poll::Ready(Ok(1))
        } else {
            q.read = Some(cx.waker().clone());
            Poll::Pending
        }
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok("127.0.0.1:1".parse().unwrap())
    }
}
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
struct Admission;
impl Drop for Admission {
    fn drop(&mut self) {
        ACTIVE.fetch_sub(1, Ordering::AcqRel);
    }
}
pub struct Live {
    _admission: Admission,
    pipes: [Arc<Pipe>; 2],
    task: tokio::task::JoinHandle<()>,
    error: Arc<Mutex<String>>,
    finished: Arc<AtomicBool>,
}
// Owned by the forwarding future, including before its first poll. Aborting the
// future must retire its visible connection just as a normal return does.
struct ConnectionLifecycle {
    runtime: Arc<Runtime>,
    epoch: u64,
    identity: Connection,
    ended: bool,
    established: bool,
}
impl ConnectionLifecycle {
    fn finish(&mut self, status: &str, problem: &str) {
        if self.ended { return; }
        self.ended = true;
        let protocol = match self.identity.quic_alpn.as_deref() {
            None => "quic", Some("h3") => "h3", Some(_) => "quic_stream",
        };
        self.runtime.lifecycle(self.epoch, &self.identity, status, protocol, problem,
            self.identity.upstream_verification_skipped);
    }
}
impl Drop for ConnectionLifecycle {
    fn drop(&mut self) {
        self.finish("Closed", "QUIC forwarding cancelled: host released the connection before normal shutdown");
    }
}
fn engine() -> Result<&'static tokio::runtime::Runtime> {
    static RT: std::sync::OnceLock<std::result::Result<tokio::runtime::Runtime, String>> =
        std::sync::OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("quic-forward")
            .build()
            .map_err(|e| e.to_string())
    })
    .as_ref()
    .map_err(|e| e.clone().into())
}
// Transport flow control is independent of capture/parser options. At this
// bounded concurrency we wait for capacity rather than resetting requests.
pub(crate) const FORWARD_STREAMS: usize = 128;
fn transport(datagrams: bool) -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    t.max_concurrent_bidi_streams((FORWARD_STREAMS as u32).into());
    t.max_concurrent_uni_streams(8u32.into());
    t.max_idle_timeout(Some(Duration::from_secs(60).try_into().unwrap()));
    t.stream_receive_window((256 * 1024u32).into());
    t.receive_window((1024 * 1024u32).into());
    t.send_window(1024 * 1024);
    t.enable_segmentation_offload(false);
    t.mtu_discovery_config(None);
    t.datagram_receive_buffer_size(if datagrams {Some(1024*1024)} else {None});
    t.datagram_send_buffer_size(256*1024);
    Arc::new(t)
}
fn offered(probe:&crate::quic_probe::Probe)->Vec<Vec<u8>> {
    // Keep the existing h3 admission for Chromium's GREASE ECH extension.
    // For other protocols an ECH outer hello is not sufficient to identify them.
    if probe.ech && !probe.raw_alpn.iter().any(|a|a==b"h3") { return Vec::new(); }
    probe.raw_alpn.clone()
}
pub fn admissible(probe:&crate::quic_probe::Probe)->bool {probe.version==Some(1) && !offered(probe).is_empty()}
fn alpn_label(alpn:&[u8])->String {
    alpn.iter().map(|b| if (0x21..=0x7e).contains(b) && *b!=b'\\' {
        (*b as char).to_string()
    } else {format!("\\x{b:02x}")}).collect()
}
pub fn prepare() -> Result<()> {
    engine()?;
    crate::context()?;
    Ok(())
}
impl Live {
    /// Called only for a fresh supported Initial. A declined packet is untouched.
    pub fn open(
        host: &str,
        metadata: &serde_json::Value,
        first: &[u8],
        inspected: Option<&crate::quic_probe::Probe>,
        notify: Notify,
        user: usize,
    ) -> Result<Option<Self>> {
        let mut local = crate::quic_probe::Probe::default();
        let probe = match inspected {
            Some(p) => p,
            None => {
                local.feed(0, first);
                &local
            }
        };
        if !admissible(probe) {
            return Ok(None);
        }
        let name = if probe.name.is_empty() {
            if host.parse::<std::net::IpAddr>().is_err() {
                return Ok(None);
            }
            host.to_owned()
        } else {
            probe.name.clone()
        };
        if ACTIVE
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < crate::options::current().connections).then_some(n + 1)
            })
            .is_err()
        {
            return Err("QUIC connection limit reached".into());
        }
        let admission = Admission;
        let alpns=offered(probe);
        let protocol="quic"; // The server has not selected an application protocol yet.
        let (runtime, epoch) = crate::protocol_runtime()?;
        let mut identity = crate::protocol::identity(metadata, host)?;
        identity.server_name = name.clone();
        identity.transport = "udp".into();
        identity.decrypted = true;
        identity.upstream_verification_skipped =
            crate::SKIP_UPSTREAM_VERIFY.load(Ordering::Acquire);
        let make = |port| {
            Arc::new(Pipe {
                queue: Mutex::new(Queue::default()),
                detached: AtomicBool::new(false),
                notify,
                user,
                remote: SocketAddr::from(([127, 0, 0, 1], port)),
            })
        };
        let pipes = [make(2), make(3)];
        let pair = pipes.clone();
        let error = Arc::new(Mutex::new(String::new()));
        let err = error.clone();
        let finished = Arc::new(AtomicBool::new(false));
        let done = finished.clone();
        let ctx = crate::context()?;
        runtime.lifecycle(
            epoch,
            &identity,
            "Connecting",
            protocol,
            "",
            identity.upstream_verification_skipped,
        );
        let mut lifecycle = ConnectionLifecycle { runtime: runtime.clone(), epoch, identity, ended: false, established:false };
        let task = engine()?.spawn(async move {
            let mut endpoints = Vec::new();
            let result = serve(
                pair.clone(),
                ctx,
                name,
                runtime.clone(),
                epoch,
                &mut lifecycle.identity,
                &mut lifecycle.established,
                &mut endpoints,
                alpns,
            )
            .await;
            let raw=lifecycle.identity.quic_alpn.as_deref()!=Some("h3");
            let status=terminal_status(lifecycle.established,result.as_ref().err().map(|e|e.as_ref()));
            let problem = result.err().map(|e| e.to_string()).unwrap_or_default();
            // Finish connection-close datagrams before publishing finished.
            // Afterwards no producer may append to queues the host is draining.
            for endpoint in &endpoints {
                endpoint.close(if raw {if problem.is_empty(){0u32}else{1u32}} else if problem.is_empty() {0x100u32} else {0x102u32}.into(), b"MITM connection ended");
            }
            let _ = tokio::time::timeout(Duration::from_secs(2), async {
                for endpoint in &endpoints { endpoint.wait_idle().await; }
            }).await;
            for pipe in &pair {
                let mut q = pipe.queue.lock().unwrap();
                q.closed = true;
                q.input.clear(); q.input_bytes = 0;
                if let Some(w) = q.read.take() { w.wake(); }
                if let Some(w) = q.write.take() { w.wake(); }
            }
            lifecycle.finish(
                status,
                &problem,
            );
            *err.lock().unwrap() = problem;
            done.store(true, Ordering::Release);
            let _q = pair[0].queue.lock().unwrap();
            // Live::drop uses the same lock to disable notifications.
            if !pair[0].detached.load(Ordering::Acquire) {
                (pair[0].notify)(pair[0].user);
            }
        });
        let live = Self {
            _admission: admission,
            pipes,
            task,
            error,
            finished,
        };
        live.feed(0, first);
        Ok(Some(live))
    }
    pub fn feed(&self, side: usize, b: &[u8]) {
        let mut q = self.pipes[side].queue.lock().unwrap();
        if !q.closed && q.input_bytes + b.len() <= QUEUE_BYTES {
            q.input_bytes += b.len();
            q.input.push_back(b.to_vec());
            if let Some(w) = q.read.take() {
                w.wake();
            }
        }
    }
    pub fn peek(&self, side: usize, b: &mut [u8]) -> usize {
        let q = self.pipes[side].queue.lock().unwrap();
        if let Some(p) = q.output.front() {
            if p.len() <= b.len() {
                b[..p.len()].copy_from_slice(p);
                return p.len();
            }
        }
        0
    }
    pub fn consume(&self, side: usize) {
        let mut q = self.pipes[side].queue.lock().unwrap();
        if let Some(p) = q.output.pop_front() {
            q.output_bytes -= p.len();
            if let Some(w) = q.write.take() {
                w.wake();
            }
        }
    }
    pub fn error(&self) -> String {
        self.error.lock().unwrap().clone()
    }
    pub fn finished(&self) -> bool {
        self.finished.load(Ordering::Acquire)
    }
}
impl Drop for Live {
    fn drop(&mut self) {
        for p in &self.pipes {
            let mut q = p.queue.lock().unwrap();
            p.detached.store(true, Ordering::Release);
            q.closed = true;
            if let Some(w) = q.read.take() {
                w.wake();
            }
            if let Some(w) = q.write.take() {
                w.wake();
            }
        }
        self.task.abort();
    }
}
struct Driver(tokio::task::JoinHandle<h3::error::ConnectionError>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}
fn headers(h: &http::HeaderMap) -> Headers {
    h.iter()
        .map(|(k, v)| {
            (
                k.as_str().into(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect()
}
async fn connect_upstream(pipes:&[Arc<Pipe>;2],ctx:&session::Context,name:&str,skip:bool,
    endpoints:&mut Vec<quinn::Endpoint>,alpns:Vec<Vec<u8>>)->Result<quinn::Connection> {
    let timeout=Duration::from_secs(crate::options::current().handshake_seconds);
    let mut tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(ctx.verifier.clone())
        .with_no_client_auth();
    if skip {
        tls.dangerous()
            .set_certificate_verifier(Arc::new(session::SkipCertificateTrust));
    }
    let tls_datagrams=alpns.iter().any(|a|a!=b"h3");
    tls.alpn_protocols = alpns;
    tls.enable_early_data = false;
    let mut config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)?,
    ));
    config.transport_config(transport(tls_datagrams));
    config.version(1);
    let mut upstream = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        pipes[1].clone(),
        Arc::new(quinn::TokioRuntime),
    )?;
    endpoints.push(upstream.clone());
    upstream.set_default_client_config(config);
    let up=tokio::time::timeout(timeout, upstream.connect(pipes[1].remote, name)?).await
        .map_err(|e|format!("Upstream QUIC handshake failed: {e}"))?
        .map_err(|e|format!("Upstream QUIC handshake failed: {e}"))?;
    Ok(up)
}
async fn serve(
    pipes: [Arc<Pipe>; 2],
    ctx: Arc<session::Context>,
    name: String,
    runtime: Arc<Runtime>,
    epoch: u64,
    identity: &mut Connection,
    established: &mut bool,
    endpoints: &mut Vec<quinn::Endpoint>,
    mut alpns:Vec<Vec<u8>>,
) -> Result<()> {
    // Always negotiate upstream first, including mixed h3/custom offers.
    // Both legs use the server's selected protocol, never a guessed first offer.
    let upstream=async {
        let up=connect_upstream(&pipes,&ctx,&name,identity.upstream_verification_skipped,endpoints,alpns.clone()).await?;
        let handshake=up.handshake_data().ok_or("Missing upstream handshake")?;
        let selected=handshake.downcast_ref::<quinn::crypto::rustls::HandshakeData>()
            .and_then(|h|h.protocol.clone()).ok_or("Missing upstream ALPN")?;
        if !alpns.contains(&selected) {return Err("Upstream selected an unoffered ALPN".into());}
        Ok::<_,Box<dyn std::error::Error+Send+Sync>>((up,selected))
    }.await;
    // On upstream failure still establish a downstream transport solely to send
    // CONNECTION_CLOSE. Otherwise the application only sees a long silent timeout.
    let selected=upstream.as_ref().map(|(_,alpn)|alpn.clone()).unwrap_or_else(|_|alpns[0].clone());
    let raw=selected!=b"h3";
    if upstream.is_ok() {identity.quic_alpn=Some(alpn_label(&selected));}
    let identity=identity.clone();
    alpns=vec![selected];
    let leaf = ctx.ca.leaf(&name, ctx.crl.port())?;
    #[derive(Debug)]
    struct Leaf(Arc<rustls::sign::CertifiedKey>);
    impl rustls::server::ResolvesServerCert for Leaf {
        fn resolve(
            &self,
            _: rustls::server::ClientHello<'_>,
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            Some(self.0.clone())
        }
    }
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Leaf(leaf)));
    tls.alpn_protocols = alpns.clone();
    tls.max_early_data_size = 0;
    tls.send_tls13_tickets = 0;
    tls.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls)?,
    ));
    server.transport_config(transport(raw && upstream.as_ref().is_ok_and(|(up,_)|up.max_datagram_size().is_some())));
    server.migration(false);
    let mut ec = quinn::EndpointConfig::default();
    ec.supported_versions(vec![1]);
    let downstream = quinn::Endpoint::new_with_abstract_socket(
        ec,
        Some(server),
        pipes[0].clone(),
        Arc::new(quinn::TokioRuntime),
    )?;
    endpoints.push(downstream.clone());
    let timeout = Duration::from_secs(crate::options::current().handshake_seconds);
    let incoming = tokio::time::timeout(timeout, downstream.accept())
        .await?
        .ok_or("QUIC endpoint closed")?;
    let conn = tokio::time::timeout(timeout, incoming).await??;
    // This bridge owns exactly one admitted QUIC connection, including its CIDs.
    downstream.set_server_config(None);
    let up=match upstream {
        Ok((up,_))=>up,
        Err(e)=>{conn.close(if raw {1u32}else{0x102u32}.into(),b"upstream QUIC handshake failed");return Err(e);}
    };
    *established=true;
    if raw {
        runtime.lifecycle(epoch,&identity,"Established","quic_stream","",identity.upstream_verification_skipped);
        return crate::quic_raw::serve(conn,up,runtime,epoch,identity,alpn_label(&alpns[0])).await;
    }
    runtime.lifecycle(
        epoch,
        &identity,
        "Established",
        "h3",
        "",
        identity.upstream_verification_skipped,
    );
    let (mut driver, sender) = h3::client::builder()
        .max_field_section_size(65536)
        .build(h3_quinn::Connection::new(up.clone()))
        .await?;
    let mut driver = Driver(tokio::spawn(async move {
        std::future::poll_fn(|cx| driver.poll_close(cx)).await
    }));
    let mut server = h3::server::builder()
        .max_field_section_size(65536)
        .build(h3_quinn::Connection::new(conn.clone()))
        .await?;
    let mut jobs = tokio::task::JoinSet::new();
    let (goaway_tx, mut goaway_rx) = tokio::sync::mpsc::channel(1);
    let mut draining = false;
    let mut driver_done = false;
    let (mut last_accepted, mut highest_accepted) = (0u64, 0u64);
    loop {
        tokio::select! {
            // Use the lower-level accept: h3 0.0.8's accept() implicitly emits
            // shutdown(0), whose GOAWAY ID can include an already processed request.
            next=std::future::poll_fn(|cx| server.poll_accept_request_stream(cx)),if jobs.len()<FORWARD_STREAMS=>{
                let mut resolver=match next {
                    Ok(Some(stream))=>server.create_resolver(h3::frame::FrameStream::new(h3::stream::BufRecvStream::new(stream))),
                    Ok(None)=>{
                        if !draining {
                            server.shutdown(((highest_accepted-last_accepted)/4+1) as usize).await?;
                        }
                        // HTTP jobs finishing only means FIN was queued, not
                        // acknowledged. Let the peer consume responses/close;
                        // QUIC's idle timeout still bounds an abandoned peer.
                        conn.closed().await;
                        break;
                    },
                    Err(e)=>{
                        if matches!(conn.close_reason(),Some(quinn::ConnectionError::ApplicationClosed(ref c)) if c.error_code.into_inner()==0 || c.error_code.into_inner()==0x100) {break;}
                        if let Some(reason)=conn.close_reason(){return Err(transport_end("application",reason));}
                        if let Some(reason)=up.close_reason(){return Err(transport_end("upstream",reason));}
                        return Err(e.into());
                    }
                };
                last_accepted=h3::quic::SendStream::send_id(&resolver.frame_stream).into_inner();
                highest_accepted=highest_accepted.max(last_accepted);
                if draining {
                    h3::quic::SendStream::reset(&mut resolver.frame_stream,Code::H3_REQUEST_REJECTED.value());
                    let mut raw=resolver.frame_stream.into_inner();
                    h3::quic::RecvStream::stop_sending(&mut raw,Code::H3_REQUEST_REJECTED.value());
                    continue;
                }
                let sender=sender.clone();let runtime=runtime.clone();let identity=identity.clone();
                let goaway=goaway_tx.clone();let down_connection=conn.clone();let up_connection=up.clone();
                // Headers belong to an individual stream. Waiting here blocks
                // acceptance of every other request; propagating a reset here
                // tears down the entire multiplexed connection. The h3 driver
                // still reports genuine connection errors through accept().
                jobs.spawn(async move {
                    let (request,stream)=resolver.resolve_request().await?;
                    forward(request,stream,sender,runtime,epoch,identity,goaway,down_connection,up_connection).await
                });
            }
            Some(result)=jobs.join_next(),if !jobs.is_empty()=>{
                match result {
                    Err(e) => return Err(e.into()), // task panic is not a normal stream cancellation
                    _ => {} // forward explicitly resets failed streams; unrelated jobs survive
                }
            }
            Some(())=goaway_rx.recv(),if !draining=>{
                // h3 0.0.8 shutdown(0) sends the last accepted ID. The wire
                // GOAWAY ID must be ABOVE every possibly processed request.
                server.shutdown(((highest_accepted-last_accepted)/4+1) as usize).await?;
                draining = true;
            }
            result=&mut driver.0,if !driver_done=>{
                driver_done = true;
                result?;
                if !draining {
                    server.shutdown(((highest_accepted-last_accepted)/4+1) as usize).await?;
                    draining = true;
                }
            }
        }
    }
    jobs.abort_all();
    while jobs.join_next().await.is_some() {}
    up.close(0u32.into(), b"downstream closed");
    Ok(())
}
async fn observe(tap:&Option<Tap>,side:usize,part:H3Part) {
    if let Some(t)=tap {t.http3_async(side,part).await;}
}
async fn observe_data(tap:&Option<Tap>,side:usize,data:&[u8]) {
    if let Some(t)=tap {t.http3_async(side,H3Part::Data(data.to_vec())).await;}
}
struct RequestCapture { tap:Option<Tap>, downstream:quinn::Connection, upstream:quinn::Connection }
impl std::ops::Deref for RequestCapture {type Target=Option<Tap>;fn deref(&self)->&Self::Target {&self.tap}}
impl Drop for RequestCapture {fn drop(&mut self){if let Some(t)=&self.tap {
    let reason=if let Some(e)=self.downstream.close_reason(){format!("HTTP/3 downstream connection closed: {e}")}
        else if let Some(e)=self.upstream.close_reason(){format!("HTTP/3 upstream connection closed: {e}")}
        else {"HTTP/3 request task ended before both directions completed".into()};
    t.close_reason(reason);
}}}
async fn forward(
    request: http::Request<()>,
    mut downstream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    mut sender: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    runtime: Arc<Runtime>,
    epoch: u64,
    identity: Connection,
    goaway: tokio::sync::mpsc::Sender<()>,
    down_connection:quinn::Connection,up_connection:quinn::Connection,
) -> Result<()> {
    let id = downstream.id().into_inner();
    let tap = RequestCapture {tap:runtime.tap_at_async(epoch, identity, Some(format!("h3:{id}").into_bytes()), true).await,downstream:down_connection,upstream:up_connection};
    let mut hs = headers(request.headers());
    if let Some(a) = request.uri().authority() {
        hs.insert(0, (":authority".into(), a.to_string()));
    }
    if let Some(s) = request.uri().scheme_str() {
        hs.insert(0, (":scheme".into(), s.into()));
    }
    let mut message = Message::default();
    message.method = Some(request.method().to_string());
    message.target = Some(
        request
            .uri()
            .path_and_query()
            .map_or("/", |v| v.as_str())
            .into(),
    );
    message.headers = hs;
    observe(&tap, 0, H3Part::Head(message)).await;
    let upstream = match sender.send_request(request).await {
        Ok(stream) => stream,
        Err(e) => {
            if let Some(t)=tap.as_ref(){t.close_reason(format!("HTTP/3 upstream request dispatch failed: {e}"));}
            // Only GOAWAY known before dispatch permits a safe retry. Do not
            // silently FIN an empty response or replay an arbitrary POST.
            let code = if matches!(e, StreamError::RemoteClosing) {
                let _ = goaway.try_send(());
                Code::H3_REQUEST_REJECTED
            } else { Code::H3_INTERNAL_ERROR };
            downstream.stop_stream(code);
            downstream.stop_sending(code);
            return Err(e.into());
        }
    };
    // Upload and response are driven concurrently; early responses cannot deadlock uploads.
    let (mut down_send, mut down_recv) = downstream.split();
    let (mut up_send, mut up_recv) = upstream.split();
    let outcome = {
        let upload = async {
            while let Some(mut data) = match down_recv.recv_data().await {
                Ok(data) => data,
                Err(StreamError::RemoteTerminate { code: Code::H3_NO_ERROR, .. }) => {
                    // A client may end its upload after seeing an early final
                    // response, while still wanting the complete response body.
                    up_send.stop_stream(Code::H3_NO_ERROR);
                    if let Some(t)=tap.as_ref(){t.close_reason("HTTP/3 application ended upload with H3_NO_ERROR".into());}
                    return Ok(false);
                }
                Err(e) => return Err(format!("application request body: {e}").into()),
            } {
                while data.has_remaining() {
                    let b = data.copy_to_bytes(data.remaining().min(16384));
                    observe_data(&tap, 0, &b).await;
                    if let Err(e) = up_send.send_data(b).await {
                        if let StreamError::RemoteTerminate { code, .. } = e {
                            down_recv.stop_sending(code);
                            if let Some(t)=tap.as_ref(){t.close_reason(format!("HTTP/3 upstream stopped upload: {code:?}"));}
                            return Ok(false); // response is still independently valid
                        }
                        return Err(format!("send request body to upstream: {e}").into());
                    }
                }
            }
            let trailers = match down_recv.recv_trailers().await {
                Ok(trailers) => trailers,
                Err(StreamError::RemoteTerminate { code: Code::H3_NO_ERROR, .. }) => {
                    up_send.stop_stream(Code::H3_NO_ERROR);
                    if let Some(t)=tap.as_ref(){t.close_reason("HTTP/3 application ended request trailers with H3_NO_ERROR".into());}
                    return Ok(false);
                }
                Err(e) => return Err(format!("application request trailers: {e}").into()),
            };
            observe(
                &tap,
                0,
                H3Part::End(trailers.as_ref().map(headers).unwrap_or_default()),
            ).await;
            let end = if let Some(t) = trailers {
                up_send.send_trailers(t).await
            } else {
                up_send.finish().await
            };
            if let Err(e) = end {
                if let StreamError::RemoteTerminate { code, .. } = e {
                    down_recv.stop_sending(code);
                    if let Some(t)=tap.as_ref(){t.close_reason(format!("HTTP/3 upstream stopped request completion: {code:?}"));}
                    return Ok(false);
                }
                return Err(format!("finish request to upstream: {e}").into());
            }
            Ok::<bool, Box<dyn std::error::Error + Send + Sync>>(true)
        };
        let download = async {
            let mut interim = 0;
            loop {
                let response = up_recv.recv_response().await.map_err(|e|format!("upstream response headers: {e}"))?;
                let informational = response.status().is_informational();
                if informational {
                    interim += 1;
                    if interim > 16 {
                        return Err("Too many HTTP/3 informational responses".into());
                    }
                }
                let mut message = Message::default();
                message.status = Some(response.status().as_u16());
                message.headers = headers(response.headers());
                observe(&tap, 1, H3Part::Head(message)).await;
                down_send.send_response(response).await.map_err(|e|format!("send response to application: {e}"))?;
                if !informational {
                    break;
                }
            }
            while let Some(mut data) = up_recv.recv_data().await.map_err(|e|format!("upstream response body: {e}"))? {
                while data.has_remaining() {
                    let b = data.copy_to_bytes(data.remaining().min(16384));
                    observe_data(&tap, 1, &b).await;
                    down_send.send_data(b).await.map_err(|e|format!("send body to application: {e}"))?;
                }
            }
            let trailers = up_recv.recv_trailers().await.map_err(|e|format!("upstream response trailers: {e}"))?;
            observe(
                &tap,
                1,
                H3Part::End(trailers.as_ref().map(headers).unwrap_or_default()),
            ).await;
            if let Some(t) = trailers {
                down_send.send_trailers(t).await.map_err(|e|format!("send response trailers to application: {e}"))?;
            } else {
                down_send.finish().await.map_err(|e|format!("finish response to application: {e}"))?;
            }
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        };
        tokio::pin!(upload, download);
        tokio::select! {
            biased;
            sent = &mut upload => match sent {
                Ok(complete) => download.await.map(|_| complete),
                Err(e) => Err(e),
            },
            received = &mut download => received.map(|_| false),
        }
    };
    match outcome {
        Ok(upload_complete) => {
            if let Some(t)=tap.as_ref(){t.close_reason(if upload_complete {
                "HTTP/3 request and response completed"
            } else {"HTTP/3 response completed before upload task completed"}.into());}
            if !upload_complete {
                down_recv.stop_sending(Code::H3_NO_ERROR);
                up_send.stop_stream(Code::H3_NO_ERROR);
            }
        }
        Err(e) => {
            if let Some(t)=tap.as_ref(){t.close_reason(format!("HTTP/3 transfer failed: {e}"));}
            // Reset, never FIN, a failed response; FIN could turn an isolated
            // cancellation into a connection-wide Content-Length error.
            let code = Code::H3_REQUEST_CANCELLED;
            down_send.stop_stream(code); down_recv.stop_sending(code);
            up_send.stop_stream(code); up_recv.stop_sending(code);
            return Err(e);
        }
    }
    Ok(())
}

#[cfg(test)]
mod raw_policy_tests {
    use super::*;
    #[test]
    fn only_established_transport_timeouts_are_closed() {
        let timeout=transport_end("application",quinn::ConnectionError::TimedOut);
        assert_eq!(terminal_status(false,Some(timeout.as_ref())),"Failed");
        assert_eq!(terminal_status(true,Some(timeout.as_ref())),"Closed");
        let reset=transport_end("upstream",quinn::ConnectionError::Reset);
        assert_eq!(terminal_status(true,Some(reset.as_ref())),"Failed");
        assert_eq!(terminal_status(true,None),"Closed");
    }
    #[test]
    fn cancelled_quic_tasks_retire_once_and_respect_capture_epoch() {
        use proxylane_protocol::cache::CacheConfig;
        use serde_json::json;
        let runtime = Runtime::new(CacheConfig { root: std::env::temp_dir().join("proxylane-quic-cancel-tests"), ..Default::default() }).unwrap();
        let executor = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let make = |id: &str| ConnectionLifecycle {
            runtime: runtime.clone(), epoch: runtime.capture_epoch(),
            identity: Connection { id: id.into(), transport: "udp".into(), decrypted: true, ..Default::default() }, ended: false, established:false,
        };
        // Cancel before the future is polled: its captured guard must still run.
        let guard = make("1");
        let task = executor.spawn(async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        });
        task.abort();
        assert!(executor.block_on(task).unwrap_err().is_cancelled());
        // Cancel an established connection after the negotiated ALPN changed.
        let mut guard = make("2");
        let task = executor.spawn(async move {
            guard.identity.quic_alpn = Some("h3".into());
            guard.runtime.lifecycle(guard.epoch, &guard.identity, "Established", "h3", "", false);
            std::future::pending::<()>().await;
            drop(guard);
        });
        executor.block_on(tokio::task::yield_now());
        task.abort();
        assert!(executor.block_on(task).unwrap_err().is_cancelled());
        // Normal error/close must keep its own reason, without a second close.
        let mut guard = make("3"); guard.finish("Failed", "handshake timeout"); drop(guard);
        let mut guard = make("4"); guard.finish("Closed", ""); drop(guard);
        // A late cancellation after stop/restart must not enter the new capture.
        let guard = make("5"); runtime.stop_capture().unwrap(); runtime.start_capture(); drop(guard);
        let result = runtime.query(&json!({"type":"poll","limit":64})).unwrap();
        let rows = result["records"].as_array().unwrap();
        for (id, protocol) in [("1", "quic"), ("2", "h3")] {
            let ended: Vec<_> = rows.iter().filter(|r|r["connection"]["id"]==id && r["status"]=="Closed").collect();
            assert_eq!(ended.len(),1); assert_eq!(ended[0]["protocol"],protocol);
            assert!(ended[0]["detail"].as_str().unwrap().contains("cancelled"));
        }
        assert_eq!(rows.iter().filter(|r|r["connection"]["id"]=="3").count(),1);
        assert!(rows.iter().any(|r|r["connection"]["id"]=="3" && r["detail"]=="handshake timeout"));
        assert_eq!(rows.iter().filter(|r|r["connection"]["id"]=="4").count(),1);
        assert!(!rows.iter().any(|r|r["connection"]["id"]=="5"));
        runtime.shutdown().unwrap();
    }
    #[test]
    fn automatic_alpn_preserves_order_and_bytes() {
        let mut probe=crate::quic_probe::Probe::default();probe.version=Some(1);
        for values in [vec![b"custom/1".to_vec()],vec![b"h3".to_vec(),vec![0,0xff,0x41]],vec![b"other".to_vec(),b"h3".to_vec()]] {
            probe.raw_alpn=values.clone();assert!(admissible(&probe));assert_eq!(offered(&probe),values);
        }
        assert_eq!(alpn_label(&[0,0xff,0x41]),"\\x00\\xffA");
        probe.ech=true;probe.raw_alpn=vec![b"custom/1".to_vec()];assert!(!admissible(&probe));
        probe.raw_alpn=vec![b"h3".to_vec()];assert!(admissible(&probe));
        probe.ech=false;probe.version=Some(2);assert!(!admissible(&probe));
        probe.version=Some(1);probe.raw_alpn.clear();assert!(!admissible(&probe));
    }
}
