//! Ordinary previews are best effort. Retained recordings use bounded,
//! lossless queues and may wait for the independent analysis/disk workers.
use proxylane_protocol::{
    cache::{CacheConfig, CacheRef, PayloadCache},
    Analyzer, Connection, Direction, Limits, Output, Protocol,
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc::{self, Receiver, SyncSender},
        Arc, Mutex, MutexGuard, Condvar,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const QUEUE: usize = 512; // <= 32 MiB for maximum-size UDP datagrams; TCP chunks stay 16 KiB
#[cfg(test)]
const CONNECTIONS: usize = 128;
const RECORDS: usize = 256;
const RECORD_BYTES: usize = 16 * 1024 * 1024;
const POLL_BYTES: usize = 2 * 1024 * 1024;
#[derive(Default)]
struct StopProgress {
    start:Option<Instant>, phase_start:Option<Instant>, phase:&'static str,
    analysis_ms:u64, write_ms:u64, finalize_ms:u64, total_ms:u64, error:Option<String>,
}
impl StopProgress {
    fn begin(&mut self) {let now=Instant::now();*self=Self{start:Some(now),phase_start:Some(now),phase:"analysis",..Default::default()};}
    fn advance(&mut self,phase:&'static str) {
        let elapsed=self.phase_start.map_or(0,|s|s.elapsed().as_millis() as u64);
        match self.phase {"analysis"=>self.analysis_ms=elapsed,"writing"=>self.write_ms=elapsed,"finalizing"=>self.finalize_ms=elapsed,_=>()}
        self.total_ms=self.start.map_or(0,|s|s.elapsed().as_millis() as u64);
        self.phase=phase;self.phase_start=Some(Instant::now());
    }
    fn snapshot(&self)->Value {
        let active=matches!(self.phase,"analysis"|"writing"|"finalizing");
        json!({"type":"monitor_stop_status","active":active,"phase":self.phase,
            "elapsed_ms":if active {self.start.map_or(0,|s|s.elapsed().as_millis() as u64)}else{self.total_ms},
            "analysis_ms":self.analysis_ms,"write_ms":self.write_ms,"finalize_ms":self.finalize_ms,"error":self.error})
    }
}
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}
// Never occupy a QUIC executor worker while waiting for analysis/disk capacity.
// Callers that lock a shared tap must put the lock INSIDE this boundary.
pub(crate) fn blocking<T>(f:impl FnOnce()->T)->T {
    if tokio::runtime::Handle::try_current().is_ok_and(|h|h.runtime_flavor()==tokio::runtime::RuntimeFlavor::MultiThread) {
        tokio::task::block_in_place(f)
    } else {f()}
}

struct Ticket {
    close_reason: Mutex<Option<(u64,String)>>,
    parser_slot: AtomicBool,
    http3_stream_id: Option<u64>,
    identity: Connection,
    pending: AtomicUsize,
    closed: AtomicBool,
    lost: AtomicBool,
}
fn eof_reason(ticket:&Ticket,side:usize,clean:bool)->String {
    lock(&ticket.close_reason).as_ref().map(|(_,s)|s.clone()).unwrap_or_else(|| {
        let peer=if side==0 {"application"}else{"upstream"};
        if clean {format!("{peer} clean transport EOF")}else{format!("{peer} TCP EOF without TLS close_notify")}
    })
}
enum Event {
    #[cfg(test)]
    Panic,
    Timed(u64,Box<Event>),
    #[cfg(test)]
    Pause(mpsc::Receiver<()>,mpsc::Sender<()>),
    Open(u64, Connection, Option<Vec<u8>>, bool, Arc<Ticket>),
    Data(u64, usize, u64, Vec<u8>, Arc<Ticket>),
    Datagram(u64, usize, Vec<u8>, Arc<Ticket>),
    Eof(u64, usize, bool, Arc<Ticket>),
    State(u64, usize, Arc<Ticket>),
    Http3(u64, usize, H3Part, Arc<Ticket>),
    Note(u64, String, Arc<Ticket>),
    Barrier(mpsc::Sender<()>),
    StopCapture(mpsc::Sender<()>),
    Shutdown,
}
impl Event { fn timed(self)->Self { if matches!(self,Self::Timed(..)) {self} else {Self::Timed(proxylane_protocol::recording::observed_ms(),Box::new(self))} } }
pub enum H3Part { Head(proxylane_protocol::Message), Data(Vec<u8>), End(proxylane_protocol::Headers) }
#[derive(Default)]
struct Results {
    archive: Option<PayloadCache>,
    sequence: u64,
    published: Arc<Mutex<PublishedResults>>,
}
#[derive(Default)]
struct PublishedResults {
    sequence:u64,
    bytes: usize,
    evicted: u64,
    records: VecDeque<(u64, Value, usize)>,
}
impl Results {
    fn add(&mut self, mut value: Value) {
        self.sequence += 1;
        value["sequence"] = self.sequence.into();
        value["observed_unix_ms"] = proxylane_protocol::recording::observed_ms().into();
        if let Some(cache)=&self.archive {cache.record(json!({"type":"observation","record":record_metadata(value.clone())}));}
        let size = serde_json::to_vec(&value).map_or(POLL_BYTES + 1, |v| v.len());
        // Keep each poll bounded, including a single pathological record.
        if size > POLL_BYTES {
            value = json!({"type":"analysis_diagnostic", "sequence":self.sequence,
                "connection":value["connection"], "detail":"result exceeds retention limit"});
        }
        let size = serde_json::to_vec(&value).unwrap().len();
        // The recording queue may wait above, but never with this UI lock held.
        let mut published=lock(&self.published);
        published.sequence=self.sequence;
        published.bytes += size;
        published.records.push_back((self.sequence, value, size));
        while published.bytes > RECORD_BYTES || published.records.len() > RECORDS {
            if let Some((_, _, size)) = published.records.pop_front() {
                published.bytes -= size;
                published.evicted += 1;
            }
        }
    }
}
fn record_metadata(mut value:Value)->Value {
    match &mut value {
        Value::Object(map)=>{for key in ["body_base64","decoded_base64","text"] {map.remove(key);}
            for child in map.values_mut() {*child=record_metadata(child.take());}}
        Value::Array(items)=>for child in items {*child=record_metadata(child.take());},
        _=>()
    }
    value
}

pub struct Runtime {
    failure: Arc<proxylane_protocol::worker_failure::WorkerFailure>,
    published:Arc<Mutex<PublishedResults>>,
    stop_progress:Mutex<StopProgress>,
    space: Arc<tokio::sync::Notify>,
    pub(crate) options: crate::options::Options,
    sender: SyncSender<Event>,
    worker: Mutex<Option<JoinHandle<()>>>,
    stopping: AtomicBool,
    // Odd epochs accept capture. Even epochs are paused; old taps never resume.
    capture_epoch: Mutex<u64>,
    process_events: Mutex<()>,
    process_inflight: Mutex<usize>,
    process_drained: Condvar,
    next: AtomicU64,
    active: Arc<AtomicUsize>,
    parsers: Arc<AtomicUsize>,
    rejected: AtomicU64,
    results: Arc<Mutex<Results>>,
    cache: Option<PayloadCache>,
    cache_error: Option<String>,
    pub run_id: String,
}
impl Runtime {
    pub(crate) fn worker_error(&self)->Option<String> {
        self.failure.reason().or_else(||self.cache.as_ref().and_then(PayloadCache::worker_error))
    }
    pub fn recording_status(&self)->Value {
        let mut status=self.cache.as_ref().map_or(json!({"enabled":false}),PayloadCache::recording_status);
        if let Some(reason)=self.worker_error() {status["stopped"]=true.into();status["worker_failed"]=true.into();status["reason"]=reason.into();}
        status
    }
    pub fn recording_failed(&self)->bool {
        self.failure.failed() || self.cache.as_ref().is_some_and(|c|c.worker_failed() || c.recording_failed())
    }
    pub fn is_recording(&self)->bool {self.cache.as_ref().is_some_and(PayloadCache::is_recording)}
    fn fail_recording(&self, reason:&str) {if let Some(cache)=&self.cache {cache.fail_recording(reason);}}
    fn issue(&self, gap:bool, reason:&str, context:Value) {
        if let Some(cache)=&self.cache {cache.recording_issue(gap,reason,context);}
    }
    pub fn lifecycle(&self, epoch: u64, identity: &Connection, state: &str, protocol: &str, problem: &str, skipped: bool) {
        blocking(||self.lifecycle_inner(epoch,identity,state,protocol,problem,skipped));
    }
    fn lifecycle_inner(&self, epoch:u64, identity:&Connection, state:&str, protocol:&str, problem:&str, skipped:bool) {
        let gate = lock(&self.capture_epoch);
        if *gate != epoch || epoch % 2 == 0 || self.stopping.load(Ordering::Acquire) || self.recording_failed() { return; }
        lock(&self.results).add(json!({"type":"connection", "connection":identity, "protocol":protocol,
            "status":state,"detail":problem,"upstream_verification_skipped":skipped}));
    }
    pub(crate) fn record_process_created(&self, request:&Value)->Result<bool,String> {
        self.record_process_with(||crate::process_events::collect(request))
    }
    fn record_process_with(&self, collect:impl FnOnce()->Result<Value,String>)->Result<bool,String> {
        if !self.is_recording() {return Ok(false);}
        let observed=proxylane_protocol::recording::now_ms();
        {
            let epoch=lock(&self.capture_epoch);
            if *epoch%2==0 || self.stopping.load(Ordering::Acquire) || self.recording_failed() {return Ok(false);}
            *lock(&self.process_inflight)+=1;
        }
        struct Admission<'a>(&'a Runtime);
        impl Drop for Admission<'_> {fn drop(&mut self) {
            let mut n=lock(&self.0.process_inflight);*n-=1;
            if *n==0 {self.0.process_drained.notify_all();}
        }}
        let _admission=Admission(self);
        // Serialize only creation notifications. Never hold the capture gate,
        // results lock, or protocol slot while serializing / waiting for disk.
        let _producer=lock(&self.process_events);
        let mut event=collect()?;event["observed_unix_ms"]=observed.into();
        self.cache.as_ref().unwrap().record_process_created(event)?;
        Ok(true)
    }
    fn drain_process_events(&self) {
        let mut n=lock(&self.process_inflight);
        while *n!=0 {n=self.process_drained.wait(n).unwrap_or_else(|e|e.into_inner());}
    }
    pub fn capture_epoch(&self) -> u64 { *lock(&self.capture_epoch) }
    pub fn start_capture(&self) {
        *lock(&self.stop_progress)=StopProgress::default();
        let mut epoch = lock(&self.capture_epoch);
        if *epoch % 2 == 0 { *epoch += 1; }
    }
    pub fn stop_capture(&self) -> Result<(), String> {
        lock(&self.stop_progress).begin();
        let result=self.finish_capture();
        let mut progress=lock(&self.stop_progress);
        progress.advance(if result.is_ok(){"complete"}else{"failed"});
        progress.error=result.as_ref().err().cloned();
        result
    }
    fn finish_capture(&self) -> Result<(), String> {
        // Only close the gate under the producer lock. Never hold it while
        // waiting for analysis or disk I/O: forwarding must keep running.
        {
            let mut epoch = lock(&self.capture_epoch);
            if *epoch % 2 != 0 { *epoch += 1; }
        }
        // A notification admitted before the gate closed must be enqueued
        // before the disk-worker finish barrier. No network locks are held.
        self.drain_process_events();
        let (tx, rx) = mpsc::channel();
        let analysis=self.sender.send(Event::StopCapture(tx).timed()).map_err(|_| "analysis worker unavailable")
            .and_then(|_|rx.recv().map_err(|_| "analysis worker unavailable"));
        // stats is a FIFO disk-worker barrier, retaining all existing payloads.
        lock(&self.stop_progress).advance("writing");
        let writing=self.cache.as_ref().map(PayloadCache::stats).transpose();
        lock(&self.stop_progress).advance("finalizing");
        let finalizing=self.cache.as_ref().map(PayloadCache::finish_recording).transpose();
        if let Some(reason)=self.worker_error() {return Err(reason);}
        analysis?;writing?;finalizing?;
        Ok(())
    }
    pub fn configured() -> Result<Arc<Self>, String> {
        let mut config = CacheConfig::default();
        if let Some(root) = std::env::var_os("PROXYLANE_PROTOCOL_CACHE_ROOT") {
            config.root = root.into();
        }
        for (name, limit) in [
            ("PROXYLANE_PROTOCOL_ENTRY_BYTES", &mut config.entry_bytes),
            ("PROXYLANE_PROTOCOL_TOTAL_BYTES", &mut config.total_bytes),
        ] {
            if let Ok(value) = std::env::var(name) {
                *limit = value.parse().map_err(|_| format!("invalid {name}"))?;
            }
        }
        let options=crate::options::current();
        if std::env::var_os("PROXYLANE_PROTOCOL_ENTRY_BYTES").is_none() {config.entry_bytes=options.entry_mib*1024*1024;}
        if std::env::var_os("PROXYLANE_PROTOCOL_TOTAL_BYTES").is_none() {config.total_bytes=options.total_mib*1024*1024;}
        config.max_entries=(options.history_rows*2).max(4096);
        if options.recording.enabled {
            config.queue_chunks=1024;
            config.root=options.recording.directory.clone().into();
            config.recording=Some(proxylane_protocol::recording::RecordingConfig {
                total_bytes:options.recording.capacity_mib*1024*1024,min_free_bytes:options.recording.reserve_mib*1024*1024});
        }
        Self::with_options(config,options)
    }
    pub fn new(config: CacheConfig) -> Result<Arc<Self>, String> {
        Self::with_options(config,crate::options::Options::default())
    }
    fn with_options(config:CacheConfig, options:crate::options::Options) -> Result<Arc<Self>,String> {
        Self::with_queue(config,options,QUEUE)
    }
    fn with_queue(mut config:CacheConfig, options:crate::options::Options,queue:usize) -> Result<Arc<Self>,String> {
        options.validate()?;
        config.decode_bytes=options.decode_mib*1024*1024;
        config.decode_input_bytes=config.entry_bytes.min(64*1024*1024) as usize;
        let worker_options=options.clone();
        let mut random = [0u8; 16];
        getrandom::getrandom(&mut random).map_err(|e| e.to_string())?;
        let retained=config.recording.is_some();
        let (cache, cache_error) = match PayloadCache::new(config) {
            Ok(cache) => (Some(cache), None),
            Err(e) if retained => return Err(e),
            Err(e) => (None, Some(e)),
        };
        let results = Arc::new(Mutex::new(Results {archive:if retained {cache.clone()}else{None},..Default::default()}));
        let published=lock(&results).published.clone();
        let active = Arc::new(AtomicUsize::new(0));
        let parsers = Arc::new(AtomicUsize::new(0));
        let (sender, receiver) = mpsc::sync_channel(queue);
        let space=Arc::new(tokio::sync::Notify::new());
        let worker_space=space.clone();
        let worker_results = results.clone();
        let worker_active = active.clone();
        let worker_parsers = parsers.clone();
        let worker_cache = cache.clone();
        let failure=Arc::new(proxylane_protocol::worker_failure::WorkerFailure::default());
        let worker_failure=failure.clone();
        let worker = thread::Builder::new()
            .name("protocol-analysis".into())
            .spawn(move || {
                let outcome=std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                Worker {
                    options: worker_options,
                    connections: BTreeMap::new(),
                    cache: worker_cache.clone(),
                    results: worker_results,
                    active: worker_active,
                    parsers: worker_parsers,
                }
                .run_notifying(receiver,worker_space.clone());
                }));
                if let Err(payload)=outcome {
                    let reason=proxylane_protocol::worker_failure::panic_reason("protocol-analysis",payload.as_ref());
                    if let Some(cache)=&worker_cache {
                        cache.analysis_worker_failed(&reason);
                    }
                    worker_failure.set(&reason);
                    worker_space.notify_waiters();
                }
            })
            .map_err(|e| e.to_string())?;
        Ok(Arc::new(Self {
            failure,
            published,
            stop_progress:Mutex::new(StopProgress::default()),
            space,
            options,
            sender,
            worker: Mutex::new(Some(worker)),
            stopping: AtomicBool::new(false),
            capture_epoch: Mutex::new(1),
            process_events: Mutex::new(()),
            process_inflight: Mutex::new(0),
            process_drained: Condvar::new(),
            next: AtomicU64::new(1),
            active,
            parsers,
            rejected: AtomicU64::new(0),
            results,
            cache,
            cache_error,
            run_id: format!("{:032x}", u128::from_le_bytes(random)),
        }))
    }
    #[cfg(test)]
    pub(crate) fn test_small_queue(config:CacheConfig)->Arc<Self> {
        Self::with_queue(config,Default::default(),2).unwrap()
    }
    #[cfg(test)]
    pub(crate) fn pause_worker(&self)->mpsc::Sender<()> {
        let (resume,wait)=mpsc::channel();let (entered,ready)=mpsc::channel();
        self.sender.send(Event::Pause(wait,entered)).unwrap();ready.recv().unwrap();resume
    }
    #[cfg(test)]
    pub(crate) fn panic_worker(&self) {
        self.sender.send(Event::Panic).unwrap();
        let deadline=Instant::now()+Duration::from_secs(3);
        while self.worker_error().is_none() {assert!(Instant::now()<deadline);thread::yield_now();}
    }
    #[cfg(test)]
    pub(crate) fn fill_paused_queue(&self) {
        for _ in 0..2 {let(tx,_)=mpsc::channel();assert!(self.sender.try_send(Event::Barrier(tx)).is_ok());}
    }
    pub fn tap(self: &Arc<Self>, connection: Connection, alpn: Option<Vec<u8>>) -> Option<Tap> {
        self.tap_transport(connection, alpn, true)
    }
    pub async fn tap_at_async(self:&Arc<Self>,epoch:u64,connection:Connection,alpn:Option<Vec<u8>>,decrypted:bool)->Option<Tap> {
        // Admission is rare and synchronous; bound the replacement threads.
        static ADMISSION:tokio::sync::Semaphore=tokio::sync::Semaphore::const_new(4);
        let _permit=ADMISSION.acquire().await.ok()?;
        blocking(||self.tap_at(epoch,connection,alpn,decrypted))
    }
    pub fn tap_transport(self: &Arc<Self>, connection: Connection, alpn: Option<Vec<u8>>, decrypted: bool) -> Option<Tap> {
        self.tap_at(self.capture_epoch(), connection, alpn, decrypted)
    }
    pub fn tap_at(self: &Arc<Self>, epoch: u64, mut connection: Connection, alpn: Option<Vec<u8>>, decrypted: bool) -> Option<Tap> {
        let gate = lock(&self.capture_epoch);
        if *gate != epoch || epoch % 2 == 0 || self.stopping.load(Ordering::Acquire) || self.recording_failed() {
            return None;
        }
        connection.decrypted = decrypted;
        let retained=self.is_recording();
        let h3=alpn.as_ref().is_some_and(|a|a.starts_with(b"h3:"));
        let raw_quic=connection.quic_stream_id.is_some() || connection.quic_datagrams;
        if self
            .active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (retained || n < self.options.connections).then_some(n + 1)
            })
            .is_err()
        {
            self.rejected.fetch_add(1, Ordering::Relaxed);
            self.issue(true,"capture stream safety limit reached",json!({"connection":connection,"alpn":alpn,
                "scope":"entire connection/request was not admitted"}));
            return None;
        }
        // HTTP/3 arrives as decoded messages, not wire bytes for another parser.
        let parser_slot=!h3 && !raw_quic && self.parsers.fetch_update(Ordering::AcqRel,Ordering::Acquire,
            |n|(n<self.options.connections).then_some(n+1)).is_ok();
        if !h3 && !raw_quic && !parser_slot && !retained {
            self.active.fetch_sub(1,Ordering::AcqRel);self.rejected.fetch_add(1,Ordering::Relaxed);return None;
        }
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let ticket = Arc::new(Ticket {
            close_reason: Mutex::new(None),
            parser_slot: AtomicBool::new(parser_slot),
            http3_stream_id: alpn.as_ref().and_then(|a|a.strip_prefix(b"h3:")).and_then(|a|std::str::from_utf8(a).ok()).and_then(|s|s.parse().ok()),
            identity: connection.clone(),
            pending: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
            lost: AtomicBool::new(false),
        });
        if let Err(error)=self.submit(Event::Open(id, connection, alpn, decrypted, ticket.clone()))
        {
            self.active.fetch_sub(1, Ordering::AcqRel);
            if parser_slot {self.parsers.fetch_sub(1,Ordering::AcqRel);}
            self.rejected.fetch_add(1, Ordering::Relaxed);
            self.issue(true,"analysis admission queue unavailable",json!({"connection":ticket.identity,"http3_stream_id":ticket.http3_stream_id,
                "scope":"entire connection/request was not admitted"}));
            if matches!(error,mpsc::TrySendError::Disconnected(_)) {self.fail_recording("analysis worker unavailable");}
            return None;
        }
        Some(Tap {
            owner: self.clone(),
            epoch,
            id,
            ticket,
            offsets: [0; 2],
            ended: [false; 2],
        })
    }
    fn submit(&self,event:Event)->Result<(),mpsc::TrySendError<Event>> {
        let event=event.timed();
        if self.is_recording() {
            blocking(||self.sender.send(event).map_err(|e|mpsc::TrySendError::Disconnected(e.0)))
        } else {self.sender.try_send(event)}
    }
    // Query calls belong on a consumer/background thread, never the PRC thread.
    pub fn query(&self, request: &Value) -> Result<Value, String> {
        // Never queue behind the workers being drained. The GUI can poll this
        // tiny snapshot even while an analysis/disk barrier is waiting.
        if request["type"]=="monitor_stop_status" {return Ok(lock(&self.stop_progress).snapshot());}
        if request["type"]=="recording_status" {return Ok(self.recording_status());}
        if let Some(reason)=self.worker_error() {return Err(reason);}
        if self.stopping.load(Ordering::Acquire) {
            return Err("analysis stopped".into());
        }
        // Only the live GUI opts into eventual, already-published snapshots.
        // Library callers and stop/finalization keep their existing barriers.
        let preview=request["live_preview"]==true && self.is_recording();
        if !preview {
        let (tx, rx) = mpsc::channel();
        self.sender
            .send(Event::Barrier(tx))
            .map_err(|_| "analysis worker unavailable")?;
        rx.recv().map_err(|_| "analysis worker unavailable")?;
        }
        let kind = request["type"].as_str().ok_or("missing query type")?;
        let result = match kind {
            "stats" => {
                let cache = if preview {None}else{self.cache.as_ref().map(PayloadCache::stats).transpose()?};
                let records = lock(&self.published);
                json!({"type":"stats", "active_connections":self.active.load(Ordering::Acquire),
                    "active_parsers":self.parsers.load(Ordering::Acquire),
                    "rejected_connections":self.rejected.load(Ordering::Relaxed),
                    "last_sequence":records.sequence, "retained_records":records.records.len(),
                    "retained_bytes":records.bytes, "evicted_records":records.evicted,
                    "cache":cache, "cache_error":self.cache_error})
            }
            "poll" => {
                let after = request["after"].as_u64().unwrap_or(0);
                let limit = request["limit"].as_u64().unwrap_or(16).clamp(1, 64) as usize;
                let records = lock(&self.published);
                let mut bytes = 0;
                let mut output = Vec::new();
                let mut next = after;
                for (seq, value, size) in &records.records {
                    if *seq <= after {
                        continue;
                    }
                    if output.len() == limit || bytes + size > POLL_BYTES {
                        break;
                    }
                    bytes += size;
                    next = *seq;
                    output.push(value.clone());
                }
                let oldest = records
                    .records
                    .front()
                    .map_or(records.sequence + 1, |r| r.0);
                json!({"type":"records", "records":output, "next":next,
                    "lost_before":oldest.saturating_sub(after.saturating_add(1)),
                    "last_sequence":records.sequence})
            }
            "cache_status" | "cache_read" | "cache_decode" | "dns_read" | "doh_read" => {
                if request["run_id"].as_str() != Some(&self.run_id) {
                    return Err("stale or missing run_id".into());
                }
                let cache = self.cache.as_ref().ok_or("payload cache unavailable")?;
                let id = request["cache_id"].as_u64().ok_or("missing cache_id")?;
                if kind == "cache_status" {
                    if preview {json!({"type":"cache_status","cache":cache.preview_status(id)?})}
                    else {json!({"type":"cache_status", "cache":cache.status(id)?})}
                } else {
                    let direction: Direction = serde_json::from_value(request["direction"].clone())
                        .map_err(|e| e.to_string())?;
                    let payload = if kind == "cache_read" || kind == "dns_read" {
                        let length =
                            request["length"].as_u64().unwrap_or(65536).min(1024*1024+1) as usize;
                        if preview {cache.preview_read(id,direction,request["offset"].as_u64().unwrap_or(0),length,false)?}
                        else {cache.read(
                            id,
                            direction,
                            request["offset"].as_u64().unwrap_or(0),
                            length,
                        )?}
                    } else {
                        let preview=request["preview_bytes"].as_u64().unwrap_or(65536).clamp(1,1024*1024) as usize;
                        // DNS parsing needs the complete wire message even when the GUI
                        // displays a smaller prefix. Its wire size is bounded to 65535.
                        let length=if kind=="doh_read" {preview.max(65535)} else {preview};
                        if request["live_preview"]==true && self.is_recording() {cache.preview_read(id,direction,0,length,true)?}
                        else {cache.decode_preview(id, direction, self.options.decode_mib * 1024 * 1024,length)?}
                    };
                    let decoded = if (kind == "dns_read" || kind == "doh_read") && !payload.data_base64.is_empty() {
                        Some(proxylane_protocol::dns::decode(&payload.data_base64).map(|p|p.text))
                    } else {None};
                    json!({"type":"cache_payload", "payload":payload,
                        "text":decoded.as_ref().and_then(|r|r.as_ref().ok()),
                        "decode_error":decoded.as_ref().and_then(|r|r.as_ref().err())})
                }
            }
            _ => return Err("unknown protocol query".into()),
        };
        let mut result = result;
        result["run_id"] = self.run_id.clone().into();
        Ok(result)
    }
    pub fn shutdown(&self) -> Result<(), String> {
        let mut worker = lock(&self.worker);
        {let _gate=lock(&self.capture_epoch);self.stopping.store(true, Ordering::Release);}
        self.drain_process_events();
        if let Some(handle) = worker.take() {
            let _ = self.sender.send(Event::Shutdown);
            handle.join().map_err(|_| "analysis worker panicked")?;
        }
        if let Some(cache) = &self.cache {
            cache.shutdown()?;
        }
        Ok(())
    }
}
impl Drop for Runtime {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

pub struct Tap {
    owner: Arc<Runtime>,
    epoch: u64,
    id: u64,
    ticket: Arc<Ticket>,
    offsets: [u64; 2],
    ended: [bool; 2],
}
struct PendingSend<'a> {tap:&'a Tap,event:Option<Event>}
impl Drop for PendingSend<'_> {
    fn drop(&mut self) {
        // Cancelling a QUIC forwarding future must not discard plaintext that
        // was already read while waiting for the recording queue.
        if let Some(event)=self.event.take() {blocking(||self.tap.send(event));}
    }
}
impl Tap {
    pub fn try_data(&mut self,side:usize,bytes:&[u8])->bool {
        if !self.owner.is_recording() {self.data(side,bytes);return true;}
        assert!(bytes.len()<=16384);
        let gate=match self.owner.capture_epoch.try_lock() {
            Ok(g)=>g,
            Err(std::sync::TryLockError::Poisoned(e))=>e.into_inner(),
            Err(std::sync::TryLockError::WouldBlock)=>return false,
        };
        if *gate!=self.epoch || self.epoch%2==0 || !self.accepting() {return true;}
        self.ticket.pending.fetch_add(1,Ordering::AcqRel);
        let event=Event::Data(self.id,side,self.offsets[side],bytes.to_vec(),self.ticket.clone()).timed();
        match self.owner.sender.try_send(event) {
            Ok(())=>{self.offsets[side]+=bytes.len() as u64;true}
            Err(e)=>{
                self.ticket.pending.fetch_sub(1,Ordering::AcqRel);
                if matches!(e,mpsc::TrySendError::Disconnected(_)) {self.owner.fail_recording("analysis worker unavailable");true}
                else {false}
            }
        }
    }
    async fn send_async(&self,event:Event) {
        if !self.owner.is_recording() {self.send(event);return;}
        let mut queued=PendingSend {tap:self,event:Some(event.timed())};
        loop {
            let wake=self.owner.space.notified();tokio::pin!(wake);wake.as_mut().enable();
            let busy = {
                match self.owner.capture_epoch.try_lock() {
                    Err(std::sync::TryLockError::WouldBlock)=>true,
                    guard=>{
                        let gate=guard.unwrap_or_else(|e|match e {std::sync::TryLockError::Poisoned(e)=>e.into_inner(),_=>unreachable!()});
                        if *gate!=self.epoch || self.epoch%2==0 || !self.accepting() {queued.event.take();return;}
                        self.ticket.pending.fetch_add(1,Ordering::AcqRel);
                        match self.owner.sender.try_send(queued.event.take().unwrap()) {
                            Ok(())=>return,
                            Err(mpsc::TrySendError::Full(e))=>{queued.event=Some(e);self.ticket.pending.fetch_sub(1,Ordering::AcqRel);}
                            Err(mpsc::TrySendError::Disconnected(_))=>{
                                self.ticket.pending.fetch_sub(1,Ordering::AcqRel);
                                self.owner.fail_recording("analysis worker unavailable");return;
                            }
                        }
                        false
                    }
                }
            };
            if busy {tokio::time::sleep(Duration::from_millis(1)).await;} else {wake.await;}
        }
    }
    pub async fn http3_async(&self,side:usize,part:H3Part) {
        self.send_async(Event::Http3(self.id,side,part,self.ticket.clone())).await;
    }
    pub async fn data_async(&mut self,side:usize,bytes:&[u8]) {
        for chunk in bytes.chunks(16384) {
            self.send_async(Event::Data(self.id,side,self.offsets[side],chunk.to_vec(),self.ticket.clone())).await;
            self.offsets[side]+=chunk.len() as u64;
        }
    }
    pub async fn datagram_async(&mut self,side:usize,bytes:&[u8]) {
        self.send_async(Event::Datagram(self.id,side,bytes.to_vec(),self.ticket.clone())).await;
    }
    pub async fn note_async(&self,note:String) {self.send_async(Event::Note(self.id,note,self.ticket.clone())).await;}
    pub async fn eof_async(&mut self,side:usize,clean:bool) {
        if !self.ended[side] {self.ended[side]=true;self.send_async(Event::Eof(self.id,side,clean,self.ticket.clone())).await;}
    }
    pub fn is_capturing(&self)->bool { *lock(&self.owner.capture_epoch)==self.epoch && self.epoch%2!=0 && self.accepting() }
    pub fn http3(&self, side:usize, part:H3Part) { self.send(Event::Http3(self.id,side,part,self.ticket.clone())); }
    pub fn close_reason(&self,reason:String) {let mut slot=lock(&self.ticket.close_reason);if slot.is_none(){*slot=Some((proxylane_protocol::recording::observed_ms(),reason));}}
    pub fn transport_closed(&self,side:usize,error:usize) {
        *lock(&self.ticket.close_reason)=Some((proxylane_protocol::recording::observed_ms(),
            format!("{} TCP transport closed (socket error {error})",if side==0 {"application"}else{"upstream"})));
    }
    pub fn note(&self, note:String) {self.send(Event::Note(self.id,note,self.ticket.clone()));}
    pub fn transport_result(&mut self, error: usize) { self.send(Event::State(self.id,error,self.ticket.clone())); }
    fn accepting(&self) -> bool {
        !self.ticket.lost.load(Ordering::Acquire) && !self.ticket.closed.load(Ordering::Acquire)
            && !self.owner.stopping.load(Ordering::Acquire) && !self.owner.recording_failed()
    }
    fn send(&self, event: Event) {
        let gate = lock(&self.owner.capture_epoch);
        if *gate != self.epoch || self.epoch % 2 == 0 || !self.accepting() { return; }
        self.enqueue(event);
    }
    fn enqueue(&self, event: Event) {
        self.ticket.pending.fetch_add(1, Ordering::AcqRel);
        if let Err(error)=self.owner.submit(event) {
            // Out-of-band terminal flag cannot itself be lost in the full queue.
            self.ticket.lost.store(true, Ordering::Release);
            self.owner.issue(true,"analysis queue overflow",json!({"connection":self.ticket.identity,
                "capture_id":self.id,"http3_stream_id":self.ticket.http3_stream_id,
                "scope":"capture is incomplete from the first rejected event until this connection/request ends"}));
            if matches!(error,mpsc::TrySendError::Disconnected(_)) {self.owner.fail_recording("analysis worker unavailable");}
            self.ticket.pending.fetch_sub(1, Ordering::AcqRel);
        }
    }
    pub fn data(&mut self, side: usize, bytes: &[u8]) {
        let gate = lock(&self.owner.capture_epoch);
        if *gate != self.epoch || self.epoch % 2 == 0 || !self.accepting() { return; }
        for chunk in bytes.chunks(16384) {
            self.enqueue(Event::Data(self.id, side, self.offsets[side], chunk.to_vec(), self.ticket.clone()));
            self.offsets[side] += chunk.len() as u64;
            if self.ticket.lost.load(Ordering::Acquire) { break; }
        }
    }
    pub fn datagram(&mut self, side: usize, bytes: &[u8]) {
        let gate = lock(&self.owner.capture_epoch);
        if bytes.len() > 65535 || *gate != self.epoch || self.epoch % 2 == 0 || !self.accepting() { return; }
        self.enqueue(Event::Datagram(self.id, side, bytes.to_vec(), self.ticket.clone()));
    }
    pub fn eof(&mut self, side: usize, clean: bool) {
        if !self.ended[side] && !self.ticket.lost.load(Ordering::Acquire) {
            self.ended[side] = true;
            self.send(Event::Eof(self.id, side, clean, self.ticket.clone()));
        }
    }
}
impl Drop for Tap {
    fn drop(&mut self) {
        self.close_reason("capture owner released; transport close cause unavailable".into());
        self.ticket.closed.store(true, Ordering::Release);
    }
}

struct Stream {
    deferred: Option<CacheRef>,
    deferred_alpn: Option<Vec<u8>>,
    deferred_bytes: u64,
    fallback: bool,
    analysis_note: Option<String>,
    h3: Option<proxylane_protocol::http3::Capture>,
    dns: Option<crate::dns::Dns>,
    quic: crate::quic_probe::Probe,
    identity: Connection,
    ticket: Arc<Ticket>,
    analyzer: Option<Analyzer>,
    sniff: Vec<u8>,
    detect: bool,
    decrypted: bool,
    encrypted: bool,
    cache: Option<CacheRef>,
    counts: [u64; 2],
    datagrams: [Vec<(u64, usize)>; 2],
    packet_counts: [u64; 2],
    ended: [bool; 2],
    dirty: bool,
    published: Instant,
    opened: Instant,
}
struct Worker {
    options:crate::options::Options,
    connections: BTreeMap<u64, Stream>,
    cache: Option<PayloadCache>,
    results: Arc<Mutex<Results>>,
    active: Arc<AtomicUsize>,
    parsers: Arc<AtomicUsize>,
}
impl Worker {
    fn records(&self, records: Vec<Value>) {
        let mut results=lock(&self.results);for record in records {results.add(record);}
    }
    fn output(&self, out: Vec<Output>) -> Option<String> {
        let mut error=None;
        for output in out {
            // A malformed/partially captured protocol affects this connection,
            // not the lifetime of all other recordings. Persist the diagnostic.
            if let Output::Diagnostic {detail,..}=&output {error=Some(detail.clone());}
            if let Ok(mut value) = serde_json::to_value(output) {
                crate::doh::annotate(&mut value);
                lock(&self.results).add(value);
            }
        }
        error
    }
    fn fallback(&self, stream:&mut Stream, reason:&str) {
        if !stream.fallback {
            if let Some(cache)=&self.cache {
                cache.recording_analysis_fallback(reason,json!({"connection":stream.identity}));
            }
        }
        stream.analyzer=None;stream.detect=false;stream.sniff.clear();stream.fallback=true;
        stream.analysis_note=Some(reason.to_owned());
        stream.cache=self.cache.as_ref().map(|c|c.scoped(json!({"connection":stream.identity,
            "protocol":"tcp","kind":"analysis_fallback","reason":reason,
            "note":"Raw data from the failing input chunk onward; that first chunk may overlap an earlier parsed payload."})).stream());
        stream.dirty=true;
    }
    fn fallback_data(&self, stream:&mut Stream, side:usize, source_offset:u64, bytes:&[u8]) {
        if let Some(c)=&stream.cache {c.record(json!({"type":"analysis_fallback_chunk","side":side,
            "source_offset":source_offset,"offset":stream.counts[side],"length":bytes.len()}));}
        self.opaque_data(stream,side,bytes);
    }
    fn data(&self,stream:&mut Stream,side:usize,offset:u64,bytes:&[u8]) {
                        if let Some(dns)=&mut stream.dns {
                            self.records(dns.tcp(&stream.identity,self.cache.as_ref(),side,&bytes));
                        } else if stream.detect {
                            if side != 0 {
                                self.opaque(stream);
                                self.opaque_data(stream, side, &bytes);
                            } else {
                                stream.sniff.extend_from_slice(&bytes);
                                const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
                                let mut opaque = false;
                                let protocol = if stream.sniff.starts_with(PREFACE) {
                                    Some(Protocol::H2)
                                } else if PREFACE.starts_with(&stream.sniff) { None }
                                else if !stream.decrypted && stream.sniff[0] == 0x16 {
                                    if stream.sniff.len() >= 3 {
                                        stream.encrypted = stream.sniff[1] == 3 && stream.sniff[2] <= 3;
                                        opaque = true;
                                    }
                                    None
                                } else if let Some(end) = stream.sniff.windows(2).position(|v| v == b"\r\n") {
                                    let parts: Vec<_> = stream.sniff[..end].split(|c| *c == b' ').collect();
                                    if parts.len() == 3 && !parts[0].is_empty() && !parts[1].is_empty()
                                        && parts[0].iter().all(|c| c.is_ascii_uppercase())
                                        && matches!(parts[2], b"HTTP/1.0" | b"HTTP/1.1") {
                                        Some(Protocol::Http1)
                                    } else { opaque = true; None }
                                } else {
                                    opaque = stream.sniff.len() > 8192 || stream.sniff.iter().any(|b| *b == 0 || *b >= 128);
                                    None
                                };
                                if let Some(protocol) = protocol {
                                    let mut parser = self.parser(stream.identity.clone(), protocol);
                                    let sniff=std::mem::take(&mut stream.sniff);
                                    if let Some(reason)=self.output(parser.push(Direction::Client, 0, &sniff)) {
                                        self.fallback(stream,&reason);self.fallback_data(stream,0,0,&sniff);
                                    } else {stream.analyzer = Some(parser);}
                                    stream.detect = false;
                                    stream.sniff = Vec::new();
                                } else if opaque { self.opaque(stream); }
                            }
                        } else if let Some(parser) = &mut stream.analyzer {
                            if let Some(reason)=self.output(parser.push(direction(side), offset, &bytes)) {
                                self.fallback(stream,&reason);self.fallback_data(stream,side,offset,&bytes);
                            }
                        } else if stream.fallback {self.fallback_data(stream,side,offset,&bytes);}
                        else { self.opaque_data(stream, side, &bytes); }
    }
    fn datagram(&self,stream:&mut Stream,side:usize,bytes:&[u8]) {
                        // Only probe DNS off-port at the beginning of a flow.
                        if !stream.decrypted && !stream.fallback && stream.dns.is_none() && stream.packet_counts==[0,0] && proxylane_protocol::dns::decode(&bytes).is_ok() {
                            stream.dns=Some(crate::dns::Dns::default());
                            if let Some(c)=stream.cache.take(){c.finish_stream([0,0],true);}
                        }
                        if let Some(dns)=&mut stream.dns {
                            self.records(dns.feed(&stream.identity,self.cache.as_ref(),side,&bytes));
                        } else {
                            if !stream.decrypted && !stream.fallback {stream.quic.feed(side,&bytes);}
                            if stream.datagrams[side].len() < self.options.udp_packets { stream.datagrams[side].push((stream.counts[side], bytes.len())); }
                            stream.packet_counts[side] += 1;
                            let offset=stream.counts[side];
                            if let Some(c)=&stream.cache {c.record(json!({"type":"datagram","side":side,"offset":offset,"length":bytes.len(),"packet_number":stream.packet_counts[side]}));}
                            self.opaque_data(stream, side, &bytes);
                        }
    }
    fn defer(&self,stream:&mut Stream,kind:u8,side:usize,bytes:&[u8]) {
        let cache=stream.deferred.as_ref().unwrap();
        let mut frame=Vec::with_capacity(bytes.len()+14);
        frame.extend_from_slice(&proxylane_protocol::recording::observed_ms().to_le_bytes());
        frame.extend_from_slice(&[kind,side as u8]);frame.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        frame.extend_from_slice(bytes);cache.append_stream(Direction::Client,&frame);
        stream.deferred_bytes+=frame.len() as u64;
    }
    fn replay(&self,stream:&mut Stream)->Result<(),String> {
        use std::io::Read;
        let spool=stream.deferred.take().unwrap();
        let cache=self.cache.as_ref().ok_or("missing backlog cache")?;
        spool.finish_stream([stream.deferred_bytes,0],true);cache.stats()?;
        if cache.recording_failed() {return Ok(());}
        let protocol=match stream.deferred_alpn.as_deref() {Some(b"h2")=>Some(Protocol::H2),Some(b"http/1.1")=>Some(Protocol::Http1),_=>None};
        let udp=stream.identity.transport=="udp";
        stream.dns=if stream.identity.server_port==53 {Some(crate::dns::Dns::default())}else{None};
        stream.analyzer=if stream.dns.is_none() {protocol.map(|p|self.parser(stream.identity.clone(),p))}else{None};
        stream.detect=stream.deferred_alpn.is_none() && !udp && stream.dns.is_none();
        if stream.dns.is_none() && (udp || (protocol.is_none() && !stream.detect)) {self.opaque(stream);}
        let mut offsets=[0u64;2];
        if stream.deferred_bytes!=0 {
            let mut file=std::fs::File::open(cache.directory().join(proxylane_protocol::recording::payload_relative(spool.id(),0))).map_err(|e|e.to_string())?;
            let mut left=stream.deferred_bytes;
            while left>0 {
                let mut time=[0u8;8];file.read_exact(&mut time).map_err(|e|e.to_string())?;
                let _time=proxylane_protocol::recording::observation_time(u64::from_le_bytes(time));
                let mut header=[0u8;6];file.read_exact(&mut header).map_err(|e|e.to_string())?;
                let n=u32::from_le_bytes(header[2..6].try_into().unwrap()) as usize;
                if header[1]>1 || n>65535 || left<14+n as u64 {return Err("invalid analysis backlog frame".into());}
                let side=header[1] as usize;let mut bytes=vec![0;n];file.read_exact(&mut bytes).map_err(|e|e.to_string())?;
                match header[0] {
                    1=>{self.data(stream,side,offsets[side],&bytes);offsets[side]+=n as u64;}
                    2=>{if let Some(p)=&mut stream.analyzer {self.output(p.eof_with_reason(direction(side),bytes==[1],&eof_reason(&stream.ticket,side,bytes==[1])));}}
                    3=>self.datagram(stream,side,&bytes),
                    _=>return Err("unknown analysis backlog event".into()),
                }
                left-=14+n as u64;
            }
        }
        cache.record(json!({"type":"analysis_resumed","connection":stream.identity,"cache_id":spool.id()}));
        Ok(())
    }
    fn diagnostic(&self, identity: &Connection, detail: &str) {
        lock(&self.results)
            .add(json!({"type":"analysis_diagnostic", "connection":identity, "detail":detail}));
    }
    fn parser(&self, identity: Connection, protocol: Protocol) -> Analyzer {
        let limits = Limits {
            encoded_body: 65536,
            decoded_body: 65536,
            pending: self.options.pending_requests,
            ..Limits::default()
        };
        if let Some(cache) = &self.cache {
            Analyzer::with_cache(identity, protocol, limits, cache.clone())
        } else {
            Analyzer::new(identity, protocol, limits)
        }
        .expect("constant valid limits")
    }
    fn opaque(&self, stream: &mut Stream) {
        stream.detect = false;
        stream.cache = self.cache.as_ref().map(|c|c.scoped(json!({"connection":stream.identity,"protocol":if stream.identity.quic_datagrams {"quic_datagram"} else if stream.identity.quic_stream_id.is_some() {"quic_stream"} else if stream.identity.transport=="udp" {"udp"}else{"tcp"}})).stream());
        if !stream.sniff.is_empty() {
            let bytes = std::mem::take(&mut stream.sniff);
            self.opaque_data(stream, 0, &bytes);
        }
        stream.dirty = true;
    }
    fn opaque_data(&self, stream: &mut Stream, side: usize, bytes: &[u8]) {
        stream.counts[side] += bytes.len() as u64;
        if let Some(cache) = &stream.cache { cache.append_stream(direction(side), bytes); }
        stream.dirty = true;
    }
    fn publish(&self, stream: &mut Stream, finished: bool) {
        if stream.dns.is_some() { stream.dirty=false; return; }
        if stream.counts == [0,0] && stream.packet_counts == [0,0] && stream.identity.quic_stream_id.is_none() { return; }
        let lost = stream.ticket.lost.load(Ordering::Acquire);
        lock(&self.results).add(json!({"type":"stream", "connection":stream.identity,
            "protocol":if stream.identity.quic_datagrams {"quic_datagram"} else if stream.identity.quic_stream_id.is_some() {"quic_stream"} else if stream.quic.version.is_some() {"quic"} else if stream.identity.transport == "udp" {"udp"} else if stream.decrypted {"tls_stream"} else if stream.encrypted {"tls_encrypted"} else {"tcp"},
            "quic":stream.quic.summary(),
            "stream":{"sent_bytes":stream.counts[0], "received_bytes":stream.counts[1],
                "finished":finished, "complete":stream.ended.iter().all(|v| *v) && !lost,
                "problem":if lost {Some("analysis queue overflow; only a contiguous prefix was captured")} else {stream.analysis_note.as_deref()},
                "cache":stream.cache, "datagrams":stream.datagrams, "packet_counts":stream.packet_counts}}));
        stream.dirty = false;
        stream.published = Instant::now();
    }
    fn progress(&mut self) {
        let ids: Vec<_> = self.connections.keys().copied().collect();
        for id in ids {
            let mut stream = self.connections.remove(&id).unwrap();
            if stream.deferred.is_some() && self.parsers.fetch_update(Ordering::AcqRel,Ordering::Acquire,
                |n|(n<self.options.connections).then_some(n+1)).is_ok() {
                stream.ticket.parser_slot.store(true,Ordering::Release);
                if let Err(e)=self.replay(&mut stream) {if let Some(c)=&self.cache {c.fail_recording(&format!("analysis replay failed: {e}"));}}
            }
            if let Some(dns)=&mut stream.dns {self.records(dns.expire(&stream.identity,None));}
            // Bound detection latency for small/idle ASCII protocols as well as memory.
            if stream.detect && !stream.sniff.is_empty() && stream.opened.elapsed() >= Duration::from_secs(2) {
                self.opaque(&mut stream);
            }
            if stream.h3.is_some() && stream.dirty && stream.published.elapsed()>=Duration::from_millis(500) {
                lock(&self.results).add(json!({"type":"exchange","connection":stream.identity,"protocol":"h3","exchange":stream.h3.as_ref().unwrap().snapshot()}));
                stream.dirty=false;stream.published=Instant::now();
            }
            if stream.h3.is_none() && stream.analyzer.is_none() && !stream.detect && stream.dirty
                && stream.published.elapsed() >= Duration::from_millis(500) {
                self.publish(&mut stream, false);
            }
            self.connections.insert(id, stream);
        }
    }
    fn reap(&mut self, all: bool, stopped: bool) {
        let ids: Vec<_> = self.connections.iter().filter_map(|(id, stream)| {
            (all || (stream.ticket.pending.load(Ordering::Acquire) == 0 &&
                (stream.ticket.closed.load(Ordering::Acquire) || stream.ticket.lost.load(Ordering::Acquire))))
                .then_some(*id)
        }).collect();
        for id in ids {
            let mut stream = self.connections.remove(&id).unwrap();
            let lost = stream.ticket.lost.load(Ordering::Acquire);
            let (ended_at,reason)=if stopped {(proxylane_protocol::recording::observed_ms(),"monitoring stopped".to_owned())}
                else {lock(&stream.ticket.close_reason).clone().unwrap_or_else(||(proxylane_protocol::recording::observed_ms(),"capture worker shutdown".into()))};
            let _time=proxylane_protocol::recording::observation_time(ended_at);
            let reason=if lost {"capture queue overflow".to_owned()} else {reason};
            if let Some(c)=&self.cache {c.record(json!({"type":"capture_end","connection":stream.identity,
                "http3_stream_id":stream.ticket.http3_stream_id,"reason":reason,"directions_ended":stream.ended}));}
            if stream.deferred.is_some() {if let Err(e)=self.replay(&mut stream) {if let Some(c)=&self.cache {c.fail_recording(&format!("analysis replay failed: {e}"));}}}
            if let Some(h3) = stream.h3.take() {
                let exchange=h3.finish(&reason);
                let mut value=json!({"type":"exchange","connection":stream.identity,"protocol":"h3","exchange":exchange});
                crate::doh::annotate(&mut value);lock(&self.results).add(value);
            } else if let Some(dns) = &mut stream.dns {
                self.records(dns.close(&stream.identity,self.cache.as_ref(),&format!("DNS response not observed: {reason}")));
            } else if let Some(parser) = &mut stream.analyzer {
                self.output(parser.close_with_reason(&reason));
                if lost { self.diagnostic(&stream.identity, "analysis queue overflow; reconstruction stopped for this connection"); }
            } else {
                if stream.detect { self.opaque(&mut stream); }
                if let Some(cache) = &stream.cache {
                    cache.finish_stream(stream.counts, stream.ended.iter().all(|v| *v) && !lost);
                }
                self.publish(&mut stream, true);
            }
            if stream.identity.transport != "udp" && !stream.decrypted {
                lock(&self.results).add(json!({"type":"connection","connection":stream.identity,"protocol":"tcp","status":if stopped {"Stopped"}else{"Closed"}}));
            }
            self.active.fetch_sub(1, Ordering::AcqRel);
            if stream.ticket.parser_slot.load(Ordering::Acquire) {self.parsers.fetch_sub(1,Ordering::AcqRel);}
        }
    }
    #[cfg(test)]
    fn run(self,receiver:Receiver<Event>) {self.run_notifying(receiver,Arc::new(tokio::sync::Notify::new()));}
    fn run_notifying(mut self, receiver: Receiver<Event>,space:Arc<tokio::sync::Notify>) {
        let mut progress = Instant::now();
        loop {
            let event=receiver.recv_timeout(Duration::from_millis(100));
            let (event,time)=match event {Ok(Event::Timed(time,event))=>(Ok(*event),time),other=>(other,proxylane_protocol::recording::now_ms())};
            let _time=proxylane_protocol::recording::observation_time(time);
            space.notify_waiters();
            match event {
                #[cfg(test)]
                Ok(Event::Panic)=>panic!("injected analysis panic"),
                Ok(Event::Timed(..))=>unreachable!("nested capture timestamp"),
                #[cfg(test)]
                Ok(Event::Pause(wait,entered))=>{let _=entered.send(());let _=wait.recv();},
                Ok(Event::Open(id, identity, alpn, decrypted, ticket)) => {
                    let h3=alpn.as_ref().filter(|a|a.starts_with(b"h3:")).and_then(|a|std::str::from_utf8(&a[3..]).ok()).and_then(|s|s.parse::<u64>().ok())
                        .map(|stream_id|proxylane_protocol::http3::Capture::new(stream_id,self.cache.as_ref().map(|c|c.scoped(json!({"connection":identity,"protocol":"h3"}))).as_ref()));
                    let protocol = match alpn.as_deref() {
                        Some(b"h2") => Some(Protocol::H2),
                        Some(b"http/1.1") => Some(Protocol::Http1),
                        _ => None,
                    };
                    let udp = identity.transport == "udp";
                    let raw_quic=identity.quic_stream_id.is_some() || identity.quic_datagrams;
                    let limited=!ticket.parser_slot.load(Ordering::Acquire) && h3.is_none() && !raw_quic;
                    let dns = if !raw_quic && !limited && identity.server_port==53 {Some(crate::dns::Dns::default())}else{None};
                    let is_dns=dns.is_some();
                    let analyzer = if limited {None}else{protocol.map(|p| self.parser(identity.clone(), p))};
                    let mut stream = Stream { deferred:None, deferred_alpn:alpn.clone(), deferred_bytes:0, fallback:false, analysis_note:None, h3, identity, ticket, analyzer, sniff: Vec::new(), dns, quic:Default::default(),
                        detect: alpn.is_none() && !udp && !is_dns, decrypted, encrypted: false, cache: None,
                        counts: [0;2], datagrams: [Vec::new(), Vec::new()], packet_counts: [0;2], ended: [false;2], dirty: false,
                        published: Instant::now() - Duration::from_secs(1), opened: Instant::now() };
                    if !limited && stream.h3.is_none() && !is_dns && (udp || (protocol.is_none() && alpn.is_some())) { self.opaque(&mut stream); }
                    if limited {
                        stream.detect=false;
                        stream.deferred=self.cache.as_ref().map(|c|c.scoped(json!({"connection":stream.identity,
                            "kind":"analysis_backlog","format":"PLAB2: observed_ms:u64le kind:u8 side:u8 length:u32le payload"})).stream());
                        if let Some(c)=&self.cache {c.record(json!({"type":"analysis_queued","backlog_format":"PLAB2","connection":stream.identity,
                            "cache_id":stream.deferred.as_ref().map(CacheRef::id)}));}
                    }
                    if !udp && !decrypted {
                        lock(&self.results).add(json!({"type":"connection","connection":stream.identity,"protocol":"tcp","status":"Connecting"}));
                    }
                    if raw_quic {self.publish(&mut stream,false);}
                    self.connections.insert(id, stream);
                }
                Ok(Event::Data(id, side, offset, bytes, ticket)) => {
                    if let Some(mut stream) = self.connections.remove(&id) {
                        if stream.deferred.is_some() {self.defer(&mut stream,1,side,&bytes);}
                        else {self.data(&mut stream,side,offset,&bytes);}
                        self.connections.insert(id, stream);
                    }
                    ticket.pending.fetch_sub(1, Ordering::AcqRel);
                }
                Ok(Event::Http3(id,side,part,ticket)) => {
                    if let Some(stream)=self.connections.get_mut(&id) {
                        if let Some(h3)=&mut stream.h3 {
                            stream.dirty=true;
                            let publish=matches!(&part,H3Part::Head(_)|H3Part::End(_));
                            match part {H3Part::Head(m)=>h3.head(side,m),H3Part::Data(b)=>h3.data(side,&b),H3Part::End(t)=>h3.end(side,t)}
                            if publish {lock(&self.results).add(json!({"type":"exchange","connection":stream.identity,"protocol":"h3","exchange":h3.snapshot()}));}
                        }
                    }
                    ticket.pending.fetch_sub(1,Ordering::AcqRel);
                }
                Ok(Event::Datagram(id, side, bytes, ticket)) => {
                    if let Some(mut stream) = self.connections.remove(&id) {
                        if stream.deferred.is_some() {self.defer(&mut stream,3,side,&bytes);}
                        else {self.datagram(&mut stream,side,&bytes);}
                        self.connections.insert(id, stream);
                    }
                    ticket.pending.fetch_sub(1, Ordering::AcqRel);
                }
                Ok(Event::Eof(id, side, clean, ticket)) => {
                    if let Some(mut stream) = self.connections.remove(&id) {
                        stream.ended[side] = clean;
                        if let Some(c)=&self.cache {c.record(json!({"type":"transport_eof","connection":stream.identity,"side":side,"clean":clean}));}
                        if stream.deferred.is_some() {self.defer(&mut stream,2,side,&[u8::from(clean)]);}
                        if let Some(parser) = &mut stream.analyzer {
                            if let Some(reason)=self.output(parser.eof_with_reason(direction(side), clean,&eof_reason(&stream.ticket,side,clean))) {self.fallback(&mut stream,&reason);}
                        }
                        else { stream.dirty = true; }
                        self.connections.insert(id, stream);
                    }
                    ticket.pending.fetch_sub(1, Ordering::AcqRel);
                }
                Ok(Event::Note(id,note,ticket)) => {
                    if let Some(stream)=self.connections.get_mut(&id) {
                        if let Some(c)=&stream.cache {c.record(json!({"type":"transport_note","message":note}));}
                        stream.analysis_note=Some(note);stream.dirty=true;
                    }
                    ticket.pending.fetch_sub(1,Ordering::AcqRel);
                }
                Ok(Event::State(id, error, ticket)) => {
                    if let Some(stream) = self.connections.get(&id) {
                        lock(&self.results).add(json!({"type":"connection","connection":stream.identity,"protocol":"tcp",
                            "status":if error==0 {"Established"} else {"Failed"},
                            "detail":if error==0 {String::new()} else {format!("TCP connection failed: {error}")}}));
                    }
                    ticket.pending.fetch_sub(1, Ordering::AcqRel);
                }
                Ok(Event::StopCapture(reply)) => {
                    // End reconstruction without fabricating transport EOFs.
                    for stream in self.connections.values() { stream.ticket.closed.store(true, Ordering::Release); }
                    self.reap(true, true);
                    let _ = reply.send(());
                }
                Ok(Event::Barrier(reply)) => {
                    self.reap(false, false); self.progress(); let _ = reply.send(());
                }
                Ok(Event::Shutdown) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => (),
            }
            self.reap(false, false);
            if progress.elapsed() >= Duration::from_millis(500) { self.progress(); progress = Instant::now(); }
        }
        self.reap(true, false);
    }
}
fn direction(side: usize) -> Direction {
    if side == 0 {
        Direction::Client
    } else {
        Direction::Server
    }
}

fn process_name(pid: u32, process_start: u64) -> String {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, FILETIME},
        System::Threading::{
            GetProcessTimes, OpenProcess, QueryFullProcessImageNameW,
            PROCESS_QUERY_LIMITED_INFORMATION,
        },
    };
    if process_start == 0 {
        return String::new();
    }
    // Called at session creation, before the request can finish and curl exit.
    // Validate creation time as well as PID; never attach a reused PID's name.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return String::new();
        }
        let mut created: FILETIME = std::mem::zeroed();
        let mut exited: FILETIME = std::mem::zeroed();
        let mut kernel: FILETIME = std::mem::zeroed();
        let mut user: FILETIME = std::mem::zeroed();
        let mut name = String::new();
        if GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user) != 0
            && (u64::from(created.dwHighDateTime) << 32 | u64::from(created.dwLowDateTime))
                == process_start
        {
            let mut path = vec![0u16; 32768];
            let mut length = path.len() as u32;
            if QueryFullProcessImageNameW(handle, 0, path.as_mut_ptr(), &mut length) != 0 {
                let path = String::from_utf16_lossy(&path[..length as usize]);
                name = path;
            }
        }
        CloseHandle(handle);
        name
    }
}

pub fn identity(metadata: &Value, host: &str) -> Result<Connection, String> {
    let number = |name| {
        metadata[name]
            .as_u64()
            .ok_or_else(|| format!("missing identity: {name}"))
    };
    let address = metadata["destination"]
        .as_str()
        .ok_or("missing destination")?;
    let target = if host.is_empty() { address } else { host };
    let port = u16::try_from(number("port")?).map_err(|e| e.to_string())?;
    // Preserve the original target separately from any later TLS SNI update.
    // Bracket IPv6 literals so their colons cannot be confused with the port.
    let destination = if target.contains(':') && !target.starts_with('[') {
        format!("[{target}]:{port}")
    } else {
        format!("{target}:{port}")
    };
    let pid = u32::try_from(number("pid")?).map_err(|e| e.to_string())?;
    let process_start = number("process_create_time")?;
    let process_path=process_name(pid,process_start);
    Ok(Connection {
        id: number("connection_id")?.to_string(),
        pid,
        process_start,
        process_name: process_path.rsplit('\\').next().unwrap_or("").to_owned(),
        process_path,
        socket: number("socket")?,
        generation: number("socket_generation")?,
        destination,
        decrypted: false,
        upstream_verification_skipped: false,
        transport: metadata["transport"].as_str().unwrap_or("tcp").to_owned(),
        server_name: host.to_owned(),
        server_port: port,
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn destination_keeps_original_target_and_unambiguous_port() {
        for transport in ["tcp", "udp"] {
            for (host, address, expected) in [
                ("www.bing.com", "127.255.0.4", "www.bing.com:443"),
                ("150.171.110.136", "150.171.110.136", "150.171.110.136:443"),
                ("2001:db8::1", "2001:db8::1", "[2001:db8::1]:443"),
                ("[2001:db8::1]", "2001:db8::1", "[2001:db8::1]:443"),
                ("fe80::1%12", "fe80::1%12", "[fe80::1%12]:443"),
                ("", "::1", "[::1]:443"),
            ] {
                let metadata = json!({"pid":0,"process_create_time":0,"connection_id":1,
                    "socket":2,"socket_generation":3,"destination":address,"port":443,"transport":transport});
                let mut connection = super::identity(&metadata, host).unwrap();
                connection.server_name = "adsdk.microsoft.com".into();
                assert_eq!(serde_json::to_value(connection).unwrap()["destination"], expected);
            }
        }
    }
    #[test]
    fn dns_and_quic_live_records_cache_and_identity() {
        let r=Runtime::new(CacheConfig { root:std::env::temp_dir().join("proxylane-live-protocol-tests"),entry_bytes:4096,total_bytes:16384,..Default::default() }).unwrap();
        let mut identity=identity(901);identity.transport="udp".into();identity.server_port=53;
        let mut tap=r.tap_transport(identity,None,false).unwrap();
        let q=[0x12,0x34,1,0,0,1,0,0,0,0,0,0,1,b'a',0,0,1,0,1];
        tap.datagram(0,&q);
        let mut answer=q.to_vec();answer[2]=0x81;answer[3]=0x80;answer[7]=1;
        answer.extend_from_slice(&[0xc0,12,0,1,0,1,0,0,0,60,0,4,1,2,3,4]);
        tap.datagram(1,&answer);drop(tap);
        let records=r.query(&json!({"type":"poll"})).unwrap();let rows=records["records"].as_array().unwrap();
        assert_eq!(rows.len(),2);assert_eq!(rows[0]["type"],"dns");assert_eq!(rows[1]["exchange"]["status"],"NOERROR");
        assert_eq!(rows[0]["exchange"]["id"],rows[1]["exchange"]["id"]);
        assert_eq!(rows[1]["connection"]["pid"],42);
        let payload=r.query(&json!({"type":"dns_read","run_id":r.run_id,"cache_id":rows[1]["exchange"]["cache"]["id"],"direction":"server"})).unwrap();
        assert!(payload["text"].as_str().unwrap().contains("1.2.3.4"));
        assert_eq!(payload["payload"]["cache"]["response_bytes"],answer.len());
        let mut tcp_identity=super::tests::identity(903);tcp_identity.server_port=53;tcp_identity.transport="tcp".into();
        let mut tcp=r.tap_transport(tcp_identity,None,false).unwrap();
        let mut wire=(q.len() as u16).to_be_bytes().to_vec();wire.extend_from_slice(&q);
        for chunk in wire.chunks(3) {tcp.data(0,chunk);}
        let mut wire=(answer.len() as u16).to_be_bytes().to_vec();wire.extend_from_slice(&answer);tcp.data(1,&wire);drop(tcp);
        let tcp_records=r.query(&json!({"type":"poll","after":records["next"]})).unwrap();
        let tcp_row=tcp_records["records"].as_array().unwrap().iter().rev().find(|r|r["type"]=="dns").unwrap();
        assert_eq!(tcp_row["type"],"dns");assert_eq!(tcp_row["connection"]["transport"],"tcp");
        assert_eq!(tcp_row["exchange"]["sent_bytes"],q.len());assert_eq!(tcp_row["exchange"]["status"],"NOERROR");
        let mut identity=super::tests::identity(902);identity.transport="udp".into();identity.server_port=443;
        let mut tap=r.tap_transport(identity,None,false).unwrap();tap.datagram(0,&crate::quic_probe::tests::vector(false));drop(tap);
        let reply=r.query(&json!({"type":"poll","after":records["next"]})).unwrap();let row=reply["records"].as_array().unwrap().last().unwrap();
        assert_eq!(row["protocol"],"quic");assert_eq!(row["quic"]["sni"],"example.com");assert_eq!(row["connection"]["decrypted"],false);
        r.shutdown().unwrap();
    }
    #[test]
    fn doh_post_decompression_and_idle_tcp_lifecycle() {
        use base64::Engine;
        let r=Runtime::new(CacheConfig {root:std::env::temp_dir().join("proxylane-doh-tests"),entry_bytes:65536,total_bytes:262144,..Default::default()}).unwrap();
        let mut tap=r.tap_transport(identity(990),None,false).unwrap();
        tap.transport_result(0);
        let idle=r.query(&json!({"type":"poll"})).unwrap();
        assert!(idle["records"].as_array().unwrap().iter().any(|v|v["status"]=="Established"));
        let q=[0,1,1,0,0,1,0,0,0,0,0,0,1,b'a',0,0,1,0,1];
        let mut answer=q.to_vec();answer[2]=0x81;answer[3]=0x80;
        // Existing fixture is gzip encoded HTML; use a minimal uncompressed DEFLATE gzip member for DNS.
        fn gzip(bytes:&[u8])->Vec<u8> {
            let mut out=vec![31,139,8,0,0,0,0,0,0,255,1];
            out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());out.extend_from_slice(&(!(bytes.len() as u16)).to_le_bytes());out.extend_from_slice(bytes);
            let mut crc=!0u32;for byte in bytes {crc^=u32::from(*byte);for _ in 0..8 {crc=(crc>>1)^if crc&1==1 {0xedb88320}else{0};}}
            out.extend_from_slice(&(!crc).to_le_bytes());out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());out
        }
        let body=gzip(&answer);
        let request=format!("POST /dns-query HTTP/1.1\r\nHost: resolver.test\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",q.len());
        tap.data(0,request.as_bytes());tap.data(0,&q);
        let response=format!("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",body.len());
        tap.data(1,response.as_bytes());tap.data(1,&body);drop(tap);
        let result=r.query(&json!({"type":"poll","limit":64})).unwrap();
        let row=result["records"].as_array().unwrap().iter().find(|v|v["type"]=="exchange").unwrap();
        assert!(row.get("doh").is_some());
        for side in ["client","server"] {
            let result=r.query(&json!({"type":"doh_read","run_id":r.run_id,"cache_id":row["exchange"]["cache"]["id"],"direction":side})).unwrap();
            assert!(result["text"].as_str().unwrap().contains("a."));
            let bytes=base64::engine::general_purpose::STANDARD.decode(result["payload"]["data_base64"].as_str().unwrap()).unwrap();
            assert_eq!(bytes,if side=="client" {q.to_vec()}else{answer.clone()});
        }
        r.shutdown().unwrap();
    }
    #[test]
    fn process_name_survives_exit_and_rejects_reused_pid() {
        use std::{
            os::windows::io::AsRawHandle,
            process::{Command, Stdio},
        };
        use windows_sys::Win32::{Foundation::FILETIME, System::Threading::GetProcessTimes};
        let mut child = Command::new("cmd.exe")
            .args(["/D", "/Q"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut created: FILETIME = unsafe { std::mem::zeroed() };
        let mut exited = created;
        let mut kernel = created;
        let mut user = created;
        let ok = unsafe {
            GetProcessTimes(
                child.as_raw_handle(),
                &mut created,
                &mut exited,
                &mut kernel,
                &mut user,
            )
        };
        let start = u64::from(created.dwHighDateTime) << 32 | u64::from(created.dwLowDateTime);
        let captured = super::identity(
            &json!({"pid":child.id(), "process_create_time":start,
            "connection_id":1, "socket":2, "socket_generation":3, "destination":"127.255.0.1", "port":443}),
            "ifconfig.io",
        );
        let mismatch = super::process_name(child.id(), start.wrapping_add(1));
        let unknown = super::process_name(child.id(), 0);
        child.kill().unwrap();
        child.wait().unwrap();
        assert_ne!(ok, 0);
        let captured = captured.unwrap();
        assert!(captured.process_name.eq_ignore_ascii_case("cmd.exe"));
        assert!(mismatch.is_empty() && unknown.is_empty());
        assert_eq!(captured.server_name, "ifconfig.io");
        assert_eq!(captured.server_port, 443);
        assert_eq!(
            serde_json::to_value(captured).unwrap()["process_name"],
            "cmd.exe"
        );
    }
    fn identity(id: u64) -> Connection {
        Connection {
            id: id.to_string(),
            pid: 42,
            process_start: 98765,
            socket: 120,
            generation: id,
            destination: "test:8443".into(),
            ..Connection::default()
        }
    }
    fn runtime() -> Arc<Runtime> {
        // Every test owns its own locked run under the test-only root.
        Runtime::new(CacheConfig {
            root: std::env::temp_dir().join("proxylane-live-protocol-tests"),
            entry_bytes: 16,
            total_bytes: 24,
            ..CacheConfig::default()
        })
        .unwrap()
    }
    fn poll(r: &Runtime) -> Value {
        let mut result=r.query(&json!({"type":"poll", "limit":64})).unwrap();
        result["records"].as_array_mut().unwrap().retain(|r|r["type"]!="connection");
        result
    }
    #[test]
    fn detection_offsets_cache_identity_and_cleanup() {
        let r = runtime();
        let directory = r.cache.as_ref().unwrap().directory().to_owned();
        let mut tap = r.tap(identity(7), None).unwrap();
        for bytes in b"GET /one HTTP/1.1\r\nHost: test\r\n\r\n".chunks(3) {
            tap.data(0, bytes);
        }
        tap.data(
            1,
            b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nabcdefghijklmnopqrst",
        );
        // Keep-alive second exchange after first body reached its cache cap.
        tap.data(0, b"GET /two HTTP/1.1\r\nHost: test\r\n\r\n");
        tap.data(1, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        drop(tap);
        let result = poll(&r);
        let records = result["records"].as_array().unwrap();
        assert_eq!(records.len(), 2, "{result}");
        assert_eq!(records[0]["connection"]["id"], "7");
        assert_eq!(records[0]["connection"]["pid"], 42);
        assert_eq!(records[0]["connection"]["process_start"], 98765);
        assert_eq!(records[0]["connection"]["generation"], 7);
        assert_eq!(records[0]["exchange"]["response"]["body_bytes"], 20);
        assert_eq!(records[1]["exchange"]["response"]["text"], "ok");
        let id = records[0]["exchange"]["cache"]["id"].as_u64().unwrap();
        let status = r
            .query(&json!({"type":"cache_status", "run_id":r.run_id,"cache_id":id}))
            .unwrap();
        assert_eq!(status["cache"]["response_bytes"], 16);
        assert_eq!(status["cache"]["reason"], "per-exchange payload limit");
        assert!(r
            .query(&json!({"type":"cache_read", "run_id":"previous-run", "cache_id":id}))
            .is_err());
        r.shutdown().unwrap();
        assert!(!directory.exists());
    }
    #[test]
    fn recording_overload_waits_without_gaps() {
        // Deliberately hold the worker until both queue slots are occupied.
        let (sender, receiver) = mpsc::sync_channel(2);
        let cache=PayloadCache::new(CacheConfig {root:std::env::temp_dir().join("proxylane-analysis-overload-test"),
            recording:Some(proxylane_protocol::recording::RecordingConfig {total_bytes:1024*1024,min_free_bytes:0}),..Default::default()}).unwrap();
        let published=Arc::new(Mutex::new(PublishedResults::default()));
        let r = Arc::new(Runtime {
            failure: Default::default(),
            published:published.clone(),
            stop_progress:Mutex::new(StopProgress::default()),
            space:Arc::new(tokio::sync::Notify::new()),
            options:Default::default(),
            sender,
            worker: Mutex::new(None),
            stopping: AtomicBool::new(false),
            capture_epoch: Mutex::new(1),
            process_events: Mutex::new(()),
            process_inflight: Mutex::new(0),
            process_drained: Condvar::new(),
            next: AtomicU64::new(1),
            active: Arc::new(AtomicUsize::new(0)),
            parsers: Arc::new(AtomicUsize::new(0)),
            rejected: AtomicU64::new(0),
            results: Arc::new(Mutex::new(Results {published,..Default::default()})),
            cache: Some(cache.clone()),
            cache_error: None,
            run_id: "test".into(),
        });
        let producer_runtime=r.clone();let (done,completed)=mpsc::channel();
        let producer=thread::spawn(move|| {
            let mut tap=producer_runtime.tap(identity(1),Some(b"http/1.1".to_vec())).unwrap();
            tap.data(0,b"GET /complete HTTP/1.1\r\nHost: test\r\n\r\n");
            tap.data(1,b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
            drop(tap);done.send(()).unwrap();
        });
        assert!(completed.recv_timeout(Duration::from_millis(100)).is_err());
        let worker = Worker {
            options:Default::default(),
            connections: BTreeMap::new(),
            cache: Some(cache.clone()),
            results: r.results.clone(),
            active: r.active.clone(),
            parsers: r.parsers.clone(),
        };
        let handle = thread::spawn(move || worker.run(receiver));
        completed.recv_timeout(Duration::from_secs(5)).unwrap();producer.join().unwrap();
        let result=poll(&r);assert!(result.to_string().contains("/complete"));
        assert_eq!(r.active.load(Ordering::Acquire),0);
        assert!(!r.recording_failed());assert_eq!(r.recording_status()["quality"]["gap_count"],0);
        cache.finish_recording().unwrap();
        let lines=std::fs::read_to_string(cache.directory().join("events-000001.jsonl")).unwrap();
        assert!(!lines.contains("recording_gap"));assert!(lines.contains("exchange_end"));
        r.sender.send(Event::Shutdown).unwrap();
        handle.join().unwrap();
    }
    #[test]
    fn non_http_and_missing_cache_do_not_affect_worker() {
        let r = runtime();
        let mut tap = r.tap(identity(1), None).unwrap();
        tap.data(0, b"\x00\x80binary");
        let mut unsupported = r.tap(identity(2), Some(b"mqtt".to_vec())).unwrap();
        unsupported.data(0, b"payload");
        drop(tap);
        drop(unsupported);
        let result = poll(&r);
        assert!(result["records"].as_array().unwrap().iter().all(|r| r["type"] == "stream"));
        assert!(!result.to_string().contains("\"type\":\"exchange\""));
        r.shutdown().unwrap();

        // A file at the cache root forces cache startup failure; analysis works.
        let path = std::env::temp_dir().join(format!("proxylane-blocked-{}", r.run_id));
        std::fs::write(&path, b"blocked").unwrap();
        let r = Runtime::new(CacheConfig {
            root: path.clone(),
            ..CacheConfig::default()
        })
        .unwrap();
        let mut tap = r.tap(identity(3), Some(b"http/1.1".to_vec())).unwrap();
        tap.data(0, b"GET / HTTP/1.1\r\nHost: test\r\n\r\n");
        tap.data(1, b"HTTP/1.1 204 No Content\r\n\r\n");
        drop(tap);
        assert_eq!(
            poll(&r)["records"][0]["exchange"]["response"]["status"],
            204
        );
        assert!(r.query(&json!({"type":"stats"})).unwrap()["cache_error"].is_string());
        r.shutdown().unwrap();
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn opaque_streams_preserve_prefix_direction_half_close_and_limits() {
        use base64::Engine;
        let r = runtime();
        let mut tap = r.tap_transport(identity(91), None, false).unwrap();
        tap.data(0, b"PI");
        tap.data(1, b"READY"); // Server first while client sniff is buffered.
        let records = poll(&r);
        let live = records["records"].as_array().unwrap().last().unwrap();
        assert_eq!(live["protocol"], "tcp");
        assert_eq!(live["stream"]["finished"], false);
        let cache = live["stream"]["cache"]["id"].as_u64().unwrap();
        let read = |side| {
            let reply = r.query(&json!({"type":"cache_read", "run_id":r.run_id, "cache_id":cache,
                "direction":side,"length":65536})).unwrap();
            base64::engine::general_purpose::STANDARD.decode(reply["payload"]["data_base64"].as_str().unwrap()).unwrap()
        };
        assert_eq!(read("client"), b"PI"); assert_eq!(read("server"), b"READY");
        tap.data(0, b"NG"); tap.eof(0, true);
        tap.data(1, b"0123456789abcdef"); tap.eof(1, true); drop(tap);
        let result = poll(&r);
        let last = result["records"].as_array().unwrap().last().unwrap();
        assert_eq!(last["stream"]["sent_bytes"], 4);
        assert_eq!(last["stream"]["received_bytes"], 21);
        assert_eq!(last["stream"]["complete"], true);
        assert_eq!(read("client"), b"PING");
        assert_eq!(read("server"), b"READY0123456"); // Combined 16-byte cap.
        let status = r.query(&json!({"type":"cache_status","run_id":r.run_id,"cache_id":cache})).unwrap();
        assert_eq!(status["cache"]["reason"], "per-exchange payload limit");
        let mut tls = r.tap_transport(identity(92), None, false).unwrap();
        tls.data(0, &[0x16]); tls.data(0, &[3,3,0,5,1]); drop(tls);
        assert_eq!(poll(&r)["records"].as_array().unwrap().last().unwrap()["protocol"], "tls_encrypted");
        r.shutdown().unwrap();
    }

    #[test]
    fn opaque_queue_gap_is_terminal_and_plain_http_still_reconstructs() {
        let r = runtime();
        let mut tap = r.tap_transport(identity(81), None, false).unwrap();
        tap.data(0, b"GET / HTTP/1.1\r\nHost: test\r\n\r\n");
        tap.data(1, b"HTTP/1.1 204 No Content\r\n\r\n"); drop(tap);
        assert_eq!(poll(&r)["records"][0]["protocol"], "http1");
        let mut tap = r.tap(identity(82), Some(b"mqtt".to_vec())).unwrap();
        tap.data(0, b"before"); let _ = poll(&r);
        tap.ticket.lost.store(true, Ordering::Release);
        tap.data(0, b"after-gap"); drop(tap);
        let result = poll(&r);
        let last = result["records"].as_array().unwrap().last().unwrap();
        assert_eq!(last["protocol"], "tls_stream");
        assert_eq!(last["stream"]["sent_bytes"], 6);
        assert!(last["stream"]["problem"].as_str().unwrap().contains("overflow"));
        r.shutdown().unwrap();
    }

    #[test]
    fn decrypted_quic_datagrams_keep_identity_and_never_sniff_dns_or_quic() {
        let r=runtime();
        let mut connection=identity(72);connection.transport="udp".into();
        connection.quic_datagrams=true;connection.quic_alpn=Some("anything/1".into());
        connection.server_port=53;
        let mut tap=r.tap_transport(connection,Some(Vec::new()),true).unwrap();
        let dns=b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01a\x00\x00\x01\x00\x01";
        tap.datagram(0,dns);tap.datagram(0,b"");tap.datagram(1,b"reply");
        tap.note("QUIC DATAGRAM forwarding dropped: test".into());
        tap.eof(0,true);tap.eof(1,true);drop(tap);
        let reply=poll(&r);let last=reply["records"].as_array().unwrap().last().unwrap();
        assert_eq!(last["protocol"],"quic_datagram");
        assert_eq!(last["connection"]["quic_datagrams"],true);
        assert_eq!(last["connection"]["decrypted"],true);
        assert!(last["connection"].get("quic_stream_id").is_none());
        assert_eq!(last["stream"]["datagrams"][0],json!([[0,dns.len()],[dns.len(),0]]));
        assert_eq!(last["stream"]["packet_counts"],json!([2,1]));
        assert_eq!(r.query(&json!({"type":"stats"})).unwrap()["active_parsers"],0);
        r.shutdown().unwrap();
    }
    #[test]
    fn udp_retains_datagram_boundaries_zero_length_and_transport_identity() {
        use base64::Engine;
        let r = runtime();
        let mut connection = identity(71); connection.transport = "udp".into();
        let mut tap = r.tap_transport(connection, None, false).unwrap();
        tap.datagram(0, b"GET"); tap.datagram(0, b""); tap.datagram(0, b"PING");
        tap.datagram(1, b"one"); tap.datagram(1, b"two");
        tap.eof(0,true); tap.eof(1,true); drop(tap);
        let reply = poll(&r); let last = reply["records"].as_array().unwrap().last().unwrap();
        assert_eq!(last["protocol"], "udp");
        assert_eq!(last["connection"]["decrypted"], false);
        assert_eq!(last["stream"]["datagrams"][0], json!([[0,3],[3,0],[3,4]]));
        assert_eq!(last["stream"]["datagrams"][1], json!([[0,3],[3,3]]));
        assert_eq!(last["stream"]["packet_counts"], json!([3,2]));
        let payload = r.query(&json!({"type":"cache_read","run_id":r.run_id,
            "cache_id":last["stream"]["cache"]["id"],"direction":"server","offset":3,"length":3})).unwrap();
        assert_eq!(base64::engine::general_purpose::STANDARD.decode(payload["payload"]["data_base64"].as_str().unwrap()).unwrap(), b"two");
        r.shutdown().unwrap();
    }

    #[test]
    fn connection_limit_and_result_retention_are_bounded() {
        let r = runtime();
        let mut taps: Vec<_> = (0..CONNECTIONS)
            .map(|n| {
                r.tap(identity(n as u64), Some(b"http/1.1".to_vec()))
                    .unwrap()
            })
            .collect();
        assert!(r.tap(identity(999), None).is_none());
        for n in 0..300 {
            taps[0].data(0, b"GET / HTTP/1.1\r\nHost: test\r\n\r\n");
            taps[0].data(1, b"HTTP/1.1 204 No Content\r\n\r\n");
            if n % 20 == 0 {
                r.query(&json!({"type":"stats"})).unwrap();
            }
        }
        drop(taps);
        let stats = r.query(&json!({"type":"stats"})).unwrap();
        assert_eq!(stats["active_connections"], 0);
        assert_eq!(stats["rejected_connections"], 1);
        assert_eq!(stats["retained_records"], 256);
        assert_eq!(stats["evicted_records"], 44);
        assert_eq!(poll(&r)["lost_before"], 44);
        r.shutdown().unwrap();
    }
    #[test]
    fn configured_connection_pending_and_datagram_limits() {
        let options=crate::options::Options{connections:1,pending_requests:2,udp_packets:16,..Default::default()};
        let r=Runtime::with_options(CacheConfig {root:std::env::temp_dir().join("proxylane-options-tests"),..Default::default()},options).unwrap();
        let mut http=r.tap(identity(1),Some(b"http/1.1".to_vec())).unwrap();
        assert!(r.tap(identity(2),None).is_none());
        http.data(0,b"GET /1 HTTP/1.1\r\nHost: t\r\n\r\nGET /2 HTTP/1.1\r\nHost: t\r\n\r\nGET /3 HTTP/1.1\r\nHost: t\r\n\r\n");
        drop(http);
        assert!(poll(&r).to_string().contains("pending exchange limit"));
        let mut id=identity(3);id.transport="udp".into();
        let mut udp=r.tap_transport(id,None,false).unwrap();
        for _ in 0..20 {udp.datagram(0,b"packet");}
        drop(udp);
        let output=poll(&r);let stream=output["records"].as_array().unwrap().iter().rev().find(|x|x["type"]=="stream").unwrap();
        assert_eq!(stream["stream"]["packet_counts"][0],20);
        assert_eq!(stream["stream"]["datagrams"][0].as_array().unwrap().len(),16);
        r.shutdown().unwrap();
    }

}

#[cfg(test)]
mod stop_tests {
    use super::*;
    #[test]
    fn stop_progress_is_readable_while_analysis_is_blocked() {
        let r=Runtime::new(CacheConfig {root:std::env::temp_dir().join("proxylane-stop-progress"),..Default::default()}).unwrap();
        let resume=r.pause_worker();let stopped=r.clone();
        let worker=thread::spawn(move||stopped.stop_capture());
        let deadline=Instant::now()+Duration::from_secs(2);
        while !r.query(&json!({"type":"monitor_stop_status"})).unwrap()["active"].as_bool().unwrap() {
            assert!(Instant::now()<deadline);thread::sleep(Duration::from_millis(1));
        }
        thread::sleep(Duration::from_millis(25));
        let progress=r.query(&json!({"type":"monitor_stop_status"})).unwrap();
        assert_eq!(progress["phase"],"analysis");assert!(progress["elapsed_ms"].as_u64().unwrap()>=20);
        assert!(!worker.is_finished());resume.send(()).unwrap();worker.join().unwrap().unwrap();
        let progress=r.query(&json!({"type":"monitor_stop_status"})).unwrap();
        assert_eq!(progress["phase"],"complete");assert_eq!(progress["active"],false);
        assert!(progress["analysis_ms"].as_u64().unwrap()>=20);
        assert_eq!(progress,r.query(&json!({"type":"monitor_stop_status"})).unwrap());
        r.start_capture();assert_eq!(r.query(&json!({"type":"monitor_stop_status"})).unwrap()["elapsed_ms"],0);
        r.shutdown().unwrap();
    }
    #[test]
    fn concurrent_stop_drains_writes_retains_history_and_invalidates_old_taps() {
        let r=Runtime::new(CacheConfig {root:std::env::temp_dir().join("proxylane-stop-race"),..Default::default()}).unwrap();
        let mut tap=r.tap_transport(Connection {id:"race".into(),transport:"udp".into(),..Default::default()},None,false).unwrap();
        tap.datagram(0,b"before-stop");
        r.query(&json!({"type":"stats"})).unwrap();
        let running=Arc::new(AtomicBool::new(true));let run=running.clone();
        let producer=thread::spawn(move || {
            while run.load(Ordering::Acquire) { tap.datagram(0,b"during-stop"); thread::yield_now(); }
            tap
        });
        r.stop_capture().unwrap();
        let snapshot=r.query(&json!({"type":"stats"})).unwrap();
        assert_eq!(snapshot["active_connections"],0);
        assert!(snapshot["cache"]["used_bytes"].as_u64().unwrap()>0);
        for _ in 0..4 {assert_eq!(r.query(&json!({"type":"stats"})).unwrap(),snapshot);}
        running.store(false,Ordering::Release);let mut old=producer.join().unwrap();
        assert!(r.tap(Default::default(),None).is_none());
        r.start_capture();
        old.datagram(0,b"must-not-resume");old.eof(0,true);old.transport_result(0);drop(old);
        assert_eq!(r.query(&json!({"type":"stats"})).unwrap(),snapshot);
        let mut fresh=r.tap_transport(Connection {id:"new".into(),transport:"udp".into(),..Default::default()},None,false).unwrap();
        fresh.datagram(0,b"new-capture");
        r.stop_capture().unwrap();
        assert!(r.query(&json!({"type":"stats"})).unwrap()["cache"]["used_bytes"].as_u64().unwrap()>snapshot["cache"]["used_bytes"].as_u64().unwrap());
        drop(fresh);r.shutdown().unwrap();
    }
}

#[cfg(test)]
mod recording_tests {
    use super::*;
    use std::{fs,path::PathBuf};
    fn runtime()->Arc<Runtime> {
        Runtime::with_options(CacheConfig {root:std::env::temp_dir().join("proxylane-runtime-recordings"),queue_chunks:1024,
            recording:Some(proxylane_protocol::recording::RecordingConfig {total_bytes:32*1024*1024,min_free_bytes:0}),..Default::default()},
            crate::options::Options {udp_packets:16,..Default::default()}).unwrap()
    }
    #[test]
    fn analysis_panic_stops_capture_explicitly_and_preserves_prior_recording() {
        for retained in [false,true] {
            let r=if retained {runtime()}else{Runtime::new(CacheConfig{root:std::env::temp_dir().join("proxylane-analysis-panic-tests"),..Default::default()}).unwrap()};
            let path=r.cache.as_ref().unwrap().directory().to_owned();
            let mut tap=r.tap_transport(Connection{id:"panic-test".into(),transport:"tcp".into(),..Default::default()},Some(b"opaque".to_vec()),false).unwrap();
            tap.data(0,b"before panic");r.query(&json!({"type":"stats"})).unwrap();
            r.sender.send(Event::Panic).unwrap();
            let deadline=Instant::now()+Duration::from_secs(3);
            while r.worker_error().is_none() {assert!(Instant::now()<deadline);thread::yield_now();}
            assert_eq!(r.recording_status()["stopped"],true);
            assert_eq!(r.recording_status()["worker_failed"],true);
            tap.data(0,b"after panic");assert!(!tap.is_capturing());
            assert!(r.tap(Default::default(),None).is_none());
            assert!(r.stop_capture().unwrap_err().contains("injected analysis panic"));
            r.shutdown().unwrap();
            if retained {
                let manifest:Value=serde_json::from_slice(&fs::read(path.join("manifest.json")).unwrap()).unwrap();
                assert_eq!(manifest["status"],"stopped");assert_eq!(manifest["quality"]["capture_incomplete"],true);
                assert!(manifest["stop_reason"].as_str().unwrap().contains("injected analysis panic"));
            }
        }
    }
    #[test]
    fn process_notifications_drain_on_stop_without_holding_capture_gate() {
        let r=runtime();let root=PathBuf::from(r.recording_status()["directory"].as_str().unwrap());
        let (entered,ready)=mpsc::channel();let (resume,wait)=mpsc::channel();let producer=r.clone();
        let job=thread::spawn(move||producer.record_process_with(|| {
            entered.send(()).unwrap();wait.recv().unwrap();
            Ok(json!({"type":"process_created","child":{"pid":123},"parent":{"pid":456}}))
        }).unwrap());
        ready.recv_timeout(Duration::from_secs(3)).unwrap();
        assert!(r.capture_epoch.try_lock().is_ok(),"identity lookup held network capture gate");
        // Network lifecycle publication still completes while producer waits.
        let mut tap=r.tap_transport(Connection{id:"process-test".into(),..Default::default()},None,false).unwrap();
        tap.data(0,b"network remains usable");
        let (done,finished)=mpsc::channel();let stopped=r.clone();
        let stopper=thread::spawn(move||{let result=stopped.stop_capture();done.send(result).unwrap();});
        assert!(finished.recv_timeout(Duration::from_millis(100)).is_err(),"stop lost an admitted creation");
        assert!(!r.record_process_with(||panic!("post-stop query must not run")).unwrap());
        resume.send(()).unwrap();assert!(job.join().unwrap());finished.recv_timeout(Duration::from_secs(10)).unwrap().unwrap();stopper.join().unwrap();
        let text=fs::read_to_string(root.join("process-events-000001.jsonl")).unwrap();assert_eq!(text.lines().count(),1);
        let manifest:Value=serde_json::from_slice(&fs::read(root.join("manifest.json")).unwrap()).unwrap();assert_eq!(manifest["process_events"]["last_sequence"],1);
        drop(tap);r.shutdown().unwrap();
    }
    #[test]
    fn live_preview_bypasses_analysis_barrier_and_recording_publication_lock() {
        let r=runtime();
        let mut tap=r.tap_transport(Connection{id:"preview".into(),transport:"tcp".into(),..Default::default()},None,false).unwrap();
        tap.data(0,b"SSH-2.0-preview\r\n");
        let batch=r.query(&json!({"type":"poll"})).unwrap();
        let id=batch["records"].as_array().unwrap().iter()
            .find_map(|v|v["stream"]["cache"]["id"].as_u64()).unwrap();
        r.cache.as_ref().unwrap().stats().unwrap();
        let resume=r.pause_worker();
        // This is the lock an observation holds while waiting for disk queue space.
        let publication=lock(&r.results);
        let reader=r.clone();let run=r.run_id.clone();let (done,wait)=mpsc::channel();
        let task=thread::spawn(move|| {
            assert!(reader.query(&json!({"type":"stats","live_preview":true})).is_ok());
            assert!(reader.query(&json!({"type":"poll","live_preview":true})).is_ok());
            let reply=reader.query(&json!({"type":"cache_read","live_preview":true,"run_id":run,
                "cache_id":id,"direction":"client","length":100})).unwrap();
            assert_eq!(reply["payload"]["data_base64"],"U1NILTIuMC1wcmV2aWV3DQo=");
            assert!(reader.query(&json!({"type":"cache_status","live_preview":true,"run_id":"stale","cache_id":id})).is_err());
            done.send(()).unwrap();
        });
        let result=wait.recv_timeout(Duration::from_secs(2));
        drop(publication);resume.send(()).unwrap();task.join().unwrap();
        assert!(result.is_ok(),"UI queries waited for analysis/recording instead of reading published snapshots");
        drop(tap);r.stop_capture().unwrap();r.shutdown().unwrap();
    }
    fn events(path:&std::path::Path)->Vec<Value> {
        let mut files:Vec<_>=fs::read_dir(path).unwrap().map(|e|e.unwrap().path()).filter(|p|p.extension().is_some_and(|x|x=="jsonl") && p.file_name().unwrap().to_string_lossy().starts_with("events-")).collect();files.sort();
        files.into_iter().flat_map(|p|fs::read_to_string(p).unwrap().lines().map(|l|serde_json::from_str(l).unwrap()).collect::<Vec<Value>>()).collect()
    }
    #[test]
    fn cancelled_async_sender_retains_its_already_read_fragment() {
        let r=Runtime::test_small_queue(CacheConfig {
            root:std::env::temp_dir().join("proxylane-cancel-queued"),
            recording:Some(proxylane_protocol::recording::RecordingConfig{total_bytes:8*1024*1024,min_free_bytes:0}),
            ..Default::default()
        });
        let tap=Arc::new(r.tap(Connection{id:"cancel".into(),..Default::default()},Some(b"h3:0".to_vec())).unwrap());
        let release=r.pause_worker();
        let mut head=proxylane_protocol::Message::default();head.method=Some("POST".into());
        tap.http3(0,H3Part::Head(head));tap.http3(0,H3Part::Data(b"before".to_vec()));
        let executor=tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        executor.block_on(async {
            let t=tap.clone();let (started,ready)=tokio::sync::oneshot::channel();
            let task=tokio::spawn(async move {
                let _=started.send(());t.http3_async(0,H3Part::Data(b"-cancelled".to_vec())).await;
            });
            ready.await.unwrap();tokio::time::sleep(Duration::from_millis(20)).await;
            task.abort();release.send(()).unwrap();let _=task.await;
        });
        drop(tap);r.stop_capture().unwrap();
        let path=PathBuf::from(r.recording_status()["directory"].as_str().unwrap());
        let lines=events(&path);
        let id=lines.iter().find(|e|e["type"]=="message_head").unwrap()["cache_id"].as_u64().unwrap();
        assert_eq!(fs::read(path.join(proxylane_protocol::recording::payload_relative(id,0))).unwrap(),b"before-cancelled");
        assert_eq!(r.recording_status()["quality"]["gap_count"],0);r.shutdown().unwrap();
    }
    #[test]
    fn recording_h2_pending_limit_spills_instead_of_falling_back() {
        let r=runtime();let path=PathBuf::from(r.recording_status()["directory"].as_str().unwrap());
        let mut idle=r.tap(Connection{id:"unused-h2".into(),..Default::default()},Some(b"h2".to_vec())).unwrap();
        idle.eof(0,false);drop(idle);
        let mut busy=r.tap(Connection{id:"busy-h2".into(),..Default::default()},Some(b"h2".to_vec())).unwrap();
        busy.data(0,b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        for id in (1u32..=17).step_by(2) {
            let mut bytes=vec![0,0,3,1,5];bytes.extend(id.to_be_bytes());bytes.extend([0x82,0x87,0x84]);
            busy.data(0,&bytes);
        }
        for id in (1u32..=17).step_by(2) {
            let mut bytes=vec![0,0,1,1,5];bytes.extend(id.to_be_bytes());bytes.push(0x88);
            busy.data(1,&bytes);
        }
        r.query(&json!({"type":"stats"})).unwrap();
        assert!(!r.recording_failed());r.stop_capture().unwrap();let lines=events(&path);
        assert_eq!(lines.iter().filter(|v|v["type"]=="exchange_end" && v["response"]["status"]==200).count(),9);
        let manifest:Value=serde_json::from_slice(&fs::read(path.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(manifest["quality"]["analysis_fallback_count"],0);
        assert_eq!(manifest["quality"]["capture_incomplete"],false);assert_eq!(manifest["status"],"completed");
        drop(busy);r.shutdown().unwrap();
    }
    #[test]
    fn parser_saturation_keeps_raw_and_http3_beyond_32_without_stopping() {
        let r=runtime();let path=PathBuf::from(r.recording_status()["directory"].as_str().unwrap());
        let mut held=Vec::new();
        for i in 0..128 {held.push(r.tap(Connection{id:format!("idle-{i}"),..Default::default()},Some(b"h2".to_vec())).unwrap());}
        let mut raw=r.tap(Connection{id:"overflow-tcp".into(),..Default::default()},Some(b"http/1.1".to_vec())).unwrap();
        let request=b"GET /raw HTTP/1.1\r\nHost: test\r\n\r\n";
        {let _time=proxylane_protocol::recording::observation_time(10000);raw.data(0,request);}
        {let _time=proxylane_protocol::recording::observation_time(20000);raw.data(1,b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");}
        let mut requests=Vec::new();
        for id in 0..96 {
            let tap=r.tap(Connection{id:"one-quic-connection".into(),transport:"udp".into(),..Default::default()},Some(format!("h3:{}",id*4).into_bytes())).unwrap();
            let mut head=proxylane_protocol::Message::default();head.method=Some("GET".into());head.target=Some(format!("/{id}"));
            tap.http3(0,H3Part::Head(head));tap.http3(0,H3Part::End(vec![]));requests.push(tap);
            if id%8==7 {r.query(&json!({"type":"stats"})).unwrap();r.cache.as_ref().unwrap().stats().unwrap();}
        }
        let stats=r.query(&json!({"type":"stats"})).unwrap();
        assert_eq!(stats["active_connections"],225);assert_eq!(stats["active_parsers"],128);
        for (id,tap) in requests.into_iter().enumerate() {
            let mut head=proxylane_protocol::Message::default();head.status=Some(200);
            tap.http3(1,H3Part::Head(head));tap.http3(1,H3Part::Data(format!("body-{id}").into_bytes()));tap.http3(1,H3Part::End(vec![]));
            drop(tap);if id%8==7 {r.query(&json!({"type":"stats"})).unwrap();r.cache.as_ref().unwrap().stats().unwrap();}
        }
        raw.eof(0,true);raw.eof(1,true);drop(raw);drop(held);
        r.stop_capture().unwrap();assert!(!r.recording_failed());
        assert_eq!(r.recording_status()["quality"]["gap_count"],0);
        assert_eq!(r.recording_status()["quality"]["analysis_deferred_count"],0);
        let lines=events(&path);
        let h3:Vec<_>=lines.iter().filter(|e|e["type"]=="message_head" && e["side"]==1 && e["context"]["protocol"]=="h3").collect();
        assert_eq!(h3.len(),96);
        for e in h3 {
            let id=e["exchange_id"].as_u64().unwrap()/4;
            let body=proxylane_protocol::recording::payload_relative(e["cache_id"].as_u64().unwrap(),1);
            assert_eq!(fs::read(path.join(body)).unwrap(),format!("body-{id}").as_bytes());
        }
        assert!(lines.iter().any(|e|e["type"]=="analysis_queued"));
        assert!(lines.iter().any(|e|e["type"]=="analysis_resumed"));
        assert!(lines.iter().any(|e|e["type"]=="message_head" && e["message"]["target"]=="/raw" && e["observed_unix_ms"]==10000));
        assert!(lines.iter().any(|e|e["type"]=="exchange_end" && e["request"]["target"]=="/raw" && e["request"]["observed_start_unix_ms"]==10000));
        assert!(lines.iter().any(|e|e["type"]=="exchange_end" && e["request"]["target"]=="/raw" && e["response"]["complete"]==true));
        r.shutdown().unwrap();
    }
    #[test]
    fn deferred_and_live_eof_preserve_close_reason_and_ingress_time() {
        let r=runtime();let path=PathBuf::from(r.recording_status()["directory"].as_str().unwrap());
        let mut live=r.tap(Connection{id:"live-eof".into(),..Default::default()},Some(b"http/1.1".to_vec())).unwrap();
        {let _time=proxylane_protocol::recording::observation_time(1000);live.data(0,b"GET /live HTTP/1.1\r\nHost: test\r\n\r\n");}
        live.close_reason("upstream TLS close_notify".into());live.eof(1,true);live.eof(0,false);drop(live);
        r.query(&json!({"type":"stats"})).unwrap();
        let held:Vec<_>=(0..128).map(|i|r.tap(Connection{id:format!("held-{i}"),..Default::default()},Some(b"h2".to_vec())).unwrap()).collect();
        let mut delayed=r.tap(Connection{id:"delayed-eof".into(),..Default::default()},Some(b"http/1.1".to_vec())).unwrap();
        {let _time=proxylane_protocol::recording::observation_time(2000);delayed.data(0,b"GET /delayed HTTP/1.1\r\nHost: test\r\n\r\n");}
        delayed.close_reason("upstream TLS close_notify".into());delayed.eof(1,true);delayed.eof(0,false);drop(delayed);
        r.query(&json!({"type":"stats"})).unwrap();drop(held);r.stop_capture().unwrap();
        let lines=events(&path);assert!(lines.iter().any(|e|e["type"]=="analysis_queued" && e["connection"]["id"]=="delayed-eof"));
        for (target,time) in [("/live",1000),("/delayed",2000)] {
            let end=lines.iter().find(|e|e["type"]=="exchange_end" && e["request"]["target"]==target).unwrap();
            assert_eq!(end["problem"],"upstream TLS close_notify");assert!(end["response"].is_null());
            let id=end["cache_id"].as_u64().unwrap();
            let saved:Value=serde_json::from_slice(&fs::read(path.join(proxylane_protocol::recording_view::session_relative(id))).unwrap()).unwrap();
            assert_eq!(saved["first_observed_unix_ms"],time);assert_eq!(saved["exchange"]["cache"],saved["cache"]);
            let registered=lines.iter().find(|e|e["type"]=="payload_registered" && e["cache_id"]==id).unwrap();
            assert_eq!(registered["observed_unix_ms"],time);
        }
        assert_eq!(r.recording_status()["quality"]["gap_count"],0);r.shutdown().unwrap();
    }
    #[test]
    fn recording_more_than_old_capture_limit_has_no_gaps() {
        let r=runtime();let path=PathBuf::from(r.recording_status()["directory"].as_str().unwrap());let mut taps=Vec::new();
        for id in 0..1050 {
            taps.push(r.tap(Connection{id:format!("h3-{id}"),..Default::default()},Some(b"h3:0".to_vec())).unwrap());
            if id%8==7 {r.query(&json!({"type":"stats"})).unwrap();r.cache.as_ref().unwrap().stats().unwrap();}
        }
        drop(r.tap(Connection{id:"also-admitted".into(),..Default::default()},Some(b"h3:4".to_vec())).unwrap());
        assert!(!r.recording_failed());assert_eq!(r.recording_status()["quality"]["gap_count"],0);
        // Release and reuse gradually, avoiding testing queue overflow here.
        while !taps.is_empty() {for _ in 0..8 {taps.pop();}r.query(&json!({"type":"stats"})).unwrap();r.cache.as_ref().unwrap().stats().unwrap();}
        assert_eq!(r.active.load(Ordering::Acquire),0);
        let next=r.tap(Connection{id:"next".into(),..Default::default()},Some(b"h3:8".to_vec())).unwrap();drop(next);
        r.stop_capture().unwrap();let lines=events(&path);
        assert!(!lines.iter().any(|e|e["type"]=="recording_gap"));
        assert!(!r.recording_failed());r.shutdown().unwrap();
    }
    #[test]
    fn recording_keeps_all_udp_boundaries_beyond_ui_limits_and_http3_headers() {
        let r=runtime();let path=PathBuf::from(r.recording_status()["directory"].as_str().unwrap());
        let mut udp=r.tap_transport(Connection {id:"udp1".into(),pid:77,process_start:123,transport:"udp".into(),..Default::default()},None,false).unwrap();
        for n in 0..400 {udp.datagram(0,format!("packet-{n:04}").as_bytes());if n%20==0 {r.query(&json!({"type":"stats"})).unwrap();}}
        let h3=r.tap(Connection {id:"quic1".into(),pid:77,..Default::default()},Some(b"h3:4".to_vec())).unwrap();
        let mut head=proxylane_protocol::Message::default();head.method=Some("POST".into());head.target=Some("/live-h3".into());
        h3.http3(0,H3Part::Head(head));h3.http3(0,H3Part::Data(b"partial upload".to_vec()));
        r.query(&json!({"type":"stats"})).unwrap();
        let lines=events(&path);
        assert_eq!(lines.iter().filter(|e|e["type"]=="datagram").count(),400);
        assert!(lines.iter().any(|e|e["type"]=="message_head" && e["message"]["target"]=="/live-h3"));
        let packets:Vec<_>=lines.iter().filter(|e|e["type"]=="datagram").collect();
        assert_eq!(packets[399]["offset"],399*11);assert_eq!(packets[399]["packet_number"],400);
        r.stop_capture().unwrap();let before=fs::metadata(path.join("events-000001.jsonl")).unwrap().len();
        udp.datagram(1,b"after stop");h3.http3(0,H3Part::Data(b"after stop".to_vec()));
        r.query(&json!({"type":"stats"})).unwrap();
        assert_eq!(fs::metadata(path.join("events-000001.jsonl")).unwrap().len(),before);
        drop(udp);drop(h3);r.shutdown().unwrap();assert!(path.join("manifest.json").exists());
    }
    #[test]
    fn malformed_connection_keeps_raw_bytes_and_does_not_stop_other_recordings() {
        let r=runtime();let path=PathBuf::from(r.recording_status()["directory"].as_str().unwrap());
        let mut broken=r.tap(Connection{id:"bad-h2".into(),..Default::default()},Some(b"h2".to_vec())).unwrap();
        broken.data(0,b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        // Unmatched ACK really is an invalid capture; do not remove this validation.
        let bad=[0,0,0,4,1,0,0,0,0];broken.data(0,&bad);broken.data(1,b"later raw bytes");
        let mut good=r.tap(Connection{id:"good-http".into(),..Default::default()},Some(b"http/1.1".to_vec())).unwrap();
        good.data(0,b"GET /healthy HTTP/1.1\r\nHost: test\r\n\r\n");
        good.data(1,b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        r.query(&json!({"type":"stats"})).unwrap();assert!(!r.recording_failed());r.stop_capture().unwrap();
        let lines=events(&path);
        assert!(lines.iter().any(|v|v["type"]=="observation" && v["record"]["detail"]=="SETTINGS ACK without captured SETTINGS"));
        assert!(lines.iter().any(|v|v["type"]=="exchange_end" && v["request"]["target"]=="/healthy" && v["response"]["complete"]==true));
        let raw=lines.iter().find(|v|v["type"]=="payload_registered" && v["context"]["kind"]=="analysis_fallback").unwrap();
        assert!(raw["files"][0].is_null(),"registration precedes payload creation");
        let checkpoint=lines.iter().rev().find(|v|v["type"]=="payload_checkpoint" && v["cache_id"]==raw["cache_id"]).unwrap();
        assert_eq!(fs::read(path.join(checkpoint["files"][0].as_str().unwrap())).unwrap(),bad);
        assert_eq!(fs::read(path.join(checkpoint["files"][1].as_str().unwrap())).unwrap(),b"later raw bytes");
        assert!(lines.iter().any(|v|v["type"]=="analysis_fallback_chunk" && v["source_offset"]==24));
        let manifest:Value=serde_json::from_slice(&fs::read(path.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(manifest["quality"]["capture_incomplete"],false);
        assert_eq!(manifest["quality"]["analysis_incomplete"],true);
        assert_eq!(manifest["quality"]["analysis_fallback_count"],1);
        assert_eq!(manifest["quality"]["analysis_fallback_reasons"]["SETTINGS ACK without captured SETTINGS"],1);
        assert_eq!(lines.iter().filter(|v|v["type"]=="analysis_fallback").count(),1);
        drop(broken);drop(good);r.shutdown().unwrap();
    }
}
