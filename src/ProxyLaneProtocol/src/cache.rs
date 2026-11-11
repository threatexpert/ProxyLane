//! Bounded asynchronous payload cache. Quotas include both directions of an
//! exchange and are enforced by the single disk worker before every write.
use crate::{cache_directory::RunDirectory, Direction, Headers};
use serde::{Serialize, Serializer, Deserialize};
use serde_json::{Value, json};
use crate::recording::{self, RecordingConfig, Journal, SavedEntry};
#[path = "cache_preview.rs"]
mod preview;
use std::{
    collections::{BTreeMap, VecDeque},
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc::{self, SyncSender, TrySendError},
        Arc, Mutex, MutexGuard, Weak,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

fn locked<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    value.lock().unwrap_or_else(|e| e.into_inner())
}
const CHUNK: usize = 16384;
pub const PREVIEW_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub struct CacheConfig {
    #[cfg(test)]
    pub write_delay: Duration,
    pub recording: Option<RecordingConfig>,
    pub root: PathBuf,
    pub entry_bytes: u64,
    pub total_bytes: u64,
    pub queue_chunks: usize,
    pub max_entries: usize,
    pub decode_bytes: usize,
    pub decode_input_bytes: usize,
}
impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            #[cfg(test)]
            write_delay:Duration::ZERO,
            recording: None,
            root: std::env::temp_dir()
                .join("ProxyLane")
                .join("protocol-cache-v1"),
            entry_bytes: 32 * 1024 * 1024,
            total_bytes: 512 * 1024 * 1024,
            queue_chunks: 128,
            max_entries: 4096,
            decode_bytes: 4*1024*1024,
            decode_input_bytes: 32*1024*1024,
        }
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CacheSnapshot {
    pub id: u64,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub finished: bool,
    pub pending_chunks: usize,
    pub evicted: bool,
    /// None means no cache loss has been observed. Check pending_chunks and
    /// the HTTP message's complete flag before assuming a full body is ready.
    pub reason: Option<String>,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct CacheStats {
    pub used_bytes: u64,
    pub peak_bytes: u64,
    pub entries: usize,
    pub evicted_entries: u64,
    pub recovered_runs: usize,
    pub warnings: Vec<String>,
}
#[derive(Clone, Default, Serialize, Deserialize)]
pub(crate) struct BodyInfo {
    #[serde(default)]
    pub present: bool,
    pub bytes: u64,
    pub complete: bool,
    pub headers: Headers,
    pub bodyless: bool,
}
struct Ticket {
    observed_unix_ms: u64,
    context: Value,
    id: u64,
    state: Mutex<CacheSnapshot>,
    info: Mutex<[BodyInfo; 2]>,
    accepting: AtomicBool,
    pending: AtomicUsize,
    finished: AtomicU64,
}
impl Ticket {
    fn snapshot(&self) -> CacheSnapshot {
        let mut state = locked(&self.state).clone();
        state.pending_chunks = self.pending.load(Ordering::Acquire);
        state.finished = self.finished.load(Ordering::Acquire) != 0;
        state
    }
    fn stop(&self, reason: &str) {
        self.accepting.store(false, Ordering::Release);
        let mut state = locked(&self.state);
        if state.reason.is_none() {
            state.reason = Some(reason.into());
        }
    }
}
#[derive(Clone)]
pub struct CacheRef {
    ticket: Arc<Ticket>,
    owner: Weak<Inner>,
}
impl std::fmt::Debug for CacheRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.snapshot().fmt(f)
    }
}
impl Serialize for CacheRef {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.snapshot().serialize(serializer)
    }
}
impl CacheRef {
    pub fn is_recording(&self)->bool {self.owner.upgrade().is_some_and(|o|o.recording.is_some())}
    pub fn record(&self, mut value: Value) {
        if value.get("observed_unix_ms").is_none() {value["observed_unix_ms"]=recording::observed_ms().into();}
        if let Some(owner)=self.owner.upgrade() {
            if !owner.recording.as_ref().is_some_and(|s|s.accepting()) {return;}
            value["cache_id"]=self.id().into();value["context"]=self.ticket.context.clone();
            if let Err(e)=owner.try_send(Command::Event(value)) {owner.resource_failure(e,json!({"cache_id":self.id(),"connection":self.ticket.context,"operation":"event"}));}
        }
    }
    /// Opaque connections share the same bounded cache as HTTP bodies.
    pub fn append_stream(&self, direction: Direction, bytes: &[u8]) {
        self.append(if matches!(direction, Direction::Client) { 0 } else { 1 }, bytes);
    }
    pub fn finish_stream(&self, bytes: [u64; 2], complete: bool) {
        if !complete { self.ticket.stop("capture ended before both directions closed"); }
        self.finish(std::array::from_fn(|side| BodyInfo {
            bytes: bytes[side], complete, ..BodyInfo::default()
        }));
    }
    pub fn id(&self) -> u64 {
        self.ticket.id
    }
    pub fn snapshot(&self) -> CacheSnapshot {
        self.ticket.snapshot()
    }
    pub(crate) fn append(&self, side: usize, bytes: &[u8]) {
        let Some(owner) = self.owner.upgrade() else {
            self.ticket.stop("cache closed");
            return;
        };
        if owner.recording.as_ref().is_some_and(|s|!s.accepting()) {return;}
        for chunk in bytes.chunks(CHUNK) {
            if !self.ticket.accepting.load(Ordering::Acquire) {
                break;
            }
            self.ticket.pending.fetch_add(1, Ordering::AcqRel);
            // Retained recording waits for capacity; ordinary previews remain lossy.
            let result = owner.try_send(Command::Append(self.ticket.clone(), side, chunk.to_vec()));
            if let Err(reason) = result {
                self.ticket.pending.fetch_sub(1, Ordering::AcqRel);
                self.ticket.stop(reason);
                owner.resource_failure(reason,json!({"cache_id":self.id(),"connection":self.ticket.context,"side":side,
                    "operation":"payload","scope":"this payload from the first rejected chunk onward"}));
                break;
            }
        }
    }
    pub(crate) fn finish(&self, info: [BodyInfo; 2]) {
        if self.ticket.finished.load(Ordering::Acquire) != 0 {
            return;
        }
        *locked(&self.ticket.info) = info;
        let order = self
            .owner
            .upgrade()
            .map_or(1, |owner| owner.completion.fetch_add(1, Ordering::Relaxed));
        self.ticket.finished.store(order, Ordering::Release);
        if let Some(owner)=self.owner.upgrade() { if owner.recording.is_some() {
            if let Err(e)=owner.try_send(Command::Finished(self.ticket.clone())) {owner.resource_failure(e,json!({"cache_id":self.id(),"operation":"finish"}));}
        }}
    }
}

#[derive(Debug, Serialize)]
pub struct CachedPayload {
    pub cache: CacheSnapshot,
    pub direction: Direction,
    pub offset: u64,
    #[serde(serialize_with = "serialize_bytes")]
    pub data_base64: Vec<u8>,
    pub decoded: bool,
    pub decoded_bytes: usize,
    pub warning: Option<String>,
}
fn serialize_bytes<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    use base64::Engine;
    serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
}
enum Query {
    Reference(u64),
    Working(String, Vec<u8>),
    FinishRecording,
    Stats,
    Status(u64),
    Read {
        id: u64,
        side: usize,
        offset: u64,
        length: usize,
        decode: bool,
        decoded_limit: usize,
    },
}
enum Answer {
    Reference(Arc<Ticket>),
    Stats(CacheStats),
    Status(Option<CacheSnapshot>),
    Payload(CachedPayload),
}
enum Command {
    #[cfg(test)]
    Panic,
    #[cfg(test)]
    Pause(mpsc::Sender<()>,mpsc::Receiver<()>),
    Event(Value),
    ProcessCreated(Value),
    Finished(Arc<Ticket>),
    Register(Arc<Ticket>),
    Append(Arc<Ticket>, usize, Vec<u8>),
    Query(Query, mpsc::Sender<Result<Answer, String>>),
}
struct Inner {
    failure: Arc<crate::worker_failure::WorkerFailure>,
    preview: Arc<preview::Reader>,
    recording: Option<Arc<recording::State>>,
    sender: Mutex<Option<SyncSender<Command>>>,
    worker: Mutex<Option<JoinHandle<Result<(), String>>>>,
    next: AtomicU64,
    completion: AtomicU64,
    directory: PathBuf,
}
impl Inner {
    fn fail(&self, reason: &str) {if let Some(state)=&self.recording {state.stop(reason);}}
    fn resource_failure(&self, reason:&str, context:Value) {
        if reason=="cache queue full" {
            if let Some(state)=&self.recording {state.issue(true,reason,context);}
        } else {self.fail(reason);}
    }
    fn try_send(&self, command: Command) -> Result<(), &'static str> {
        if self.failure.failed() {return Err("cache worker failed");}
        let sender = locked(&self.sender).clone();
        match sender.as_ref() {
            None => Err("cache closed"),
            Some(sender) if self.recording.is_some() =>
                sender.send(command).map_err(|_| "cache worker unavailable"),
            Some(sender) => sender.try_send(command).map_err(|e| match e {
                TrySendError::Full(_) => "cache queue full",
                TrySendError::Disconnected(_) => "cache worker unavailable",
            }),
        }
    }
    fn query(&self, query: Query) -> Result<Answer, String> {
        if let Some(reason)=self.failure.reason() {return Err(reason);}
        let (sender, receiver) = mpsc::channel();
        // Reads/flushes are explicitly synchronous API operations, not called
        // from the analyzer's packet path. Do not hold sender mutex while waiting.
        let queue = locked(&self.sender)
            .as_ref()
            .cloned()
            .ok_or("cache closed")?;
        queue
            .send(Command::Query(query, sender))
            .map_err(|_| "cache worker unavailable")?;
        drop(queue);
        receiver.recv().map_err(|_| self.failure.reason().unwrap_or_else(||"cache worker unavailable".into()))?
    }
    fn shutdown(&self) -> Result<(), String> {
        // Serialize simultaneous shutdowns; drain accepted writes before cleanup.
        let mut worker = locked(&self.worker);
        locked(&self.sender).take();
        if let Some(handle) = worker.take() {
            handle.join().map_err(|_| "cache worker panicked")??;
        }
        Ok(())
    }
}
impl Drop for Inner {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

#[derive(Clone)]
pub struct PayloadCache {
    inner: Arc<Inner>,
    context: Value,
}
impl PayloadCache {
    pub fn worker_failed(&self)->bool {self.inner.failure.failed()}
    pub fn worker_error(&self)->Option<String> {self.inner.failure.reason()}
    pub fn analysis_worker_failed(&self,reason:&str) {
        if let Some(state)=&self.inner.recording {state.fail_worker(reason);}
    }
    pub fn working_id(&self)->u64 {
        static NEXT:AtomicU64=AtomicU64::new(1);
        NEXT.fetch_add(1,Ordering::Relaxed)
    }
    pub fn working_write(&self,name:String,bytes:Vec<u8>)->Result<(),String> {
        self.inner.query(Query::Working(name,bytes))?;Ok(())
    }
    pub fn reference(&self,id:u64)->Result<CacheRef,String> {
        match self.inner.query(Query::Reference(id))? {
            Answer::Reference(ticket)=>Ok(CacheRef {ticket,owner:Arc::downgrade(&self.inner)}),
            _=>unreachable!()
        }
    }
    pub fn scoped(&self, context: Value) -> Self {Self {inner:self.inner.clone(),context}}
    pub fn is_recording(&self)->bool {self.inner.recording.is_some()}
    pub fn recording_status(&self)->Value {self.inner.recording.as_ref().map_or(json!({"enabled":false}),|s|s.status(&self.inner.directory))}
    pub fn recording_failed(&self)->bool {self.inner.recording.as_ref().is_some_and(|s|s.stopped.load(Ordering::Acquire))}
    pub fn fail_recording(&self, reason:&str) {self.inner.fail(reason);}
    pub fn recording_issue(&self, gap:bool, reason:&str, context:Value) {
        if let Some(state)=&self.inner.recording {state.issue(gap,reason,context);}
    }
    pub fn recording_analysis_fallback(&self, reason:&str, context:Value) {
        if let Some(state)=&self.inner.recording {state.analysis_fallback(reason,context);}
    }
    pub fn record(&self, mut value:Value) {if self.inner.recording.as_ref().is_some_and(|s|s.accepting()) {
        if value.get("observed_unix_ms").is_none() {value["observed_unix_ms"]=recording::observed_ms().into();}
        if value["type"]=="analysis_queued" || value["type"]=="analysis_resumed" {
            self.inner.recording.as_ref().unwrap().analysis_progress(value["type"]=="analysis_resumed");
        }
        let context=json!({"event_type":value["type"],"connection":value["connection"],"cache_id":value["cache_id"]});
        if let Err(e)=self.inner.try_send(Command::Event(value)) {self.inner.resource_failure(e,context);}}}
    pub(crate) fn connection_event(&self,mut event:Value) {
        event["connection"]=self.context["connection"].clone();
        event["protocol"]=self.context["protocol"].clone();self.record(event);
    }
    /// Creation notification producer only; bounded lossless disk queue.
    pub fn record_process_created(&self,event:Value)->Result<(),String> {
        if !self.is_recording() {return Ok(());}
        // Bound callers too, rather than accepting arbitrary large JSON values.
        if serde_json::to_vec(&event).map_err(|e|e.to_string())?.len()>128*1024 {
            self.inner.fail("process creation event exceeds 128 KiB");
            return Err("process creation event exceeds 128 KiB".into());
        }
        self.inner.try_send(Command::ProcessCreated(event)).map_err(|e|{self.inner.fail(e);e.to_string()})
    }
    pub fn finish_recording(&self)->Result<(),String> {if self.is_recording() {self.inner.query(Query::FinishRecording)?;}Ok(())}
    pub fn stream(&self) -> CacheRef { self.entry() }
    pub fn new(config: CacheConfig) -> Result<Self, String> {
        if config.decode_bytes == 0 || config.decode_bytes > 64*1024*1024 || config.decode_input_bytes > 64*1024*1024 {
            return Err("invalid decode limits".into());
        }
        if config.queue_chunks == 0
            || config.queue_chunks > 4096
            || config.max_entries == 0
            || config.max_entries > 65536
        {
            return Err("invalid cache queue/entry count limit".into());
        }
        let directory = if config.recording.is_some() {
            RunDirectory::recording(&config.root).map_err(|e|json!({
                "error":"recording_directory_error","path":config.root.to_string_lossy(),"detail":e.to_string()
            }).to_string())?
        } else {RunDirectory::create(&config.root).map_err(|e|e.to_string())?};
        let path = directory.path.clone();
        let recording=config.recording.as_ref().map(|_|Arc::new(recording::State::default()));
        let journal=config.recording.clone().map(|c|Journal::new(&path,c,recording.as_ref().unwrap().clone())
            .map_err(|e|json!({"error":"recording_initialize_error","path":config.root.to_string_lossy(),"detail":e}).to_string())).transpose()?;
        let (sender, receiver) = mpsc::sync_channel(config.queue_chunks);
        let preview = Arc::new(preview::Reader::new(path.clone(), config.max_entries));
        let worker_preview = preview.clone();
        let failure=Arc::new(crate::worker_failure::WorkerFailure::default());
        let worker_failure=failure.clone();
        let worker = thread::Builder::new()
            .name("protocol-payload-cache".into())
            .spawn(move || {
                let mut worker = Worker::new(config, directory);
                worker.preview = Some(worker_preview);
                worker.journal=journal;
                let outcome=std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut checkpoint=Instant::now();
                loop {
                    let command=match receiver.recv_timeout(Duration::from_millis(250)) {
                        Ok(c)=>Some(c),Err(mpsc::RecvTimeoutError::Timeout)=>None,Err(mpsc::RecvTimeoutError::Disconnected)=>break,
                    };
                    if let Some(command)=command {
                    match command {
                        #[cfg(test)]
                        Command::Panic=>panic!("injected cache panic"),
                        #[cfg(test)]
                        Command::Pause(entered,resume)=>{let _=entered.send(());let _=resume.recv();},
                        Command::Event(value)=>worker.event(value),
                        Command::ProcessCreated(value)=>{
                            if let Some(j)=&mut worker.journal {
                                if let Err(e)=j.process_event(value) {j.state.stop(&e);}
                            }
                        },
                        Command::Finished(ticket)=>worker.finished(&ticket),
                        Command::Register(ticket) => {
                            worker.register(ticket);
                        }
                        Command::Append(ticket, side, bytes) => {
                            #[cfg(test)]
                            thread::sleep(worker.config.write_delay);
                            worker.append(&ticket, side, &bytes);
                            ticket.pending.fetch_sub(1, Ordering::AcqRel);
                        }
                        Command::Query(query, response) => {
                            let _ = response.send(worker.query(query));
                        }
                    }
                    }
                    if checkpoint.elapsed()>=Duration::from_secs(1) {
                        worker.checkpoint();checkpoint=Instant::now();
                    }
                }
                worker.checkpoint();
                if let Some(j)=&mut worker.journal {let _=j.finish();}
                }));
                if let Err(payload)=outcome {
                    let reason=crate::worker_failure::panic_reason("protocol-payload-cache",payload.as_ref());
                    if let Some(j)=&mut worker.journal {j.worker_panicked(&reason);}
                    worker_failure.set(&reason);
                    // Disconnect first: release producers and synchronous queries
                    // before any best-effort terminal disk I/O.
                    drop(receiver);
                    let _=std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        if let Some(j)=&mut worker.journal {let _=j.finish();}
                    }));
                }
                // Close payload handles before removing their files on Windows.
                for record in worker.records.values() {
                    record.ticket.stop(&worker_failure.reason().unwrap_or_else(||"cache closed".into()));
                }
                worker.records.clear();
                worker
                    .directory
                    .cleanup()
                    .map_err(|e| format!("cache cleanup: {e}"))
            })
            .map_err(|e| e.to_string())?;
        Ok(Self {
            inner: Arc::new(Inner {
                failure,
                preview,
                recording,
                sender: Mutex::new(Some(sender)),
                worker: Mutex::new(Some(worker)),
                next: AtomicU64::new(1),
                completion: AtomicU64::new(1),
                directory: path,
            }),
            context: Value::Null,
        })
    }
    pub fn directory(&self) -> &std::path::Path {
        &self.inner.directory
    }
    pub(crate) fn entry(&self) -> CacheRef {
        let id = self.inner.next.fetch_add(1, Ordering::Relaxed);
        let ticket = Arc::new(Ticket {
            observed_unix_ms: recording::observed_ms(),
            context: self.context.clone(),
            id,
            state: Mutex::new(CacheSnapshot {
                id,
                ..CacheSnapshot::default()
            }),
            info: Mutex::new(Default::default()),
            accepting: AtomicBool::new(true),
            pending: AtomicUsize::new(0),
            finished: AtomicU64::new(0),
        });
        // A list observation can precede disk registration. Publish its empty,
        // pending state so a click does not report a missing payload file.
        if self.is_recording() {self.inner.preview.admit(&ticket);}
        if let Err(reason) = self.inner.try_send(Command::Register(ticket.clone())) {
            ticket.stop(reason);
            self.inner.resource_failure(reason,json!({"cache_id":id,"connection":self.context,"operation":"register",
                "scope":"entire payload was not admitted"}));
        }
        CacheRef {
            ticket,
            owner: Arc::downgrade(&self.inner),
        }
    }
    /// A barrier for earlier accepted writes. Does not complete HTTP messages.
    pub fn stats(&self) -> Result<CacheStats, String> {
        match self.inner.query(Query::Stats)? {
            Answer::Stats(stats) => Ok(stats),
            _ => unreachable!(),
        }
    }
    pub fn status(&self, id: u64) -> Result<Option<CacheSnapshot>, String> {
        match self.inner.query(Query::Status(id))? {
            Answer::Status(status) => Ok(status),
            _ => unreachable!(),
        }
    }
    /// UI-only reads of published bytes. No analysis/write barrier and no writes.
    pub fn preview_status(&self, id:u64) -> Result<Value,String> {
        self.inner.preview.status(id)
    }
    pub fn preview_read(&self,id:u64,direction:Direction,offset:u64,length:usize,decode:bool) -> Result<CachedPayload,String> {
        self.inner.preview.read(id,direction,offset,length,decode)
    }
    /// Read a retained encoded-body range (maximum 1 MiB per call).
    pub fn read(
        &self,
        id: u64,
        direction: Direction,
        offset: u64,
        length: usize,
    ) -> Result<CachedPayload, String> {
        if length > 1024*1024 {
            return Err("cache read range exceeds 1 MiB".into());
        }
        self.payload(Query::Read {
            id,
            side: direction.index(),
            offset,
            length,
            decode: false,
            decoded_limit: 0,
        })
    }
    /// Decode only a completely captured body, on demand. The result is never
    /// retained on disk; the configured budget defaults to 4 MiB (maximum 64 MiB).
    pub fn decode(
        &self,
        id: u64,
        direction: Direction,
        limit: usize,
    ) -> Result<CachedPayload, String> {
        self.decode_preview(id,direction,limit,0)
    }
    /// Decode fully within the configured budget, returning only the requested prefix.
    /// A zero preview returns the full decoded value for library callers.
    pub fn decode_preview(&self,id:u64,direction:Direction,limit:usize,preview:usize) -> Result<CachedPayload,String> {
        if limit > 64*1024*1024 || preview > 1024*1024 {return Err("invalid decode/preview limit".into());}
        self.payload(Query::Read {
            id,
            side: direction.index(),
            offset: 0,
            length: preview,
            decode: true,
            decoded_limit: limit,
        })
    }
    fn payload(&self, query: Query) -> Result<CachedPayload, String> {
        match self.inner.query(query)? {
            Answer::Payload(payload) => Ok(payload),
            _ => unreachable!(),
        }
    }
    /// Closes all clones, drains the queue and removes this run's files.
    pub fn shutdown(&self) -> Result<(), String> {
        self.inner.shutdown()
    }
}

struct Record {
    ticket: Arc<Ticket>,
    files: [Option<File>; 2],
    stored: [u64; 2],
    stopped: bool,
    dirty: bool,
}
struct Worker {
    preview: Option<Arc<preview::Reader>>,
    journal: Option<Journal>,
    config: CacheConfig,
    directory: RunDirectory,
    records: BTreeMap<u64, Record>,
    retired: BTreeMap<u64, CacheSnapshot>,
    retired_order: VecDeque<u64>,
    // At most one read-only historical entry is loaded outside the live metadata budget.
    restored: Option<u64>,
    stats: CacheStats,
}
impl Worker {
    fn fail(&self, reason:&str) {if let Some(j)=&self.journal {j.state.stop(reason);}}
    fn event(&mut self, value:Value) {
        if value["type"]=="message_head" && matches!(value["context"]["protocol"].as_str(),Some("http1"|"h2"|"h3")) {
            if let Some(j)=&mut self.journal {j.decode_queued();}
        }
        if let Some(j)=&mut self.journal {if let Err(e)=j.event(value) {j.state.stop(&e);}}
    }
    fn finished(&mut self, ticket:&Arc<Ticket>) {
        if self.directory.retained && !self.records.get(&ticket.id).is_some_and(|r|Arc::ptr_eq(&r.ticket,ticket)) {
            if let Err(e)=self.restore_live(ticket.clone()) {self.fail(&e);return;}
        }
        if let Some(record)=self.records.get_mut(&ticket.id) {record.dirty=true;}
        self.check_entry(ticket.id);
        if matches!(ticket.context["protocol"].as_str(),Some("http1"|"h2"|"h3")) {
            if let Some(j)=&mut self.journal {
                let info=locked(&ticket.info).clone();
                let stored=self.records.get(&ticket.id).map(|r|r.stored).unwrap_or_default();
                for side in 0..2 {
                    let started=Instant::now();
                    crate::recording_decode::run(j,&self.directory.path,ticket.id,side,&info[side],stored[side]);
                    j.measure(recording::Stage::Decode,started);
                }
            }
        }
    }
    fn check_entry(&mut self, id:u64) {
        if self.journal.is_none() {return;}
        let Some(record)=self.records.get_mut(&id) else {return;};
        if !record.dirty {return;}
        let mut failure=None;
        let started=Instant::now();
        for f in record.files.iter().flatten() {if let Err(e)=f.sync_data() {failure=Some(format!("recording payload sync failed: {e}"));}}
        self.journal.as_mut().unwrap().measure(recording::Stage::PayloadSync,started);
        let value=json!({"type":"payload_checkpoint","cache_id":id,"context":record.ticket.context,
            "cache":record.ticket.snapshot(),"info":locked(&record.ticket.info).clone()});
        record.dirty=false;
        if record.ticket.finished.load(Ordering::Acquire)!=0 {record.files=[None,None];}
        if let Some(e)=failure {self.fail(&e);}
        self.event(value);
    }
    fn checkpoint(&mut self) {
        if self.journal.is_none() {return;}
        let ids:Vec<_>=self.records.keys().copied().collect();
        for id in ids {self.check_entry(id);}
        if let Some(j)=&mut self.journal {
            if j.state.stopped.load(Ordering::Acquire) {let _=j.finish();}
            else if let Err(e)=j.flush() {j.state.stop(&e);let _=j.finish();}
        }
    }
    fn restore(&mut self, id:u64)->Result<(),String> {
        if self.records.contains_key(&id) || !self.directory.retained {return Ok(());}
        let path=self.directory.path.join(recording::metadata_relative(id));
        let saved:SavedEntry=serde_json::from_slice(&fs::read(path).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
        // A read must not write metadata, consume recording quota, or change a stopped archive.
        if let Some(old)=self.restored.take() {self.records.remove(&old);}
        let stored=[saved.cache.request_bytes,saved.cache.response_bytes];
        let ticket=Arc::new(Ticket {observed_unix_ms:0,context:saved.context,state:Mutex::new(saved.cache),info:Mutex::new(saved.info),id,
            accepting:AtomicBool::new(false),pending:AtomicUsize::new(0),finished:AtomicU64::new(1)});
        self.records.insert(id,Record {ticket,files:[None,None],stored,stopped:true,dirty:false});
        self.restored=Some(id);
        Ok(())
    }
    fn restore_live(&mut self,ticket:Arc<Ticket>)->Result<(),String> {
        if self.restored==Some(ticket.id) {self.restored=None;}
        self.records.remove(&ticket.id);
        if self.records.len()>=self.config.max_entries {
            if let Some(id)=self.oldest().or_else(||self.records.keys().next().copied()) {self.evict(id)?;}
        }
        let snapshot=ticket.snapshot();
        self.records.insert(ticket.id,Record {ticket,files:[None,None],
            stored:[snapshot.request_bytes,snapshot.response_bytes],stopped:snapshot.reason.is_some(),dirty:true});
        if let Some(reader)=&self.preview {reader.publish(self.records[&snapshot.id].ticket.clone());}
        Ok(())
    }
    fn new(config: CacheConfig, directory: RunDirectory) -> Self {
        let stats = CacheStats {
            recovered_runs: directory.recovered,
            warnings: directory.warnings.clone(),
            ..CacheStats::default()
        };
        Self {
            preview: None,
            journal: None,
            config,
            directory,
            records: BTreeMap::new(),
            retired: BTreeMap::new(),
            retired_order: VecDeque::new(),
            restored: None,
            stats,
        }
    }
    fn path(&self, id: u64, side: usize) -> PathBuf {
        if self.directory.retained {return self.directory.path.join(recording::payload_relative(id,side));}
        self.directory.path.join(format!(
            "{id:016x}.{}.body",
            if side == 0 { "request" } else { "response" }
        ))
    }
    fn oldest(&self) -> Option<u64> {
        self.records
            .iter()
            .filter_map(|(&id, record)| {
                let order = record.ticket.finished.load(Ordering::Acquire);
                (order != 0 && record.ticket.pending.load(Ordering::Acquire) == 0)
                    .then_some((id, order))
            })
            .min_by_key(|(_, order)| *order)
            .map(|(id, _)| id)
    }
    fn evict(&mut self, id: u64) -> Result<(), String> {
        if self.directory.retained {
            // Retire only in-memory metadata/handles; recorded files are never evicted.
            let record=self.records.get_mut(&id).unwrap();
            for file in record.files.iter_mut() {if let Some(f)=file.take() {if record.dirty {f.sync_data().map_err(|e|e.to_string())?;}}}
            let entry=SavedEntry {cache:record.ticket.snapshot(),info:locked(&record.ticket.info).clone(),context:record.ticket.context.clone()};
            self.journal.as_mut().unwrap().working_file(&recording::metadata_relative(id),
                &serde_json::to_vec(&entry).map_err(|e|e.to_string())?)?;
            self.records.remove(&id);
            if let Some(reader)=&self.preview {reader.retire(id);}
            return Ok(());
        }
        let paths = [self.path(id, 0), self.path(id, 1)];
        let record = self.records.get_mut(&id).unwrap();
        record.ticket.stop("payload evicted");
        locked(&record.ticket.state).evicted = true;
        for (side, path) in paths.iter().enumerate() {
            if record.files[side].take().is_some() || record.stored[side] != 0 {
                fs::remove_file(path).map_err(|e| format!("payload eviction failed: {e}"))?;
                self.stats.used_bytes -= record.stored[side];
                record.stored[side] = 0;
            }
        }
        let record = self.records.remove(&id).unwrap();
        let mut snapshot = record.ticket.snapshot();
        snapshot.request_bytes = 0;
        snapshot.response_bytes = 0;
        *locked(&record.ticket.state) = snapshot.clone();
        self.retired.insert(id, snapshot);
        self.retired_order.push_back(id);
        while self.retired_order.len() > self.config.max_entries {
            self.retired
                .remove(&self.retired_order.pop_front().unwrap());
        }
        self.stats.evicted_entries += 1;
        Ok(())
    }
    fn register(&mut self, ticket: Arc<Ticket>) {
        if self.records.contains_key(&ticket.id) {
            return;
        }
        if self.records.len() >= self.config.max_entries {
            if let Some(id) = self.oldest().or_else(||self.directory.retained.then(||*self.records.keys().next().unwrap())) {
                if let Err(reason) = self.evict(id) {
                    ticket.stop(&reason);
                    self.fail(&reason);
                    return;
                }
            } else {
                ticket.stop("cache entry count limit");
                if let Some(j)=&self.journal {j.state.issue(true,"recording active entry count limit",
                    json!({"cache_id":ticket.id,"connection":ticket.context,"scope":"entire payload was not admitted"}));}
                return;
            }
        }
        if self.directory.retained {if let Some(reader)=&self.preview {reader.publish(ticket.clone());}}
        if self.journal.is_some() {self.event(json!({"type":"payload_registered","cache_id":ticket.id,"context":ticket.context,"observed_unix_ms":ticket.observed_unix_ms,
            "files":[recording::payload_relative(ticket.id,0),recording::payload_relative(ticket.id,1)]}));}
        self.records.insert(
            ticket.id,
            Record {
                ticket,
                files: Default::default(),
                stored: [0; 2],
                stopped: false,
                dirty: true,
            },
        );
    }
    fn append(&mut self, ticket: &Arc<Ticket>, side: usize, bytes: &[u8]) {
        if self.directory.retained && !self.records.get(&ticket.id).is_some_and(|r|Arc::ptr_eq(&r.ticket,ticket)) {
            if let Err(e)=self.restore_live(ticket.clone()) {self.fail(&e);return;}
        }
        let Some(record) = self.records.get(&ticket.id) else {
            return;
        };
        if record.stopped {
            return;
        }
        if let Some(j)=&mut self.journal {
            if !j.state.accepting() {return;}
            if let Err(e)=j.charge(bytes.len() as u64) {self.stop(ticket.id,&e);return;}
        }
        let entry_left = if self.directory.retained {u64::MAX} else {self
            .config
            .entry_bytes
            .saturating_sub(record.stored.iter().sum())};
        let wanted = (bytes.len() as u64).min(entry_left);
        while !self.directory.retained && self.config.total_bytes - self.stats.used_bytes < wanted {
            let Some(id) = self.oldest() else {
                break;
            };
            if let Err(reason) = self.evict(id) {
                self.stop(ticket.id, &reason);
                return;
            }
        }
        let keep = if self.directory.retained {wanted as usize} else {wanted.min(self.config.total_bytes - self.stats.used_bytes) as usize};
        if keep != 0 {
            let path = self.path(ticket.id, side);
            let record = self.records.get_mut(&ticket.id).unwrap();
            let started=Instant::now();
            let result = (|| -> std::io::Result<()> {
                if record.files[side].is_none() {
                    if self.directory.retained {fs::create_dir_all(path.parent().unwrap())?;}
                    record.files[side] = Some(
                        OpenOptions::new()
                            .read(true)
                            .append(true)
                            .create(true)
                            .open(path)?,
                    );
                }
                // Reserve the entire write first, including any partially
                // successful write on a full disk. Never refund unknown bytes.
                self.stats.used_bytes += keep as u64;
                self.stats.peak_bytes = self.stats.peak_bytes.max(self.stats.used_bytes);
                let file = record.files[side].as_mut().unwrap();
                let result = file.write_all(&bytes[..keep]);
                let actual = if result.is_ok() {
                    record.stored[side] + keep as u64
                } else {
                    file.metadata()
                        .map_or(record.stored[side] + keep as u64, |m| m.len())
                };
                let actual = actual.clamp(record.stored[side], record.stored[side] + keep as u64);
                self.stats.used_bytes -= record.stored[side] + keep as u64 - actual;
                record.stored[side] = actual;
                record.dirty=true;
                let mut state = locked(&ticket.state);
                state.request_bytes = record.stored[0];
                state.response_bytes = record.stored[1];
                result
            })();
            if let Some(j)=&mut self.journal {
                j.measure(recording::Stage::PayloadWrite,started);
                j.payload_written(ticket.id,side,Some(record.stored[side]));
            }
            if let Err(error) = result {
                self.stop(ticket.id, &format!("cache write failed: {error}"));
                return;
            }
        }
        if keep < bytes.len() {
            self.stop(
                ticket.id,
                if wanted < bytes.len() as u64 && keep as u64 == wanted {
                    "per-exchange payload limit"
                } else {
                    "total payload limit (active entries protected)"
                },
            );
        }
    }
    fn stop(&mut self, id: u64, reason: &str) {
        self.fail(reason);
        if let Some(record) = self.records.get_mut(&id) {
            record.stopped = true;
            record.ticket.stop(reason);
        }
    }
    fn query(&mut self, query: Query) -> Result<Answer, String> {
        match query {
            Query::Working(name,bytes)=>{
                let result=self.journal.as_mut().ok_or("working file requires recording")?.working_file(&name,&bytes);
                if let Err(e)=&result {self.fail(e);}
                result?;Ok(Answer::Stats(self.stats.clone()))
            }
            Query::Reference(id)=>{
                if !self.records.contains_key(&id) || self.restored==Some(id) {
                    let saved:SavedEntry=serde_json::from_slice(&fs::read(self.directory.path.join(recording::metadata_relative(id))).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
                    let ticket=Arc::new(Ticket {observed_unix_ms:0,id,context:saved.context,state:Mutex::new(saved.cache.clone()),
                        info:Mutex::new(saved.info),accepting:AtomicBool::new(saved.cache.reason.is_none()),
                        pending:AtomicUsize::new(0),finished:AtomicU64::new(u64::from(saved.cache.finished))});
                    self.restore_live(ticket)?;
                }
                Ok(Answer::Reference(self.records[&id].ticket.clone()))
            }
            Query::FinishRecording=>{
                self.checkpoint();if let Some(j)=&mut self.journal {j.finish()?;}
                Ok(Answer::Stats(self.stats.clone()))
            }
            Query::Stats => {
                self.stats.entries = self.records.len();
                Ok(Answer::Stats(self.stats.clone()))
            }
            Query::Status(id) => {let _=self.restore(id);Ok(Answer::Status(
                self.records
                    .get(&id)
                    .map(|r| r.ticket.snapshot())
                    .or_else(|| self.retired.get(&id).cloned()),
            ))},
            Query::Read {
                id,
                side,
                offset,
                length,
                decode,
                decoded_limit,
            } => {
                self.restore(id)?;
                let path=self.path(id,side);
                let record = self
                    .records
                    .get_mut(&id)
                    .ok_or("payload unavailable (evicted or not admitted)")?;
                let snapshot = record.ticket.snapshot();
                if snapshot.evicted {
                    return Err("payload evicted".into());
                }
                // Complete recorded decodes are already validated on disk. A small UI
                // preview must not re-inflate the entire body or inherit its old size cap.
                if decode && length!=0 && self.directory.retained {
                    if let Some(value)=crate::recording_view::decode_metadata(&self.directory.path,id,side) {
                        if value["state"]=="complete" {
                            if let Some(size)=value["decoded_bytes"].as_u64() {
                                let relative=if value["reused_source"]==true {recording::payload_relative(id,side)}else{crate::recording_decode::relative(id,side)};
                                let mut data=vec![0;size.min(length as u64) as usize];
                                if !data.is_empty() {File::open(self.directory.path.join(relative)).and_then(|mut f|f.read_exact(&mut data)).map_err(|e|e.to_string())?;}
                                return Ok(Answer::Payload(CachedPayload {cache:snapshot,direction:if side==0{Direction::Client}else{Direction::Server},
                                    offset:0,data_base64:data,decoded:true,decoded_bytes:usize::try_from(size).map_err(|_|"decoded size overflow")?,warning:None}));
                            }
                        }
                    }
                }
                let info = locked(&record.ticket.info)[side].clone();
                let stored = record.stored[side];
                let count = if decode {
                    if !snapshot.finished
                        || snapshot.pending_chunks != 0
                        || !info.complete
                        || info.bytes != stored
                    {
                        return Err("cannot decode incomplete cached body".into());
                    }
                    // Bound the temporary input allocation independently of
                    // user-supplied disk quotas, including on 32-bit builds.
                    if stored > self.config.decode_input_bytes as u64 {
                        return Err(format!("decode input exceeds {} MiB",self.config.decode_input_bytes/1024/1024));
                    }
                    stored as usize
                } else {
                    (stored.saturating_sub(offset)).min(length as u64) as usize
                };
                let mut bytes = vec![0; count];
                if count != 0 {
                    if record.files[side].is_none() {record.files[side]=Some(File::open(path).map_err(|e|e.to_string())?);}
                    let file = record.files[side]
                        .as_mut()
                        .ok_or("payload file unavailable")?;
                    file.seek(SeekFrom::Start(offset))
                        .and_then(|_| file.read_exact(&mut bytes))
                        .map_err(|e| e.to_string())?;
                }
                let mut warning=None;
                if decode && !info.bodyless {
                    let limit=decoded_limit.min(self.config.decode_bytes);
                    if length!=0 {(bytes,warning)=crate::decode::preview(&info.headers,&bytes,limit)?;}
                    else {bytes = crate::decode::body(&info.headers, &bytes, limit)?;}
                }
                let decoded_bytes=if decode {bytes.len()} else {0};
                if decode && length!=0 {bytes.truncate(length);}
                Ok(Answer::Payload(CachedPayload {
                    cache: snapshot,
                    direction: if side == 0 {
                        Direction::Client
                    } else {
                        Direction::Server
                    },
                    offset,
                    data_base64: bytes,
                    decoded: decode,
                    decoded_bytes,
                    warning,
                }))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn worker_panic_unblocks_waiters_and_finalizes_failure() {
        for retained in [false,true] {
            let config=CacheConfig {root:std::env::temp_dir().join("proxylane-audit-worker-tests"),queue_chunks:2,recording:retained.then_some(RecordingConfig{total_bytes:1024*1024,min_free_bytes:0}),..Default::default()};
            let cache=PayloadCache::new(config.clone()).unwrap();let path=cache.directory().to_owned();
            let stream=cache.stream();stream.append_stream(Direction::Client,b"before panic");cache.stats().unwrap();
            let (entered,ready)=mpsc::channel();let (resume,wait)=mpsc::channel();
            let sender=locked(&cache.inner.sender).as_ref().unwrap().clone();
            sender.send(Command::Pause(entered,wait)).unwrap();ready.recv_timeout(Duration::from_secs(3)).unwrap();
            sender.send(Command::Panic).unwrap();
            let (reply,answer)=mpsc::channel();sender.send(Command::Query(Query::Stats,reply)).unwrap();
            let (done,result)=mpsc::channel();let producer=sender.clone();
            let blocked=thread::spawn(move||done.send(producer.send(Command::Event(json!({"type":"test"}))).is_err()).unwrap());
            resume.send(()).unwrap();
            assert!(result.recv_timeout(Duration::from_secs(3)).unwrap());blocked.join().unwrap();
            assert!(answer.recv_timeout(Duration::from_secs(3)).is_err());drop(sender);
            cache.shutdown().unwrap();
            assert!(cache.worker_error().unwrap().contains("injected cache panic"));
            assert!(cache.stats().err().unwrap().contains("injected cache panic"));
            if retained {
                let manifest:Value=serde_json::from_slice(&fs::read(path.join("manifest.json")).unwrap()).unwrap();
                assert_eq!(manifest["status"],"stopped");assert_eq!(manifest["quality"]["capture_incomplete"],true);
                assert!(manifest["stop_reason"].as_str().unwrap().contains("injected cache panic"));
                assert_eq!(fs::read(path.join(recording::payload_relative(stream.id(),0))).unwrap(),b"before panic");
            }
            let fresh=PayloadCache::new(config).unwrap();assert!(fresh.stats().is_ok());fresh.shutdown().unwrap();
        }
    }
    #[test]
    fn recording_previews_read_published_prefix_while_writer_is_paused() {
        let cache=PayloadCache::new(CacheConfig {
            root:std::env::temp_dir().join(format!("proxylane-preview-{}-{}",std::process::id(),recording::now_ms())),
            recording:Some(RecordingConfig{total_bytes:32*1024*1024,min_free_bytes:0}),
            queue_chunks:2,max_entries:2,..Default::default()
        }).unwrap();
        let stream=cache.stream();stream.append_stream(Direction::Server,b"written prefix");
        cache.stats().unwrap();
        let (entered,ready)=mpsc::channel();let (resume,wait)=mpsc::channel();
        locked(&cache.inner.sender).as_ref().unwrap().send(Command::Pause(entered,wait)).unwrap();
        ready.recv().unwrap();
        stream.append_stream(Direction::Server,b" queued suffix");
        let fresh=cache.stream();let fresh_id=fresh.id();
        let reader=cache.clone();let id=stream.id();let (done,result)=mpsc::channel();
        let task=thread::spawn(move|| {
            let status=reader.preview_status(id).unwrap();
            assert_eq!(status["response_bytes"],14);assert_eq!(status["pending_chunks"],1);
            let pending=reader.preview_status(fresh_id).unwrap();
            assert_eq!(pending["response_bytes"],0);assert_eq!(pending["finished"],false);
            let bytes=reader.preview_read(id,Direction::Server,0,65536,false).unwrap();
            assert_eq!(bytes.data_base64,b"written prefix");
            assert!(reader.preview_read(id,Direction::Server,0,1024*1024+1,false).is_err());
            done.send(()).unwrap();
        });
        let immediate=result.recv_timeout(Duration::from_secs(2));
        resume.send(()).unwrap();task.join().unwrap();
        assert!(immediate.is_ok(),"UI read queued behind paused recording writer");
        stream.finish_stream([0,28],true);cache.stats().unwrap();
        fresh.finish_stream([0,0],true);
        assert_eq!(cache.preview_read(id,Direction::Server,0,65536,false).unwrap().data_base64,b"written prefix queued suffix");
        // Retire metadata to disk, then read without restoring it into the writer.
        for _ in 0..4 {let other=cache.stream();other.append_stream(Direction::Client,b"x");other.finish_stream([1,0],true);}
        cache.stats().unwrap();
        assert!(cache.inner.preview.ticket_count()<=2);
        assert_eq!(cache.preview_read(id,Direction::Server,8,6,false).unwrap().data_base64,b"prefix");
        cache.finish_recording().unwrap();
        cache.shutdown().unwrap();
    }
    #[test]
    fn slow_disk_concurrent_large_recordings_keep_all_bytes_with_two_slots() {
        let cache=PayloadCache::new(CacheConfig {
            root:std::env::temp_dir().join(format!("proxylane-slow-recording-{}",recording::now_ms())),
            recording:Some(RecordingConfig{total_bytes:64*1024*1024,min_free_bytes:0}),
            queue_chunks:2,max_entries:2,write_delay:Duration::from_millis(2),
            ..Default::default()
        }).unwrap();
        let root=cache.directory().to_owned();
        let mut jobs=Vec::new();
        for tag in 0..8u8 {
            let c=cache.clone();
            jobs.push(thread::spawn(move|| {
                let stream=c.stream();let id=stream.id();let block=vec![tag;CHUNK];
                for _ in 0..128 {stream.append_stream(Direction::Server,&block);}
                stream.finish_stream([0,128*CHUNK as u64],true);id
            }));
        }
        let ids:Vec<_>=jobs.into_iter().map(|j|j.join().unwrap()).collect();
        cache.stats().unwrap();assert!(!cache.recording_failed());
        assert!(cache.stats().unwrap().entries<=3);
        cache.finish_recording().unwrap();cache.shutdown().unwrap();
        for (tag,id) in ids.into_iter().enumerate() {
            assert_eq!(fs::read(root.join(recording::payload_relative(id,1))).unwrap(),vec![tag as u8;128*CHUNK]);
        }
        let manifest:Value=serde_json::from_slice(&fs::read(root.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(manifest["quality"]["gap_count"],0);assert_eq!(manifest["status"],"completed");
    }
    #[test]
    fn recording_full_queue_waits_then_keeps_every_byte() {
        let (sender, receiver) = mpsc::sync_channel(1);
        let cache = PayloadCache { context:Value::Null, inner: Arc::new(Inner {
            failure: Default::default(),
            preview:Arc::new(preview::Reader::new(PathBuf::new(),1)),
            recording:Some(Arc::new(recording::State::default())), sender:Mutex::new(Some(sender)),
            worker:Mutex::new(None),next:AtomicU64::new(1),completion:AtomicU64::new(1),directory:PathBuf::new(),
        })};
        let reference=cache.entry();assert!(matches!(receiver.recv().unwrap(),Command::Register(_)));
        let writer=reference.clone();let (done,completed)=mpsc::channel();
        let producer=thread::spawn(move|| {writer.append(1,&vec![42;CHUNK*3]);done.send(()).unwrap();});
        assert!(completed.recv_timeout(Duration::from_millis(100)).is_err(),"full queue must wait");
        let mut all=Vec::new();
        for _ in 0..3 {match receiver.recv_timeout(Duration::from_secs(3)).unwrap() {
            Command::Append(ticket,side,bytes)=>{assert_eq!(side,1);all.extend(bytes);ticket.pending.fetch_sub(1,Ordering::AcqRel);}
            _=>panic!("unexpected command")
        }}
        completed.recv_timeout(Duration::from_secs(3)).unwrap();producer.join().unwrap();
        assert_eq!(all,vec![42;CHUNK*3]);assert!(reference.snapshot().reason.is_none());
        assert_eq!(reference.snapshot().pending_chunks,0);assert_eq!(cache.recording_status()["quality"]["gap_count"],0);
    }
}
