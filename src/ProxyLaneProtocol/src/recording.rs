//! Open, append-only recording format. Only the existing cache worker performs I/O.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::{BTreeMap, VecDeque}, fs::{self, File, OpenOptions}, io::Write, path::{Path, PathBuf},
    sync::{Arc, Mutex, atomic::{AtomicBool, AtomicU64, Ordering}}, time::{Instant, Duration, SystemTime, UNIX_EPOCH}};

const RESERVE: u64 = 64 * 1024;
const VOLUME: u64 = 16 * 1024 * 1024;
pub const README: &str = include_str!("recording-format.txt");

#[derive(Clone, Debug)]
pub struct RecordingConfig { pub total_bytes: u64, pub min_free_bytes: u64 }

#[derive(Default)]
pub struct State {
    decode_queued: AtomicU64,
    decode_finished: AtomicU64,
    decode_failed: AtomicU64,
    decode_last: Mutex<Value>,
    pub stopped: AtomicBool,
    ended: AtomicBool,
    reason: Mutex<Option<String>>,
    used: AtomicU64,
    has_data: AtomicBool,
    gaps: AtomicU64,
    fallbacks: AtomicU64,
    analysis_fallbacks: AtomicU64,
    analysis_queued: AtomicU64,
    analysis_resumed: AtomicU64,
    fallback_reasons: Mutex<BTreeMap<String, u64>>,
    issues: Mutex<VecDeque<Value>>,
    omitted_issues: AtomicU64,
}
impl State {
    fn decoding(&self)->Value {
        let queued=self.decode_queued.load(Ordering::Acquire);let finished=self.decode_finished.load(Ordering::Acquire);
        json!({"queued":queued,"finished":finished,"pending":queued.saturating_sub(finished),
            "incomplete":self.decode_failed.load(Ordering::Acquire),"last_result":*self.decode_last.lock().unwrap_or_else(|e|e.into_inner())})
    }
    pub fn analysis_progress(&self,resumed:bool) {
        if resumed {self.analysis_resumed.fetch_add(1,Ordering::AcqRel);}
        else {self.analysis_queued.fetch_add(1,Ordering::AcqRel);}
    }
    // Separate from payload queues: a full capture queue must not lose its own
    // warning. Bound detailed notices, retaining exact aggregate counts as well.
    pub fn issue(&self, gap: bool, reason: &str, context: Value) {
        if !self.accepting() { return; }
        if gap { self.gaps.fetch_add(1, Ordering::AcqRel); }
        else { self.fallbacks.fetch_add(1, Ordering::AcqRel); }
        self.notice(json!({"type":if gap {"recording_gap"}else{"analysis_deferred"},
            "observed_unix_ms":now_ms(),"reason":reason,"context":context}));
    }
    pub fn analysis_fallback(&self, reason: &str, context: Value) {
        if !self.accepting() { return; }
        self.analysis_fallbacks.fetch_add(1,Ordering::AcqRel);
        let mut reasons=self.fallback_reasons.lock().unwrap_or_else(|e|e.into_inner());
        // Bound the manifest even if diagnostics contain arbitrary peer text.
        let key:String=reason.chars().take(64).collect();
        let key=if reasons.contains_key(&key) || reasons.len()<16 {key}else{"other".into()};
        *reasons.entry(key).or_default()+=1;
        drop(reasons);
        self.notice(json!({"type":"analysis_fallback","observed_unix_ms":now_ms(),
            "reason":reason,"context":context}));
    }
    fn notice(&self, notice: Value) {
        let mut issues=self.issues.lock().unwrap_or_else(|e|e.into_inner());
        if issues.len()<128 {issues.push_back(notice);}
        else {self.omitted_issues.fetch_add(1,Ordering::AcqRel);}
    }
    fn completeness(&self) -> Value {
        let gaps=self.gaps.load(Ordering::Acquire);
        let deferred=self.fallbacks.load(Ordering::Acquire);
        let fallback=self.analysis_fallbacks.load(Ordering::Acquire);
        let queued=self.analysis_queued.load(Ordering::Acquire);
        let resumed=self.analysis_resumed.load(Ordering::Acquire);
        json!({"capture_incomplete":gaps!=0,"gap_count":gaps,"analysis_deferred_count":deferred,
            "analysis_incomplete":gaps!=0 || deferred!=0 || fallback!=0 || queued>resumed,
            "analysis_queued_count":queued,"analysis_resumed_count":resumed,
            "analysis_pending_count":queued.saturating_sub(resumed),
            "analysis_fallback_count":fallback,
            "analysis_fallback_reasons":*self.fallback_reasons.lock().unwrap_or_else(|e|e.into_inner())})
    }
    pub fn accepting(&self) -> bool { !self.stopped.load(Ordering::Acquire) && !self.ended.load(Ordering::Acquire) }
    pub fn stop(&self, reason: &str) {
        let mut stored = self.reason.lock().unwrap_or_else(|e| e.into_inner());
        if stored.is_none() { *stored = Some(reason.chars().take(512).collect()); }
        self.stopped.store(true, Ordering::Release);
    }
    pub fn fail_worker(&self, reason:&str) {
        // A disconnected producer can report "worker unavailable" while the
        // worker unwinds. Retain the actual cause and mark uncertain capture.
        self.gaps.fetch_add(1,Ordering::AcqRel);
        *self.reason.lock().unwrap_or_else(|e|e.into_inner())=Some(reason.chars().take(512).collect());
        self.stopped.store(true,Ordering::Release);
    }
    pub fn reason(&self) -> Option<String> { self.reason.lock().unwrap_or_else(|e| e.into_inner()).clone() }
    pub fn status(&self, path: &Path) -> Value {
        json!({"enabled":true,"directory":path,"stopped":self.stopped.load(Ordering::Acquire),
            "ended":self.ended.load(Ordering::Acquire),"reason":self.reason(),"used_bytes":self.used.load(Ordering::Acquire),
            "has_data":self.has_data.load(Ordering::Acquire),
            "quality":self.completeness(),"body_decoding":self.decoding()})
    }
}
pub fn now_ms() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64 }
thread_local! { static OBSERVED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) }; }
/// Original ingress time, carried through queued analysis and disk replay.
pub fn observed_ms() -> u64 { OBSERVED.with(|v| match v.get() {0=>now_ms(), n=>n}) }
pub struct ObservationTime(u64);
pub fn observation_time(time:u64)->ObservationTime {ObservationTime(OBSERVED.with(|v|v.replace(time)))}
impl Drop for ObservationTime {fn drop(&mut self){OBSERVED.with(|v|v.set(self.0));}}
pub fn payload_relative(id: u64, side: usize) -> String {
    format!("payload/{:06}/{id:012}.{}.bin", id/1000, if side==0 {"request"} else {"response"})
}
pub fn metadata_relative(id: u64) -> String { format!("payload/{:06}/{id:012}.cache.json",id/1000) }

#[derive(Serialize, Deserialize)]
pub(crate) struct SavedEntry {
    pub cache: crate::cache::CacheSnapshot,
    pub info: [crate::cache::BodyInfo;2],
    pub context: Value,
}

#[derive(Default, Serialize)]
struct Timing { calls:u64, total_us:u64, max_us:u64 }
/// Fixed stage names only. No payloads, per-packet logs, or growing samples.
#[derive(Clone,Copy)]
pub(crate) enum Stage { Projection, Replace, Decode, PayloadWrite, PayloadSync, IndexSync, Manifest }
impl Stage {
    fn name(self)->&'static str {match self {
        Self::Projection=>"session_projection",Self::Replace=>"atomic_file_replace",Self::Decode=>"body_decode",
        Self::PayloadWrite=>"payload_write",Self::PayloadSync=>"payload_sync",Self::IndexSync=>"index_sync",Self::Manifest=>"manifest",
    }}
}

pub(crate) struct Journal {
    timings:BTreeMap<&'static str,Timing>,
    pub(crate) root: PathBuf,
    config: RecordingConfig,
    pub state: Arc<State>,
    file: File,
    process_file: Option<File>,
    process_volume: u64,
    process_bytes: u64,
    process_sequence: u64,
    volume: u64,
    volume_bytes: u64,
    sequence: u64,
    started: u64,
    manifest_size: u64,
    dirty: bool,
    finalized: bool,
    free_credit: u64,
    space_checked: Instant,
    bytes_since_space_check: u64,
    list_file: File,
    list_sequence: u64,
    list_recent: crate::recording_index::Recent,
    list_failed: bool,
    // At most one committed detail awaits its list row when a quota stops us.
    list_pending: Option<Vec<u8>>,
    list_lock: Option<File>,
    hot: crate::recording_hot::HotFiles,
    payload_sizes: std::collections::BTreeMap<(u64,usize),Option<u64>>,
    #[cfg(test)]
    list_disk_full: bool,
}
impl Journal {
    pub(crate) fn measure(&mut self,stage:Stage,start:Instant) {
        let elapsed=start.elapsed().as_micros().min(u64::MAX as u128) as u64;
        let value=self.timings.entry(stage.name()).or_default();
        value.calls=value.calls.saturating_add(1);value.total_us=value.total_us.saturating_add(elapsed);value.max_us=value.max_us.max(elapsed);
    }
    pub fn decode_queued(&mut self) {self.state.decode_queued.fetch_add(1,Ordering::AcqRel);}
    pub fn decode_update(&mut self,mut value:Value,terminal:bool)->Result<(),String> {
        for key in ["file","source_file"] {if value[key].as_str().is_some_and(|p|!self.root.join(p).is_file()){value[key]=Value::Null;}}
        let mut summary=value.clone();
        if let Some(enc)=summary["encodings"].as_array_mut() {
            enc.truncate(4);
            for e in enc {if let Some(s)=e.as_str(){*e=s.chars().take(128).collect::<String>().into();}}
        }
        if let Some(e)=summary["error"].as_str(){summary["error"]=e.chars().take(512).collect::<String>().into();}
        *self.state.decode_last.lock().unwrap_or_else(|e|e.into_inner())=summary;
        if terminal {
            self.state.decode_finished.fetch_add(1,Ordering::AcqRel);
            if value["state"]!="complete" {self.state.decode_failed.fetch_add(1,Ordering::AcqRel);}
        }
        self.event(value)
    }
    fn issues(&mut self) -> Result<(),String> {
        let pending=std::mem::take(&mut *self.state.issues.lock().unwrap_or_else(|e|e.into_inner()));
        for notice in pending { self.event(notice)?; }
        let omitted=self.state.omitted_issues.swap(0,Ordering::AcqRel);
        if omitted!=0 {self.event(json!({"type":"recording_issue_overflow","omitted_details":omitted,
            "quality":self.state.completeness(),"note":"Detailed notices exceeded the bounded warning queue; aggregate counts remain exact."}))?;}
        Ok(())
    }
    pub fn new(root: &Path, config: RecordingConfig, state: Arc<State>) -> Result<Self,String> {
        if config.total_bytes < 2*RESERVE { return Err("recording capacity must be at least 128 KiB".into()); }
        let free = fs2::available_space(root).map_err(|e| e.to_string())?;
        if free < config.min_free_bytes.saturating_add(2*RESERVE) { return Err("recording disk reserve reached".into()); }
        fs::write(root.join("README.txt"), README).map_err(|e| e.to_string())?;
        let mut reserve = File::create(root.join("finish.reserve")).map_err(|e| e.to_string())?;
        reserve.write_all(&vec![0;RESERVE as usize]).map_err(|e|e.to_string())?;
        reserve.sync_all().map_err(|e|e.to_string())?;
        let file=OpenOptions::new().create_new(true).append(true).open(root.join("events-000001.jsonl")).map_err(|e|e.to_string())?;
        let list_file=OpenOptions::new().create_new(true).append(true).open(root.join(crate::recording_index::NAME)).map_err(|e|e.to_string())?;
        let list_lock=OpenOptions::new().create_new(true).read(true).write(true).open(root.join("sessions.index.lock")).map_err(|e|e.to_string())?;
        fs2::FileExt::try_lock_exclusive(&list_lock).map_err(|e|e.to_string())?;
        state.used.store(README.len() as u64 + RESERVE,Ordering::Release);
        let free_credit=free.saturating_sub(config.min_free_bytes).saturating_sub(2*RESERVE);
        let mut journal=Self {process_file:None,process_volume:0,process_bytes:0,process_sequence:0,timings:Default::default(),root:root.to_owned(),config,state,file,volume:1,volume_bytes:0,sequence:0,
            started:now_ms(),manifest_size:0,dirty:false,finalized:false,
            free_credit,
            space_checked:Instant::now(),bytes_since_space_check:0,
            list_file,list_sequence:0,list_recent:Default::default(),list_failed:false,list_pending:None,list_lock:Some(list_lock),
            hot:Default::default(),payload_sizes:Default::default(),
            #[cfg(test)] list_disk_full:false};
        journal.list_write(json!({"format":"ProxyLaneListIndex","version":1}))?;
        journal.manifest("recording",None)?;
        journal.event(json!({"type":"recording_started"}))?;
        journal.flush()?;
        Ok(journal)
    }
    pub fn charge(&mut self, bytes: u64) -> Result<(),String> {
        if self.state.stopped.load(Ordering::Acquire) { return Err(self.state.reason().unwrap_or_else(||"recording stopped".into())); }
        let used=self.state.used.load(Ordering::Acquire);
        let result:Result<(),String>=if bytes>self.config.total_bytes.saturating_sub(used).saturating_sub(8192) {Err("recording capacity reached".into())}
        else {
            // Account every byte, but avoid a filesystem capacity syscall for every TLS fragment.
            // Other writers are detected within 250 ms or 1 MiB; actual write errors stop immediately.
            if self.free_credit<bytes || self.bytes_since_space_check>=1024*1024 || self.space_checked.elapsed()>=Duration::from_millis(250) {
                match fs2::available_space(&self.root) {
                    Ok(free)=> {self.free_credit=free.saturating_sub(self.config.min_free_bytes);self.space_checked=Instant::now();self.bytes_since_space_check=0;}
                    Err(e)=> {let reason=format!("cannot query recording disk space: {e}");self.state.stop(&reason);return Err(reason);}
                }
            }
            if self.free_credit<bytes {Err("recording disk reserve reached".into())}else{Ok(())}
        };
        if let Err(reason)=&result {self.state.stop(reason);return result;}
        self.state.used.fetch_add(bytes,Ordering::AcqRel);
        self.free_credit=self.free_credit.saturating_sub(bytes);self.bytes_since_space_check+=bytes;
        Ok(())
    }
    pub fn event(&mut self, mut value: Value) -> Result<(),String> {
        if self.finalized { return Ok(()); }
        if self.state.stopped.load(Ordering::Acquire) {return Err(self.state.reason().unwrap_or_else(||"recording stopped".into()));}
        let next_sequence=self.sequence+1;
        value["sequence"]=next_sequence.into(); value["timestamp_unix_ms"]=now_ms().into();
        value["recording_id"]=self.root.file_name().unwrap().to_string_lossy().to_string().into();
        let started=Instant::now();let projected=crate::recording_view::project(self,&mut value);
        self.measure(Stage::Projection,started);
        if let Err(e)=projected {
            // A quota rejection occurs before a write. Actual projection/index
            // corruption must still require an explicit rebuild on opening.
            if !Self::quota_stop(&e) {self.list_failed=true;} return Err(e);
        }
        let mut line=serde_json::to_vec(&value).map_err(|e|e.to_string())?;line.push(b'\n');
        self.charge(line.len() as u64)?;
        if self.volume_bytes>0 && self.volume_bytes+line.len() as u64>VOLUME {
            self.file.sync_data().map_err(|e|e.to_string())?;
            self.volume+=1;self.volume_bytes=0;
            self.file=OpenOptions::new().create_new(true).append(true).open(self.root.join(format!("events-{:06}.jsonl",self.volume))).map_err(|e|e.to_string())?;
        }
        self.file.write_all(&line).map_err(|e|format!("recording index write failed: {e}"))?;
        // Administrative files/events alone do not mean traffic was captured.
        if matches!(value["type"].as_str(),Some("observation"|"message_head"|"exchange_end"|"websocket_message")) ||
            (value["type"]=="payload_checkpoint" &&
                (value["cache"]["request_bytes"].as_u64().unwrap_or(0)>0 || value["cache"]["response_bytes"].as_u64().unwrap_or(0)>0)) {
            self.state.has_data.store(true,Ordering::Release);
        }
        self.sequence=next_sequence;
        self.volume_bytes+=line.len() as u64;self.dirty=true;
        Ok(())
    }
    /// Independent journal: no session projection, traffic event or list row.
    pub fn process_event(&mut self, mut value:Value)->Result<(),String> {
        if self.finalized {return Err("recording already finalized".into());}
        value["sequence"]=(self.process_sequence+1).into();
        value["timestamp_unix_ms"]=now_ms().into();
        value["recording_id"]=self.root.file_name().unwrap().to_string_lossy().to_string().into();
        let mut line=serde_json::to_vec(&value).map_err(|e|e.to_string())?;line.push(b'\n');
        self.charge(line.len() as u64)?;
        if self.process_file.is_none() || self.process_bytes+line.len() as u64>VOLUME {
            if let Some(file)=&self.process_file {file.sync_data().map_err(|e|format!("process journal sync failed: {e}"))?;}
            self.process_volume+=1;self.process_bytes=0;
            self.process_file=Some(OpenOptions::new().create_new(true).append(true)
                .open(self.root.join(format!("process-events-{:06}.jsonl",self.process_volume)))
                .map_err(|e|format!("process journal open failed: {e}"))?);
        }
        self.process_file.as_mut().unwrap().write_all(&line).map_err(|e|format!("process journal write failed: {e}"))?;
        self.process_sequence+=1;self.process_bytes+=line.len() as u64;
        self.state.has_data.store(true,Ordering::Release);self.dirty=true;Ok(())
    }
    fn sync_files(&self)->std::io::Result<()> {
        self.file.sync_data()?;self.list_file.sync_data()?;
        if let Some(file)=&self.process_file {file.sync_data()?;} Ok(())
    }
    pub fn append_file(&mut self, relative:&str, data:&[u8])->Result<(),String> {
        self.charge(data.len() as u64)?;
        let path=self.root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).map_err(|e|e.to_string())?;
        let mut file=OpenOptions::new().create(true).append(true).open(path).map_err(|e|e.to_string())?;
        file.write_all(data).map_err(|e|e.to_string())
    }
    fn list_write(&mut self,value:Value)->Result<(),String> {
        let bytes=crate::recording_index::line(self.list_sequence,value)?;
        if let Err(e)=self.charge(bytes.len() as u64) {
            // The detail JSON is already committed. Preserve its final row,
            // bounded by the preallocated finish budget, instead of hiding it.
            if Self::quota_stop(&e) && self.list_pending.is_none() && bytes.len() as u64<=RESERVE-8192-1024 {
                self.list_pending=Some(bytes);
            } else {self.list_failed=true;}
            return Err(e);
        }
        self.list_append(&bytes)
    }
    fn list_append(&mut self,bytes:&[u8])->Result<(),String> {
        #[cfg(test)]
        if self.list_disk_full {
            // Fault injection: a partially written row followed by ERROR_DISK_FULL.
            self.list_file.write_all(&bytes[..bytes.len()/2]).unwrap();self.list_failed=true;
            return Err(format!("recording list index write failed: {}",std::io::Error::from_raw_os_error(112)));
        }
        if let Err(e)=self.list_file.write_all(bytes){self.list_failed=true;return Err(format!("recording list index write failed: {e}"));}
        self.list_sequence+=1;self.dirty=true;Ok(())
    }
    pub(crate) fn list_snapshot(&mut self,value:&Value)->Result<(),String> {
        let Some(summary)=crate::recording_index::summary(value) else{return Ok(());};
        let key=crate::recording_index::key(&summary)?;
        let hash=crate::recording_index::checksum(&serde_json::to_vec(&summary).unwrap());
        if self.list_recent.changed(key,hash){self.list_write(summary)?;} Ok(())
    }
    pub fn working_file(&mut self, relative:&str, data:&[u8]) -> Result<(),String> {
        let started=Instant::now();let result=self.working_file_inner(relative,data);
        self.measure(Stage::Replace,started);result
    }
    pub(crate) fn read_working(&mut self,relative:&str)->std::io::Result<Arc<Vec<u8>>> {
        if let Some(data)=self.hot.get(relative){return Ok(data);}
        let data=Arc::new(fs::read(self.root.join(relative))?);self.hot.put(relative,data.clone());Ok(data)
    }
    pub(crate) fn payload_written(&mut self,id:u64,side:usize,size:Option<u64>) {
        if self.payload_sizes.len()>=512 && !self.payload_sizes.contains_key(&(id,side)) {self.payload_sizes.pop_first();}
        self.payload_sizes.insert((id,side),size);
    }
    pub(crate) fn payload_size(&mut self,id:u64,side:usize)->Option<u64> {
        if let Some(size)=self.payload_sizes.get(&(id,side)){return *size;}
        let size=fs::metadata(self.root.join(payload_relative(id,side))).ok().map(|m|m.len());
        self.payload_written(id,side,size);size
    }
    fn working_file_inner(&mut self, relative:&str, data:&[u8]) -> Result<(),String> {
        let path=self.root.join(relative);
        let cached=self.hot.get(relative);
        let previous=cached.as_ref().map_or_else(||fs::metadata(&path).map_or(0,|m|m.len()),|b|b.len() as u64);
        if data==b"null" && relative.starts_with("analysis/") {
            // Completed working state is disposable; recorded traffic is not.
            if path.exists() {fs::remove_file(&path).map_err(|e|e.to_string())?;}
            self.state.used.fetch_sub(previous,Ordering::AcqRel);
            self.hot.remove(relative);
            return Ok(());
        }
        if cached.as_ref().is_some_and(|b|b.as_slice()==data){return Ok(());}
        // Charge the replacement before writing. Work files count against the
        // same capacity/disk reserve as payloads, not an unbounded side cache.
        self.charge(data.len() as u64)?;
        fs::create_dir_all(path.parent().unwrap()).map_err(|e|e.to_string())?;
        let temp=path.with_extension("next");
        fs::write(&temp,data).map_err(|e|e.to_string())?;
        replace(&temp,&path).map_err(|e|e.to_string())?;
        self.state.used.fetch_sub(previous,Ordering::AcqRel);
        self.hot.put(relative,Arc::new(data.to_vec()));
        Ok(())
    }
    fn manifest(&mut self, status: &str, reason: Option<String>) -> Result<(),String> {
        let started=Instant::now();let result=self.manifest_inner(status,reason);
        self.measure(Stage::Manifest,started);result
    }
    fn manifest_inner(&mut self, status: &str, reason: Option<String>) -> Result<(),String> {
        let mut value=json!({"format":"ProxyLaneRecording","version":2,"producer":{"name":"ProxyLane","version":env!("PROXYLANE_PRODUCT_VERSION")},"recording_id":self.root.file_name().unwrap().to_string_lossy(),
            "started_unix_ms":self.started,"updated_unix_ms":now_ms(),"status":status,"stop_reason":reason,
            "last_sequence":self.sequence,"volumes":self.volume,"capacity_bytes":self.config.total_bytes,
            "min_free_bytes":self.config.min_free_bytes,"used_bytes":self.state.used.load(Ordering::Acquire),
            "process_events":{"files":"process-events-*.jsonl","version":1,"last_sequence":self.process_sequence,"volumes":self.process_volume,
                "scope":"Observed child creation notifications and launcher operations during this recording; not a system-wide process audit"},
            "events":"events-*.jsonl","readme":"README.txt","list_index":{"file":crate::recording_index::NAME,"version":1},"has_data":self.state.has_data.load(Ordering::Acquire),"quality":self.state.completeness(),
            "body_decoding":self.state.decoding(),
            "performance":{"unit":"microseconds","stages":self.timings,
                "note":"Inclusive worker timings; stages overlap and must not be summed. Final manifest write is excluded."}});
        // Include this replacement's size, including changes in timing fields
        // and the digit count of used_bytes itself.
        let base=self.state.used.load(Ordering::Acquire).saturating_sub(self.manifest_size);
        let bytes=loop {
            let bytes=serde_json::to_vec_pretty(&value).map_err(|e|e.to_string())?;
            let used=base+bytes.len() as u64;
            if value["used_bytes"].as_u64()==Some(used) {break bytes;}
            value["used_bytes"]=used.into();
        };
        // Working/terminal manifest replacements are bounded by the preallocated finish reserve.
        if bytes.len()>8192 { return Err("recording manifest exceeds reserve".into()); }
        let temp=self.root.join("manifest.next");
        let mut file=File::create(&temp).map_err(|e|e.to_string())?;
        file.write_all(&bytes).and_then(|_|file.sync_all()).map_err(|e|e.to_string())?;drop(file);
        replace(&temp,&self.root.join("manifest.json")).map_err(|e|e.to_string())?;
        let previous=self.manifest_size;self.manifest_size=bytes.len() as u64;
        if self.manifest_size>=previous {self.state.used.fetch_add(self.manifest_size-previous,Ordering::AcqRel);}
        else {self.state.used.fetch_sub(previous-self.manifest_size,Ordering::AcqRel);}
        Ok(())
    }
    pub fn flush(&mut self) -> Result<(),String> {
        if self.finalized {return Ok(());}
        self.issues()?;
        if self.dirty {
            let started=Instant::now();let result=self.sync_files();
            self.measure(Stage::IndexSync,started);
            result.map_err(|e|format!("recording index sync failed: {e}"))?;self.dirty=false;
        }
        self.manifest("recording",None)
    }
    pub fn finish(&mut self) -> Result<(),String> {
        if self.finalized {return Ok(());}
        if !self.state.stopped.load(Ordering::Acquire) {if let Err(e)=self.issues() {self.state.stop(&e);}}
        // This budget was already charged and physically allocated at start.
        // Final rows must not use charge(), which rejects every stopped writer.
        match fs::remove_file(self.root.join("finish.reserve")) {
            Ok(())=>{self.state.used.fetch_sub(RESERVE,Ordering::AcqRel);},
            Err(e)=>{self.list_failed=true;self.state.stop(&format!("cannot release recording finish reserve: {e}"));},
        }
        if !self.list_failed {
            let result=(|| {
                if let Some(bytes)=self.list_pending.take() {
                    self.list_append(&bytes)?;self.state.used.fetch_add(bytes.len() as u64,Ordering::AcqRel);
                }
                let end=crate::recording_index::line(self.list_sequence,json!({"end":self.list_sequence}))?;
                self.list_append(&end)?;self.state.used.fetch_add(end.len() as u64,Ordering::AcqRel);
                Ok::<_,String>(())
            })();
            if let Err(e)=result {self.list_failed=true;self.state.stop(&e);}
        }
        self.finalized=true;self.state.ended.store(true,Ordering::Release);
        let started=Instant::now();
        let sync=self.sync_files().map_err(|e|format!("recording index sync failed: {e}"));
        self.measure(Stage::IndexSync,started);
        if let Err(e)=&sync {self.state.stop(e);}
        let manifest=self.manifest(if self.state.stopped.load(Ordering::Acquire) {"stopped"}else{"completed"},self.state.reason());
        self.list_lock.take();manifest?;
        sync
    }
    fn quota_stop(reason:&str)->bool {matches!(reason,"recording capacity reached"|"recording disk reserve reached")}
    pub(crate) fn worker_panicked(&mut self, reason:&str) {
        // We cannot know which write/projection unwound. Do not seal an index
        // whose correspondence to its detail files is now uncertain.
        self.list_failed=true;
        self.finalized=false; // Also retry the terminal manifest if finish unwound.
        self.state.fail_worker(reason);
    }
}

pub(crate) fn replace(from: &Path, to: &Path) -> std::io::Result<()> {
    #[cfg(windows)] { use std::os::windows::ffi::OsStrExt;
        #[link(name="kernel32")] extern "system" {fn MoveFileExW(from:*const u16,to:*const u16,flags:u32)->i32;}
        let a:Vec<u16>=from.as_os_str().encode_wide().chain(Some(0)).collect();
        let b:Vec<u16>=to.as_os_str().encode_wide().chain(Some(0)).collect();
        if unsafe{MoveFileExW(a.as_ptr(),b.as_ptr(),1|8)}==0 {return Err(std::io::Error::last_os_error());} Ok(())
    }
    #[cfg(not(windows))] {fs::rename(from,to)}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quota_stops_seal_valid_indexes_without_rebuild() {
        for disk in [false,true] {
            let path=std::env::temp_dir().join(format!("proxylane-index-stop-{}-{}-{disk}",std::process::id(),now_ms()));
            fs::create_dir_all(&path).unwrap();File::create(path.join("owner.lock")).unwrap();
            let state=Arc::new(State::default());
            let mut j=Journal::new(&path,RecordingConfig{total_bytes:1024*1024,min_free_bytes:0},state.clone()).unwrap();
            j.event(json!({"type":"observation","record":{"type":"connection","connection":{"id":"1"},"status":"Closed"}})).unwrap();
            if disk {j.config.min_free_bytes=u64::MAX;j.free_credit=0;}
            else {j.config.total_bytes=state.used.load(Ordering::Acquire)+8192;}
            // The second detail is rejected before writing; index 1 remains usable.
            assert!(j.event(json!({"type":"observation","record":{"type":"connection","connection":{"id":"2"}}})).is_err());
            j.finish().unwrap();j.finish().unwrap();drop(j);
            let mut reader=crate::recording_reader::Reader::open(&path).unwrap();
            assert_eq!(reader.query(&json!({"type":"recording_page"})).unwrap()["total"],1);
            let manifest:Value=serde_json::from_slice(&fs::read(path.join("manifest.json")).unwrap()).unwrap();
            assert_eq!(manifest["status"],"stopped");
            assert_eq!(manifest["stop_reason"],if disk {"recording disk reserve reached"}else{"recording capacity reached"});
            assert!(!path.join("finish.reserve").exists());
        }
    }
    #[test]
    fn quota_after_detail_commit_flushes_one_pending_index_row() {
        let path=std::env::temp_dir().join(format!("proxylane-index-pending-{}-{}",std::process::id(),now_ms()));
        fs::create_dir_all(&path).unwrap();File::create(path.join("owner.lock")).unwrap();
        let state=Arc::new(State::default());
        let mut j=Journal::new(&path,RecordingConfig{total_bytes:1024*1024,min_free_bytes:0},state.clone()).unwrap();
        let record=json!({"type":"connection","connection":{"id":"quic-1"},"status":"Closed"});
        let mut saved=record.clone();saved["format"]="ProxyLaneSession".into();saved["version"]=2.into();saved["first_observed_unix_ms"]=100.into();
        j.config.total_bytes=state.used.load(Ordering::Acquire)+8192+serde_json::to_vec_pretty(&saved).unwrap().len() as u64;
        let limit=j.config.total_bytes;
        assert_eq!(j.event(json!({"type":"observation","observed_unix_ms":100,"record":record})).unwrap_err(),"recording capacity reached");
        assert!(path.join("connections/quic-1.json").is_file());assert!(j.list_pending.is_some());
        j.finish().unwrap();drop(j);
        let mut reader=crate::recording_reader::Reader::open(&path).unwrap();
        assert_eq!(reader.query(&json!({"type":"recording_page"})).unwrap()["total"],1);
        let manifest:Value=serde_json::from_slice(&fs::read(path.join("manifest.json")).unwrap()).unwrap();
        assert!(manifest["used_bytes"].as_u64().unwrap()<=limit);
        let size:u64=fs::read_dir(&path).unwrap().map(|e|e.unwrap()).filter(|e|e.file_type().unwrap().is_file())
            .map(|e|e.metadata().unwrap().len()).sum::<u64>()+fs::metadata(path.join("connections/quic-1.json")).unwrap().len();
        assert_eq!(manifest["used_bytes"],size);
    }
    #[test]
    fn list_index_disk_full_preserves_details_and_requires_rebuild() {
        let path=std::env::temp_dir().join(format!("proxylane-list-full-{}-{}",std::process::id(),now_ms()));fs::create_dir_all(&path).unwrap();
        File::create(path.join("owner.lock")).unwrap();
        let state=Arc::new(State::default());let mut journal=Journal::new(&path,RecordingConfig{total_bytes:1024*1024,min_free_bytes:0},state.clone()).unwrap();
        journal.list_disk_full=true;
        let error=journal.event(json!({"type":"observation","record":{"type":"connection","protocol":"h3","connection":{"id":"quic-29"},"status":"Closed"}})).unwrap_err();
        assert!(error.contains("list index write failed"));state.stop(&error);journal.finish().unwrap();drop(journal);
        assert!(path.join("connections/quic-29.json").is_file(),"detail was committed before the failed index write");
        assert!(crate::recording_reader::Reader::open(&path).err().unwrap().starts_with(crate::recording_index::REQUIRED));
        let mut reader=crate::recording_reader::Reader::rebuild(&path).unwrap();
        assert_eq!(reader.query(&json!({"type":"recording_page"})).unwrap()["total"],1);
        let manifest:Value=serde_json::from_slice(&fs::read(path.join("manifest.json")).unwrap()).unwrap();assert_eq!(manifest["status"],"stopped");
    }
    #[test]
    fn list_index_counts_toward_capacity_and_recent_dedup_is_bounded() {
        let path=std::env::temp_dir().join(format!("proxylane-list-quota-{}-{}",std::process::id(),now_ms()));fs::create_dir_all(&path).unwrap();
        let state=Arc::new(State::default());let mut journal=Journal::new(&path,RecordingConfig{total_bytes:1024*1024,min_free_bytes:0},state.clone()).unwrap();
        let snapshot=json!({"format":"ProxyLaneSession","version":2,"type":"connection","connection":{"id":"1"},"status":"Active"});
        let before=state.used.load(Ordering::Acquire);journal.list_snapshot(&snapshot).unwrap();
        let after=state.used.load(Ordering::Acquire);assert!(after>before);
        journal.list_snapshot(&snapshot).unwrap();assert_eq!(state.used.load(Ordering::Acquire),after);
        journal.config.total_bytes=after+8192;
        assert_eq!(journal.list_snapshot(&json!({"format":"ProxyLaneSession","version":2,"type":"connection","connection":{"id":"2"}})).unwrap_err(),"recording capacity reached");
        journal.finish().unwrap();assert!(state.stopped.load(Ordering::Acquire));
    }
    #[test]
    fn analysis_quality_is_checkpointed_and_survives_notice_overflow() {
        let path=std::env::temp_dir().join(format!("proxylane-analysis-quality-{}-{}",std::process::id(),now_ms()));
        fs::create_dir_all(&path).unwrap();let state=Arc::new(State::default());
        let mut journal=Journal::new(&path,RecordingConfig{total_bytes:1024*1024,min_free_bytes:0},state.clone()).unwrap();
        for _ in 0..1000 {state.analysis_fallback("pending exchange limit",json!({"connection_id":"test"}));}
        journal.flush().unwrap();
        for finished in [false,true] {
            if finished {journal.finish().unwrap();}
            let manifest:Value=serde_json::from_slice(&fs::read(path.join("manifest.json")).unwrap()).unwrap();
            assert_eq!(manifest["quality"]["capture_incomplete"],false);
            assert_eq!(manifest["quality"]["analysis_incomplete"],true);
            assert_eq!(manifest["quality"]["analysis_deferred_count"],0);
            assert_eq!(manifest["quality"]["analysis_fallback_count"],1000);
            assert_eq!(manifest["quality"]["analysis_fallback_reasons"]["pending exchange limit"],1000);
        }
        let events:Vec<Value>=fs::read_to_string(path.join("events-000001.jsonl")).unwrap().lines().map(|s|serde_json::from_str(s).unwrap()).collect();
        assert_eq!(events.iter().filter(|v|v["type"]=="analysis_fallback").count(),128);
        assert_eq!(events.iter().find(|v|v["type"]=="recording_issue_overflow").unwrap()["omitted_details"],872);
    }
    #[test]
    fn overload_notices_are_bounded_but_manifest_counts_remain_exact() {
        let path=std::env::temp_dir().join(format!("proxylane-recording-notices-{}-{}",std::process::id(),now_ms()));
        fs::create_dir_all(&path).unwrap();let state=Arc::new(State::default());
        let mut journal=Journal::new(&path,RecordingConfig {total_bytes:1024*1024,min_free_bytes:0},state.clone()).unwrap();
        for id in 0..1000 {state.issue(true,"test overload",json!({"connection_id":id}));}
        assert_eq!(state.issues.lock().unwrap().len(),128);assert!(!state.stopped.load(Ordering::Acquire));
        journal.flush().unwrap();journal.event(json!({"type":"still_recording"})).unwrap();journal.finish().unwrap();
        let manifest:Value=serde_json::from_slice(&fs::read(path.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(manifest["status"],"completed");assert_eq!(manifest["quality"]["gap_count"],1000);
        let events:Vec<Value>=fs::read_to_string(path.join("events-000001.jsonl")).unwrap().lines().map(|l|serde_json::from_str(l).unwrap()).collect();
        assert_eq!(events.iter().filter(|e|e["type"]=="recording_gap").count(),128);
        assert_eq!(events.iter().find(|e|e["type"]=="recording_issue_overflow").unwrap()["omitted_details"],872);
    }
    #[test]
    fn a_disk_reserve_change_stops_an_active_writer() {
        let path=std::env::temp_dir().join(format!("proxylane-recording-disk-{}-{}",std::process::id(),now_ms()));
        fs::create_dir_all(&path).unwrap();
        let state=Arc::new(State::default());
        let mut journal=Journal::new(&path,RecordingConfig {total_bytes:1024*1024,min_free_bytes:0},state.clone()).unwrap();
        journal.config.min_free_bytes=u64::MAX;
        journal.free_credit=0;
        assert_eq!(journal.event(json!({"type":"test"})).unwrap_err(),"recording disk reserve reached");
        assert!(state.stopped.load(Ordering::Acquire));journal.finish().unwrap();
        let manifest:Value=serde_json::from_slice(&fs::read(path.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(manifest["status"],"stopped");assert_eq!(manifest["stop_reason"],"recording disk reserve reached");
    }
}
