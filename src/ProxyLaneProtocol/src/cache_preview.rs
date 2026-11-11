//! Read-only live recording previews. Never enqueue work on the disk writer.
//! The bounded registry contains weak references, not payloads or extra history.
use super::*;

const META_LIMIT:u64 = 8*1024*1024;
pub(super) struct Reader {
    root:PathBuf,
    limit:usize,
    tickets:Mutex<BTreeMap<u64,Weak<Ticket>>>,
    pending:Mutex<BTreeMap<u64,Weak<Ticket>>>,
    // One bounded preview at a time, without an unbounded waiting work queue.
    reading:Mutex<()>,
}
impl Reader {
    pub fn new(root:PathBuf,limit:usize)->Self {
        Self {root,limit,tickets:Mutex::new(BTreeMap::new()),pending:Mutex::new(BTreeMap::new()),reading:Mutex::new(())}
    }
    pub fn admit(&self,ticket:&Arc<Ticket>) {
        let mut pending=locked(&self.pending);
        pending.insert(ticket.id,Arc::downgrade(ticket));
        while pending.len()>self.limit {let oldest=*pending.keys().next().unwrap();pending.remove(&oldest);}
    }
    pub fn publish(&self,ticket:Arc<Ticket>) {
        let mut tickets=locked(&self.tickets);
        tickets.insert(ticket.id,Arc::downgrade(&ticket));
        locked(&self.pending).remove(&ticket.id);
        while tickets.len()>self.limit {
            let oldest=*tickets.keys().next().unwrap();tickets.remove(&oldest);
        }
    }
    pub fn retire(&self,id:u64) {locked(&self.tickets).remove(&id);}
    #[cfg(test)]
    pub fn ticket_count(&self)->usize {locked(&self.tickets).len()+locked(&self.pending).len()}
    fn json(&self,relative:&str)->Result<Value,String> {
        let file=File::open(self.root.join(relative)).map_err(|e|e.to_string())?;
        let mut bytes=Vec::new();file.take(META_LIMIT+1).read_to_end(&mut bytes).map_err(|e|e.to_string())?;
        if bytes.len() as u64>META_LIMIT {return Err("preview metadata exceeds 8 MiB".into());}
        serde_json::from_slice(&bytes).map_err(|e|e.to_string())
    }
    fn snapshot(&self,id:u64)->Result<(CacheSnapshot,[BodyInfo;2]),String> {
        let ticket=locked(&self.tickets).get(&id).and_then(Weak::upgrade)
            .or_else(||locked(&self.pending).get(&id).and_then(Weak::upgrade));
        if let Some(ticket)=ticket {
            // Neither lock is held across disk I/O. Byte counts are published
            // only after write_all, and bound every independent file read.
            let state=ticket.snapshot();let info=locked(&ticket.info).clone();
            return Ok((state,info));
        }
        let saved:SavedEntry=serde_json::from_value(self.json(&recording::metadata_relative(id))?)
            .map_err(|e|e.to_string())?;
        Ok((saved.cache,saved.info))
    }
    pub fn status(&self,id:u64)->Result<Value,String> {
        let _read=self.reading.try_lock().map_err(|_|"recording preview reader busy; retry")?;
        let (snapshot,_)=self.snapshot(id)?;
        let mut value=serde_json::to_value(snapshot).map_err(|e|e.to_string())?;
        // Decode completion/progress must invalidate the GUI's status stamp,
        // even if encoded bytes and HTTP completion have not changed.
        let session=self.json(&crate::recording_view::session_relative(id)).unwrap_or(Value::Null);
        value["preview_decode"]=json!([session["payloads"]["request"]["decode"],session["payloads"]["response"]["decode"]]);
        Ok(value)
    }
    fn prefix(&self,relative:&str,offset:u64,size:u64,length:usize)->Result<Vec<u8>,String> {
        let count=size.saturating_sub(offset).min(length as u64) as usize;
        let mut bytes=vec![0;count];
        if count!=0 {
            // Never borrow the append handle or alter the writer's file cursor.
            let mut file=File::open(self.root.join(relative)).map_err(|e|e.to_string())?;
            file.seek(SeekFrom::Start(offset)).and_then(|_|file.read_exact(&mut bytes)).map_err(|e|e.to_string())?;
        }
        Ok(bytes)
    }
    pub fn read(&self,id:u64,direction:Direction,offset:u64,length:usize,decode:bool)->Result<CachedPayload,String> {
        if length>1024*1024 {return Err("cache read range exceeds 1 MiB".into());}
        let _read=self.reading.try_lock().map_err(|_|"recording preview reader busy; retry")?;
        let side=direction.index();
        let (snapshot,info)=self.snapshot(id)?;
        if snapshot.evicted {return Err("payload evicted".into());}
        let stored=if side==0 {snapshot.request_bytes}else{snapshot.response_bytes};
        let mut relative=recording::payload_relative(id,side);
        let mut size=stored;let mut warning=None;
        if decode {
            let session=self.json(&crate::recording_view::session_relative(id)).unwrap_or(Value::Null);
            let metadata=&session["payloads"][if side==0 {"request"}else{"response"}]["decode"];
            if let Some(bytes)=metadata["decoded_bytes"].as_u64().filter(|n|*n!=0 || metadata["state"]=="complete") {
                size=bytes;
                if metadata["reused_source"]!=true {relative=crate::recording_decode::relative(id,side);}
                if metadata["state"]!="complete" {
                    warning=Some(if metadata["state"]=="decoding" {"Recorded body decoding is in progress; available decoded prefix only.".into()}
                        else {format!("Recorded body decoding is incomplete: {}",metadata["error"].as_str().unwrap_or("partial decoded prefix"))});
                }
            } else if info[side].present && (info[side].bodyless || crate::model::tokens(&info[side].headers,"content-encoding").iter().all(|e|e=="identity")) {
                if !snapshot.finished || snapshot.pending_chunks!=0 || !info[side].complete || stored!=info[side].bytes {
                    warning=Some("Recording is still being written; available body prefix only.".into());
                }
            } else {
                // Do not inflate an entire large body just to render a preview,
                // nor wait for its recording decode job. The GUI falls back to
                // the encoded prefix, marked as such, then refreshes by stamp.
                return Err("Recorded body decoding is pending; available encoded prefix only".into());
            }
        }
        let bytes=self.prefix(&relative,offset,size,length)?;
        Ok(CachedPayload {cache:snapshot,direction,offset,data_base64:bytes,decoded:decode,
            decoded_bytes:if decode {usize::try_from(size).map_err(|_|"decoded size overflow")?}else{0},warning})
    }
}
