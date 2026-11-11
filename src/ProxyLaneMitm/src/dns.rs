//! Per-connection DNS transactions; no socket I/O and no unbounded payloads.
use proxylane_protocol::{
    cache::{CacheRef, PayloadCache},
    dns, Connection, Direction,
};
use serde_json::{json, Value};
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

const PENDING: usize = 64;
const TIMEOUT: Duration = Duration::from_secs(10);
struct Transaction {
    id: u64,
    key: String,
    name: String,
    kind: String,
    wire_id: u16,
    cache: Option<CacheRef>,
    bytes: [u64; 2],
    started: Instant,
    started_ms:u64,
    retries: u32,
}
#[derive(Default)]
pub struct Dns {
    spill:Option<(PayloadCache,String)>,
    pending: VecDeque<Transaction>,
    recent: VecDeque<String>,
    next: u64,
    buffers: [Vec<u8>; 2],
}
impl Dns {
    fn spill_name(dir:&str,key:&str)->String {
        use sha2::Digest;
        format!("{dir}/{:x}.json",sha2::Sha256::digest(key.as_bytes()))
    }
    fn spill_oldest(&mut self)->Result<(),String> {
        let (cache,dir)=self.spill.as_ref().unwrap();
        if let Some(t)=self.pending.pop_front() {
            let value=json!({"id":t.id,"key":t.key,"name":t.name,"kind":t.kind,"wire_id":t.wire_id,
                "cache_id":t.cache.as_ref().map(CacheRef::id),"bytes":t.bytes,"retries":t.retries,
                "started_ms":t.started_ms});
            cache.working_write(Self::spill_name(dir,&t.key),serde_json::to_vec(&value).unwrap())?;
        }
        Ok(())
    }
    fn restore_query(&mut self,key:&str)->Result<(),String> {
        if self.pending.iter().any(|t|t.key==key) {return Ok(());}
        let Some((cache,dir))=self.spill.clone() else {return Ok(());};
        let name=Self::spill_name(&dir,key);let path=cache.directory().join(&name);
        if !std::fs::metadata(&path).is_ok_and(|m|m.len()>4) {return Ok(());}
        let value:Value=serde_json::from_slice(&std::fs::read(path).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
        if self.pending.len()>=PENDING {self.spill_oldest()?;}
        let age=proxylane_protocol::recording::now_ms().saturating_sub(value["started_ms"].as_u64().unwrap());
        let t=Transaction {id:value["id"].as_u64().unwrap(),key:key.into(),name:value["name"].as_str().unwrap().into(),
            kind:value["kind"].as_str().unwrap().into(),wire_id:value["wire_id"].as_u64().unwrap() as u16,
            cache:value["cache_id"].as_u64().map(|id|cache.reference(id)).transpose()?,
            bytes:serde_json::from_value(value["bytes"].clone()).map_err(|e|e.to_string())?,
            started_ms:value["started_ms"].as_u64().unwrap(),
            started:Instant::now().checked_sub(Duration::from_millis(age)).unwrap_or_else(Instant::now),
            retries:value["retries"].as_u64().unwrap() as u32};
        cache.working_write(name,b"null".to_vec())?;self.pending.push_back(t);Ok(())
    }
    fn duplicate(cache:Option<&PayloadCache>, identity:&Connection, side:usize, bytes:&[u8]) {
        if let Some(c)=cache.filter(|c|c.is_recording()) {
            let payload=c.scoped(json!({"connection":identity,"protocol":"dns","kind":"duplicate_datagram"})).stream();
            payload.record(json!({"type":"dns_duplicate","side":side,"length":bytes.len()}));
            payload.append_stream(if side==0 {Direction::Client}else{Direction::Server},bytes);
            let mut lengths=[0,0];lengths[side]=bytes.len() as u64;payload.finish_stream(lengths,true);
        }
    }
    fn record(
        t: &Transaction,
        identity: &Connection,
        status: &str,
        problem: Option<&str>,
        finished: bool,
    ) -> Value {
        json!({"type":"dns","protocol":"dns","connection":identity,
            "exchange":{"id":t.id,"wire_id":t.wire_id,"name":t.name,"kind":t.kind,
                "status":status,"problem":problem,"retries":t.retries,
                "started_unix_ms":t.started_ms,"elapsed_ms":proxylane_protocol::recording::observed_ms().saturating_sub(t.started_ms),"finished":finished,
                "sent_bytes":t.bytes[0],"received_bytes":t.bytes[1],"cache":t.cache}})
    }
    fn finish(t: &Transaction) {
        if let Some(cache) = &t.cache {
            cache.finish_stream(t.bytes, true);
        }
    }
    pub fn expire(&mut self, identity: &Connection, closing: Option<&str>) -> Vec<Value> {
        let mut out = Vec::new();
        // Recording backlog may be slow; wall-clock analysis delay must not
        // expire otherwise matchable queries. Spill instead until reply/stop.
        if self.spill.is_some() && closing.is_none() {return out;}
        if closing.is_some() {
            if let Some((cache,dir))=self.spill.clone() {
                if let Ok(files)=std::fs::read_dir(cache.directory().join(&dir)) {
                    for file in files.flatten() {
                        if file.path().extension().and_then(|s|s.to_str())!=Some("json") {continue;}
                        let result=(||->Result<(),String>{
                            let data=std::fs::read(file.path()).map_err(|e|e.to_string())?;
                            if data==b"null" {return Ok(());}
                            let v:Value=serde_json::from_slice(&data).map_err(|e|e.to_string())?;
                            // Flush resident queries to make room without creating
                            // more files while enumerating this directory.
                            while let Some(t)=self.pending.pop_front() {
                                Self::finish(&t);let record=Self::record(&t,identity,"Incomplete",closing,true);
                                cache.record(json!({"type":"observation","record":record}));
                                if out.len()>=PENDING {out.remove(0);}out.push(record);
                            }
                            self.restore_query(v["key"].as_str().ok_or("invalid DNS state")?)?;
                            Ok(())
                        })();
                        if let Err(e)=result {cache.fail_recording(&format!("DNS analysis state: {e}"));break;}
                    }
                }
            }
        }
        while self
            .pending
            .front()
            .is_some_and(|p| closing.is_some() || p.started.elapsed() >= TIMEOUT)
        {
            let t = self.pending.pop_front().unwrap();
            Self::finish(&t);
            out.push(Self::record(
                &t,
                identity,
                if closing.is_some() {
                    "Incomplete"
                } else {
                    "Timeout"
                },
                Some(closing.unwrap_or("DNS response timeout")),
                true,
            ));
        }
        out
    }
    pub fn feed(
        &mut self,
        identity: &Connection,
        cache: Option<&PayloadCache>,
        side: usize,
        bytes: &[u8],
    ) -> Vec<Value> {
        if self.spill.is_none() {
            if let Some(c)=cache.filter(|c|c.is_recording()) {
                self.spill=Some((c.clone(),format!("analysis/dns-{}",c.working_id())));
            }
        }
        let mut out = self.expire(identity, None);
        let packet = dns::decode(bytes);
        let valid = packet.as_ref().ok();
        if let Some(p) = valid {
            if let Err(e)=self.restore_query(&p.key) {
                if let Some(c)=cache {c.fail_recording(&format!("DNS analysis state: {e}"));}
            }
            if !p.response && side == 0 {
                if let Some(t) = self.pending.iter_mut().find(|t| t.key == p.key) {
                    Self::duplicate(cache,identity,side,bytes);
                    t.retries = t.retries.saturating_add(1);
                    out.push(Self::record(t, identity, "Pending", None, false));
                    return out;
                }
            } else if p.response && side == 1 {
                if let Some(index) = self.pending.iter().position(|t| t.key == p.key) {
                    let mut t = self.pending.remove(index).unwrap();
                    t.bytes[1] = bytes.len() as u64;
                    if let Some(c) = &t.cache {
                        c.append_stream(Direction::Server, bytes);
                    }
                    Self::finish(&t);
                    out.push(Self::record(&t, identity, &p.status, None, true));
                    self.recent.push_back(t.key);
                    if self.recent.len() > PENDING {
                        self.recent.pop_front();
                    }
                    return out;
                }
                if self.recent.contains(&p.key) {
                    Self::duplicate(cache,identity,side,bytes);
                    return out;
                }
            }
        }
        self.next += 1;
        let mut t = Transaction {
            id: self.next,
            key: valid.map(|p| p.key.clone()).unwrap_or_default(),
            name: valid.map(|p| p.name.clone()).unwrap_or_default(),
            kind: valid.map(|p| p.kind.clone()).unwrap_or_default(),
            wire_id: valid.map(|p| p.id).unwrap_or(0),
            cache: cache.map(|c|c.scoped(json!({"connection":identity,"protocol":"dns"})).stream()),
            bytes: [0; 2],
            started: Instant::now(),
            started_ms:proxylane_protocol::recording::observed_ms(),
            retries: 0,
        };
        t.bytes[side] = bytes.len() as u64;
        if let Some(c) = &t.cache {
            c.append_stream(
                if side == 0 {
                    Direction::Client
                } else {
                    Direction::Server
                },
                bytes,
            );
        }
        match packet {
            Ok(p) if !p.response && side == 0 => {
                self.recent.retain(|key| key != &t.key);
                if self.pending.len() >= PENDING {
                    if self.spill.is_some() {
                        if let Err(e)=self.spill_oldest() {if let Some(c)=cache {c.fail_recording(&e);}}
                    } else {
                    let old = self.pending.pop_front().unwrap();
                    Self::finish(&old);
                    out.push(Self::record(
                        &old,
                        identity,
                        "Incomplete",
                        Some("DNS pending query limit reached"),
                        true,
                    ));
                    }
                }
                out.push(Self::record(&t, identity, "Pending", None, false));
                self.pending.push_back(t);
            }
            Ok(p) => {
                Self::finish(&t);
                out.push(Self::record(
                    &t,
                    identity,
                    &p.status,
                    Some("Unmatched DNS message"),
                    true,
                ));
            }
            Err(e) => {
                Self::finish(&t);
                out.push(Self::record(&t, identity, "Malformed", Some(&e), true));
            }
        }
        out
    }
    pub fn tcp(
        &mut self,
        identity: &Connection,
        cache: Option<&PayloadCache>,
        side: usize,
        bytes: &[u8],
    ) -> Vec<Value> {
        // Input chunks are <=16 KiB; incomplete messages are <=65537 bytes.
        self.buffers[side].extend_from_slice(bytes);
        let mut out = Vec::new();
        loop {
            let b = &self.buffers[side];
            if b.len() < 2 {
                break;
            }
            let len = u16::from_be_bytes([b[0], b[1]]) as usize;
            if b.len() < len + 2 {
                break;
            }
            let message = b[2..len + 2].to_vec();
            self.buffers[side].drain(..len + 2);
            out.extend(self.feed(identity, cache, side, &message));
        }
        out
    }
    pub fn close(
        &mut self,
        identity: &Connection,
        cache: Option<&PayloadCache>,
        reason: &str,
    ) -> Vec<Value> {
        let mut out = Vec::new();
        for side in 0..2 {
            if !self.buffers[side].is_empty() {
                let bytes = std::mem::take(&mut self.buffers[side]);
                out.extend(self.feed(identity, cache, side, &bytes));
            }
        }
        out.extend(self.expire(identity, Some(reason)));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn query(id: u16, name: u8) -> Vec<u8> {
        let mut b = vec![0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, name, 0, 0, 1, 0, 1];
        b[..2].copy_from_slice(&id.to_be_bytes());
        b
    }
    fn response(q: &[u8]) -> Vec<u8> {
        let mut b = q.to_vec();
        b[2] = 0x81;
        b[3] = 0x83;
        b
    }
    #[test]
    fn retained_dns_overflow_matches_all_queries_without_expiring_on_analysis_delay() {
        let cache=PayloadCache::new(proxylane_protocol::cache::CacheConfig {
            root:std::env::temp_dir().join("proxylane-dns-recording-pressure"),
            recording:Some(proxylane_protocol::recording::RecordingConfig{total_bytes:16*1024*1024,min_free_bytes:0}),
            queue_chunks:2,max_entries:2,..Default::default()
        }).unwrap();
        let c=Connection::default();let mut d=Dns::default();
        for id in 0..200 {let out=d.feed(&c,Some(&cache),0,&query(id,b'a'));assert_eq!(out.last().unwrap()["exchange"]["status"],"Pending");}
        assert_eq!(d.pending.len(),PENDING);
        d.pending.front_mut().unwrap().started=Instant::now()-TIMEOUT*2;
        assert!(d.expire(&c,None).is_empty());
        for id in 0..200 {
            let out=d.feed(&c,Some(&cache),1,&response(&query(id,b'a')));
            assert_eq!(out.last().unwrap()["exchange"]["status"],"NXDOMAIN");
            assert!(out.last().unwrap()["exchange"]["problem"].is_null());
        }
        assert!(d.close(&c,Some(&cache),"stopped").is_empty());
        cache.finish_recording().unwrap();assert!(!cache.recording_failed());
        assert_eq!(cache.recording_status()["quality"]["gap_count"],0);cache.shutdown().unwrap();
    }
    #[test]
    fn matching_retransmit_reordering_id_reuse_timeout_and_limits() {
        let c = Connection::default();
        let mut d = Dns::default();
        let a = query(1, b'a');
        let b = query(1, b'b');
        let first = d.feed(&c, None, 0, &a);
        let id = first[0]["exchange"]["id"].clone();
        assert_eq!(d.feed(&c, None, 0, &a)[0]["exchange"]["retries"], 1);
        let second = d.feed(&c, None, 0, &b);
        assert_ne!(second[0]["exchange"]["id"], id);
        assert_eq!(
            d.feed(&c, None, 1, &response(&b))[0]["exchange"]["id"],
            second[0]["exchange"]["id"]
        );
        let done = d.feed(&c, None, 1, &response(&a));
        assert_eq!(done[0]["exchange"]["id"], id);
        assert_eq!(done[0]["exchange"]["status"], "NXDOMAIN");
        assert!(d.feed(&c, None, 1, &response(&a)).is_empty());
        assert_ne!(d.feed(&c, None, 0, &a)[0]["exchange"]["id"], id);
        d.pending.front_mut().unwrap().started = Instant::now() - TIMEOUT;
        assert_eq!(d.expire(&c, None)[0]["exchange"]["status"], "Timeout");
        for id in 0..100 {
            d.feed(&c, None, 0, &query(id, b'z'));
        }
        assert_eq!(d.pending.len(), PENDING);
        assert_eq!(d.expire(&c, Some("stopped")).len(), PENDING);
        assert_eq!(
            d.feed(&c, None, 0, b"bad")[0]["exchange"]["status"],
            "Malformed"
        );
    }
    #[test]
    fn tcp_split_coalesced_and_partial_close() {
        let c = Connection::default();
        let mut d = Dns::default();
        let a = query(1, b'a');
        let b = query(2, b'b');
        let mut wire = Vec::new();
        for q in [&a, &b] {
            wire.extend_from_slice(&(q.len() as u16).to_be_bytes());
            wire.extend_from_slice(q);
        }
        assert!(d.tcp(&c, None, 0, &wire[..1]).is_empty());
        assert!(d.tcp(&c, None, 0, &wire[1..7]).is_empty());
        assert_eq!(d.tcp(&c, None, 0, &wire[7..]).len(), 2);
        let res = response(&b);
        let mut wire = (res.len() as u16).to_be_bytes().to_vec();
        wire.extend_from_slice(&res);
        assert_eq!(d.tcp(&c, None, 1, &wire)[0]["exchange"]["name"], "b.");
        d.tcp(&c, None, 1, &[0, 100, 1]);
        let out = d.close(&c, None, "end");
        assert_eq!(out.len(), 2);
        assert_eq!(out[0]["exchange"]["status"], "Malformed");
        assert!(d.buffers.iter().all(Vec::is_empty));
    }
}
