//! Append-only list snapshots. No headers or bodies; details remain in payload/.
use serde_json::{json,Value};
use std::{fs::File,io::{BufRead,Read,Seek,SeekFrom},collections::{HashMap,VecDeque}};

pub const NAME:&str="sessions.index.jsonl";
pub const LIMIT:u64=128*1024;
pub const REQUIRED:&str="INDEX_REBUILD_REQUIRED: ";
pub fn checksum(bytes:&[u8])->String {
    // Integrity check for accidental corruption, not an authentication mechanism.
    let mut h=0xcbf29ce484222325u64;
    for b in bytes {h^=*b as u64;h=h.wrapping_mul(0x100000001b3);}
    format!("{h:016x}")
}
pub fn line(sequence:u64,value:Value)->Result<Vec<u8>,String> {
    let data=serde_json::to_string(&value).map_err(|e|e.to_string())?;
    let mut bytes=serde_json::to_vec(&json!({"sequence":sequence,"checksum":checksum(data.as_bytes()),"record":value})).unwrap();
    bytes.push(b'\n');
    if bytes.len() as u64>LIMIT {return Err("recording list index row exceeds limit".into());} Ok(bytes)
}
pub fn decode(bytes:&[u8],sequence:u64)->Result<Value,String> {
    if !bytes.ends_with(b"\n") {return Err("incomplete index tail".into());}
    let v:Value=serde_json::from_slice(bytes).map_err(|e|e.to_string())?;
    let record=v.get("record").ok_or("missing index record")?;
    let data=serde_json::to_vec(record).map_err(|e|e.to_string())?;
    if v["sequence"]!=sequence || v["checksum"]!=checksum(&data) {return Err("index sequence/checksum mismatch".into());}
    Ok(record.clone())
}
pub fn read_line(reader:&mut impl BufRead)->Result<Vec<u8>,String> {
    let mut bytes=Vec::new();reader.take(LIMIT+1).read_until(b'\n',&mut bytes).map_err(|e|e.to_string())?;
    if bytes.len() as u64>LIMIT {return Err("index row exceeds limit".into());} Ok(bytes)
}
pub fn key(v:&Value)->Result<String,String> {
    if v["format"]!="ProxyLaneSession" || v["version"]!=2 {return Err("invalid list snapshot format".into());}
    if v["type"]=="connection" {
        let id=v["connection"]["id"].as_str().ok_or("missing connection ID")?;
        if id.is_empty() || id.len()>128 || !id.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-'||b==b'_'){return Err("invalid connection ID".into());}
        Ok(format!("c:{id}"))
    } else if matches!(v["type"].as_str(),Some("exchange"|"stream"|"dns")) {
        let id=v["cache_id"].as_u64().filter(|n|*n!=0).ok_or("missing cache ID")?;
        Ok(format!("s:{id}"))
    } else {Err("unsupported list snapshot type".into())}
}
fn select(v:&Value,keys:&[&str])->Value {
    if !v.is_object(){return Value::Null;}
    let mut out=json!({});for key in keys {if let Some(x)=v.get(key){out[*key]=x.clone();}}out
}
pub fn summary(v:&Value)->Option<Value> {
    if !matches!(v["type"].as_str(),Some("connection"|"exchange"|"stream"|"dns")){return None;}
    let mut out=select(v,&["format","version","type","cache_id","first_observed_unix_ms","protocol","connection","status"]);
    out["detail_file"]=if v["type"]=="connection" {format!("connections/{}.json",v["connection"]["id"].as_str().unwrap_or(""))}
        else{crate::recording_view::session_relative(v["cache_id"].as_u64().unwrap_or(0))}.into();
    out["summary"]=v["summary"].clone();
    out["exchange"]=select(&v["exchange"],&["id","kind","name","status","sent_bytes","received_bytes"]);
    if out["exchange"].is_object() {
        out["exchange"]["cache"]=select(&v["exchange"]["cache"],&["id"]);
        out["exchange"]["cache"]["id"]=v["cache_id"].clone();
        for side in ["request","response"] {out["exchange"][side]=select(&v["exchange"][side],&["method","target","status","body_bytes","complete","observed_start_unix_ms"]);}
        out["exchange"]["informational"]=json!([]);
        if v["exchange"]["problem"].as_str().is_some_and(|s|!s.is_empty()){out["exchange"]["problem"]="Recorded problem".into();}
    }
    out["stream"]=select(&v["stream"],&["sent_bytes","received_bytes","finished","complete"]);
    if out["stream"].is_object(){out["stream"]["cache"]=json!({"id":v["cache_id"]});if v["stream"]["problem"].is_string(){out["stream"]["problem"]="Recorded problem".into();}}
    if v.get("doh").is_some(){out["doh"]=json!({});}
    if v["quic"].is_object(){out["quic"]=select(&v["quic"],&["version","sni"]);}
    // Arbitrary peer strings cannot make the list index unbounded. Details keep full values.
    fn bound(v:&mut Value){match v {Value::String(s)=>{if s.len()>4096{let mut n=4096;while !s.is_char_boundary(n){n-=1;}s.truncate(n);}},Value::Object(m)=>for x in m.values_mut(){bound(x)},Value::Array(a)=>for x in a{bound(x)},_=>()}}
    bound(&mut out);Some(out)
}
#[derive(Default)]
pub struct Recent { hashes:HashMap<String,String>,order:VecDeque<String> }
impl Recent {
    pub fn changed(&mut self,key:String,hash:String)->bool {
        if self.hashes.get(&key)==Some(&hash){return false;}
        if !self.hashes.contains_key(&key){if self.order.len()>=4096 {if let Some(old)=self.order.pop_front(){self.hashes.remove(&old);}}self.order.push_back(key.clone());}
        self.hashes.insert(key,hash);true
    }
}
pub fn read_at(file:&File,offset:u64,len:u64,sequence:u64)->Result<Value,String> {
    if len>LIMIT{return Err("invalid index offset length".into());}
    let mut file=file.try_clone().map_err(|e|e.to_string())?;
    file.seek(SeekFrom::Start(offset)).map_err(|e|e.to_string())?;
    let mut bytes=vec![0;len as usize];file.read_exact(&mut bytes).map_err(|e|e.to_string())?;decode(&bytes,sequence)
}
