//! Read-only recorded session reader. Index IDs only; bodies are read on demand.
use serde_json::{json,Value};
use std::{collections::{HashMap,HashSet},fs::{self,File,OpenOptions},io::{Read,Write,Seek,SeekFrom,BufRead,BufReader},path::{Path,PathBuf,Component}};
use base64::{Engine,engine::general_purpose::STANDARD};
use crate::{recording_view::session_relative,recording_index as index};
use fs2::FileExt;
const META_LIMIT:u64=8*1024*1024;
#[derive(Clone)]
struct Item { id:u64, connection:Option<String>, time:u64, offset:u64, length:u64, sequence:u64 }
impl Item {fn path(&self)->String {self.connection.as_ref().map(|id|format!("connections/{id}.json")).unwrap_or_else(||session_relative(self.id))}}
pub struct Reader {root:PathBuf,pub run:String,manifest:Value,items:Vec<Item>,matches:Vec<usize>,filter:Option<(String,u64)>,warnings:usize,list_file:Option<File>}
impl Reader {
    fn path(&self,relative:&str)->Result<PathBuf,String> {
        let p=Path::new(relative);
        if p.components().any(|c|!matches!(c,Component::Normal(_))) || relative.contains(':') || relative.contains('\\') {return Err("invalid recording relative path".into());}
        let path=self.root.join(p).canonicalize().map_err(|e|format!("{relative}: {e}"))?;
        if !path.starts_with(&self.root){return Err("recording reference escapes directory".into());}
        Ok(path)
    }
    fn bytes(&self,relative:&str,limit:u64)->Result<Vec<u8>,String> {
        let mut file=File::open(self.path(relative)?).map_err(|e|e.to_string())?;
        if file.metadata().map_err(|e|e.to_string())?.len()>limit{return Err(format!("recording metadata exceeds read limit: {relative}"));}
        let mut bytes=Vec::new();Read::by_ref(&mut file).take(limit+1).read_to_end(&mut bytes).map_err(|e|e.to_string())?;
        if bytes.len() as u64>limit{return Err("recording metadata grew beyond limit".into());} Ok(bytes)
    }
    fn json(&self,relative:&str)->Result<Value,String> {serde_json::from_slice(&self.bytes(relative,META_LIMIT)?).map_err(|e|format!("{relative}: {e}"))}
    fn empty(path:&Path)->Result<Self,String> {
        let root=path.canonicalize().map_err(|e|format!("Cannot open recording directory: {e}"))?;
        let mut r=Self{root,run:format!("recording:{}",crate::recording::now_ms()),manifest:Value::Null,items:Vec::new(),matches:Vec::new(),filter:None,warnings:0,list_file:None};
        r.manifest=r.json("manifest.json")?;
        if r.manifest["format"]!="ProxyLaneRecording" || r.manifest["version"]!=2{return Err("This viewer requires recording format version 2. Create a new recording with this version of ProxyLane.".into());}
        Ok(r)
    }
    pub fn open(path:&Path)->Result<Self,String> {
        let mut r=Self::empty(path)?;
        r.load_index().map_err(|e|format!("{}{e}",index::REQUIRED))?;Ok(r)
    }
    fn load_index(&mut self)->Result<(),String> {
        let file=File::open(self.path(index::NAME)?).map_err(|e|e.to_string())?;
        let mut reader=BufReader::new(file.try_clone().map_err(|e|e.to_string())?);
        let mut latest=HashMap::new();let mut offset=0;let mut sequence=0;let mut ended=false;
        loop {
            let bytes=index::read_line(&mut reader)?;if bytes.is_empty(){break;}
            if ended{return Err("data after index completion marker".into());}
            let value=index::decode(&bytes,sequence)?;
            if sequence==0 {
                if value!=json!({"format":"ProxyLaneListIndex","version":1}){return Err("unsupported list index format".into());}
            } else if value.get("end").is_some() {
                if value["end"]!=sequence{return Err("invalid index completion marker".into());}ended=true;
            } else {
                let key=index::key(&value)?;
                let connection=value["connection"]["id"].as_str().unwrap_or("").to_owned();
                let item=Item{id:value["cache_id"].as_u64().unwrap_or(0),connection:if value["type"]=="connection"{Some(connection.clone())}else{None},
                    time:value["first_observed_unix_ms"].as_u64().unwrap_or(0),offset,length:bytes.len() as u64,sequence};
                latest.insert(key,(item,connection));
                if latest.len()>2_000_000{return Err("Recording index exceeds two million sessions; no entries were silently omitted.".into());}
            }
            offset+=bytes.len() as u64;sequence+=1;
        }
        if !ended{return Err("index was not finalized; the recording may have been interrupted".into());}
        let represented:HashSet<_>=latest.values().filter(|(i,_)|i.connection.is_none()).map(|(_,c)|c.clone()).collect();
        self.items=latest.into_values().filter(|(i,c)|i.connection.is_none() || !represented.contains(c)).map(|(i,_)|i).collect();
        self.items.sort_by(|a,b|a.time.cmp(&b.time).then(a.id.cmp(&b.id)).then(a.connection.cmp(&b.connection)));
        self.list_file=Some(file);Ok(())
    }
    /// Explicit user-approved recovery only. Never called by open/query.
    pub fn rebuild(path:&Path)->Result<Self,String> {
        let r=Self::empty(path)?;
        let lock_name=if r.root.join("sessions.index.lock").exists(){"sessions.index.lock"}else{"owner.lock"};
        let owner=OpenOptions::new().read(true).write(true).open(r.path(lock_name)?).map_err(|e|e.to_string())?;
        owner.try_lock_exclusive().map_err(|_|"Recording is still in use; stop/close its owner before rebuilding the index.".to_string())?;
        let temp=r.root.join(format!("sessions.index.rebuild-{}-{}",std::process::id(),crate::recording::now_ms()));
        let result=(||->Result<(),String>{
            let mut file=OpenOptions::new().write(true).create_new(true).open(&temp).map_err(|e|e.to_string())?;
            let mut sequence=0u64;
            let mut write=|v:Value|->Result<(),String>{file.write_all(&index::line(sequence,v)?).map_err(|e|format!("Cannot write rebuilt index: {e}"))?;sequence+=1;Ok(())};
            write(json!({"format":"ProxyLaneListIndex","version":1}))?;
            let mut count=0;
            for top in ["payload","connections"] {
                if !r.root.join(top).exists(){continue;}
                let mut dirs=vec![r.path(top)?];
                while let Some(dir)=dirs.pop() {
                    for entry in fs::read_dir(dir).map_err(|e|e.to_string())? {
                        let entry=entry.map_err(|e|e.to_string())?;let name=entry.file_name().to_string_lossy().to_string();
                        if top=="payload" && entry.path().parent()==Some(r.root.join("payload").as_path()) && entry.file_type().map_err(|e|e.to_string())?.is_dir() && name.bytes().all(|b|b.is_ascii_digit()) {
                            // Only one bucket level; resolve against root to reject escaping links.
                            dirs.push(r.path(&format!("payload/{name}"))?);continue;
                        }
                        let Some(stem)=name.strip_suffix(".json") else {continue;};
                        let relative=if top=="payload" {let Ok(id)=stem.parse::<u64>() else{continue;};session_relative(id)}else{format!("connections/{name}")};
                        let value=r.json(&relative)?;
                        if let Some(summary)=index::summary(&value) {
                            if summary["detail_file"]!=relative{return Err(format!("Session identity does not match metadata filename: {relative}"));}
                            index::key(&summary)?;write(summary)?;count+=1;
                            if count>2_000_000{return Err("Recording index exceeds two million sessions".into());}
                        }
                    }
                }
            }
            drop(write);file.write_all(&index::line(sequence,json!({"end":sequence}))?).map_err(|e|e.to_string())?;
            file.sync_all().map_err(|e|e.to_string())?;drop(file);
            // Install only after all metadata was read and the entire replacement synced.
            crate::recording::replace(&temp,&r.root.join(index::NAME)).map_err(|e|format!("Cannot replace recording index: {e}"))?;Ok(())
        })();
        if result.is_err(){let _=fs::remove_file(&temp);}result?;drop(owner);Self::open(&r.root)
    }
    fn list_record(&self,item:&Item)->Result<Value,String> {
        let mut v=index::read_at(self.list_file.as_ref().ok_or("No list index")?,item.offset,item.length,item.sequence)?;
        v["sequence"]=if item.connection.is_some(){u64::MAX-item.time}else{item.id}.into();
        v["observed_unix_ms"]=item.time.into();Ok(v)
    }
    fn side_path(id:u64,name:&str)->Result<String,String> {
        if name.is_empty() || name.contains(['/', '\\', ':']) || !name.starts_with(&format!("{id:012}.")){return Err("invalid session file reference".into());}
        Ok(format!("payload/{:06}/{name}",id/1000))
    }
    fn hydrate_message(&self,id:u64,message:&mut Value)->Result<(),String> {
        if !message.is_object(){return Ok(());}
        for (field,target) in [("headers_file","headers"),("trailers_file","trailers")] {
            if let Some(file)=message[field].as_str() {
                let text=String::from_utf8(self.bytes(&Self::side_path(id,file)?,META_LIMIT)?).map_err(|e|e.to_string())?;
                let mut headers=Vec::new();
                for (i,line) in text.lines().enumerate() {
                    if (i==0 && target=="headers") || line.is_empty(){continue;}
                    // HTTP/2 pseudo header names contain a leading colon.
                    if let Some(split)=line[usize::from(line.starts_with(':'))..].find(':').map(|n|n+usize::from(line.starts_with(':'))) {
                        headers.push(json!([&line[..split],line[split+1..].trim_start()]));
                    }
                }
                message[target]=headers.into();
            } else if !message[target].is_array(){message[target]=json!([]);}
        } Ok(())
    }
    fn record(&self,item:&Item,detail:bool,preview:u64)->Result<Value,String> {
        let mut v=self.json(&item.path())?;
        if v["format"]!="ProxyLaneSession" || v["version"]!=2 {return Err("Unsupported recorded session format".into());}
        v["sequence"]=if item.connection.is_some(){u64::MAX-item.time}else{item.id}.into();
        v["observed_unix_ms"]=item.time.into();
        if detail {
            if let Some(e)=v["exchange"].as_object_mut() {
                for side in ["request","response"] {if let Some(m)=e.get_mut(side){self.hydrate_message(item.id,m)?;}}
                if let Some(infos)=e.get_mut("informational").and_then(Value::as_array_mut){for m in infos {self.hydrate_message(item.id,m)?;}}
            }
            let mut packets=[Vec::new(),Vec::new()];let mut has_index=false;
            for side in 0..2 {
                if let Some(file)=v["payloads"][if side==0{"request"}else{"response"}]["datagrams_file"].as_str() {
                    has_index=true;
                    let path=self.path(&Self::side_path(item.id,file)?)?;
                    let mut reader=BufReader::new(File::open(path).map_err(|e|e.to_string())?);
                    let mut line=String::new();
                    loop {
                        line.clear();let n=reader.by_ref().take(2048).read_line(&mut line).map_err(|e|e.to_string())?;
                        if n==0{break;} if !line.ends_with('\n'){break;}
                        let p:Value=serde_json::from_str(&line).map_err(|e|e.to_string())?;
                        let offset=p["offset"].as_u64().ok_or("invalid datagram offset")?;
                        if offset>=preview || packets[side].len()>=16384 {break;}
                        packets[side].push(json!([offset,p["length"]]));
                    }
                }
            }
            if has_index {v["stream"]["datagrams"]=json!(packets);}
        }
        Ok(v)
    }
    fn matches(v:&Value,filter:&str,kind:u64)->bool {
        let p=v["protocol"].as_str().unwrap_or("");
        let transport=v["connection"]["transport"].as_str().unwrap_or("");
        let kind_ok=match kind {1=>matches!(p,"http1"|"h2"|"h3"),2=>p=="tcp" || (v["type"]=="dns" && transport!="udp"),3=>transport=="udp",4=>p.starts_with("tls") || v["connection"]["decrypted"]==true,5=>v["type"]=="dns" || v.get("doh").is_some(),6=>p.starts_with("quic")||p=="h3",_=>true};
        if !kind_ok{return false;} if filter.is_empty(){return true;}
        let c=&v["connection"];
        if filter.bytes().all(|c|c.is_ascii_digit()){return c["pid"].as_u64().map(|p|p.to_string()).as_deref()==Some(filter);}
        let text=format!("{} {} {} {} {} {} {} {}",c["process_name"].as_str().unwrap_or(""),c["pid"],c["destination"].as_str().unwrap_or(""),c["server_name"].as_str().unwrap_or(""),v["summary"]["request"]["authority"].as_str().unwrap_or(""),v["exchange"]["request"]["target"].as_str().unwrap_or(""),v["exchange"]["name"].as_str().unwrap_or(""),p);
        text.to_lowercase().contains(filter)
    }
    pub fn query(&mut self,q:&Value)->Result<Value,String> {
        let kind=q["type"].as_str().unwrap_or("");
        if kind!="recording_page" && q["run_id"].as_str()!=Some(&self.run){return Err("stale recording view".into());}
        if kind=="recording_page" {
            let filter=q["filter"].as_str().unwrap_or("").to_lowercase();let protocol=q["protocol"].as_u64().unwrap_or(0);
            if self.filter.as_ref()!=Some(&(filter.clone(),protocol)) {
                self.matches.clear();
                if filter.is_empty() && protocol==0 {self.matches.extend(0..self.items.len());}
                else {for (i,item) in self.items.iter().enumerate(){if Self::matches(&self.list_record(item)?,&filter,protocol){self.matches.push(i);}}}
                self.filter=Some((filter,protocol));
            }
            let start=(q["offset"].as_u64().unwrap_or(0) as usize).min(self.matches.len());
            let limit=q["limit"].as_u64().unwrap_or(128).clamp(1,128) as usize;
            let mut records=Vec::new();let mut bytes=0;
            for index in self.matches.iter().skip(start).take(limit) {
                let mut v=self.list_record(&self.items[*index])?;
                // Exclude large packet lists from list pages; detail loads their disk index.
                if let Some(s)=v["stream"].as_object_mut(){s.remove("datagrams");}
                bytes+=v.to_string().len();if bytes>4*1024*1024 && !records.is_empty(){break;}
                v["recording_number"]=(*index as u64+1).into();records.push(v);
            }
            return Ok(json!({"type":"records","run_id":self.run,"records":records,"next":0,"lost_before":0,"offset":start,"total":self.matches.len(),"all":self.items.len(),"warnings":self.warnings,"manifest":self.manifest,"directory":self.root}));
        }
        let id=q["cache_id"].as_u64().unwrap_or(0);
        let item=if id!=0 {Item{id,connection:None,time:0,offset:0,length:0,sequence:0}}else{Item{id:0,connection:Some(q["connection_id"].as_str().ok_or("missing session identity")?.into()),time:0,offset:0,length:0,sequence:0}};
        if kind=="recording_detail" {let mut item=item;let v=self.json(&item.path())?;item.time=v["first_observed_unix_ms"].as_u64().unwrap_or(0);return Ok(self.record(&item,true,q["preview_bytes"].as_u64().unwrap_or(65536).clamp(1,1024*1024))?);}
        let v=self.json(&item.path())?;
        let mut cache=v.get("cache").filter(|c|c.is_object()).cloned().unwrap_or_else(||v["exchange"]["cache"].clone());
        if !cache.is_object(){cache=v["stream"]["cache"].clone();}
        if !cache.is_object(){cache=json!({"id":id,"evicted":false,"finished":true,"pending_chunks":0,"reason":null});}
        if cache["finished"]!=true || cache["pending_chunks"].as_u64().unwrap_or(0)>0 {
            cache["reason"]="Recording ended before capture completion was confirmed.".into();cache["finished"]=true.into();cache["pending_chunks"]=0.into();
        }
        if kind=="cache_status" {return Ok(json!({"type":"cache_status","cache":cache,"run_id":self.run}));}
        let side=match q["direction"].as_str(){Some("client")=>"request",Some("server")=>"response",_=>return Err("invalid direction".into())};
        let payload=&v["payloads"][side];let decode=kind=="cache_decode" || kind=="doh_read";
        let info=&payload["decode"];
        let (file,size,warning)=if decode {
            if !info.is_object(){return Err("Recorded decoded body is unavailable; capture may have been interrupted.".into());}
            (info["file"].as_str(),info["decoded_bytes"].as_u64().unwrap_or(0),if info["state"]!="complete"{Some(info["error"].as_str().unwrap_or("Decoded preview is incomplete."))}else{None})
        } else {(payload["file"].as_str(),payload["bytes"].as_u64().unwrap_or(0),None)};
        let offset=if decode{0}else{q["offset"].as_u64().unwrap_or(0)};
        let limit=q[if decode{"preview_bytes"}else{"length"}].as_u64().unwrap_or(65536).min(1024*1024+1);
        let mut bytes=vec![0;size.saturating_sub(offset).min(limit) as usize];
        if !bytes.is_empty() {
            let path=self.path(&Self::side_path(id,file.ok_or("Payload file is missing")?)?)?;
            let mut f=File::open(path).map_err(|e|e.to_string())?;
            f.seek(SeekFrom::Start(offset)).and_then(|_|f.read_exact(&mut bytes)).map_err(|e|format!("Recorded payload is missing or truncated: {e}"))?;
        }
        let dns=if (kind=="dns_read" || kind=="doh_read") && !bytes.is_empty(){Some(crate::dns::decode(&bytes).map(|p|p.text))}else{None};
        Ok(json!({"type":"cache_payload","run_id":self.run,"payload":{"cache":cache,"direction":q["direction"],"offset":offset,"data_base64":STANDARD.encode(&bytes),"decoded":decode,"decoded_bytes":if decode{size}else{0},"warning":warning},"text":dns.as_ref().and_then(|d|d.as_ref().ok()),"decode_error":dns.as_ref().and_then(|d|d.as_ref().err())}))
    }
}
