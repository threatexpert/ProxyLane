//! Per-session projections. Written before their append-only event references.
use crate::recording::{Journal,payload_relative};
use serde_json::{json,Value};
use std::{fs,path::Path};

pub fn session_relative(id:u64)->String {format!("payload/{:06}/{id:012}.json",id/1000)}
// A queued/replayed event can arrive after its snapshot was first created.
// Disk registration time must never replace the original ingress time.
fn first_observed(saved:&Value, observed:u64)->u64 {
    [Some(observed),saved["first_observed_unix_ms"].as_u64(),
        saved["exchange"]["request"]["observed_start_unix_ms"].as_u64(),
        saved["exchange"]["response"]["observed_start_unix_ms"].as_u64()]
        .into_iter().flatten().filter(|t|*t!=0).min().unwrap_or(observed)
}
fn side_name(side:usize)->&'static str {if side==0 {"request"}else{"response"}}
pub fn decode_metadata(root:&Path,id:u64,side:usize)->Option<Value> {
    let v:Value=serde_json::from_slice(&fs::read(root.join(session_relative(id))).ok()?).ok()?;
    v["payloads"][side_name(side)]["decode"].as_object().map(|_|v["payloads"][side_name(side)]["decode"].clone())
}
fn header_text(message:&Value,side:usize,protocol:&str)->String {
    let p=match protocol {"h2"=>"HTTP/2","h3"=>"HTTP/3",_=>"HTTP/1.1"};
    let mut s=if side==0 {format!("{} {} {p}\r\n",message["method"].as_str().unwrap_or(""),message["target"].as_str().unwrap_or(""))}
        else {format!("{p} {}\r\n",message["status"])};
    if let Some(h)=message["headers"].as_array() {for pair in h {s.push_str(&format!("{}: {}\r\n",pair[0].as_str().unwrap_or(""),pair[1].as_str().unwrap_or("")));}}
    s.push_str("\r\n");s
}
fn strip_headers(j:&mut Journal,message:&mut Value,id:u64,side:usize,protocol:&str,suffix:&str)->Result<(),String> {
    if !message.is_object(){return Ok(());}
    if message["headers"].is_array() {
        let relative=payload_relative(id,side).replace(".bin",&format!("{suffix}.headers.txt"));
        let bytes=header_text(message,side,protocol);
        if j.read_working(&relative).ok().as_ref().map(|b|b.as_slice())!=Some(bytes.as_bytes()) {j.working_file(&relative,bytes.as_bytes())?;}
        message["headers_file"]=Path::new(&relative).file_name().unwrap().to_string_lossy().to_string().into();
        message.as_object_mut().unwrap().remove("headers");
    }
    if let Some(trailers)=message.as_object_mut().unwrap().remove("trailers") {
        if trailers.as_array().is_some_and(|a|!a.is_empty()) {
            let relative=payload_relative(id,side).replace(".bin",&format!("{suffix}.trailers.txt"));
            let mut text=String::new();for pair in trailers.as_array().unwrap(){text.push_str(&format!("{}: {}\r\n",pair[0].as_str().unwrap_or(""),pair[1].as_str().unwrap_or("")));}
            j.working_file(&relative,text.as_bytes())?;
            message["trailers_file"]=Path::new(&relative).file_name().unwrap().to_string_lossy().to_string().into();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn late_observations_preserve_checkpoint_and_original_time() {
        let path=std::env::temp_dir().join(format!("proxylane-projection-{}-{}",std::process::id(),crate::recording::now_ms()));
        fs::create_dir_all(&path).unwrap();
        let mut j=Journal::new(&path,crate::recording::RecordingConfig{total_bytes:16*1024*1024,min_free_bytes:0},Default::default()).unwrap();
        for (id,section) in [(1,"exchange"),(2,"stream")] {
            j.event(json!({"type":"payload_registered","cache_id":id,"observed_unix_ms":9000})).unwrap();
            let cache=json!({"id":id,"request_bytes":0,"response_bytes":3,"pending_chunks":0,"finished":true,"evicted":false,"reason":null});
            j.event(json!({"type":"payload_checkpoint","cache_id":id,"cache":cache,"observed_unix_ms":10000})).unwrap();
            let mut record=json!({"type":section,"protocol":"tcp","connection":{"id":"test"}});
            record[section]=json!({"cache":{"id":id,"response_bytes":0,"pending_chunks":4,"finished":true}});
            if section=="exchange" {record[section]["request"]=json!({"observed_start_unix_ms":1000});}
            j.event(json!({"type":"observation","observed_unix_ms":2000,"record":record})).unwrap();
            let saved:Value=serde_json::from_slice(&fs::read(path.join(session_relative(id))).unwrap()).unwrap();
            assert_eq!(saved[section]["cache"],cache);assert_eq!(saved["cache"],cache);
            assert_eq!(saved["first_observed_unix_ms"],if section=="exchange" {1000}else{2000});
        }
        for time in [9000,1000,12000] {j.event(json!({"type":"observation","observed_unix_ms":time,"record":{"type":"connection","connection":{"id":"quic-1"}}})).unwrap();}
        let saved:Value=serde_json::from_slice(&fs::read(path.join("connections/quic-1.json")).unwrap()).unwrap();
        assert_eq!(saved["first_observed_unix_ms"],1000);
        j.finish().unwrap();
    }
}
fn message_summary(m:&Value)->Value {
    if !m.is_object(){return Value::Null;}
    let mut v=json!({});
    for key in ["method","target","status","body_bytes","complete","observed_start_unix_ms"] {
        if let Some(x)=m.get(key){v[key]=x.clone();}
    }
    for pair in m["headers"].as_array().into_iter().flatten() {
        match pair[0].as_str().unwrap_or("").to_ascii_lowercase().as_str() {
            ":authority"|"host"=>v["authority"]=pair[1].clone(),
            ":scheme"=>v["scheme"]=pair[1].clone(),
            "content-type"=>v["content_type"]=pair[1].clone(),
            "content-encoding"=>v["content_encoding"]=pair[1].clone(),_=>()
        }
    }
    v
}
pub fn compact(value:&mut Value) {
    if let Some(map)=value.as_object_mut() {
        for key in ["headers","trailers","body_base64","decoded_base64","text","datagrams"] {map.remove(key);}
        for child in map.values_mut(){compact(child);}
    } else if let Some(a)=value.as_array_mut(){for v in a {compact(v);}}
}
pub(crate) fn project(j:&mut Journal,event:&mut Value)->Result<(),String> {
    let typ=event["type"].as_str().unwrap_or("").to_owned();
    let observed=event["observed_unix_ms"].as_u64().unwrap_or_else(crate::recording::observed_ms);
    if typ=="observation" && event["record"]["type"]=="connection" {
        let mut r=event["record"].clone();let id=r["connection"]["id"].as_str().ok_or("missing recorded connection id")?;
        if id.is_empty() || id.len()>128 || !id.bytes().all(|c|c.is_ascii_alphanumeric() || c==b'-' || c==b'_') {return Err("invalid recorded connection id".into());}
        let relative=format!("connections/{id}.json");
        let previous:Value=j.read_working(&relative).ok().and_then(|b|serde_json::from_slice(&b).ok()).unwrap_or(Value::Null);
        r["first_observed_unix_ms"]=first_observed(&previous,observed).into();
        r["format"]="ProxyLaneSession".into();r["version"]=2.into();
        j.working_file(&relative,&serde_json::to_vec_pretty(&r).unwrap())?;
        j.list_snapshot(&r)?;
        event["detail_file"]=relative.into();return Ok(());
    }
    let record=if typ=="observation" {Some(event["record"].clone())} else {None};
    let id=event["cache_id"].as_u64().or_else(||record.as_ref().and_then(|r|r["exchange"]["cache"]["id"].as_u64().or(r["stream"]["cache"]["id"].as_u64())));
    let Some(id)=id else {compact(event);return Ok(());};
    let relative=session_relative(id);
    let mut saved:Value=match j.read_working(&relative) {
        Ok(b)=>serde_json::from_slice(&b).map_err(|e|format!("invalid session snapshot {relative}: {e}"))?,
        Err(e) if e.kind()==std::io::ErrorKind::NotFound=>json!({"format":"ProxyLaneSession","version":2,"cache_id":id,"payloads":{},"first_observed_unix_ms":observed}),
        Err(e)=>return Err(format!("read session snapshot {relative}: {e}")),
    };
    if let Some(r)=record {
        for (key,v) in r.as_object().ok_or("invalid observation")? {saved[key]=v.clone();}
    } else {
        if event["context"]["connection"].is_object(){saved["connection"]=event["context"]["connection"].clone();}
        if event["context"]["protocol"].is_string(){saved["protocol"]=event["context"]["protocol"].clone();}
        if event["context"]["kind"].is_string(){saved["kind"]=event["context"]["kind"].clone();}
        match typ.as_str() {
            "message_head"=>{
                saved["type"]="exchange".into();
                if !saved["exchange"].is_object(){saved["exchange"]=json!({"id":event["exchange_id"],"request":null,"response":null,"informational":[],"cache":{"id":id}});}
                saved["exchange"]["id"]=event["exchange_id"].clone();
                saved["exchange"]["cache"]["id"]=id.into();
                let side=event["side"].as_u64().unwrap_or(0) as usize;
                saved["exchange"][side_name(side)]=event["message"].clone();
            },
            "exchange_end"=>{
                saved["type"]="exchange".into();
                for key in ["request","response","informational","problem"] {saved["exchange"][key]=event[key].clone();}
                saved["exchange"]["id"]=event["exchange_id"].clone();
            },
            "payload_checkpoint"=>{
                saved["cache"]=event["cache"].clone();
                for section in ["exchange","stream"] {if saved[section].is_object(){saved[section]["cache"]=event["cache"].clone();}}
            },
            "body_decode"=>{
                let side=event["side"].as_u64().unwrap_or(0) as usize;
                let mut decode=event.clone();
                for key in ["file","source_file"] {
                    decode[key]=event[key].as_str().filter(|p|j.root.join(p).is_file())
                        .map(|p|Value::String(Path::new(p).file_name().unwrap().to_string_lossy().to_string())).unwrap_or(Value::Null);
                }
                saved["payloads"][side_name(side)]["decode"]=decode;
            },
            "datagram"=>{
                let side=event["side"].as_u64().unwrap_or(0) as usize;
                let name=payload_relative(id,side).replace(".bin",".datagrams.jsonl");
                let line=json!({"side":event["side"],"offset":event["offset"],"length":event["length"],"packet_number":event["packet_number"],"observed_unix_ms":observed});
                let mut bytes=serde_json::to_vec(&line).unwrap();bytes.push(b'\n');j.append_file(&name,&bytes)?;
                saved["payloads"][side_name(side)]["datagrams_file"]=Path::new(&name).file_name().unwrap().to_string_lossy().to_string().into();
            },_=>()
        }
    }
    // Checkpoints belong to the writer and are authoritative about committed
    // bytes. Producer observations may have been queued before those writes.
    if saved["cache"].is_object() {
        let cache=saved["cache"].clone();
        for section in ["exchange","stream"] {
            if saved[section].is_object(){saved[section]["cache"]=cache.clone();}
        }
    }
    saved["first_observed_unix_ms"]=first_observed(&saved,observed).into();
    let protocol=saved["protocol"].as_str().unwrap_or("").to_owned();
    if typ=="payload_checkpoint" && !saved["type"].is_string() && matches!(protocol.as_str(),"tcp"|"udp"|"quic_stream"|"quic_datagram"|"tls_stream"|"tls_encrypted") {
        saved["type"]="stream".into();saved["stream"]=json!({"cache":event["cache"],"datagrams":[[],[]],"packet_counts":[0,0]});
    }
    if typ=="payload_checkpoint" && saved["type"]=="stream" {
        saved["stream"]["sent_bytes"]=event["cache"]["request_bytes"].clone();saved["stream"]["received_bytes"]=event["cache"]["response_bytes"].clone();
        saved["stream"]["finished"]=event["cache"]["finished"].clone();
        saved["stream"]["complete"]=(event["cache"]["finished"]==true && event["cache"]["reason"].is_null()).into();
    }
    if typ=="payload_checkpoint" && saved["type"]=="exchange" {
        for (side,bytes) in [("request","request_bytes"),("response","response_bytes")] {
            if saved["exchange"][side].is_object(){saved["exchange"][side]["body_bytes"]=event["cache"][bytes].clone();}
        }
    }
    for side in 0..2 {
        let key=side_name(side);
        let summary=message_summary(&saved["exchange"][key]);
        if summary.is_object() {
            // Preserve derived target/content fields when later snapshots omit headers.
            for (k,v) in summary.as_object().unwrap(){saved["summary"][key][k]=v.clone();}
        }
        if matches!(protocol.as_str(),"http1"|"h2"|"h3") {strip_headers(j,&mut saved["exchange"][key],id,side,&protocol,"")?;}
        let body=payload_relative(id,side);
        let size=j.payload_size(id,side);
        saved["payloads"][key]["file"]=if size.is_some(){Path::new(&body).file_name().unwrap().to_string_lossy().to_string().into()}else{Value::Null};
        saved["payloads"][key]["bytes"]=size.unwrap_or(0).into();
    }
    if let Some(infos)=saved["exchange"]["informational"].as_array_mut() {
        for (index,m) in infos.iter_mut().enumerate(){strip_headers(j,m,id,1,&protocol,&format!(".info-{index}"))?;}
    }
    saved["observed_unix_ms"]=observed.into();saved["sequence"]=id.into();
    j.working_file(&relative,&serde_json::to_vec_pretty(&saved).unwrap())?;
    j.list_snapshot(&saved)?;
    // A small, useful timeline summary, not a second full header store.
    event["detail_file"]=relative.into();event["summary"]=saved["summary"].clone();
    if saved["connection"].is_object(){event["connection"]=saved["connection"].clone();}
    event["protocol"]=saved["protocol"].clone();
    if typ=="payload_registered" || typ=="payload_checkpoint" {
        event["files"]=json!([saved["payloads"]["request"]["file"].as_str().map(|n|format!("payload/{:06}/{n}",id/1000)),saved["payloads"]["response"]["file"].as_str().map(|n|format!("payload/{:06}/{n}",id/1000))]);
    }
    if typ=="body_decode" {for key in ["file","source_file"] {if event[key].as_str().is_some_and(|p|!j.root.join(p).is_file()){event[key]=Value::Null;}}}
    compact(event);
    Ok(())
}
