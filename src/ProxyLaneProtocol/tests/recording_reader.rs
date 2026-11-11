use proxylane_protocol::{*,cache::{CacheConfig,PayloadCache},recording::{RecordingConfig,payload_relative},recording_reader::Reader,recording_view::session_relative};
use serde_json::{json,Value};
use std::{fs,path::{Path,PathBuf},io::Write};
fn cache()->PayloadCache {
    let root=std::env::temp_dir().join(format!("proxylane-reader-{}-{}",std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    PayloadCache::new(CacheConfig{root,max_entries:2,queue_chunks:2,recording:Some(RecordingConfig{total_bytes:128*1024*1024,min_free_bytes:0}),..Default::default()}).unwrap()
}
fn files(path:&Path)->Vec<(PathBuf,Vec<u8>)>{let mut v=Vec::new();for f in fs::read_dir(path).unwrap(){let p=f.unwrap().path();if p.is_dir(){v.extend(files(&p));}else{v.push((p.clone(),fs::read(p).unwrap()));}}v.sort_by(|a,b|a.0.cmp(&b.0));v}
#[test]
fn paged_readonly_archive_retains_all_sessions_headers_and_decoded_bodies() {
    let c=cache();let path=c.directory().to_owned();
    let mut parser=Analyzer::with_cache(Connection{id:"7".into(),pid:987,process_name:"reader-test.exe".into(),server_name:"original-ip.test".into(),server_port:443,decrypted:true,..Default::default()},Protocol::Http1,Limits::default(),c.clone()).unwrap();
    let mut encoder=flate2::write::GzEncoder::new(Vec::new(),flate2::Compression::fast());encoder.write_all(&vec![42;128*1024]).unwrap();let encoded=encoder.finish().unwrap();
    let mut offsets=[0,0];
    for n in 0..530 {
        let head=format!("GET /item-{n} HTTP/1.1\r\nHost: authority.test\r\nX-Repeat: one\r\nX-Repeat: two\r\n\r\n");
        parser.push(Direction::Client,offsets[0],head.as_bytes());offsets[0]+=head.len() as u64;
        let head=format!("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",encoded.len());
        parser.push(Direction::Server,offsets[1],head.as_bytes());offsets[1]+=head.len() as u64;
        parser.push(Direction::Server,offsets[1],&encoded);offsets[1]+=encoded.len() as u64;
    }
    c.finish_recording().unwrap();assert!(!c.recording_failed(),"{}",c.recording_status());c.shutdown().unwrap();
    assert!(!path.join(payload_relative(1,0)).exists());
    let snapshot:Value=serde_json::from_slice(&fs::read(path.join(session_relative(1))).unwrap()).unwrap();
    assert!(snapshot["payloads"]["request"]["file"].is_null());assert!(snapshot["payloads"]["request"]["decode"]["file"].is_null());
    assert!(snapshot["exchange"]["request"]["headers_file"].is_string());
    let before=files(&path);let mut r=Reader::open(&path).unwrap();
    let mut count=0;let mut ids=std::collections::HashSet::new();
    loop {
        let page=r.query(&json!({"type":"recording_page","offset":count})).unwrap();assert_eq!(page["total"],530);
        let rows=page["records"].as_array().unwrap();if rows.is_empty(){break;}
        for row in rows {assert!(ids.insert(row["cache_id"].as_u64().unwrap()));}
        count+=rows.len();
    }
    assert_eq!(count,530);
    let page=r.query(&json!({"type":"recording_page","filter":"/item-529"})).unwrap();assert_eq!(page["total"],1);
    let detail=r.query(&json!({"type":"recording_detail","run_id":r.run,"cache_id":530})).unwrap();
    assert_eq!(detail["exchange"]["request"]["headers"],json!([["host","authority.test"],["x-repeat","one"],["x-repeat","two"]]));
    let body=r.query(&json!({"type":"cache_decode","run_id":r.run,"cache_id":530,"direction":"server","preview_bytes":100})).unwrap();
    assert_eq!(body["payload"]["decoded_bytes"],128*1024);assert_eq!(body["payload"]["data_base64"].as_str().unwrap().len(),136);
    assert_eq!(r.query(&json!({"type":"recording_page","filter":"987"})).unwrap()["total"],530);
    assert_eq!(before,files(&path),"offline browsing must not modify any recording file");
}
#[test]
fn unfinished_metadata_missing_payload_and_escape_are_explicit() {
    let c=cache();let path=c.directory().to_owned();
    let mut p=Analyzer::with_cache(Connection{id:"8".into(),pid:12,..Default::default()},Protocol::Http1,Limits::default(),c.clone()).unwrap();
    p.push(Direction::Client,0,b"POST /partial HTTP/1.1\r\nHost: local.test\r\nContent-Length: 100\r\n\r\nhello");c.stats().unwrap();c.finish_recording().unwrap();
    // No finished event: the reader must retain an incomplete request without replaying events.
    let mut r=Reader::open(&path).unwrap();assert_eq!(r.query(&json!({"type":"recording_page"})).unwrap()["total"],1);
    let payload=r.query(&json!({"type":"cache_read","run_id":r.run,"cache_id":1,"direction":"client"})).unwrap();assert_eq!(payload["payload"]["data_base64"],"aGVsbG8=");
    assert!(r.query(&json!({"type":"cache_status","run_id":r.run,"cache_id":1})).unwrap()["cache"]["reason"].as_str().unwrap().contains("completion"));
    let relative=session_relative(1);let mut v:Value=serde_json::from_slice(&fs::read(path.join(&relative)).unwrap()).unwrap();
    v["exchange"]["request"]["headers_file"]="../../manifest.json".into();fs::write(path.join(&relative),v.to_string()).unwrap();
    assert!(r.query(&json!({"type":"recording_detail","run_id":r.run,"cache_id":1})).unwrap_err().contains("invalid"));
    fs::remove_file(path.join(payload_relative(1,0))).unwrap();
    assert!(r.query(&json!({"type":"cache_read","run_id":r.run,"cache_id":1,"direction":"client"})).is_err());
    c.shutdown().unwrap();
}
#[test]
fn udp_preview_retains_packet_boundaries_without_reading_entire_payload() {
    let c=cache();let connection=json!({"id":"9","pid":77,"transport":"udp","destination":"1.2.3.4:444"});
    let scoped=c.scoped(json!({"connection":connection,"protocol":"udp"}));let stream=scoped.stream();
    for (n,bytes) in [b"one".as_slice(),b"",b"last"].iter().enumerate() {
        let offset=if n==0{0}else{3};stream.append_stream(Direction::Client,bytes);
        stream.record(json!({"type":"datagram","side":0,"offset":offset,"length":bytes.len(),"packet_number":n+1}));
    }
    stream.finish_stream([7,0],true);c.finish_recording().unwrap();let path=c.directory().to_owned();c.shutdown().unwrap();
    let mut r=Reader::open(&path).unwrap();assert_eq!(r.query(&json!({"type":"recording_page"})).unwrap()["total"],1);
    let detail=r.query(&json!({"type":"recording_detail","run_id":r.run,"cache_id":stream.id(),"preview_bytes":4})).unwrap();
    assert_eq!(detail["stream"]["datagrams"][0],json!([[0,3],[3,0],[3,4]]));
}
#[test]
fn format_version_is_independent_of_product_version_and_event_tail() {
    let c=cache();let path=c.directory().to_owned();
    c.record(json!({"type":"observation","record":{"type":"connection","protocol":"h2","connection":{"id":"45","pid":4},"status":"Established"}}));
    c.finish_recording().unwrap();c.shutdown().unwrap();
    let manifest=path.join("manifest.json");let mut v:Value=serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    assert_eq!(v["version"],2);assert_eq!(v["producer"]["name"],"ProxyLane");assert!(v["producer"]["version"].as_str().unwrap().starts_with("1."));
    v["producer"]["version"]="99.0.0".into();v["status"]="recording".into();fs::write(&manifest,v.to_string()).unwrap();
    std::fs::OpenOptions::new().append(true).open(path.join("events-000001.jsonl")).unwrap().write_all(b"{\"interrupted").unwrap();
    let mut r=Reader::open(&path).unwrap();let page=r.query(&json!({"type":"recording_page"})).unwrap();
    assert_eq!(page["total"],1);assert_eq!(page["records"][0]["status"],"Established");
    for version in [1,3] {
        v["version"]=version.into();fs::write(&manifest,v.to_string()).unwrap();
        assert!(Reader::open(&path).err().unwrap().contains("format version 2"));
    }
}
#[test]
fn http3_progress_is_one_session_and_pseudo_headers_are_reconstructed() {
    let c=cache();
    let connection=Connection{id:((1u64<<63)+29).to_string(),pid:33,transport:"udp".into(),decrypted:true,..Default::default()};
    assert_eq!(json!(connection)["id"],"quic-29");
    assert_eq!(json!(Connection{id:"188".into(),..Default::default()})["id"],"188");
    assert_eq!(connection.id,((1u64<<63)+29).to_string()); // Internal identity unchanged.
    c.record(json!({"type":"observation","record":{"type":"connection","protocol":"h3","connection":connection,"status":"Established"}}));
    let scoped=c.scoped(json!({"protocol":"h3","connection":connection}));
    let mut capture=http3::Capture::new(0,Some(&scoped));
    let mut request=Message::default();request.method=Some("GET".into());request.target=Some("/h3".into());
    request.headers=vec![(":method".into(),"GET".into()),(":authority".into(),"h3.test".into())];
    capture.head(0,request);capture.end(0,vec![]);
    let mut response=Message::default();response.status=Some(200);capture.head(1,response);
    capture.data(1,b"http3 body");capture.end(1,vec![]);let exchange=capture.finish("done");
    let id=exchange.cache.as_ref().unwrap().id();
    for n in 1..5 { c.record(json!({"type":"observation","record":{"type":"exchange","sequence":n,"protocol":"h3","connection":connection,"exchange":exchange}})); }
    c.finish_recording().unwrap();let mut r=Reader::open(c.directory()).unwrap();c.shutdown().unwrap();
    let page=r.query(&json!({"type":"recording_page"})).unwrap();assert_eq!(page["total"],1);
    let root=c.directory();
    assert!(root.join("connections/quic-29.json").is_file());
    assert!(!fs::read_to_string(root.join("events-000001.jsonl")).unwrap().contains(&connection.id));
    assert_eq!(page["records"][0]["connection"]["id"],"quic-29");
    assert_eq!(r.query(&json!({"type":"recording_detail","run_id":r.run,"connection_id":"quic-29"})).unwrap()["connection"]["id"],"quic-29");
    assert_eq!(page["records"][0]["summary"]["request"]["authority"],"h3.test");
    assert_eq!(r.query(&json!({"type":"recording_page","protocol":2})).unwrap()["total"],0);
    assert_eq!(r.query(&json!({"type":"recording_page","filter":"3"})).unwrap()["total"],0);
    assert_eq!(r.query(&json!({"type":"recording_page","filter":"33"})).unwrap()["total"],1);
    let detail=r.query(&json!({"type":"recording_detail","run_id":r.run,"cache_id":id})).unwrap();
    assert_eq!(detail["exchange"]["request"]["headers"][1],json!([":authority","h3.test"]));
    let payload=r.query(&json!({"type":"cache_decode","run_id":r.run,"cache_id":id,"direction":"server"})).unwrap();
    assert_eq!(payload["payload"]["data_base64"],"aHR0cDMgYm9keQ==");
}

#[test]
fn index_only_open_filter_and_scroll_do_not_touch_detail_files() {
    let c=cache();let path=c.directory().to_owned();
    let mut p=Analyzer::with_cache(Connection{id:"139".into(),pid:42,server_name:"mail.test".into(),..Default::default()},Protocol::Http1,Limits::default(),c.clone()).unwrap();
    p.push(Direction::Client,0,b"GET /mail HTTP/1.1\r\nHost: mail.test\r\n\r\n");
    p.push(Direction::Server,0,b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
    c.finish_recording().unwrap();c.shutdown().unwrap();
    // Renaming ALL details and event files proves no fallback scan is hidden in opening/filtering.
    fs::rename(path.join("payload"),path.join("details-hidden")).unwrap();
    fs::rename(path.join("events-000001.jsonl"),path.join("events-hidden")).unwrap();
    let mut reader=Reader::open(&path).unwrap();
    for filter in ["","mail.test","42"] {
        let page=reader.query(&json!({"type":"recording_page","filter":filter})).unwrap();
        assert_eq!(page["total"],1);assert_eq!(page["records"][0]["exchange"]["response"]["body_bytes"],5);
    }
    assert!(reader.query(&json!({"type":"recording_detail","run_id":reader.run,"cache_id":1})).is_err());
    fs::rename(path.join("details-hidden"),path.join("payload")).unwrap();
    assert_eq!(reader.query(&json!({"type":"recording_detail","run_id":reader.run,"cache_id":1})).unwrap()["exchange"]["response"]["status"],200);
}

#[test]
fn index_damage_requires_explicit_rebuild_and_preserves_originals() {
    use proxylane_protocol::recording_index::{NAME,REQUIRED};
    let c=cache();let path=c.directory().to_owned();
    c.record(json!({"type":"observation","record":{"type":"connection","protocol":"h3","connection":{"id":"quic-29","pid":4},"status":"Closed"}}));
    c.finish_recording().unwrap();c.shutdown().unwrap();
    let pristine=fs::read(path.join(NAME)).unwrap();
    for mode in 0..4 {
        fs::write(path.join(NAME),&pristine).unwrap();
        match mode {
            0=>fs::remove_file(path.join(NAME)).unwrap(),
            1=>{let mut b=pristine.clone();b.truncate(b.len()-10);fs::write(path.join(NAME),b).unwrap();},
            2=>{let b=String::from_utf8(pristine.clone()).unwrap().replace("Closed","Failed");fs::write(path.join(NAME),b).unwrap();},
            _=>{let mut b=pristine.clone();b.extend_from_slice(b"garbage\n");fs::write(path.join(NAME),b).unwrap();}
        }
        let before=files(&path);
        assert!(Reader::open(&path).err().unwrap().starts_with(REQUIRED));
        assert_eq!(files(&path),before,"opening never rebuilds or rewrites anything");
        let mut r=Reader::rebuild(&path).unwrap();let page=r.query(&json!({"type":"recording_page"})).unwrap();
        assert_eq!(page["total"],1);assert_eq!(page["records"][0]["connection"]["id"],"quic-29");
        let originals=|v:Vec<(PathBuf,Vec<u8>)>|v.into_iter().filter(|(p,_)|p.file_name().unwrap()!=NAME).collect::<Vec<_>>();
        assert_eq!(originals(before),originals(files(&path)));
    }
    // A bad source snapshot must not replace an existing index with a partial reconstruction.
    let before=fs::read(path.join(NAME)).unwrap();fs::write(path.join("connections/quic-29.json"),b"{").unwrap();
    assert!(Reader::rebuild(&path).is_err());assert_eq!(fs::read(path.join(NAME)).unwrap(),before);
}

#[test]
fn index_rebuild_rejects_active_owner() {
    let c=cache();assert!(Reader::rebuild(c.directory()).err().unwrap().contains("still in use"));
    c.finish_recording().unwrap();
    // A stopped recording can be repaired without exiting the proxy or its read-only cache.
    fs::remove_file(c.directory().join(recording_index::NAME)).unwrap();
    Reader::rebuild(c.directory()).unwrap();c.shutdown().unwrap();
}

#[test]
#[ignore = "spawned by abrupt_exit_index_recovery"]
fn index_crash_child() {
    let root=PathBuf::from(std::env::var_os("PROXYLANE_INDEX_CRASH_ROOT").unwrap());
    let c=PayloadCache::new(CacheConfig{root:root.clone(),recording:Some(RecordingConfig{total_bytes:16*1024*1024,min_free_bytes:0}),..Default::default()}).unwrap();
    let mut p=Analyzer::with_cache(Connection{id:"crash".into(),pid:123,..Default::default()},Protocol::Http1,Limits::default(),c.clone()).unwrap();
    p.push(Direction::Client,0,b"POST /unfinished HTTP/1.1\r\nHost: crash.test\r\nContent-Length: 100\r\n\r\nhello");
    c.stats().unwrap();
    // The cache syncs dirty snapshots once per second; Stats is only a queue barrier.
    let start=std::time::Instant::now();loop {
        let v:Value=fs::read(c.directory().join(session_relative(1))).ok().and_then(|b|serde_json::from_slice(&b).ok()).unwrap_or(Value::Null);
        if v["payloads"]["request"]["bytes"]==5 {break;}
        assert!(start.elapsed().as_secs()<10);std::thread::sleep(std::time::Duration::from_millis(20));
    }
    fs::write(root.join("ready"),c.directory().to_string_lossy().as_bytes()).unwrap();
    loop {std::thread::sleep(std::time::Duration::from_secs(1));}
}

#[test]
fn abrupt_exit_index_recovery() {
    let root=std::env::temp_dir().join(format!("proxylane-crash-index-{}-{}",std::process::id(),recording::now_ms()));fs::create_dir_all(&root).unwrap();
    let mut child=std::process::Command::new(std::env::current_exe().unwrap()).args(["--exact","index_crash_child","--ignored","--nocapture"])
        .env("PROXYLANE_INDEX_CRASH_ROOT",&root).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().unwrap();
    let start=std::time::Instant::now();while !root.join("ready").exists() && start.elapsed().as_secs()<30 {std::thread::sleep(std::time::Duration::from_millis(20));}
    child.kill().unwrap();child.wait().unwrap();
    let path=PathBuf::from(fs::read_to_string(root.join("ready")).expect("child produced a flushed checkpoint"));
    assert!(Reader::open(&path).err().unwrap().starts_with(recording_index::REQUIRED));
    let mut r=Reader::rebuild(&path).unwrap();assert_eq!(r.query(&json!({"type":"recording_page"})).unwrap()["total"],1);
    let body=r.query(&json!({"type":"cache_read","run_id":r.run,"cache_id":1,"direction":"client"})).unwrap();
    assert_eq!(body["payload"]["data_base64"],"aGVsbG8=");
    assert!(r.query(&json!({"type":"cache_status","run_id":r.run,"cache_id":1})).unwrap()["cache"]["reason"].is_string());
}

#[test]
fn large_index_latest_rows_filter_without_any_session_json() {
    use proxylane_protocol::recording_index as ix;
    let root=std::env::temp_dir().join(format!("proxylane-large-index-{}-{}",std::process::id(),recording::now_ms()));fs::create_dir_all(&root).unwrap();
    fs::write(root.join("manifest.json"),json!({"format":"ProxyLaneRecording","version":2,"status":"completed"}).to_string()).unwrap();
    let mut file=std::io::BufWriter::new(fs::File::create(root.join(ix::NAME)).unwrap());let mut seq=0;
    file.write_all(&ix::line(seq,json!({"format":"ProxyLaneListIndex","version":1})).unwrap()).unwrap();seq+=1;
    for pass in 0..2 {for id in 1..=100_000u64 {
        let value=json!({"format":"ProxyLaneSession","version":2,"type":"exchange","cache_id":id,"first_observed_unix_ms":id,"protocol":"h3",
            "connection":{"id":format!("quic-{}",id/50),"pid":id%10},"exchange":{"id":id,"cache":{"id":id},"request":{"method":"GET","target":format!("/item-{id}")},"response":{"status":if pass==0{100}else{200},"body_bytes":id}}});
        file.write_all(&ix::line(seq,value).unwrap()).unwrap();seq+=1;
    }}
    file.write_all(&ix::line(seq,json!({"end":seq})).unwrap()).unwrap();file.flush().unwrap();drop(file);
    let start=std::time::Instant::now();let mut r=Reader::open(&root).unwrap();let opened=start.elapsed();
    let page=r.query(&json!({"type":"recording_page","offset":99_990})).unwrap();assert_eq!(page["total"],100_000);assert_eq!(page["records"][0]["cache_id"],99_991);assert_eq!(page["records"][0]["exchange"]["response"]["status"],200);
    assert_eq!(r.query(&json!({"type":"recording_page","filter":"7"})).unwrap()["total"],10_000);
    println!("100000 sessions / 200000 updates: open {:?}, total with filter {:?}, index {} bytes",opened,start.elapsed(),fs::metadata(root.join(ix::NAME)).unwrap().len());
}
