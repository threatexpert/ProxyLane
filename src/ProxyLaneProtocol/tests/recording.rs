use proxylane_protocol::{*,cache::{CacheConfig,PayloadCache},recording::{RecordingConfig,payload_relative}};
use serde_json::Value;
use std::{fs,io::Write,path::{Path,PathBuf},process::{Command,Stdio},time::{Duration,Instant,SystemTime,UNIX_EPOCH}};

fn root()->PathBuf {std::env::temp_dir().join(format!("proxylane-recording-test-{}-{}",std::process::id(),SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()))}
#[test]
fn recording_has_data_distinguishes_empty_run_headers_and_raw_payload() {
    for mode in 0..3 {
        let cache=PayloadCache::new(config(root(),64*1024*1024)).unwrap();
        assert_eq!(cache.recording_status()["has_data"],false);
        if mode==1 {
            let mut parser=Analyzer::with_cache(Connection::default(),Protocol::Http1,Limits::default(),cache.clone()).unwrap();
            parser.push(Direction::Client,0,b"GET / HTTP/1.1\r\nHost: test\r\n\r\n");
            parser.push(Direction::Server,0,b"HTTP/1.1 204 No Content\r\n\r\n");
        } else {
            let stream=cache.stream(); // An empty allocated cache is not captured data.
            if mode==2 {stream.append_stream(Direction::Client,b"raw payload");}
            stream.finish_stream([if mode==2 {11}else{0},0],true);
        }
        cache.finish_recording().unwrap();
        let status=cache.recording_status();
        assert_eq!(status["ended"],true);assert_eq!(status["has_data"],mode!=0);
        let manifest:Value=serde_json::from_slice(&fs::read(cache.directory().join("manifest.json")).unwrap()).unwrap();
        assert_eq!(manifest["has_data"],mode!=0);
        cache.shutdown().unwrap();
    }
}
#[test]
fn recording_start_error_identifies_unusable_directory_and_preserves_existing_file() {
    let base=root();fs::create_dir_all(&base).unwrap();
    let blocker=base.join("not-a-directory");fs::write(&blocker,b"existing file").unwrap();
    for location in [blocker.clone(),blocker.join("Recordings")] {
        let error=match PayloadCache::new(config(location.clone(),64*1024*1024)) {
            Ok(_)=>panic!("recording must not start on an unusable path"),Err(e)=>e,
        };
        let value:Value=serde_json::from_str(&error).unwrap();
        assert_eq!(value["error"],"recording_directory_error");
        assert_eq!(value["path"],location.to_string_lossy().as_ref());
        assert!(value["detail"].as_str().unwrap().contains("directory"));
        assert_eq!(fs::read(&blocker).unwrap(),b"existing file");
    }
    fs::remove_file(blocker).unwrap();fs::remove_dir(base).unwrap();
}
#[test]
fn recording_start_disk_reserve_failure_is_not_reported_as_invalid_path() {
    let location=root();let mut cfg=config(location.clone(),64*1024*1024);
    cfg.recording.as_mut().unwrap().min_free_bytes=u64::MAX-1024*1024;
    let error=match PayloadCache::new(cfg) {Ok(_)=>panic!("reserve must prevent recording"),Err(e)=>e};
    let value:Value=serde_json::from_str(&error).unwrap();
    assert_eq!(value["error"],"recording_initialize_error");
    assert_eq!(value["path"],location.to_string_lossy().as_ref());
    assert_eq!(value["detail"],"recording disk reserve reached");
}
#[test]
fn one_resident_exchange_reconstructs_http1_pipeline_and_interleaved_http2() {
    for protocol in [Protocol::Http1,Protocol::H2] {
        let mut cfg=config(root(),64*1024*1024);cfg.queue_chunks=2;cfg.max_entries=2;
        let cache=PayloadCache::new(cfg).unwrap();let path=cache.directory().to_owned();
        let mut parser=Analyzer::with_cache(Connection::default(),protocol,Limits{pending:1,..Default::default()},cache.clone()).unwrap();
        let frame=|kind:u8,flags:u8,id:u32,bytes:&[u8]| {
            let mut f=(bytes.len() as u32).to_be_bytes()[1..].to_vec();f.extend([kind,flags]);f.extend(id.to_be_bytes());f.extend(bytes);f
        };
        let mut offsets=[0u64;2];let mut completed=0;
        let mut feed=|side:usize,bytes:&[u8]| {
            for out in parser.push(if side==0 {Direction::Client}else{Direction::Server},offsets[side],bytes) {
                match out {Output::Exchange{exchange,..}=>{assert!(exchange.request.as_ref().unwrap().complete);assert!(exchange.response.as_ref().unwrap().complete);completed+=1;},
                    Output::Diagnostic{detail,..}=>panic!("{detail}")}
            }
            offsets[side]+=bytes.len() as u64;
        };
        if protocol==Protocol::H2 {feed(0,b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");}
        for i in 0..32u32 {
            if protocol==Protocol::H2 {feed(0,&frame(1,5,i*2+1,&[0x82,0x87,0x84]));}
            else {feed(0,format!("GET /{i} HTTP/1.1\r\nHost: test\r\n\r\n").as_bytes());}
        }
        if protocol==Protocol::H2 {
            for i in (0..32u32).rev() {feed(1,&frame(1,4,i*2+1,&[0x88]));}
            for part in 0..16 {
                for i in (0..32u32).rev() {feed(1,&frame(0,if part==15 {1}else{0},i*2+1,&vec![i as u8;16384]));}
            }
        } else {
            for i in 0..32u32 {
                feed(1,b"HTTP/1.1 200 OK\r\nContent-Length: 262144\r\n\r\n");
                for _ in 0..16 {feed(1,&vec![i as u8;16384]);}
            }
        }
        drop(feed);assert_eq!(completed,32);assert!(!cache.recording_failed());
        cache.finish_recording().unwrap();
        let ends:Vec<_>=events(&path).into_iter().filter(|v|v["type"]=="exchange_end").collect();
        assert_eq!(ends.len(),32);
        for e in ends {
            let id=e["exchange_id"].as_u64().unwrap();
            let tag=if protocol==Protocol::H2 {(id-1)/2}else{id-1};
            let saved=fs::read(path.join(payload_relative(e["cache_id"].as_u64().unwrap(),1))).unwrap();
            assert_eq!(saved,vec![tag as u8;262144]);
        }
        assert_eq!(cache.recording_status()["quality"]["gap_count"],0);
        cache.shutdown().unwrap();
    }
}
#[test]
fn active_entry_limit_pages_metadata_without_losing_payloads() {
    let mut cfg=config(root(),8*1024*1024);cfg.max_entries=1;
    let cache=PayloadCache::new(cfg).unwrap();let path=cache.directory().to_owned();
    assert_eq!(path.file_name().unwrap().to_str().unwrap().rsplit('-').next().unwrap().len(),16);
    let kept=cache.stream();kept.append_stream(Direction::Client,b"first");cache.stats().unwrap();
    let missed=cache.stream();cache.stats().unwrap();assert!(missed.snapshot().reason.is_none());
    missed.append_stream(Direction::Client,b"second");
    assert!(!cache.recording_failed());
    kept.append_stream(Direction::Client,b" still recorded");kept.finish_stream([20,0],true);cache.stats().unwrap();
    let later=cache.stream();later.append_stream(Direction::Client,b"new payload");later.finish_stream([11,0],true);
    cache.stats().unwrap();cache.finish_recording().unwrap();cache.shutdown().unwrap();
    assert_eq!(fs::read(path.join(payload_relative(kept.id(),0))).unwrap(),b"first still recorded");
    assert_eq!(fs::read(path.join(payload_relative(later.id(),0))).unwrap(),b"new payload");
    let manifest:Value=serde_json::from_slice(&fs::read(path.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["status"],"completed");assert_eq!(manifest["quality"]["gap_count"],0);
    assert_eq!(manifest["quality"]["capture_incomplete"],false);
    assert_eq!(fs::read(path.join(payload_relative(missed.id(),0))).unwrap(),b"second");
}
fn config(root:PathBuf,total:u64)->CacheConfig {CacheConfig {root,entry_bytes:4,total_bytes:8,max_entries:2,queue_chunks:1024,
    recording:Some(RecordingConfig {total_bytes:total,min_free_bytes:0}),..Default::default()}}
fn events(path:&Path)->Vec<Value> {
    let mut files:Vec<_>=fs::read_dir(path).unwrap().map(|e|e.unwrap().path()).filter(|p|p.extension().is_some_and(|x|x=="jsonl") && p.file_name().unwrap().to_string_lossy().starts_with("events-")).collect();files.sort();
    files.into_iter().flat_map(|p|fs::read_to_string(p).unwrap().lines().map(|l|serde_json::from_str(l).unwrap()).collect::<Vec<Value>>()).collect()
}
fn size(path:&Path)->u64 {fs::read_dir(path).unwrap().map(|e|{let e=e.unwrap();if e.file_type().unwrap().is_dir(){size(&e.path())}else{e.metadata().unwrap().len()}}).sum()}

#[test]
fn headers_and_payload_survive_shutdown_and_ram_retirement() {
    let root=root();let cache=PayloadCache::new(config(root.clone(),8*1024*1024)).unwrap();let path=cache.directory().to_owned();
    assert!(path.join("manifest.json").exists());
    let mut parser=Analyzer::with_cache(Connection {id:"c1".into(),pid:123,process_start:456,process_name:"test.exe".into(),..Default::default()},Protocol::Http1,Limits::default(),cache.clone()).unwrap();
    let mut offsets=[0,0];
    for i in 0..8 {
        let request=format!("GET /{i} HTTP/1.1\r\nHost: test\r\nX-Repeat: first\r\nX-Repeat: second\r\n\r\n");
        parser.push(Direction::Client,offsets[0],request.as_bytes());offsets[0]+=request.len() as u64;
        let response=b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        parser.push(Direction::Server,offsets[1],response);offsets[1]+=response.len() as u64;
        cache.stats().unwrap();
    }
    assert_eq!(cache.stats().unwrap().evicted_entries,0);
    assert_eq!(cache.read(1,Direction::Server,0,5).unwrap().data_base64,b"hello");
    cache.finish_recording().unwrap();let before=size(&path);
    for id in 1..=8 {assert_eq!(cache.read(id,Direction::Server,0,5).unwrap().data_base64,b"hello");}
    assert_eq!(size(&path),before,"reading retired entries must not modify a finished recording");
    cache.shutdown().unwrap();
    let lines=events(&path);assert_eq!(lines.iter().filter(|v|v["type"]=="exchange_end").count(),8);
    let first=lines.iter().find(|v|v["type"]=="message_head").unwrap();
    assert_eq!(first["context"]["connection"]["pid"],123);
    assert!(first["message"].get("headers").is_none());
    let snapshot:Value=serde_json::from_slice(&fs::read(path.join(first["detail_file"].as_str().unwrap())).unwrap()).unwrap();
    let headers=fs::read_to_string(path.join("payload/000000").join(snapshot["exchange"]["request"]["headers_file"].as_str().unwrap())).unwrap();
    assert!(headers.contains("X-Repeat: first\r\nX-Repeat: second") || headers.contains("x-repeat: first\r\nx-repeat: second"));
    for id in 1..=8 {assert_eq!(fs::read(path.join(payload_relative(id,1))).unwrap(),b"hello");}
    let manifest:Value=serde_json::from_slice(&fs::read(path.join("manifest.json")).unwrap()).unwrap();assert_eq!(manifest["status"],"completed");
    // Starting temporary-cache cleanup in the same parent must never remove an archive.
    let temporary=PayloadCache::new(CacheConfig {root,..Default::default()}).unwrap();temporary.shutdown().unwrap();assert!(path.exists());
}

#[test]
fn total_limit_stops_without_eviction_or_late_writes() {
    let cache=PayloadCache::new(config(root(),256*1024)).unwrap();let path=cache.directory().to_owned();
    let first=cache.stream();first.append_stream(Direction::Server,b"keep me");first.finish_stream([0,7],true);cache.stats().unwrap();
    let ongoing=cache.stream();
    for _ in 0..128 {ongoing.append_stream(Direction::Server,&vec![42;16384]);cache.stats().unwrap();if cache.recording_failed(){break;}}
    assert!(cache.recording_failed());assert!(cache.recording_status()["reason"].as_str().unwrap().contains("capacity"));
    let before=cache.stats().unwrap().used_bytes;ongoing.append_stream(Direction::Server,b"must not be saved");assert_eq!(cache.stats().unwrap().used_bytes,before);
    cache.finish_recording().unwrap();cache.shutdown().unwrap();
    assert_eq!(fs::read(path.join(payload_relative(first.id(),1))).unwrap(),b"keep me");
    assert!(size(&path)<=256*1024);
    let manifest:Value=serde_json::from_slice(&fs::read(path.join("manifest.json")).unwrap()).unwrap();assert_eq!(manifest["status"],"stopped");
    assert_eq!(manifest["last_sequence"],events(&path).last().unwrap()["sequence"]);
}

#[test]
fn disk_reserve_is_checked_before_start() {
    let root=root();fs::create_dir_all(&root).unwrap();
    let mut c=config(root.clone(),1024*1024);c.recording.as_mut().unwrap().min_free_bytes=u64::MAX;
    assert!(PayloadCache::new(c).err().unwrap().contains("disk reserve"));
}

#[test]
fn http2_multiplexing_records_ongoing_headers_and_separate_bodies() {
    fn frame(kind:u8,flags:u8,id:u32,payload:&[u8])->Vec<u8> {
        let mut data=(payload.len() as u32).to_be_bytes()[1..].to_vec();
        data.extend([kind,flags]);data.extend(id.to_be_bytes());data.extend(payload);data
    }
    let cache=PayloadCache::new(config(root(),8*1024*1024)).unwrap();let path=cache.directory().to_owned();
    let mut a=Analyzer::with_cache(Connection{id:"h2".into(),..Default::default()},Protocol::H2,Limits::default(),cache.clone()).unwrap();
    let mut client=b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    client.extend(frame(1,5,1,&[0x82,0x87,0x84]));client.extend(frame(1,5,3,&[0x82,0x87,0x84]));
    a.push(Direction::Client,0,&client);
    let mut server=frame(1,4,3,&[0x88]);server.extend(frame(0,0,3,b"ongoing"));
    server.extend(frame(1,4,1,&[0x88]));server.extend(frame(0,1,1,b"complete"));
    a.push(Direction::Server,0,&server);cache.stats().unwrap();cache.finish_recording().unwrap();
    let rows=events(&path);let headers:Vec<_>=rows.iter().filter(|v|v["type"]=="message_head").collect();
    assert_eq!(headers.len(),4);
    for (stream,body) in [(1,b"complete".as_slice()),(3,b"ongoing".as_slice())] {
        let h=headers.iter().find(|v|v["exchange_id"]==stream && v["side"]==1).unwrap();
        assert_eq!(fs::read(path.join(payload_relative(h["cache_id"].as_u64().unwrap(),1))).unwrap(),body);
    }
    let before=size(&path);a.push(Direction::Server,server.len() as u64,&frame(0,1,3,b"late"));cache.stats().unwrap();
    assert_eq!(size(&path),before,"finished recording must reject late payloads and metadata");
    cache.shutdown().unwrap();
}

#[test]
fn payload_write_failure_stops_capture_and_keeps_manifest() {
    let cache=PayloadCache::new(config(root(),1024*1024)).unwrap();let path=cache.directory().to_owned();
    let payload=cache.stream();cache.stats().unwrap();
    fs::create_dir_all(path.join(payload_relative(payload.id(),1))).unwrap();
    payload.append_stream(Direction::Server,b"write must fail");cache.stats().unwrap();
    assert!(cache.recording_failed());assert!(cache.recording_status()["reason"].as_str().unwrap().contains("write failed"));
    cache.finish_recording().unwrap();cache.shutdown().unwrap();assert!(path.join("manifest.json").exists());
}

#[test]
fn simultaneous_instances_keep_distinct_archives() {
    let root=root();let a=PayloadCache::new(config(root.clone(),1024*1024)).unwrap();let b=PayloadCache::new(config(root,1024*1024)).unwrap();
    assert_ne!(a.directory(),b.directory());
    let first=a.stream();first.append_stream(Direction::Client,b"first");a.stats().unwrap();
    let second=b.stream();second.append_stream(Direction::Client,b"second");b.stats().unwrap();
    let paths=[a.directory().to_owned(),b.directory().to_owned()];a.shutdown().unwrap();b.shutdown().unwrap();
    assert_eq!(fs::read(paths[0].join(payload_relative(1,0))).unwrap(),b"first");
    assert_eq!(fs::read(paths[1].join(payload_relative(1,0))).unwrap(),b"second");
}

#[test]
fn crash_child() {
    let Some(root)=std::env::var_os("PROXYLANE_RECORDING_CRASH_CHILD") else{return;};
    let cache=PayloadCache::new(config(root.into(),16*1024*1024)).unwrap();
    let mut parser=Analyzer::with_cache(Connection {id:"crash-connection".into(),pid:987,..Default::default()},Protocol::Http1,Limits::default(),cache.clone()).unwrap();
    parser.push(Direction::Client,0,b"GET /still-downloading HTTP/1.1\r\nHost: crash.test\r\n\r\n");
    parser.push(Direction::Server,0,b"HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\nalready persisted");
    cache.stats().unwrap();std::thread::sleep(Duration::from_millis(1300));
    println!("READY {}",cache.directory().display());std::io::stdout().flush().unwrap();
    loop {std::thread::sleep(Duration::from_secs(60));}
}

#[test]
fn forced_process_exit_keeps_in_progress_headers_and_body() {
    use std::io::{BufRead,BufReader};
    let root=root();let mut child=Command::new(std::env::current_exe().unwrap()).args(["--exact","crash_child","--nocapture"])
        .env("PROXYLANE_RECORDING_CRASH_CHILD",&root).stdout(Stdio::piped()).spawn().unwrap();
    let mut reader=BufReader::new(child.stdout.take().unwrap());let start=Instant::now();
    loop {let mut line=String::new();assert!(reader.read_line(&mut line).unwrap()>0);if line.contains("READY "){break;}assert!(start.elapsed()<Duration::from_secs(30));}
    child.kill().unwrap();child.wait().unwrap();
    let path=fs::read_dir(&root).unwrap().map(|e|e.unwrap().path()).find(|p|p.is_dir()).unwrap();
    let manifest:Value=serde_json::from_slice(&fs::read(path.join("manifest.json")).unwrap()).unwrap();assert_eq!(manifest["status"],"recording");
    let lines=events(&path);assert!(lines.iter().any(|v|v["type"]=="message_head" && v["message"]["target"]=="/still-downloading"));
    assert!(lines.iter().any(|v|v["type"]=="payload_checkpoint"));
    assert!(!lines.iter().any(|v|v["type"]=="exchange_end"));
    assert_eq!(fs::read(path.join(payload_relative(1,1))).unwrap(),b"already persisted");
    assert!(proxylane_protocol::recording_reader::Reader::open(&path).err().unwrap().starts_with(recording_index::REQUIRED));
    let mut view=proxylane_protocol::recording_reader::Reader::rebuild(&path).unwrap();
    let page=view.query(&serde_json::json!({"type":"recording_page"})).unwrap();
    assert_eq!(page["total"],1);assert_eq!(page["records"][0]["exchange"]["request"]["target"],"/still-downloading");
    let detail=view.query(&serde_json::json!({"type":"recording_detail","run_id":view.run,"cache_id":1})).unwrap();
    assert_eq!(detail["exchange"]["request"]["headers"][0],serde_json::json!(["host","crash.test"]));
    let payload=view.query(&serde_json::json!({"type":"cache_read","run_id":view.run,"cache_id":1,"direction":"server"})).unwrap();
    assert_eq!(payload["payload"]["data_base64"],"YWxyZWFkeSBwZXJzaXN0ZWQ=");
    let another=PayloadCache::new(config(root,1024*1024)).unwrap();assert_ne!(another.directory(),path);another.shutdown().unwrap();assert!(path.exists());
}
