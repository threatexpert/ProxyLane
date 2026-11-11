use proxylane_protocol::{*,cache::{CacheConfig,PayloadCache},recording::{RecordingConfig,payload_relative}};
use serde_json::Value;
use std::{fs,io::Write,path::{Path,PathBuf},time::{SystemTime,UNIX_EPOCH}};
fn root()->PathBuf {std::env::temp_dir().join(format!("proxylane-decoded-{}-{}",std::process::id(),SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()))}
fn cache(capacity:u64)->PayloadCache {
    PayloadCache::new(CacheConfig {root:root(),queue_chunks:2,max_entries:2,decode_bytes:1024,decode_input_bytes:1024,
        recording:Some(RecordingConfig {total_bytes:capacity,min_free_bytes:0}),..Default::default()}).unwrap()
}
fn encode(name:&str,body:&[u8])->Vec<u8> {
    match name {
        "gzip"|"x-gzip" => {let mut w=flate2::write::GzEncoder::new(Vec::new(),flate2::Compression::fast());w.write_all(body).unwrap();w.finish().unwrap()},
        "deflate" => {let mut w=flate2::write::ZlibEncoder::new(Vec::new(),flate2::Compression::fast());w.write_all(body).unwrap();w.finish().unwrap()},
        "raw" => {let mut w=flate2::write::DeflateEncoder::new(Vec::new(),flate2::Compression::fast());w.write_all(body).unwrap();w.finish().unwrap()},
        "br" => {let mut out=Vec::new();{let mut w=brotli::CompressorWriter::new(&mut out,16384,3,22);w.write_all(body).unwrap();}out},
        "zstd" => zstd::stream::encode_all(body,1).unwrap(),
        _=>panic!(),
    }
}
fn feed(cache:&PayloadCache,encoding:&str,encoded:&[u8],complete:bool)->u64 {
    let mut a=Analyzer::with_cache(Connection::default(),Protocol::Http1,Limits::default(),cache.clone()).unwrap();
    a.push(Direction::Client,0,b"GET /payload HTTP/1.1\r\nHost: test\r\n\r\n");
    let head=format!("HTTP/1.1 200 OK\r\nContent-Encoding: {encoding}\r\nContent-Length: {}\r\n\r\n",encoded.len()+usize::from(!complete));
    let mut offset=head.len() as u64;a.push(Direction::Server,0,head.as_bytes());
    let mut out=Vec::new();
    for b in encoded.chunks(16384) {out.extend(a.push(Direction::Server,offset,b));offset+=b.len() as u64;}
    out.extend(a.close_with_reason("monitoring stopped"));
    let id=out.into_iter().find_map(|v|match v {Output::Exchange{exchange,..}=>exchange.cache.map(|c|c.id()),_=>None}).unwrap();
    cache.stats().unwrap();id
}
fn state(path:&Path,id:u64)->Value {
    { let mut value=proxylane_protocol::recording_view::decode_metadata(path,id,1).unwrap();
      for key in ["file","source_file"] { if let Some(name)=value[key].as_str() {value[key]=format!("payload/{:06}/{name}",id/1000).into();} } value }
}
#[test]
fn all_encodings_and_layers_are_fully_recorded_beyond_preview_limits() {
    let c=cache(256*1024*1024);let path=c.directory();
    let body=(0..5*1024*1024).map(|n|((n*17+n/997)%256) as u8).collect::<Vec<_>>();
    for name in ["gzip","x-gzip","deflate","raw","br","zstd","gzip, br","members"] {
        let bytes=match name {
            "gzip, br"=>encode("br",&encode("gzip",&body)),
            "members"=>{let mut b=encode("gzip",&body[..1000]);b.extend(encode("gzip",&body[1000..]));b},
            _=>encode(name,&body),
        };
        let id=feed(&c,match name {"raw"=>"deflate","members"=>"gzip",s=>s},&bytes,true);
        let s=state(path,id);assert_eq!(s["state"],"complete","{name}: {s}");
        assert_eq!(s["decoded_bytes"],body.len() as u64);
        assert_eq!(fs::read(path.join(s["file"].as_str().unwrap())).unwrap(),body);
        assert_eq!(fs::read(path.join(payload_relative(id,1))).unwrap(),bytes);
        // UI reads a prefix of the already decoded file, not the full body.
        assert_eq!(c.decode_preview(id,Direction::Server,1024,100).unwrap().data_base64,&body[..100]);
        assert_eq!(c.preview_read(id,Direction::Server,0,100,true).unwrap().data_base64,&body[..100]);
        assert_eq!(c.preview_status(id).unwrap()["preview_decode"][1]["state"],"complete");
    }
    c.finish_recording().unwrap();
    assert_eq!(c.recording_status()["body_decoding"]["pending"],0);
    assert_eq!(c.recording_status()["body_decoding"]["incomplete"],0);
    c.shutdown().unwrap();
}
#[test]
fn damaged_unsupported_and_incomplete_bodies_remain_explicit_and_do_not_stop_recording() {
    let c=cache(32*1024*1024);let body=b"readable decoded content".repeat(4000);
    for name in ["gzip","deflate","raw","br","zstd"] {
        let mut encoded=encode(name,&body);encoded.truncate(encoded.len()-3);
        let id=feed(&c,if name=="raw"{"deflate"}else{name},&encoded,true);
        assert!(!c.recording_failed(),"{name}: {}",c.recording_status());
        let s=state(c.directory(),id);assert_ne!(s["state"],"complete","{name}: {s}");
        assert!(s["error"].is_string());assert!(!c.recording_failed());
    }
    let mut crc=encode("gzip",&body);let len=crc.len();crc[len-8]^=1;
    let id=feed(&c,"gzip",&crc,true);assert_ne!(state(c.directory(),id)["state"],"complete");
    let id=feed(&c,"unknown",&body,true);assert_eq!(state(c.directory(),id)["state"],"failed");
    let id=feed(&c,"gzip",&encode("gzip",&body),false);
    let s=state(c.directory(),id);assert_eq!(s["state"],"partial");assert_eq!(s["source_complete"],false);
    assert_eq!(fs::read(c.directory().join(s["file"].as_str().unwrap())).unwrap(),body);
    let id=feed(&c,"identity",b"uncompressed",true);
    let s=state(c.directory(),id);assert_eq!(s["reused_source"],true);assert_eq!(s["file"],payload_relative(id,1));
    assert!(!c.recording_failed());c.finish_recording().unwrap();assert_eq!(c.recording_status()["body_decoding"]["pending"],0);
    c.shutdown().unwrap();
}
#[test]
fn decompression_capacity_failure_preserves_source_and_records_partial_result() {
    let c=cache(512*1024);let encoded=encode("gzip",&vec![7;8*1024*1024]);
    let id=feed(&c,"gzip",&encoded,true);
    assert!(c.recording_failed());
    assert_eq!(fs::read(c.directory().join(payload_relative(id,1))).unwrap(),encoded);
    c.finish_recording().unwrap();
    let m:Value=serde_json::from_slice(&fs::read(c.directory().join("manifest.json")).unwrap()).unwrap();
    assert_eq!(m["stop_reason"],"recording capacity reached");
    assert_eq!(m["body_decoding"]["last_result"]["state"],"partial");
    assert!(m["body_decoding"]["last_result"]["decoded_bytes"].as_u64().unwrap()<8*1024*1024);
    assert!(m["used_bytes"].as_u64().unwrap()<=512*1024);
    c.shutdown().unwrap();
}
#[test]
fn http3_request_and_response_use_same_full_decode_files() {
    let c=cache(4*1024*1024);
    let scoped=c.scoped(serde_json::json!({"protocol":"h3","connection":{"id":"h3-test"}}));
    let mut h=proxylane_protocol::http3::Capture::new(4,Some(&scoped));
    for side in 0..2 {
        let mut m=Message::default();m.method=if side==0 {Some("POST".into())}else{None};m.status=if side==1{Some(200)}else{None};
        m.headers=vec![("content-encoding".into(),"gzip".into())];h.head(side,m);
        h.data(side,&encode("gzip",b"request and response"));h.end(side,vec![]);
    }
    let e=h.finish("done");c.stats().unwrap();
    let id=e.cache.unwrap().id();
    for side in 0..2 {
        let p=c.directory().join(payload_relative(id,side).replace(".bin",".decoded.bin"));
        assert_eq!(fs::read(p).unwrap(),b"request and response");
    }
    c.finish_recording().unwrap();c.shutdown().unwrap();
}
#[test]
fn bodyless_response_does_not_decode_content_encoding_header() {
    let c=cache(1024*1024);
    let mut a=Analyzer::with_cache(Connection::default(),Protocol::Http1,Limits::default(),c.clone()).unwrap();
    a.push(Direction::Client,0,b"HEAD / HTTP/1.1\r\nHost: test\r\n\r\n");
    a.push(Direction::Server,0,b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 9000\r\n\r\n");
    c.stats().unwrap();let s=state(c.directory(),1);
    assert_eq!(s["state"],"complete");assert_eq!(s["decoded_bytes"],0);assert_eq!(s["reused_source"],true);
    c.finish_recording().unwrap();c.shutdown().unwrap();
}
#[test]
fn decode_crash_child() {
    let Some(root)=std::env::var_os("PROXYLANE_DECODE_CRASH_CHILD") else{return;};
    let c=PayloadCache::new(CacheConfig {root:root.into(),queue_chunks:2,
        recording:Some(RecordingConfig {total_bytes:2*1024*1024*1024,min_free_bytes:0}),..Default::default()}).unwrap();
    let mut writer=flate2::write::GzEncoder::new(Vec::new(),flate2::Compression::fast());
    for _ in 0..32768 {writer.write_all(&[0;32768]).unwrap();}
    let encoded=writer.finish().unwrap();
    feed(&c,"gzip",&encoded,true);
    panic!("parent should interrupt decoding");
}
#[test]
fn crash_during_decode_keeps_original_and_never_claims_complete() {
    use std::{process::{Command,Stdio},time::{Duration,Instant}};
    let root=root();
    let mut child=Command::new(std::env::current_exe().unwrap()).args(["--exact","decode_crash_child","--nocapture"])
        .env("PROXYLANE_DECODE_CRASH_CHILD",&root).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let start=Instant::now();
    let path=loop {
        if let Ok(dirs)=fs::read_dir(&root) {
            if let Some(path)=dirs.filter_map(Result::ok).map(|e|e.path()).find(|p|p.is_dir()) {
                let decoded=path.join(payload_relative(1,1).replace(".bin",".decoded.bin"));
                if fs::metadata(decoded).is_ok_and(|m|m.len()>=1024*1024) {break path;}
            }
        }
        if start.elapsed()>Duration::from_secs(60) || child.try_wait().unwrap().is_some() {
            let _=child.kill();let _=child.wait();panic!("decode crash checkpoint did not arrive");
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    child.kill().unwrap();child.wait().unwrap();
    let s=state(&path,1);assert_eq!(s["state"],"decoding");
    assert_eq!(fs::metadata(path.join(payload_relative(1,1))).unwrap().len(),s["source_bytes"].as_u64().unwrap());
    let m:Value=serde_json::from_slice(&fs::read(path.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(m["status"],"recording");assert!(m["body_decoding"]["pending"].as_u64().unwrap()>0);
}
