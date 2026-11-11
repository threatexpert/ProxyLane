//! Repeatable local writer profile; explicitly run with --ignored --nocapture.
use proxylane_protocol::{*,cache::{CacheConfig,PayloadCache},recording::RecordingConfig};
use std::{fs,io::Write,time::{Instant,SystemTime,UNIX_EPOCH}};
use serde_json::{json,Value};

#[test]
#[ignore]
fn mixed_recording_writer_profile() {
    let root=std::env::temp_dir().join(format!("proxylane-writer-profile-{}-{}",std::process::id(),SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
    let cache=PayloadCache::new(CacheConfig{root,max_entries:128,queue_chunks:64,recording:Some(RecordingConfig{total_bytes:512*1024*1024,min_free_bytes:0}),..Default::default()}).unwrap();
    let path=cache.directory().to_owned();let started=Instant::now();
    let body:Vec<u8>=(0..65536).map(|n|(n%251) as u8).collect();
    let mut gz=flate2::write::GzEncoder::new(Vec::new(),flate2::Compression::fast());gz.write_all(&body).unwrap();let compressed=gz.finish().unwrap();
    let mut parser=Analyzer::with_cache(Connection{id:"profile".into(),decrypted:true,..Default::default()},Protocol::Http1,Limits::default(),cache.clone()).unwrap();
    let mut offsets=[0,0];
    for n in 0..300 {
        let req=format!("GET /{n} HTTP/1.1\r\nHost: profile.test\r\n\r\n");
        parser.push(Direction::Client,offsets[0],req.as_bytes());offsets[0]+=req.len() as u64;
        let bytes=match n%6 {0=>compressed.as_slice(),1=>&[],_=>body.as_slice()};
        let response=format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n{}\r\n",bytes.len(),if n%6==0 {"Content-Encoding: gzip\r\n"}else{""});
        parser.push(Direction::Server,offsets[1],response.as_bytes());offsets[1]+=response.len() as u64;
        for chunk in bytes.chunks(16384) {parser.push(Direction::Server,offsets[1],chunk);offsets[1]+=chunk.len() as u64;}
    }
    cache.finish_recording().unwrap();cache.shutdown().unwrap();let elapsed=started.elapsed().as_millis();
    let manifest:Value=serde_json::from_slice(&fs::read(path.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["status"],"completed");assert_eq!(manifest["quality"]["gap_count"],0);assert_eq!(manifest["body_decoding"]["finished"],600);
    let mut dirs=vec![path.clone()];let mut disk_bytes=0;
    while let Some(dir)=dirs.pop() {for e in fs::read_dir(dir).unwrap() {let p=e.unwrap().path();if p.is_dir(){dirs.push(p);}else{disk_bytes+=p.metadata().unwrap().len();}}}
    assert_eq!(manifest["used_bytes"],disk_bytes);
    for id in 1..=300 {
        let snapshot:Value=serde_json::from_slice(&fs::read(path.join(recording_view::session_relative(id))).unwrap()).unwrap();
        assert_eq!(snapshot["cache"],snapshot["exchange"]["cache"]);
        let expected=if (id-1)%6==1 {&[][..]}else{body.as_slice()};
        let decoded=&snapshot["payloads"]["response"]["decode"];
        assert_eq!(decoded["state"],"complete");
        if let Some(file)=decoded["file"].as_str() {assert_eq!(fs::read(path.join("payload/000000").join(file)).unwrap(),expected);}
        else {assert!(expected.is_empty());}
    }
    println!("{}",json!({"directory":path,"elapsed_ms":elapsed,"performance":manifest["performance"]}));
}
