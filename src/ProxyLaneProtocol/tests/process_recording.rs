use proxylane_protocol::{cache::{CacheConfig,PayloadCache},recording::RecordingConfig};
use serde_json::{json,Value};
use std::{fs,path::{Path,PathBuf},time::{SystemTime,UNIX_EPOCH},process::Command};
fn config(capacity:u64)->CacheConfig {CacheConfig {
    root:std::env::temp_dir().join(format!("proxylane-process-log-{}-{}",std::process::id(),SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos())),
    queue_chunks:2,recording:Some(RecordingConfig{total_bytes:capacity,min_free_bytes:0}),..Default::default()
}}
fn rows(path:&Path)->Vec<Value> {
    let mut paths:Vec<_>=fs::read_dir(path).unwrap().map(|e|e.unwrap().path()).filter(|p|p.file_name().unwrap().to_string_lossy().starts_with("process-events-")).collect();paths.sort();
    paths.into_iter().flat_map(|p|fs::read_to_string(p).unwrap().lines().map(|l|serde_json::from_str(l).unwrap()).collect::<Vec<_>>()).collect()
}
fn event(id:u64)->Value {json!({"type":"process_created","observed_unix_ms":1234,
    "parent":{"pid":1,"path":"parent.exe","process_start":100},"child":{"pid":id,"process_start":200,"path":"child.exe"}})}
#[test]
fn concurrent_process_journal_rotates_without_session_changes_or_loss() {
    let cache=PayloadCache::new(config(64*1024*1024)).unwrap();let root=cache.directory().to_owned();
    let mut jobs=vec![];
    for producer in 0..8 {let c=cache.clone();jobs.push(std::thread::spawn(move|| {
        for i in 0..40 {let mut e=event(producer*40+i);e["test_padding"]="x".repeat(60000).into();c.record_process_created(e).unwrap();}
    }));}
    for job in jobs {job.join().unwrap();}cache.finish_recording().unwrap();cache.shutdown().unwrap();
    let data=rows(&root);assert_eq!(data.len(),320);
    assert!(root.join("process-events-000002.jsonl").is_file());
    let mut ids=std::collections::HashSet::new();
    for (i,row) in data.iter().enumerate() {assert_eq!(row["sequence"],i+1);assert_eq!(row["observed_unix_ms"],1234);assert!(ids.insert(row["child"]["pid"].as_u64().unwrap()));}
    let manifest:Value=serde_json::from_slice(&fs::read(root.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["process_events"]["last_sequence"],320);assert_eq!(manifest["has_data"],true);assert_eq!(manifest["status"],"completed");
    assert_eq!(manifest["quality"]["gap_count"],0);
    let actual:u64=fs::read_dir(&root).unwrap().map(|e|e.unwrap().metadata().unwrap().len()).sum();
    assert_eq!(manifest["used_bytes"],actual);
    assert!(!root.join("connections").exists());assert!(!root.join("payload").exists());
    let traffic=fs::read_to_string(root.join("events-000001.jsonl")).unwrap();assert!(!traffic.contains("process_created"));
}
#[test]
fn process_journal_capacity_stops_with_valid_prefix_and_explicit_reason() {
    let cache=PayloadCache::new(config(256*1024)).unwrap();let root=cache.directory().to_owned();
    for i in 0..20 {let mut e=event(i);e["padding"]="x".repeat(30000).into();cache.record_process_created(e).unwrap();}
    cache.finish_recording().unwrap();cache.shutdown().unwrap();
    let data=rows(&root);assert!(!data.is_empty() && data.len()<20);
    for (i,row) in data.iter().enumerate() {assert_eq!(row["sequence"],i+1);}
    let manifest:Value=serde_json::from_slice(&fs::read(root.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["status"],"stopped");assert!(manifest["stop_reason"].as_str().unwrap().contains("capacity"));
    assert_eq!(manifest["process_events"]["last_sequence"],data.len());
}
#[test]
fn process_journal_write_error_stops_recording_explicitly() {
    let cache=PayloadCache::new(config(1024*1024)).unwrap();let root=cache.directory().to_owned();
    fs::create_dir(root.join("process-events-000001.jsonl")).unwrap();
    cache.record_process_created(event(1)).unwrap();cache.finish_recording().unwrap();cache.shutdown().unwrap();
    let v:Value=serde_json::from_slice(&fs::read(root.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(v["status"],"stopped");assert!(v["stop_reason"].as_str().unwrap().contains("process journal open failed"));
}
#[test]
fn process_journal_survives_abrupt_exit() {
    let marker=config(1024*1024).root.with_extension("txt");
    let status=Command::new(std::env::current_exe().unwrap()).args(["--exact","process_journal_crash_child","--ignored"])
        .env("PROXYLANE_PROCESS_TEST_MARKER",&marker).status().unwrap();assert!(status.success());
    let root=PathBuf::from(fs::read_to_string(&marker).unwrap());let data=rows(&root);assert_eq!(data.len(),100);
    for (i,r) in data.iter().enumerate(){assert_eq!(r["sequence"],i+1);}
}
#[test]
#[ignore]
fn process_journal_crash_child() {
    let Ok(marker)=std::env::var("PROXYLANE_PROCESS_TEST_MARKER") else{return;};
    let cache=PayloadCache::new(config(1024*1024)).unwrap();fs::write(marker,cache.directory().to_string_lossy().as_bytes()).unwrap();
    for i in 0..100 {cache.record_process_created(event(i)).unwrap();}cache.stats().unwrap();
    std::process::exit(0); // No finish/drop; the standalone JSONL must remain readable.
}
