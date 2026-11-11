use proxylane_protocol::{
    cache::{CacheConfig, PayloadCache},
    *,
};
use std::{
    fs,
    io::Write,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
                "proxylane-cache-test-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            )))
    }
    fn cache(&self, entry: u64, total: u64) -> PayloadCache {
        PayloadCache::new(CacheConfig {
            root: self.0.clone(),
            entry_bytes: entry,
            total_bytes: total,
            ..CacheConfig::default()
        })
        .unwrap()
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        // Non-recursive: retain unexpected leftovers for diagnosis.
        let _ = fs::remove_file(self.0.join("manager.lock"));
        let _ = fs::remove_dir(&self.0);
    }
}
fn flows(outputs: Vec<Output>) -> Vec<Exchange> {
    outputs
        .into_iter()
        .map(|output| match output {
            Output::Exchange { exchange, .. } => *exchange,
            Output::Diagnostic { detail, .. } => panic!("{detail}"),
        })
        .collect()
}
struct Http {
    analyzer: Analyzer,
    offsets: [u64; 2],
}
impl Http {
    fn new(cache: &PayloadCache) -> Self {
        Self {
            analyzer: Analyzer::with_cache(
                Connection::default(),
                Protocol::Http1,
                Limits::default(),
                cache.clone(),
            )
            .unwrap(),
            offsets: [0; 2],
        }
    }
    fn send(&mut self, side: usize, bytes: &[u8]) -> Vec<Exchange> {
        let out = flows(self.analyzer.push(
            if side == 0 {
                Direction::Client
            } else {
                Direction::Server
            },
            self.offsets[side],
            bytes,
        ));
        self.offsets[side] += bytes.len() as u64;
        out
    }
    fn transaction(&mut self, request: &[u8], response: &[u8], cache: &PayloadCache) -> Exchange {
        self.send(
            0,
            format!(
                "POST /test HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
                request.len()
            )
            .as_bytes(),
        );
        if !request.is_empty() {
            self.send(0, request);
        }
        self.send(
            1,
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                response.len()
            )
            .as_bytes(),
        );
        let out = self.send(1, response);
        cache.stats().unwrap();
        out.into_iter().next().unwrap()
    }
}

#[test]
fn combined_request_response_limit_preserves_next_message() {
    let root = Root::new();
    let cache = root.cache(5, 100);
    let mut http = Http::new(&cache);
    let first = http.transaction(b"abc", b"defg", &cache);
    let reference = first.cache.as_ref().unwrap();
    let state = reference.snapshot();
    assert_eq!((state.request_bytes, state.response_bytes), (3, 2));
    assert_eq!(state.reason.as_deref(), Some("per-exchange payload limit"));
    assert!(first.response.as_ref().unwrap().complete);
    assert_eq!(first.response.as_ref().unwrap().body_bytes, 4);
    assert_eq!(
        cache
            .read(reference.id(), Direction::Server, 0, 99)
            .unwrap()
            .data_base64,
        b"de"
    );
    assert!(cache
        .decode(reference.id(), Direction::Server, 100)
        .is_err());
    assert_eq!(
        cache
            .decode(reference.id(), Direction::Client, 100)
            .unwrap()
            .data_base64,
        b"abc"
    );
    let next = http.transaction(b"", b"xy", &cache);
    assert_eq!(next.response.as_ref().unwrap().text.as_deref(), Some("xy"));
    assert_eq!(cache.stats().unwrap().used_bytes, 7);
    let directory = cache.directory().to_owned();
    cache.shutdown().unwrap();
    assert!(!directory.exists());
}

#[test]
fn total_limit_evicts_oldest_completed_payload_but_keeps_summary() {
    let root = Root::new();
    let cache = root.cache(10, 10);
    let mut http = Http::new(&cache);
    let first = http.transaction(b"", b"1111", &cache);
    let second = http.transaction(b"", b"2222", &cache);
    let third = http.transaction(b"", b"3333", &cache);
    let stats = cache.stats().unwrap();
    assert_eq!(stats.used_bytes, 8);
    assert!(stats.peak_bytes <= 10);
    assert_eq!(stats.evicted_entries, 1);
    let old = first.cache.as_ref().unwrap();
    assert!(old.snapshot().evicted);
    assert!(cache.status(old.id()).unwrap().unwrap().evicted);
    assert!(cache.read(old.id(), Direction::Server, 0, 4).is_err());
    assert_eq!(
        first.request.as_ref().unwrap().target.as_deref(),
        Some("/test")
    );
    for exchange in [&second, &third] {
        assert!(!exchange.cache.as_ref().unwrap().snapshot().evicted);
    }
    cache.shutdown().unwrap();
}

#[test]
fn active_entries_are_protected_and_global_budget_never_exceeded() {
    let root = Root::new();
    let cache = root.cache(100, 10);
    let mut active = Http::new(&cache);
    let mut other = Http::new(&cache);
    active.send(0, b"GET / HTTP/1.1\r\n\r\n");
    active.send(1, b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n12345");
    cache.stats().unwrap();
    let old = other.transaction(b"", b"abcde", &cache);
    let newest = other.transaction(b"", b"abcdefgh", &cache);
    assert!(old.cache.as_ref().unwrap().snapshot().evicted);
    let state = newest.cache.as_ref().unwrap().snapshot();
    assert_eq!(state.response_bytes, 5);
    assert!(state
        .reason
        .as_ref()
        .unwrap()
        .contains("total payload limit"));
    assert_eq!(cache.stats().unwrap().used_bytes, 10);
    let done = active.send(1, b"67890");
    cache.stats().unwrap();
    assert_eq!(
        done[0].cache.as_ref().unwrap().snapshot().response_bytes,
        10
    );
    assert!(newest.cache.as_ref().unwrap().snapshot().evicted);
    assert!(cache.stats().unwrap().peak_bytes <= 10);
    cache.shutdown().unwrap();
}

#[test]
fn large_download_keeps_preview_and_full_bounded_disk_payload() {
    let root = Root::new();
    let cache = root.cache(32 * 1024 * 1024, 64 * 1024 * 1024);
    let mut http = Http::new(&cache);
    let size = 34 * 1024 * 1024;
    http.send(0, b"GET /large HTTP/1.1\r\n\r\n");
    http.send(
        1,
        format!("HTTP/1.1 200 OK\r\nContent-Length: {size}\r\n\r\n").as_bytes(),
    );
    let block = [b'x'; 16384];
    let mut out = Vec::new();
    for _ in 0..size / block.len() {
        out.extend(http.send(1, &block));
        cache.stats().unwrap();
    }
    let response = out[0].response.as_ref().unwrap();
    assert!(response.complete);
    assert_eq!(response.body_bytes, size as u64);
    assert_eq!(response.body.len(), 65536);
    let reference = out[0].cache.as_ref().unwrap();
    assert_eq!(reference.snapshot().response_bytes, 32 * 1024 * 1024);
    assert_eq!(
        cache
            .read(reference.id(), Direction::Server, 31 * 1024 * 1024, 65536)
            .unwrap()
            .data_base64,
        vec![b'x'; 65536]
    );
    assert!(cache
        .decode(reference.id(), Direction::Server, 4 * 1024 * 1024)
        .is_err());
    let files: u64 = fs::read_dir(cache.directory())
        .unwrap()
        .map(|p| p.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "body"))
        .map(|p| fs::metadata(p).unwrap().len())
        .sum();
    assert_eq!(files, 32 * 1024 * 1024);
    cache.shutdown().unwrap();
}

#[test]
fn chunked_cache_contains_only_entity_body_and_on_demand_decode_works() {
    let root = Root::new();
    let cache = root.cache(1024 * 1024, 1024 * 1024);
    let mut http = Http::new(&cache);
    let original = vec![b'A'; 200000];
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&original).unwrap();
    let encoded = encoder.finish().unwrap();
    http.send(0, b"GET /compressed HTTP/1.1\r\n\r\n");
    http.send(
        1,
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n",
    );
    for chunk in encoded.chunks(7) {
        http.send(1, format!("{:x}\r\n", chunk.len()).as_bytes());
        http.send(1, chunk);
        http.send(1, b"\r\n");
        cache.stats().unwrap();
    }
    let out = http.send(1, b"0\r\nX-End: yes\r\n\r\n");
    cache.stats().unwrap();
    let id = out[0].cache.as_ref().unwrap().id();
    assert_eq!(
        cache
            .read(id, Direction::Server, 0, 65536)
            .unwrap()
            .data_base64,
        encoded
    );
    assert_eq!(
        cache
            .decode(id, Direction::Server, 300000)
            .unwrap()
            .data_base64,
        original
    );
    assert!(cache.decode(id, Direction::Server, 100).is_err());
    cache.shutdown().unwrap();
}

#[test]
fn metadata_count_limit_also_evicts_empty_payloads_and_drop_closes_run() {
    let root = Root::new();
    let directory;
    {
        let cache = PayloadCache::new(CacheConfig {
            root: root.0.clone(),
            max_entries: 1,
            ..CacheConfig::default()
        })
        .unwrap();
        directory = cache.directory().to_owned();
        let mut http = Http::new(&cache);
        http.send(0, b"GET / HTTP/1.1\r\n\r\n");
        let first = http.send(1, b"HTTP/1.1 204 No Content\r\n\r\n");
        cache.stats().unwrap();
        http.send(0, b"GET /2 HTTP/1.1\r\n\r\n");
        cache.stats().unwrap();
        assert!(first[0].cache.as_ref().unwrap().snapshot().evicted);
        assert_eq!(cache.stats().unwrap().entries, 1);
    }
    assert!(!directory.exists());
}

#[test]
fn live_run_lock_protects_other_instances() {
    let root = Root::new();
    let first = root.cache(100, 100);
    let mut http = Http::new(&first);
    let out = http.transaction(b"", b"hello", &first);
    let second = root.cache(100, 100);
    assert_eq!(second.stats().unwrap().recovered_runs, 0);
    assert!(first.directory().exists());
    second.shutdown().unwrap();
    assert_eq!(
        first
            .read(out.cache.as_ref().unwrap().id(), Direction::Server, 0, 100)
            .unwrap()
            .data_base64,
        b"hello"
    );
    first.shutdown().unwrap();
}

#[test]
fn cache_io_failure_does_not_break_http_reconstruction() {
    let root = Root::new();
    let cache = root.cache(100, 100);
    let mut http = Http::new(&cache);
    let obstacle = cache.directory().join("0000000000000001.response.body");
    fs::create_dir(&obstacle).unwrap();
    let first = http.transaction(b"", b"abc", &cache);
    assert!(first.response.as_ref().unwrap().complete);
    assert!(first
        .cache
        .as_ref()
        .unwrap()
        .snapshot()
        .reason
        .unwrap()
        .contains("write failed"));
    assert_eq!(cache.stats().unwrap().used_bytes, 0);
    fs::remove_dir(obstacle).unwrap();
    let next = http.transaction(b"", b"xyz", &cache);
    assert_eq!(next.cache.as_ref().unwrap().snapshot().response_bytes, 3);
    cache.shutdown().unwrap();
}

#[test]
fn h2_streams_cache_separately_and_keep_parsing_after_limits() {
    fn frame(kind: u8, flags: u8, id: u32, payload: &[u8]) -> Vec<u8> {
        let mut data = (payload.len() as u32).to_be_bytes()[1..].to_vec();
        data.extend([kind, flags]);
        data.extend(id.to_be_bytes());
        data.extend(payload);
        data
    }
    let root = Root::new();
    let cache = root.cache(3, 100);
    let mut analyzer = Analyzer::with_cache(
        Connection::default(),
        Protocol::H2,
        Limits::default(),
        cache.clone(),
    )
    .unwrap();
    let mut request = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    request.extend(frame(1, 5, 1, &[0x82, 0x87, 0x84]));
    request.extend(frame(1, 5, 3, &[0x82, 0x87, 0x84]));
    flows(analyzer.push(Direction::Client, 0, &request));
    let mut response = frame(1, 4, 1, &[0x88]);
    response.extend(frame(1, 4, 3, &[0x88]));
    response.extend(frame(0, 0, 1, b"abcdef"));
    response.extend(frame(0, 1, 3, b"ok"));
    response.extend(frame(0, 1, 1, b"ghi"));
    let out = flows(analyzer.push(Direction::Server, 0, &response));
    cache.stats().unwrap();
    assert_eq!(out.iter().map(|e| e.id).collect::<Vec<_>>(), [3, 1]);
    assert_eq!(out[1].response.as_ref().unwrap().body_bytes, 9);
    assert_eq!(out[0].cache.as_ref().unwrap().snapshot().response_bytes, 2);
    assert_eq!(out[1].cache.as_ref().unwrap().snapshot().response_bytes, 3);
    assert_eq!(
        cache
            .read(
                out[0].cache.as_ref().unwrap().id(),
                Direction::Server,
                0,
                99
            )
            .unwrap()
            .data_base64,
        b"ok"
    );
    assert_eq!(
        cache
            .read(
                out[1].cache.as_ref().unwrap().id(),
                Direction::Server,
                0,
                99
            )
            .unwrap()
            .data_base64,
        b"abc"
    );
    cache.shutdown().unwrap();
}

#[test]
fn configured_decode_budget_and_bounded_preview() {
    for decode_mib in [1,2] {
        let root=Root::new();
        let cache=PayloadCache::new(CacheConfig {root:root.0.clone(),decode_bytes:decode_mib*1024*1024,..Default::default()}).unwrap();
        let mut http=Http::new(&cache);
        let body=vec![b'x';1536*1024];
        let mut compressor=flate2::write::GzEncoder::new(Vec::new(),flate2::Compression::default());
        compressor.write_all(&body).unwrap();let packed=compressor.finish().unwrap();
        http.send(0,b"GET / HTTP/1.1\r\nHost: t\r\n\r\n");
        http.send(1,format!("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",packed.len()).as_bytes());
        let exchange=http.send(1,&packed).remove(0);cache.stats().unwrap();
        let id=exchange.cache.as_ref().unwrap().id();
        let result=cache.decode_preview(id,Direction::Server,2*1024*1024,128*1024);
        if decode_mib==1 {assert!(result.unwrap_err().contains("decoded body limit"));}
        else {let value=result.unwrap();assert_eq!(value.data_base64.len(),128*1024);assert_eq!(value.decoded_bytes,body.len());assert_eq!(value.data_base64,body[..128*1024]);}
        cache.shutdown().unwrap();
    }
}
