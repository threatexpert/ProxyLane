//! Persisted by the host; validated here as well as in the GUI.
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Options {
    pub recording: RecordingOptions,
    pub entry_mib: u64,
    pub total_mib: u64,
    pub history_rows: usize,
    pub preview_kib: usize,
    pub decode_mib: usize,
    pub connections: usize,
    pub pending_requests: usize,
    pub udp_packets: usize,
    pub handshake_seconds: u64,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RecordingOptions {
    pub enabled: bool,
    pub directory: String,
    pub capacity_mib: u64,
    pub reserve_mib: u64,
}
impl Default for RecordingOptions {
    fn default()->Self {Self {enabled:false,directory:String::new(),capacity_mib:8192,reserve_mib:512}}
}
impl Default for Options {
    fn default() -> Self {
        Self { recording:RecordingOptions::default(), entry_mib:32, total_mib:512, history_rows:512, preview_kib:64,
            decode_mib:4, connections:128, pending_requests:8, udp_packets:256, handshake_seconds:15 }
    }
}
impl Options {
    pub fn validate(&self) -> Result<(), String> {
        let r=&self.recording;
        if !(16..=1_048_576).contains(&r.capacity_mib) || !(16..=1_048_576).contains(&r.reserve_mib) {
            return Err("recording capacity/reserve must be between 16 and 1048576 MiB".into());
        }
        if r.enabled && (r.directory.is_empty() || r.directory.len()>2048 || !std::path::Path::new(&r.directory).is_absolute()) {
            return Err(serde_json::json!({"error":"recording_directory_error","path":r.directory,
                "detail":"Recording directory must be an absolute path (at most 2048 UTF-8 bytes)."}).to_string());
        }
        for (name, value, min, max) in [
            ("entry_mib",self.entry_mib,1,1024), ("total_mib",self.total_mib,16,8192),
            ("history_rows",self.history_rows as u64,128,10000), ("preview_kib",self.preview_kib as u64,16,1024),
            ("decode_mib",self.decode_mib as u64,1,64), ("connections",self.connections as u64,1,256),
            ("pending_requests",self.pending_requests as u64,1,256), ("udp_packets",self.udp_packets as u64,16,4096),
            ("handshake_seconds",self.handshake_seconds,5,120),
        ] {
            if !(min..=max).contains(&value) { return Err(format!("{name} must be between {min} and {max}")); }
        }
        if self.entry_mib > self.total_mib { return Err("Single payload limit must not exceed total cache limit".into()); }
        Ok(())
    }
    pub fn same_analysis(&self, other: &Self) -> bool {
        let mut a=self.clone(); let mut b=other.clone();
        a.preview_kib=0; b.preview_kib=0; a.handshake_seconds=0; b.handshake_seconds=0;
        a==b
    }
}
static OPTIONS: Mutex<Option<Options>> = Mutex::new(None);
pub fn current() -> Options { OPTIONS.lock().unwrap_or_else(|e|e.into_inner()).clone().unwrap_or_default() }
pub fn update(value: &serde_json::Value, validate_only: bool) -> Result<Options,String> {
    let next:Options=serde_json::from_value(value.clone()).map_err(|e|e.to_string())?;
    next.validate()?;
    if !validate_only { *OPTIONS.lock().map_err(|e|e.to_string())?=Some(next.clone()); }
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_invalid_ranges_and_inconsistent_quotas() {
        Options::default().validate().unwrap();
        for (key,value) in [("entry_mib",0),("total_mib",9000),("history_rows",10001),("preview_kib",1025),
            ("decode_mib",65),("connections",257),("pending_requests",0),("udp_packets",4097),("handshake_seconds",121)] {
            let mut json=serde_json::to_value(Options::default()).unwrap();json[key]=value.into();
            assert!(update(&json,true).is_err(),"{key}");
        }
        let bad=Options {entry_mib:1024,total_mib:512,..Default::default()};assert!(bad.validate().is_err());
    }
}
