//! Serialize sender-collected creation snapshots; no process queries or identity checks.
use serde_json::{json, Value};

fn identity(value:&Value)->Result<Value,String> {
    let pid=value["pid"].as_u64().and_then(|n|u32::try_from(n).ok()).ok_or("invalid process PID field")?;
    let started=value["process_start"].as_u64().ok_or("invalid process creation time field")?;
    let path=value["path"].as_str().ok_or("invalid process path field")?;
    Ok(json!({"pid":pid,"process_start":started,"path":path}))
}
pub(crate) fn collect(request:&Value)->Result<Value,String> {
    let source=request["source"].as_str().unwrap_or("hook");
    if !matches!(source,"hook"|"launcher"|"launcher_activation") {return Err("invalid process observation source".into());}
    let mut value=json!({"type":if source=="launcher_activation" {"process_activated"}else{"process_created"},
        "observed_unix_ms":proxylane_protocol::recording::now_ms(),"source":source,
        "parent":identity(&request["parent"])?,"child":identity(&request["child"])?});
    let mut notes=Vec::new();
    for side in ["parent","child"] {
        let item=&value[side];
        let path=item["path"].as_str().unwrap();
        if item["pid"]==0 || item["process_start"]==0 || path.is_empty() {
            notes.push(format!("{side} identity incomplete in notification"));
        }
        if path.encode_utf16().count()>=259 {
            notes.push(format!("{side} path may be truncated by notification MAX_PATH limit"));
        }
    }
    if !notes.is_empty(){value["identity_note"]=notes.join("; ").into();}
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn notice()->Value {
        json!({"parent":{"pid":u32::MAX,"process_start":123456789,"path":"Z:\\gone\\父.exe"},
            "child":{"pid":u32::MAX-1,"process_start":1,"path":"Y:\\gone\\子.exe"},"source":"hook"})
    }
    #[test]
    fn supplied_snapshots_survive_missing_processes_without_identity_checks() {
        let request=notice();let record=collect(&request).unwrap();
        assert_eq!(record["parent"],request["parent"]);assert_eq!(record["child"],request["child"]);
        assert!(record.get("creator").is_none());assert!(record.get("identity_note").is_none());
        assert_eq!(record["type"],"process_created");
    }
    #[test]
    fn missing_identity_and_truncated_paths_are_kept_and_described() {
        let mut request=notice();request["parent"]=json!({"pid":0,"process_start":0,"path":""});
        request["child"]["path"]="x".repeat(259).into();request["source"]="launcher_activation".into();
        let record=collect(&request).unwrap();
        assert_eq!(record["parent"],request["parent"]);assert_eq!(record["child"],request["child"]);
        assert!(record["identity_note"].as_str().unwrap().contains("parent identity incomplete"));
        assert!(record["identity_note"].as_str().unwrap().contains("child path may be truncated"));
        assert_eq!(record["type"],"process_activated");
    }
    #[test]
    fn malformed_fields_are_rejected_without_querying_processes() {
        let mut request=notice();request["child"]["pid"]="bad".into();assert!(collect(&request).is_err());
        let mut request=notice();request["parent"]["path"]=false.into();assert!(collect(&request).is_err());
    }
}
