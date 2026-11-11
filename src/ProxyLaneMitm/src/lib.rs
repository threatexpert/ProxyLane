pub mod pki;
pub mod protocol;
mod options;
mod dns;
mod doh;
mod doh_client;
mod quic_probe;
mod quic_locator;
mod quic_live;
mod quic_raw;
mod verification;
pub mod session;
#[cfg(test)]
mod tests;
pub mod windows;

use session::{Context, Session};
use std::{
    ffi::{c_char, CStr},
    panic::{catch_unwind, AssertUnwindSafe},
    ptr, slice,
    sync::{Arc, Mutex},
};
pub(crate) static SKIP_UPSTREAM_VERIFY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static CONTEXT: Mutex<Option<Arc<Context>>> = Mutex::new(None);
mod process_events;
static RECORDING_VIEW: Mutex<Option<proxylane_protocol::recording_reader::Reader>> = Mutex::new(None);
static PROTOCOL: Mutex<Option<Arc<protocol::Runtime>>> = Mutex::new(None);
static MONITORING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
// Serialize control requests, without holding the runtime slot during stop/drain.
static PROTOCOL_CONTROL: Mutex<()> = Mutex::new(());

fn protocol_runtime() -> Result<(Arc<protocol::Runtime>, u64), String> {
    let mut slot = PROTOCOL.lock().map_err(|e| e.to_string())?;
    if !MONITORING.load(std::sync::atomic::Ordering::Acquire) { return Err("monitoring stopped".into()); }
    if let Some(runtime) = slot.as_ref() {
        return Ok((runtime.clone(), runtime.capture_epoch()));
    }
    let runtime = protocol::Runtime::configured()?;
    *slot = Some(runtime.clone());
    let epoch = runtime.capture_epoch();
    Ok((runtime, epoch))
}

fn context() -> Result<Arc<Context>, String> {
    let mut slot = CONTEXT.lock().map_err(|e| e.to_string())?;
    if let Some(c) = slot.as_ref() {
        return Ok(c.clone());
    }
    let c = Context::open()?;
    *slot = Some(c.clone());
    Ok(c)
}
unsafe fn text<'a>(s: *const c_char) -> Result<&'a str, String> {
    if s.is_null() {
        return Err("null string".into());
    }
    CStr::from_ptr(s).to_str().map_err(|e| e.to_string())
}
unsafe fn write_error(output: *mut c_char, capacity: usize, error: &str) {
    if output.is_null() || capacity == 0 {
        return;
    }
    let n = error.len().min(capacity - 1);
    ptr::copy_nonoverlapping(error.as_ptr(), output as *mut u8, n);
    *output.add(n) = 0;
}
#[no_mangle]
pub extern "C" fn plm_abi_version() -> u32 {
    10
}

#[no_mangle]
/// # Safety
/// The output buffer must be writable for capacity bytes, or null.
/// Actions: 0 status, 1 initialize, 2 trust, 3 remove trust, 4 prepare TLS.
/// Returns flags (1 initialized, 2 trusted) or -1 with an error message.
pub unsafe extern "C" fn plm_ca(action: u32, output: *mut c_char, capacity: usize) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| -> Result<(i32, String), String> {
        if action > 4 {
            return Err("Unknown CA action".into());
        }
        let path = pki::directory()?;
        if action == 0 && !path.join("ca.json").exists() {
            return Ok((0, format!("CA not initialized.\r\n{}", path.display())));
        }
        let ca = pki::Authority::load(&path, action == 1 || action == 2)?;
        let trusted = windows::trust(
            &ca.der,
            match action {
                2 => "install",
                3 => "remove",
                _ => "status",
            },
        )?;
        if action == 4 {
            if !trusted {
                return Err(
                    "Initialize and install the CA in CA Management first (CurrentUser ROOT)."
                        .into(),
                );
            }
            context()?;
        }
        // Status must not initialize a listener or show a different instance's
        // preferred port as if it were this process's running endpoint.
        let crl = CONTEXT
            .lock()
            .map_err(|e| e.to_string())?
            .as_ref()
            .filter(|context| context.ca.id == ca.id)
            .map(|context| format!("http://127.0.0.1:{}/pki/{}.crl", context.crl.port(), ca.id))
            .unwrap_or_else(|| "not started in this instance".into());
        Ok((
            1 | if trusted { 2 } else { 0 },
            format!(
                "SHA-256: {}\r\nCertificate: {}\r\nCurrentUser ROOT: {}\r\nCRL: {}",
                ca.id,
                path.join("proxylane-ca.cer").display(),
                trusted,
                crl
            ),
        ))
    }));
    match result {
        Ok(Ok((flags, info))) => {
            write_error(output, capacity, &info);
            flags
        }
        Ok(Err(e)) => {
            write_error(output, capacity, &e);
            -1
        }
        Err(_) => {
            write_error(output, capacity, "CA operation failed");
            -1
        }
    }
}

#[no_mangle]
/// # Safety
/// The session must be live and exclusively accessed. Callback must not unwind,
/// reenter or retain the borrowed bytes; user must remain valid until plm_free.
pub unsafe extern "C" fn plm_observe(
    handle: *mut Session,
    callback: extern "C" fn(usize, u32, *const u8, usize),
    user: usize,
) {
    if !handle.is_null() {
        (*handle).observer = Some((callback, user));
    }
}

#[no_mangle]
/// # Safety
/// Strings must be NUL-terminated UTF-8. `out` and the optional error buffer
/// must be writable for their declared sizes, and must not alias the strings.
pub unsafe extern "C" fn plm_create(
    host: *const c_char,
    metadata: *const c_char,
    out: *mut *mut Session,
    error: *mut c_char,
    capacity: usize,
) -> i32 {
    if out.is_null() {
        return -1;
    }
    *out = ptr::null_mut();
    let result = catch_unwind(AssertUnwindSafe(|| {
        let host = text(host)?.to_owned();
        let metadata = serde_json::from_str(text(metadata)?).map_err(|e| e.to_string())?;
        // GUI logging remains memory-only. The separate protocol cache is
        // bounded/temporary and failure must not affect network forwarding.
        let identity = protocol::identity(&metadata, &host);
        let mut session = Session::new(context()?, host, metadata, false)?;
        if let (Ok((runtime, epoch)), Ok(identity)) = (protocol_runtime(), identity) {
            session.enable_protocol_at(runtime, identity, epoch);
        }
        Ok::<_, String>(session)
    }));
    match result {
        Ok(Ok(session)) => {
            *out = Box::into_raw(Box::new(session));
            0
        }
        Ok(Err(e)) => {
            write_error(error, capacity, &e);
            -1
        }
        Err(_) => {
            write_error(error, capacity, "panic creating MITM session");
            -1
        }
    }
}

// Passive TCP capture: no CA, listener, TLS handshake or forwarding changes.
#[no_mangle]
/// # Safety
/// Strings are NUL terminated UTF-8; returned tap is exclusively owned by caller.
pub unsafe extern "C" fn plm_stream_open(host: *const c_char, metadata: *const c_char) -> *mut protocol::Tap {
    catch_unwind(AssertUnwindSafe(|| {
        let host = text(host).ok()?;
        let metadata = serde_json::from_str(text(metadata).ok()?).ok()?;
        let identity = protocol::identity(&metadata, host).ok()?;
        let (runtime, epoch) = protocol_runtime().ok()?;
        runtime.tap_at(epoch, identity, None, false).map(|tap| Box::into_raw(Box::new(tap)))
    })).ok().flatten().unwrap_or(ptr::null_mut())
}
#[no_mangle]
/// # Safety
/// Tap must be live and exclusively accessed; bytes readable for len. op 0 data,
/// 1 clean direction EOF, 2 destroy. Capture errors never affect forwarding.
pub unsafe extern "C" fn plm_stream_io(handle: *mut protocol::Tap, op: u32, side: u32, bytes: *const u8, len: usize) {
    if handle.is_null() { return; }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if op == 2 { drop(Box::from_raw(handle)); }
        else if side < 2 {
            if op == 5 && !bytes.is_null() && len<=4096 {(*handle).close_reason(String::from_utf8_lossy(slice::from_raw_parts(bytes,len)).into_owned());}
            else if op == 4 { (*handle).transport_result(len); }
            else if op == 6 { (*handle).transport_closed(side as usize,len); }
            else if op == 1 { (*handle).eof(side as usize, true); }
            else if op == 3 && !bytes.is_null() && len <= 65535 {
                (*handle).datagram(side as usize, slice::from_raw_parts(bytes, len));
            }
            else if op == 0 && !bytes.is_null() && len <= 65536 {
                (*handle).data(side as usize, slice::from_raw_parts(bytes, len));
            }
        }
    }));
}

fn call(session: &mut Session, f: impl FnOnce(&mut Session) -> Result<i32, String>) -> i32 {
    if !session.error.is_empty() {
        return -1;
    }
    match catch_unwind(AssertUnwindSafe(|| f(session))) {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            session.fail(e);
            -1
        }
        Err(_) => {
            session.fail("panic in MITM session".into());
            -1
        }
    }
}
// op: 0 feed, 1 peek output, 2 consume output, 3 EOF, 4 status/tick.
// status bits: 1 can read; 2 shutdown application output; 4 shutdown upstream output;
//              8 application input EOF; 16 upstream input EOF; 32 ready.
//              64 application can read; 128 upstream can read.
#[no_mangle]
/// # Safety
/// `handle` must be a live session from plm_create, used on one thread at a time.
/// For feed/peek, `data` must address `len` readable/writable bytes respectively.
pub unsafe extern "C" fn plm_io(
    handle: *mut Session,
    op: u32,
    side: u32,
    data: *mut u8,
    len: usize,
) -> i32 {
    if handle.is_null() || side > 1 {
        return -1;
    }
    let s = &mut *handle;
    call(s, |s| {
        let side = side as usize;
        match op {
            0 => {
                if data.is_null() || len == 0 {
                    return Err("empty input".into());
                }
                s.feed(side, slice::from_raw_parts(data, len))?;
                Ok(0)
            }
            1 => {
                if data.is_null() || len == 0 {
                    return Err("empty output buffer".into());
                }
                Ok(s.peek(side, slice::from_raw_parts_mut(data, len))? as i32)
            }
            2 => {
                s.consume(side, len)?;
                Ok(0)
            }
            3 => {
                s.input_eof(side)?;
                Ok(0)
            }
            4 => {
                s.tick()?;
                s.pump()?;
                Ok(i32::from(s.can_read())
                    | (i32::from(s.shutdown_output(0)) << 1)
                    | (i32::from(s.shutdown_output(1)) << 2)
                    | (i32::from(s.eof[0]) << 3)
                    | (i32::from(s.eof[1]) << 4)
                    | (i32::from(s.ready()) << 5)
                    | (i32::from(s.can_read_side(0)) << 6)
                    | (i32::from(s.can_read_side(1)) << 7)
                    | (i32::from(s.handshake_pending()) << 8)
                    | (i32::from(s.recording_pending()) << 9))
            }
            5 => { s.transport_result(len); Ok(0) },
            6 => { s.transport_closed(side,len); Ok(0) },
            _ => Err("invalid operation".into()),
        }
    })
}
#[no_mangle]
/// # Safety
/// `handle` must be live and exclusively accessed. `output` must be writable
/// for `capacity` bytes (or null when no output is needed).
pub unsafe extern "C" fn plm_error(handle: *mut Session, output: *mut c_char, capacity: usize) {
    if !handle.is_null() {
        write_error(output, capacity, (*handle).reported_error());
    }
}
#[no_mangle]
/// # Safety
/// A non-null handle must come from plm_create, have no concurrent users, and
/// must not have been freed. It becomes invalid after this call.
pub unsafe extern "C" fn plm_free(handle: *mut Session) {
    if !handle.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| drop(Box::from_raw(handle))));
    }
}

#[no_mangle]
/// # Safety
/// UTF-8 NUL-terminated request, writable output of capacity bytes. Consumer
/// thread only. Returns required bytes INCLUDING NUL; undersized buffers are
/// untouched and queries are non-destructive, so callers can retry. Negative
/// means invalid input/operation, with a bounded error string when possible.
/// Shutdown is internal host lifecycle, after all sessions have been freed.
pub unsafe extern "C" fn plm_protocol(
    request: *const c_char,
    output: *mut c_char,
    capacity: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| -> Result<String, String> {
        let input = text(request)?;
        if input.len() > 4096 {
            return Err("protocol query exceeds 4 KiB".into());
        }
        let request: serde_json::Value = serde_json::from_str(input).map_err(|e| e.to_string())?;
        if request["type"]=="recording_process_created" {
            // No lazy initialization, barriers or global control lock here. This
            // endpoint runs only on pipe-client/launcher threads, never PRC I/O.
            let runtime=PROTOCOL.lock().map_err(|e|e.to_string())?.clone();
            let accepted=if let Some(runtime)=runtime {runtime.record_process_created(&request)?}else{false};
            return Ok(serde_json::json!({"accepted":accepted}).to_string());
        }
        if request["type"]=="recording_open" || request["type"]=="recording_close" {
            let _control=PROTOCOL_CONTROL.lock().map_err(|e|e.to_string())?;
            if MONITORING.load(std::sync::atomic::Ordering::Acquire) {return Err("Stop monitoring before opening a recording.".into());}
            let mut view=RECORDING_VIEW.lock().map_err(|e|e.to_string())?;
            if request["type"]=="recording_close" {*view=None;return Ok("{}".into());}
            let path=request["path"].as_str().ok_or("missing recording directory")?;
            let reader=if request["rebuild_index"]==true {
                proxylane_protocol::recording_reader::Reader::rebuild(std::path::Path::new(path))?
            }else{proxylane_protocol::recording_reader::Reader::open(std::path::Path::new(path))?};
            let run=reader.run.clone();*view=Some(reader);
            return Ok(serde_json::json!({"run_id":run}).to_string());
        }
        if request["type"]=="recording_page" || request["type"]=="recording_detail" || request["run_id"].as_str().is_some_and(|s|s.starts_with("recording:")) {
            let mut view=RECORDING_VIEW.lock().map_err(|e|e.to_string())?;
            return Ok(view.as_mut().ok_or("No recording is open")?.query(&request)?.to_string());
        }
        if request["type"]=="quic_locate" {
            return Ok(quic_locator::locate(request["path"].as_str().ok_or("missing module path")?)?.to_string());
        }
        if request["type"]=="quic_prepare" {quic_live::prepare().map_err(|e|e.to_string())?;return Ok("{}".into());}
        if request["type"] == "mitm_options" {
            use std::sync::atomic::Ordering;
            let validate_only=request["validate_only"].as_bool().unwrap_or(false);
            let skip=request.get("skip_upstream_verify").map(|v|v.as_bool().ok_or("invalid verification option")).transpose()?;
            let settings=if let Some(value)=request.get("settings") { options::update(value,validate_only)? } else {options::current()};
            if !validate_only { if let Some(value) = skip {
                SKIP_UPSTREAM_VERIFY.store(value, Ordering::Release);
            }
            }
            return Ok(serde_json::json!({"skip_upstream_verify":SKIP_UPSTREAM_VERIFY.load(Ordering::Acquire),"settings":settings}).to_string());
        }
        if request["type"] == "analysis_start" || request["type"] == "analysis_stop" || request["type"] == "shutdown" {
            use std::sync::atomic::Ordering;
            let _control = PROTOCOL_CONTROL.lock().map_err(|e| e.to_string())?;
            if request["type"] == "analysis_start" {
                if RECORDING_VIEW.lock().map_err(|e|e.to_string())?.is_some() {return Err("Close the recording view before starting monitoring.".into());}
                // Exclude lazy initialization by arriving connections while the
                // old runtime is drained and the new recording is constructed.
                // A failed start must also leave capture disabled.
                MONITORING.store(false, Ordering::Release);
                let (changed, old) = {
                    let mut slot = PROTOCOL.lock().map_err(|e| e.to_string())?;
                    let changed = slot.as_ref().is_some_and(|r| r.worker_error().is_some() || r.is_recording() || !r.options.same_analysis(&options::current()));
                    let old = if changed { slot.take() } else { None };
                    if let Some(runtime) = slot.as_ref() { runtime.start_capture(); }
                    (changed, old)
                };
                if let Some(runtime) = old { runtime.shutdown()?; }
                // Recording must create and sync its manifest before monitoring can start.
                if options::current().recording.enabled {
                    let runtime=protocol::Runtime::configured()?;
                    *PROTOCOL.lock().map_err(|e|e.to_string())?=Some(runtime);
                }
                MONITORING.store(true, Ordering::Release);
                return Ok(serde_json::json!({"type":"analysis_started","reset":changed}).to_string());
            }
            let runtime = {
                let mut slot = PROTOCOL.lock().map_err(|e| e.to_string())?;
                // Proxy shutdown clears resources, but preserves the selected
                // monitoring mode for a later proxy restart.
                if request["type"] == "analysis_stop" { MONITORING.store(false, Ordering::Release); }
                if request["type"] == "shutdown" { slot.take() } else { slot.clone() }
            };
            if let Some(runtime) = runtime {
                if request["type"] == "shutdown" { runtime.shutdown()?; }
                else { runtime.stop_capture()?; }
            }
            return Ok("{\"type\":\"stopped\"}".into());
        }
        let runtime = PROTOCOL.lock().map_err(|e| e.to_string())?.clone();
        let value = if let Some(runtime) = runtime {
            runtime.query(&request)?
        } else {
            serde_json::json!({"type":"inactive"})
        };
        serde_json::to_string(&value).map_err(|e| e.to_string())
    }));
    match result {
        Ok(Ok(json)) => {
            let required = json.len() + 1;
            if capacity >= required && !output.is_null() {
                write_error(output, capacity, &json);
            }
            required as i32
        }
        Ok(Err(e)) => {
            write_error(output, capacity, &e);
            -1
        }
        Err(_) => {
            write_error(output, capacity, "protocol query panicked");
            -1
        }
    }
}

// Local-process locator only: the caller owns a readable immutable image snapshot.
// Does not initialize CA, network, capture cache or Tokio.
#[no_mangle]
pub unsafe extern "C" fn plm_quic_locate_image(image:*const u8, length:usize, output:*mut c_char, capacity:usize)->i32 {
    if image.is_null() || length < 4096 || length >= 1024*1024*1024 { return -1; }
    let result=catch_unwind(AssertUnwindSafe(|| quic_locator::locate_image(slice::from_raw_parts(image,length),true)));
    match result {
        Ok(Ok(value))=>{let json=value.to_string(); if json.len()+1>capacity {return -1;} write_error(output,capacity,&json); (json.len()+1) as i32},
        Ok(Err(e))=>{write_error(output,capacity,&e);-1},
        Err(_)=>{write_error(output,capacity,"Local QUIC locator failed");-1}
    }
}

// Internal optional-module ABI. Host owns Live handles on its PRC thread.
#[no_mangle]
pub unsafe extern "C" fn plm_quic_open(host:*const c_char, metadata:*const c_char, first:*const u8, length:usize, inspected:*const quic_probe::Probe,
    notify:quic_live::Notify,user:usize,out:*mut *mut quic_live::Live,error:*mut c_char,capacity:usize)->i32 {
    if out.is_null()||first.is_null()||length>65535 {return -1;}*out=ptr::null_mut();
    let result=catch_unwind(AssertUnwindSafe(||->Result<Option<quic_live::Live>,String> {
        let meta=serde_json::from_str(text(metadata)?).map_err(|e|e.to_string())?;
        quic_live::Live::open(text(host)?,&meta,slice::from_raw_parts(first,length),inspected.as_ref(),notify,user).map_err(|e|e.to_string())
    }));
    match result {Ok(Ok(Some(live)))=>{*out=Box::into_raw(Box::new(live));1},Ok(Ok(None))=>0,
        Ok(Err(e))=>{write_error(error,capacity,&e);-1},Err(_)=>{write_error(error,capacity,"QUIC initialization failed");-1}}
}
#[no_mangle]
pub unsafe extern "C" fn plm_quic_io(handle:*mut quic_live::Live,op:u32,side:u32,data:*mut u8,len:usize)->i32 {
    if handle.is_null()||side>1{return -1;}
    catch_unwind(AssertUnwindSafe(||{let live=&*handle;
        match op {
            0 if !data.is_null()&&len<=65535=>{live.feed(side as usize,slice::from_raw_parts(data,len));0},
            1 if !data.is_null()=>live.peek(side as usize,slice::from_raw_parts_mut(data,len)) as i32,
            2=>{live.consume(side as usize);0},
            3=>{drop(Box::from_raw(handle));0},
            4=>live.finished() as i32,
            5=>{write_error(data as *mut c_char,len,&live.error());0},_=>-1}
    })).unwrap_or(-1)
}

/// Bounded admission inspector. No network output until a complete supported ClientHello.
#[no_mangle]
pub unsafe extern "C" fn plm_quic_inspect(handle:*mut *mut quic_probe::Probe,op:u32,data:*const u8,len:usize)->i32 {
    if handle.is_null(){return -1;}
    catch_unwind(AssertUnwindSafe(|| {
        if op==1 {if !(*handle).is_null(){drop(Box::from_raw(*handle));*handle=ptr::null_mut();}return 0;}
        if data.is_null()||len>65535{return -1;}
        if (*handle).is_null(){*handle=Box::into_raw(Box::new(quic_probe::Probe::default()));}
        let probe=&mut **handle;probe.feed(0,slice::from_raw_parts(data,len));
        if probe.version!=Some(1){return -1;}
        if !probe.complete(){return 0;}
        if quic_live::admissible(probe){1}else{-1}
    })).unwrap_or(-1)
}
