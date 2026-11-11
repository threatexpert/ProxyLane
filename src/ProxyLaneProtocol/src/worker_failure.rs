//! A worker failure is terminal for this capture, never for socket forwarding.
use std::sync::{Mutex, atomic::{AtomicBool, Ordering}};

#[derive(Default)]
pub struct WorkerFailure {
    failed: AtomicBool,
    reason: Mutex<Option<String>>,
}
impl WorkerFailure {
    pub fn failed(&self) -> bool { self.failed.load(Ordering::Acquire) }
    pub fn reason(&self) -> Option<String> {
        if !self.failed() { return None; }
        self.reason.lock().unwrap_or_else(|e|e.into_inner()).clone()
    }
    pub fn set(&self, reason: &str) {
        let mut stored=self.reason.lock().unwrap_or_else(|e|e.into_inner());
        if stored.is_none() { *stored=Some(reason.chars().take(512).collect()); }
        self.failed.store(true,Ordering::Release);
    }
}
pub fn panic_reason(worker:&str, payload:&(dyn std::any::Any + Send)) -> String {
    let detail=payload.downcast_ref::<String>().map(String::as_str)
        .or_else(||payload.downcast_ref::<&str>().copied()).unwrap_or("non-string panic");
    format!("{worker} panicked; monitoring stopped: {}",detail.chars().take(384).collect::<String>())
}
