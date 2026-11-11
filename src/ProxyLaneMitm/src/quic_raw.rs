//! Opaque reliable QUIC streams. No HTTP framing, message boundary guesses or
//! transport dependency on capture. Each of the four stream spaces stays ordered.
use crate::protocol::{Runtime, Tap};
use proxylane_protocol::Connection;
use quinn::{RecvStream, SendStream, VarInt};
use std::sync::Arc;
use tokio::sync::{Mutex,OnceCell};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
type Capture = Arc<Mutex<Option<Tap>>>;
async fn note(tap:&Capture,message:String) {if let Some(t)=tap.lock().await.as_ref() {t.note_async(message).await;}}
async fn eof(tap:&Capture,side:usize,clean:bool) {if let Some(t)=tap.lock().await.as_mut() {t.eof_async(side,clean).await;}}
async fn copy(mut src:RecvStream,mut dst:SendStream,side:usize,tap:Capture) {
    let mut buffer=[0u8;16384];
    loop {
        let read=tokio::select! {
            stop=dst.stopped()=>{
                let code=stop.ok().flatten().unwrap_or(VarInt::from_u32(1));
                let _=src.stop(code);
                note(&tap,format!("QUIC STOP_SENDING: direction {side}, code {code}")).await;
                return;
            }
            data=src.read(&mut buffer)=>data
        };
        match read {
            Ok(Some(n))=>{
                if let Some(t)=tap.lock().await.as_mut() {t.data_async(side,&buffer[..n]).await;}
                if let Err(e)=dst.write_all(&buffer[..n]).await {
                    let code=match e {quinn::WriteError::Stopped(c)=>c,_=>1u32.into()};
                    let _=src.stop(code);
                    note(&tap,format!("QUIC forwarding: direction {side}: {e}")).await;
                    return;
                }
            }
            Ok(None)=>{
                eof(&tap,side,true).await;
                if dst.finish().is_ok() {
                    // FIN queued is not FIN delivered. Retain the stream until ACK/reset.
                    if let Err(e)=dst.stopped().await {
                        note(&tap,format!("QUIC final delivery: direction {side}: {e}")).await;
                    }
                }
                return;
            }
            Err(e)=>{
                let code=match e {quinn::ReadError::Reset(c)=>c,_=>1u32.into()};
                let _=dst.reset(code);
                note(&tap,format!("QUIC receive: direction {side}: {e}")).await;
                return;
            }
        }
    }
}
#[derive(Clone)]
struct Context {runtime:Arc<Runtime>,epoch:u64,identity:Connection,alpn:String}
impl Context {
    async fn capture(&self,id:u64,side:usize,uni:bool)->Capture {
        let mut identity=self.identity.clone();
        identity.quic_stream_id=Some(id);identity.quic_alpn=Some(self.alpn.clone());
        let mut tap=self.runtime.tap_at_async(self.epoch,identity,Some(Vec::new()),true).await;
        if uni {if let Some(t)=tap.as_mut() {t.eof_async(1-side,true).await;}}
        Arc::new(Mutex::new(tap))
    }
}
async fn relay(src:quinn::Connection,dst:quinn::Connection,side:usize,uni:bool,ctx:Context)->Result<()> {
    let mut jobs=tokio::task::JoinSet::new();
    let limit=crate::quic_live::FORWARD_STREAMS;
    loop {
        // Each stream space has one allocator. Quinn reports peer streams in ID
        // order (including implicit lower IDs), so opening the peer leg here
        // preserves IDs even when a higher-numbered stream transmits first.
        if jobs.len()>=limit {jobs.join_next().await.unwrap()?;continue;}
        tokio::select! {
            Some(result)=jobs.join_next(),if !jobs.is_empty()=>{result?;}
            next=async {
                if uni {Ok::<_,quinn::ConnectionError>((None,src.accept_uni().await?))}
                else {let (send,recv)=src.accept_bi().await?;Ok((Some(send),recv))}
            }=>{
                let (src_send,src_recv): (Option<SendStream>,RecvStream)=next?;
                let id=src_recv.id();
                let (dst_send,dst_recv)=if uni {(dst.open_uni().await?,None)}
                    else {let (send,recv)=dst.open_bi().await?;(send,Some(recv))};
                if id!=dst_send.id() {return Err("QUIC stream ID preservation failed".into());}
                let tap=ctx.capture(id.into(),side,uni).await;
                jobs.spawn(async move {
                    if let (Some(send),Some(recv))=(src_send,dst_recv) {
                        tokio::join!(copy(src_recv,dst_send,side,tap.clone()),copy(recv,send,1-side,tap));
                    }else {copy(src_recv,dst_send,side,tap).await;}
                });
            }
        }
    }
}
// One capture per connection, allocated only when a decrypted DATAGRAM arrives.
// It has no Stream ID. Both its network queues and capture queues remain bounded.
type DatagramCapture=Arc<OnceCell<Capture>>;
async fn datagrams(src:quinn::Connection,dst:quinn::Connection,side:usize,
    ctx:Context,capture:DatagramCapture)->Result<()> {
    let mut dropped=0u64;
    loop {
        let bytes=src.read_datagram().await?;
        let tap=capture.get_or_init(|| async {
            let mut identity=ctx.identity.clone();
            identity.quic_datagrams=true;
            identity.quic_alpn=Some(ctx.alpn.clone());
            Arc::new(Mutex::new(ctx.runtime.tap_at_async(ctx.epoch,identity,Some(Vec::new()),true).await))
        }).await;
        if let Some(t)=tap.lock().await.as_mut() {t.datagram_async(side,&bytes).await;}
        // Wait for the bounded send queue, avoiding silent eviction of queued
        // packets. This task never blocks independent reliable streams.
        if let Err(error)=dst.send_datagram_wait(bytes).await {
            dropped+=1;
            note(tap,format!("QUIC DATAGRAM forwarding dropped: direction {side}, count {dropped}: {error}")).await;
            if let quinn::SendDatagramError::ConnectionLost(e)=error {return Err(e.into());}
            // An oversized/unsupported unreliable datagram must not tear down
            // the reliable streams. Preserve its captured bytes and report it.
        }
    }
}
pub async fn serve(down:quinn::Connection,up:quinn::Connection,runtime:Arc<Runtime>,
    epoch:u64,identity:Connection,alpn:String)->Result<()> {
    let ctx=Context {runtime,epoch,identity,alpn};
    let mut tasks=tokio::task::JoinSet::new();
    let packets=Arc::new(OnceCell::new());
    for (src,dst,side) in [(down.clone(),up.clone(),0),(up.clone(),down.clone(),1)] {
        for uni in [false,true] {tasks.spawn(relay(src.clone(),dst.clone(),side,uni,ctx.clone()));}
        tasks.spawn(datagrams(src,dst,side,ctx.clone(),packets.clone()));
    }
    let result=tokio::select! {
        biased;
        e=down.closed()=>{close_peer(&up,&e);connection_result("application",e)}
        e=up.closed()=>{close_peer(&down,&e);connection_result("upstream",e)}
        task=tasks.join_next()=>{task.ok_or("QUIC relay ended")??}
    };
    tasks.abort_all();while tasks.join_next().await.is_some() {}
    if let Some(tap)=packets.get() {
        eof(tap,0,result.is_ok()).await;eof(tap,1,result.is_ok()).await;
    }
    result
}
fn close_peer(peer:&quinn::Connection,error:&quinn::ConnectionError) {
    if let quinn::ConnectionError::ApplicationClosed(c)=error {peer.close(c.error_code,&c.reason);}
    else {peer.close(1u32.into(),b"QUIC peer transport closed");}
}
fn connection_result(side:&'static str,error:quinn::ConnectionError)->Result<()> {
    match error {
        quinn::ConnectionError::ApplicationClosed(ref c) if c.error_code==VarInt::from_u32(0)=>Ok(()),
        _=>Err(crate::quic_live::transport_end(side,error))
    }
}
