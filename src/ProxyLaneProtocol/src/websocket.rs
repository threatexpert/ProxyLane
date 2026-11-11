//! Passive RFC 6455 messages. Wire bytes are retained separately in recordings.
//! Payloads stream to the cache, including permessage-deflate with context takeover.
use crate::{cache::{CacheRef,PayloadCache},model::*};
#[derive(Clone,Default)]
pub(crate) struct Config {pub deflate:bool,pub reset:[bool;2],pub target:String}
pub(crate) fn negotiated(request:&Message,response:&Message)->Result<Option<Config>> {
    if response.status!=Some(101) || !tokens(&response.headers,"upgrade").iter().any(|s|s=="websocket") {return Ok(None);}
    if request.method.as_deref()!=Some("GET") || !tokens(&request.headers,"upgrade").iter().any(|s|s=="websocket") {
        return Err("WebSocket upgrade without matching request".into());
    }
    let mut c=Config {target:request.target.clone().unwrap_or_default(),..Default::default()};
    for (_,v) in response.headers.iter().filter(|(k,_)|k.eq_ignore_ascii_case("sec-websocket-extensions")) {
        for extension in v.split(',') {
            let mut parts=extension.split(';').map(str::trim);
            if parts.next()!=Some("permessage-deflate") {return Err("unsupported WebSocket extension".into());}
            c.deflate=true;
            for p in parts {
                match p {
                    "client_no_context_takeover"=>c.reset[0]=true,
                    "server_no_context_takeover"=>c.reset[1]=true,
                    _ if p.starts_with("client_max_window_bits=") || p.starts_with("server_max_window_bits=")=>{
                        let n=p.split('=').nth(1).unwrap().parse::<u8>().map_err(|_|"invalid WebSocket window")?;
                        if !(8..=15).contains(&n){return Err("invalid WebSocket window".into());}
                    },
                    _=>return Err("unsupported permessage-deflate parameter".into()),
                }
            }
        }
    }
    Ok(Some(c))
}
struct Frame {remaining:u64,offset:u64,mask:Option<[u8;4]>,fin:bool,control:bool}
struct Active {exchange:Exchange,compressed:bool,fragments:u64}
#[derive(Default)]
struct Side {buffer:Vec<u8>,frame:Option<Frame>,message:Option<Active>,control:Option<Active>,decoder:Option<flate2::Decompress>}
pub(crate) struct WebSocket {config:Config,sides:[Side;2],next:u64,wire:Option<CacheRef>,wire_bytes:[u64;2]}
impl WebSocket {
    pub fn new(config:Config,cache:Option<&PayloadCache>)->Self {
        let wire=cache.filter(|c|c.is_recording()).map(|c|c.stream());
        Self {config,sides:Default::default(),next:0,wire,wire_bytes:[0,0]}
    }
    fn message<'a>(active:&'a mut Active,side:usize)->&'a mut Message {
        if side==0 {active.exchange.request.as_mut().unwrap()}else{active.exchange.response.as_mut().unwrap()}
    }
    fn append(side:&mut Side,index:usize,control:bool,bytes:&[u8],limits:&Limits)->Result<()> {
        let active=if control {side.control.as_mut()}else{side.message.as_mut()}.ok_or("missing WebSocket message")?;
        if !active.compressed {Self::message(active,index).append(bytes,limits);return Ok(());}
        let decoder=side.decoder.as_mut().ok_or("missing WebSocket inflater")?;
        let mut pos=0;
        loop {
            let mut output=[0;8192];let before=decoder.total_in();let out_before=decoder.total_out();
            let status=decoder.decompress(&bytes[pos..],&mut output,flate2::FlushDecompress::Sync).map_err(|e|format!("WebSocket deflate: {e}"))?;
            let consumed=(decoder.total_in()-before) as usize;let n=(decoder.total_out()-out_before) as usize;pos+=consumed;
            Self::message(active,index).append(&output[..n],limits);
            if status==flate2::Status::StreamEnd {return Err("unexpected final deflate block in WebSocket message".into());}
            if pos==bytes.len() && n<output.len(){break;}
            if consumed==0 && n==0 {return Err("WebSocket inflater made no progress".into());}
        }
        Ok(())
    }
    pub fn feed(&mut self,index:usize,bytes:&[u8],limits:&Limits,cache:Option<&PayloadCache>,out:&mut Vec<Exchange>)->Result<()> {
        if let Some(w)=&self.wire {w.append_stream(if index==0{Direction::Client}else{Direction::Server},bytes);}
        self.wire_bytes[index]+=bytes.len() as u64;
        let s=&mut self.sides[index];s.buffer.extend_from_slice(bytes);
        loop {
            if s.frame.is_none() {
                let b=&s.buffer;if b.len()<2{break;}
                let fin=b[0]&128!=0;let compressed=b[0]&64!=0;let op=b[0]&15;let masked=b[1]&128!=0;
                if b[0]&48!=0 || (masked!=(index==0)) {return Err("invalid WebSocket reserved bits or mask direction".into());}
                let extra=match b[1]&127 {126=>2,127=>8,_=>0};let header=2+extra+if masked {4}else{0};
                if b.len()<header {break;}
                let n=match extra {2=>u16::from_be_bytes(b[2..4].try_into().unwrap()) as u64,8=>u64::from_be_bytes(b[2..10].try_into().unwrap()),_=>u64::from(b[1]&127)};
                if n>>63!=0 || (extra==2&&n<126) || (extra==8&&n<65536) {return Err("invalid WebSocket payload length".into());}
                let control=op>=8;
                if control && (!fin || n>125 || compressed || ![8,9,10].contains(&op)) {return Err("invalid WebSocket control frame".into());}
                if op==0 {
                    if compressed || s.message.is_none(){return Err("unexpected WebSocket continuation".into());}
                    s.message.as_mut().unwrap().fragments+=1;
                } else {
                    if !control && (![1,2].contains(&op) || s.message.is_some()){return Err("invalid WebSocket message sequence".into());}
                    if compressed && !self.config.deflate {return Err("unnegotiated WebSocket compression".into());}
                    if compressed && (s.decoder.is_none() || self.config.reset[index]) {s.decoder=Some(flate2::Decompress::new(false));}
                    self.next+=1;
                    let m=Message {method:Some(match op {1=>"TEXT",2=>"BINARY",8=>"CLOSE",9=>"PING",10=>"PONG",_=>unreachable!()}.into()),
                        target:Some(self.config.target.clone()),observed_start_unix_ms:crate::recording::observed_ms(),..Default::default()};
                    let mut e=Exchange {id:self.next,..Default::default()};
                    if index==0 {e.request=Some(m);}else{e.response=Some(m);}
                    e.start_cache(cache);if index==1 {e.bind_cache(1);}
                    let active=Active {exchange:e,compressed,fragments:1};
                    if control{s.control=Some(active);}else{s.message=Some(active);}
                }
                let mask=if masked {Some(b[2+extra..header].try_into().unwrap())}else{None};
                s.frame=Some(Frame {remaining:n,offset:0,mask,fin,control});s.buffer.drain(..header);
            }
            let f=s.frame.as_mut().unwrap();let count=f.remaining.min(s.buffer.len() as u64) as usize;
            if count>0 {
                let mut bytes:Vec<u8>=s.buffer.drain(..count).collect();
                if let Some(mask)=f.mask {for(i,b)in bytes.iter_mut().enumerate(){*b^=mask[((f.offset+i as u64)%4) as usize];}}
                f.remaining-=count as u64;f.offset+=count as u64;let control=f.control;
                Self::append(s,index,control,&bytes,limits)?;
            }
            if s.frame.as_ref().unwrap().remaining!=0 {break;}
            let frame=s.frame.take().unwrap();
            if frame.fin {
                if !frame.control && s.message.as_ref().is_some_and(|m|m.compressed) {Self::append(s,index,false,&[0,0,255,255],limits)?;}
                let mut active=if frame.control{s.control.take()}else{s.message.take()}.unwrap();
                Self::message(&mut active,index).complete=true;
                if let Some(c)=&active.exchange.cache {c.record(serde_json::json!({"type":"websocket_message","message_id":active.exchange.id,
                    "side":index,"compressed":active.compressed,"fragments":active.fragments,
                    "wire_cache_id":self.wire.as_ref().map(CacheRef::id)}));}
                active.exchange.finish_cache();out.push(active.exchange);
            }
            if s.buffer.is_empty(){break;}
        }
        Ok(())
    }
    pub fn drain(&mut self,reason:&str)->Vec<Exchange> {
        let mut out=Vec::new();
        for s in &mut self.sides {for a in [&mut s.message,&mut s.control] {if let Some(mut a)=a.take(){a.exchange.problem=Some(reason.into());a.exchange.finish_cache();out.push(a.exchange);}}}
        if let Some(w)=self.wire.take(){w.finish_stream(self.wire_bytes,true);}
        out
    }
}
