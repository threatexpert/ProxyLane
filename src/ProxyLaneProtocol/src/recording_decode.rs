//! Full recorded HTTP bodies, decoded from disk with bounded buffers.
//! Runs on the existing disk worker: its bounded queue provides backpressure.
use crate::{cache::BodyInfo, model::tokens, recording::{self,Journal}};
use serde_json::json;
use std::{fs::{self,File,OpenOptions},io::{self,Read,Write,BufRead,BufReader},path::Path,time::{Instant,Duration},sync::{Arc,Mutex}};

pub fn relative(id:u64,side:usize)->String {
    recording::payload_relative(id,side).replace(".bin",".decoded.bin")
}
fn invalid(message:&str)->io::Error {io::Error::new(io::ErrorKind::InvalidData,message)}
struct Source {file:File,error:Arc<Mutex<Option<String>>>}
impl Read for Source {
    fn read(&mut self,bytes:&mut[u8])->io::Result<usize> {
        let result=self.file.read(bytes);
        if let Err(e)=&result {*self.error.lock().unwrap_or_else(|e|e.into_inner())=Some(format!("decode source read failed: {e}"));}
        result
    }
}

// The flate2 Read adapter accepts a truncated deflate stream. Require StreamEnd.
struct Deflate {input:BufReader<Box<dyn Read>>,state:flate2::Decompress,ended:bool}
impl Deflate {
    fn new(input:Box<dyn Read>)->io::Result<Self> {
        let mut input=BufReader::with_capacity(16384,input);
        let b=input.fill_buf()?;
        let zlib=b.len()>=2 && b[0]&15==8 && b[0]>>4<=7 && u16::from_be_bytes([b[0],b[1]])%31==0;
        Ok(Self {input,state:flate2::Decompress::new(zlib),ended:false})
    }
}
impl Read for Deflate {
    fn read(&mut self,out:&mut[u8])->io::Result<usize> {
        if out.is_empty(){return Ok(0);}
        if self.ended {return if self.input.fill_buf()?.is_empty(){Ok(0)}else{Err(invalid("trailing deflate data"))};}
        loop {
            let bytes=self.input.fill_buf()?;
            let before=self.state.total_in();let written=self.state.total_out();
            let status=self.state.decompress(bytes,out,flate2::FlushDecompress::None).map_err(|e|invalid(&format!("deflate: {e}")))?;
            let used=(self.state.total_in()-before) as usize;let n=(self.state.total_out()-written) as usize;
            self.input.consume(used);
            if status==flate2::Status::StreamEnd {self.ended=true;}
            if n!=0{return Ok(n);}
            if self.ended{return self.read(out);}
            if used==0{return Err(io::Error::new(io::ErrorKind::UnexpectedEof,"incomplete deflate stream"));}
        }
    }
}
struct Brotli {decoder:brotli::Decompressor<Box<dyn Read>>,ended:bool}
impl Read for Brotli {
    fn read(&mut self,out:&mut[u8])->io::Result<usize> {
        if out.is_empty() || self.ended{return Ok(0);}
        let n=self.decoder.read(out)?;
        if n==0 {
            // A second call checks buffered trailing bytes; also verify the underlying EOF.
            let mut b=[0];
            if self.decoder.read(&mut b)?!=0 || self.decoder.get_mut().read(&mut b)?!=0 {
                return Err(invalid("trailing Brotli data"));
            }
            self.ended=true;
        }
        Ok(n)
    }
}
pub(crate) fn reader(input:Box<dyn Read>,encodings:&[String])->io::Result<Box<dyn Read>> {
    // Bound decoder states and stack depth independently from the body size.
    if encodings.len()>4 {return Err(invalid("unsupported Content-Encoding nesting (more than four layers)"));}
    let mut reader=input;
    for encoding in encodings.iter().rev() {
        reader=match encoding.as_str() {
            "identity"=>reader,
            "gzip"|"x-gzip"=>Box::new(flate2::read::MultiGzDecoder::new(reader)),
            "deflate"=>Box::new(Deflate::new(reader)?),
            "br"=>Box::new(Brotli {decoder:brotli::Decompressor::new(reader,16384),ended:false}),
            "zstd"=>{
                let mut decoder=zstd::stream::read::Decoder::new(reader)?;
                decoder.window_log_max(27)?; // <=128 MiB per decoder, no output-size limit
                Box::new(decoder)
            },
            other=>return Err(invalid(&format!("unsupported Content-Encoding: {other}"))),
        };
    }
    Ok(reader)
}

pub(crate) fn run(journal:&mut Journal,root:&Path,id:u64,side:usize,info:&BodyInfo,stored:u64) {
    if !journal.state.accepting() || !info.present{return;}
    let encodings=tokens(&info.headers,"content-encoding");
    let compressed=!info.bodyless && encodings.iter().any(|e|e!="identity");
    let original=recording::payload_relative(id,side);
    let file=if compressed {relative(id,side)}else{original.clone()};
    let mut value=json!({"type":"body_decode","cache_id":id,"side":side,"source_file":original,
        "file":file,"encodings":encodings,"source_bytes":stored,"expected_source_bytes":info.bytes,
        "source_complete":info.complete && stored==info.bytes,"decoded_bytes":0,
        "state":"decoding","reused_source":!compressed,"error":null});
    let source_complete=info.complete && stored==info.bytes;
    let mut total=0u64;
    let mut storage_failure=false;
    let source_error=Arc::new(Mutex::new(None));
    let result=(||->Result<(),String>{
        // Empty/uncompressed bodies reuse the source already committed by the
        // writer. There is no long-running decode to checkpoint: publish the
        // terminal result below, without a transient event + forced journal sync.
        if !compressed {total=stored;return Ok(());}
        journal.decode_update(value.clone(),false)?;
        journal.flush()?;
        // Source writes precede Finished on the same queue. Do not read growing data.
        let input:Box<dyn Read>=if stored==0 {Box::new(io::empty())}else {
            Box::new(Source {file:File::open(root.join(&original)).map_err(|e|{storage_failure=true;format!("decode source read failed: {e}")})?,error:source_error.clone()})
        };
        let mut decoder=reader(input,&encodings).map_err(|e|e.to_string())?;
        let path=root.join(&file);
        fs::create_dir_all(path.parent().unwrap()).map_err(|e|{storage_failure=true;e.to_string()})?;
        let mut output=OpenOptions::new().write(true).create_new(true).open(path)
            .map_err(|e|{storage_failure=true;format!("decoded payload create failed: {e}")})?;
        let mut buffer=[0;16384];let mut checkpoint=Instant::now();
        let decoded=(||->Result<(),String>{
            loop {
                let n=decoder.read(&mut buffer).map_err(|e|e.to_string())?;
                if n==0{break;}
                journal.charge(n as u64)?;
                if let Err(e)=output.write_all(&buffer[..n]) {
                    total=output.metadata().map_or(total,|m|m.len());storage_failure=true;
                    return Err(format!("decoded payload write failed: {e}"));
                }
                total+=n as u64;
                if checkpoint.elapsed()>=Duration::from_secs(1) {
                    output.sync_data().map_err(|e|{storage_failure=true;e.to_string()})?;
                    value["decoded_bytes"]=total.into();
                    journal.decode_update(value.clone(),false)?;
                    journal.flush()?;checkpoint=Instant::now();
                }
            }
            Ok(())
        })();
        output.sync_data().map_err(|e|{storage_failure=true;format!("decoded payload sync failed: {e}")})?;
        decoded
    })();
    if let Some(error)=&*source_error.lock().unwrap_or_else(|e|e.into_inner()) {journal.state.stop(error);}
    if storage_failure {journal.state.stop(result.as_ref().err().map_or("decoded payload I/O failure",String::as_str));}
    value["decoded_bytes"]=total.into();
    value["state"]=if result.is_ok() && source_complete {"complete"}else if total!=0 {"partial"}else{"failed"}.into();
    value["error"]=result.err().or_else(||(!source_complete).then(||"HTTP body incomplete; decoded content is not confirmed complete".into())).into();
    // Even if disk/capacity prevents a terminal event, the finishing reserve persists
    // this last result and aggregate counters in manifest.json. Never claim success.
    if let Err(e)=journal.decode_update(value.clone(),true) {journal.state.stop(&e);}
}
