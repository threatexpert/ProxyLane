use crate::model::{tokens, Headers, Result};
use std::io::Read;

fn bounded(reader: impl Read, limit: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    reader
        .take(limit as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|e| e.to_string())?;
    if out.len() > limit {
        return Err("decoded body limit".into());
    }
    Ok(out)
}

// Use the low-level flate2 state to require StreamEnd. Read adapters can accept
// premature EOF for deflate, which would falsely label a damaged body complete.
fn deflate(input: &[u8], zlib: bool, limit: usize) -> Result<Vec<u8>> {
    let mut decoder = flate2::Decompress::new(zlib);
    let mut output = Vec::new();
    loop {
        let mut chunk = [0; 8192];
        let before_in = decoder.total_in();
        let before_out = decoder.total_out();
        let remaining = &input[before_in as usize..];
        let status = decoder
            .decompress(remaining, &mut chunk, flate2::FlushDecompress::None)
            .map_err(|e| e.to_string())?;
        let written = (decoder.total_out() - before_out) as usize;
        if output.len() + written > limit {
            return Err("decoded body limit".into());
        }
        output.extend_from_slice(&chunk[..written]);
        if status == flate2::Status::StreamEnd {
            return if decoder.total_in() as usize == input.len() {
                Ok(output)
            } else {
                Err("trailing deflate data".into())
            };
        }
        if before_in == decoder.total_in() && written == 0 {
            return Err("incomplete deflate stream".into());
        }
    }
}

fn brotli_body(input: &[u8], limit: usize) -> Result<Vec<u8>> {
    let mut state = brotli::BrotliState::new(
        brotli::HeapAlloc::default(),
        brotli::HeapAlloc::default(),
        brotli::HeapAlloc::default(),
    );
    let mut available_in = input.len();
    let mut input_offset = 0;
    let mut total = 0;
    let mut output = Vec::new();
    loop {
        let mut chunk = [0; 8192];
        let mut available_out = chunk.len();
        let mut offset = 0;
        let result = brotli::BrotliDecompressStream(
            &mut available_in,
            &mut input_offset,
            input,
            &mut available_out,
            &mut offset,
            &mut chunk,
            &mut total,
            &mut state,
        );
        if output.len() + offset > limit {
            return Err("decoded body limit".into());
        }
        output.extend_from_slice(&chunk[..offset]);
        match result {
            brotli::BrotliResult::ResultSuccess => {
                return if available_in == 0 {
                    Ok(output)
                } else {
                    Err("trailing Brotli data".into())
                }
            }
            brotli::BrotliResult::ResultFailure => return Err("invalid Brotli stream".into()),
            brotli::BrotliResult::NeedsMoreInput => return Err("incomplete Brotli stream".into()),
            brotli::BrotliResult::NeedsMoreOutput => {}
        }
    }
}

pub(crate) fn body(headers: &Headers, input: &[u8], limit: usize) -> Result<Vec<u8>> {
    if input.len() > limit {
        return Err("decoded body limit".into());
    }
    let encodings = tokens(headers, "content-encoding");
    if encodings.len() > 4 {
        return Err("too many Content-Encoding layers".into());
    }
    let mut data = input.to_vec();
    for encoding in encodings.iter().rev() {
        data = match encoding.as_str() {
            "identity" => data,
            "gzip" | "x-gzip" => {
                bounded(flate2::read::MultiGzDecoder::new(data.as_slice()), limit)?
            }
            "deflate" => {
                // RFC deflate is zlib-wrapped. Only use the legacy raw format
                // when the two-byte zlib signature is absent, never on errors.
                let zlib = data.len() >= 2
                    && data[0] & 15 == 8
                    && data[0] >> 4 <= 7
                    && u16::from_be_bytes([data[0], data[1]]) % 31 == 0;
                deflate(&data, zlib, limit)?
            }
            "br" => brotli_body(&data, limit)?,
            "zstd" => {
                let mut decoder =
                    zstd::stream::read::Decoder::new(data.as_slice()).map_err(|e| e.to_string())?;
                decoder.window_log_max(23).map_err(|e| e.to_string())?;
                bounded(decoder, limit)?
            }
            other => return Err(format!("unsupported Content-Encoding: {other}")),
        };
    }
    Ok(data)
}

/// A view may expose a useful prefix of an unfinished gzip stream, but must
/// never present it as integrity-verified. CRC/format errors remain failures.
pub(crate) fn preview(headers:&Headers,input:&[u8],limit:usize)->Result<(Vec<u8>,Option<String>)> {
    match body(headers,input,limit) {
        Ok(data)=>Ok((data,None)),
        Err(error)=>{
            let enc=tokens(headers,"content-encoding");
            if input.len()>limit || !(enc==["gzip"] || enc==["x-gzip"]) {return Err(error);}
            let mut reader=flate2::read::MultiGzDecoder::new(input);
            let mut out=Vec::new();let mut buf=[0;8192];
            loop {
                match reader.read(&mut buf) {
                    Ok(0)=>return Err(error),
                    Ok(n)=>{if out.len()+n>limit{return Err("decoded body limit".into());}out.extend_from_slice(&buf[..n]);}
                    Err(e) if e.kind()==std::io::ErrorKind::UnexpectedEof && !out.is_empty()=>return Ok((out,Some(
                        "Gzip stream did not finish; showing decoded data with unverified completeness and integrity.".into()))),
                    Err(_)=>return Err(error),
                }
            }
        }
    }
}

#[cfg(test)]
mod preview_tests {
    use super::*;
    use std::io::Write;
    #[test]
    fn unfinished_gzip_is_only_a_warned_preview() {
        let h=vec![("content-encoding".into(),"gzip".into())];
        let mut gz=flate2::write::GzEncoder::new(Vec::new(),flate2::Compression::default());
        gz.write_all(br#"{"message":"complete JSON, unfinished gzip"}"#).unwrap();gz.flush().unwrap();
        let partial=gz.get_ref().clone();
        assert!(body(&h,&partial,4096).is_err());
        let(data,note)=preview(&h,&partial,4096).unwrap();
        assert!(note.is_some());assert!(serde_json::from_slice::<serde_json::Value>(&data).is_ok());
        let mut good=gz.finish().unwrap();assert!(preview(&h,&good,4096).unwrap().1.is_none());
        let n=good.len();good[n-8]^=1;assert!(preview(&h,&good,4096).is_err(),"CRC corruption must not be accepted");
        assert!(preview(&h,&partial,8).is_err(),"preview limits remain enforced");
    }
}
