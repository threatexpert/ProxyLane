use crate::model::*;
use std::collections::{BTreeMap, VecDeque};

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
struct Block {
    stream: u32,
    end_stream: bool,
    bytes: Vec<u8>,
}
#[derive(Default)]
struct Side {
    buffer: Vec<u8>,
    decoder: httlib_hpack::Decoder<'static>,
    block: Option<Block>,
    settings: VecDeque<Option<u32>>,
}
#[derive(Default)]
pub(crate) struct Http2 {
    sides: [Side; 2],
    preface: bool,
    streams: crate::pending::Pending,
    // Keep bounded reset tombstones so in-flight frames in the opposite
    // direction cannot invalidate unrelated streams. HPACK still advances.
    resets: BTreeMap<u32, usize>,
    highest_stream: u32,
    goaway: Option<u32>,
    goaway_reason: Option<String>,
}
fn unpad(mut payload: &[u8], flags: u8) -> Result<&[u8]> {
    if flags & 8 != 0 {
        let pad = *payload.first().ok_or("missing HTTP/2 padding length")? as usize;
        payload = &payload[1..];
        if pad > payload.len() {
            return Err("invalid HTTP/2 padding".into());
        }
        payload = &payload[..payload.len() - pad];
    }
    Ok(payload)
}
fn validate(fields: &Headers, trailers: bool, client: bool) -> Result<()> {
    let mut ordinary = false;
    let mut pseudo = std::collections::HashSet::new();
    for (name, value) in fields {
        if name.is_empty()
            || name
                .bytes()
                .any(|c| c.is_ascii_uppercase() || c <= 32 || c >= 127)
            || value.contains(['\r', '\n', '\0'])
        {
            return Err("invalid HTTP/2 header".into());
        }
        if name.starts_with(':') {
            if trailers || ordinary || !pseudo.insert(name.as_str()) {
                return Err("invalid HTTP/2 pseudo-header ordering/duplicate".into());
            }
            let allowed = if client {
                matches!(
                    name.as_str(),
                    ":method" | ":scheme" | ":authority" | ":path"
                )
            } else {
                name == ":status"
            };
            if !allowed {
                return Err("unsupported HTTP/2 pseudo-header".into());
            }
        } else {
            ordinary = true;
        }
        if matches!(
            name.as_str(),
            "connection" | "proxy-connection" | "keep-alive" | "transfer-encoding" | "upgrade"
        ) || (name == "te" && !value.eq_ignore_ascii_case("trailers"))
        {
            return Err("connection-specific HTTP/2 header".into());
        }
    }
    content_length(fields)?;
    Ok(())
}

impl Http2 {
    pub(crate) fn feed(
        &mut self,
        side: usize,
        data: &[u8],
        limits: &Limits,
        out: &mut Vec<Exchange>,
        cache: Option<&crate::cache::PayloadCache>,
    ) -> Result<()> {
        self.streams.configure(cache,limits.pending);
        self.sides[side].buffer.extend_from_slice(data);
        if side == 0 && !self.preface {
            let buffer = &mut self.sides[side].buffer;
            let length = buffer.len().min(PREFACE.len());
            if buffer[..length] != PREFACE[..length] {
                return Err(
                    "missing HTTP/2 client preface (capture must start at connection beginning)"
                        .into(),
                );
            }
            if buffer.len() < PREFACE.len() {
                return Ok(());
            }
            buffer.drain(..PREFACE.len());
            self.preface = true;
        }
        loop {
            let buffer = &mut self.sides[side].buffer;
            if buffer.len() < 9 {
                break;
            }
            let length =
                ((buffer[0] as usize) << 16) | ((buffer[1] as usize) << 8) | buffer[2] as usize;
            if length > limits.frame {
                return Err("HTTP/2 frame limit".into());
            }
            if buffer.len() < length + 9 {
                break;
            }
            let kind = buffer[3];
            let flags = buffer[4];
            let stream = u32::from_be_bytes(buffer[5..9].try_into().unwrap()) & 0x7fff_ffff;
            let payload = buffer[9..9 + length].to_vec();
            buffer.drain(..9 + length);
            self.frame(side, kind, flags, stream, &payload, limits, out, cache)?;
        }
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    fn frame(
        &mut self,
        side: usize,
        kind: u8,
        flags: u8,
        stream: u32,
        payload: &[u8],
        limits: &Limits,
        out: &mut Vec<Exchange>,
        cache: Option<&crate::cache::PayloadCache>,
    ) -> Result<()> {
        if let Some(block) = &self.sides[side].block {
            if kind != 9 || stream != block.stream {
                return Err("interleaved/mismatched HTTP/2 CONTINUATION".into());
            }
        }
        match kind {
            0 => {
                let data = unpad(payload, flags)?;
                if self.resets.get(&stream).is_some_and(|sender| *sender != side) {
                    return Ok(());
                }
                let exchange = self
                    .streams
                    .get_mut(&(stream as u64))?
                    .ok_or("DATA on unknown HTTP/2 stream")?;
                let head =
                    exchange.request.as_ref().and_then(|m| m.method.as_deref()) == Some("HEAD");
                let message = if side == 0 {
                    exchange.request.as_mut()
                } else {
                    exchange.response.as_mut()
                }
                .ok_or("DATA before headers")?;
                if message.complete {
                    return Err("DATA after END_STREAM".into());
                }
                if side == 1
                    && (head || message.status == Some(204) || message.status == Some(304))
                    && !data.is_empty()
                {
                    return Err("DATA on bodyless response".into());
                }
                message.append(data, limits);
                if flags & 1 != 0 {
                    self.end_stream(side, stream, out)?;
                }
            }
            1 => {
                if stream == 0 || stream % 2 == 0 {
                    return Err("invalid/unsupported HTTP/2 stream ID".into());
                }
                let mut data = unpad(payload, flags)?;
                if flags & 32 != 0 {
                    if data.len() < 5 {
                        return Err("incomplete HEADERS priority".into());
                    }
                    data = &data[5..];
                }
                if data.len() > limits.headers {
                    return Err("HPACK block limit".into());
                }
                self.sides[side].block = Some(Block {
                    stream,
                    end_stream: flags & 1 != 0,
                    bytes: data.to_vec(),
                });
                if flags & 4 != 0 {
                    self.headers(side, limits, out, cache)?;
                }
            }
            9 => {
                let block = self.sides[side]
                    .block
                    .as_mut()
                    .ok_or("unexpected CONTINUATION")?;
                if block.bytes.len() + payload.len() > limits.headers {
                    return Err("HPACK block limit".into());
                }
                block.bytes.extend_from_slice(payload);
                if flags & 4 != 0 {
                    self.headers(side, limits, out, cache)?;
                }
            }
            4 => {
                if stream != 0 {
                    return Err("SETTINGS on nonzero stream".into());
                }
                if flags & 1 != 0 {
                    if !payload.is_empty() {
                        return Err("nonempty SETTINGS ACK".into());
                    }
                    let size = self.sides[side]
                        .settings
                        .pop_front()
                        .ok_or("SETTINGS ACK without captured SETTINGS")?;
                    if let Some(size) = size {
                        self.sides[side].decoder.set_max_dynamic_size(size);
                    }
                } else {
                    if payload.len() % 6 != 0 {
                        return Err("invalid SETTINGS length".into());
                    }
                    let mut size = None;
                    for pair in payload.chunks_exact(6) {
                        if pair[..2] == [0, 1] {
                            let value = u32::from_be_bytes(pair[2..].try_into().unwrap());
                            if value > limits.hpack_table {
                                return Err("HPACK table limit".into());
                            }
                            size = Some(value);
                        }
                    }
                    let queue = &mut self.sides[1 - side].settings;
                    if queue.len() >= 16 {
                        return Err("unacknowledged SETTINGS limit".into());
                    }
                    queue.push_back(size);
                }
            }
            3 => {
                if stream == 0 || payload.len() != 4 {
                    return Err("invalid RST_STREAM".into());
                }
                if stream <= self.highest_stream {
                    self.resets.entry(stream).or_insert(side);
                    if self.resets.len() > 1024 { self.resets.pop_first(); }
                }
                if let Some(mut exchange) = self.streams.remove(&(stream as u64))? {
                    exchange.problem = Some(format!(
                        "RST_STREAM {} from {}",
                        u32::from_be_bytes(payload.try_into().unwrap()),
                        if side==0 {"application"} else {"upstream"}
                    ));
                    exchange.finish_cache();
                    out.push(exchange);
                }
            }
            7 => {
                if stream != 0 || payload.len() < 8 {
                    return Err("invalid GOAWAY".into());
                }
                let last = u32::from_be_bytes(payload[..4].try_into().unwrap()) & 0x7fff_ffff;
                let code = u32::from_be_bytes(payload[4..8].try_into().unwrap());
                self.goaway_reason=Some(format!("HTTP/2 GOAWAY {code} from {} (last stream {last})",if side==0 {"application"}else{"upstream"}));
                if let Some(cache)=cache {cache.connection_event(serde_json::json!({"type":"http2_goaway","side":side,"last_stream_id":last,"error_code":code}));}
                if side == 1 {
                    self.goaway = Some(self.goaway.map_or(last, |old| old.min(last)));
                    let ids=self.streams.keys()?;
                    for id in ids {
                        let id=id?;if id<=last as u64 {continue;}
                        let exchange = self.streams.get_mut(&id)?.unwrap();
                        exchange.problem = Some(format!("GOAWAY {code}: stream not processed"));
                        // A request body may still be in flight on the other leg.
                        // Retain it until END_STREAM/EOF, even though no response is expected.
                        if !exchange.request.as_ref().is_some_and(|m|m.complete) {continue;}
                        let exchange = self.streams.remove(&id)?.unwrap();
                        exchange.finish_cache();
                        if cache.is_some_and(crate::cache::PayloadCache::is_recording) && out.len()>=limits.pending {out.remove(0);}
                        out.push(exchange);
                    }
                }
                // A peer-reported error is a valid frame, not parser failure.
                // Streams <= last_stream_id may still deliver their final data.
            }
            5 => return Err("HTTP/2 server push not implemented".into()),
            2 if stream == 0 || payload.len() != 5 => return Err("invalid PRIORITY".into()),
            6 if stream != 0 || payload.len() != 8 => return Err("invalid PING".into()),
            8 if payload.len() != 4 => return Err("invalid WINDOW_UPDATE".into()),
            _ => {} // Unknown extension frames do not carry HTTP message data.
        }
        Ok(())
    }
    fn headers(
        &mut self,
        side: usize,
        limits: &Limits,
        out: &mut Vec<Exchange>,
        cache: Option<&crate::cache::PayloadCache>,
    ) -> Result<()> {
        let mut block = self.sides[side].block.take().unwrap();
        crate::hpack_guard::validate(&block.bytes)?;
        let mut fields = Vec::new();
        let mut size = 0;
        while !block.bytes.is_empty() {
            let mut one = Vec::with_capacity(1);
            self.sides[side]
                .decoder
                .decode_exact(&mut block.bytes, &mut one)
                .map_err(|e| format!("HPACK: {e}"))?;
            for (name, value, _) in one {
                size += name.len() + value.len() + 32;
                if size > limits.headers || fields.len() >= limits.header_count {
                    return Err("decoded HTTP/2 header limit".into());
                }
                let name = String::from_utf8(name).map_err(|_| "non-ASCII HTTP/2 header name")?;
                let value = value.iter().map(|&b| char::from(b)).collect();
                fields.push((name, value));
            }
        }
        let id = block.stream as u64;
        // Decode even discarded HEADERS/CONTINUATION blocks above: their
        // dynamic table entries may be referenced by the next live stream.
        if self.resets.get(&block.stream).is_some_and(|sender| *sender != side) {
            return Ok(());
        }
        if side == 0 && !self.streams.contains_key(&id) {
            if block.stream <= self.highest_stream {
                return Err("reused/closed HTTP/2 stream".into());
            }
            if self.streams.limited() {
                return Err("pending exchange limit".into());
            }
            self.highest_stream = block.stream;
            self.streams.insert(
                id,
                Exchange {
                    id,
                    ..Exchange::default()
                },
            )?;
            self.streams.get_mut(&id)?.unwrap().start_cache(cache);
            if self.goaway.is_some_and(|last| block.stream>last) {
                self.streams.get_mut(&id)?.unwrap().problem=Some("GOAWAY: request in flight was not processed".into());
            }
        }
        let exchange = self
            .streams
            .get_mut(&id)?
            .ok_or("response without captured request")?;
        let slot = if side == 0 {
            &mut exchange.request
        } else {
            &mut exchange.response
        };
        validate(&fields, slot.is_some(), side == 0)?;
        if let Some(message) = slot {
            if message.complete || !block.end_stream {
                return Err("invalid HTTP/2 trailers/END_STREAM".into());
            }
            message.trailers = fields;
        } else {
            let get = |name: &str| {
                fields
                    .iter()
                    .find(|(n, _)| n == name)
                    .map(|(_, v)| v.clone())
            };
            let mut message = Message::default();
            if side == 0 {
                let method = get(":method")
                    .filter(|s| !s.is_empty())
                    .ok_or("missing :method")?;
                if method == "CONNECT" {
                    return Err("HTTP/2 CONNECT not implemented".into());
                }
                message.method = Some(method);
                message.target = Some(
                    get(":path")
                        .filter(|s| !s.is_empty())
                        .ok_or("missing :path")?,
                );
                if get(":scheme").is_none() {
                    return Err("missing :scheme".into());
                }
            } else {
                let status = get(":status").ok_or("missing :status")?;
                if status.len() != 3 || !status.bytes().all(|b| b.is_ascii_digit()) {
                    return Err("invalid :status".into());
                }
                let status: u16 = status.parse().map_err(|_| "invalid :status")?;
                if status < 100 || status == 101 || status > 599 {
                    return Err("invalid :status".into());
                }
                message.status = Some(status);
            }
            message.headers = fields;
            if message.status.is_some_and(|s| s < 200) {
                if block.end_stream {
                    return Err("informational response with END_STREAM".into());
                }
                if exchange.informational.len() >= 16 {
                    return Err("informational response limit".into());
                }
                message.complete = true;
                exchange.informational.push(message);
                return Ok(());
            }
            *slot = Some(message);
            exchange.bind_cache(side);
        }
        if block.end_stream {
            self.end_stream(side, block.stream, out)?;
        }
        Ok(())
    }
    fn end_stream(&mut self, side: usize, stream: u32, out: &mut Vec<Exchange>) -> Result<()> {
        let id = stream as u64;
        let exchange = self.streams.get_mut(&id)?.unwrap();
        let head = exchange.request.as_ref().and_then(|r| r.method.as_deref()) == Some("HEAD");
        let message = if side == 0 {
            exchange.request.as_mut()
        } else {
            exchange.response.as_mut()
        }
        .unwrap();
        let bodyless =
            side == 1 && (head || message.status == Some(304) || message.status == Some(204));
        if !bodyless && content_length(&message.headers)?.is_some_and(|n| n != message.body_bytes) {
            return Err("HTTP/2 Content-Length mismatch".into());
        }
        message.complete = true;
        if exchange.ready() || (side==0 && self.goaway.is_some_and(|last|stream>last)) {
            let exchange = self.streams.remove(&id)?.unwrap();
            exchange.finish_cache();
            out.push(exchange);
        }
        Ok(())
    }
    pub(crate) fn eof(&mut self, side: usize) -> Result<()> {
        if !self.sides[side].buffer.is_empty() || self.sides[side].block.is_some() {
            return Err("incomplete HTTP/2 frame/header block at EOF".into());
        }
        // ALPN can select h2 on an unused preconnection. No client bytes is
        // not a truncated preface; a partial preface is caught by buffer above.
        Ok(())
    }
    pub(crate) fn drain(&mut self, reason: &str) -> Vec<Exchange> {
        self.streams.drain(&self.goaway_reason.as_ref().map(|g|format!("{g}; {reason}")).unwrap_or_else(||reason.into()))
    }
}
