use crate::model::*;
use crate::pending::Pending;

enum Framing {
    Fixed(u64),
    UntilEof,
    ChunkSize,
    ChunkData(u64),
    ChunkEnd,
    Trailers,
}
struct Active {
    id: u64,
    framing: Framing,
}
#[derive(Default)]
pub(crate) struct Http1 {
    upgrade:Option<crate::websocket::Config>,
    buffers: [Vec<u8>; 2],
    active: [Option<Active>; 2],
    pending: Pending,
    requests: u64,
    responses: u64,
}

fn text(bytes: &[u8]) -> String {
    // HTTP/1 field values are octets, not necessarily UTF-8. ISO-8859-1 gives
    // lossless byte-to-character mapping; bodies retain their original bytes.
    bytes.iter().map(|&b| char::from(b)).collect()
}
fn headers(input: &[u8], client: bool, limits: &Limits) -> Result<Option<(usize, Message)>> {
    let mut fields = vec![httparse::EMPTY_HEADER; limits.header_count];
    let mut message = Message::default();
    let (parsed, fields) = if client {
        let mut request = httparse::Request::new(&mut fields);
        let parsed = request
            .parse(input)
            .map_err(|e| format!("HTTP/1 request: {e}"))?;
        message.method = request.method.map(str::to_owned);
        message.target = request.path.map(str::to_owned);
        (parsed, request.headers)
    } else {
        let mut response = httparse::Response::new(&mut fields);
        let parsed = response
            .parse(input)
            .map_err(|e| format!("HTTP/1 response: {e}"))?;
        message.status = response.code;
        (parsed, response.headers)
    };
    match parsed {
        httparse::Status::Complete(length) => {
            if length > limits.headers {
                return Err("HTTP/1 header limit".into());
            }
            message.headers = fields
                .iter()
                .map(|h| (h.name.to_ascii_lowercase(), text(h.value)))
                .collect();
            Ok(Some((length, message)))
        }
        httparse::Status::Partial => {
            if input.len() > limits.headers {
                return Err("HTTP/1 header limit".into());
            }
            Ok(None)
        }
    }
}
fn framing(message: &Message, method: &str, client: bool) -> Result<Framing> {
    let status = message.status.unwrap_or(0);
    if !client
        && (method == "HEAD"
            || status == 204
            || status == 304
            || status < 200
            || (method == "CONNECT" && (200..300).contains(&status)))
    {
        return Ok(Framing::Fixed(0));
    }
    let length = content_length(&message.headers)?;
    let transfer = tokens(&message.headers, "transfer-encoding");
    if !transfer.is_empty() {
        if length.is_some() {
            return Err("ambiguous Transfer-Encoding + Content-Length".into());
        }
        if transfer != ["chunked"] {
            return Err("unsupported Transfer-Encoding".into());
        }
        Ok(Framing::ChunkSize)
    } else if let Some(length) = length {
        Ok(Framing::Fixed(length))
    } else if client {
        Ok(Framing::Fixed(0))
    } else {
        Ok(Framing::UntilEof)
    }
}

impl Http1 {
    pub(crate) fn take_upgrade(&mut self)->Option<(crate::websocket::Config,[Vec<u8>;2])>{self.upgrade.take().map(|c|(c,std::mem::take(&mut self.buffers)))}
    pub(crate) fn feed(
        &mut self,
        side: usize,
        data: &[u8],
        limits: &Limits,
        out: &mut Vec<Exchange>,
        cache: Option<&crate::cache::PayloadCache>,
    ) -> Result<()> {
        self.pending.configure(cache,limits.pending);
        self.buffers[side].extend_from_slice(data);
        loop {
            if self.active[side].is_none() {
                if self.buffers[side].is_empty() {
                    break;
                }
                let Some((length, mut message)) = headers(&self.buffers[side], side == 0, limits)?
                else {
                    break;
                };
                let id = if side == 0 {
                    self.requests + 1
                } else {
                    self.responses + 1
                };
                let method = if side == 0 {
                    message.method.as_deref().unwrap_or("")
                } else {
                    self.pending
                        .get_mut(&id)?
                        .and_then(|e| e.request.as_ref())
                        .and_then(|r| r.method.as_deref())
                        .ok_or("response without captured request")?
                }
                .to_owned();
                let frame = framing(&message, &method, side == 0)?;
                self.buffers[side].drain(..length);
                if side == 1
                    && message
                        .status
                        .is_some_and(|s| (100..200).contains(&s) && s != 101)
                {
                    let exchange = self.pending.get_mut(&id)?.unwrap();
                    if exchange.informational.len() >= 16 {
                        return Err("informational response limit".into());
                    }
                    message.complete = true;
                    exchange.informational.push(message);
                    continue;
                }
                let tunnel = side == 1
                    && (message.status == Some(101)
                        || (method == "CONNECT"
                            && message.status.is_some_and(|s| (200..300).contains(&s))));
                if side == 0 {
                    if self.pending.limited() {
                        return Err("pending exchange limit".into());
                    }
                    self.requests = id;
                    self.pending.insert(
                        id,
                        Exchange {
                            id,
                            request: Some(message),
                            ..Exchange::default()
                        },
                    )?;
                    self.pending.get_mut(&id)?.unwrap().start_cache(cache);
                } else {
                    self.pending.get_mut(&id)?.unwrap().response = Some(message);
                    self.pending.get_mut(&id)?.unwrap().bind_cache(1);
                }
                self.active[side] = Some(Active { id, framing: frame });
                if tunnel {
                    let exchange=self.pending.get_mut(&id)?.unwrap();
                    let websocket=crate::websocket::negotiated(exchange.request.as_ref().unwrap(),exchange.response.as_ref().unwrap())?;
                    self.complete(side, out)?;
                    if let Some(config)=websocket {self.upgrade=Some(config);return Ok(());}
                    return Err(
                        "protocol switched: tunnel/WebSocket/h2c decoding not implemented".into(),
                    );
                }
            }
            let active = self.active[side].as_mut().unwrap();
            let exchange = self.pending.get_mut(&active.id)?.unwrap();
            let message = if side == 0 {
                exchange.request.as_mut()
            } else {
                exchange.response.as_mut()
            }
            .unwrap();
            let buffer = &mut self.buffers[side];
            match active.framing {
                Framing::Fixed(0) => self.complete(side, out)?,
                Framing::Fixed(ref mut left) | Framing::ChunkData(ref mut left) => {
                    if buffer.is_empty() {
                        break;
                    }
                    let length = (*left).min(buffer.len() as u64) as usize;
                    message.append(&buffer[..length], limits);
                    buffer.drain(..length);
                    *left -= length as u64;
                    if *left == 0 && matches!(active.framing, Framing::ChunkData(_)) {
                        active.framing = Framing::ChunkEnd;
                    }
                }
                Framing::UntilEof => {
                    message.append(buffer, limits);
                    buffer.clear();
                    break;
                }
                Framing::ChunkSize => {
                    match httparse::parse_chunk_size(buffer).map_err(|_| "invalid chunk size")? {
                        httparse::Status::Partial => {
                            if buffer.len() > limits.headers {
                                return Err("chunk size line limit".into());
                            }
                            break;
                        }
                        httparse::Status::Complete((length, size)) => {
                            if length > limits.headers {
                                return Err("chunk size line limit".into());
                            }
                            buffer.drain(..length);
                            active.framing = if size == 0 {
                                Framing::Trailers
                            } else {
                                Framing::ChunkData(size)
                            };
                        }
                    }
                }
                Framing::ChunkEnd => {
                    if buffer.len() < 2 {
                        break;
                    }
                    if !buffer.starts_with(b"\r\n") {
                        return Err("invalid chunk terminator".into());
                    }
                    buffer.drain(..2);
                    active.framing = Framing::ChunkSize;
                }
                Framing::Trailers => {
                    let mut fields = vec![httparse::EMPTY_HEADER; limits.header_count];
                    match httparse::parse_headers(buffer, &mut fields)
                        .map_err(|e| format!("trailers: {e}"))?
                    {
                        httparse::Status::Partial => {
                            if buffer.len() > limits.headers {
                                return Err("trailer limit".into());
                            }
                            break;
                        }
                        httparse::Status::Complete((length, fields)) => {
                            if length > limits.headers {
                                return Err("trailer limit".into());
                            }
                            message.trailers = fields
                                .iter()
                                .map(|h| (h.name.to_ascii_lowercase(), text(h.value)))
                                .collect();
                            buffer.drain(..length);
                            self.complete(side, out)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }
    fn complete(&mut self, side: usize, out: &mut Vec<Exchange>) -> Result<()> {
        let active = self.active[side].take().unwrap();
        let exchange = self.pending.get_mut(&active.id)?.unwrap();
        if side == 0 {
            exchange.request.as_mut().unwrap().complete = true;
        } else {
            exchange.response.as_mut().unwrap().complete = true;
            self.responses = active.id;
        }
        if exchange.ready() {
            let exchange = self.pending.remove(&active.id)?.unwrap();
            exchange.finish_cache();
            out.push(exchange);
        }
        Ok(())
    }
    pub(crate) fn eof(&mut self, side: usize, clean: bool, out: &mut Vec<Exchange>) -> Result<()> {
        if let Some(active) = &self.active[side] {
            if matches!(active.framing, Framing::UntilEof) && clean {
                self.complete(side, out)?;
            } else {
                return Err("incomplete HTTP/1 message at EOF".into());
            }
        }
        if !self.buffers[side].is_empty() {
            return Err("incomplete HTTP/1 headers at EOF".into());
        }
        Ok(())
    }
    pub(crate) fn drain(&mut self, reason: &str) -> Vec<Exchange> {
        self.pending.drain(reason)
    }
}
