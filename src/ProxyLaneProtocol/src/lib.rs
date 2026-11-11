//! Passive HTTP reconstruction from ordered, decrypted application bytes.
//! Optional bounded temporary payload storage; no TLS or socket interception.
pub mod cache;
pub mod worker_failure;
pub mod recording;
pub mod recording_view;
mod recording_hot;
pub mod recording_reader;
pub mod recording_index;
mod recording_decode;
pub mod dns;
pub mod http3;
mod cache_directory;
mod decode;
mod hpack_guard;
mod http1;
mod http2;
mod model;
mod pending;
mod websocket;

pub use model::{Connection, Direction, Exchange, Headers, Limits, Message, Protocol};
use serde::Serialize;

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Output {
    Exchange {
        connection: Connection,
        protocol: Protocol,
        exchange: Box<Exchange>,
    },
    Diagnostic {
        connection: Connection,
        protocol: Protocol,
        detail: String,
    },
}
enum Parser {
    Http1(http1::Http1),
    H2(http2::Http2),
    WebSocket(websocket::WebSocket),
}

/// One instance per socket generation. Feed bytes from the start of the
/// application stream, preserving order within and causality between sides.
pub struct Analyzer {
    connection: Connection,
    protocol: Protocol,
    limits: Limits,
    parser: Option<Parser>,
    offsets: [u64; 2],
    ended: [bool; 2],
    cache: Option<cache::PayloadCache>,
}
impl Analyzer {
    pub fn new(connection: Connection, protocol: Protocol, limits: Limits) -> Result<Self, String> {
        if limits.headers == 0
            || limits.header_count == 0
            || limits.pending == 0
            || limits.frame < 16384
            || limits.hpack_table < 4096
        {
            return Err("invalid analyzer limits".into());
        }
        let parser = match protocol {
            Protocol::Http1 => Parser::Http1(Default::default()),
            Protocol::H2 => Parser::H2(Default::default()),
            Protocol::WebSocket=>return Err("WebSocket requires a captured HTTP Upgrade".into()),
        };
        Ok(Self {
            connection,
            protocol,
            limits,
            parser: Some(parser),
            offsets: [0; 2],
            ended: [false; 2],
            cache: None,
        })
    }
    pub fn with_cache(
        connection: Connection,
        protocol: Protocol,
        mut limits: Limits,
        cache: cache::PayloadCache,
    ) -> Result<Self, String> {
        limits.encoded_body = if cache.is_recording() {0} else {limits.encoded_body.min(cache::PREVIEW_BYTES)};
        let mut analyzer = Self::new(connection, protocol, limits)?;
        analyzer.cache = Some(cache.scoped(serde_json::json!({"connection":analyzer.connection,"protocol":protocol})));
        Ok(analyzer)
    }
    /// Offset is the absolute plaintext byte offset in this direction. A gap,
    /// overlap or duplicate is terminal: guessing would corrupt HTTP/2 HPACK.
    /// Drain outputs immediately; retaining them is the caller's memory policy.
    pub fn push(&mut self, direction: Direction, offset: u64, bytes: &[u8]) -> Vec<Output> {
        if self.parser.is_none() {
            return Vec::new();
        }
        let side = direction.index();
        if self.ended[side] {
            return self.fail("data after EOF".into(), Vec::new());
        }
        if offset != self.offsets[side] {
            return self.fail(
                format!(
                    "capture gap/overlap on {direction:?}: expected {}, got {offset}",
                    self.offsets[side]
                ),
                Vec::new(),
            );
        }
        let Some(next) = offset.checked_add(bytes.len() as u64) else {
            return self.fail("offset overflow".into(), Vec::new());
        };
        self.offsets[side] = next;
        let mut outputs = Vec::new();
        // Bound parser input buffers independently of the caller's chunk size.
        for chunk in bytes.chunks(16384) {
            let mut exchanges = Vec::new();
            let result = match self.parser.as_mut().unwrap() {
                Parser::WebSocket(parser)=>parser.feed(side,chunk,&self.limits,self.cache.as_ref(),&mut exchanges),
                Parser::Http1(parser) => parser.feed(
                    side,
                    chunk,
                    &self.limits,
                    &mut exchanges,
                    self.cache.as_ref(),
                ),
                Parser::H2(parser) => parser.feed(
                    side,
                    chunk,
                    &self.limits,
                    &mut exchanges,
                    self.cache.as_ref(),
                ),
            };
            if let Err(error) = result {
                outputs.extend(self.fail(error, exchanges));
                return outputs;
            }
            outputs.extend(self.wrap(exchanges));
            let upgraded=match self.parser.as_mut().unwrap(){Parser::Http1(p)=>p.take_upgrade(),_=>None};
            if let Some((config,buffers))=upgraded {
                self.protocol=Protocol::WebSocket;
                self.cache=self.cache.take().map(|c|c.scoped(serde_json::json!({"connection":self.connection,"protocol":"websocket"})));
                let wire=self.cache.as_ref().map(|c|c.scoped(serde_json::json!({"connection":self.connection,"protocol":"websocket_wire","kind":"wire_frames"})));
                let mut ws=websocket::WebSocket::new(config,wire.as_ref());
                let mut messages=Vec::new();let mut failure=None;
                for(i,bytes)in buffers.iter().enumerate(){if let Err(e)=ws.feed(i,bytes,&self.limits,self.cache.as_ref(),&mut messages){failure=Some(e);break;}}
                self.parser=Some(Parser::WebSocket(ws));
                if let Some(e)=failure {outputs.extend(self.fail(e,messages));return outputs;}
                outputs.extend(self.wrap(messages));
            }
        }
        outputs
    }
    /// `clean` means an authenticated TLS close_notify (or ordinary TCP EOF
    /// for plaintext). Only EOF-delimited HTTP/1 responses depend on it.
    pub fn eof(&mut self, direction: Direction, clean: bool) -> Vec<Output> {
        self.eof_with_reason(direction,clean,"capture ended before exchange completed")
    }
    /// Preserve the transport's cause when the second EOF drains pending requests.
    pub fn eof_with_reason(&mut self, direction: Direction, clean: bool, reason:&str) -> Vec<Output> {
        if self.parser.is_none() || self.ended[direction.index()] {
            return Vec::new();
        }
        let side = direction.index();
        self.ended[side] = true;
        let mut exchanges = Vec::new();
        let result = match self.parser.as_mut().unwrap() {
            Parser::Http1(parser) => parser.eof(side, clean, &mut exchanges),
            Parser::H2(parser) => parser.eof(side),
            Parser::WebSocket(_)=>Ok(()),
        };
        if let Err(error) = result {
            return self.fail(error, exchanges);
        }
        let mut out = self.wrap(exchanges);
        if self.ended == [true; 2] {
            out.extend(self.close_with_reason(reason));
        }
        out
    }
    /// Capture stopped, not a synthetic network EOF. Pending exchanges remain
    /// explicitly incomplete; this also releases all parser buffers and tables.
    pub fn close(&mut self) -> Vec<Output> {
        self.close_with_reason("capture ended before exchange completed")
    }
    pub fn close_with_reason(&mut self,reason:&str)->Vec<Output> {
        let exchanges = self.drain(reason);
        self.wrap(exchanges)
    }
    fn drain(&mut self, reason: &str) -> Vec<Exchange> {
        match self.parser.take() {
            Some(Parser::Http1(mut parser)) => parser.drain(reason),
            Some(Parser::H2(mut parser)) => parser.drain(reason),
            Some(Parser::WebSocket(mut parser))=>parser.drain(reason),
            None => Vec::new(),
        }
    }
    fn fail(&mut self, error: String, mut exchanges: Vec<Exchange>) -> Vec<Output> {
        exchanges.extend(self.drain(&error));
        let mut out = self.wrap(exchanges);
        out.push(Output::Diagnostic {
            connection: self.connection.clone(),
            protocol: self.protocol,
            detail: error,
        });
        out
    }
    fn wrap(&self, exchanges: Vec<Exchange>) -> Vec<Output> {
        exchanges
            .into_iter()
            .map(|mut exchange| {
                exchange.finish_cache();
                exchange.finish(&self.limits);
                Output::Exchange {
                    connection: self.connection.clone(),
                    protocol: self.protocol,
                    exchange: Box::new(exchange),
                }
            })
            .collect()
    }
}
impl Drop for Analyzer {
    fn drop(&mut self) {
        for exchange in self.drain("analyzer dropped") {
            exchange.finish_cache();
        }
    }
}
