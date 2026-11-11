//! Observation of messages already decoded by the HTTP/3 transport. No wire parser.
use crate::{cache::PayloadCache, Exchange, Limits, Message};
pub struct Capture {
    exchange: Exchange,
    limits: Limits,
}
impl Capture {
    pub fn new(id: u64, cache: Option<&PayloadCache>) -> Self {
        let mut exchange = Exchange {
            id,
            ..Default::default()
        };
        exchange.start_cache(cache);
        Self {
            exchange,
            limits: Limits {
                encoded_body: if cache.is_some_and(PayloadCache::is_recording) {0}else{65536},
                decoded_body: 65536,
                ..Default::default()
            },
        }
    }
    pub fn head(&mut self, side: usize, mut message: Message) {
        if side == 1 && message.status.is_some_and(|s| (100..200).contains(&s)) {
            message.complete = true;
            if self.exchange.informational.len() < 16 {
                self.exchange.informational.push(message);
            }
            return;
        }
        if side == 0 {
            self.exchange.request = Some(message)
        } else {
            self.exchange.response = Some(message)
        }
        self.exchange.bind_cache(side);
    }
    pub fn data(&mut self, side: usize, data: &[u8]) {
        let message = if side == 0 {
            &mut self.exchange.request
        } else {
            &mut self.exchange.response
        };
        if let Some(m) = message {
            m.append(data, &self.limits);
        }
    }
    pub fn end(&mut self, side: usize, trailers: crate::Headers) {
        let message = if side == 0 {
            &mut self.exchange.request
        } else {
            &mut self.exchange.response
        };
        if let Some(m) = message {
            m.complete = true;
            m.trailers = trailers;
        }
    }
    pub fn snapshot(&self) -> serde_json::Value {
        serde_json::to_value(&self.exchange).unwrap()
    }
    pub fn finish(mut self, reason: &str) -> Exchange {
        if !self.exchange.ready() {
            self.exchange.problem = Some(reason.into());
        }
        self.exchange.finish_cache();
        self.exchange.finish(&self.limits);
        self.exchange
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    #[test]
    fn compressed_message_and_trailers_use_existing_body_decoder() {
        let mut capture = Capture::new(12, None);
        let mut request = Message::default();
        request.method = Some("GET".into());
        capture.head(0, request);
        capture.end(0, vec![]);
        let mut interim = Message::default();
        interim.status = Some(103);
        capture.head(1, interim);
        let mut response = Message::default();
        response.status = Some(200);
        response
            .headers
            .push(("content-encoding".into(), "gzip".into()));
        capture.head(1, response);
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(b"HTTP/3 decoded body").unwrap();
        let body = gzip.finish().unwrap();
        for b in body.chunks(3) {
            capture.data(1, b);
        }
        capture.end(1, vec![("x-trailer".into(), "ok".into())]);
        let exchange = capture.finish("unexpected close");
        assert!(exchange.problem.is_none());
        assert_eq!(exchange.id, 12);
        assert_eq!(exchange.informational[0].status, Some(103));
        let response = exchange.response.unwrap();
        assert_eq!(response.text.as_deref(), Some("HTTP/3 decoded body"));
        assert_eq!(response.trailers[0].1, "ok");
        assert_eq!(response.body_bytes, body.len() as u64);
    }
    #[test]
    fn partial_capture_never_claims_a_complete_message() {
        let mut capture = Capture::new(0, None);
        let mut request = Message::default();
        request.method = Some("POST".into());
        capture.head(0, request);
        capture.data(0, &vec![42; 131072]);
        let exchange = capture.finish("monitoring stopped");
        assert_eq!(exchange.problem.as_deref(), Some("monitoring stopped"));
        let request = exchange.request.unwrap();
        assert_eq!(request.body_bytes, 131072);
        assert_eq!(request.body.len(), 65536);
        assert!(!request.complete);
        assert!(request.decoded_base64.is_none());
    }
}
