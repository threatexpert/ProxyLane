//! Passive QUIC v1/v2 Initial inspection. rustls supplies packet/header crypto.
//! No application keys, packet forwarding, or HTTP/3 plaintext are produced.
use rustls::{
    quic::{Keys, Version},
    Side,
};
use serde_json::{json, Value};
use std::fmt::Write;

const CRYPTO_LIMIT: usize = 65536;
#[derive(Default)]
pub struct Probe {
    contexts: Vec<Initial>,
    attempts: usize,
    pub version: Option<u32>,
    pub name: String,
    pub alpn: Vec<String>,
    pub raw_alpn: Vec<Vec<u8>>,
    pub ech: bool,
    pub note: String,
}
struct Initial {
    dcid: Vec<u8>,
    version: u32,
    keys: Keys,
    largest: [Option<u64>; 2],
    crypto: Vec<u8>,
    present: Vec<bool>,
    done: bool,
}
struct Read<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Read<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let b = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(b)
    }
    fn byte(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u16(&mut self) -> Option<usize> {
        let b = self.take(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]) as usize)
    }
    fn var(&mut self) -> Option<u64> {
        let first = self.byte()?;
        let mut n = (first & 63) as u64;
        for _ in 1..(1 << (first >> 6)) {
            n = (n << 8) | self.byte()? as u64;
        }
        Some(n)
    }
}
fn keys(dcid: &[u8], v: u32) -> Keys {
    rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .unwrap()
        .quic_suite()
        .unwrap()
        .keys(
            dcid,
            Side::Server,
            if v == 1 { Version::V1 } else { Version::V2 },
        )
}
fn packet_number(truncated: u64, bits: u32, largest: Option<u64>) -> u64 {
    let expected = largest.map_or(0, |n| n + 1);
    let window = 1u64 << bits;
    let half = window / 2;
    let candidate = (expected & !(window - 1)) | truncated;
    if candidate + half <= expected && candidate < (1u64 << 62) - window {
        candidate + window
    } else if candidate > expected + half && candidate >= window {
        candidate - window
    } else {
        candidate
    }
}
impl Initial {
    fn decrypt(&mut self, packet: &[u8], pn_at: usize, side: usize) -> Option<Vec<u8>> {
        let key = if side == 0 {
            &self.keys.remote
        } else {
            &self.keys.local
        };
        let sample = packet.get(pn_at + 4..pn_at + 4 + key.header.sample_len())?;
        let mut header = packet.get(..pn_at + 4)?.to_vec();
        let (first, rest) = header.split_at_mut(1);
        key.header
            .decrypt_in_place(sample, &mut first[0], &mut rest[pn_at - 1..])
            .ok()?;
        if first[0] & 0x0c != 0 {
            return None;
        }
        let pn_len = (first[0] & 3) as usize + 1;
        header.truncate(pn_at + pn_len);
        let truncated = header[pn_at..]
            .iter()
            .fold(0u64, |a, b| (a << 8) | *b as u64);
        let pn = packet_number(truncated, (pn_len * 8) as u32, self.largest[side]);
        let mut payload = packet[header.len()..].to_vec();
        let n = key
            .packet
            .decrypt_in_place(pn, &header, &mut payload)
            .ok()?
            .len();
        payload.truncate(n);
        self.largest[side] = Some(self.largest[side].map_or(pn, |old| old.max(pn)));
        Some(payload)
    }
    fn frames(&mut self, bytes: &[u8]) -> Result<Option<Hello>, &'static str> {
        let mut r = Read::new(bytes);
        while r.at < bytes.len() {
            match r.var().ok_or("Incomplete QUIC Initial frame")? {
                0 | 1 => {}
                kind @ (2 | 3) => {
                    let ecn = kind == 3;
                    r.var().ok_or("Invalid ACK")?;
                    r.var().ok_or("Invalid ACK")?;
                    let ranges = r.var().ok_or("Invalid ACK")?;
                    if ranges > 256 {
                        return Err("QUIC ACK range limit");
                    }
                    r.var().ok_or("Invalid ACK")?;
                    for _ in 0..ranges {
                        r.var().ok_or("Invalid ACK")?;
                        r.var().ok_or("Invalid ACK")?;
                    }
                    if ecn {
                        for _ in 0..3 {
                            r.var().ok_or("Invalid ACK ECN")?;
                        }
                    }
                }
                6 => {
                    let offset = r.var().ok_or("Invalid CRYPTO offset")?;
                    let len = r.var().ok_or("Invalid CRYPTO length")?;
                    if offset > CRYPTO_LIMIT as u64 || len > CRYPTO_LIMIT as u64 - offset {
                        return Err("QUIC CRYPTO preview limit (64 KiB)");
                    }
                    let bytes = r.take(len as usize).ok_or("Incomplete CRYPTO frame")?;
                    let end = offset as usize + bytes.len();
                    self.crypto.resize(self.crypto.len().max(end), 0);
                    self.present.resize(self.crypto.len(), false);
                    for (i, &b) in bytes.iter().enumerate() {
                        let at = offset as usize + i;
                        if self.present[at] && self.crypto[at] != b {
                            return Err("Conflicting QUIC CRYPTO fragments");
                        }
                        self.crypto[at] = b;
                        self.present[at] = true;
                    }
                }
                0x1c => {
                    return Ok(None);
                }
                _ => return Err("Unsupported frame in QUIC Initial"),
            }
        }
        let contiguous = self
            .present
            .iter()
            .position(|v| !*v)
            .unwrap_or(self.present.len());
        if contiguous < 4 {
            return Ok(None);
        }
        let size = ((self.crypto[1] as usize) << 16)
            | ((self.crypto[2] as usize) << 8)
            | self.crypto[3] as usize;
        if size + 4 > CRYPTO_LIMIT {
            return Err("QUIC ClientHello preview limit (64 KiB)");
        }
        if contiguous < size + 4 {
            return Ok(None);
        }
        if self.crypto[0] != 1 {
            return Err("QUIC CRYPTO is not a ClientHello");
        }
        let hello = hello(&self.crypto[4..size + 4]).ok_or("Malformed QUIC ClientHello")?;
        self.done = true;
        self.crypto.clear();
        self.present.clear();
        Ok(Some(hello))
    }
}
struct Hello {
    name: String,
    alpn: Vec<String>,
    raw_alpn: Vec<Vec<u8>>,
    ech: bool,
}
fn hello(bytes: &[u8]) -> Option<Hello> {
    let mut r = Read::new(bytes);
    r.take(34)?;
    let len = r.byte()? as usize;
    r.take(len)?;
    let len = r.u16()?;
    if len == 0 || len % 2 != 0 {
        return None;
    }
    r.take(len)?;
    let len = r.byte()? as usize;
    r.take(len)?;
    let len = r.u16()?;
    let ext = r.take(len)?;
    if r.at != bytes.len() {
        return None;
    }
    let mut e = Read::new(ext);
    let mut result = Hello {
        name: String::new(),
        alpn: Vec::new(),
        raw_alpn: Vec::new(),
        ech: false,
    };
    while e.at < ext.len() {
        let kind = e.u16()?;
        let len = e.u16()?;
        let data = e.take(len)?;
        let mut d = Read::new(data);
        match kind {
            0 => {
                let total = d.u16()?;
                if total != data.len() - 2 {
                    return None;
                }
                while d.at < data.len() {
                    let ty = d.byte()?;
                    let n = d.u16()?;
                    let host = d.take(n)?;
                    if ty == 0
                        && n <= 253
                        && !host.is_empty()
                        && host
                            .iter()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
                    {
                        result.name = String::from_utf8_lossy(host).into_owned();
                    }
                }
            }
            16 => {
                let total = d.u16()?;
                if total != data.len() - 2 {
                    return None;
                }
                while d.at < data.len() {
                    let n = d.byte()? as usize;
                    let value = d.take(n)?;
                    if n == 0 || result.alpn.len() >= 32 {
                        return None;
                    }
                    result.raw_alpn.push(value.to_vec());
                    result.alpn.push(
                        value
                            .iter()
                            .map(|&b| if b.is_ascii_graphic() { b as char } else { '.' })
                            .collect(),
                    );
                }
            }
            0xfe0d => result.ech = true,
            _ => {}
        }
    }
    Some(result)
}
impl Probe {
    pub fn complete(&self)->bool {self.contexts.iter().any(|c|c.done)}
    pub fn feed(&mut self, side: usize, bytes: &[u8]) {
        if self.attempts >= 128 {
            if self.version.is_some() && !self.contexts.iter().any(|c| c.done) {
                self.note = "QUIC Initial inspection limit reached".into();
            }
            return;
        }
        let mut r = Read::new(bytes);
        for _ in 0..16 {
            let start = r.at;
            let Some(first) = r.byte() else {
                return;
            };
            if first & 0xc0 != 0xc0 {
                return;
            }
            let Some(v) = r.take(4) else {
                return;
            };
            let v = u32::from_be_bytes(v.try_into().unwrap());
            if v != 1 && v != 0x6b3343cf {
                return;
            }
            let Some(n) = r.byte() else {
                return;
            };
            if n > 20 {
                return;
            }
            let Some(dcid) = r.take(n as usize) else {
                return;
            };
            let Some(n) = r.byte() else {
                return;
            };
            if n > 20 {
                return;
            }
            if r.take(n as usize).is_none() {
                return;
            }
            let ty = (first >> 4) & 3;
            let initial = ty == if v == 1 { 0 } else { 1 };
            if ty == if v == 1 { 3 } else { 0 } {
                return;
            } // Retry has no Length field.
            if initial {
                let Some(len) = r.var() else {
                    return;
                };
                if len > 65535 || r.take(len as usize).is_none() {
                    return;
                }
            }
            let Some(len) = r.var() else {
                return;
            };
            if len > 65535 {
                return;
            }
            let pn_at = r.at - start;
            if r.take(len as usize).is_none() {
                return;
            }
            if !initial {
                continue;
            }
            self.attempts += 1;
            if self.attempts > 128 {
                return;
            }
            let packet = &bytes[start..r.at];
            // Try a new DCID only after successful AEAD authentication; bogus
            // datagrams must not evict genuine handshake fragments.
            let index = if side == 0 {
                self.contexts.iter().position(|c| c.dcid == dcid && c.version == v)
            } else {
                None
            };
            let mut fresh;
            let (context, plain) = if side == 0 {
                if let Some(i) = index {
                    let c = &mut self.contexts[i];
                    let Some(p) = c.decrypt(packet, pn_at, side) else {
                        continue;
                    };
                    (c, p)
                } else {
                    if self.contexts.len() >= 4 {
                        self.note = "QUIC Initial context limit".into();
                        return;
                    }
                    fresh = Initial {
                        dcid: dcid.to_vec(),
                        version: v,
                        keys: keys(dcid, v),
                        largest: [None; 2],
                        crypto: Vec::new(),
                        present: Vec::new(),
                        done: false,
                    };
                    let Some(p) = fresh.decrypt(packet, pn_at, side) else {
                        continue;
                    };
                    self.contexts.push(fresh);
                    (self.contexts.last_mut().unwrap(), p)
                }
            } else {
                let mut found = None;
                for (i, c) in self.contexts.iter_mut().enumerate() {
                    if c.version != v { continue; }
                    if let Some(p) = c.decrypt(packet, pn_at, side) {
                        found = Some((i, p));
                        break;
                    }
                }
                let Some((i, p)) = found else {
                    continue;
                };
                (&mut self.contexts[i], p)
            };
            self.version = Some(v);
            if side == 0 && !context.done {
                match context.frames(&plain) {
                    Ok(Some(h)) => {
                        self.name = h.name;
                        self.alpn = h.alpn;
                        self.raw_alpn = h.raw_alpn;
                        self.ech = h.ech;
                        self.note.clear();
                    }
                    Ok(None) => {}
                    Err(e) => {
                        self.note = e.into();
                        context.done = true;
                        context.crypto.clear();
                        context.present.clear();
                    }
                }
            }
        }
    }
    pub fn summary(&self) -> Value {
        json!({"version":self.version,"sni":self.name,"offered_alpn":self.alpn,"ech":self.ech,"note":self.note,
            "initial_dcids":self.contexts.iter().map(|c|c.dcid.iter().fold(String::new(),|mut s,b| {let _=write!(s,"{b:02x}");s})).collect::<Vec<_>>()})
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub fn vector(v2: bool) -> Vec<u8> {
        let text = if v2 {
            include_str!("../testdata/rfc9369-client-initial.hex")
        } else {
            include_str!("../testdata/rfc9001-client-initial.hex")
        };
        let hex: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }
    #[test]
    fn rfc_initial_vectors_and_authentication() {
        for v2 in [false, true] {
            let bytes = vector(v2);
            let mut probe = Probe::default();
            probe.feed(0, &bytes);
            assert_eq!(probe.version, Some(if v2 { 0x6b3343cf } else { 1 }));
            assert_eq!(probe.name, "example.com");
            assert_eq!(probe.alpn, vec!["alpn"]);
            assert!(probe.note.is_empty(), "{}", probe.note);
            let mut corrupt = bytes.clone();
            corrupt[100] ^= 1;
            let mut other = Probe::default();
            other.feed(0, &corrupt);
            assert!(other.version.is_none());
            for len in [0, 1, 5, 20, 100, 1199] {
                let mut p = Probe::default();
                p.feed(0, &bytes[..len]);
                assert!(p.version.is_none());
            }
            probe.feed(0, &bytes);
            assert_eq!(probe.contexts.len(), 1);
        }
    }
    fn encrypted(crypto: &[u8], offset: usize, pn: u64) -> Vec<u8> {
        let dcid = [1, 2, 3, 4, 5, 6, 7, 8];
        let k = keys(&dcid, 1);
        let mut plain = vec![6]; // CRYPTO with 2-byte varints for offset/length
        plain.extend_from_slice(&(0x4000 | offset as u16).to_be_bytes());
        plain.extend_from_slice(&(0x4000 | crypto.len() as u16).to_be_bytes());
        plain.extend_from_slice(crypto);
        plain.resize(1170, 0);
        let mut header = vec![0xc1, 0, 0, 0, 1, 8];
        header.extend_from_slice(&dcid);
        header.extend_from_slice(&[0, 0]);
        header.extend_from_slice(&(0x4000 | (2 + plain.len() + 16) as u16).to_be_bytes());
        let at = header.len();
        header.extend_from_slice(&(pn as u16).to_be_bytes());
        let tag = k
            .remote
            .packet
            .encrypt_in_place(pn, &header, &mut plain)
            .unwrap();
        plain.extend_from_slice(tag.as_ref());
        header.extend_from_slice(&plain);
        let sample = header[at + 4..at + 20].to_vec();
        let (first, rest) = header.split_at_mut(1);
        k.remote
            .header
            .encrypt_in_place(&sample, &mut first[0], &mut rest[at - 1..at + 1])
            .unwrap();
        header
    }
    #[test]
    fn reordered_crypto_and_bounds() {
        let vector = vector(false);
        let mut c = Initial {
            dcid: vec![],
            version: 1,
            keys: keys(&[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08], 1),
            largest: [None; 2],
            crypto: vec![],
            present: vec![],
            done: false,
        };
        let plain = c.decrypt(&vector, 18, 0).unwrap();
        let mut r = Read::new(&plain);
        assert_eq!(r.var(), Some(6));
        assert_eq!(r.var(), Some(0));
        let n = r.var().unwrap() as usize;
        let hello = r.take(n).unwrap();
        let mut p = Probe::default();
        p.feed(0, &encrypted(&hello[70..], 70, 2));
        assert!(p.name.is_empty());
        p.feed(0, &encrypted(&hello[..70], 0, 1));
        assert_eq!(p.name, "example.com");
        assert_eq!(packet_number(0, 8, Some(255)), 256);
        let mut c = Initial {
            dcid: vec![],
            version: 1,
            keys: keys(b"test", 1),
            largest: [None; 2],
            crypto: vec![],
            present: vec![],
            done: false,
        };
        assert!(c.frames(&[6, 0x80, 1, 0, 0, 1, 0]).is_err()); // offset 65536, length 1
        assert!(c.crypto.is_empty());
    }
}
