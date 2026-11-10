//! Active DoH over a caller-owned proxy tunnel. No sockets, system DNS, CA
//! creation, capture runtime or platform-verifier network fetches are used.
use std::{ffi::c_char, io::{Cursor, Read, Write}, sync::Arc};
use rustls::{ClientConfig, ClientConnection, RootCertStore, pki_types::ServerName};
use serde_json::{json, Value};

const HEADER_LIMIT: usize = 16 * 1024;
const RESPONSE_LIMIT: usize = 160 * 1024;

struct Client {
    tls: ClientConnection,
    authority: String,
    path: String,
    name: String,
    ipv6: bool,
    request: Vec<u8>,
    response: Vec<u8>,
    result: Option<String>,
    error: Option<String>,
    aliases: Vec<String>,
    ttl: u32,
    expires: Option<std::time::Instant>,
    wire_query: Option<Vec<u8>>,
}

impl Client {
    fn new(url: &str, query: &str) -> Result<Self, String> {
        if url.len() > 1023 || !url.is_ascii() || url.contains('#') {
            return Err("Invalid DoH HTTPS URL".into());
        }
        let uri: http::Uri = url.parse().map_err(|_| "Invalid DoH URL")?;
        let authority = uri.authority().ok_or("DoH URL has no host")?;
        if uri.scheme_str() != Some("https") || authority.as_str().contains('@')
            || uri.host().is_none() || uri.port_u16() == Some(0) {
            return Err("DoH requires an HTTPS URL without user information".into());
        }
        let host = uri.host().unwrap().trim_start_matches('[').trim_end_matches(']');
        let server_name = ServerName::try_from(host.to_owned()).map_err(|e| e.to_string())?;
        let q: Value = serde_json::from_str(query).map_err(|e| e.to_string())?;
        let wire_query = q.get("wire").map(|v| unhex(v.as_str().ok_or("Invalid DNS wire")?)).transpose()?;
        if let Some(wire) = &wire_query { proxylane_protocol::dns::relay_query(wire)?; }
        let name = if wire_query.is_some() { String::new() } else { q["name"].as_str().ok_or("Missing DNS name")?.to_owned() };
        let ipv6 = q["ipv6"].as_bool().unwrap_or(false);
        let mut roots = RootCertStore::empty();
        roots.add_parsable_certificates(webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter().cloned());
        let mut config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|e| e.to_string())?.with_root_certificates(roots).with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        config.enable_early_data = false;
        let mut client = Self {
            tls: ClientConnection::new(Arc::new(config), server_name).map_err(|e| e.to_string())?,
            authority: authority.to_string(), path: uri.path_and_query().map_or("/dns-query", |p| p.as_str()).into(),
            name: name.clone(), ipv6, request: Vec::new(), response: Vec::new(),
            result: None, error: None, aliases: vec![name.to_ascii_lowercase()], ttl: u32::MAX, expires: None, wire_query,
        };
        client.prepare()?;
        Ok(client)
    }
    fn prepare(&mut self) -> Result<(), String> {
        let wire = match &self.wire_query { Some(wire) => wire.clone(), None => proxylane_protocol::dns::question(&self.name, self.ipv6)? };
        self.request = format!("POST {} HTTP/1.1\r\nHost: {}\r\nAccept: application/dns-message\r\nContent-Type: application/dns-message\r\nAccept-Encoding: identity\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
            self.path, self.authority, wire.len()).into_bytes();
        self.request.extend(wire);
        Ok(())
    }
    fn advance(&mut self) -> Result<(), String> {
        if self.result.is_some() { return Ok(()); }
        if !self.tls.is_handshaking() && !self.request.is_empty() {
            self.tls.writer().write_all(&self.request).map_err(|e| e.to_string())?;
            self.request.clear();
        }
        let mut buffer = [0u8; 8192];
        loop {
            match self.tls.reader().read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    if self.response.len() + n > RESPONSE_LIMIT { return Err("DoH response limit exceeded".into()); }
                    self.response.extend_from_slice(&buffer[..n]);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e.to_string()),
            }
        }
        if let Some(body) = response_body(&self.response)? {
            if let Some(query) = &self.wire_query {
                let ttl = proxylane_protocol::dns::relay_answer(&body, query)?;
                // Apply HTTP Age to record TTLs as well as the cache lifetime.
                let aged = proxylane_protocol::dns::relay_reply(query, Some(&body), http_age(&self.response)?, false)?;
                self.result = Some(json!({"wire":hex(&aged),"ttl":cache_lifetime(&self.response, ttl)?}).to_string());
                return Ok(());
            }
            let answer = proxylane_protocol::dns::answer(&body, &self.name, self.ipv6)?;
            let now = std::time::Instant::now();
            self.ttl = cache_lifetime(&self.response, answer.ttl)?;
            let expires = now + std::time::Duration::from_secs(self.ttl as u64);
            self.expires = Some(self.expires.map_or(expires, |previous| previous.min(expires)));
            if answer.addresses.is_empty() {
                let canonical = answer.canonical.to_ascii_lowercase();
                if self.aliases.len() >= 8 || self.aliases.contains(&canonical) {
                    return Err("DoH CNAME loop or limit exceeded".into());
                }
                self.aliases.push(canonical);
                self.name = answer.canonical;
                self.response.clear();
                self.prepare()?;
                self.tls.writer().write_all(&self.request).map_err(|e| e.to_string())?;
                self.request.clear();
            } else {
                let ttl = self.expires.unwrap().saturating_duration_since(now).as_secs();
                self.result = Some(json!({"addresses":answer.addresses,"ttl":ttl}).to_string());
            }
        }
        Ok(())
    }
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }
fn unhex(value: &str) -> Result<Vec<u8>, String> {
    if value.len() > 131070 || value.len() % 2 != 0 || !value.is_ascii() { return Err("Invalid DNS wire length".into()); }
    (0..value.len()).step_by(2).map(|i| u8::from_str_radix(&value[i..i+2], 16).map_err(|_| "Invalid DNS wire hex".into())).collect()
}
fn http_age(bytes: &[u8]) -> Result<u32, String> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);
    response.parse(bytes).map_err(|e| e.to_string())?;
    let mut age = 0;
    for h in response.headers.iter().filter(|h| h.name.eq_ignore_ascii_case("age")) {
        age = std::str::from_utf8(h.value).map_err(|_| "Invalid HTTP Age")?.trim().parse().map_err(|_| "Invalid HTTP Age")?;
    }
    Ok(age)
}

#[no_mangle]
/// # Safety
/// Input is a NUL-terminated JSON string; output points to capacity writable bytes.
pub unsafe extern "C" fn plm_dns_message(input: *const c_char, output: *mut c_char, capacity: usize) -> i32 {
    let result = std::panic::catch_unwind(|| -> Result<String, String> {
        if input.is_null() { return Err("Missing DNS message".into()); }
        let text = std::ffi::CStr::from_ptr(input).to_str().map_err(|e| e.to_string())?;
        let v: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
        let query = unhex(v["query"].as_str().ok_or("Missing DNS query")?)?;
        let q = proxylane_protocol::dns::relay_query(&query)?;
        if v["validate"].as_bool() == Some(true) {
            let mut info = json!({"name":q.queries()[0].name().to_ascii(),"type":q.queries()[0].query_type().to_string()});
            if let Some(reply) = proxylane_protocol::dns::private_ipv4_ptr_reply(&q)? {
                info["local_reply"] = json!(hex(&reply));
            }
            return Ok(info.to_string());
        }
        let answer = v.get("answer").map(|a| unhex(a.as_str().ok_or("Invalid DNS answer")?)).transpose()?;
        let wire = proxylane_protocol::dns::relay_reply(&query, answer.as_deref(),
            v["age"].as_u64().unwrap_or(0).min(u32::MAX as u64) as u32, v["udp"].as_bool().unwrap_or(false))?;
        Ok(json!({"wire":hex(&wire)}).to_string())
    });
    match result {
        Ok(Ok(text)) if capacity > text.len() => { super::write_error(output, capacity, &text); text.len() as i32 }
        Ok(Err(e)) => { super::write_error(output, capacity, &e); -1 }
        _ => { super::write_error(output, capacity, "DNS message processing failed"); -1 }
    }
}

fn cache_lifetime(bytes: &[u8], dns_ttl: u32) -> Result<u32, String> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);
    response.parse(bytes).map_err(|e| e.to_string())?;
    let mut ttl = dns_ttl;
    let mut age = 0;
    for header in response.headers.iter() {
        let value = std::str::from_utf8(header.value).map_err(|_| "Invalid cache header")?.trim();
        if header.name.eq_ignore_ascii_case("age") {
            age = value.parse::<u32>().map_err(|_| "Invalid DoH HTTP Age")?;
        }
        if header.name.eq_ignore_ascii_case("cache-control") {
            for directive in value.split(',').map(str::trim) {
                let mut parts = directive.splitn(2, '=');
                let key = parts.next().unwrap_or("");
                if key.eq_ignore_ascii_case("no-store") || key.eq_ignore_ascii_case("no-cache") { ttl = 0; }
                if key.eq_ignore_ascii_case("max-age") {
                    let value = parts.next().unwrap_or("").trim_matches('"');
                    ttl = ttl.min(value.parse::<u32>().map_err(|_| "Invalid DoH HTTP max-age")?);
                }
            }
        }
    }
    Ok(ttl.saturating_sub(age))
}

fn response_body(bytes: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);
    let offset = match response.parse(bytes).map_err(|e| e.to_string())? {
        httparse::Status::Partial if bytes.len() <= HEADER_LIMIT => return Ok(None),
        httparse::Status::Partial => return Err("DoH header limit exceeded".into()),
        httparse::Status::Complete(n) => n,
    };
    if offset > HEADER_LIMIT || response.code != Some(200) {
        return Err(format!("DoH HTTP error: {}", response.code.unwrap_or(0)));
    }
    let mut length = None;
    let mut chunked = false;
    let mut media = false;
    for header in response.headers.iter() {
        let value = std::str::from_utf8(header.value).map_err(|_| "Invalid DoH header")?.trim();
        if header.name.eq_ignore_ascii_case("content-type") {
            if media || !value.split(';').next().unwrap_or("").trim().eq_ignore_ascii_case("application/dns-message") {
                return Err("DoH response Content-Type must be application/dns-message".into());
            }
            media = true;
        } else if header.name.eq_ignore_ascii_case("content-length") {
            if length.is_some() || value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err("Invalid DoH Content-Length".into());
            }
            length = Some(value.parse::<usize>().map_err(|_| "Invalid DoH Content-Length")?);
        } else if header.name.eq_ignore_ascii_case("transfer-encoding") {
            if chunked || !value.eq_ignore_ascii_case("chunked") { return Err("Unsupported DoH Transfer-Encoding".into()); }
            chunked = true;
        } else if header.name.eq_ignore_ascii_case("content-encoding") && !value.eq_ignore_ascii_case("identity") {
            return Err("Unsupported DoH Content-Encoding".into());
        }
    }
    if !media || (chunked && length.is_some()) { return Err("Invalid DoH response framing".into()); }
    let body = &bytes[offset..];
    if chunked {
        let mut cursor = 0;
        let mut decoded = Vec::new();
        loop {
            let line = &body[cursor..];
            let Some(end) = line.windows(2).position(|v| v == b"\r\n") else { return Ok(None); };
            if end > 1024 { return Err("DoH chunk header too long".into()); }
            let size = std::str::from_utf8(&line[..end]).map_err(|_| "Invalid DoH chunk")?
                .split(';').next().unwrap_or("");
            if size.is_empty() || !size.bytes().all(|b| b.is_ascii_hexdigit()) { return Err("Invalid DoH chunk size".into()); }
            let size = usize::from_str_radix(size, 16).map_err(|_| "Invalid DoH chunk size")?;
            cursor += end + 2;
            if size == 0 {
                // Validate trailers with the same bounded HTTP parser.
                let mut trailers = [httparse::EMPTY_HEADER; 32];
                return match httparse::parse_headers(&body[cursor..], &mut trailers).map_err(|e| e.to_string())? {
                    httparse::Status::Partial => Ok(None),
                    httparse::Status::Complete((used, _)) if cursor + used == body.len() => Ok(Some(decoded)),
                    _ => Err("Trailing data after DoH response".into()),
                };
            }
            if size > 65535 - decoded.len() { return Err("DoH DNS body too large".into()); }
            if body.len() - cursor < size + 2 { return Ok(None); }
            decoded.extend_from_slice(&body[cursor..cursor + size]);
            cursor += size;
            if &body[cursor..cursor + 2] != b"\r\n" { return Err("Invalid DoH chunk terminator".into()); }
            cursor += 2;
        }
    } else if let Some(length) = length {
        if !(12..=65535).contains(&length) { return Err("Invalid DoH DNS body size".into()); }
        if body.len() < length { return Ok(None); }
        if body.len() != length { return Err("Trailing data after DoH response".into()); }
        Ok(Some(body.to_vec()))
    } else {
        Err("DoH response requires Content-Length or chunked framing".into())
    }
}

#[no_mangle]
/// # Safety
/// Strings must be NUL terminated; output pointers must be writable.
pub unsafe extern "C" fn plm_doh_create(url: *const c_char, query: *const c_char,
    output: *mut *mut std::ffi::c_void, error: *mut c_char, capacity: usize) -> i32 {
    if output.is_null() { return -1; }
    *output = std::ptr::null_mut();
    match std::panic::catch_unwind(|| Client::new(super::text(url)?, super::text(query)?)) {
        Ok(Ok(client)) => { *output = Box::into_raw(Box::new(client)).cast(); 0 }
        result => {
            let message = match result { Ok(Err(e)) => e, _ => "DoH client panic".into() };
            super::write_error(error, capacity, &message); -1
        }
    }
}

#[no_mangle]
/// # Safety
/// Session must belong to this thread. Buffer must hold length writable bytes.
/// 0 feed TLS (consumes all length bytes or returns an error), 1 drain TLS,
/// 2 EOF, 3 result (0 pending, required NUL size on success).
pub unsafe extern "C" fn plm_doh_io(session: *mut std::ffi::c_void, op: u32, buffer: *mut u8, length: usize) -> i32 {
    if session.is_null() || buffer.is_null() || length == 0 { return -1; }
    let client = &mut *session.cast::<Client>();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<i32, String> {
        if let Some(error) = &client.error { return Err(error.clone()); }
        let data = std::slice::from_raw_parts_mut(buffer, length);
        match op {
            0 => {
                // read_tls may accept only part of a TCP receive buffer. Keep
                // the cursor, process each accepted part and drain plaintext
                // before feeding the remainder. A short read is not an error.
                let mut input = Cursor::new(&*data);
                while input.position() < length as u64 {
                    let n = client.tls.read_tls(&mut input).map_err(|e| e.to_string())?;
                    if n == 0 { return Err("DoH TLS input made no progress".into()); }
                    client.tls.process_new_packets().map_err(|e| e.to_string())?;
                    client.advance()?;
                }
                Ok(length as i32)
            }
            1 => {
                client.advance()?;
                let n = client.tls.write_tls(&mut &mut data[..]).map_err(|e| e.to_string())?;
                Ok(n as i32)
            }
            2 => { client.advance()?; if client.result.is_none() { Err("DoH connection closed before a complete answer".into()) } else { Ok(0) } }
            3 => {
                if let Some(result) = &client.result {
                    if length > result.len() { super::write_error(buffer.cast(), length, result); }
                    Ok((result.len() + 1) as i32)
                } else { Ok(0) }
            }
            _ => Err("Unknown DoH operation".into()),
        }
    }));
    match result {
        Ok(Ok(n)) => n,
        result => {
            let message = match result { Ok(Err(e)) => e, _ => "DoH client panic".into() };
            super::write_error(buffer.cast(), length, &message);
            client.error = Some(message); -1
        }
    }
}

#[no_mangle]
/// # Safety
/// Session must be null or an unfreed handle from plm_doh_create, on its owner thread.
pub unsafe extern "C" fn plm_doh_free(session: *mut std::ffi::c_void) {
    if !session.is_null() { drop(Box::from_raw(session.cast::<Client>())); }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn framing_and_limits() {
        let wire = proxylane_protocol::dns::question("example.org", false).unwrap();
        let mut response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n", wire.len()).into_bytes();
        response.extend(&wire);
        for n in 0..response.len() { assert!(response_body(&response[..n]).unwrap().is_none()); }
        assert_eq!(response_body(&response).unwrap().unwrap(), wire);
        response.push(0); assert!(response_body(&response).is_err());
        let chunked = format!("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n", wire.len());
        let mut response = chunked.into_bytes(); response.extend(&wire); response.extend(b"\r\n0\r\n\r\n");
        assert_eq!(response_body(&response).unwrap().unwrap(), wire);
        assert!(response_body(b"HTTP/1.1 302 Found\r\nLocation: http://example.org\r\n\r\n").is_err());
        assert!(response_body(b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 999999\r\n\r\n").is_err());
    }
    #[test]
    fn validates_urls_without_network_or_ca() {
        let q = r#"{"name":"example.org","ipv6":false}"#;
        assert!(Client::new("https://cloudflare-dns.com/dns-query", q).is_ok());
        for url in ["http://example.org/dns-query", "https://user:pass@example.org/", "https://example.org/#x"] {
            assert!(Client::new(url, q).is_err());
        }
    }
    #[test]
    fn cache_respects_dns_ttl_http_age_and_no_store() {
        assert_eq!(cache_lifetime(b"HTTP/1.1 200 OK\r\nAge: 20\r\nCache-Control: max-age=50\r\n\r\n", 120).unwrap(), 30);
        assert_eq!(cache_lifetime(b"HTTP/1.1 200 OK\r\nAge: 50\r\n\r\n", 10).unwrap(), 0);
        assert_eq!(cache_lifetime(b"HTTP/1.1 200 OK\r\nCache-Control: no-store\r\n\r\n", 120).unwrap(), 0);
        assert_eq!(cache_lifetime(b"HTTP/1.1 200 OK\r\n\r\n", 0).unwrap(), 0);
    }
    #[test]
    fn tls_exchange_uses_original_name_and_checks_certificates() {
        // A large certificate flight reproduces read_tls short reads when TCP
        // coalesces records; seven-byte fragments alone concealed the FFI bug.
        let mut names = vec!["resolver.example".into()];
        names.extend((0..200).map(|i| format!("padding-{i}.resolver.example")));
        let identity = rcgen::generate_simple_self_signed(names).unwrap();
        let certificate = identity.cert.der().clone();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(identity.key_pair.serialize_der());
        let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13]).unwrap()
            .with_no_client_auth().with_single_cert(vec![certificate.clone()], key.into()).unwrap();
        for (trusted, raw, chunk_size) in [(false, false, 16384), (true, false, 7), (true, false, 16384), (true, true, 16384)] {
            let query = if raw { json!({"wire":hex(&proxylane_protocol::dns::question("example.org", false).unwrap())}).to_string() }
                else { r#"{"name":"example.org","ipv6":false}"#.into() };
            let mut client = Client::new("https://resolver.example/dns-query", &query).unwrap();
            if trusted {
                // Only this test instance trusts its in-memory fixture root.
                let mut roots = RootCertStore::empty(); roots.add(certificate.clone()).unwrap();
                let mut config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                    .with_protocol_versions(&[&rustls::version::TLS13]).unwrap()
                    .with_root_certificates(roots).with_no_client_auth();
                config.alpn_protocols = vec![b"http/1.1".to_vec()];
                client.tls = ClientConnection::new(Arc::new(config), ServerName::try_from("resolver.example").unwrap()).unwrap();
            }
            let mut server = rustls::ServerConnection::new(Arc::new(server_config.clone())).unwrap();
            let mut request = Vec::new();
            let mut replied = false;
            let mut rejected = false;
            for _ in 0..20 {
                client.advance().unwrap();
                let mut wire = Vec::new(); client.tls.write_tls(&mut wire).unwrap();
                if !wire.is_empty() {
                    server.read_tls(&mut Cursor::new(wire)).unwrap(); server.process_new_packets().unwrap();
                }
                let mut data = [0u8; 4096];
                if let Ok(n) = server.reader().read(&mut data) { request.extend_from_slice(&data[..n]); }
                if !request.is_empty() && !replied {
                    assert_eq!(server.server_name(), Some("resolver.example"));
                    assert!(request.starts_with(b"POST /dns-query HTTP/1.1\r\nHost: resolver.example\r\n"));
                    let mut answer = proxylane_protocol::dns::question("example.org", false).unwrap();
                    answer[2] = 0x81; answer[3] = 0x80; answer[7] = 1;
                    answer.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 20]);
                    server.writer().write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nAge: 10\r\nX-Test-Padding: {}\r\n\r\n", answer.len(), "x".repeat(8000)).as_bytes()).unwrap();
                    server.writer().write_all(&answer).unwrap(); replied = true;
                }
                let mut wire = Vec::new(); server.write_tls(&mut wire).unwrap();
                if !wire.is_empty() && chunk_size == 16384 {
                    assert!(wire.len() > 4096, "fixture must exceed rustls initial read capacity");
                }
                for chunk in wire.chunks(chunk_size) {
                    let mut input = chunk.to_vec();
                    let consumed = unsafe { plm_doh_io((&mut client as *mut Client).cast(), 0, input.as_mut_ptr(), input.len()) };
                    if consumed < 0 {
                        assert!(!trusted, "FFI TLS input failed: {:?}", client.error);
                        rejected = true; break;
                    }
                    assert_eq!(consumed as usize, input.len(), "FFI must consume the full caller buffer, including coalesced TLS records");
                }
                if rejected || client.result.is_some() { break; }
            }
            if trusted {
                let result: Value = serde_json::from_str(client.result.as_ref().unwrap()).unwrap();
                if raw {
                    let bytes = unhex(result["wire"].as_str().unwrap()).unwrap();
                    assert_eq!(proxylane_protocol::dns::answer(&bytes, "example.org", false).unwrap().ttl, 50);
                } else { assert_eq!(result["addresses"], json!(["192.0.2.20"])); }
                assert_eq!(result["ttl"], 50);
            } else { assert!(rejected); assert!(request.is_empty()); }
        }
    }
}
