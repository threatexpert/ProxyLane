//! Bounded DNS wire decoding. Transport framing and transaction lifetime belong
//! to the caller. Names/compression/record formats are handled by Hickory.
use hickory_proto::{
    op::{Message, MessageType, OpCode},
    serialize::binary::{BinDecodable, BinDecoder},
};

// The local DNS adapter accepts ordinary queries, never zone transfers,
// updates or signed transactions (rewriting their IDs would invalidate them).
pub fn relay_query(bytes: &[u8]) -> Result<Message, String> {
    use hickory_proto::rr::RecordType;
    decode(bytes)?;
    let q = Message::from_vec(bytes).map_err(|e| e.to_string())?;
    if q.message_type() != MessageType::Query || q.op_code() != OpCode::Query
        || q.queries().len() != 1 || !q.answers().is_empty() || !q.name_servers().is_empty()
        || !q.signature().is_empty() || !q.additionals().is_empty()
        || matches!(q.queries()[0].query_type(), RecordType::AXFR | RecordType::IXFR)
        || q.truncated() {
        return Err("Unsupported DNS query".into());
    }
    Ok(q)
}

// Policy for proxied DNS only: do not disclose RFC1918 IPv4 reverse lookups.
// Other PTR namespaces and record types keep their normal DoH route.
pub fn private_ipv4_ptr_reply(query: &Message) -> Result<Option<Vec<u8>>, String> {
    use hickory_proto::{op::ResponseCode, rr::{DNSClass, RecordType}};
    if query.queries().len() != 1 { return Ok(None); }
    let q = &query.queries()[0];
    if q.query_type() != RecordType::PTR || q.query_class() != DNSClass::IN { return Ok(None); }
    let labels: Vec<&[u8]> = q.name().iter().collect();
    if labels.len() != 6 || !labels[4].eq_ignore_ascii_case(b"in-addr")
        || !labels[5].eq_ignore_ascii_case(b"arpa") { return Ok(None); }
    let mut octets = [0u8; 4];
    for (i, label) in labels[..4].iter().enumerate() {
        if label.is_empty() || label.len() > 3 || !label.iter().all(u8::is_ascii_digit) { return Ok(None); }
        let number: u16 = label.iter().fold(0, |n, c| n * 10 + u16::from(c - b'0'));
        if number > 255 { return Ok(None); }
        octets[3-i] = number as u8;
    }
    if !std::net::Ipv4Addr::from(octets).is_private() { return Ok(None); }
    let mut reply = Message::new();
    reply.set_id(query.id()).set_message_type(MessageType::Response).set_op_code(query.op_code())
        .set_recursion_desired(query.recursion_desired()).set_recursion_available(true)
        .set_response_code(ResponseCode::Refused).add_queries(query.queries().iter().cloned());
    Ok(Some(reply.to_vec().map_err(|e| e.to_string())?))
}

// A connectivity probe needs a valid successful response, not an address.
pub fn probe_answer(bytes: &[u8], query: &[u8]) -> Result<(), String> {
    relay_answer(bytes, query)?;
    let a = Message::from_vec(bytes).map_err(|e| e.to_string())?;
    if a.truncated() { return Err("DoH probe received a truncated DNS response".into()); }
    if a.response_code() != hickory_proto::op::ResponseCode::NoError {
        return Err(format!("DoH DNS response: {}", relay_summary(bytes)?));
    }
    Ok(())
}

pub fn relay_answer(bytes: &[u8], query: &[u8]) -> Result<u32, String> {
    use hickory_proto::op::ResponseCode;
    let q = relay_query(query)?;
    decode(bytes)?;
    let a = Message::from_vec(bytes).map_err(|e| e.to_string())?;
    if a.message_type() != MessageType::Response || a.op_code() != q.op_code()
        || a.id() != q.id() || a.queries() != q.queries() || !a.signature().is_empty() {
        return Err("DoH response does not match the DNS query".into());
    }
    // Negative and truncated replies are forwarded but deliberately not cached.
    if a.response_code() != ResponseCode::NoError || a.truncated() || a.answers().is_empty() {
        return Ok(0);
    }
    Ok(a.answers().iter().chain(a.name_servers()).chain(a.additionals())
        .map(|r| r.ttl()).min().unwrap_or(0))
}

// Age records independently; preserve all record types and flags, including
// DNSSEC/EDNS. An oversized UDP reply becomes a valid truncated reply, not a
// sliced packet. The client can retry the same query over TCP.
pub fn relay_reply(query: &[u8], answer: Option<&[u8]>, age: u32, udp: bool) -> Result<Vec<u8>, String> {
    use hickory_proto::op::ResponseCode;
    let q = relay_query(query)?;
    let mut a = if let Some(bytes) = answer {
        let mut normalized = query.to_vec(); normalized[0] = 0; normalized[1] = 0;
        relay_answer(bytes, &normalized)?;
        Message::from_vec(bytes).map_err(|e| e.to_string())?
    } else {
        let mut a = Message::new();
        a.set_message_type(MessageType::Response).set_op_code(q.op_code())
            .set_recursion_desired(q.recursion_desired()).set_recursion_available(true)
            .set_response_code(ResponseCode::ServFail).add_queries(q.queries().iter().cloned());
        a
    };
    a.set_id(q.id());
    for r in a.answers_mut() { r.set_ttl(r.ttl().saturating_sub(age)); }
    for r in a.name_servers_mut() { r.set_ttl(r.ttl().saturating_sub(age)); }
    for r in a.additionals_mut() { r.set_ttl(r.ttl().saturating_sub(age)); }
    let wire = a.to_vec().map_err(|e| e.to_string())?;
    let limit = q.extensions().as_ref().map_or(512, |e| usize::from(e.max_payload()).max(512)).min(65507);
    if udp && wire.len() > limit {
        a.take_answers(); a.take_name_servers(); a.take_additionals();
        a.set_truncated(true);
        *a.extensions_mut() = None;
        return a.to_vec().map_err(|e| e.to_string());
    }
    Ok(wire)
}

// Shared, bounded runtime-log format. Detailed record decoding belongs to the
// protocol viewer; logging must not accumulate CNAME history or track TTLs.
pub fn relay_summary(bytes: &[u8]) -> Result<String, String> {
    use hickory_proto::{op::ResponseCode, rr::RecordType};
    let msg = Message::from_vec(bytes).map_err(|e| e.to_string())?;
    if msg.message_type() != MessageType::Response { return Err("Not a DNS response".into()); }
    let mut text = match msg.response_code() {
        ResponseCode::NoError => "NOERROR".to_string(),
        ResponseCode::FormErr => "FORMERR".to_string(),
        ResponseCode::ServFail => "SERVFAIL".to_string(),
        ResponseCode::NXDomain => "NXDOMAIN".to_string(),
        ResponseCode::NotImp => "NOTIMP".to_string(),
        ResponseCode::Refused => "REFUSED".to_string(),
        code => format!("RCODE={}", u16::from(code)),
    };
    if msg.truncated() { text.push_str("; truncated=yes"); }
    if msg.response_code() != ResponseCode::NoError { return Ok(text); }
    let kind = msg.queries().first().map(|q| q.query_type());
    if matches!(kind, Some(RecordType::A | RecordType::AAAA)) {
        let matching: Vec<_> = msg.answers().iter().filter(|r| Some(r.record_type()) == kind).collect();
        let addresses: Vec<_> = matching.iter().take(4).filter_map(|r| r.data().map(ToString::to_string)).collect();
        if !addresses.is_empty() {
            text.push_str(&format!("; addresses={}", addresses.join(",")));
            if matching.len() > 4 { text.push_str(&format!(",...(+{})", matching.len()-4)); }
        } else if !msg.truncated() { text.push_str("; no addresses"); }
    }
    Ok(text)
}

#[cfg(test)]
mod relay_tests {
    use super::*;
    use hickory_proto::{op::{Edns, ResponseCode}, rr::{Record, RData, rdata::TXT}};
    #[test]
    fn connectivity_probe_accepts_nodata_but_rejects_errors_and_mismatches() {
        let q = question("example.org", false).unwrap();
        let mut a = relay_query(&q).unwrap();
        a.set_message_type(MessageType::Response);
        assert!(probe_answer(&a.to_vec().unwrap(), &q).is_ok());
        for code in [ResponseCode::NXDomain, ResponseCode::ServFail, ResponseCode::Refused] {
            a.set_response_code(code);
            assert!(probe_answer(&a.to_vec().unwrap(), &q).is_err());
        }
        a.set_response_code(ResponseCode::NoError).set_truncated(true);
        assert!(probe_answer(&a.to_vec().unwrap(), &q).is_err());
        a.set_truncated(false).set_id(123);
        assert!(probe_answer(&a.to_vec().unwrap(), &q).is_err());
        assert!(probe_answer(&[0; 3], &q).is_err());
        assert!(probe_answer(&question("other.example", false).unwrap(), &q).is_err());
    }
    #[test]
    fn private_ptr_refused_without_affecting_public_ptr_or_other_queries() {
        use hickory_proto::rr::{DNSClass, RecordType};
        let ptr = |name: &str| {
            let mut q = relay_query(&question(name, false).unwrap()).unwrap();
            q.set_id(0x1234);
            q.queries_mut()[0].set_query_type(RecordType::PTR);
            q
        };
        for name in ["182.88.16.172.in-addr.arpa.", "1.0.0.10.in-addr.arpa.",
            "255.255.31.172.IN-ADDR.ARPA.", "1.1.168.192.in-addr.arpa."] {
            let q = ptr(name);
            let reply = Message::from_vec(&private_ipv4_ptr_reply(&q).unwrap().unwrap()).unwrap();
            assert_eq!(reply.response_code(), ResponseCode::Refused);
            assert_eq!(reply.id(), q.id()); assert_eq!(reply.queries(), q.queries());
            assert!(reply.recursion_desired()); assert!(reply.answers().is_empty());
            assert_eq!(reply.message_type(), MessageType::Response);
        }
        for name in ["8.8.8.8.in-addr.arpa.", "1.0.15.172.in-addr.arpa.",
            "1.0.32.172.in-addr.arpa.", "1.1.167.192.in-addr.arpa.",
            "1.1.169.192.in-addr.arpa.", "1.0.0.11.in-addr.arpa.",
            "1.0.254.169.in-addr.arpa.", "256.0.0.10.in-addr.arpa.",
            "x.0.0.10.in-addr.arpa.", "0.0.10.in-addr.arpa.",
            "1.0.0.10.in-addr.arpa.example.", "example.org."] {
            assert!(private_ipv4_ptr_reply(&ptr(name)).unwrap().is_none(), "{name}");
        }
        let mut q = ptr("182.88.16.172.in-addr.arpa.");
        q.queries_mut()[0].set_query_type(RecordType::A);
        assert!(private_ipv4_ptr_reply(&q).unwrap().is_none());
        q.queries_mut()[0].set_query_type(RecordType::PTR).set_query_class(DNSClass::CH);
        assert!(private_ipv4_ptr_reply(&q).unwrap().is_none());
    }
    fn fixture() -> (Vec<u8>, Message) {
        let mut q = relay_query(&question("example.org", false).unwrap()).unwrap();
        q.queries_mut()[0].set_query_type(hickory_proto::rr::RecordType::TXT);
        let mut a = q.clone(); a.set_message_type(MessageType::Response).set_recursion_available(true);
        a.add_answer(Record::from_rdata(q.queries()[0].name().clone(), 60, RData::TXT(TXT::new(vec!["hello".into()]))));
        (q.to_vec().unwrap(), a)
    }
    #[test]
    fn full_records_ids_age_and_failures() {
        let (mut q, a) = fixture(); let wire = a.to_vec().unwrap();
        assert_eq!(relay_answer(&wire, &q).unwrap(), 60);
        q[0] = 0x12; q[1] = 0x34;
        let reply = relay_reply(&q, Some(&wire), 7, false).unwrap();
        let m = Message::from_vec(&reply).unwrap();
        assert_eq!(m.id(), 0x1234); assert_eq!(m.answers()[0].ttl(), 53);
        assert_eq!(m.answers()[0].data(), a.answers()[0].data());
        let error = Message::from_vec(&relay_reply(&q, None, 0, true).unwrap()).unwrap();
        assert_eq!(error.id(), 0x1234); assert_eq!(error.response_code(), ResponseCode::ServFail);
        assert_eq!(error.queries(), m.queries());
        let mut negative = a.clone(); negative.take_answers(); negative.set_response_code(ResponseCode::NXDomain);
        let negative = negative.to_vec().unwrap();
        let m = Message::from_vec(&relay_reply(&q, Some(&negative), 0, false).unwrap()).unwrap();
        assert_eq!(m.response_code(), ResponseCode::NXDomain);
        let mut wrong = wire.clone(); wrong[1] = 1;
        assert!(relay_reply(&q, Some(&wrong), 0, false).is_err());
        let mut wrong = a.clone(); wrong.queries_mut()[0].set_query_type(hickory_proto::rr::RecordType::AAAA);
        assert!(relay_reply(&q, Some(&wrong.to_vec().unwrap()), 0, false).is_err());
    }
    #[test]
    fn brief_summary_addresses_and_errors() {
        use hickory_proto::rr::{Name, rdata::{A, AAAA, CNAME}};
        let q = question("example.org", false).unwrap();
        let mut a = relay_query(&q).unwrap(); a.set_message_type(MessageType::Response);
        let alias: Name = "alias.example.org.".parse().unwrap();
        a.add_answer(Record::from_rdata(a.queries()[0].name().clone(), 40, RData::CNAME(CNAME(alias.clone()))));
        for n in 1..=6 { a.add_answer(Record::from_rdata(alias.clone(), 60, RData::A(A::new(192, 0, 2, n)))); }
        let wire = relay_reply(&q, Some(&a.to_vec().unwrap()), 7, false).unwrap();
        assert_eq!(relay_summary(&wire).unwrap(), "NOERROR; addresses=192.0.2.1,192.0.2.2,192.0.2.3,192.0.2.4,...(+2)");
        a.take_answers(); a.queries_mut()[0].set_query_type(hickory_proto::rr::RecordType::AAAA);
        a.add_answer(Record::from_rdata(alias, 0, RData::AAAA(AAAA("2001:db8::1".parse().unwrap()))));
        assert_eq!(relay_summary(&a.to_vec().unwrap()).unwrap(), "NOERROR; addresses=2001:db8::1");
        a.take_answers();
        assert_eq!(relay_summary(&a.to_vec().unwrap()).unwrap(), "NOERROR; no addresses");
        a.set_response_code(ResponseCode::NXDomain);
        assert_eq!(relay_summary(&a.to_vec().unwrap()).unwrap(), "NXDOMAIN");
        assert_eq!(relay_summary(&relay_reply(&q, None, 0, false).unwrap()).unwrap(), "SERVFAIL");
    }
    #[test]
    fn brief_summary_omits_other_record_details() {
        use hickory_proto::rr::{Name, RecordType, rdata::{HTTPS, SVCB}};
        let (q, mut a) = fixture();
        a.take_answers(); a.queries_mut()[0].set_query_type(RecordType::HTTPS);
        a.add_answer(Record::from_rdata(a.queries()[0].name().clone(), 120, RData::HTTPS(HTTPS(SVCB::new(1, Name::root(), vec![])))));
        assert_eq!(relay_summary(&a.to_vec().unwrap()).unwrap(), "NOERROR");
        let (_, mut a) = fixture();
        a.answers_mut()[0].set_data(Some(RData::TXT(TXT::new(vec!["x\r\ny\tz".repeat(30); 4]))));
        assert_eq!(relay_summary(&a.to_vec().unwrap()).unwrap(), "NOERROR");
        let udp = relay_reply(&q, Some(&a.to_vec().unwrap()), 0, true).unwrap();
        assert_eq!(relay_summary(&udp).unwrap(), "NOERROR; truncated=yes");
        assert!(relay_summary(&q).is_err());
        assert!(relay_summary(&[0; 3]).is_err());
    }
    #[test]
    fn udp_truncation_tcp_full_answer_and_edns() {
        let (q, mut a) = fixture();
        a.answers_mut()[0].set_data(Some(RData::TXT(TXT::new(vec!["x".repeat(250); 4]))));
        let wire = a.to_vec().unwrap(); assert!(wire.len() > 512);
        let udp = relay_reply(&q, Some(&wire), 0, true).unwrap();
        assert!(udp.len() <= 512 && Message::from_vec(&udp).unwrap().truncated());
        assert_eq!(relay_reply(&q, Some(&wire), 0, false).unwrap(), wire);
        let mut edns = relay_query(&q).unwrap();
        edns.set_edns(Edns::new().set_max_payload(1232).set_dnssec_ok(true).clone());
        assert_eq!(relay_reply(&edns.to_vec().unwrap(), Some(&wire), 0, true).unwrap(), wire);
    }
    #[test]
    fn rejects_malformed_and_non_query_transactions() {
        let (q, a) = fixture();
        for length in 0..q.len() { assert!(relay_query(&q[..length]).is_err()); }
        assert!(relay_query(&a.to_vec().unwrap()).is_err());
        let mut unsupported = relay_query(&q).unwrap();
        unsupported.queries_mut()[0].set_query_type(hickory_proto::rr::RecordType::AXFR);
        assert!(relay_query(&unsupported.to_vec().unwrap()).is_err());
        unsupported.set_op_code(OpCode::Update);
        assert!(relay_query(&unsupported.to_vec().unwrap()).is_err());
    }
}

// Active resolvers share Hickory's wire codec with passive DNS inspection.
pub fn question(name: &str, ipv6: bool) -> Result<Vec<u8>, String> {
    use hickory_proto::{op::Query, rr::{Name, RecordType}};
    let name = Name::from_ascii(name).map_err(|e| e.to_string())?;
    let mut message = Message::new();
    message.set_recursion_desired(true).add_query(Query::query(name,
        if ipv6 { RecordType::AAAA } else { RecordType::A }));
    message.to_vec().map_err(|e| e.to_string())
}

pub struct Answer {
    pub addresses: Vec<String>,
    pub canonical: String,
    pub ttl: u32,
}

pub fn answer(bytes: &[u8], name: &str, ipv6: bool) -> Result<Answer, String> {
    use hickory_proto::{op::ResponseCode, rr::{Name, RData, RecordType}};
    // Apply the same message size, record count and trailing-byte checks.
    decode(bytes)?;
    let message = Message::from_vec(bytes).map_err(|e| e.to_string())?;
    let expected = Name::from_ascii(name).map_err(|e| e.to_string())?;
    let kind = if ipv6 { RecordType::AAAA } else { RecordType::A };
    if message.message_type() != MessageType::Response || message.truncated()
        || message.id() != 0 || message.queries().len() != 1
        || message.queries()[0].name() != &expected
        || message.queries()[0].query_type() != kind
        || message.queries()[0].query_class() != hickory_proto::rr::DNSClass::IN {
        return Err("DoH response does not match the DNS question".into());
    }
    if message.response_code() != ResponseCode::NoError {
        return Err(format!("DoH DNS error: {}", message.response_code()));
    }
    let mut current = expected.clone();
    let mut ttl = u32::MAX;
    let mut visited = Vec::new();
    for _ in 0..=8 {
        if visited.contains(&current) { return Err("DNS CNAME loop".into()); }
        visited.push(current.clone());
        let mut addresses = Vec::new();
        for record in message.answers().iter().filter(|r| r.name() == &current
            && r.dns_class() == hickory_proto::rr::DNSClass::IN) {
            let address = match record.data() {
                Some(RData::A(value)) if !ipv6 => Some(value.0.to_string()),
                Some(RData::AAAA(value)) if ipv6 => Some(value.0.to_string()),
                _ => None,
            };
            if let Some(address) = address {
                ttl = ttl.min(record.ttl());
                if !addresses.contains(&address) { addresses.push(address); }
            }
        }
        if !addresses.is_empty() {
            addresses.truncate(16);
            return Ok(Answer { addresses, canonical: current.to_ascii(), ttl });
        }
        let alias = message.answers().iter().find_map(|record| {
            if record.name() == &current && record.dns_class() == hickory_proto::rr::DNSClass::IN {
                if let Some(RData::CNAME(alias)) = record.data() {
                    return Some((alias.0.clone(), record.ttl()));
                }
            }
            None
        });
        match alias {
            Some((next, lifetime)) => { current = next; ttl = ttl.min(lifetime); }
            None if current != expected => return Ok(Answer {
                addresses, canonical: current.to_ascii(), ttl,
            }),
            None => return Err("DoH DNS response has no address of the requested family".into()),
        }
    }
    Err("DNS CNAME limit exceeded".into())
}

pub struct Packet {
    pub id: u16,
    pub response: bool,
    pub key: String,
    pub name: String,
    pub kind: String,
    pub status: String,
    pub text: String,
}
pub fn decode(bytes: &[u8]) -> Result<Packet, String> {
    if !(12..=65535).contains(&bytes.len()) {
        return Err("Invalid DNS message length".into());
    }
    let count = |at| u16::from_be_bytes([bytes[at], bytes[at + 1]]) as usize;
    if count(4) > 16 || count(6) + count(8) + count(10) > 256 {
        return Err("DNS record limit exceeded".into());
    }
    let mut decoder = BinDecoder::new(bytes);
    let msg = Message::read(&mut decoder).map_err(|e| format!("Invalid DNS message: {e}"))?;
    if decoder.index() != bytes.len() {
        return Err("Trailing bytes after DNS message".into());
    }
    if msg.op_code() != OpCode::Query {
        return Err("Unsupported DNS opcode".into());
    }
    let response = msg.message_type() == MessageType::Response;
    if !response && msg.queries().is_empty() {
        return Err("DNS query has no question".into());
    }
    let mut key = format!("{}", msg.id());
    let mut names = Vec::new();
    let mut kinds = Vec::new();
    for q in msg.queries() {
        key.push_str(&format!(
            "|{}:{}:{}",
            q.name().to_ascii().to_lowercase(),
            q.query_type(),
            q.query_class()
        ));
        names.push(q.name().to_ascii());
        kinds.push(q.query_type().to_string());
    }
    let status = format!("{:?}", msg.response_code()).to_uppercase();
    let mut text = format!(
        "ID: 0x{:04X}\r\n{}\r\nRCODE: {}\r\nFlags: AA={} TC={} RD={} RA={} AD={} CD={}\r\n",
        msg.id(),
        if response { "Response" } else { "Query" },
        status,
        msg.authoritative(),
        msg.truncated(),
        msg.recursion_desired(),
        msg.recursion_available(),
        msg.authentic_data(),
        msg.checking_disabled()
    );
    text.push_str("\r\n[Question]\r\n");
    for q in msg.queries() {
        text.push_str(&format!(
            "{} {} {}\r\n",
            q.name(),
            q.query_class(),
            q.query_type()
        ));
    }
    for (label, records) in [
        ("Answer", msg.answers()),
        ("Authority", msg.name_servers()),
        ("Additional", msg.additionals()),
    ] {
        if records.is_empty() {
            continue;
        }
        text.push_str(&format!("\r\n[{label}]\r\n"));
        for r in records {
            if text.len() >= 60000 {
                text.push_str("DNS text preview limited.\r\n");
                break;
            }
            text.push_str(&format!(
                "{} {} {} {} {}\r\n",
                r.name(),
                r.ttl(),
                r.dns_class(),
                r.record_type(),
                r.data().map(ToString::to_string).unwrap_or_default()
            ));
        }
    }
    if let Some(edns) = msg.extensions() {
        text.push_str(&format!("\r\n[EDNS]\r\n{edns}\r\n"));
    }
    if text.len() > 65536 {
        let mut n = 65536;
        while !text.is_char_boundary(n) {
            n -= 1;
        }
        text.truncate(n);
        text.push_str("\r\nDNS text preview limited.");
    }
    Ok(Packet {
        id: msg.id(),
        response,
        key,
        name: names.join(", "),
        kind: kinds.join(", "),
        status,
        text,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ipv6_alias_https_records_and_bounded_damage() {
        for (kind,rdata,expected) in [
            (28u16,vec![0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1],"2001:db8::1"),
            (5,vec![0xc0,12],"CNAME"),
            (65,vec![0,1,0],"HTTPS"),
        ] {
            let mut b=vec![0,1,0x81,0x80,0,1,0,1,0,0,0,0,1,b'a',0];
            b.extend_from_slice(&kind.to_be_bytes());b.extend_from_slice(&[0,1,0xc0,12]);
            b.extend_from_slice(&kind.to_be_bytes());b.extend_from_slice(&[0,1,0,0,0,60]);
            b.extend_from_slice(&(rdata.len() as u16).to_be_bytes());b.extend_from_slice(&rdata);
            assert!(decode(&b).unwrap().text.contains(expected));
            for cut in 0..b.len() { assert!(decode(&b[..cut]).is_err()); }
            for i in 0..b.len() { let mut damaged=b.clone();damaged[i]^=0xff;let _=decode(&damaged); }
        }
    }
    #[test]
    fn compression_and_malformed_input() {
        let mut q = vec![
            0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1,
        ];
        assert_eq!(decode(&q).unwrap().name, "a.");
        q[2] = 0x81;
        q[3] = 0x80;
        q[7] = 1;
        q.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
        let p = decode(&q).unwrap();
        assert!(p.response);
        assert!(p.text.contains("1.2.3.4"));
        q.pop();
        assert!(decode(&q).is_err());
        assert!(decode(&[0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1]).is_err());
        for n in 0..19 {
            assert!(decode(&[0u8; 19][..n]).is_err());
        }
    }
}

#[cfg(test)]
mod resolver_tests {
    use super::*;
    use hickory_proto::{op::ResponseCode, rr::{Name, Record, RData, rdata::{A, CNAME}}};
    fn reply(ttl: u32) -> Message {
        let mut m = Message::from_vec(&question("example.org", false).unwrap()).unwrap();
        m.set_message_type(MessageType::Response);
        m.add_answer(Record::from_rdata(Name::from_ascii("example.org").unwrap(), ttl,
            RData::A(A("192.0.2.1".parse().unwrap()))));
        m
    }
    #[test]
    fn ttl_zero_cname_and_unrelated_records() {
        assert_eq!(answer(&reply(0).to_vec().unwrap(), "example.org", false).unwrap().ttl, 0);
        let mut m = reply(100);
        m.answers_mut().clear();
        m.add_answer(Record::from_rdata(Name::from_ascii("example.org").unwrap(), 15,
            RData::CNAME(CNAME(Name::from_ascii("alias.example.org").unwrap()))));
        m.add_answer(Record::from_rdata(Name::from_ascii("alias.example.org").unwrap(), 90,
            RData::A(A("192.0.2.2".parse().unwrap()))));
        m.add_answer(Record::from_rdata(Name::from_ascii("unrelated.org").unwrap(), 1,
            RData::A(A("192.0.2.3".parse().unwrap()))));
        let a = answer(&m.to_vec().unwrap(), "example.org", false).unwrap();
        assert_eq!(a.ttl, 15); assert_eq!(a.addresses, ["192.0.2.2"]);
        m.answers_mut().remove(1);
        let a = answer(&m.to_vec().unwrap(), "example.org", false).unwrap();
        assert!(a.addresses.is_empty()); assert_eq!(a.canonical, "alias.example.org.");
    }
    #[test]
    fn wrong_question_family_and_failure_are_rejected() {
        let mut m = reply(100);
        assert!(answer(&m.to_vec().unwrap(), "other.org", false).is_err());
        assert!(answer(&m.to_vec().unwrap(), "example.org", true).is_err());
        m.set_response_code(ResponseCode::NXDomain);
        assert!(answer(&m.to_vec().unwrap(), "example.org", false).is_err());
        m.set_response_code(ResponseCode::NoError).set_truncated(true);
        assert!(answer(&m.to_vec().unwrap(), "example.org", false).is_err());
    }
}
