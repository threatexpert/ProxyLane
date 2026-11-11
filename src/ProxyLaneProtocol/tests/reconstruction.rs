use proxylane_protocol::*;

fn analyzer(protocol: Protocol, limits: Limits) -> Analyzer {
    Analyzer::new(
        Connection {
            id: "test/1".into(),
            pid: 123,
            ..Connection::default()
        },
        protocol,
        limits,
    )
    .unwrap()
}
fn exchanges(output: Vec<Output>) -> Vec<Exchange> {
    output
        .into_iter()
        .map(|o| match o {
            Output::Exchange {
                exchange,
                connection,
                ..
            } => {
                assert_eq!(connection.pid, 123);
                *exchange
            }
            Output::Diagnostic { detail, .. } => panic!("unexpected diagnostic: {detail}"),
        })
        .collect()
}
fn diagnostic(output: &[Output], expected: &str) {
    assert!(
        output
            .iter()
            .any(|o| matches!(o, Output::Diagnostic { detail, .. } if detail.contains(expected))),
        "{output:?}"
    );
}
fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut frame = (payload.len() as u32).to_be_bytes()[1..].to_vec();
    frame.extend([kind, flags]);
    frame.extend(stream.to_be_bytes());
    frame.extend(payload);
    frame
}
fn h2_request(id: u32) -> Vec<u8> {
    frame(1, 5, id, &[0x82, 0x87, 0x84])
}
fn h2_start(a: &mut Analyzer) -> u64 {
    let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    assert!(a.push(Direction::Client, 0, preface).is_empty());
    preface.len() as u64
}

#[test]
fn h2_cancelled_response_updates_hpack_without_losing_other_requests() {
    let mut a=analyzer(Protocol::H2,Limits::default());
    let mut client=h2_start(&mut a);
    for id in [1,3] {
        let b=h2_request(id);assert!(a.push(Direction::Client,client,&b).is_empty());client+=b.len() as u64;
    }
    let reset=frame(3,0,1,&8u32.to_be_bytes());
    let cancelled=exchanges(a.push(Direction::Client,client,&reset));
    assert_eq!(cancelled.len(),1);assert_eq!(cancelled[0].id,1);
    assert_eq!(cancelled[0].problem.as_deref(),Some("RST_STREAM 8 from application"));
    // A late response inserts x-late: yes in HPACK's dynamic table, fragmented
    // across HEADERS/CONTINUATION and across input chunks.
    let block=b"\x88\x40\x06x-late\x03yes";
    let mut response=frame(1,0,1,&block[..5]);
    response.extend(frame(9,4,1,&block[5..]));
    response.extend(frame(0,1,1,b"cancelled body"));
    response.extend(frame(1,5,3,&[0x88,0xbe])); // reference the discarded header
    let mut out=Vec::new();
    for (offset,b) in response.iter().enumerate() {out.extend(a.push(Direction::Server,offset as u64,&[*b]));}
    let out=exchanges(out);assert_eq!(out.len(),1);assert_eq!(out[0].id,3);
    let message=out[0].response.as_ref().unwrap();assert!(message.complete);
    assert!(message.headers.contains(&("x-late".into(),"yes".into())));
    assert!(a.close().is_empty());
}

#[test]
fn h2_server_reset_allows_inflight_upload_but_not_unknown_response() {
    let mut a=analyzer(Protocol::H2,Limits::default());
    let mut offset=h2_start(&mut a);
    let request=frame(1,4,1,&[0x82,0x87,0x84]);
    assert!(a.push(Direction::Client,offset,&request).is_empty());offset+=request.len() as u64;
    assert_eq!(exchanges(a.push(Direction::Server,0,&frame(3,0,1,&8u32.to_be_bytes()))).len(),1);
    let upload=frame(0,1,1,b"already in flight");
    assert!(a.push(Direction::Client,offset,&upload).is_empty());offset+=upload.len() as u64;
    assert!(a.push(Direction::Client,offset,&h2_request(3)).is_empty());
    assert_eq!(exchanges(a.push(Direction::Server,13,&frame(1,5,3,&[0x88]))).len(),1);
    // An unrelated, never-requested stream must still fail validation.
    diagnostic(&a.push(Direction::Server,23,&frame(1,5,99,&[0x88])),"response without captured request");
}

#[test]
fn h2_unused_preconnection_is_quiet_but_partial_preface_is_not() {
    for clean in [false,true] {
        for server_settings in [false,true] {
            let mut a=analyzer(Protocol::H2,Limits::default());
            if server_settings {assert!(a.push(Direction::Server,0,&frame(4,0,0,&[])).is_empty());}
            assert!(a.eof(Direction::Client,clean).is_empty());
            assert!(a.eof(Direction::Server,clean).is_empty());
            assert!(a.close().is_empty());
        }
        let mut a=analyzer(Protocol::H2,Limits::default());
        assert!(a.push(Direction::Client,0,b"PRI * HTTP/2").is_empty());
        diagnostic(&a.eof(Direction::Client,clean),"incomplete");
    }
}

#[test]
fn http1_pipeline_informational_head_and_trailers() {
    let mut a = analyzer(Protocol::Http1, Limits::default());
    a.push(Direction::Client, 0, b"HEAD /one HTTP/1.1\r\nHost: example.test\r\n\r\nGET /two HTTP/1.1\r\nHost: example.test\r\n\r\n");
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 900\r\nContent-Encoding: gzip\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </style>\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;x=y\r\nabc\r\n2\r\nde\r\n0\r\nX-Check: yes\r\n\r\n";
    let mut out = Vec::new();
    for (i, b) in response.iter().enumerate() {
        out.extend(a.push(Direction::Server, i as u64, &[*b]));
    }
    let out = exchanges(out);
    assert_eq!(out.len(), 2);
    assert_eq!(
        out[0].request.as_ref().unwrap().method.as_deref(),
        Some("HEAD")
    );
    assert!(out[0]
        .response
        .as_ref()
        .unwrap()
        .decoding
        .starts_with("not applicable"));
    assert_eq!(out[1].informational[0].status, Some(103));
    assert_eq!(
        out[1].response.as_ref().unwrap().text.as_deref(),
        Some("abcde")
    );
    assert_eq!(
        out[1].response.as_ref().unwrap().trailers,
        vec![("x-check".into(), "yes".into())]
    );
}
#[test]
fn http1_truncation_gap_and_ambiguous_framing() {
    for bytes in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc".as_slice(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabc",
    ] {
        let mut a = analyzer(Protocol::Http1, Limits::default());
        a.push(Direction::Client, 0, b"GET / HTTP/1.1\r\n\r\n");
        a.push(Direction::Server, 0, bytes);
        let out = a.eof(Direction::Server, true);
        diagnostic(&out, "incomplete");
        if let Output::Exchange { exchange, .. } = &out[0] {
            assert!(!exchange.response.as_ref().unwrap().complete);
            assert!(exchange.response.as_ref().unwrap().decoded_base64.is_none());
        } else {
            panic!("missing incomplete exchange");
        }
    }
    let mut a = analyzer(Protocol::Http1, Limits::default());
    diagnostic(&a.push(Direction::Client, 4, b"GET"), "gap/overlap");
    assert!(a
        .push(Direction::Client, 0, b"GET / HTTP/1.1\r\n\r\n")
        .is_empty());
    let mut a = analyzer(Protocol::Http1, Limits::default());
    diagnostic(
        &a.push(
            Direction::Client,
            0,
            b"POST / HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
        ),
        "ambiguous",
    );
}
#[test]
fn http1_eof_delimited_vs_complete_without_tls_close_notify() {
    for clean in [true, false] {
        let mut a = analyzer(Protocol::Http1, Limits::default());
        a.push(Direction::Client, 0, b"GET / HTTP/1.1\r\n\r\n");
        a.push(Direction::Server, 0, b"HTTP/1.1 200 OK\r\n\r\nhello");
        let out = a.eof(Direction::Server, clean);
        if clean {
            assert_eq!(
                exchanges(out)[0].response.as_ref().unwrap().text.as_deref(),
                Some("hello")
            );
        } else {
            diagnostic(&out, "incomplete");
        }
    }
    let mut a = analyzer(Protocol::Http1, Limits::default());
    a.push(Direction::Client, 0, b"GET / HTTP/1.1\r\n\r\n");
    assert_eq!(
        exchanges(a.push(
            Direction::Server,
            0,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        ))
        .len(),
        1
    );
    assert!(a.eof(Direction::Server, false).is_empty());
}
#[test]
fn body_limit_does_not_lose_next_response() {
    let mut a = analyzer(
        Protocol::Http1,
        Limits {
            encoded_body: 2,
            ..Limits::default()
        },
    );
    a.push(
        Direction::Client,
        0,
        b"GET /a HTTP/1.1\r\n\r\nGET /b HTTP/1.1\r\n\r\n",
    );
    let out = exchanges(a.push(Direction::Server, 0, b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabcdeHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"));
    assert_eq!(out.len(), 2);
    let first = out[0].response.as_ref().unwrap();
    assert_eq!(first.body_bytes, 5);
    assert_eq!(first.body, b"ab");
    assert!(first.complete);
    assert!(first.decoding.contains("limit"));
    assert_eq!(
        out[1].response.as_ref().unwrap().text.as_deref(),
        Some("ok")
    );
}
#[test]
fn headers_and_pending_are_bounded() {
    let mut a = analyzer(
        Protocol::Http1,
        Limits {
            headers: 32,
            ..Limits::default()
        },
    );
    diagnostic(
        &a.push(
            Direction::Client,
            0,
            b"GET / HTTP/1.1\r\nX: 123456789012345678901234567890",
        ),
        "limit",
    );
    let mut a = analyzer(
        Protocol::Http1,
        Limits {
            pending: 1,
            ..Limits::default()
        },
    );
    diagnostic(
        &a.push(
            Direction::Client,
            0,
            b"GET / HTTP/1.1\r\n\r\nGET / HTTP/1.1\r\n\r\n",
        ),
        "pending",
    );
}
#[test]
fn h2_continuation_multiplex_padding_and_trailers() {
    let mut a = analyzer(Protocol::H2, Limits::default());
    let offset = h2_start(&mut a);
    let mut requests = h2_request(1);
    requests.extend(h2_request(3));
    a.push(Direction::Client, offset, &requests);
    let mut response = frame(1, 1, 3, &[0x88]); // END_STREAM before END_HEADERS
    response.extend(frame(9, 4, 3, &[]));
    response.extend(frame(1, 4, 1, &[0x88]));
    response.extend(frame(0, 8, 1, &[2, b'o', b'k', 0, 0]));
    response.extend(frame(1, 5, 1, &[0x00, 1, b'x', 1, b'y']));
    let mut output = Vec::new();
    for (i, b) in response.iter().enumerate() {
        output.extend(a.push(Direction::Server, i as u64, &[*b]));
    }
    let output = exchanges(output);
    assert_eq!(output.iter().map(|e| e.id).collect::<Vec<_>>(), [3, 1]);
    assert_eq!(
        output[1].response.as_ref().unwrap().text.as_deref(),
        Some("ok")
    );
    assert_eq!(
        output[1].response.as_ref().unwrap().trailers,
        vec![("x".into(), "y".into())]
    );
}
#[test]
fn h2_invalid_continuation_and_hpack_and_length() {
    let cases = [
        (
            vec![frame(1, 0, 1, &[0x88]), frame(6, 0, 0, &[0; 8])],
            "CONTINUATION",
        ),
        (
            vec![frame(1, 5, 1, &[0xff, 0xff, 0xff, 0xff, 0x0f])],
            "HPACK",
        ),
        (
            vec![frame(1, 5, 1, &[0x88, 0x0f, 13, 1, b'5'])],
            "Content-Length",
        ),
    ];
    for (frames, expected) in cases {
        let mut a = analyzer(Protocol::H2, Limits::default());
        let offset = h2_start(&mut a);
        a.push(Direction::Client, offset, &h2_request(1));
        diagnostic(&a.push(Direction::Server, 0, &frames.concat()), expected);
    }
}
#[test]
fn h2_error_goaway_keeps_inflight_streams_and_is_not_a_parser_error() {
    let mut a=analyzer(Protocol::H2,Limits::default());
    let offset=h2_start(&mut a);
    let first=h2_request(1);
    assert!(a.push(Direction::Client,offset,&first).is_empty());
    let goaway=frame(7,0,0,&[0,0,0,1,0,0,0,2]);
    assert!(a.push(Direction::Server,0,&goaway).is_empty());
    let response=frame(1,5,1,&[0x88]);
    let done=exchanges(a.push(Direction::Server,goaway.len() as u64,&response));
    assert_eq!(done.len(),1);assert!(done[0].response.as_ref().unwrap().complete);
    // A client request raced the GOAWAY. Its entire body must still be captured.
    let head=frame(1,4,3,&[0x83,0x87,0x84]);
    assert!(a.push(Direction::Client,offset+first.len() as u64,&head).is_empty());
    let body=frame(0,1,3,b"late request body");
    let done=exchanges(a.push(Direction::Client,offset+(first.len()+head.len()) as u64,&body));
    assert_eq!(done[0].request.as_ref().unwrap().body,b"late request body");
    assert!(done[0].problem.as_ref().unwrap().contains("GOAWAY"));
    assert!(a.eof(Direction::Server,true).is_empty());
    assert!(a.eof(Direction::Client,true).is_empty());
    let mut empty=analyzer(Protocol::H2,Limits::default());
    assert!(empty.push(Direction::Server,0,&frame(7,0,0,&[0,0,0,0,0,0,0,2])).is_empty());
    assert!(empty.eof(Direction::Server,true).is_empty());
}
#[test]
fn h2_reset_goaway_and_partial_frame() {
    for kind in [3, 7] {
        let mut a = analyzer(Protocol::H2, Limits::default());
        let offset = h2_start(&mut a);
        a.push(Direction::Client, offset, &h2_request(1));
        let bytes = if kind == 3 {
            frame(3, 0, 1, &8u32.to_be_bytes())
        } else {
            frame(7, 0, 0, &[0; 8])
        };
        let out = exchanges(a.push(Direction::Server, 0, &bytes));
        assert!(out[0].problem.as_ref().unwrap().contains(if kind == 3 {
            "RST_STREAM"
        } else {
            "GOAWAY"
        }));
    }
    let mut a = analyzer(Protocol::H2, Limits::default());
    let offset = h2_start(&mut a);
    a.push(Direction::Client, offset, &h2_request(1));
    a.push(Direction::Server, 0, &[0, 0, 3, 0]);
    diagnostic(&a.eof(Direction::Server, false), "incomplete HTTP/2 frame");
}
#[test]
fn hpack_expansion_and_frame_limits() {
    let mut a = analyzer(
        Protocol::H2,
        Limits {
            header_count: 4,
            ..Limits::default()
        },
    );
    let offset = h2_start(&mut a);
    a.push(Direction::Client, offset, &h2_request(1));
    diagnostic(
        &a.push(Direction::Server, 0, &frame(1, 5, 1, &[0x88; 5])),
        "header limit",
    );
    let mut a = analyzer(Protocol::H2, Limits::default());
    h2_start(&mut a);
    diagnostic(
        &a.push(Direction::Server, 0, &[0x20, 0, 0, 0, 0, 0, 0, 0, 1]),
        "frame limit",
    );
}

#[test]
fn hpack_table_survives_completed_exchanges() {
    let mut a = analyzer(Protocol::H2, Limits::default());
    let offset = h2_start(&mut a);
    let request = frame(1, 5, 1, &[0x82, 0x87, 0x84, 0x40, 1, b'x', 1, b'y']);
    a.push(Direction::Client, offset, &request);
    let response = frame(1, 5, 1, &[0x88]);
    assert_eq!(exchanges(a.push(Direction::Server, 0, &response)).len(), 1);
    // Dynamic index 62 refers to a header introduced by the now-removed flow.
    let next = frame(1, 5, 3, &[0x82, 0x87, 0x84, 0xbe]);
    a.push(Direction::Client, offset + request.len() as u64, &next);
    let out = exchanges(a.push(
        Direction::Server,
        response.len() as u64,
        &frame(1, 5, 3, &[0x88]),
    ));
    assert!(out[0]
        .request
        .as_ref()
        .unwrap()
        .headers
        .contains(&("x".into(), "y".into())));
}

#[test]
fn chunked_upload_and_early_continue() {
    let mut a = analyzer(Protocol::Http1, Limits::default());
    let request =
        b"POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\nExpect: 100-continue\r\n\r\n";
    a.push(Direction::Client, 0, request);
    let interim = b"HTTP/1.1 100 Continue\r\n\r\n";
    assert!(a.push(Direction::Server, 0, interim).is_empty());
    a.push(
        Direction::Client,
        request.len() as u64,
        b"3\r\nabc\r\n0\r\n\r\n",
    );
    let out = exchanges(a.push(
        Direction::Server,
        interim.len() as u64,
        b"HTTP/1.1 204 No Content\r\n\r\n",
    ));
    assert_eq!(
        out[0].request.as_ref().unwrap().text.as_deref(),
        Some("abc")
    );
    assert_eq!(out[0].informational[0].status, Some(100));
}

#[test]
fn damaged_wire_inputs_never_panic_or_resume_after_error() {
    let request1 = b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello".to_vec();
    let request2 = [
        b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".as_slice(),
        &h2_request(1),
    ]
    .concat();
    for (protocol, original) in [(Protocol::Http1, request1), (Protocol::H2, request2)] {
        for position in 0..original.len() {
            for value in [0, 10, 13, 32, 127, 128, 255] {
                let mut bytes = original.clone();
                bytes[position] = value;
                let mut a = analyzer(protocol, Limits::default());
                let mut terminal = false;
                for (index, chunk) in bytes.chunks(3).enumerate() {
                    let out = a.push(Direction::Client, (index * 3) as u64, chunk);
                    if terminal {
                        assert!(out.is_empty());
                    }
                    terminal |= out.iter().any(|o| matches!(o, Output::Diagnostic { .. }));
                }
                a.eof(Direction::Client, false);
                a.close();
            }
        }
    }
}

#[test]
fn malformed_hpack_blocks_are_errors_not_panics() {
    let mut seed = 0x1234_5678u32;
    let mut blocks = vec![
        vec![0xff, 0x80],
        vec![0x40],
        vec![0x40, 0],
        vec![0x3f],
        vec![0x40, 127],
    ];
    for length in 0..64 {
        for _ in 0..64 {
            let mut block = Vec::new();
            for _ in 0..length {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                block.push(seed as u8);
            }
            blocks.push(block);
        }
    }
    for block in blocks {
        let mut a = analyzer(Protocol::H2, Limits::default());
        let offset = h2_start(&mut a);
        a.push(Direction::Client, offset, &h2_request(1));
        a.push(Direction::Server, 0, &frame(1, 5, 1, &block));
        a.close();
    }
}
