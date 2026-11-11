use proxylane_protocol::*;
fn data(out:Vec<Output>)->Vec<Exchange>{out.into_iter().map(|o|match o {Output::Exchange{exchange,..}=>*exchange,Output::Diagnostic{detail,..}=>panic!("{detail}")}).collect()}
fn upgraded(compressed:bool)->(Analyzer,[u64;2]){
    let mut a=Analyzer::new(Connection::default(),Protocol::Http1,Limits {encoded_body:2*1024*1024,decoded_body:2*1024*1024,..Default::default()}).unwrap();
    let request=b"GET /chat HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n";
    assert!(a.push(Direction::Client,0,request).is_empty());
    let response=format!("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n{}\r\n",if compressed{"Sec-WebSocket-Extensions: permessage-deflate\r\n"}else{""});
    let r=data(a.push(Direction::Server,0,response.as_bytes()));assert_eq!(r[0].response.as_ref().unwrap().status,Some(101));
    (a,[request.len() as u64,response.len() as u64])
}
fn frame(op:u8,fin:bool,compressed:bool,masked:bool,b:&[u8])->Vec<u8>{
    let mut v=vec![op|if fin{128}else{0}|if compressed{64}else{0}];let flag=if masked{128}else{0};
    if b.len()<126{v.push(flag|b.len() as u8);}else if b.len()<65536{v.push(flag|126);v.extend_from_slice(&(b.len() as u16).to_be_bytes());}
    else{v.push(flag|127);v.extend_from_slice(&(b.len() as u64).to_be_bytes());}
    let mask=[21,32,43,54];if masked{v.extend_from_slice(&mask);}
    v.extend(b.iter().enumerate().map(|(i,x)|*x^if masked{mask[i%4]}else{0}));v
}
#[test]
fn fragmented_masked_messages_and_interleaved_control(){
    let(mut a,mut off)=upgraded(false);
    let mut bytes=frame(1,false,false,true,b"hello ");bytes.extend(frame(9,true,false,true,b"ping"));bytes.extend(frame(0,true,false,true,b"world"));
    let mut output=vec![];
    for b in bytes.chunks(1){output.extend(data(a.push(Direction::Client,off[0],b)));off[0]+=b.len() as u64;}
    assert_eq!(output.len(),2);
    assert_eq!(output[0].request.as_ref().unwrap().method.as_deref(),Some("PING"));
    assert_eq!(output[1].request.as_ref().unwrap().body,b"hello world");
    let b=frame(2,true,false,false,&vec![17;65536]);
    let mut output=vec![];for b in b.chunks(2048){output.extend(data(a.push(Direction::Server,off[1],b)));off[1]+=b.len() as u64;}
    assert_eq!(output[0].response.as_ref().unwrap().body.len(),65536);
}
#[test]
fn permessage_deflate_context_is_retained_across_messages(){
    let(mut a,mut off)=upgraded(true);let mut compressor=flate2::Compress::new(flate2::Compression::default(),false);
    for _ in 0..3 {
        let body=b"shared websocket compression dictionary".repeat(8192);
        let mut encoded=Vec::with_capacity(body.len()*2+1024);
        compressor.compress_vec(&body,&mut encoded,flate2::FlushCompress::Sync).unwrap();
        assert!(encoded.ends_with(&[0,0,255,255]));encoded.truncate(encoded.len()-4);
        let split=encoded.len()/2;let mut b=frame(2,false,true,true,&encoded[..split]);b.extend(frame(0,true,false,true,&encoded[split..]));
        let mut out=vec![];for chunk in b.chunks(17){out.extend(data(a.push(Direction::Client,off[0],chunk)));off[0]+=chunk.len() as u64;}
        assert_eq!(out.len(),1);assert_eq!(out[0].request.as_ref().unwrap().body,body);
    }
}
#[test]
fn upgrade_and_first_frame_in_one_input_preserves_frame_and_http_label(){
    let mut a=Analyzer::new(Connection::default(),Protocol::Http1,Limits::default()).unwrap();
    a.push(Direction::Client,0,b"GET / HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n");
    let mut b=b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n".to_vec();
    b.extend(frame(1,true,false,false,b"immediate"));
    let out=a.push(Direction::Server,0,&b);assert_eq!(out.len(),2);
    assert!(matches!(out[0],Output::Exchange{protocol:Protocol::Http1,..}));
    assert!(matches!(out[1],Output::Exchange{protocol:Protocol::WebSocket,..}));
}
#[test]
fn interrupted_message_is_incomplete_and_mask_violation_is_diagnostic(){
    let(mut a,off)=upgraded(false);let b=frame(1,false,false,true,b"partial");
    assert!(a.push(Direction::Client,off[0],&b).is_empty());
    let out=data(a.close_with_reason("monitoring stopped"));
    assert_eq!(out[0].problem.as_deref(),Some("monitoring stopped"));assert!(!out[0].request.as_ref().unwrap().complete);
    let(mut a,off)=upgraded(false);
    let out=a.push(Direction::Client,off[0],&frame(1,true,false,false,b"wrong mask"));
    assert!(out.iter().any(|o|matches!(o,Output::Diagnostic{detail,..} if detail.contains("mask"))));
}
