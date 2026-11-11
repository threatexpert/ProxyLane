//! Exercise the authenticated TLS rejection/retry path without public DNS.
//! HPKE ciphertext is intentionally opaque test data: this server cannot decrypt
//! ECH. TLS records, server authentication and the client's alert are real rustls.
use super::*;
use rustls::crypto::hpke::*;
use rustls::internal::msgs::{enums::{HpkeKem,HpkeKdf,HpkeAead},handshake::HpkeSymmetricCipherSuite};

#[derive(Debug)]
struct RejectedHpke;
impl HpkeSealer for RejectedHpke {
    fn seal(&mut self,_:&[u8],plain:&[u8])->Result<Vec<u8>,rustls::Error>{Ok(vec![0x73;plain.len()+16])}
}
impl Hpke for RejectedHpke {
    fn suite(&self)->HpkeSuite {HpkeSuite {kem:HpkeKem::DHKEM_X25519_HKDF_SHA256,sym:HpkeSymmetricCipherSuite {kdf_id:HpkeKdf::HKDF_SHA256,aead_id:HpkeAead::AES_128_GCM}}}
    fn setup_sealer(&self,_:&[u8],_:&HpkePublicKey)->Result<(EncapsulatedSecret,Box<dyn HpkeSealer>),rustls::Error>{Ok((EncapsulatedSecret(vec![7;32]),Box::new(Self)))}
    fn seal(&self,i:&[u8],a:&[u8],p:&[u8],k:&HpkePublicKey)->Result<(EncapsulatedSecret,Vec<u8>),rustls::Error>{let(e,mut s)=self.setup_sealer(i,k)?;Ok((e,s.seal(a,p)?))}
    fn open(&self,_:&EncapsulatedSecret,_:&[u8],_:&[u8],_:&[u8],_:&HpkePrivateKey)->Result<Vec<u8>,rustls::Error>{unreachable!()}
    fn setup_opener(&self,_:&EncapsulatedSecret,_:&[u8],_:&HpkePrivateKey)->Result<Box<dyn HpkeOpener>,rustls::Error>{unreachable!()}
    fn generate_key_pair(&self)->Result<(HpkePublicKey,HpkePrivateKey),rustls::Error>{unreachable!()}
}

#[test]
fn ech_authenticated_rejection_is_closed_and_fresh_retry_transfers() {
    for fragment in [1,4096] { check_rejection(fragment); }
}
fn check_rejection(fragment:usize) {
    let f=Fixture::new();
    let runtime=protocol::Runtime::new(proxylane_protocol::cache::CacheConfig {
        root:f.path.join("ech-retry"),..Default::default()
    }).unwrap();
    // RFC ECHConfigList: X25519/AES128GCM, public name localhost.
    let mut contents=vec![1,0,32,0,32];contents.extend([9;32]);
    contents.extend([0,4,0,1,0,1,32,9]);contents.extend(b"localhost");contents.extend([0,0]);
    let mut config=vec![0xfe,0x0d];config.extend((contents.len() as u16).to_be_bytes());config.extend(contents);
    let mut list=(config.len() as u16).to_be_bytes().to_vec();list.extend(config);
    let ech=rustls::client::EchConfig::new(list.into(),&[&RejectedHpke]).unwrap();
    let mut client=ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_ech(ech.into()).unwrap().with_root_certificates(f.context.roots.clone()).with_no_client_auth();
    client.alpn_protocols=vec![b"http/1.1".to_vec()];
    let mut app=ClientConnection::new(Arc::new(client),ServerName::try_from("localhost").unwrap()).unwrap();
    let (_,mut origin)=f.endpoints(false,true);
    let mut session=f.session();
    session.enable_protocol(runtime.clone(),proxylane_protocol::Connection{id:"ech".into(),..Default::default()});
    let rejected=(0..30).find_map(|_|exchange(&mut session,&mut app,&mut origin,fragment).err()).unwrap();
    assert!(rejected.contains("ServerRejectedEncryptedClientHello"),"{rejected}");
    // Flush the client's authenticated alert back into the MITM endpoint.
    let mut alert=Vec::new();app.write_tls(&mut alert).unwrap();assert!(!alert.is_empty());
    let error=alert.chunks(fragment).find_map(|part|session.feed(0,part).err()).unwrap();session.fail(error);
    assert_eq!(session.reported_error(),"ECH negotiation rejected; application may retry without ECH.");
    drop(session);
    let mut retry=f.session();
    retry.enable_protocol(runtime.clone(),proxylane_protocol::Connection{id:"retry".into(),..Default::default()});
    let (mut app,mut origin)=f.endpoints(false,true);
    for _ in 0..30 {exchange(&mut retry,&mut app,&mut origin,4096).unwrap();}
    app.writer().write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
    origin.writer().write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").unwrap();
    for _ in 0..4 {exchange(&mut retry,&mut app,&mut origin,4096).unwrap();}
    let mut received=Vec::new();let _=app.reader().read_to_end(&mut received);assert!(received.ends_with(b"\r\n\r\nok"));
    let result=runtime.query(&json!({"type":"poll","limit":64})).unwrap();
    assert!(result["records"].as_array().unwrap().iter().any(|r|r["connection"]["id"]=="ech" && r["status"]=="Closed"));
    assert!(!result["records"].as_array().unwrap().iter().any(|r|r["connection"]["id"]=="ech" && r["status"]=="Failed"));
    drop(retry);runtime.shutdown().unwrap();
}
