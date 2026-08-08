use std::collections::VecDeque;
use std::ffi::c_void;
use std::ffi::CStr;
use std::io::{Cursor, Read, Write};
use std::os::raw::c_char;
use std::ptr;
use std::sync::Arc;

use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use p256::ecdsa::SigningKey;
use p256::pkcs8::EncodePrivateKey;
use p256::SecretKey;
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, Error as TlsError, SignatureScheme,
};
use sha2::Sha256;
use x509_parser::parse_x509_certificate;

type Aes256Ctr = ctr::Ctr128BE<Aes256>;
type HmacSha256 = Hmac<Sha256>;

const ABI_VERSION: u32 = 1;
const OK: i32 = 0;
const ERROR: i32 = -1;
const WOULD_BLOCK: i32 = -2;
const INVALID_ARGUMENT: i32 = -3;
const BUFFER_TOO_SMALL: i32 = -4;
const EXPORTER_LABEL: &[u8] = b"EXPERIMENTAL-SERVER-KEY";
const UDP_IV_SIZE: usize = 16;

struct Session {
    connection: ClientConnection,
    pending_tls: VecDeque<u8>,
    last_error: String,
}

impl Session {
    fn fail(&mut self, error: impl std::fmt::Display) -> i32 {
        self.last_error = error.to_string();
        ERROR
    }

    fn collect_tls(&mut self) -> Result<(), std::io::Error> {
        while self.connection.wants_write() {
            let mut output = Vec::new();
            let written = self.connection.write_tls(&mut output)?;
            if written == 0 {
                break;
            }
            self.pending_tls.extend(output);
        }
        Ok(())
    }
}

#[derive(Debug)]
struct PskServerVerifier {
    expected_public_key: Vec<u8>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PskServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let (_, certificate) = parse_x509_certificate(end_entity.as_ref())
            .map_err(|_| TlsError::General("invalid gonc server certificate".into()))?;
        let actual = certificate.public_key().subject_public_key.data.as_ref();
        if actual != self.expected_public_key.as_slice() {
            return Err(TlsError::General(
                "PSK identity mismatch: unexpected server public key".into(),
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(message, certificate, signature, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, certificate, signature, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

fn derive_secret(psk: &[u8]) -> Result<SecretKey, String> {
    let mut mac = HmacSha256::new_from_slice(psk).map_err(|e| e.to_string())?;
    mac.update(b"ecdsa-psk-derive");
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&mac.finalize().into_bytes());

    // P-256's order is less than 2^256, so the SHA-256 value needs at most
    // one subtraction to match gonc's big.Int.Mod implementation.
    const ORDER: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];
    if scalar >= ORDER {
        let mut borrow = 0u16;
        for index in (0..32).rev() {
            let lhs = scalar[index] as u16;
            let rhs = ORDER[index] as u16 + borrow;
            if lhs >= rhs {
                scalar[index] = (lhs - rhs) as u8;
                borrow = 0;
            } else {
                scalar[index] = (lhs + 256 - rhs) as u8;
                borrow = 1;
            }
        }
    }
    SecretKey::from_slice(&scalar).map_err(|_| "derived invalid P-256 secret".into())
}

fn create_connection(psk: &[u8], server_name: &str) -> Result<ClientConnection, String> {
    if psk.is_empty() {
        return Err("PSK must not be empty".into());
    }
    let secret = derive_secret(psk)?;
    let signing = SigningKey::from(secret.clone());
    let expected_public_key = signing
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();

    let pkcs8 = secret.to_pkcs8_der().map_err(|e| e.to_string())?;
    let private_der = PrivatePkcs8KeyDer::from(pkcs8.as_bytes().to_vec());
    let key_pair =
        KeyPair::from_pkcs8_der_and_sign_algo(&private_der, &rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| e.to_string())?;
    let certificate_name = if server_name.is_empty() {
        "localhost"
    } else {
        server_name
    };
    let mut params =
        CertificateParams::new(vec![certificate_name.to_owned()]).map_err(|e| e.to_string())?;
    params.is_ca = IsCa::NoCa;
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ClientAuth,
        ExtendedKeyUsagePurpose::ServerAuth,
    ];
    let certificate = params.self_signed(&key_pair).map_err(|e| e.to_string())?;

    let provider = rustls::crypto::ring::default_provider();
    let verifier = Arc::new(PskServerVerifier {
        expected_public_key,
        algorithms: provider.signature_verification_algorithms,
    });
    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(
            vec![CertificateDer::from(certificate.der().to_vec())],
            PrivateKeyDer::Pkcs8(private_der.clone_key()),
        )
        .map_err(|e| e.to_string())?;
    let name = ServerName::try_from(certificate_name.to_owned()).map_err(|e| e.to_string())?;
    ClientConnection::new(Arc::new(config), name).map_err(|e| e.to_string())
}

unsafe fn session_mut<'a>(session: *mut c_void) -> Result<&'a mut Session, i32> {
    (session as *mut Session).as_mut().ok_or(INVALID_ARGUMENT)
}

#[no_mangle]
pub extern "C" fn plst_abi_version() -> u32 {
    ABI_VERSION
}

#[no_mangle]
pub unsafe extern "C" fn plst_session_create(
    psk: *const u8,
    psk_len: usize,
    server_name: *const c_char,
    output: *mut *mut c_void,
) -> i32 {
    if psk.is_null() || psk_len == 0 || server_name.is_null() || output.is_null() {
        return INVALID_ARGUMENT;
    }
    let psk = std::slice::from_raw_parts(psk, psk_len);
    let server_name = match CStr::from_ptr(server_name).to_str() {
        Ok(value) => value,
        Err(_) => return INVALID_ARGUMENT,
    };
    match create_connection(psk, server_name) {
        Ok(connection) => {
            let mut session = Box::new(Session {
                connection,
                pending_tls: VecDeque::new(),
                last_error: String::new(),
            });
            if let Err(error) = session.collect_tls() {
                return session.fail(error);
            }
            *output = Box::into_raw(session).cast();
            OK
        }
        Err(_) => ERROR,
    }
}

#[no_mangle]
pub unsafe extern "C" fn plst_session_free(session: *mut c_void) {
    if !session.is_null() {
        drop(Box::from_raw(session as *mut Session));
    }
}

#[no_mangle]
pub unsafe extern "C" fn plst_session_is_ready(session: *mut c_void) -> i32 {
    match session_mut(session) {
        Ok(value) => (!value.connection.is_handshaking()) as i32,
        Err(code) => code,
    }
}

#[no_mangle]
pub unsafe extern "C" fn plst_session_feed_tls(
    session: *mut c_void,
    data: *const u8,
    data_len: usize,
    consumed: *mut usize,
) -> i32 {
    if (data.is_null() && data_len != 0) || consumed.is_null() {
        return INVALID_ARGUMENT;
    }
    let session = match session_mut(session) {
        Ok(v) => v,
        Err(c) => return c,
    };
    let input = if data_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(data, data_len)
    };
    let mut cursor = Cursor::new(input);
    match session.connection.read_tls(&mut cursor) {
        Ok(_) => *consumed = cursor.position() as usize,
        Err(error) => return session.fail(error),
    }
    if let Err(error) = session.connection.process_new_packets() {
        return session.fail(error);
    }
    if let Err(error) = session.collect_tls() {
        return session.fail(error);
    }
    OK
}

#[no_mangle]
pub unsafe extern "C" fn plst_session_drain_tls(
    session: *mut c_void,
    output: *mut u8,
    output_capacity: usize,
    written: *mut usize,
) -> i32 {
    if (output.is_null() && output_capacity != 0) || written.is_null() {
        return INVALID_ARGUMENT;
    }
    let session = match session_mut(session) {
        Ok(v) => v,
        Err(c) => return c,
    };
    if let Err(error) = session.collect_tls() {
        return session.fail(error);
    }
    let count = output_capacity.min(session.pending_tls.len());
    for index in 0..count {
        *output.add(index) = session.pending_tls.pop_front().unwrap();
    }
    *written = count;
    OK
}

#[no_mangle]
pub unsafe extern "C" fn plst_session_write_plain(
    session: *mut c_void,
    data: *const u8,
    data_len: usize,
    written: *mut usize,
) -> i32 {
    if (data.is_null() && data_len != 0) || written.is_null() {
        return INVALID_ARGUMENT;
    }
    let session = match session_mut(session) {
        Ok(v) => v,
        Err(c) => return c,
    };
    if session.connection.is_handshaking() {
        *written = 0;
        return WOULD_BLOCK;
    }
    let input = if data_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(data, data_len)
    };
    match session.connection.writer().write(input) {
        Ok(count) => *written = count,
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
            *written = 0;
            return WOULD_BLOCK;
        }
        Err(error) => return session.fail(error),
    }
    if let Err(error) = session.collect_tls() {
        return session.fail(error);
    }
    OK
}

#[no_mangle]
pub unsafe extern "C" fn plst_session_read_plain(
    session: *mut c_void,
    output: *mut u8,
    output_capacity: usize,
    read: *mut usize,
) -> i32 {
    if (output.is_null() && output_capacity != 0) || read.is_null() {
        return INVALID_ARGUMENT;
    }
    let session = match session_mut(session) {
        Ok(v) => v,
        Err(c) => return c,
    };
    let output = if output_capacity == 0 {
        &mut []
    } else {
        std::slice::from_raw_parts_mut(output, output_capacity)
    };
    match session.connection.reader().read(output) {
        Ok(count) => {
            *read = count;
            if count == 0 {
                WOULD_BLOCK
            } else {
                OK
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
            *read = 0;
            WOULD_BLOCK
        }
        Err(error) => session.fail(error),
    }
}

#[no_mangle]
pub unsafe extern "C" fn plst_session_send_close_notify(session: *mut c_void) -> i32 {
    let session = match session_mut(session) {
        Ok(v) => v,
        Err(c) => return c,
    };
    session.connection.send_close_notify();
    match session.collect_tls() {
        Ok(()) => OK,
        Err(error) => session.fail(error),
    }
}

#[no_mangle]
pub unsafe extern "C" fn plst_session_export_key(
    session: *mut c_void,
    output: *mut u8,
    output_len: usize,
) -> i32 {
    if output.is_null() || output_len != 32 {
        return INVALID_ARGUMENT;
    }
    let session = match session_mut(session) {
        Ok(v) => v,
        Err(c) => return c,
    };
    if session.connection.is_handshaking() {
        return WOULD_BLOCK;
    }
    let output = std::slice::from_raw_parts_mut(output, output_len);
    match session
        .connection
        .export_keying_material(output, EXPORTER_LABEL, None)
    {
        Ok(_) => OK,
        Err(error) => session.fail(error),
    }
}

#[no_mangle]
pub unsafe extern "C" fn plst_session_last_error(
    session: *mut c_void,
    output: *mut c_char,
    output_capacity: usize,
) -> i32 {
    if output.is_null() || output_capacity == 0 {
        return INVALID_ARGUMENT;
    }
    let session = match session_mut(session) {
        Ok(v) => v,
        Err(c) => return c,
    };
    let bytes = session.last_error.as_bytes();
    let count = bytes.len().min(output_capacity - 1);
    ptr::copy_nonoverlapping(bytes.as_ptr(), output.cast::<u8>(), count);
    *output.add(count) = 0;
    OK
}

fn crypt_udp(key: &[u8], iv: &[u8; UDP_IV_SIZE], input: &[u8], output: &mut [u8]) {
    output[..input.len()].copy_from_slice(input);
    let mut cipher = Aes256Ctr::new(key.into(), iv.into());
    cipher.apply_keystream(&mut output[..input.len()]);
}

#[no_mangle]
pub unsafe extern "C" fn plst_udp_encrypt(
    key: *const u8,
    key_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    output: *mut u8,
    output_capacity: usize,
    written: *mut usize,
) -> i32 {
    if key.is_null()
        || key_len != 32
        || (plaintext.is_null() && plaintext_len != 0)
        || output.is_null()
        || written.is_null()
    {
        return INVALID_ARGUMENT;
    }
    if output_capacity < UDP_IV_SIZE + plaintext_len {
        return BUFFER_TOO_SMALL;
    }
    let key = std::slice::from_raw_parts(key, key_len);
    let plaintext = std::slice::from_raw_parts(plaintext, plaintext_len);
    let output = std::slice::from_raw_parts_mut(output, output_capacity);
    let mut iv = [0u8; UDP_IV_SIZE];
    if getrandom::getrandom(&mut iv).is_err() {
        return ERROR;
    }
    output[..UDP_IV_SIZE].copy_from_slice(&iv);
    crypt_udp(key, &iv, plaintext, &mut output[UDP_IV_SIZE..]);
    *written = UDP_IV_SIZE + plaintext_len;
    OK
}

#[no_mangle]
pub unsafe extern "C" fn plst_udp_decrypt(
    key: *const u8,
    key_len: usize,
    packet: *const u8,
    packet_len: usize,
    output: *mut u8,
    output_capacity: usize,
    written: *mut usize,
) -> i32 {
    if key.is_null()
        || key_len != 32
        || packet.is_null()
        || packet_len < UDP_IV_SIZE
        || output.is_null()
        || written.is_null()
    {
        return INVALID_ARGUMENT;
    }
    let plaintext_len = packet_len - UDP_IV_SIZE;
    if output_capacity < plaintext_len {
        return BUFFER_TOO_SMALL;
    }
    let key = std::slice::from_raw_parts(key, key_len);
    let packet = std::slice::from_raw_parts(packet, packet_len);
    let output = std::slice::from_raw_parts_mut(output, output_capacity);
    let iv: &[u8; UDP_IV_SIZE] = packet[..UDP_IV_SIZE].try_into().unwrap();
    crypt_udp(key, iv, &packet[UDP_IV_SIZE..], output);
    *written = plaintext_len;
    OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_round_trip() {
        let key = [0x5au8; 32];
        let iv = [0x33u8; 16];
        let input = b"\0\0\0\x01\x08\x08\x08\x08\0\x35dns";
        let mut encrypted = vec![0u8; input.len()];
        crypt_udp(&key, &iv, input, &mut encrypted);
        let mut plain = vec![0u8; input.len()];
        crypt_udp(&key, &iv, &encrypted, &mut plain);
        assert_eq!(plain, input);
    }

    #[test]
    fn psk_derivation_is_stable() {
        let secret = derive_secret(b"123").unwrap();
        assert_eq!(secret.to_bytes().len(), 32);
        assert_eq!(
            SigningKey::from(secret)
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .len(),
            65
        );
    }
}
