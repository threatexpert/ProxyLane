"""Controlled negative certificates. Reads existing test CA keys locally; never logs them.
No trust-store changes. Temporary leaf keys are removed by the runner's finally.
"""
import base64
import ctypes as C
import datetime as dt
import json
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

def proxylane_key(path):
    stored=json.loads(path.read_text())
    data=base64.b64decode(stored['protected_key'])
    class Blob(C.Structure): _fields_=[('size',C.c_uint32),('data',C.c_void_p)]
    raw=C.create_string_buffer(data); source=Blob(len(data),C.cast(raw,C.c_void_p)); output=Blob()
    api=C.WinDLL('crypt32',use_last_error=True).CryptUnprotectData
    api.argtypes=[C.POINTER(Blob),C.c_void_p,C.c_void_p,C.c_void_p,C.c_void_p,C.c_uint32,C.POINTER(Blob)]
    if not api(C.byref(source),None,None,None,None,1,C.byref(output)): raise C.WinError(C.get_last_error())
    free=C.WinDLL('kernel32').LocalFree; free.argtypes=[C.c_void_p]; free.restype=C.c_void_p
    try:
        key=serialization.load_der_private_key(C.string_at(output.data,output.size),password=None)
    finally:
        C.memset(output.data,0,output.size); free(output.data)
    return x509.load_der_x509_certificate(base64.b64decode(stored['certificate'])),key

def generate(work,stored):
    ca,key=proxylane_key(stored)
    now=dt.datetime.now(dt.timezone.utc)
    other_data=(Path.home()/'.mitmproxy/mitmproxy-ca.pem').read_bytes()
    other_ca=x509.load_pem_x509_certificate(other_data)
    other_key=serialization.load_pem_private_key(other_data,password=None)
    fake_key=ec.generate_private_key(ec.SECP256R1())
    # Same display name as ProxyLane: must never pass identity comparison.
    fake_ca=(x509.CertificateBuilder().subject_name(ca.subject).issuer_name(ca.subject)
        .public_key(fake_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-dt.timedelta(days=1)).not_valid_after(now+dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True,path_length=0),True).sign(fake_key,hashes.SHA256()))
    result={}
    for mode,issuer,issuer_key,name,expired in [
        ('other-trusted-ca',other_ca,other_key,'quic-probe.test',False),
        ('same-name-untrusted-ca',fake_ca,fake_key,'quic-probe.test',False),
        ('expired',ca,key,'quic-probe.test',True),
        ('wrong-host',ca,key,'wrong.quic-probe.test',False)]:
        leafkey=ec.generate_private_key(ec.SECP256R1())
        cert=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,name)]))
            .issuer_name(issuer.subject).public_key(leafkey.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-dt.timedelta(days=2))
            .not_valid_after(now-dt.timedelta(hours=1) if expired else now+dt.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]),False)
            .add_extension(x509.BasicConstraints(ca=False,path_length=None),True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),False)
            .sign(issuer_key,hashes.SHA256()))
        der=work/(mode+'.der'); private=work/(mode+'-key.der')
        der.write_bytes(cert.public_bytes(serialization.Encoding.DER))
        private.write_bytes(leafkey.private_bytes(serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        result[mode]={'quic_certificate':str(der),'quic_key':str(private),
                      'expected_issuer_sha256':issuer.fingerprint(hashes.SHA256()).hex()}
    return result
