"""TLS 1.3 probe for systems whose Schannel supports only TLS 1.2."""
import socket
import ssl
import sys
from pathlib import Path

port, ca, output = int(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(ca.read_bytes()))
context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
context.set_alpn_protocols(["http/1.1"])
with socket.create_connection(("203.0.113.10", port), 10) as raw:
    with context.wrap_socket(raw, server_hostname="mitm.test") as tls:
        assert tls.version() == "TLSv1.3"
        tls.sendall(b"GET /probe HTTP/1.1\r\nHost: mitm.test\r\nConnection: close\r\n\r\n")
        result = b""
        while True:
            part = tls.recv(65536)
            if not part:
                break
            result += part
        output.write_bytes(result.split(b"\r\n\r\n", 1)[1])
        tls.unwrap().close()
