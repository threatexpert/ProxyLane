"""Synthetic TLS endpoints and assertions for mitm_e2e.py --protocol.

Uses its unique test CA and local proxy; never reads real application traffic.
Also invoked as an injected child (client mode) to exercise real Hook/PRC flow.
"""
import base64
import gzip
import json
import os
from pathlib import Path
import re
import socket
import socketserver
import ssl
import subprocess
import sys
import zlib

import brotli
import h2.config
import h2.connection
import h2.events
import zstandard

TEXT = ("ProxyLane live protocol / 进程关联 / payload cache\n" * 150).encode()
UPLOAD = gzip.compress(b"request body retained independently" * 100)
BODIES = [bytes(range(256)) * 1200, b"second-body" * 2000, bytes(range(256)) * 1200]


def records(result):
    values = [json.loads(line[len(b"PROTOCOL_JSON "):]) for line in result.stdout.splitlines()
              if line.startswith(b"PROTOCOL_JSON ")]
    flows = [entry for value in values if value["type"] == "records" for entry in value["records"]]
    return values, flows


def check_identity(result, flows):
    pid = int(re.search(br"CHILD pid=(\d+)", result.stderr).group(1))
    for flow in flows:
        c = flow["connection"]
        assert c["pid"] == pid and c["process_start"] > 0 and c["socket"] > 0 and c["generation"] > 0, c
        assert int(c["id"]) > 0 and ":" in c["destination"]
    return pid


def check_original(result, label, expected, work):
    values, flows = records(result)
    check_identity(result, flows)
    exchanges = [f for f in flows if f["type"] == "exchange"]
    if expected:
        assert len(exchanges) == 1, (label, flows)
        flow = exchanges[0]
        assert flow["exchange"]["response"]["status"] == 200, flow
        assert flow["exchange"]["response"]["complete"], flow
        assert flow["exchange"]["response"]["body_bytes"] == (2 * 1024 * 1024 if label == "large" else len(b"ProxyLane MITM verified\n"))
        # Original monitor and protocol stream use the SAME connection number.
        ids = re.findall(br"GUI_EVENT .*?connection=(\d+)", result.stderr)
        assert flow["connection"]["id"].encode() in ids
    else:
        assert not exchanges, (label, exchanges)
    assert values[-1]["type"] == "inactive", values[-1]
    assert not list((work / "protocol-cache").glob("run-*"))


class Origin(socketserver.BaseRequestHandler):
    def handle(self):
        with self.server.context.wrap_socket(self.request, server_side=True) as tls:
            tls.settimeout(20)
            mode = self.server.mode
            if mode == "h2":
                conn = h2.connection.H2Connection(h2.config.H2Configuration(client_side=False))
                conn.initiate_connection()
                tls.sendall(conn.data_to_send())
                requests = {}
                ended = set()
                while len(ended) != 2:
                    for event in conn.receive_data(tls.recv(65536)):
                        if isinstance(event, h2.events.DataReceived):
                            requests.setdefault(event.stream_id, bytearray()).extend(event.data)
                            conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                        if isinstance(event, h2.events.StreamEnded): ended.add(event.stream_id)
                    outgoing = conn.data_to_send()
                    if outgoing: tls.sendall(outgoing)
                assert gzip.decompress(requests[1]) == gzip.decompress(UPLOAD)
                for stream, coding, encoded in [(3, "br", brotli.compress(TEXT)),
                                                  (1, "zstd", zstandard.ZstdCompressor().compress(TEXT))]:
                    conn.send_headers(stream, [(":status", "200"), ("content-encoding", coding),
                                              ("content-length", str(len(encoded))), ("x-reused", "dynamic-value")])
                    conn.send_data(stream, encoded, end_stream=True)
                outgoing = conn.data_to_send()
                for index in range(0, len(outgoing), 19): tls.sendall(outgoing[index:index + 19])
                # Client confirms receipt by closing TLS; don't race GOAWAY.
                while tls.recv(65536): pass
                tls.unwrap().close()
                return
            if mode == "nonhttp":
                assert tls.recv(1024) == b"\x00binary-request"
                tls.sendall(b"\x01binary-response")
            else:
                count = 3 if mode == "limits" else 1
                buffered = b""
                for index in range(count):
                    while b"\r\n\r\n" not in buffered: buffered += tls.recv(4096)
                    _, buffered = buffered.split(b"\r\n\r\n", 1)
                    if mode == "limits":
                        body = BODIES[index]
                        tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n")
                        for pos in range(0, len(body), 4096): tls.sendall(body[pos:pos + 4096])
                    else:
                        body = gzip.compress(TEXT)
                        tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n")
                        for pos in range(0, len(body), 7):
                            chunk = body[pos:pos + 7]
                            tls.sendall(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                        tls.sendall(b"0\r\nX-Trailer: retained\r\n\r\n")
            tls.unwrap().close()


def client(port, ca, mode):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(Path(ca).read_bytes()))
    if mode not in ("noalpn", "nonhttp"):
        context.set_alpn_protocols(["h2" if mode == "h2" else "http/1.1"])
    # Two sockets in one PID test lifetime/connection association and reused H2 stream IDs.
    for _ in range(2 if mode == "h2" else 1):
        with socket.create_connection(("203.0.113.10", port), 10) as raw:
            with context.wrap_socket(raw, server_hostname="mitm.test") as tls:
                tls.settimeout(20)
                if mode == "h2":
                    conn = h2.connection.H2Connection()
                    conn.initiate_connection()
                    for stream in (1, 3):
                        headers = [(":method", "POST" if stream == 1 else "GET"), (":scheme", "https"),
                                   (":authority", "mitm.test"), (":path", f"/stream-{stream}"), ("x-reused", "dynamic-value")]
                        if stream == 1: headers += [("content-encoding", "gzip"), ("content-length", str(len(UPLOAD)))]
                        conn.send_headers(stream, headers, end_stream=stream == 3)
                        if stream == 1: conn.send_data(stream, UPLOAD, end_stream=True)
                    tls.sendall(conn.data_to_send())
                    responses, ended, codings = {}, set(), {}
                    while len(ended) != 2:
                        for event in conn.receive_data(tls.recv(65536)):
                            if isinstance(event, h2.events.ResponseReceived): codings[event.stream_id] = dict(event.headers)[b"content-encoding"]
                            if isinstance(event, h2.events.DataReceived):
                                responses.setdefault(event.stream_id, bytearray()).extend(event.data)
                                conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                            if isinstance(event, h2.events.StreamEnded): ended.add(event.stream_id)
                        outgoing = conn.data_to_send()
                        if outgoing: tls.sendall(outgoing)
                    assert brotli.decompress(responses[3]) == TEXT
                    assert zstandard.ZstdDecompressor().decompress(responses[1]) == TEXT
                elif mode == "nonhttp":
                    tls.sendall(b"\x00binary-request")
                    assert tls.recv(1024) == b"\x01binary-response"
                else:
                    import http.client
                    for index in range(3 if mode == "limits" else 1):
                        tls.sendall(f"GET /request-{index} HTTP/1.1\r\nHost: mitm.test\r\n\r\n".encode())
                        response = http.client.HTTPResponse(tls)
                        response.begin()
                        body = response.read()
                        assert body == BODIES[index] if mode == "limits" else gzip.decompress(body) == TEXT
                        response.close()
                tls.unwrap().close()


def run(host, env, work, proxy, start, servers):
    for mode in ("chunked", "noalpn", "h2", "limits", "nonhttp", "chunked32"):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(work / "origin.pem", work / "origin-key.pem")
        if mode not in ("noalpn", "nonhttp"):
            context.set_alpn_protocols(["h2" if mode == "h2" else "http/1.1"])
        server = start(Origin, context)
        server.mode = mode
        servers.append(server)
        child = [sys.executable, str(Path(__file__).resolve()), "client", str(server.server_address[1]),
                 str(work / "pki" / "proxylane-ca.cer"), mode]
        test_host = host
        if mode == "chunked32":
            port = server.server_address[1]
            child = [str(Path(os.environ["WINDIR"]) / "SysWOW64" / "curl.exe"), "--silent", "--show-error", "--compressed",
                     "--noproxy", "*", "--max-time", "20", "--resolve", f"mitm.test:{port}:203.0.113.10",
                     "--output", str(work / "protocol-chunked32.body"), f"https://mitm.test:{port}/probe"]
        case_env = dict(env, PROXYLANE_TEST_NO_PREVIEW="1")
        if mode == "limits":
            case_env.update(PROXYLANE_PROTOCOL_ENTRY_BYTES=str(128 * 1024), PROXYLANE_PROTOCOL_TOTAL_BYTES=str(192 * 1024))
        result = subprocess.run([str(test_host), str(proxy.server_address[1]), "SOCKS5", subprocess.list2cmdline(child)],
                                env=case_env, capture_output=True, timeout=45)
        (work / ("protocol-" + mode + ".log")).write_bytes(result.stdout + result.stderr)
        assert result.returncode == 0, (mode, result.returncode, result.stderr.decode(errors="replace"))
        assert b"GUI_EVENT" not in result.stderr, "Protocol reconstruction must work without the legacy preview observer"
        values, flows = records(result)
        check_identity(result, flows)
        exchanges = [r for r in flows if r["type"] == "exchange"]
        stats = next(v for v in values if v["type"] == "stats")
        assert stats["rejected_connections"] == 0 and stats["cache_error"] is None
        if mode == "nonhttp":
            assert not exchanges and "unrecognized TLS application protocol" in str(flows)
        else:
            assert not [r for r in flows if r["type"] != "exchange"], flows
            assert len(exchanges) == (4 if mode == "h2" else 3 if mode == "limits" else 1)
            for flow in exchanges:
                assert flow["exchange"]["response"]["complete"] and flow["exchange"]["problem"] is None, flow
                if mode != "limits": assert flow["exchange"]["response"]["text"] == TEXT.decode()
            if mode == "h2":
                assert [f["exchange"]["id"] for f in exchanges] == [3, 1, 3, 1]
                assert len({f["connection"]["id"] for f in exchanges}) == 2
                assert len({f["connection"]["generation"] for f in exchanges}) == 2
                for flow in exchanges:
                    assert flow["protocol"] == "h2"
                    if flow["exchange"]["id"] == 1:
                        assert flow["exchange"]["request"]["text"] == gzip.decompress(UPLOAD).decode()
            if mode == "limits":
                assert stats["cache"]["peak_bytes"] <= 192 * 1024
                assert stats["cache"]["evicted_entries"] >= 1
                statuses = [v["cache"] for v in values if v["type"] == "cache_status" and v["cache"]]
                assert statuses[0]["evicted"]
                assert statuses[2]["response_bytes"] == 128 * 1024
                assert statuses[2]["reason"] == "per-exchange payload limit"
                assert [f["exchange"]["response"]["body_bytes"] for f in exchanges] == list(map(len, BODIES))
            else:
                payloads = [v["payload"] for v in values if v["type"] == "cache_payload" and v["payload"]["decoded"]]
                assert len(payloads) == len(exchanges)
                assert all(base64.b64decode(p["data_base64"]) == TEXT for p in payloads)
        assert values[-1]["type"] == "inactive"
        assert not list((work / "protocol-cache").glob("run-*"))
        print("protocol-" + mode + " PASS", flush=True)


if __name__ == "__main__":
    assert sys.argv[1] == "client"
    client(int(sys.argv[2]), sys.argv[3], sys.argv[4])
