"""Independent wire-format/codec oracle for the Rust protocol prototype.

Requires Python h2, brotli, zstandard; does not touch proxies, certificates or GUI.
Fixtures are synthetic. h2's endpoint implementation generates real HPACK frames.
"""
import argparse
import base64
import gzip
import json
from pathlib import Path
import subprocess
import zlib

import brotli
import h2.config
import h2.connection
import h2.settings
import zstandard

ROOT = Path(__file__).resolve().parents[2]
BODY = ('{"message":"ProxyLane 协议还原验证","items":[1,2,3]}\n' * 20).encode()
CODECS = {
    "identity": lambda data: data,
    "gzip": lambda data: gzip.compress(data, mtime=0),
    "deflate": zlib.compress,
    "raw-deflate": lambda data: zlib.compress(data)[2:-4],
    "br": brotli.compress,
    "zstd": lambda data: zstandard.ZstdCompressor().compress(data),
    "gzip, br": lambda data: brotli.compress(gzip.compress(data, mtime=0)),
}


class Trace:
    def __init__(self, protocol, size=4096):
        self.id = "fixture-" + protocol
        self.size = size
        self.offsets = {"client": 0, "server": 0}
        self.events = [{"type": "open", "protocol": protocol, "connection": {
            "id": self.id, "pid": 1234, "process_start": 987654321,
            "socket": 1680, "generation": 18, "destination": "example.test:8443",
        }}]

    def data(self, direction, data):
        for start in range(0, len(data), self.size):
            part = data[start:start + self.size]
            self.events.append({"type": "data", "connection_id": self.id,
                                "direction": direction, "offset": self.offsets[direction],
                                "data_base64": base64.b64encode(part).decode()})
            self.offsets[direction] += len(part)

    def finish(self):
        for direction in ("client", "server"):
            self.events.append({"type": "eof", "connection_id": self.id,
                                "direction": direction, "clean": True})
        self.events.append({"type": "close", "connection_id": self.id})
        return self.events


def encoding(name):
    return "deflate" if name == "raw-deflate" else name


def http1(name, size, payload=None, chunked=True):
    compressed = CODECS[name](BODY) if payload is None else payload
    trace = Trace("http1", size)
    trace.data("client", ("POST /echo HTTP/1.1\r\nHost: example.test\r\n"
                         f"Content-Encoding: {encoding(name)}\r\nContent-Length: {len(compressed)}\r\n\r\n").encode() + compressed)
    if chunked:
        trace.data("server", ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                              f"Content-Encoding: {encoding(name)}\r\nTransfer-Encoding: chunked\r\n\r\n").encode())
        for start in range(0, len(compressed), 11):
            part = compressed[start:start + 11]
            trace.data("server", f"{len(part):x};test=1\r\n".encode() + part + b"\r\n")
        trace.data("server", b"0\r\nX-Checksum: fixture\r\n\r\n")
    else:
        trace.data("server", (f"HTTP/1.1 200 OK\r\nContent-Encoding: {encoding(name)}\r\n"
                              f"Content-Length: {len(compressed)}\r\n\r\n").encode() + compressed)
    return trace.finish()


def http2(name, size):
    compressed = CODECS[name](BODY)
    trace = Trace("h2", size)
    client = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
    server = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=False))
    client.initiate_connection()
    server.initiate_connection()

    def transfer(sender, receiver, direction):
        data = sender.data_to_send()
        trace.data(direction, data)
        receiver.receive_data(data)

    transfer(client, server, "client")
    transfer(server, client, "server")
    transfer(client, server, "client")
    # Exercise SETTINGS acknowledgements and HPACK table-size updates in both
    # directions, including an increase beyond the default 4096-byte table.
    for capacity in (0, 8192):
        server.update_settings({h2.settings.SettingCodes.HEADER_TABLE_SIZE: capacity})
        transfer(server, client, "server")
        transfer(client, server, "client")
        client.update_settings({h2.settings.SettingCodes.HEADER_TABLE_SIZE: capacity})
        transfer(client, server, "client")
        transfer(server, client, "server")
    # Requests share dynamic-table fields and use Huffman-coded header literals.
    for stream, path in [(1, "/echo"), (3, "/second")]:
        headers = [(":method", "POST" if stream == 1 else "GET"), (":scheme", "https"),
                   (":authority", "example.test:8443"), (":path", path),
                   ("x-shared", "same value across streams for HPACK indexing")]
        if stream == 1:
            headers += [("content-encoding", encoding(name)), ("content-length", str(len(compressed)))]
        client.send_headers(stream, headers, end_stream=stream == 3)
        if stream == 1:
            client.send_data(stream, compressed, end_stream=True)
    transfer(client, server, "client")
    server.send_headers(1, [(":status", "103"), ("link", "</style.css>; rel=preload")])
    for stream in (1, 3):
        server.send_headers(stream, [(":status", "200"), ("content-type", "application/json"),
                                    ("content-encoding", encoding(name)), ("content-length", str(len(compressed))),
                                    ("x-shared", "same value across streams for HPACK indexing")])
    half = len(compressed) // 2
    for stream in (3, 1):
        server.send_data(stream, compressed[:half])
    # Stream 3 finishes first; responses must not be matched by arrival order.
    for stream in (3, 1):
        server.send_data(stream, compressed[half:])
        server.send_headers(stream, [("x-checksum", "fixture")], end_stream=True)
    transfer(server, client, "server")
    return trace.finish()


def run(binary, events):
    result = subprocess.run([str(binary)], input="".join(json.dumps(e) + "\n" for e in events),
                            text=True, encoding="utf-8", capture_output=True, timeout=30)
    assert result.returncode == 0, result.stderr
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    diagnostics = [r for r in rows if r["type"] == "diagnostic"]
    assert not diagnostics, diagnostics
    for row in rows:
        assert row["connection"]["pid"] == 1234
        assert row["connection"]["generation"] == 18
    return [r["exchange"] for r in rows]


def expect_body(message, body=BODY):
    assert message["complete"], message
    assert message["decoding"] == "ok", message["decoding"]
    assert base64.b64decode(message["decoded_base64"]) == body
    assert message["text"].encode() == body


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=ROOT / "build/tools/ProxyLaneProtocol64.exe")
    parser.add_argument("--write-demo", type=Path)
    args = parser.parse_args()
    if args.write_demo:
        args.write_demo.parent.mkdir(parents=True, exist_ok=True)
        args.write_demo.write_text("".join(json.dumps(e) + "\n" for e in http1("gzip", 4096) + http2("zstd", 4096)), encoding="utf-8")
    count = 0
    for name in CODECS:
        for size in (1, 7, 65536):
            for factory in (http1, http2):
                rows = run(args.binary, factory(name, size))
                assert len(rows) == (1 if factory == http1 else 2)
                assert all(row["problem"] is None for row in rows)
                if factory == http2:
                    assert [row["id"] for row in rows] == [3, 1]
                    assert rows[1]["request"]["target"] == "/echo"
                    assert rows[1]["informational"][0]["status"] == 103
                    expect_body(rows[1]["request"])
                else:
                    expect_body(rows[0]["request"])
                for row in rows:
                    expect_body(row["response"])
                    assert ["x-checksum", "fixture"] in row["response"]["trailers"]
                count += 1
    for name in ("gzip", "deflate", "raw-deflate", "br", "zstd"):
        compressed = CODECS[name](BODY)
        for bad in (compressed[:-1], b"not a compressed stream", compressed + b"trailing garbage"):
            response = run(args.binary, http1(name, 7, bad, False))[0]["response"]
            assert response["complete"]  # HTTP framing complete, codec damaged.
            assert response["decoding"].startswith("failed:"), (name, response)
            assert response["decoded_base64"] is None
            count += 1
        bomb = CODECS[name](b"x" * (4 * 1024 * 1024 + 1))
        response = run(args.binary, http1(name, 65536, bomb, False))[0]["response"]
        assert "limit" in response["decoding"], (name, response["decoding"])
        count += 1
    # Concatenated gzip members are a valid single content-coding body.
    combined = gzip.compress(BODY[:20], mtime=0) + gzip.compress(BODY[20:], mtime=0)
    expect_body(run(args.binary, http1("gzip", 7, combined, False))[0]["response"])
    count += 1
    print(f"PASS: {count} independent HTTP/codec cases ({args.binary.name})")


if __name__ == "__main__":
    main()
