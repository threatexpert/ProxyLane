"""Local stand-in for the 10000.download release API, for testing in-app updates.

Build ProxyLane with /DPROXYLANE_UPDATE_LOCAL_TEST (see docs/installer-and-updates.md),
install that build, then run:

    python scripts/serve-update-test.py dist\\ProxyLane-1.3.9-Setup.exe

The server listens on 127.0.0.1:8765 and advertises the given setup program as a
newer release (default v9.9.9) with its size and SHA-256, using the same JSON
shape as the real service. Use --corrupt to serve altered bytes and check that
ProxyLane rejects a download whose hash does not match.
"""
import argparse
import hashlib
import http.server
import json
import os
import sys

ASSET_ID = "local-test"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("setup", help="setup program to serve as the newer release")
    parser.add_argument("--version", default="9.9.9", help="advertised version without the leading v")
    parser.add_argument("--port", type=int, default=8765, help="must match the test build (8765)")
    parser.add_argument("--corrupt", action="store_true", help="serve bytes that do not match the advertised SHA-256")
    args = parser.parse_args()

    with open(args.setup, "rb") as f:
        payload = f.read()
    digest = hashlib.sha256(payload).hexdigest()
    if args.corrupt:
        payload = payload[:-1] + bytes([payload[-1] ^ 0xFF])

    release = {
        "version": "v" + args.version,
        "publishedAt": "2026-01-01T00:00:00Z",
        "assets": [{
            "id": ASSET_ID,
            "name": "ProxyLane-%s-Setup.exe" % args.version,
            "size": len(payload),
            "platform": "Windows",
            "path": "/d/proxylane/" + ASSET_ID,
            "digest": "sha256:" + digest,
        }],
        "refreshSeconds": 600,
    }
    body = json.dumps(release).encode("utf-8")

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/api/tools/proxylane/release":
                self.reply(body, "application/json")
            elif self.path == "/d/proxylane/" + ASSET_ID:
                self.reply(payload, "application/octet-stream")
            else:
                self.send_error(404)

        def reply(self, data, content_type):
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

    print("Advertising v%s: %s (%d bytes, sha256 %s%s)" % (
        args.version, os.path.basename(args.setup), len(payload), digest, ", CORRUPTED" if args.corrupt else ""))
    print("Listening on http://127.0.0.1:%d - press Ctrl+C to stop" % args.port)
    sys.stdout.flush()
    http.server.ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
