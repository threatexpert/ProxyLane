"""Print connection identity, TLS events and bounded plaintext previews from JSONL."""
import argparse
import base64
import json
import os
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", type=Path, help="capture file or directory; defaults to this user's MITM captures")
    parser.add_argument("--preview", type=int, default=4096, help="maximum plaintext bytes to print per connection")
    args = parser.parse_args()
    if args.preview < 0:
        parser.error("--preview must be nonnegative")
    home = Path(os.environ.get("PROXYLANE_MITM_HOME", str(Path(os.environ["LOCALAPPDATA"]) / "ProxyLane" / "mitm")))
    path = args.path or home / "captures"
    files = sorted(path.glob("*.jsonl"), key=lambda p: p.stat().st_mtime) if path.is_dir() else [path]
    for file in files:
        print(f"\n--- {file.name} ---")
        remaining = args.preview
        # Stream the file: a connection may have up to 16 MiB of captured payload.
        with file.open(encoding="utf-8") as stream:
            for line in stream:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    print("[incomplete event: capture is still being written]")
                    break
                if event.get("event") == "plaintext":
                    data = base64.b64decode(event["base64"])
                    if remaining:
                        print(f"[{event['from']}, {len(data)} bytes]")
                        # repr escapes control characters from untrusted network content.
                        print(repr(data[:remaining].decode("utf-8", errors="replace")))
                        remaining = max(0, remaining - len(data))
                else:
                    print(json.dumps(event, ensure_ascii=True))


if __name__ == "__main__":
    main()
