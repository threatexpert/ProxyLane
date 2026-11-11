"""Process-level cache lifecycle tests. Only terminates child processes it starts.

Uses private temporary roots under build/qa; never touches the user's cache.
No third-party Python dependencies.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import queue
import subprocess
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[2]


class Session:
    def __init__(self, binary, root, *options):
        self.root = root
        self.process = subprocess.Popen([str(binary), "--cache-root", str(root), *options],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        text=True, encoding="utf-8")
        self.rows = queue.Queue()
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()
        self.offsets = {"client": 0, "server": 0}

    def _read(self):
        for line in self.process.stdout:
            try:
                self.rows.put(json.loads(line))
            except Exception as error:
                self.rows.put({"type": "reader_error", "error": str(error), "line": line})

    def send(self, event):
        self.process.stdin.write(json.dumps(event) + "\n")
        self.process.stdin.flush()

    def result(self, kind):
        try:
            row = self.rows.get(timeout=15)
        except queue.Empty as error:
            raise AssertionError(f"timed out waiting for {kind}, child status {self.process.poll()}") from error
        assert row["type"] == kind, row
        return row

    def query(self, event, kind):
        self.send(event)
        return self.result(kind)

    def stats(self):
        return self.query({"type": "cache_stats"}, "cache_stats")["stats"]

    def open(self):
        self.send({"type": "open", "protocol": "http1", "connection": {
            "id": "test", "pid": 1234, "process_start": 987, "socket": 1,
            "generation": 2, "destination": "example.test:8443"}})

    def data(self, direction, data):
        self.send({"type": "data", "connection_id": "test", "direction": direction,
                   "offset": self.offsets[direction], "data_base64": base64.b64encode(data).decode()})
        self.offsets[direction] += len(data)

    def exchange(self, body):
        self.data("client", b"GET /download HTTP/1.1\r\n\r\n")
        self.data("server", f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body)
        exchange = self.result("exchange")["exchange"]
        self.stats()
        return exchange

    def stop(self, kill=False):
        if kill:
            self.process.kill()
        self.process.stdin.close()
        code = self.process.wait(timeout=15)
        self.thread.join(timeout=5)
        errors = self.process.stderr.read()
        self.process.stdout.close()
        self.process.stderr.close()
        if not kill:
            assert code == 0, errors

    def abort_if_running(self):
        if self.process.poll() is None:
            self.stop(kill=True)


def run_dirs(root):
    return set(root.glob("run-*"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=ROOT / "build/tools/ProxyLaneProtocol64.exe")
    args = parser.parse_args()
    binary = args.binary.resolve()
    qa = ROOT / "build/qa"
    qa.mkdir(parents=True, exist_ok=True)
    sessions = []
    cases = 0
    # This context owns and only removes this newly-created QA directory.
    with tempfile.TemporaryDirectory(prefix="protocol-cache-", dir=qa) as temporary:
        assert Path(temporary).resolve().parent == qa.resolve()
        root = Path(temporary) / "cache"

        def start(*options):
            session = Session(binary, root, *options)
            sessions.append(session)
            return session

        try:
            first = start("--cache-entry-bytes", "6", "--cache-total-bytes", "10")
            assert first.stats()["recovered_runs"] == 0
            first.open()
            item1 = first.exchange(b"111111")
            item2 = first.exchange(b"22222222")
            state1 = first.query({"type": "cache_status", "cache_id": item1["cache"]["id"]}, "cache_status")["cache"]
            state2 = first.query({"type": "cache_status", "cache_id": item2["cache"]["id"]}, "cache_status")["cache"]
            assert state1["evicted"] and state2["response_bytes"] == 6
            assert "per-exchange" in state2["reason"]
            assert first.stats()["peak_bytes"] <= 10
            payload = first.query({"type": "cache_read", "cache_id": state2["id"], "direction": "server", "offset": 0, "length": 65536}, "cache_payload")
            assert base64.b64decode(payload["payload"]["data_base64"]) == b"222222"
            error = first.query({"type": "cache_decode", "cache_id": state2["id"], "direction": "server"}, "cache_error")
            assert "incomplete" in error["error"]
            cases += 1

            active = run_dirs(root)
            assert len(active) == 1
            second = start()
            assert second.stats()["recovered_runs"] == 0
            second.open()
            second.exchange(b"crash residue")
            abandoned = run_dirs(root) - active
            assert len(abandoned) == 1
            second.stop(kill=True)
            assert all(path.exists() for path in abandoned)
            third = start()
            assert third.stats()["recovered_runs"] == 1
            assert not any(path.exists() for path in abandoned)
            assert all(path.exists() for path in active)
            third.stop()
            first.stop()
            assert not run_dirs(root)
            cases += 2

            # Failure during normal input parsing must still run cleanup.
            failed = subprocess.run([str(binary), "--cache-root", str(root)], input="{invalid\n",
                                    text=True, capture_output=True, timeout=15)
            assert failed.returncode == 2
            assert not run_dirs(root)
            cases += 1

            # Recover crashes during directory/marker initialization as well.
            empty = root / ("run-" + "a" * 32)
            partial = root / ("run-" + "b" * 32)
            empty.mkdir()
            partial.mkdir()
            (partial / "owner.lock").touch()
            (partial / "format").write_bytes(b"ProxyLane")
            resumed = start()
            assert resumed.stats()["recovered_runs"] == 2
            resumed.stop()
            assert not run_dirs(root)
            cases += 1

            # Unknown data inside a lookalike directory is never deleted.
            foreign = root / ("run-" + "c" * 32)
            foreign.mkdir()
            (foreign / "keep.txt").write_text("user data", encoding="utf-8")
            guarded = start()
            assert guarded.stats()["warnings"]
            assert (foreign / "keep.txt").read_text(encoding="utf-8") == "user data"
            guarded.stop()
            (foreign / "keep.txt").unlink()
            foreign.rmdir()
            cases += 1

            # Windows directory junctions must never be followed by cleanup.
            if os.name == "nt":
                outside = Path(temporary) / "outside"
                outside.mkdir()
                sentinel = outside / "keep.txt"
                sentinel.write_text("outside cache", encoding="utf-8")
                junction = root / ("run-" + "d" * 32)
                made = subprocess.run(["cmd", "/c", "mklink", "/J", str(junction), str(outside)], capture_output=True)
                assert made.returncode == 0, made.stderr
                guarded = start()
                assert guarded.stats()["warnings"]
                guarded.stop()
                assert sentinel.read_text(encoding="utf-8") == "outside cache"
                # Non-recursive rmdir removes this junction, never its target.
                os.rmdir(junction)
                sentinel.unlink()
                outside.rmdir()
                cases += 1

            # Entry metadata stays bounded even when payloads are empty.
            bounded = start("--cache-max-entries", "2")
            bounded.open()
            for _ in range(12):
                bounded.exchange(b"")
            assert bounded.stats()["entries"] <= 2
            bounded.stop()
            assert not run_dirs(root)
            cases += 1
        finally:
            for session in sessions:
                session.abort_if_running()
    print(f"PASS: {cases} process/cache lifecycle cases ({binary.name})")


if __name__ == "__main__":
    main()
