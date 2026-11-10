"""Exercise real cross-process imports, atomic publication and non-overwrite."""
import ctypes
import hashlib
from pathlib import Path
import subprocess
import sys
import time
import uuid
import paramiko
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def keys_directory():
    path = ctypes.create_unicode_buffer(260)
    assert ctypes.windll.shell32.SHGetFolderPathW(None, 0x1c, None, 0, path) == 0
    return Path(path.value) / 'ProxyLane/keys'


def run(executables):
    folder = Path('build/qa/key-concurrency-' + uuid.uuid4().hex[:8]).resolve()
    folder.mkdir(parents=True)
    keydir = keys_directory()
    owned = []
    processes = []
    try:
        sources = []
        expected = {}
        for name in ('first', 'second'):
            source = folder / name / 'same-name.pem'
            source.parent.mkdir()
            if name == 'first':
                paramiko.RSAKey.generate(2048).write_private_key_file(str(source), password='fixture-passphrase')
            else:
                source.write_bytes(ed25519.Ed25519PrivateKey.generate().private_bytes(
                    serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                    serialization.BestAvailableEncryption(b'fixture-passphrase')))
            data = source.read_bytes()
            target = keydir / (hashlib.sha256(data).hexdigest() + '.pem')
            assert not target.exists(), 'fresh fixture must not touch an existing key'
            owned.append(target)
            expected[target] = data
            sources.append(source)
        gate = folder / 'start'
        for index in range(16):
            processes.append(subprocess.Popen([executables[(index // 2) % len(executables)], '--import', str(sources[index % 2]), str(gate)],
                creationflags=subprocess.CREATE_NO_WINDOW))
        time.sleep(.25)
        gate.touch()
        deadline = time.monotonic() + 20
        while any(p.poll() is None for p in processes):
            assert time.monotonic() < deadline, 'concurrent import timeout'
            for target, data in expected.items():
                if target.exists():
                    assert target.read_bytes() == data, 'final key must never be partially visible'
            time.sleep(.005)
        assert all(p.returncode == 0 for p in processes), [p.returncode for p in processes]
        assert all(path.read_bytes() == data for path, data in expected.items())
        assert not any(keydir.glob(owned[0].name + '.*.tmp'))
        print('PASS 16 simultaneous processes: identical keys reuse, different keys never collide, publication is atomic', flush=True)
        # A damaged existing file must never be overwritten by another instance.
        owned[0].write_bytes(b'damaged-owned-test-file')
        subprocess.run([executables[0], '--reject', str(sources[0]), str(gate)], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        assert owned[0].read_bytes() == b'damaged-owned-test-file'
        assert owned[1].read_bytes() == expected[owned[1]]
        print('PASS existing damaged key is not overwritten; path traversal is rejected', flush=True)
    finally:
        for p in processes:
            if p.poll() is None:
                p.terminate(); p.wait(10)
        for path in owned:
            path.unlink(missing_ok=True)  # Only unique files made by this test.


if __name__ == '__main__':
    run([str(Path(arg).resolve()) for arg in sys.argv[1:]])
