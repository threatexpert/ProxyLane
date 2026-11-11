"""Exercise storage resolution and first-run writes in isolated executable directories."""
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile

source = Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix="ProxyLane-storage-policy-") as temporary:
    root = Path(temporary)
    exe = root / "ProxyLane64.exe"
    shutil.copy2(source, exe)

    def run(*args):
        return subprocess.check_output([str(exe), *args], text=True, creationflags=0x08000000).strip()

    expected_user = str(Path(os.environ["LOCALAPPDATA"]) / "ProxyLane" / "ProxyLane.ini")
    assert run("--resolve").lower() == expected_user.lower()
    print("PASS: clean install resolves to Local AppData without writing configuration")
    ini = root / "ProxyLane.ini"
    ini.write_text("[options]\ncustom=keep\n", encoding="utf-16")
    assert run("--resolve").lower() == expected_user.lower()
    print("PASS: an adjacent INI alone does not select portable mode")
    flag = root / "portable.flag"
    flag.mkdir()
    assert run("--resolve").lower() == expected_user.lower()
    flag.rmdir()
    print("PASS: a directory named portable.flag is not a marker file")
    run("--portable", "1")
    assert run("--resolve").lower() == str(ini).lower()
    assert ini.read_text(encoding="utf-16") == "[options]\ncustom=keep\n"
    print("PASS: an empty portable.flag selects the existing adjacent INI")
    ini.unlink()
    assert run("--resolve").lower() == str(ini).lower()
    run("--initialize")
    print("PASS: portable.flag creates valid UTF-16 Test and Direct defaults")
    before = ini.read_bytes()
    run("--initialize")
    assert ini.read_bytes() == before
    print("PASS: startup never overwrites an existing configuration")
    run("--portable", "0")
    assert run("--resolve").lower() == expected_user.lower()
    assert ini.read_bytes() == before
    print("PASS: switching to user storage leaves the old INI unchanged")
    run("--portable", "1")
    assert run("--resolve").lower() == str(ini).lower()
    assert ini.read_bytes() == before
    assert sorted(p.name for p in root.iterdir()) == ["ProxyLane.ini", "ProxyLane64.exe", "portable.flag"]
    print("PASS: switching back uses the existing INI without backup or migration files")

    # Use the same host binary under each product filename: path selection must
    # not depend on executing ARM64 code to catch an ARM64 suffix regression.
    original_exe = exe
    for filename in ("ProxyLane.exe", "ProxyLaneARM64.exe", "ProxyLanearm64.exe"):
        exe = root / filename
        shutil.copy2(source, exe)
        assert run("--resolve").lower() == str(ini).lower()
        assert ini.read_bytes() == before
        exe.unlink()
    exe = original_exe
    print("PASS: x86/x64/ARM64 product filenames share the portable INI")
