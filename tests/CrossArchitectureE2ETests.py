"""Real startup/attachment and child routing; 9 pairs on ARM64, 4 on Intel.

Run with an unproxied native 64-bit Python and psutil. Build the three probe
architectures with CrossArchitectureProbe.vcxproj before copying to ARM.
"""
import argparse
import ctypes
import os
from pathlib import Path
import shutil
import socket
import subprocess
import threading
import time
import uuid

from LogonChildE2ETests import serve
from ManagedStartupE2ETests import stop_tree
from HookRebindE2ETests import owned_pipe


def wait_for(check, owner, seconds=45):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        if owner.poll() is not None:
            raise RuntimeError("Process exited early: %s" % owner.returncode)
        time.sleep(.05)
    raise TimeoutError("Timed out waiting for proxy test completion")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin", type=Path, default=Path("bin"))
    parser.add_argument("--probes", type=Path, default=Path("build/qa/cross-architecture"))
    args = parser.parse_args()
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.IsWow64Process2.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ushort), ctypes.POINTER(ctypes.c_ushort)]
    process, native = ctypes.c_ushort(), ctypes.c_ushort()
    if not kernel.IsWow64Process2(ctypes.c_void_p(-1), ctypes.byref(process), ctypes.byref(native)):
        raise ctypes.WinError(ctypes.get_last_error())
    if process.value or ctypes.sizeof(ctypes.c_void_p) != 8:
        raise RuntimeError("Use native 64-bit Python, outside ProxyLane")
    kernel.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
    kernel.GetModuleHandleW.restype = ctypes.c_void_p
    # This disposable runner owns quiescence: detach before starting threads or I/O.
    for suffix in ("32", "64", "ARM64"):
        name = "ProxyLaneHook%s.dll" % suffix
        if kernel.GetModuleHandleW(name) and not ctypes.WinDLL(name).gp_UnhookWinsock():
            raise RuntimeError("Cannot detach inherited Hook; use an unproxied terminal")
    arm = native.value == 0xaa64
    architectures = ["Win32", "x64"] + (["ARM64"] if arm else [])
    suffix = {"Win32": "32", "x64": "64", "ARM64": "ARM64"}
    directory = Path("build/qa/cross-runtime-" + uuid.uuid4().hex[:8]).resolve()
    directory.mkdir(parents=True)
    print("Results:", directory, flush=True)
    gui = "ProxyLaneARM64.exe" if arm else "ProxyLane64.exe"
    shutil.copy2(args.bin / gui, directory / gui)
    for architecture in architectures:
        name = "ProxyLaneHook%s.dll" % suffix[architecture]
        shutil.copy2(args.bin / name, directory / name)
        name = "CrossArchitectureProbe%s.exe" % architecture
        shutil.copy2(args.probes / name, directory / name)
    probe = {a: directory / ("CrossArchitectureProbe%s.exe" % a) for a in architectures}
    observations = []
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        threading.Thread(target=serve, args=(listener, observations), daemon=True).start()
        (directory / "portable.flag").touch()
        (directory / "ProxyLane.ini").write_text("""[options]
lastselected=CrossArchitecture
language=en-US
[proxy_CrossArchitecture]
HookChildProcess=1
HookTCP=1
HookUDP=0
BlockUDP=1
dnsOpt=1
ChildFilter=
ChildFilterMode=1
TargetFilter=
TargetFilterMode=1
Type=SOCKS5
Host=127.0.0.1
Port=%d
Transport=PLAIN
""" % listener.getsockname()[1], encoding="utf-8")
        owner = None
        try:
            for api in ("kernel32", "kernelbase"):
                for parent in architectures:
                    for child in architectures:
                        grandchild = architectures[(architectures.index(child) + 1) % len(architectures)]
                        report = directory / ("startup-%s-%s-%s.txt" % (api, parent, child))
                        before = len(observations)
                        owner = subprocess.Popen([str(directory / gui), "--auto", "--profile", "CrossArchitecture",
                            "--run", str(probe[parent]), "--"] + (["--kernelbase"] if api == "kernelbase" else []) +
                            [str(report), str(probe[child]), str(probe[grandchild])],
                            cwd=directory, creationflags=subprocess.CREATE_NO_WINDOW)
                        wait_for(report.exists, owner)
                        for depth, architecture in enumerate((parent, child, grandchild)):
                            contents = Path(str(report) + ".child" * depth).read_text(encoding="utf-8-sig")
                            expected = str(directory / ("ProxyLaneHook%s.dll" % suffix[architecture]))
                            assert contents.startswith("PASS ") and expected.casefold() in contents.casefold(), contents
                        assert len(observations) - before == 3, observations[before:]
                        print("PASS startup via %s: %s -> %s -> %s, 3 proxied connections" % (api, parent, child, grandchild), flush=True)
                        stop_tree(owner)
                        owner = None

            # Keep one PRC alive while exercising running-process attachment
            # from each caller ABI through the same RundllHost used by the GUI.
            host_arch = "ARM64" if arm else "x64"
            warmup = directory / "warmup.txt"
            owner = subprocess.Popen([str(directory / gui), "--auto", "--profile", "CrossArchitecture",
                "--run", str(probe[host_arch]), "--", str(warmup)], cwd=directory,
                creationflags=subprocess.CREATE_NO_WINDOW)
            wait_for(warmup.exists, owner)
            assert warmup.read_text(encoding="utf-8-sig").startswith("PASS ")
            pipe = wait_for(lambda: owned_pipe(owner.pid), owner)
            for source in architectures:
                for target in architectures:
                    report = directory / ("attach-%s-%s.txt" % (source, target))
                    child = architectures[(architectures.index(target) + 1) % len(architectures)]
                    before = len(observations)
                    waiting = subprocess.Popen([str(probe[target]), "--wait", "--kernelbase", str(report),
                        str(probe[child]), str(probe[source])], cwd=directory,
                        stdin=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
                    try:
                        subprocess.run([str(probe[source]), "--attach", str(waiting.pid), pipe,
                            str(directory / ("ProxyLaneHook%s.dll" % suffix[target]))],
                            cwd=directory, check=True, timeout=25)
                        waiting.communicate(b"G\n", timeout=25)
                        assert waiting.returncode == 0, report.read_text(encoding="utf-8-sig") if report.exists() else waiting.returncode
                        for depth, architecture in enumerate((target, child, source)):
                            contents = Path(str(report) + ".child" * depth).read_text(encoding="utf-8-sig")
                            expected = str(directory / ("ProxyLaneHook%s.dll" % suffix[architecture]))
                            assert contents.startswith("PASS ") and expected.casefold() in contents.casefold(), contents
                        assert len(observations) - before == 3, observations[before:]
                        print("PASS attachment %s -> %s, followed by child/grandchild via KernelBase" % (source, target), flush=True)
                    finally:
                        stop_tree(waiting)
            expected_count = 9 * len(architectures) ** 2 + 1
            assert len(observations) == expected_count and all(isinstance(x, tuple) for x in observations), observations
            print("PASS %d startup cases, %d attachment/child cases, %d proxied connections" %
                  (2 * len(architectures) ** 2, len(architectures) ** 2, expected_count), flush=True)
        finally:
            if owner is not None:
                stop_tree(owner)


if __name__ == "__main__":
    main()
