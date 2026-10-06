"""Real x86/x64 CLR startup through hooked command shells, with proxy traffic."""
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

import psutil

from LogonChildE2ETests import serve


def stop_tree(owner):
    try:
        descendants = psutil.Process(owner.pid).children(recursive=True)
    except psutil.NoSuchProcess:
        descendants = []
    for child in reversed(descendants):
        try:
            child.kill()
        except psutil.NoSuchProcess:
            pass
    if owner.poll() is None:
        owner.terminate()
    owner.wait(timeout=10)
    psutil.wait_procs(descendants, timeout=5)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin", type=Path, default=Path("bin"))
    parser.add_argument("--msbuild-dir", type=Path,
                        help="Optional VS 2019 MSBuild/Current/Bin containing MSBuild.exe and amd64/MSBuild.exe")
    args = parser.parse_args()
    # Only disable the inherited Hook in this disposable runner.
    kernel = ctypes.WinDLL("kernel32")
    kernel.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
    kernel.GetModuleHandleW.restype = ctypes.c_void_p
    hook = "ProxyLaneHook%d.dll" % (ctypes.sizeof(ctypes.c_void_p) * 8)
    if kernel.GetModuleHandleW(hook):
        ctypes.WinDLL(hook).gp_UnhookWinsock()
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        raise RuntimeError("Run this matrix with 64-bit Python")

    directory = Path("build/qa/managed-startup-" + uuid.uuid4().hex[:8]).resolve()
    directory.mkdir(parents=True)
    print("Results:", directory, flush=True)
    for name in ("ProxyLane.exe", "ProxyLane64.exe", "ProxyLaneHook32.dll", "ProxyLaneHook64.dll"):
        shutil.copy2(args.bin / name, directory / name)
    windows = Path(os.environ["SystemRoot"])
    compiler = windows / "Microsoft.NET/Framework/v4.0.30319/csc.exe"
    source = Path(__file__).resolve().parent / "e2e/managed_startup_probe.cs"
    for bits, platform in ((32, "x86"), (64, "x64")):
        subprocess.run([str(compiler), "/nologo", "/target:exe", "/platform:" + platform,
                        "/out:" + str(directory / ("managed%d.exe" % bits)), str(source)], check=True)

    observations = []
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        threading.Thread(target=serve, args=(listener, observations), daemon=True).start()
        (directory / "ProxyLane.ini").write_text("""[options]
lastselected=ManagedStartup
language=en-US

[proxy_ManagedStartup]
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
        for parent_bits in (32, 64):
            # Copy both shells so WOW64 file-system redirection cannot alter the requested bitness.
            system = windows / ("SysWOW64" if parent_bits == 32 else "System32")
            shell = directory / ("cmd%d.exe" % parent_bits)
            shutil.copy2(system / "cmd.exe", shell)
            for child_bits in (32, 64):
                name = "%d-to-%d" % (parent_bits, child_bits)
                report = directory / (name + ".txt")
                done = directory / (name + ".done")
                batch = directory / (name + ".cmd")
                commands = ["@echo off"]
                if args.msbuild_dir:
                    msbuild = args.msbuild_dir.resolve() / ("MSBuild.exe" if child_bits == 32 else "amd64/MSBuild.exe")
                    if not msbuild.is_file():
                        raise FileNotFoundError(msbuild)
                    output = directory / (name + ".msbuild.txt")
                    commands += ['"%s" -nologo -version > "%s" 2>&1' % (msbuild, output),
                                 "if errorlevel 1 exit /b 1"]
                commands += ['"%s" "%s" managed%d.exe' % (
                    directory / ("managed%d.exe" % child_bits), report, 64 if child_bits == 32 else 32),
                    "if errorlevel 1 exit /b 1", 'echo PASS > "%s"' % done]
                batch.write_text("\r\n".join(commands) + "\r\n", encoding="mbcs")
                owner = subprocess.Popen([str(directory / "ProxyLane64.exe"),
                                          "--auto", "--profile", "ManagedStartup", "--run", str(shell),
                                          "--", "/d", "/c", str(batch)], cwd=directory,
                                         creationflags=subprocess.CREATE_NO_WINDOW)
                try:
                    deadline = time.monotonic() + 45
                    while not done.exists() and time.monotonic() < deadline:
                        if owner.poll() is not None:
                            raise RuntimeError("ProxyLane exited early: " + name)
                        time.sleep(0.05)
                    if not done.exists():
                        raise TimeoutError("Startup failed; inspect reports in " + str(directory))
                    for path in (report, Path(str(report) + ".child")):
                        result = path.read_text(encoding="utf-8-sig")
                        if not result.startswith("PASS bits="):
                            raise AssertionError(result)
                    if args.msbuild_dir and not output.read_text(encoding="utf-8-sig").strip():
                        raise AssertionError("MSBuild produced no version output")
                    print("PASS", name, "managed child/grandchild loaded Hook and used SOCKS5" +
                          ("; MSBuild -version passed" if args.msbuild_dir else ""), flush=True)
                finally:
                    stop_tree(owner)
        if len(observations) != 8 or any(not isinstance(item, tuple) for item in observations):
            raise AssertionError(observations)
        print("PASS all 4 architecture combinations; 8 proxied connections", flush=True)


if __name__ == "__main__":
    main()
