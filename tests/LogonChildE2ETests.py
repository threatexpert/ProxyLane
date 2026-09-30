"""Real alternate-user child injection and PRC routing; never stores credentials.

Build tests/e2e/logon_child_probe.cpp for x86 and x64 first. Set
PROXYLANE_TEST_PASSWORD only in the test runner's environment, or use the
interactive password prompt. Results are retained under build/qa.
"""
import argparse
import ctypes
from ctypes import wintypes
import getpass
import os
from pathlib import Path
import shutil
import socket
import subprocess
import threading
import time
import uuid


def receive(sock, count):
    data = b""
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise EOFError()
        data += part
    return data


def proxy_connection(conn, observations):
    try:
        with conn:
            conn.settimeout(15)
            version, count = receive(conn, 2)
            assert version == 5
            receive(conn, count)
            conn.sendall(b"\x05\x00")
            header = receive(conn, 4)
            assert header == b"\x05\x01\x00\x01", header
            host = socket.inet_ntoa(receive(conn, 4))
            port = int.from_bytes(receive(conn, 2), "big")
            assert host == "203.0.113.10" and port == 39093, (host, port)
            conn.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x98\xb5")
            assert receive(conn, 4) == b"PING"
            observations.append((host, port))
            conn.sendall(b"PONG")
    except Exception as error:
        observations.append(repr(error))


def serve(listener, observations):
    while True:
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        threading.Thread(target=proxy_connection, args=(conn, observations), daemon=True).start()


def verify_pipe_permissions(directory, user, domain, password):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CreateNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                       wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
    kernel.CreateNamedPipeW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
    advapi.LogonUserW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR,
                                 wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.ImpersonateLoggedOnUser.argtypes = [wintypes.HANDLE]
    before = set(os.listdir("\\\\.\\pipe\\"))
    process = subprocess.Popen([str(directory / "ProxyLane64.exe"), "--auto", "--profile", "LogonTest", "--run",
                                str(directory / "logon_probe64.exe"), "--", "--hold"],
                               cwd=directory, creationflags=subprocess.CREATE_NO_WINDOW)
    token = wintypes.HANDLE()
    try:
        deadline = time.monotonic() + 15
        names = []
        while not names and time.monotonic() < deadline:
            names = [name for name in set(os.listdir("\\\\.\\pipe\\")) - before if name.startswith("PRCPipeName")]
            time.sleep(0.05)
        assert len(names) == 1, names
        pipe = "\\\\.\\pipe\\" + names[0]
        assert advapi.LogonUserW(user, domain, password, 2, 0, ctypes.byref(token)), ctypes.WinError(ctypes.get_last_error())
        assert advapi.ImpersonateLoggedOnUser(token)
        invalid = ctypes.c_void_p(-1).value
        try:
            client = kernel.CreateFileW(pipe, 0x12019B, 3, None, 3, 0x110000, None)
            assert client != invalid, ctypes.WinError(ctypes.get_last_error())
            kernel.CloseHandle(client)
            assert kernel.WaitNamedPipeW(pipe, 5000)
            # Cross-user clients must not be able to replace the DACL or
            # create a competing server instance under the PRC's pipe name.
            for rights in (0x40000,):  # WRITE_DAC
                handle = kernel.CreateFileW(pipe, rights, 3, None, 3, 0, None)
                error = ctypes.get_last_error()
                if handle != invalid:
                    kernel.CloseHandle(handle)
                assert handle == invalid and error == 5, (rights, error)
            handle = kernel.CreateNamedPipeW(pipe, 3, 6, 255, 4096, 4096, 0, None)
            error = ctypes.get_last_error()
            if handle != invalid:
                kernel.CloseHandle(handle)
            assert handle == invalid and error == 5, error
        finally:
            advapi.RevertToSelf()
        # Lower the test user's token to verify that the explicit DACL and
        # low-integrity label work together without restoring a NULL DACL.
        class MandatoryLabel(ctypes.Structure):
            _fields_ = [("sid", ctypes.c_void_p), ("attributes", wintypes.DWORD)]
        sid = ctypes.c_void_p()
        advapi.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
        advapi.GetLengthSid.argtypes = [ctypes.c_void_p]
        advapi.SetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        assert advapi.ConvertStringSidToSidW("S-1-16-4096", ctypes.byref(sid))
        try:
            label = MandatoryLabel(sid, 0x20)
            assert advapi.SetTokenInformation(token, 25, ctypes.byref(label), ctypes.sizeof(label) + advapi.GetLengthSid(sid)), ctypes.WinError(ctypes.get_last_error())
        finally:
            kernel.LocalFree(sid)
        assert advapi.ImpersonateLoggedOnUser(token)
        try:
            assert kernel.WaitNamedPipeW(pipe, 5000)
            client = kernel.CreateFileW(pipe, 0x12019B, 3, None, 3, 0x110000, None)
            assert client != invalid, ctypes.WinError(ctypes.get_last_error())
            kernel.CloseHandle(client)
        finally:
            advapi.RevertToSelf()
        print("PASS PRC ACL: alternate/low-integrity user read/write; DACL changes and server creation denied", flush=True)
    finally:
        if token:
            kernel.CloseHandle(token)
        process.terminate()
        process.wait(timeout=10)


def interactive_runas(directory, user, domain, observations):
    """Use a real terminal: runas explicitly does not accept redirected stdin."""
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)

    class Startup(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("reserved", wintypes.LPWSTR), ("desktop", wintypes.LPWSTR),
                    ("title", wintypes.LPWSTR), ("x", wintypes.DWORD), ("y", wintypes.DWORD),
                    ("width", wintypes.DWORD), ("height", wintypes.DWORD), ("chars_x", wintypes.DWORD),
                    ("chars_y", wintypes.DWORD), ("fill", wintypes.DWORD), ("flags", wintypes.DWORD),
                    ("show", wintypes.WORD), ("reserved_size", wintypes.WORD), ("reserved_data", ctypes.c_void_p),
                    ("stdin", wintypes.HANDLE), ("stdout", wintypes.HANDLE), ("stderr", wintypes.HANDLE)]

    class Process(ctypes.Structure):
        _fields_ = [("process", wintypes.HANDLE), ("thread", wintypes.HANDLE),
                    ("pid", wintypes.DWORD), ("tid", wintypes.DWORD)]

    kernel.CreateProcessW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p,
                                     wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
                                     ctypes.POINTER(Startup), ctypes.POINTER(Process)]
    kernel.ResumeThread.argtypes = [wintypes.HANDLE]
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    before = set(os.listdir("\\\\.\\pipe\\"))
    host = subprocess.Popen([str(directory / "ProxyLane64.exe"), "--auto", "--profile", "LogonTest", "--run",
                             str(directory / "logon_probe64.exe"), "--", "--hold"], cwd=directory)
    try:
        names = []
        deadline = time.monotonic() + 15
        while not names and time.monotonic() < deadline:
            names = [name for name in set(os.listdir("\\\\.\\pipe\\")) - before if name.startswith("PRCPipeName")]
            time.sleep(0.05)
        assert len(names) == 1, names
        pipe = "\\\\.\\pipe\\" + names[0]
        for parent in (64, 32):
            system = Path(os.environ["SystemRoot"]) / ("System32" if parent == 64 else "SysWOW64")
            for child in (64, 32):
                report = directory / f"runas-{parent}-to-{child}.txt"
                target = f'"{directory / f"logon_probe{child}.exe"}" --child "{user}" "{report}" 39093 child null'
                command = f'"{system / "runas.exe"}" /user:{domain}\\{user} "' + target.replace('"', '\\"') + '"'
                startup = Startup()
                startup.cb = ctypes.sizeof(startup)
                process = Process()
                assert kernel.CreateProcessW(None, ctypes.create_unicode_buffer(command), None, None, False,
                                             4, None, str(directory), ctypes.byref(startup), ctypes.byref(process)), ctypes.WinError(ctypes.get_last_error())
                try:
                    helper = subprocess.run([str(system / "rundll32.exe"), f'{directory / f"ProxyLaneHook{parent}.dll"},AttachTo',
                                             f"--pid={process.pid}", f"--tid={process.tid}", f"--pipe={pipe}"], timeout=20)
                    assert helper.returncode == 0xFF01, helper.returncode
                    count = len(observations)
                    print(f"runas {parent} -> {child}: enter the test account password at the Windows prompt", flush=True)
                    assert kernel.ResumeThread(process.thread) == 1
                    assert kernel.WaitForSingleObject(process.process, 60000) == 0
                    code = wintypes.DWORD()
                    kernel.GetExitCodeProcess(process.process, ctypes.byref(code))
                    assert code.value == 0, code.value
                    deadline = time.monotonic() + 30
                    while time.monotonic() < deadline and not Path(str(report) + ".grandchild").exists():
                        time.sleep(0.1)
                    for path in (report, Path(str(report) + ".grandchild")):
                        assert "hooked=1 network=1 environment=1" in path.read_text(), path
                    assert len(observations) == count + 2
                    print(f"PASS actual runas {parent} -> {child}: child + grandchild, PRC + SOCKS5", flush=True)
                finally:
                    if kernel.WaitForSingleObject(process.process, 0) != 0:
                        kernel.TerminateProcess(process.process, 99)
                    kernel.CloseHandle(process.thread)
                    kernel.CloseHandle(process.process)
    finally:
        host.terminate()
        host.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--user", required=True)
    parser.add_argument("--domain", default=".")
    parser.add_argument("--bin", type=Path, default=Path("bin"))
    parser.add_argument("--probes", type=Path, default=Path("build/qa"))
    parser.add_argument("--modes", nargs="+", default=["null", "unicode", "ansi", "suspended", "invalid-flags", "missing-file"])
    parser.add_argument("--interactive-runas", action="store_true")
    args = parser.parse_args()
    # Unhook only this disposable runner if the developer shell is already
    # proxied by another installation, so children use the test binaries.
    kernel = ctypes.WinDLL("kernel32")
    kernel.GetModuleHandleW.restype = wintypes.HMODULE
    if kernel.GetModuleHandleW("ProxyLaneHook64.dll"):
        ctypes.WinDLL("ProxyLaneHook64.dll").gp_UnhookWinsock()
    password = os.environ.get("PROXYLANE_TEST_PASSWORD") or getpass.getpass()
    directory = Path("build/qa/logon-" + uuid.uuid4().hex[:8]).resolve()
    directory.mkdir()
    # Only disposable test output is made writable by the test account.
    account = args.user if args.domain == "." else args.domain + "\\" + args.user
    subprocess.run(["icacls", str(directory), "/grant", account + ":(OI)(CI)M"], check=True, capture_output=True)
    for name in ("ProxyLane64.exe", "ProxyLaneHook32.dll", "ProxyLaneHook64.dll"):
        shutil.copy2(args.bin / name, directory / name)
    for bits in (32, 64):
        shutil.copy2(args.probes / f"logon_probe{bits}.exe", directory)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    observations = []
    threading.Thread(target=serve, args=(listener, observations), daemon=True).start()
    (directory / "ProxyLane.ini").write_text(f"""[options]
lastselected=LogonTest
language=en-US

[proxy_LogonTest]
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
Port={listener.getsockname()[1]}
Transport=PLAIN
""", encoding="utf-8")
    env = os.environ.copy()
    env["PROXYLANE_TEST_PASSWORD"] = password
    print(f"Results: {directory}", flush=True)
    try:
        verify_pipe_permissions(directory, args.user, args.domain, password)
        if args.interactive_runas:
            interactive_runas(directory, args.user, args.domain, observations)
            return
        for parent in (64, 32):
            for child in (64, 32):
                for mode in args.modes:
                    label = f"{parent}-to-{child}-{mode}"
                    report = directory / (label + ".txt")
                    arguments = [str(directory / "ProxyLane64.exe"), "--auto", "--profile", "LogonTest", "--run",
                                 str(directory / f"logon_probe{parent}.exe"), "--", "--parent", args.user, args.domain,
                                 str(directory / f"logon_probe{child}.exe"), str(report), "39093", mode]
                    before = len(observations)
                    process = subprocess.Popen(arguments, cwd=directory, env=env, creationflags=subprocess.CREATE_NO_WINDOW)
                    try:
                        deadline = time.monotonic() + 60
                        while time.monotonic() < deadline and not report.exists():
                            time.sleep(0.1)
                        assert report.exists(), f"{label}: timed out"
                        content = report.read_text()
                        if mode in ("invalid-flags", "missing-file"):
                            expected = 87 if mode == "invalid-flags" else 2
                            assert f"parent_hooked=1 created=0 error={expected} " in content, content
                            assert len(observations) == before, observations
                            print("PASS " + label + " (original Win32 error preserved)", flush=True)
                            continue
                        assert "parent_hooked=1 created=1" in content and "child_exit=0" in content, (label, content)
                        if mode == "suspended":
                            assert "resume=1" in content, content
                        for suffix in (".child", ".child.grandchild"):
                            result = Path(str(report) + suffix).read_text()
                            assert "hooked=1 network=1 environment=1" in result, result
                        assert len(observations) == before + 2 and all(isinstance(x, tuple) for x in observations), observations
                        print("PASS " + label + " (child + grandchild, PRC + SOCKS5)", flush=True)
                    finally:
                        process.terminate()
                        process.wait(timeout=10)
    finally:
        listener.close()
    print(f"PASS: all {4 * len(args.modes)} cross-user cases, {len(observations)} proxied connections", flush=True)


if __name__ == "__main__":
    main()
