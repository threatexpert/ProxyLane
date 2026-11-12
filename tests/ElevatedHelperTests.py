"""Run the real native helper and Hook entry point without requesting UAC.

Build the helper's x64 test configuration or use the ARM64 product on a device.
No successful launch is requested: valid requests name a nonexistent target.
"""
import argparse
import base64
import ctypes
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile


def request(target, command=None, directory=b"", pipe=b"\\\\.\\pipe\\PRCPipeNameHelperTest", **changes):
    if isinstance(target, str):
        target = target.encode("utf-8")
    if command is None:
        command = b'"' + target + b'"'
    fields = [target, command, directory, pipe]
    header = dict(magic=0x4C454C50, version=2, size=32, total=32 + sum(map(len, fields)),
                  target=len(target), command=len(command), directory=len(directory), pipe=len(pipe), flags=0)
    header.update(changes)
    wire = struct.pack("<IHHIIIIII", *header.values()) + b"".join(fields)
    return "--request=" + base64.urlsafe_b64encode(wire).decode("ascii").rstrip("=")


def elevated():
    from ctypes import wintypes
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                         wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    token = wintypes.HANDLE()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        value, length = wintypes.DWORD(), wintypes.DWORD()
        if not advapi.GetTokenInformation(token, 20, ctypes.byref(value), ctypes.sizeof(value), ctypes.byref(length)):
            raise ctypes.WinError(ctypes.get_last_error())
        return bool(value.value)
    finally:
        kernel.CloseHandle(token)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helper", type=Path, required=True)
    parser.add_argument("--hook", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    qa = root / "build/qa/elevated-helper"
    qa.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="host test 中文, ", dir=qa) as temp:
        work = Path(temp)
        helper = work / args.helper.name
        shutil.copy2(args.helper, helper)
        missing_target = str(work / "不存在 target.exe")
        valid = request(missing_target, directory=str(work).encode("utf-8"))
        count = 0

        def check(name, arguments, expected, cwd=work):
            nonlocal count
            result = subprocess.run([str(helper), *arguments], cwd=cwd, timeout=20)
            assert result.returncode == expected, f"{name}: expected {expected}, got {result.returncode}"
            count += 1

        # A different current directory must not supply the Hook DLL.
        check("missing companion", [valid], 16, args.hook.resolve().parent)
        shutil.copy2(args.hook, work / args.hook.name)
        check("no request", [], 10)
        check("unknown argument", ["--launch=x"], 10)
        check("empty envelope", ["--request="], 10)
        check("invalid base64", ["--request=%%%"], 10)
        check("non ASCII", ["--request=ＡAAA"], 10)
        check("oversized envelope", ["--request=" + "A" * 24000], 10)
        check("truncated header", ["--request=AAAA"], 10)
        check("wrong magic", [request(missing_target, magic=0)], 10)
        check("wrong version", [request(missing_target, version=1)], 10)
        check("wrong size", [request(missing_target, total=32)], 10)
        check("relative target", [request("relative.exe")], 10)
        check("relative cwd", [request(missing_target, directory=b"relative")], 10)
        check("wrong pipe", [request(missing_target, pipe=b"\\\\.\\pipe\\Other")], 10)
        check("embedded null", [request(missing_target.encode("utf-8") + b"\x00.exe")], 10)
        check("invalid UTF-8", [request(b"C:\\bad\xff.exe")], 10)
        check("trailing arguments", [valid, "--extra"], 10)
        # Shows the envelope and Unicode fields reached production validation.
        # A standard token must be refused before any target is created.
        check("valid Unicode request", [valid], 12 if elevated() else 11)
        print(f"Elevated helper: {count} checks passed; UAC and successful launch were not exercised.")


if __name__ == "__main__":
    main()
