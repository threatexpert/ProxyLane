"""Run system rundll32 and the production ElevatedLaunch entry without UAC.

Use --platform Win32/x64 on Intel Windows, or native ARM64 Python on ARM Windows.
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
    parser.add_argument("--platform", choices=("Win32", "x64", "ARM64"), required=True)
    parser.add_argument("--hook", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    # Match the native GUI's launch environment; an emulated Python process
    # on ARM must not stand in for the ARM64 UAC/loader acceptance test.
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.IsWow64Process2.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.WORD), ctypes.POINTER(wintypes.WORD)]
    process, native = wintypes.WORD(), wintypes.WORD()
    if not kernel.IsWow64Process2(kernel.GetCurrentProcess(), ctypes.byref(process), ctypes.byref(native)):
        raise ctypes.WinError(ctypes.get_last_error())
    if args.platform == "ARM64":
        if native.value != 0xaa64 or process.value != 0:
            raise RuntimeError("ARM64 runtime tests require native ARM64 Python on Windows ARM64")
    elif native.value not in (0x14c, 0x8664):
        raise RuntimeError("Intel runtime tests require Intel Windows")
    elif args.platform == "x64" and native.value != 0x8664:
        raise RuntimeError("x64 runtime tests require Windows x64")
    machine = {"Win32": 0x14c, "x64": 0x8664, "ARM64": 0xaa64}[args.platform]
    blob = args.hook.read_bytes()
    pe = struct.unpack_from("<I", blob, 0x3c)[0]
    if struct.unpack_from("<H", blob, pe + 4)[0] != machine:
        raise RuntimeError("Hook DLL architecture does not match --platform")
    folder = "SysWOW64" if args.platform == "Win32" and native.value == 0x8664 else "System32"
    if folder == "System32" and process.value == 0x14c and native.value == 0x8664:
        folder = "Sysnative"
    rundll = Path(os.environ["SystemRoot"]) / folder / "rundll32.exe"
    if not rundll.is_file():
        raise RuntimeError(f"System rundll32 missing: {rundll}")
    qa = root / "build/qa/elevated-rundll"
    qa.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="host test 中文 ", dir=qa) as temp:
        work = Path(temp)
        hook = work / args.hook.name
        shutil.copy2(args.hook, hook)
        missing_target = str(work / "不存在 target.exe")
        valid = request(missing_target, directory=str(work).encode("utf-8"))
        count = 0

        def check(name, arguments, expected, cwd=work):
            nonlocal count
            # Match the GUI's quoting: the comma/export are outside DLL quotes.
            command = f'"{rundll}" "{hook}",ElevatedLaunch ' + " ".join(arguments)
            result = subprocess.run(command, cwd=cwd, timeout=20)
            assert result.returncode == expected, f"{name}: expected {expected}, got {result.returncode}"
            count += 1

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
        print(f"Elevated system rundll32 ({args.platform}): {count} checks passed; UAC and successful launch were not exercised.")


if __name__ == "__main__":
    main()
