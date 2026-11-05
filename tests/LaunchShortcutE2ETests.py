"""Headless launch/forwarding checks; uses only temporary portable configurations."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

import psutil
import win32com.client
import win32gui
import win32process
import re

PROBE = '''import ctypes,json,os,sys
with open(sys.argv[1], "w", encoding="utf-8") as f:
 json.dump({"pid":os.getpid(), "cwd":os.getcwd(), "args":sys.argv[2:],
  "hooked":bool(ctypes.windll.kernel32.GetModuleHandleW("ProxyLaneHook64.dll"))}, f)
'''


def wait_result(path, timeout=25):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except (ValueError, PermissionError):
                pass
        time.sleep(.05)
    raise AssertionError(f"No application result: {path}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin", required=True)
    args = parser.parse_args()
    binary_dir = Path(args.bin).resolve()
    with tempfile.TemporaryDirectory(prefix="ProxyLaneShortcut-", ignore_cleanup_errors=True) as temporary:
        root = Path(temporary)
        for name in ("ProxyLane.exe", "ProxyLane64.exe", "ProxyLaneHook32.dll", "ProxyLaneHook64.dll"):
            shutil.copy2(binary_dir / name, root / name)
        (root / "portable.flag").touch()
        (root / "ProxyLane.ini").write_text("""[options]
lastselected=ShortcutTest
InterfaceLanguage=en-US
[proxy_ShortcutTest]
Type=NOPROXY
HookTCP=1
HookUDP=0
BlockUDP=0
BlockIPv6=0
HookChildProcess=0
dnsOpt=1
""", encoding="utf-16")
        executable = root / "ProxyLane64.exe"
        entry32 = root / "ProxyLane.exe"
        working = root / "Working directory 中文"
        working.mkdir()
        probe = root / "probe.py"
        probe.write_text(PROBE, encoding="utf-8")
        expected = ["--help", "space argument", 'embedded"quote', "trailing space\\", "中文"]
        owners = []

        def main_window(pid):
            windows = []
            def collect(hwnd, _):
                if win32process.GetWindowThreadProcessId(hwnd)[1] == pid and win32gui.GetWindowText(hwnd).startswith("ProxyLane 1."):
                    windows.append(hwnd)
            win32gui.EnumWindows(collect, None)
            assert len(windows) == 1, windows
            return windows[0]

        def expect_visibility(pid, visible):
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if bool(win32gui.IsWindowVisible(main_window(pid))) == visible:
                    return
                time.sleep(.05)
            raise AssertionError(f"Main window visibility did not become {visible}")

        def open_from_tray(pid):
            # Exercise the app's existing tray Open path without touching other windows.
            resource = (Path(__file__).resolve().parent.parent / "src/ProxyLane/Resource.h").read_text(encoding="utf-8-sig")
            icon_id = int(re.search(r"#define\s+IDD_PROXYLANE_DIALOG\s+(\d+)", resource).group(1))
            win32gui.PostMessage(main_window(pid), 0x8000 + 100, icon_id, 0x203)  # WM_LBUTTONDBLCLK
            expect_visibility(pid, True)

        def command(exe, output):
            return [str(exe), "--auto", "--profile", "ShortcutTest", "--run", sys.executable,
                    "--shortcut", "--app-name", "Shortcut test application 中文",
                    "--working-directory", str(working), "--arguments",
                    subprocess.list2cmdline([str(probe), str(output)] + expected)]

        def verify(output):
            result = wait_result(output)
            assert result["args"] == expected, result
            assert os.path.normcase(result["cwd"]) == os.path.normcase(str(working)), result
            assert result["hooked"], result

        def stop_owners():
            for process in psutil.process_iter(["exe", "pid"]):
                try:
                    if process.info["exe"] and Path(process.info["exe"]).parent == root:
                        process.terminate()
                        process.wait(5)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

        try:
            first = root / "first.json"
            owners.append(subprocess.Popen(command(executable, first), cwd=root))
            verify(first)
            assert owners[-1].poll() is None, "initial owner should stay resident"
            time.sleep(.4)  # Include the first MFC modal-loop idle cycle.
            expect_visibility(owners[-1].pid, False)
            print("PASS: initial launch preserves raw arguments/cwd and injects the application", flush=True)
            for name, exe in [("forward64", executable), ("forward32", entry32)]:
                open_from_tray(owners[-1].pid)
                placement = win32gui.GetWindowPlacement(main_window(owners[-1].pid))
                output = root / f"{name}.json"
                result = subprocess.run(command(exe, output), cwd=root, timeout=30)
                assert result.returncode == 0, result.returncode
                verify(output)
                expect_visibility(owners[-1].pid, True)
                assert win32gui.GetWindowPlacement(main_window(owners[-1].pid)) == placement, "shortcut changed the open window placement"
                # Exercise the existing Minimize-to-tray path, then reuse the hidden owner.
                win32gui.PostMessage(main_window(owners[-1].pid), 0x112, 0xF020, 0)  # WM_SYSCOMMAND / SC_MINIMIZE
                expect_visibility(owners[-1].pid, False)
                hidden_output = root / f"{name}-hidden.json"
                hidden_result = subprocess.run(command(exe, hidden_output), cwd=root, timeout=30)
                assert hidden_result.returncode == 0, hidden_result.returncode
                verify(hidden_output)
                expect_visibility(owners[-1].pid, False)
                print(f"PASS: {name} retains launch information through the active instance", flush=True)
            print("PASS: startup stays in tray; forwarded shortcuts preserve both visible and hidden window states", flush=True)

            # Shell invocation of the same format produced by the export code.
            output = root / "shell.json"
            shell = win32com.client.Dispatch("WScript.Shell")
            shortcut = shell.CreateShortcut(str(root / "Example (ShortcutTest).lnk"))
            shortcut.TargetPath = str(executable)
            shortcut.Arguments = subprocess.list2cmdline(command(executable, output)[1:])
            shortcut.IconLocation = sys.executable + ",0"
            shortcut.Save()
            os.startfile(str(root / "Example (ShortcutTest).lnk"))
            verify(output)
            print("PASS: opening the .lnk launches the original application", flush=True)

            for target in (executable, root / "Example (ShortcutTest).lnk"):
                result = subprocess.run([str(executable), "--auto", "--profile", "ShortcutTest", "--run", str(target)],
                                        cwd=root, timeout=20)
                assert result.returncode == 5, (target, result.returncode)
            print("PASS: CLI blocks ProxyLane and wrapper shortcuts as launch targets", flush=True)
            stop_owners()
            output = root / "bootstrap32.json"
            owners.append(subprocess.Popen(command(entry32, output), cwd=root))
            verify(output)
            assert owners[-1].wait(20) == 0
            print("PASS: x86-to-x64 bootstrap preserves the extended options", flush=True)
        finally:
            stop_owners()


if __name__ == "__main__":
    main()
