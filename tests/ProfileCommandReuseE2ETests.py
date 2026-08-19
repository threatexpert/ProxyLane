"""Verify that repeated --auto launches reuse one profile owner instance."""

import argparse
import ctypes
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

import psutil


CLIENT_CODE = r'''
import ctypes
import json
import os
import sys
import time

hooked = bool(ctypes.windll.kernel32.GetModuleHandleW("ProxyLaneHook64.dll"))
with open(sys.argv[1], "w", encoding="utf-8") as output:
    json.dump({"pid": os.getpid(), "hooked": hooked}, output)
time.sleep(20)
'''


def click_start_proxy(process_id, timeout=15):
    user32 = ctypes.windll.user32
    user32.PostMessageW.argtypes = [ctypes.c_void_p, ctypes.c_uint,
                                    ctypes.c_size_t, ctypes.c_ssize_t]
    user32.PostMessageW.restype = ctypes.c_bool
    user32.IsWindowEnabled.argtypes = [ctypes.c_void_p]
    user32.IsWindowEnabled.restype = ctypes.c_bool
    enum_callback = ctypes.WINFUNCTYPE(
        ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
    top_windows = []

    def collect_top(window, _param):
        pid = ctypes.c_ulong()
        user32.GetWindowThreadProcessId(window, ctypes.byref(pid))
        if pid.value == process_id:
            top_windows.append(window)
        return True

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        top_windows.clear()
        user32.EnumWindows(enum_callback(collect_top), 0)
        for top_window in top_windows:
            buttons = []

            def collect_child(window, _param):
                if user32.GetDlgCtrlID(window) == 1:  # IDOK: Start proxy
                    buttons.append(window)
                return True

            user32.EnumChildWindows(
                top_window, enum_callback(collect_child), 0)
            if buttons:
                button = buttons[0]
                if not user32.PostMessageW(button, 0x00F5, 0, 0):  # BM_CLICK
                    raise ctypes.WinError()
                state_deadline = time.monotonic() + timeout
                while time.monotonic() < state_deadline:
                    if not user32.IsWindowEnabled(button):
                        return
                    time.sleep(0.05)
                raise TimeoutError(
                    "manual instance did not enter the proxy-running state")
        time.sleep(0.05)
    raise TimeoutError("could not find the manual instance Start proxy button")


def verify_command_line_help(executable, working_directory, timeout=15):
    process = subprocess.Popen([executable, "/?"], cwd=working_directory)
    user32 = ctypes.windll.user32
    enum_callback = ctypes.WINFUNCTYPE(
        ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            windows = []

            def collect_top(window, _param):
                pid = ctypes.c_ulong()
                user32.GetWindowThreadProcessId(window, ctypes.byref(pid))
                if pid.value == process.pid:
                    windows.append(window)
                return True

            user32.EnumWindows(enum_callback(collect_top), 0)
            for window in windows:
                texts = []

                def collect_text(child, _param):
                    length = user32.GetWindowTextLengthW(child)
                    if length:
                        value = ctypes.create_unicode_buffer(length + 1)
                        user32.GetWindowTextW(child, value, length + 1)
                        texts.append(value.value)
                    return True

                user32.EnumChildWindows(
                    window, enum_callback(collect_text), 0)
                combined = "\n".join(texts)
                if "--profile" not in combined or "--run" not in combined:
                    continue
                buttons = []

                def collect_ok(child, _param):
                    class_name = ctypes.create_unicode_buffer(32)
                    user32.GetClassNameW(child, class_name, 32)
                    if class_name.value == "Button":
                        buttons.append(child)
                    return True

                user32.EnumChildWindows(window, enum_callback(collect_ok), 0)
                if not buttons:
                    continue
                user32.PostMessageW(buttons[0], 0x00F5, 0, 0)  # BM_CLICK
                if process.wait(timeout=5) != 0:
                    raise RuntimeError("/? returned a non-zero exit code")
                return
            if process.poll() is not None:
                raise RuntimeError("/? exited without displaying command help")
            time.sleep(0.05)
        raise TimeoutError("command-line help dialog did not appear")
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()


def wait_for_file(path, owner, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(path):
            return
        if owner is not None and owner.poll() is not None:
            raise RuntimeError(
                f"initial ProxyLane exited early with {owner.returncode}")
        time.sleep(0.05)
    raise TimeoutError(f"timed out waiting for {path}")


def instances_for(executable):
    expected = os.path.normcase(os.path.abspath(executable))
    matches = []
    for process in psutil.process_iter(("pid", "exe")):
        try:
            actual = process.info["exe"]
            if actual and os.path.normcase(os.path.abspath(actual)) == expected:
                matches.append(process.info["pid"])
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
    return matches


def stop_process(pid):
    try:
        process = psutil.Process(pid)
        process.terminate()
        try:
            process.wait(3)
        except psutil.TimeoutExpired:
            process.kill()
    except psutil.NoSuchProcess:
        pass


def read_client_result(path):
    result = json.load(open(path, encoding="utf-8"))
    if not result["hooked"]:
        raise RuntimeError(f"client {result['pid']} was not injected")
    return result["pid"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin", default=os.path.join(
        os.path.dirname(__file__), "..", "bin"))
    args = parser.parse_args()
    binary_dir = os.path.abspath(args.bin)

    with tempfile.TemporaryDirectory(prefix="ProxyLaneProfileReuseE2E-",
                                     ignore_cleanup_errors=True) as temp:
        for name in ("ProxyLane.exe", "ProxyLane64.exe", "ProxyLaneHook32.dll",
                     "ProxyLaneHook64.dll"):
            shutil.copy2(os.path.join(binary_dir, name),
                         os.path.join(temp, name))

        profile_text = """[options]
lastselected=ReuseTest
HookLanIP=1
DisableLLMNR=1
DisableMDNS=1
language=en-US

[proxy_ReuseTest]
HookChildProcess=0
HookTCP=0
HookUDP=0
BlockUDP=0
BlockIPv6=0
dnsOpt=1
RedirectPrivateDNS=0
ChildFilter=
ChildFilterMode=1
TargetFilter=
TargetFilterMode=0
Type=SOCKS5
Host=127.0.0.1
Port=7799
User=
Pass=
Transport=PLAIN
PSK=
"""
        with open(os.path.join(temp, "ProxyLane.ini"), "w",
                  encoding="utf-8") as profile:
            profile.write(profile_text)

        executable = os.path.join(temp, "ProxyLane64.exe")
        entry32 = os.path.join(temp, "ProxyLane.exe")

        verify_command_line_help(entry32, temp)
        if instances_for(entry32) or instances_for(executable):
            raise RuntimeError("/? left a ProxyLane process running")
        print("PASS: /? displayed help without starting an x64 instance")

        # A normal visible instance that is already running this profile must
        # be able to receive the first automation request without another
        # resident ProxyLane process being created.
        manual_result = os.path.join(temp, "manual.json")
        manual_owner = subprocess.Popen([executable], cwd=temp)
        manual_client_pid = None
        forwarded = None
        try:
            click_start_proxy(manual_owner.pid)
            time.sleep(1)
            manual_command = [
                executable, "--auto", "--profile", "ReuseTest",
                "--run", sys.executable, "--", "-c", CLIENT_CODE,
                manual_result]
            forwarded = subprocess.Popen(manual_command, cwd=temp)
            wait_for_file(manual_result, manual_owner)
            manual_client_pid = read_client_result(manual_result)
            try:
                forwarded_exit = forwarded.wait(timeout=15)
            except subprocess.TimeoutExpired as error:
                raise RuntimeError(
                    "command did not reuse the running manual instance") from error
            if forwarded_exit != 0:
                raise RuntimeError(
                    f"manual-instance forwarding returned {forwarded_exit}")
            if instances_for(executable) != [manual_owner.pid]:
                raise RuntimeError(
                    "manual profile reuse left another ProxyLane instance")
            print("PASS: command reused a running manual profile instance")
        finally:
            if forwarded is not None and forwarded.poll() is None:
                forwarded.terminate()
            if manual_client_pid is not None:
                stop_process(manual_client_pid)
            if manual_owner.poll() is None:
                manual_owner.terminate()
                try:
                    manual_owner.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    manual_owner.kill()

        deadline = time.monotonic() + 5
        while instances_for(executable) and time.monotonic() < deadline:
            time.sleep(0.05)

        first_result = os.path.join(temp, "first.json")
        second_result = os.path.join(temp, "second.json")
        third_result = os.path.join(temp, "third.json")
        cross_bitness_result = os.path.join(temp, "cross-bitness.json")
        base_command = [executable, "--auto", "--profile", "ReuseTest",
                        "--run", sys.executable, "--", "-c", CLIENT_CODE]

        first_owner = subprocess.Popen(base_command + [first_result], cwd=temp)
        client_pids = []
        later_manual = None
        try:
            wait_for_file(first_result, first_owner)
            client_pids.append(read_client_result(first_result))

            owner_pids = instances_for(executable)
            if owner_pids != [first_owner.pid]:
                raise RuntimeError(
                    f"expected one initial owner {first_owner.pid}, got {owner_pids}")

            second = subprocess.run(
                base_command + [second_result], cwd=temp, timeout=30,
                check=False)
            if second.returncode != 0:
                raise RuntimeError(
                    f"forwarded command returned {second.returncode}")
            wait_for_file(second_result, first_owner)
            client_pids.append(read_client_result(second_result))

            owner_pids = instances_for(executable)
            if owner_pids != [first_owner.pid]:
                raise RuntimeError(
                    "second launch left another ProxyLane instance: "
                    f"{owner_pids}")
            print("PASS: repeated profile command reused one ProxyLane owner")

            cross_bitness = subprocess.run([
                entry32, "--auto", "--profile", "ReuseTest",
                "--run", sys.executable, "--", "-c", CLIENT_CODE,
                cross_bitness_result], cwd=temp, timeout=30, check=False)
            if cross_bitness.returncode != 0:
                raise RuntimeError(
                    "32-bit entry forwarding returned "
                    f"{cross_bitness.returncode}")
            wait_for_file(cross_bitness_result, first_owner)
            client_pids.append(read_client_result(cross_bitness_result))
            if instances_for(entry32):
                raise RuntimeError("32-bit forwarding entry stayed resident")
            if instances_for(executable) != [first_owner.pid]:
                raise RuntimeError(
                    "32-bit forwarding created another x64 ProxyLane owner")
            print("PASS: 32-bit entry forwarded directly to the x64 owner")

            # A later normal instance may run the same profile, but it must not
            # steal the command endpoint from the earlier automation owner.
            later_manual = subprocess.Popen([executable], cwd=temp)
            click_start_proxy(later_manual.pid)
            time.sleep(1)
            third = subprocess.run(
                base_command + [third_result], cwd=temp, timeout=30,
                check=False)
            if third.returncode != 0:
                raise RuntimeError(
                    f"post-manual forwarded command returned {third.returncode}")
            wait_for_file(third_result, first_owner)
            client_pids.append(read_client_result(third_result))
            expected_instances = sorted([first_owner.pid, later_manual.pid])
            if sorted(instances_for(executable)) != expected_instances:
                raise RuntimeError(
                    "later manual instance either conflicted or stole the "
                    "profile command owner")
            print("PASS: later manual instance did not steal command ownership")
        finally:
            for pid in client_pids:
                stop_process(pid)
            if later_manual is not None and later_manual.poll() is None:
                later_manual.terminate()
                try:
                    later_manual.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    later_manual.kill()
            if first_owner.poll() is None:
                first_owner.terminate()
                try:
                    first_owner.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    first_owner.kill()

        deadline = time.monotonic() + 5
        while instances_for(executable) and time.monotonic() < deadline:
            time.sleep(0.05)

        # Two simultaneous first launches are serialized by the profile gate:
        # one stays as owner and the other forwards to it and exits.
        race_results = [os.path.join(temp, f"race-{index}.json")
                        for index in range(2)]
        contenders = [subprocess.Popen(base_command + [path], cwd=temp)
                      for path in race_results]
        race_client_pids = []
        try:
            for path in race_results:
                wait_for_file(path, None)
                race_client_pids.append(read_client_result(path))
            deadline = time.monotonic() + 15
            while (sum(process.poll() is None for process in contenders) != 1 and
                   time.monotonic() < deadline):
                time.sleep(0.05)
            live_contenders = [process for process in contenders
                               if process.poll() is None]
            exited_contenders = [process for process in contenders
                                 if process.poll() is not None]
            if len(live_contenders) != 1 or len(exited_contenders) != 1:
                raise RuntimeError(
                    "concurrent launches did not settle on one profile owner")
            if exited_contenders[0].returncode != 0:
                raise RuntimeError(
                    "concurrent forwarded command returned "
                    f"{exited_contenders[0].returncode}")
            if instances_for(executable) != [live_contenders[0].pid]:
                raise RuntimeError(
                    "concurrent launch left more than one ProxyLane owner")
            print("PASS: concurrent first launches elected one profile owner")
        finally:
            for pid in race_client_pids:
                stop_process(pid)
            for contender in contenders:
                if contender.poll() is None:
                    contender.terminate()
                    try:
                        contender.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        contender.kill()


if __name__ == "__main__":
    main()
