"""Caller-side COM / ShellExecuteExW rewrite experiment, using isolated PL copies.

Build tests/tools/ShellLaunchProbe/build.ps1 first. Does not inject Explorer,
change user profiles, request elevation, or run installers. UAC remains manual.
"""
import argparse
import ctypes
import os
import re
from pathlib import Path
import shutil
import socket
import subprocess
import threading
import time
import uuid

import psutil

from LogonChildE2ETests import serve
from ManagedStartupE2ETests import stop_tree


def wait_file(path):
    deadline = time.monotonic() + 35
    while time.monotonic() < deadline:
        if path.exists() and path.stat().st_size:
            try:
                return path.read_text(encoding="utf-8-sig")
            except PermissionError:
                pass
        time.sleep(.05)
    raise AssertionError("No target report: " + str(path))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin", type=Path, default=Path("bin"))
    parser.add_argument("--production", action="store_true", help="Inject caller with product Hook; no probe detours")
    parser.add_argument("--shortcuts-only", action="store_true", help="Run shortcut launch regression only (requires pywin32)")
    parser.add_argument("--benchmark-only", action="store_true", help="Measure COM discovery cost without launching targets through Shell")
    args = parser.parse_args()
    os.environ['PL_SHELL_ARGS'] = 'must remain literal in the target command line'
    # Only detach this disposable controller, before starting threads or children.
    kernel = ctypes.WinDLL("kernel32")
    try:
        storage_available = bool(ctypes.WinDLL(str(Path(os.environ['SystemRoot']) / 'System32/Windows.Storage.dll')).ShellExecuteExW)
    except (OSError, AttributeError):
        storage_available = False
        print('SKIP: Windows.Storage ShellExecuteExW unavailable on this test host', flush=True)
    kernel.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
    kernel.GetModuleHandleW.restype = ctypes.c_void_p
    hook = "ProxyLaneHook%d.dll" % (ctypes.sizeof(ctypes.c_void_p) * 8)
    if kernel.GetModuleHandleW(hook):
        assert ctypes.WinDLL(hook).gp_UnhookWinsock(), "Inherited Hook cannot be detached"
    root = Path("build/qa/shell-launch-" + uuid.uuid4().hex[:8]).resolve()
    root.mkdir(parents=True)
    print("Artifacts:", root, flush=True)
    for name in ("ProxyLane.exe", "ProxyLane64.exe", "ProxyLaneHook32.dll", "ProxyLaneHook64.dll"):
        shutil.copy2(args.bin / name, root / name)
    (root / "portable.flag").touch()
    probes = {}
    for bits, platform in ((32, "Win32"), (64, "x64")):
        probes[bits] = root / ("shell probe %d.exe" % bits)
        shutil.copy2(Path("build/tools/shell-launch-probe") / platform / "ShellLaunchProbe.exe", probes[bits])
        compiler = Path(os.environ["SystemRoot"]) / "Microsoft.NET/Framework/v4.0.30319/csc.exe"
        subprocess.run([str(compiler), "/nologo", "/target:exe", "/platform:" + ("x86" if bits == 32 else "x64"),
                        "/out:" + str(root / ("managed%d.exe" % bits)),
                        str(Path(__file__).parent / "e2e/managed_startup_probe.cs")], check=True)

    work = root / "working directory"
    work.mkdir()
    observations = []
    owner = None
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0)); listener.listen()
        threading.Thread(target=serve, args=(listener, observations), daemon=True).start()
        (root / "ProxyLane.ini").write_text("""[options]
lastselected=ShellLaunch
language=en-US
[proxy_ShellLaunch]
HookChildProcess=1
HookTCP=1
HookUDP=0
BlockUDP=1
dnsOpt=1
ChildFilterMode=1
TargetFilterMode=1
Type=SOCKS5
Host=127.0.0.1
Port=%d
Transport=PLAIN
""" % listener.getsockname()[1], encoding="utf-8")
        base_config = (root / 'ProxyLane.ini').read_text(encoding='utf-8')
        try:
            previous_pipes = set(os.listdir("\\\\.\\pipe\\"))
            initial = root / "host-started.txt"
            owner = subprocess.Popen([str(root / "ProxyLane64.exe"), "--auto", "--profile", "ShellLaunch",
                                      "--run", str(probes[64]), "--", "--record", str(initial)],
                                     cwd=root, creationflags=subprocess.CREATE_NO_WINDOW)
            assert "hook=1" in wait_file(initial)
            def run_probe(command, name, redirect):
                report = root / (name + ' caller.log')
                if args.production and redirect:
                    command += ['--output', str(report)]
                    command = [str(root / 'ProxyLane64.exe'), '--auto', '--profile', 'ShellLaunch',
                               '--wait-exit', '--literal-arguments', '--run', command[0], '--', *command[1:]]
                output = subprocess.run(command, capture_output=True, text=True, timeout=45,
                                        creationflags=subprocess.CREATE_NO_WINDOW)
                if args.production and redirect:
                    output.stdout = wait_file(report)
                    assert 'Caller hook=1' in output.stdout, output.stdout
                return output
            if args.benchmark_only:
                for bits in (32, 64):
                    for hooked in (False, True):
                        report = root / ('benchmark-%d-%d.txt' % (bits, hooked))
                        command = [str(probes[bits]), '--com-benchmark', str(report)]
                        if hooked:
                            command = [str(root / 'ProxyLane64.exe'), '--auto', '--profile', 'ShellLaunch',
                                       '--wait-exit', '--run', command[0], '--', *command[1:]]
                        output = subprocess.run(command, capture_output=True, text=True, timeout=60,
                                                creationflags=subprocess.CREATE_NO_WINDOW)
                        assert output.returncode == 0, output.stdout + output.stderr
                        print('BENCHMARK bits=%d hooked=%d\n%s' % (bits, hooked, report.read_text()), flush=True)
                return
            if args.production:
                from AppLauncherE2ETests import transact
                import struct
                candidates = [name for name in set(os.listdir('\\\\.\\pipe\\')) - previous_pipes if name.startswith('PRCPipeName')]
                pipes = ['\\\\.\\pipe\\' + name for name in candidates]
                pipes = [pipe for pipe in pipes if struct.unpack('<IIQ', transact(pipe, 1, 4)[-1048:-1032])[1] == owner.pid]
                assert len(pipes) == 1, pipes
                for bits in (32, 64):
                    output = subprocess.run([str(probes[bits]), '--audit-active',
                        str(root / ('ProxyLaneHook%d.dll' % bits)), pipes[0]],
                        capture_output=True, text=True, timeout=45, creationflags=subprocess.CREATE_NO_WINDOW)
                    assert output.returncode == 0, (bits, output.returncode, output.stdout, output.stderr)
                    print('PASS:', bits, 'active discovery audit: no intermediate hooks, deferred discovery, failure/repatch/unhook', flush=True)
                for caller_bits in (32, 64):
                    for target_bits in (32, 64):
                        report = root / ('strict-%d-%d.txt' % (caller_bits, target_bits))
                        before = len(observations)
                        output = subprocess.run([str(probes[caller_bits]), '--inject-child',
                            str(root / ('ProxyLaneHook%d.dll' % caller_bits)), pipes[0],
                            str(root / ('managed%d.exe' % target_bits)),
                            '"%s" managed%d.exe' % (report, 64 if target_bits == 32 else 32)],
                            capture_output=True, text=True, timeout=60, creationflags=subprocess.CREATE_NO_WINDOW)
                        assert output.returncode == 0, output.stdout + output.stderr
                        assert wait_file(report).startswith('PASS') and wait_file(Path(str(report) + '.child')).startswith('PASS')
                        assert observations[before:] == [('203.0.113.10', 39093)] * 2, observations[before:]
                    report = root / ('strict-failed-%d.txt' % caller_bits)
                    output = subprocess.run([str(probes[caller_bits]), '--inject-child',
                        str(root / ('ProxyLaneHook%d.dll' % caller_bits)), '\\\\.\\pipe\\MissingPL-' + uuid.uuid4().hex,
                        str(probes[caller_bits]), '--record ' + subprocess.list2cmdline([str(report)])],
                        capture_output=True, text=True, timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)
                    assert output.returncode == 1 and 'suspension=1' in output.stdout and not report.exists(), output.stdout
                    report = root / ('strict-write-failed-%d.txt' % caller_bits)
                    output = subprocess.run([str(probes[caller_bits]), '--inject-child-deny-write',
                        str(root / ('ProxyLaneHook%d.dll' % caller_bits)), pipes[0],
                        str(probes[caller_bits]), '--record ' + subprocess.list2cmdline([str(report)])],
                        capture_output=True, text=True, timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)
                    assert output.returncode == 1 and 'suspension=1' in output.stdout and not report.exists(), output.stdout
                print('PASS: strict helper injection, both architectures, child traffic, pipe/write failure stays suspended', flush=True)
                import win32com.client
                shell = win32com.client.Dispatch('WScript.Shell')
                for bits in (32, 64):
                    for api, extra in [('com', []), ('com', ['--invoke']), ('shell', [])]:
                        name = '%d-link-%s%s' % (bits, api, '-invoke' if extra else '')
                        for explicit in (False, True):
                            baseline = None
                            for redirect in (False, True):
                                report = root / (name + '-target.txt')
                                if report.exists(): report.unlink()
                                link = root / (name + '.lnk')
                                shortcut = shell.CreateShortcut(str(link))
                                shortcut.TargetPath = str(probes[bits])
                                shortcut.Arguments = '--record "%s" "link argument" "%%PL_SHELL_ARGS%%"' % report
                                shortcut.WorkingDirectory = str(work)
                                shortcut.WindowStyle = 7
                                shortcut.Save()
                                command = [str(probes[bits]), '--api', api, *extra, '--target', str(link)]
                                if explicit: command += ['--args', '"caller argument"', '--cwd', str(root)]
                                output = run_probe(command, name, redirect)
                                assert output.returncode == 0, output.stdout + output.stderr
                                target = wait_file(report)
                                metadata = [line for line in target.splitlines() if line.startswith(('command=', 'cwd=', 'show='))]
                                if not redirect:
                                    baseline = metadata
                                    print('BASELINE:', name, explicit, metadata, flush=True)
                                else:
                                    assert 'hook=1' in target, target
                                    assert metadata == baseline, (baseline, metadata)
                                    print('PASS:', name, 'explicit=' + str(explicit), 'Hook and Windows shortcut semantics', flush=True)
                        report = root / (name + '-network.txt')
                        shortcut = shell.CreateShortcut(str(root / (name + '-network.lnk')))
                        shortcut.TargetPath = str(root / ('managed%d.exe' % bits))
                        shortcut.Arguments = '"%s" managed%d.exe' % (report, 64 if bits == 32 else 32)
                        shortcut.WorkingDirectory = str(root)
                        shortcut.Save()
                        before = len(observations)
                        output = run_probe([str(probes[bits]), '--api', api, *extra, '--target', shortcut.FullName], name, True)
                        assert output.returncode == 0, output.stdout + output.stderr
                        assert wait_file(report).startswith('PASS')
                        assert wait_file(Path(str(report) + '.child')).startswith('PASS')
                        assert observations[before:] == [('203.0.113.10', 39093)] * 2, observations[before:]
                        print('PASS:', name, 'target and cross-bitness child SOCKS PING/PONG', flush=True)
                # No extension whitelist: PL/CreateProcess can launch a PE image
                # even when its file name does not end in .exe.
                other_image = root / 'ordinary-image.other'
                shutil.copy2(probes[64], other_image)
                for api in ('com', 'shell'):
                    report = root / ('other-extension-' + api + '.txt')
                    output = run_probe([str(probes[64]), '--api', api, '--target', str(other_image),
                        '--args', '--record ' + subprocess.list2cmdline([str(report)])], 'other-extension-' + api, True)
                    assert output.returncode == 0, output.stdout + output.stderr
                    assert 'hook=1' in wait_file(report)
                    print('PASS:', api, 'non-.exe target accepted by PL', flush=True)
                invalid = root / 'unsupported.txt'; invalid.write_text('not an executable', encoding='utf-8')
                for target in (invalid, root / 'missing.lnk'):
                    output = run_probe([str(probes[64]), '--api', 'shell', '--wait-exit', '--target', str(target)],
                        'failed-' + target.name, True)
                    assert output.returncode == (6 if target.exists() else 5), (output.returncode, output.stdout, output.stderr)
                    assert re.search(r'hProcessPID=[1-9][0-9]*', output.stdout), output.stdout
                    print('PASS: unsupported/missing target goes to PL and fails without Shell fallback:', target.name, flush=True)
                from AppLauncherE2ETests import launcher_log
                logs = launcher_log(owner, ('missing.lnk',))
                assert 'unsupported.txt' in logs and 'missing.lnk' in logs, logs
                (root / 'shell-failures.log').write_text(logs, encoding='utf-8')
                print('PASS: launch failures are visible in the main PL runtime log', flush=True)
                if args.shortcuts_only: return
            for bits in (32, 64):
                modes = [("com", []), ("invoke", ["--invoke"]), ("shell", [])]
                if args.production: modes += [("storage", []), ("named", ["--named"]), ("byref", ["--byref"]), ("local", []), ("factory", []), ("extended", []), ("com-factory", []), ("com-extended", []), ("com-dispatch", []), ("dispatch-view", ["--dispatch-view"]), ("legacy", ["--shell-version", "1"]), ("shell5", ["--shell-version", "5"])]
                if not storage_available: modes = [(mode, extra) for mode, extra in modes if mode != 'storage']
                for mode, extra in modes:
                    api = "local" if mode in ("legacy", "shell5") else mode if mode in ("shell", "storage", "local", "factory", "extended", "com-factory", "com-extended", "com-dispatch") else "com"
                    for redirect in (False, True):
                        name = "%d-%s-%s" % (bits, mode, "redirect" if redirect else "baseline")
                        report = root / (name + " target.txt")
                        raw = '--record "%s" "argument with spaces" "quote\\\"inside" "trailing\\\\"' % report
                        if args.production: raw += ' "%PL_SHELL_ARGS%"'
                        command = [str(probes[bits]), "--api", api, *extra, "--target", str(probes[bits]),
                                   "--args", raw, "--cwd", str(work)]
                        if redirect and not args.production:
                            command += ["--redirect", str(root / "ProxyLane64.exe"), "--profile", "ShellLaunch"]
                        output = run_probe(command, name, redirect)
                        (root / (name + ".log")).write_text(output.stdout + output.stderr, encoding="utf-8")
                        assert output.returncode == 0, output.stdout + output.stderr
                        target = wait_file(report)
                        assert "hook=%d" % redirect in target, target
                        assert "cwd=" + str(work) in target, target
                        assert next(line for line in target.splitlines() if line.startswith('command=')).endswith(raw), target
                        if args.production and redirect:
                            assert 'show=1' in target, target
                        assert "rewrites=%d" % (redirect and not args.production) in output.stdout, output.stdout
                        if redirect and mode in ("shell", "storage"):
                            handle_pid = int(re.search(r"hProcessPID=(\d+)", output.stdout)[1])
                            target_pid = int(next(s[4:] for s in target.splitlines() if s.startswith("pid=")))
                            assert handle_pid and handle_pid != target_pid, (output.stdout, target)
                        if not redirect and mode in ("com", "invoke", "named", "byref", "dispatch-view", "com-factory", "com-extended", "com-dispatch"):
                            parent = int(next(s[7:] for s in target.splitlines() if s.startswith("parent=")))
                            assert psutil.Process(parent).name().lower() == "explorer.exe", target
                        print("PASS:", name, "parent, Hook state, raw arguments, working directory", flush=True)

                    # Verify actual TCP proxy traffic and creation of the other-bitness child.
                    report = root / ("%d-%s-network.txt" % (bits, mode))
                    before = len(observations)
                    command = [str(probes[bits]), "--api", api, *extra,
                        "--target", str(root / ("managed%d.exe" % bits)),
                        "--args", '"%s" managed%d.exe' % (report, 64 if bits == 32 else 32)]
                    if not args.production: command += ["--redirect", str(root / "ProxyLane64.exe"), "--profile", "ShellLaunch"]
                    output = run_probe(command, '%d-%s-network' % (bits, mode), True)
                    assert output.returncode == 0, output.stdout + output.stderr
                    assert wait_file(report).startswith("PASS"), report.read_text(encoding="utf-8-sig")
                    assert wait_file(Path(str(report) + ".child")).startswith("PASS")
                    assert observations[before:] == [("203.0.113.10", 39093)] * 2, observations[before:]
                    print("PASS:", bits, mode, "target and cross-bitness child SOCKS PING/PONG", flush=True)
                if args.production:
                    lifecycle = root / ('lifecycle-%d' % bits); lifecycle.mkdir()
                    result = subprocess.run([str(root / 'ProxyLane64.exe'), '--auto', '--profile', 'ShellLaunch', '--wait-exit',
                        '--run', str(probes[bits]), '--', '--com-lifecycle', str(lifecycle), '5'], timeout=120,
                        creationflags=subprocess.CREATE_NO_WINDOW)
                    assert result.returncode == 0, ('COM lifecycle', bits, result.returncode)
                    for thread in range(2):
                        for iteration in range(5):
                            target = wait_file(lifecycle / ('life-%d-%d.txt' % (thread, iteration)))
                            assert 'hook=1' in target and 'show=0' in target, target
                    assert 'hook=0' in wait_file(lifecycle / 'after-unhook.txt')
                    if storage_available:
                        assert 'hook=0' in wait_file(lifecycle / 'storage-after-unhook.txt')
                    print('PASS:', bits, 'concurrent apartments, reinitialization, release and unhook', flush=True)
            if args.production:
                for helper_name in ('ProxyLane.exe', 'ProxyLane64.exe'):
                    report = root / (helper_name + '-self-excluded.txt')
                    nested = ['--auto', '--profile', 'ShellLaunch', '--run', str(probes[64]), '--', '--record', str(report)]
                    output = run_probe([str(probes[64]), '--api', 'shell', '--target', str(root / helper_name),
                        '--args', subprocess.list2cmdline(nested)], helper_name + '-self-excluded', True)
                    assert output.returncode == 0 and 'hook=1' in wait_file(report), output.stdout
                print('PASS: both PL helper architectures bypass recursive interception', flush=True)
                excluded = root / 'excluded.exe'; shutil.copy2(probes[64], excluded)
                for policy in ('disabled', 'excluded'):
                    stop_tree(owner); owner = None
                    config = base_config.replace('HookChildProcess=1', 'HookChildProcess=0') if policy == 'disabled' else \
                        base_config.replace('ChildFilterMode=1', 'ChildFilterMode=0\nChildFilter=*excluded.exe')
                    (root / 'ProxyLane.ini').write_text(config, encoding='utf-8')
                    ready = root / (policy + '-owner.txt')
                    owner = subprocess.Popen([str(root / 'ProxyLane64.exe'), '--auto', '--profile', 'ShellLaunch',
                        '--run', str(probes[64]), '--', '--record', str(ready)], cwd=root, creationflags=subprocess.CREATE_NO_WINDOW)
                    assert 'hook=1' in wait_file(ready)
                    for api in ('com', 'shell', 'storage'):
                        if api == 'storage' and not storage_available: continue
                        report = root / (policy + '-' + api + '.txt')
                        output = run_probe([str(probes[64]), '--api', api, '--target', str(excluded),
                            '--args', '--record ' + subprocess.list2cmdline([str(report)])], policy + '-' + api, True)
                        assert output.returncode == 0, output.stdout
                        assert 'hook=0' in wait_file(report)
                    print('PASS: Shell/COM respect child policy:', policy, flush=True)
                    if policy == 'excluded':
                        # The wrapper path is not the process image. Let PL resolve
                        # it and enforce the target rule; never fall back to Explorer.
                        report = root / 'excluded-via-link.txt'
                        link = root / 'excluded-wrapper.lnk'
                        shortcut = shell.CreateShortcut(str(link))
                        shortcut.TargetPath = str(excluded)
                        shortcut.Arguments = '--record ' + subprocess.list2cmdline([str(report)])
                        shortcut.Save()
                        output = run_probe([str(probes[64]), '--api', 'shell', '--wait-exit', '--target', str(link)],
                            'excluded-wrapper', True)
                        assert output.returncode == 10 and not report.exists(), (output.returncode, output.stdout)
                        print('PASS: excluded shortcut target fails in PL without unproxied fallback', flush=True)
        finally:
            if owner is not None:
                stop_tree(owner)
            # Shell-created launchers may not be children of owner. Clean up only
            # executables copied into this run's unique directory, never Explorer.
            owned = []
            for process in psutil.process_iter(["exe"]):
                try:
                    if process.info["exe"] and Path(process.info["exe"]).parent == root:
                        process.terminate(); owned.append(process)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            _, alive = psutil.wait_procs(owned, timeout=5)
            for process in alive:
                process.kill()


if __name__ == "__main__":
    main()
