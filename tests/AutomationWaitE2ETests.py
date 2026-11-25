"""Optional CLI/Shell launcher wait, using isolated PL copies and event-controlled targets.

Build ShellLaunchProbe first. Never opens installers, requests UAC, or changes user profiles.
"""
import argparse
import ctypes
from pathlib import Path
import shutil
import subprocess
import time
import uuid

import psutil
from ShellLaunchE2ETests import wait_file
from ManagedStartupE2ETests import stop_tree


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--bin', type=Path, default=Path('build/automation-wait/bin'))
    parser.add_argument('--production', action='store_true')
    args = parser.parse_args()
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
    kernel.GetModuleHandleW.restype = ctypes.c_void_p
    hook = 'ProxyLaneHook%d.dll' % (ctypes.sizeof(ctypes.c_void_p) * 8)
    if kernel.GetModuleHandleW(hook):
        assert ctypes.WinDLL(hook).gp_UnhookWinsock()
    kernel.CreateEventW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_wchar_p]
    kernel.CreateEventW.restype = ctypes.c_void_p
    kernel.SetEvent.argtypes = kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    root = Path('build/qa/automation-wait-' + uuid.uuid4().hex[:8]).resolve()
    root.mkdir(parents=True)
    print('Artifacts:', root, flush=True)
    for name in ('ProxyLane.exe', 'ProxyLane64.exe', 'ProxyLaneHook32.dll', 'ProxyLaneHook64.dll'):
        shutil.copy2(args.bin / name, root / name)
    probes = {}
    for bits, platform in ((32, 'Win32'), (64, 'x64')):
        probes[bits] = root / ('target%d.exe' % bits)
        shutil.copy2(Path('build/tools/shell-launch-probe') / platform / 'ShellLaunchProbe.exe', probes[bits])
    (root / 'portable.flag').touch()
    (root / 'ProxyLane.ini').write_text('''[options]
lastselected=WaitTest
language=en-US
[proxy_WaitTest]
HookChildProcess=1
HookTCP=1
HookUDP=0
BlockUDP=1
dnsOpt=1
ChildFilterMode=1
TargetFilterMode=1
Type=SOCKS5
Host=127.0.0.1
Port=7890
Transport=PLAIN
''', encoding='utf-8')
    owner = None
    events = []
    launchers = []

    def cli(bits, target, tail=(), wait=False, shortcut=False):
        return [str(root / ('ProxyLane64.exe' if bits == 64 else 'ProxyLane.exe')),
                '--auto', '--profile', 'WaitTest', '--run', str(target),
                *(['--wait-exit'] if wait else []), *(['--shortcut'] if shortcut else []), '--', *tail]

    def start(command):
        p = subprocess.Popen(command, cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             creationflags=subprocess.CREATE_NO_WINDOW)
        launchers.append(p)
        return p

    def target_args(label, code):
        name = 'Local\\PLWaitTest-' + uuid.uuid4().hex
        event = kernel.CreateEventW(None, True, False, name)
        assert event, ctypes.get_last_error()
        events.append(event)
        report = root / (label + '.txt')
        return event, report, ['--wait-child', str(report), name, str(code)]

    def check_target(report):
        text = wait_file(report)
        assert 'hook=1' in text, text
        return int(next(line[4:] for line in text.splitlines() if line.startswith('pid=')))

    try:
        first = root / 'owner.txt'
        owner = start(cli(64, probes[64], ['--record', str(first)]))
        check_target(first)
        for bits, code in ((32, 42), (64, 259), (64, 0xC0000005)):
            event, report, tail = target_args('wait-%d-%d' % (bits, code), code)
            waiter = start(cli(bits, probes[bits], tail, wait=True, shortcut=code == 259))
            check_target(report)
            time.sleep(.3)
            assert waiter.poll() is None, 'helper exited before target'
            # This must finish while the first target is still blocked: neither
            # the pipe worker nor launch gate may remain occupied by a wait.
            parallel = root / ('parallel-%d-%d.txt' % (bits, code))
            ordinary = start(cli(64, probes[64], ['--record', str(parallel)]))
            assert ordinary.wait(timeout=20) == 0
            check_target(parallel)
            kernel.SetEvent(event)
            assert waiter.wait(timeout=20) & 0xFFFFFFFF == code
            assert owner.poll() is None
            print('PASS: forwarded', bits, 'exit', code, 'and concurrent launch', flush=True)

        event, report, tail = target_args('async', 73)
        ordinary = start(cli(64, probes[64], tail))
        pid = check_target(report)
        assert ordinary.wait(timeout=20) == 0
        assert psutil.pid_exists(pid), 'ordinary CLI must not wait for target'
        kernel.SetEvent(event)
        print('PASS: ordinary CLI remains asynchronous', flush=True)

        # The caller waits on the hProcess returned by ShellExecuteExW, which is
        # now the PL helper, and observes the target's exit code through it.
        for bits in (32, 64):
            event, report, tail = target_args('shell-%d' % bits, 87)
            command = ['--api', 'shell', '--target', str(probes[bits]), '--args', subprocess.list2cmdline(tail), '--wait-exit']
            shell = start(cli(bits, probes[bits], command, wait=True) if args.production else
                          [str(probes[bits]), *command, '--redirect', str(root / 'ProxyLane64.exe'), '--profile', 'WaitTest'])
            check_target(report)
            time.sleep(.3)
            assert shell.poll() is None
            kernel.SetEvent(event)
            assert shell.wait(timeout=20) == 87
            print('PASS: ShellExecuteExW', bits, 'helper handle waits and returns 87', flush=True)

        missing = start(cli(64, root / 'missing.exe', wait=True))
        assert missing.wait(timeout=20) == 5, 'preserve target-invalid launch error'
        # An immediate target may vanish before OpenProcess. The accepted fallback
        # is zero; importantly it must finish and must not wait for a recycled PID.
        short_report = root / 'short.txt'
        short = start(cli(64, probes[64], ['--record', str(short_report)], wait=True))
        assert short.wait(timeout=20) == 0
        check_target(short_report)
        print('PASS: launch failure and immediate-exit target', flush=True)
        stop_tree(owner)
        owner = None

        # No existing PL: its UI thread must keep serving the proxy while waiting.
        # A Win32 launcher also has to propagate the native host's final code.
        for bits in (64, 32):
            event, report, tail = target_args('new-owner-%d' % bits, 93)
            initial = start(cli(bits, probes[bits], tail, wait=True, shortcut=True))
            check_target(report)
            time.sleep(.3)
            assert initial.poll() is None
            kernel.SetEvent(event)
            assert initial.wait(timeout=25) == 93
            print('PASS: new owner via', bits, 'launcher returns target exit', flush=True)
    finally:
        for event in events:
            kernel.SetEvent(event)
        if owner is not None:
            stop_tree(owner)
        owned = []
        for p in psutil.process_iter(['exe']):
            try:
                if p.info['exe'] and Path(p.info['exe']).parent == root:
                    p.terminate(); owned.append(p)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        _, alive = psutil.wait_procs(owned, timeout=5)
        for p in alive:
            p.kill()
        for event in events:
            kernel.CloseHandle(event)


if __name__ == '__main__':
    main()
