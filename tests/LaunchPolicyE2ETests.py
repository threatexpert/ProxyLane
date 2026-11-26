"""Distinguish child-rule rejection from injection errors, without running the target."""
import argparse
import ctypes
import shutil
import subprocess
import time
import uuid
from pathlib import Path

from ExitWarningE2ETests import USER, text, wait_for, windows
from ManagedStartupE2ETests import stop_tree
from ShellLaunchE2ETests import wait_file


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--bin', type=Path, default=Path('bin'))
    args = parser.parse_args()
    # Tests may be launched from a proxied shell; isolate this controller first.
    kernel = ctypes.WinDLL('kernel32')
    kernel.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
    kernel.GetModuleHandleW.restype = ctypes.c_void_p
    hook = 'ProxyLaneHook%d.dll' % (ctypes.sizeof(ctypes.c_void_p) * 8)
    if kernel.GetModuleHandleW(hook):
        assert ctypes.WinDLL(hook).gp_UnhookWinsock()
    root = Path('build/qa/launch-policy-' + uuid.uuid4().hex[:8]).resolve()
    root.mkdir(parents=True)
    print('Artifacts:', root, flush=True)
    for name in ('ProxyLane.exe', 'ProxyLane64.exe', 'ProxyLaneHook32.dll', 'ProxyLaneHook64.dll'):
        shutil.copy2(args.bin / name, root / name)
    probe = Path('build/tools/shell-launch-probe/x64/ShellLaunchProbe.exe')
    for name in ('allowed.exe', 'blocked.exe'):
        shutil.copy2(probe, root / name)
    (root / 'portable.flag').touch()

    def launch(bits, target, report, shortcut=False):
        startup = subprocess.STARTUPINFO()
        startup.dwFlags = subprocess.STARTF_USESHOWWINDOW
        startup.wShowWindow = 1  # Do not inherit the automation shell's hidden-window startup state.
        return subprocess.Popen([str(root / ('ProxyLane64.exe' if bits == 64 else 'ProxyLane.exe')),
            '--auto', '--profile', 'PolicyTest', '--wait-exit', '--run', str(root / target),
            *(['--shortcut'] if shortcut else []), '--', '--record', str(report)],
            cwd=root, startupinfo=startup, creationflags=subprocess.CREATE_NO_WINDOW)

    for language in ('en-US', 'zh-CN'):
        for mode, pattern in ((0, '*blocked.exe'), (1, '*allowed.exe')):
            (root / 'ProxyLane.ini').write_text(f'''[options]
lastselected=PolicyTest
language={language}
[proxy_PolicyTest]
Type=SOCKS5
Host=127.0.0.1
Port=7890
HookChildProcess=1
HookTCP=1
HookUDP=0
BlockUDP=1
dnsOpt=1
TargetFilterMode=1
ChildFilterMode={mode}
ChildFilter={pattern}
''', encoding='utf-8')
            owner = None
            clients = []
            label = f'{language}-{mode}'
            try:
                # No existing host: the policy result must survive native forwarding.
                for bits in (32, 64):
                    report = root / f'{label}-cold-{bits}.txt'
                    client = launch(bits, 'blocked.exe', report)
                    clients.append(client)
                    code = client.wait(timeout=30)
                    assert code == 10, (label, bits, code, report.exists())
                    assert not report.exists(), 'blocked target executed'
                ready = root / f'{label}-owner.txt'
                owner = subprocess.Popen([str(root / 'ProxyLane64.exe'), '--auto', '--profile', 'PolicyTest',
                    '--run', str(root / 'allowed.exe'), '--', '--record', str(ready)],
                    cwd=root, creationflags=subprocess.CREATE_NO_WINDOW)
                assert 'hook=1' in wait_file(ready)
                for bits in (32, 64):
                    report = root / f'{label}-forwarded-{bits}.txt'
                    client = launch(bits, 'blocked.exe', report, shortcut=True)
                    clients.append(client)
                    title = '启动被代理规则阻止' if language == 'zh-CN' else 'Launch Blocked by Proxy Rules'
                    dialog = wait_for(lambda: next((w for w in windows(client.pid) if text(w) == title), None),
                                      'policy-specific dialog')
                    message = text(USER.GetDlgItem(dialog, 65535))
                    assert 'blocked.exe' in message, message
                    assert ('子进程代理规则' if language == 'zh-CN' else 'child-process proxy rules') in message, message
                    assert '1223' not in message and '0x000004C7' not in message, message
                    (root / f'{label}-{bits}-message.txt').write_text(message, encoding='utf-8')
                    button = wait_for(lambda: (USER.GetDlgItem(dialog, 1) or USER.GetDlgItem(dialog, 2))
                                      if USER.IsWindowVisible(dialog) else None,
                                      'policy dialog ready')
                    time.sleep(.2)  # Let MessageBox finish initializing before the synthetic click.
                    USER.PostMessageW(button, 0x00F5, 0, 0)  # BM_CLICK (the sole OK button may use IDCANCEL).
                    assert client.wait(timeout=20) == 10
                    assert not report.exists(), 'blocked target executed'
                print('PASS:', label, 'cold/forwarded 32/64 launch, localized policy dialog, no target execution', flush=True)
            finally:
                for client in clients:
                    if client.poll() is None:
                        stop_tree(client)
                if owner is not None:
                    stop_tree(owner)


if __name__ == '__main__':
    main()
