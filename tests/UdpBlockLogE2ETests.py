"""Real injected UDP blocking, API coverage and rate-limited GUI logging.

Uses only disposable GUI/probe processes and a loopback socket; external
documentation addresses must return WSAEACCES before any packet is sent.
"""
import argparse
import ctypes
from pathlib import Path
import shutil
import subprocess
import time
import uuid
import psutil

from ExitWarningE2ETests import USER, CALLBACK, windows, text, wait_for
from HookRebindE2ETests import KERNEL, owned_pipe


def run(binary_dir, bits, language):
    # Isolate this test runner from an inherited user profile, as the other
    # injected-process fixtures do. Touch only the current test process.
    module = KERNEL.GetModuleHandleW('ProxyLaneHook64.dll')
    if module:
        assert ctypes.WinDLL('ProxyLaneHook64.dll', handle=module).gp_UnhookWinsock()
    root = Path(__file__).resolve().parents[1]
    directory = root / 'build/qa' / ('udp-block-log-' + uuid.uuid4().hex[:8])
    directory.mkdir(parents=True)
    for name in ('ProxyLane64.exe', 'ProxyLaneHook64.dll', 'ProxyLaneHook32.dll'):
        shutil.copy2(binary_dir / name, directory / name)
    platform = 'x64' if bits == 64 else 'Win32'
    shutil.copy2(root / 'tests/bin' / platform / 'Release/ProxyLaneTests.exe', directory / 'UdpLogProbe.exe')
    (directory / 'portable.flag').touch()
    (directory / 'ProxyLane.ini').write_text(f'''[options]
language={language}
lastselected=UdpBlock
[proxy_UdpBlock]
HookTCP=0
HookUDP=0
BlockUDP=1
BlockIPv6=0
HookChildProcess=0
dnsOpt=0
Type=SOCKS5
Host=127.0.0.1
Port=7799
Transport=PLAIN
''', encoding='utf-8')
    result = directory / 'probe.txt'
    owner = subprocess.Popen([str(directory / 'ProxyLane64.exe'), '--auto', '--profile', 'UdpBlock',
                              '--run', str(directory / 'UdpLogProbe.exe'), '--', '--udp-block-probe', str(result)],
                             cwd=directory, creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        main = wait_for(lambda: next((w for w in windows(owner.pid) if not USER.GetParent(w)), None), 'GUI')
        pipe = wait_for(lambda: owned_pipe(owner.pid), 'owned proxy pipe')
        Path(str(result) + '.pipe').write_text(pipe, encoding='ascii')
        wait_for(result.exists, 'UDP probe result')
        assert result.read_text() == 'PASS', result.read_text()
        edits = []
        @CALLBACK
        def visit(window, _):
            if USER.GetDlgItem(window, 1043):  # Run-log page, identified by Copy log button.
                edits.append(USER.GetDlgItem(window, 1000))  # IDC_EDIT1
            return True
        USER.EnumChildWindows(main, visit, 0)
        assert len(edits) == 1 and edits[0], edits
        marker = 'UDP 已禁用' if language == 'zh-CN' else 'UDP disabled'
        logs = wait_for(lambda: text(edits[0]) if text(edits[0]).count(marker) >= 7 else None, 'UDP log delivery')
        lines = [line for line in logs.splitlines() if marker in line]
        assert len(lines) == 7, lines
        for port in range(12000, 12006):
            assert sum(f':{port} ' in line for line in lines) == (2 if port == 12002 else 1), lines
        assert all('UdpLogProbe.exe' in line for line in lines), lines
        assert not any('127.0.0.1' in line for line in lines), lines
        (directory / 'run-log.txt').write_text(logs, encoding='utf-8')
        print(f'PASS {bits}-bit {language}: all 5 APIs, IPv6, loopback exception, 1000 retries, cooldown; {len(lines)} logs', flush=True)
    finally:
        # A failed probe must not leave injected test processes behind.
        for process in psutil.process_iter(['exe']):
            if process.info['exe'] and Path(process.info['exe']) == directory / 'UdpLogProbe.exe':
                process.terminate()
                process.wait(timeout=10)
        if owner.poll() is None:
            owner.terminate()
        owner.wait(timeout=10)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin', type=Path, default=Path('bin'))
    parser.add_argument('--bits', type=int, choices=(32, 64), default=64)
    parser.add_argument('--language', choices=('zh-CN', 'en-US'), default='zh-CN')
    args = parser.parse_args()
    run(args.bin.resolve(), args.bits, args.language)
