"""Close/retry single SOCKS5 test results, including synchronous IPv6 setup failure."""
import argparse
import ctypes
import json
from pathlib import Path
import shutil
import subprocess
import time
import uuid

from Ipv6ConfigTestE2E import Endpoint
from ExitWarningE2ETests import USER, wait_for, windows, settings_page, text
from HookRebindE2ETests import KERNEL


def run(binary, outcome, ipv6, debugger=None):
    module = KERNEL.GetModuleHandleW('ProxyLaneHook64.dll')
    if module:
        assert ctypes.WinDLL('ProxyLaneHook64.dll', handle=module).gp_UnhookWinsock()
    root = Path(__file__).resolve().parents[1]
    folder = root / 'build/qa' / ('test-completion-' + uuid.uuid4().hex[:8])
    folder.mkdir(parents=True)
    for name in (binary.name, 'ProxyLaneHook32.dll', 'ProxyLaneHook64.dll'):
        source = binary.parent / name
        if source.exists():
            shutil.copy2(source, folder / name)
    locale = json.loads((root / 'src/ProxyLane/locales/zh-CN.json').read_text(encoding='utf-8'))
    endpoint = Endpoint(protocol='SOCKS5', outcome=outcome)
    (folder / 'portable.flag').touch()
    (folder / 'ProxyLane.ini').write_text(
        '[options]\nlanguage=zh-CN\nlastselected=Probe\ntesthost=127.0.0.1:80\n'
        f'IPv6TestAddress={ipv6}\n[proxy_Probe]\nType=SOCKS5\nHost=127.0.0.1\n'
        f'Port={endpoint.port}\nHookTCP=1\nHookUDP=0\nBlockUDP=1\n', encoding='utf-8')
    process = subprocess.Popen([str(folder / binary.name), '--profile', 'Probe'], cwd=folder,
                               creationflags=subprocess.CREATE_NO_WINDOW)
    debug_process = None
    if debugger:
        debug_process = subprocess.Popen([str(debugger), '-p', str(process.pid), '-G',
            '-logo', str(folder / 'debugger.log'), '-c', 'sxe -c ".ecxr;kv;qd" -c2 ".ecxr;kv;qd" av;g'],
            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, creationflags=subprocess.CREATE_NO_WINDOW)
        time.sleep(2)
    try:
        main = wait_for(lambda: next((w for w in windows(process.pid) if settings_page(w)), None), 'main')
        page = settings_page(main)
        for attempt in range(3):
            USER.PostMessageW(page, 0x111, 1008, 0)
            dialog = wait_for(lambda: next((w for w in windows(process.pid)
                if w != main and text(w) == locale['test.title']), None), 'test result')
            wait_for(lambda: USER.GetDlgItem(dialog, 2) and USER.IsWindowVisible(USER.GetDlgItem(dialog, 2)), 'close button')
            tcp = text(USER.GetDlgItem(dialog, 1201))
            assert locale['test.result.failed' if outcome == 'tcp_failed' else 'test.result.passed'] in tcp, tcp
            udp_status = {'success': 'passed', 'tcp_failed': 'skipped',
                          'udp_failed': 'failed', 'udp_unsupported': 'unsupported'}[outcome]
            assert locale['test.result.' + udp_status] in text(USER.GetDlgItem(dialog, 1202))
            if ipv6 == 'invalid-address' and outcome != 'tcp_failed':
                assert locale['test.result.invalid'] in text(USER.GetDlgItem(dialog, 1203))
            # Let deferred deletion messages run inside the modal dialog.
            time.sleep(.5)
            USER.PostMessageW(dialog, 0x111, 2, 0)
            wait_for(lambda: not USER.IsWindow(dialog), 'close result')
            time.sleep(.5)
            assert process.poll() is None, f'crashed after result close: {process.returncode:#x}'
            wait_for(lambda: text(USER.GetDlgItem(page, 1008)) == locale['action.test_current'], 'test ready to retry')
            print(f'PASS {binary.name}: {outcome}, IPv6={ipv6}, close/retry {attempt+1}', flush=True)
        assert not endpoint.errors, endpoint.errors
        print(folder, flush=True)
    finally:
        if process.poll() is None:
            process.terminate()
        if debug_process:
            try:
                debug_process.wait(5)
            except subprocess.TimeoutExpired:
                debug_process.terminate()
                debug_process.wait(5)
        process.wait(10)
        endpoint.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, default=Path('bin/ProxyLane64.exe'))
    parser.add_argument('--outcome', choices=('success', 'tcp_failed', 'udp_failed', 'udp_unsupported'), default='udp_unsupported')
    parser.add_argument('--ipv6', default='invalid-address')
    parser.add_argument('--debugger', type=Path)
    args = parser.parse_args()
    run(args.binary.resolve(), args.outcome, args.ipv6, args.debugger)
