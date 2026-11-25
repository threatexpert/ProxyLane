"""Opt-in URL smoke test: opens one local page in the user's default browser.

Requires an already-running default Chrome/Edge. Never terminates or injects
an already-running browser. The browser tab remains
open; only the disposable PL host and its explicit launcher are cleaned up.
"""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
import re
from pathlib import Path
import shutil
import subprocess
import threading
import uuid

from ExitWarningE2ETests import USER, CALLBACK, wait_for, windows, owned_pipe, text, dismiss


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin', type=Path, default=Path('bin'))
    parser.add_argument('--entry', choices=('rundll32', 'start'), default='rundll32')
    parser.add_argument('--allow-default-browser', action='store_true', required=True)
    args = parser.parse_args()
    root = Path('build/qa/shell-url-' + uuid.uuid4().hex[:8]).resolve()
    root.mkdir(parents=True)
    for name in ('ProxyLane.exe', 'ProxyLane64.exe', 'ProxyLaneHook32.dll', 'ProxyLaneHook64.dll'):
        shutil.copy2(args.bin / name, root / name)
    shutil.copy2('build/tools/browser-launch-probe/x64/BrowserLaunchProbe.exe', root / 'startup.exe')
    (root / 'portable.flag').touch()
    (root / 'ProxyLane.ini').write_text('''[options]
lastselected=UrlSmoke
language=en-US
[proxy_UrlSmoke]
HookChildProcess=1
HookTCP=1
HookUDP=0
BlockUDP=1
dnsOpt=0
ChildFilterMode=1
TargetFilterMode=1
Type=SOCKS5
Host=127.0.0.1
Port=9
Transport=PLAIN
''', encoding='utf-8')
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            body = b'<title>ProxyLane local URL test</title><p>ProxyLane local URL launch test completed. You can close this tab.</p>'
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    owner = None
    logs = lambda: ''
    try:
        owner = subprocess.Popen([str(root / 'ProxyLane64.exe'), '--auto', '--profile', 'UrlSmoke',
                                  '--run', str(root / 'startup.exe')], cwd=root,
                                 creationflags=subprocess.CREATE_NO_WINDOW)
        main_window = wait_for(lambda: next((w for w in windows(owner.pid) if not USER.GetParent(w)), None), 'host window')
        wait_for(lambda: owned_pipe(owner.pid), 'host pipe')
        controls = []

        @CALLBACK
        def find_log(window, _):
            if USER.GetDlgItem(window, 1043):
                controls.append(USER.GetDlgItem(window, 1000))
            return True

        USER.EnumChildWindows(main_window, find_log, 0)
        assert len(controls) == 1
        logs = lambda: text(controls[0])
        path = '/pl-url-test?a=1&encoded=%25PL_URL_TEST%25&quote=%22x%22'
        url = 'http://127.0.0.1:%d%s#fragment' % (server.server_port, path)
        system = Path(os.environ['SystemRoot']) / 'System32'
        command = [str(root / 'ProxyLane64.exe'), '--auto', '--profile', 'UrlSmoke', '--wait-exit', '--run']
        if args.entry == 'rundll32':
            command += [str(system / 'rundll32.exe'), '--', 'url.dll,FileProtocolHandler', url]
        else:
            # /c's tail is cmd syntax, so quote the URL to preserve its ampersands.
            command += [str(system / 'cmd.exe'), '--arguments', '/d /s /c start "" "' + url + '"']
        result = subprocess.run(command, cwd=root, timeout=40, creationflags=subprocess.CREATE_NO_WINDOW)
        assert result.returncode == 0, (result.returncode, logs())
        wait_for(lambda: path in requests, 'local URL received without parameter corruption')
        wait_for(lambda: 'possible reuse of an existing process detected' in logs(), 'resident browser risk log')
        wait_for(lambda: 'The system accepted the notification request' in logs(), 'notification accepted')
        assert re.search(r'\[Process\] (?:chrome|msedge)\.exe \(\d+\) · Injection succeeded', logs()), logs()
        assert 'Shell launch failed' not in logs(), logs()
        # The tray click opens the original details dialog, without acting on it.
        USER.PostMessageW(main_window, 0x8000 + 100, 102, 0x400 + 5)
        dialog = wait_for(lambda: next((w for w in windows(owner.pid) if USER.GetDlgItem(w, 1134)), None), 'reuse details')
        details = text(USER.GetDlgItem(dialog, 1134))
        (root / 'notification.txt').write_text(details, encoding='utf-8')
        dismiss(dialog, 2)
        print('PASS:', args.entry, 'local URL, browser launch, resident risk notification and details;', root, flush=True)
    finally:
        (root / 'runtime.log').write_text(logs(), encoding='utf-8')
        if owner and owner.poll() is None:
            owner.terminate()
            owner.wait(timeout=10)
        server.shutdown()
        server.server_close()


if __name__ == '__main__':
    main()
