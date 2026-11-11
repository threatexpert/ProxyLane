"""Two-node chain ending at an ordinary HTTP server must stop its spinner."""
import http.server
import json
from pathlib import Path
import shutil
import subprocess
import threading
import time
import uuid

from PIL import Image, ImageChops
from ChainProgressE2ETests import Relay
from ChainViewProbe import ChainView
from ExitWarningE2ETests import USER, wait_for, windows, settings_page, text, capture_dialog
from ProcessListE2ETests import send


def run():
    root = Path(__file__).resolve().parents[1]
    folder = root / 'build/qa' / ('chain-http-failure-' + uuid.uuid4().hex[:8])
    folder.mkdir(parents=True)
    locale = json.loads((root / 'src/ProxyLane/locales/zh-CN.json').read_text(encoding='utf-8'))
    received, release = threading.Event(), threading.Event()

    class OrdinaryHttp(http.server.BaseHTTPRequestHandler):
        def do_CONNECT(self):
            received.set()
            release.wait(15)
            self.send_error(400, 'CONNECT is not supported by this web server')

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), OrdinaryHttp)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    relay = Relay(0)
    process = probe = None
    try:
        for name in ('ProxyLane64.exe', 'ProxyLaneHook64.dll', 'ProxyLaneHook32.dll'):
            shutil.copy2(root / 'bin' / name, folder / name)
        (folder / 'portable.flag').touch()
        (folder / 'ProxyLane.ini').write_text(
            '[options]\nlanguage=zh-CN\nlastselected=Chain\ntesthost=127.0.0.1:80\n'
            f'[proxy_First]\nType=SOCKS5\nHost=127.0.0.1\nPort={relay.port}\n'
            f'[proxy_WebServer]\nType=HTTP\nHost=127.0.0.1\nPort={server.server_port}\n'
            '[proxy_Chain]\nType=CHAIN\nHookTCP=1\nHookUDP=0\nBlockUDP=1\n'
            'Hop1=First\nHop2=WebServer\n', encoding='utf-8')
        process = subprocess.Popen([str(folder / 'ProxyLane64.exe'), '--profile', 'Chain'],
                                   cwd=folder, creationflags=subprocess.CREATE_NO_WINDOW)
        main = wait_for(lambda: next((w for w in windows(process.pid)
            if USER.IsWindowVisible(w) and settings_page(w)), None), 'main')
        page = settings_page(main)
        navigation = USER.GetParent(page)
        # Use the same owned-window navigation as the seven-hop regression.
        from ctypes import wintypes as W
        USER.GetDpiForWindow.argtypes = [W.HWND]
        dpi = USER.GetDpiForWindow(navigation)
        point = (20 * dpi // 96) | ((136 * dpi // 96) << 16)
        send(navigation, 0x201, 1, point)
        send(navigation, 0x202, 0, point)
        wait_for(lambda: USER.IsWindowVisible(page), 'profiles visible')
        view = USER.GetDlgItem(page, 0x2405)
        probe = ChainView(view, locale)
        wait_for(lambda: probe.count() == 2, 'two cards')
        USER.PostMessageW(page, 0x111, 1008, 0)
        wait_for(received.is_set, 'ordinary HTTP server receives CONNECT through first proxy')
        wait_for(lambda: locale['chain.test.passed'] in probe.cell(0), 'first proxy passed')
        wait_for(lambda: locale['chain.test.auth'] in probe.cell(1), 'HTTP CONNECT pending')
        capture_dialog(view, folder / 'pending.png')
        release.set()
        dialog = wait_for(lambda: next((w for w in windows(process.pid)
            if w != main and text(w) == locale['test.title']), None), 'failure result')
        wait_for(lambda: locale['test.result.failed'] in text(USER.GetDlgItem(dialog, 1201)),
                 'failed TCP result')
        assert locale['chain.test.passed'] in probe.cell(0)
        assert locale['chain.test.connected_unconfirmed'] in probe.cell(1), probe.description(1)

        def assert_stopped(phase):
            # Text alone misses this bug: the tooltip was neutral while the
            # projected Running state kept drawing a rotating yellow arc.
            before = [probe.description(i) for i in range(2)]
            frames = []
            for index in range(3):
                time.sleep(.23)
                path = folder / f'{phase}-{index}.png'
                capture_dialog(view, path)
                with Image.open(path) as image:
                    frames.append(image.convert('RGB'))
            assert before == [probe.description(i) for i in range(2)], 'terminal timings stay frozen'
            assert all(ImageChops.difference(frames[0], frame).getbbox() is None
                       for frame in frames[1:]), f'{phase}: terminal card is still animating'

        assert_stopped('result-open')
        USER.PostMessageW(dialog, 0x111, 2, 0)
        wait_for(lambda: not USER.IsWindow(dialog), 'close result')
        wait_for(lambda: text(USER.GetDlgItem(page, 1008)) == locale['action.test_current'], 'test complete')
        assert_stopped('result-closed')
        print('PASS: two-node HTTP 400 failure stops animation before and after closing the result')
        print(folder)
    finally:
        release.set()
        if probe:
            probe.close()
        if process:
            process.terminate()
            process.wait(10)
        relay.stop()
        server.shutdown()
        server.server_close()


if __name__ == '__main__':
    run()
