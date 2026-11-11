"""Real browser first-injection race, using shipping DLLs and isolated profiles.
No forced QUIC / certificate-ignore flags and no artificial locator delay.
"""
import asyncio
import ctypes
import json
import os
from pathlib import Path
import re
import socket
import tempfile
import quic_mitm_probe as probe
from quic_live_route_probe import Host, RUNTIME
from quic_late_hook_probe import SlowHTTPS, eval_async, recording
from quic_hook_probe import BROWSERS, adopt_browser
from quic_hook_control import network_process
from quic_ssl_policy_probe import attach

ctypes.windll.kernel32.GetTickCount64.restype = ctypes.c_ulonglong
def tick():
    return ctypes.windll.kernel32.GetTickCount64()

async def run():
    probe.isolate()
    results = []
    with tempfile.TemporaryDirectory(dir=RUNTIME) as tmp:
        work = Path(tmp)
        processes = probe.Processes(work)
        origin = SlowHTTPS(work, Path(os.environ['LOCALAPPDATA']) / 'ProxyLane')
        ip = next(ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith('127.'))
        config = probe.QuicConfiguration(is_client=False, alpn_protocols=['h3'], supported_versions=[1])
        config.load_cert_chain(str(origin.cert), str(origin.key))
        servers = []
        async def fixture():
            port = probe.port()
            events = []
            async def bootstrap(reader, writer):
                try:
                    await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 5)
                    body = b'<html><title>Timing probe</title></html>'
                    writer.write(f'HTTP/1.1 200 OK\r\nAlt-Svc: h3=":{port}"; ma=60\r\nContent-Length: {len(body)}\r\nContent-Type: text/html\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n'.encode() + body)
                    await writer.drain()
                except (TimeoutError, ConnectionError):
                    pass
                finally:
                    writer.close()
            udp = await probe.serve('0.0.0.0', port, configuration=config,
                create_protocol=lambda *a, **k: probe.Peer(*a, origin=True, events=events, **k))
            tcp = await asyncio.start_server(bootstrap, '0.0.0.0', port, ssl=origin.context)
            servers.append((udp, tcp))
            return port
        try:
            for name, path in BROWSERS.items():
                if os.environ.get('QUIC_TEST_BROWSER') not in (None, name):
                    continue
                host = Host(work, name)
                browser = cdp = collector = None
                polls = []
                stop = asyncio.Event()
                async def collect():
                    after = 0
                    while not stop.is_set():
                        reply = await asyncio.to_thread(host.call, type='poll', after=after, limit=512)
                        after = reply.get('next', after)
                        polls.append({'tick': tick(), 'reply': reply})
                        await asyncio.sleep(.05)
                try:
                    debug = probe.port()
                    profile = work / name
                    netlog = RUNTIME / (name + '-timing-netlog.json')
                    args = [str(path), '--headless=new', '--no-first-run', '--no-default-browser-check',
                        '--disable-background-networking', '--disable-component-update', '--no-proxy-server',
                        '--user-data-dir=' + str(profile), '--remote-debugging-port=' + str(debug),
                        '--host-resolver-rules=MAP quic-probe.test ' + ip,
                        '--log-net-log=' + str(netlog), 'about:blank']
                    browser = processes.start(name + '-browser', args)
                    cdp = recording(await attach(debug))
                    browser = adopt_browser(browser, profile, processes)
                    await asyncio.sleep(.5)
                    pid = network_process(browser)
                    await asyncio.to_thread(host.call, type='quic_injection_policy', enabled=True)
                    await asyncio.to_thread(host.call, type='monitor_start', decrypt=False, quic=True)
                    # Create fixtures before attachment, so traffic starts immediately.
                    ports = [await fixture() for _ in range(5)]
                    start = tick()
                    attached = await asyncio.to_thread(host.call, type='attach', pid=pid)
                    assert attached['result'] == 0xff01, attached
                    collector = asyncio.create_task(collect())
                    for port in ports:
                        await asyncio.to_thread(cdp.call, 'Page.navigate', {'url': f'https://{probe.NAME}:{port}/'})
                        await asyncio.sleep(.15)
                        for i in range(4):
                            await eval_async(cdp, f"fetch('/timing-{port}?i={i}',{{cache:'no-store'}}).then(r=>r.text())")
                            await asyncio.sleep(.1)
                    for _ in range(120):
                        log = (work / (name + '.log')).read_text(errors='replace')
                        if 'compatibility installed;' in log:
                            break
                        assert 'compatibility unavailable:' not in log, log
                        await asyncio.sleep(.25)
                    else:
                        raise AssertionError(log)
                    installed = int(re.search(r'TICK=(\d+) PID=\d+ QUIC browser compatibility installed;', log)[1])
                    # A new origin avoids Chromium's cached broken Alt-Svc entry.
                    port = await fixture()
                    await asyncio.to_thread(cdp.call, 'Page.navigate', {'url': f'https://{probe.NAME}:{port}/'})
                    await asyncio.sleep(.5)
                    for i in range(5):
                        await eval_async(cdp, f"fetch('/after-install?i={i}',{{cache:'no-store'}}).then(r=>r.text())")
                        await asyncio.sleep(.2)
                    assert cdp.records[-1]['protocol'] == 'h3', cdp.records[-5:]
                    await asyncio.sleep(.5)
                    stop.set()
                    await collector
                    collector = None
                    failures = [{'observed_tick': p['tick'], 'record': r} for p in polls
                        for r in p['reply'].get('records', [])
                        if r.get('status') == 'Failed' and 'certificate unknown' in r.get('detail', '')]
                    before = [f for f in failures if f['observed_tick'] < installed]
                    result = dict(browser=name, version=(await asyncio.to_thread(cdp.call, 'Browser.getVersion'))['product'],
                        pid=pid, injection_tick=start, installed_log_tick=installed,
                        failures=failures, failure_observed_before_install_log=bool(before),
                        after_install_http3=True, polls=polls, responses=cdp.records)
                    results.append(result)
                    print(name, 'install_ms=', installed-start, 'early_cert_failures=', len(before),
                        'later_http3=PASS', flush=True)
                finally:
                    stop.set()
                    if collector:
                        await collector
                    if cdp:
                        cdp.ws.close()
                    if browser:
                        processes.stop(browser)
                    host.close()
                    (RUNTIME / (name + '-timing-host.log')).write_bytes((work / (name + '.log')).read_bytes())
                    (RUNTIME / 'install-timing-results.json').write_text(json.dumps(results, indent=2), encoding='utf8')
        finally:
            processes.close()
            for udp, tcp in servers:
                udp.close()
                tcp.close()
                await tcp.wait_closed()

if __name__ == '__main__':
    asyncio.run(run())
