"""Test SSLErrorOverrideAllowed with private-CA QUIC; restore HKCU in finally.

Uses isolated Chrome profiles and the existing locally controlled QUIC fixture.
The policy is user-wide while each case runs, not profile-local. Only this value
is changed; its previous data/type are preserved. No certificate trust changes.
"""
import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request
import winreg

if '--registry-helper' not in sys.argv:
    import quic_mitm_probe as probe
    import websocket

KEY = r'Software\Policies\Google\Chrome'
VALUE = 'SSLErrorOverrideAllowed'
CASES = [('unset',None,False), ('disabled',0,False),
         ('enabled',1,False), ('enabled-positive-control',1,True)]


def query(root, name=VALUE):
    try:
        with winreg.OpenKey(root, KEY) as key:
            return winreg.QueryValueEx(key, name)
    except FileNotFoundError:
        return None


class LocalPolicy:
    def __init__(self, work):
        # Do not silently override a machine-level or URL-specific policy.
        for root in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
            for name in (VALUE, 'QuicAllowed'):
                if root == winreg.HKEY_LOCAL_MACHINE or name != VALUE:
                    assert query(root, name) is None, 'Existing policy needs explicit test handling'
        self.original = query(winreg.HKEY_CURRENT_USER)
        self.changed = False
        self.created = []
        for suffix in ('', r'\Google', r'\Google\Chrome'):
            path = r'Software\Policies' + suffix
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path):
                    pass
            except FileNotFoundError:
                self.created.append(path)
        self.backup = work/'registry-backup.json'
        self.backup.write_text(json.dumps({'hive':'HKCU','key':KEY,'value':VALUE,
            'original':self.original,'created_keys':self.created,'restored':False}, indent=2))

    def set(self, value):
        if value is None and query(winreg.HKEY_CURRENT_USER) is None:
            return
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, KEY, 0, winreg.KEY_SET_VALUE) as key:
            self.changed = True
            if value is None:
                try:
                    winreg.DeleteValue(key, VALUE)
                except FileNotFoundError:
                    pass
            else:
                winreg.SetValueEx(key, VALUE, 0, winreg.REG_DWORD, value)

    def restore(self):
        if self.changed:
            with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, KEY, 0, winreg.KEY_SET_VALUE) as key:
                if self.original is None:
                    try:
                        winreg.DeleteValue(key, VALUE)
                    except FileNotFoundError:
                        pass
                else:
                    winreg.SetValueEx(key, VALUE, 0, self.original[1], self.original[0])
        for path in reversed(self.created):
            # Remove only keys created here and still completely empty.
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
                    empty = winreg.QueryInfoKey(key)[:2] == (0, 0)
            except FileNotFoundError:
                continue
            if empty:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
        assert query(winreg.HKEY_CURRENT_USER) == self.original
        data = json.loads(self.backup.read_text())
        data['restored'] = True
        self.backup.write_text(json.dumps(data, indent=2))


class ReadOnlyPolicy:
    """Observe the user's installed policy without requesting write access."""
    def __init__(self, work):
        self.original = query(winreg.HKEY_CURRENT_USER)
        assert self.original == (1, winreg.REG_DWORD), 'Expected existing DWORD 1'
        self.path = work/'registry-observation.json'
        self.record = {'hive':'HKCU','key':KEY,'value':VALUE,
                       'before':self.original,'registry_written':False}
        self.path.write_text(json.dumps(self.record,indent=2))

    def set(self, value):
        assert value == 1 and query(winreg.HKEY_CURRENT_USER) == self.original

    def restore(self):
        # This is an observation only; never restore or delete the user's value.
        self.record['after'] = query(winreg.HKEY_CURRENT_USER)
        self.record['unchanged'] = self.record['after'] == self.original
        self.path.write_text(json.dumps(self.record,indent=2))
        assert self.record['unchanged'], 'Policy changed externally during test'


def atomic_json(path, value):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value,indent=2), encoding='utf-8')
    temporary.replace(path)


def registry_helper(work):
    root = Path(__file__).resolve().parents[2]/'build'/'qa'
    assert work.resolve().is_relative_to(root.resolve())
    policy = LocalPolicy(work)
    start = last = time.monotonic()
    seen = 0
    try:
        atomic_json(work/'registry-helper-ready.json', {'pid':os.getpid()})
        while time.monotonic()-start < 300 and time.monotonic()-last < 90:
            request = work/'registry-request.json'
            if not request.exists():
                time.sleep(.1)
                continue
            command = json.loads(request.read_text())
            if command['id'] <= seen:
                time.sleep(.1)
                continue
            seen = command['id']
            last = time.monotonic()
            if command['op'] == 'restore':
                policy.restore()
                atomic_json(work/'registry-response.json', {'id':seen,'restored':True})
                return
            assert command['op'] == 'set' and command['value'] in (None,0,1)
            policy.set(command['value'])
            atomic_json(work/'registry-response.json', {'id':seen,'value':query(winreg.HKEY_CURRENT_USER)})
    finally:
        policy.restore()


class Policy:
    def __init__(self, work):
        self.work, self.serial = work, 0
        # UAC elevates only this bounded registry helper. Browsers stay unelevated.
        arguments = subprocess.list2cmdline(['-X','utf8',str(Path(__file__).resolve()),
                                             '--registry-helper',str(work)])
        quote = lambda s: "'" + str(s).replace("'", "''") + "'"
        command = ('Start-Process -Verb RunAs -WindowStyle Hidden -FilePath ' + quote(sys.executable)
                   + ' -ArgumentList ' + quote(arguments) + ' -ErrorAction Stop')
        subprocess.run(['powershell.exe','-NoProfile','-Command',command],check=True,timeout=180)
        for _ in range(100):
            if (work/'registry-helper-ready.json').exists():
                return
            time.sleep(.1)
        raise TimeoutError('Elevated registry helper did not start')

    def request(self, op, value=None):
        self.serial += 1
        atomic_json(self.work/'registry-request.json', {'id':self.serial,'op':op,'value':value})
        for _ in range(100):
            response = self.work/'registry-response.json'
            if response.exists():
                data = json.loads(response.read_text())
                if data['id'] == self.serial:
                    return data
            time.sleep(.1)
        raise TimeoutError('Registry helper response missing; watchdog will restore policy')

    def set(self, value):
        self.request('set',value)

    def restore(self):
        self.request('restore')


class CDP:
    def __init__(self, url):
        self.ws = websocket.create_connection(url, timeout=8, suppress_origin=True)
        self.serial = 0

    def call(self, method, params=None):
        self.serial += 1
        self.ws.send(json.dumps({'id':self.serial,'method':method,'params':params or {}}))
        while True:
            msg = json.loads(self.ws.recv())
            if msg.get('id') == self.serial:
                assert 'error' not in msg, msg
                return msg.get('result', {})

    def evaluate(self, expression):
        result = self.call('Runtime.evaluate', {'expression':expression,'returnByValue':True})
        assert 'exceptionDetails' not in result, result
        return result['result'].get('value')


POLICY_TEXT = """(() => {
  const parts = [];
  function walk(root) {
    if (root.innerText) parts.push(root.innerText);
    for (const element of root.querySelectorAll('*')) {
      if (element.shadowRoot) walk(element.shadowRoot);
    }
  }
  walk(document.body);
  return parts.join('\\n');
})()"""

POLICY_ROWS = """(() => {
  const rows = [];
  function walk(root) {
    for (const element of root.querySelectorAll('*')) {
      if (element.tagName === 'POLICY-ROW') {
        rows.push({policy:element.policy, text:element.shadowRoot?.textContent});
      }
      if (element.shadowRoot) walk(element.shadowRoot);
    }
  }
  walk(document);
  return rows;
})()"""


async def attach(port):
    def get_url():
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(f'http://127.0.0.1:{port}/json/list', timeout=2) as response:
            pages = json.load(response)
        return next(p['webSocketDebuggerUrl'] for p in pages if p['type'] == 'page')
    for _ in range(80):
        try:
            return await asyncio.to_thread(CDP, await asyncio.to_thread(get_url))
        except (OSError, StopIteration):
            await asyncio.sleep(.1)
    raise TimeoutError('Chrome CDP did not start')


def netlog_evidence(path):
    text = path.read_text(errors='replace')
    try:
        data = json.loads(text)
    except ValueError:
        data = json.loads(text.rstrip().rstrip(',')+']}')
    names = {v:k for k,v in data['constants']['logEventTypes'].items()}
    ids = {e['source']['id'] for e in data['events']
        if 'QUIC' in names.get(e['type'],'') and e.get('params',{}).get('host') == probe.NAME}
    return {'client_info':data['constants'].get('clientInfo',{}),
        'target_quic_sources':sorted(ids),
        'quic_proof_errors':[e.get('params',{}) for e in data['events']
            if e['source']['id'] in ids and 'QUIC' in names.get(e['type'],'')
            and any(k in e.get('params',{}) for k in ('net_error','details','quic_error'))]}


async def policy_browsers(work, processes, listen, mitm_log):
    exe = Path(r'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe')
    assert exe.exists()
    result = []
    policy = await asyncio.to_thread(Policy, work)
    try:
        for label, value, force in CASES:
            await asyncio.to_thread(policy.set, value)
            profile = work/('chrome-policy-'+label)
            profile.mkdir()
            debug_port = probe.port()
            command = [str(exe),'--headless=new','--allow-chrome-scheme-url','--no-first-run','--no-default-browser-check',
                '--disable-background-networking','--disable-component-update','--no-proxy-server',
                '--enable-quic',f'--user-data-dir={profile}',f'--remote-debugging-port={debug_port}',
                f'--host-resolver-rules=MAP {probe.NAME} 127.0.0.1',
                f'--log-net-log={profile}/netlog.json','chrome://policy']
            if force:
                command.insert(-1,f'--origin-to-force-quic-on={probe.NAME}:{listen}')
            process = processes.start('chrome-policy-'+label,command)
            cdp = None
            try:
                cdp = await attach(debug_port)
                await asyncio.sleep(2)
                policy_text = await asyncio.to_thread(cdp.evaluate, POLICY_TEXT)
                rows = await asyncio.to_thread(cdp.evaluate, POLICY_ROWS)
                (profile/'policy-text.txt').write_text(policy_text, encoding='utf-8')
                (profile/'policy-rows.json').write_text(json.dumps(rows,indent=2),encoding='utf-8')
                matched = [row for row in rows if row.get('policy',{}).get('name') == VALUE]
                assert len(matched) == 1, ('Policy row missing',rows)
                observed = matched[0]['policy']
                if value is None:
                    assert observed.get('value') is None, observed
                else:
                    assert observed.get('value') is bool(value), observed
                    assert not observed.get('error') and not observed.get('ignored'), observed
                before = len(probe.events(mitm_log))
                url = f'https://{probe.NAME}:{listen}/browser-start?name=policy-{label}'
                await asyncio.to_thread(cdp.call, 'Page.navigate', {'url':url})
                await asyncio.sleep(12)
                page = await asyncio.to_thread(cdp.evaluate,
                    "({url:location.href,text:document.body.innerText,protocols:performance.getEntriesByType('resource').map(e=>e.nextHopProtocol)})")
                new = probe.events(mitm_log)[before:]
                h3 = [e for e in new if e.get('event') == 'request' and e.get('role') == 'mitm']
                tcp = [e for e in new if e.get('event') == 'tcp_bootstrap']
                evidence = {'browser':'chrome','mode':label,'policy':observed,
                    'h3_requests':len(h3),'tcp_requests':len(tcp),'page':page,
                    'certificate_errors_ignored':False,'force_quic_positive_control':force}
                await asyncio.to_thread(cdp.call, 'Browser.close')
                for _ in range(50):
                    if process.poll() is not None:
                        break
                    await asyncio.sleep(.1)
                processes.stop(process)
                evidence.update(netlog_evidence(profile/'netlog.json'))
                result.append(evidence)
                (work/'policy-results.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
                print('POLICY',label,'h3',len(h3),'tcp',len(tcp),'effective',observed,flush=True)
                if force:
                    assert h3, 'Positive control did not establish private-CA HTTP/3'
                else:
                    assert tcp, 'TCP bootstrap did not succeed'
                    assert evidence['target_quic_sources'], 'QUIC was never attempted'
            finally:
                if cdp:
                    cdp.ws.close()
                processes.stop(process)
    finally:
        await asyncio.to_thread(policy.restore)
    return result


async def main():
    probe.isolate()
    root = Path(__file__).resolve().parents[2]
    work = root/'build'/'qa'/('quic-policy-'+probe.uuid.uuid4().hex[:12])
    work.mkdir(parents=True)
    print('WORK',work,flush=True)
    pki = work/'mitm-pki'
    pki.mkdir()
    processes = probe.Processes(work)
    origin = None
    results = {'work':str(work),'browsers':[],'passed':False}
    try:
        probe.shutil.copy2(Path(os.environ['LOCALAPPDATA'])/'ProxyLane'/'ca.json',pki/'ca.json')
        ca = probe.base64.b64decode(json.loads((pki/'ca.json').read_text())['certificate'])
        probe.origin_pki(work)
        config = probe.QuicConfiguration(is_client=False,alpn_protocols=['h3'],supported_versions=[1])
        config.load_cert_chain(str(work/'origin-cert.pem'),str(work/'origin-key.pem'))
        origin_events = []
        origin_port, relay_port, listen = probe.port(),probe.port(),probe.port()
        origin = await probe.serve('127.0.0.1',origin_port,configuration=config,
            create_protocol=lambda *a,**kw: probe.Peer(*a,origin=True,events=origin_events,**kw))
        results['origin_events'] = origin_events
        processes.start('socks',[sys.executable,str(root/'tests/e2e/socks5_udp_server.py'),
            '--port',str(relay_port),'--log',str(work/'relay.log')])
        for _ in range(100):
            if (work/'relay.log').exists() and 'LISTEN' in (work/'relay.log').read_text():
                break
            await asyncio.sleep(.05)
        else:
            raise TimeoutError('SOCKS relay not ready')
        config = {'role':'mitm','listen':f'127.0.0.1:{listen}','ca_directory':str(pki),'name':probe.NAME,
            'upstream':f'origin.quic.test:{origin_port}','upstream_ca':str(work/'origin-ca.der'),
            'ready':str(work/'mitm.ready.json'),'stop':str(work/'mitm.stop')}
        config_file = work/'mitm.json'
        config_file.write_text(json.dumps(config))
        runtime = root/'build'/'quic-probe'
        worker = [str(runtime/'quic-probe.exe'),str(config_file)]
        process = processes.start('mitm',[str(runtime/'route-host.exe'),'SOCKS5',str(relay_port),
                                          subprocess.list2cmdline(worker)])
        metadata = await probe.wait_ready(Path(config['ready']),process)
        assert metadata['current_user_trust'], 'Existing ProxyLane CA must already be trusted'
        results['independent_client'] = await probe.client_case(listen,ca,metadata['certificate_sha256'],batch=False)
        results['browsers'] = await policy_browsers(work,processes,listen,work/'mitm.log')
        Path(config['stop']).touch()
        for _ in range(100):
            if process.poll() is not None:
                break
            await asyncio.sleep(.05)
        assert process.poll() == 0
        assert 'DOMAIN:origin.quic.test' in (work/'relay.log').read_text()
        results['passed'] = True
    finally:
        if origin:
            origin.close()
        processes.close()
        (pki/'ca.json').unlink(missing_ok=True)
        (work/'origin-key.pem').unlink(missing_ok=True)
        (work/'results.json').write_text(json.dumps(results,indent=2),encoding='utf-8')
        print('RESULT',work/'results.json',flush=True)


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--registry-helper':
        try:
            registry_helper(Path(sys.argv[2]))
        except BaseException:
            import traceback
            (Path(sys.argv[2])/'registry-helper-error.txt').write_text(traceback.format_exc(),encoding='utf-8')
            raise
    else:
        if '--current-policy-only' in sys.argv:
            Policy = ReadOnlyPolicy
            CASES = [('existing-enabled',1,False)]
        elif '--baseline-only' in sys.argv:
            assert query(winreg.HKEY_CURRENT_USER) is None
            Policy = LocalPolicy
            CASES = [('unset',None,False)]
        asyncio.run(main())
