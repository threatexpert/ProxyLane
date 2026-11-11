"""Real Hook creation notifications; no CA, user profile or browser changes.
Build quic_live_host.cpp as build/process-recording/host.exe with shipping DLLs.
Build process_creation_sender.cpp for x86/x64 there as sender32.exe/sender64.exe.
"""
import ctypes, json, os, socket, socketserver, subprocess, sys, threading, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]

def child():
    for command in sys.stdin:
        count=int(command)
        if count<0:break
        ids=[]
        for i in range(count):
            system='SysWOW64' if i%2 else 'System32'
            proc=subprocess.Popen([str(Path(os.environ['WINDIR'])/system/'cmd.exe'),'/D','/C','exit','0'],
                stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW)
            ids.append(proc.pid);assert proc.wait(timeout=30)==0
        print(json.dumps(ids),flush=True)

def echo_client(ip,port):
    assert input()=='start'
    count=0
    with socket.create_connection((ip,int(port)),20) as s:
        s.settimeout(30)
        for line in sys.stdin:
            if line.strip()=='quit':break
            data=bytes(range(256))*128
            for _ in range(int(line)):
                s.sendall(data);got=bytearray()
                while len(got)<len(data):
                    part=s.recv(len(data)-len(got));assert part;got.extend(part)
                assert got==data;count+=len(data)
            print(json.dumps({'bytes':count}),flush=True)

class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            b=self.request.recv(65536)
            if not b:return
            self.request.sendall(b)

def run():
    # Isolate only this test runner from an enclosing ProxyLane instance.
    # Otherwise its child injection and DNS policy interfere with the test host.
    module=ctypes.windll.kernel32.GetModuleHandleW
    module.argtypes=[ctypes.c_wchar_p];module.restype=ctypes.c_void_p
    for name in ('ProxyLaneHook64.dll','ProxyLaneHook32.dll'):
        if module(name):assert ctypes.WinDLL(name).gp_UnhookWinsock()
    work=ROOT/'build/process-recording'/str(time.time_ns());work.mkdir(parents=True)
    log=open(work/'host.log','w',encoding='utf8')
    host=subprocess.Popen([str(work.parent/'host.exe'),'NOPROXY','0'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log,text=True,encoding='utf8',creationflags=subprocess.CREATE_NO_WINDOW)
    def call(**q):
        host.stdin.write(json.dumps(q)+'\n');host.stdin.flush();line=host.stdout.readline()
        assert line,('host exited',host.poll());v=json.loads(line);assert 'error' not in v,v;return v
    def launch(*args):
        return subprocess.Popen([sys.executable,__file__,*args],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log,text=True,creationflags=subprocess.CREATE_NO_WINDOW)
    def send(p,text):p.stdin.write(str(text)+'\n');p.stdin.flush()
    def create(p,n):send(p,n);return json.loads(p.stdout.readline())
    parent=network=after=None;senders=[];server=socketserver.ThreadingTCPServer(('0.0.0.0',0),Echo);server.daemon_threads=True
    threading.Thread(target=server.serve_forever,daemon=True).start()
    try:
        call(type='test_child_policy',enabled=True);call(type='test_tcp_policy',enabled=True)
        parent=launch('child');assert call(type='attach',pid=parent.pid)['result']==0xff01
        ignored=create(parent,3)
        settings=call(type='mitm_options')['settings'];settings['recording']={'enabled':True,'directory':str(work/'archives'),'capacity_mib':32,'reserve_mib':16}
        call(type='mitm_options',settings=settings);call(type='monitor_start',decrypt=False,quic=False)
        archive=Path(call(type='recording_status')['directory'])
        ip=next(ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith('127.'))
        network=launch('echo',ip,str(server.server_address[1]));assert call(type='attach',pid=network.pid)['result']==0xff01
        time.sleep(.5) # Attach returns before the injected initialization worker finishes.
        send(network,'start')
        # Existing TCP transfer progresses concurrently with child creation.
        send(network,128);expected=create(parent,40);transfer=json.loads(network.stdout.readline());assert transfer['bytes']==4194304
        send(parent,-1);assert parent.wait(timeout=20)==0
        # Parent is gone. Persistent identity must already have been captured.
        deadline=time.monotonic()+20;rows=[]
        while time.monotonic()<deadline:
            rows=[json.loads(l) for f in sorted(archive.glob('process-events-*.jsonl')) for l in f.read_text(encoding='utf8').splitlines()]
            if len(rows)==40:break
            time.sleep(.05)
        assert len(rows)==40,(len(rows),expected)
        assert sorted(r['child']['pid'] for r in rows)==sorted(expected)
        assert all(r['parent']['pid']==parent.pid and r['parent']['path'].lower()==sys.executable.lower() for r in rows)
        assert all(r['parent']['process_start']>0 and r['child']['process_start']>0 for r in rows)
        assert all('creator' not in r for r in rows)
        # Host's filter rejects all child injection; creation must still be logged.
        assert all(r['source']=='hook' for r in rows)
        # Attach to already-running 32/64-bit native parents, then create children.
        for bits in (32,64):
            executable=work.parent/f'sender{bits}.exe'
            sender=subprocess.Popen([str(executable)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log,text=True,creationflags=subprocess.CREATE_NO_WINDOW)
            senders.append(sender)
            if bits==32:
                # Match the GUI's cross-bitness path: use the 32-bit helper.
                pipe=call(type='test_pipe')['pipe']
                injected=subprocess.run([str(Path(os.environ['WINDIR'])/'SysWOW64/rundll32.exe'),str(work.parent/'ProxyLaneHook32.dll')+',AttachTo',
                    f'--pid={sender.pid}','--tid=0',f'--pipe={pipe}'],timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)
                assert injected.returncode==0xff01,injected.returncode
            else:assert call(type='attach',pid=sender.pid)['result']==0xff01
            time.sleep(.5);send(sender,'start');line=sender.stdout.readline()
            assert line,(bits,'native sender exited',sender.wait(timeout=30),(work/'host.log').read_text(encoding='utf8',errors='replace'))
            snapshot=json.loads(line);assert sender.wait(timeout=30)==0
            expected.extend(c['pid'] for c in snapshot['children'])
            # Flush through stop below; no dependence on when the disk worker runs.
            snapshot['path']=str(executable);sender.snapshot=snapshot
        launched=call(type='test_recorded_launch');expected.append(launched['child_pid'])
        call(type='monitor_stop')
        rows=[json.loads(l) for f in sorted(archive.glob('process-events-*.jsonl')) for l in f.read_text(encoding='utf8').splitlines()]
        assert len(rows)==57 and sorted(r['child']['pid'] for r in rows)==sorted(expected)
        for sender in senders:
            actual=[r for r in rows if r['parent']['pid']==sender.pid];assert len(actual)==8
            snap=sender.snapshot
            assert all(r['parent']['path'].lower()==snap['path'].lower() and r['parent']['process_start']==snap['process_start'] for r in actual)
            assert {r['child']['pid']:r['child']['process_start'] for r in actual}=={c['pid']:c['process_start'] for c in snap['children']}
        launch_row=next(r for r in rows if r['child']['pid']==launched['child_pid'])
        assert launch_row['source']=='launcher' and launch_row['parent']['pid']==host.pid and launch_row['child']['process_start']==launched['child_start']
        assert all('creator' not in r for r in rows)
        assert all(r['child']['path'].lower().endswith('\\cmd.exe') and 'identity_note' not in r for r in rows)
        before={str(p.relative_to(archive)):(p.stat().st_size,p.stat().st_mtime_ns) for p in archive.rglob('*') if p.is_file()}
        after=launch('child');assert call(type='attach',pid=after.pid)['result']==0xff01;create(after,3);send(after,-1);after.wait(timeout=20)
        send(network,4);post=json.loads(network.stdout.readline());assert post['bytes']==4325376
        send(network,'quit');assert network.wait(timeout=20)==0
        assert before=={str(p.relative_to(archive)):(p.stat().st_size,p.stat().st_mtime_ns) for p in archive.rglob('*') if p.is_file()}
        manifest=json.loads((archive/'manifest.json').read_text(encoding='utf8'));assert manifest['status']=='completed';assert manifest['process_events']['last_sequence']==57
        result={'archive':str(archive),'creations':57,'native_sender_bits':[32,64],'launcher_snapshot':True,'parent_snapshot_survives_exit':True,'filtered_children_recorded':True,
            'before_start_and_after_stop_excluded':True,'concurrent_tcp_bytes':transfer['bytes'],'existing_tcp_survives_stop':True}
        (work/'result.json').write_text(json.dumps(result,indent=2),encoding='utf8');print(json.dumps(result,indent=2))
    finally:
        for p in [parent,network,after]+senders:
            if p and p.poll() is None:p.kill();p.wait()
        if host.poll() is None:send(host,'{"type":"quit"}');host.wait(timeout=30)
        server.shutdown();server.server_close();log.close()

if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='child':child()
    elif len(sys.argv)>1 and sys.argv[1]=='echo':echo_client(*sys.argv[2:])
    else:run()
