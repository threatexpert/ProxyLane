"""Headless PRC plus 32/64-bit production Hook UDP-blocking probes."""
import json
from pathlib import Path
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[2]
WORK=ROOT/'build/qa/udp-fakeip'

def run():
    # The existing test host uses the public interface and an isolated PRC.
    shutil.copy2(ROOT/'build/quic-live/host.exe',WORK/'host.exe')
    for name in ('ProxyLaneHook32.dll','ProxyLaneHook64.dll'):
        shutil.copy2(ROOT/'bin'/name,WORK/name)
    with (WORK/'host.log').open('w') as log:
        host=subprocess.Popen([str(WORK/'host.exe'),'NOPROXY','0'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log,text=True,creationflags=subprocess.CREATE_NO_WINDOW)
        def call(**request):
            host.stdin.write(json.dumps(request)+'\n');host.stdin.flush()
            reply=json.loads(host.stdout.readline());assert 'error' not in reply,reply
            return reply
        try:
            call(type='test_udp_policy',blocked=True)
            call(type='test_tcp_policy',enabled=True)
            pipe=call(type='test_pipe')['pipe']
            for arch,bits in [('x64',64),('x86',32)]:
                result=subprocess.run([str(WORK/f'probe-{arch}.exe'),str(WORK/f'ProxyLaneHook{bits}.dll'),pipe],capture_output=True,text=True,timeout=40,creationflags=subprocess.CREATE_NO_WINDOW)
                (WORK/f'result-{arch}.log').write_text(result.stdout+result.stderr,encoding='utf-8')
                assert result.returncode==0,(arch,result.stdout,result.stderr)
                print(arch+': '+result.stdout.splitlines()[-1],flush=True)
        finally:
            try:host.communicate('{"type":"quit"}\n',timeout=10)
            except subprocess.TimeoutExpired:host.kill();host.wait()

if __name__=='__main__':run()
