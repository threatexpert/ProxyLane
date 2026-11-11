"""Strict public-site TLS through the actual PRC/Hook, no OS trust changes.

The child trusts only ProxyLane's public CA for the MITM leg. The host must
validate the origin using the production system + bundled public roots.
"""
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import quic_mitm_probe as probe
from quic_hook_certificates import proxylane_key
from quic_live_route_probe import Host
from cryptography.hazmat.primitives import serialization

ROOT=Path(__file__).resolve().parents[2]
def child(cafile):
    assert input()=='start'
    context=ssl.create_default_context(cafile=cafile)
    context.set_alpn_protocols(['http/1.1'])
    for domain,ip in [('www.msn.com','23.41.253.51'),('assets.msn.com','23.41.253.51'),('github.com',None)]:
        start=time.monotonic()
        with socket.create_connection((ip or domain,443),timeout=25) as raw:
            with context.wrap_socket(raw,server_hostname=domain) as s:
                issuer=s.getpeercert()['issuer']
                assert any(value=='ProxyLane CA' for rdn in issuer for key,value in rdn if key=='commonName'),issuer
                s.sendall(f'HEAD / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n'.encode())
                head=b''
                while b'\r\n\r\n' not in head:
                    b=s.recv(4096);assert b and len(head)<65536;head+=b
                status=head.split(b'\r\n',1)[0].decode()
                assert status.startswith('HTTP/1.1 '),status
                print(json.dumps(dict(domain=domain,ip=ip,mitm=True,strict_upstream=True,status=status,
                    seconds=round(time.monotonic()-start,3))),flush=True)

def run():
    probe.isolate()
    base=ROOT/'build/recording-validation'
    with tempfile.TemporaryDirectory(dir=base,prefix='public-trust-') as tmp:
        work=Path(tmp)
        ca,_=proxylane_key(Path(os.environ['LOCALAPPDATA'])/'ProxyLane/ca.json')
        (work/'ca.pem').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        host=Host(work)
        process=None
        try:
            host.call(type='test_tcp_policy',enabled=True)
            host.call(type='mitm_options',skip_upstream_verify=False)
            host.call(type='monitor_start',decrypt=True,quic=False)
            process=subprocess.Popen([sys.executable,__file__,'child',str(work/'ca.pem')],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding='utf-8',
                creationflags=subprocess.CREATE_NO_WINDOW)
            assert host.call(type='attach',pid=process.pid)['result']==0xff01
            time.sleep(.5)
            out,err=process.communicate('start\n',timeout=100)
            assert process.returncode==0,(out,err)
            rows=[json.loads(line) for line in out.splitlines()]
            (base/'public-trust-results.json').write_text(json.dumps(rows,indent=2),encoding='utf-8')
            print(out,end='')
        finally:
            if process and process.poll() is None:process.kill();process.wait()
            host.close()
            (base/'public-trust-host.log').write_bytes((work/'host.log').read_bytes())
if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='child':child(sys.argv[2])
    else:run()
