"""x64 proxy host decrypts x86/x64 curl; uses an existing trusted CA unchanged.

No certificate installation/removal. The disposable host skips verification only
for this test's self-signed local origin; curl still validates the MITM certificate.
"""
import datetime
import ctypes
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import uuid
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from mitm_e2e import start, Origin, Proxy, free_port


def main():
    kernel=ctypes.WinDLL('kernel32');kernel.GetModuleHandleW.argtypes=[ctypes.c_wchar_p];kernel.GetModuleHandleW.restype=ctypes.c_void_p
    module=kernel.GetModuleHandleW('ProxyLaneHook64.dll')
    if module:
        assert ctypes.WinDLL('ProxyLaneHook64.dll',handle=module).gp_UnhookWinsock()
    root=Path(__file__).resolve().parents[2]
    tool=root/'build/tools/ProxyLaneMitm64.exe'
    status=json.loads(subprocess.check_output([str(tool),'status'],text=True))
    assert status['trusted_current_user'], 'This test requires an existing trusted CA; it does not install one'
    ca_dir=Path(status['certificate']).parent
    saved_ca=(ca_dir/'ca.json').read_bytes()
    work=root/'build/qa'/('host-arch-'+uuid.uuid4().hex[:10]);work.mkdir()
    for name in ('ProxyLaneHook32.dll','ProxyLaneHook64.dll','ProxyLaneMitm64.dll'):
        shutil.copy2(root/'bin'/name,work/name)
    shutil.copy2(root/'build/tools/mitm_host64.exe',work/'mitm_host64.exe')
    assert not (work/'ProxyLaneMitm32.dll').exists()
    key=ec.generate_private_key(ec.SECP256R1())
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'mitm.test')])
    now=datetime.datetime.now(datetime.timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1))
          .not_valid_after(now+datetime.timedelta(hours=1)).sign(key,hashes.SHA256()))
    (work/'origin.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (work/'origin-key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(work/'origin.pem',work/'origin-key.pem')
    context.set_alpn_protocols(['http/1.1'])
    origin=start(Origin,context);proxy=start(Proxy)
    env=dict(os.environ,PROXYLANE_MITM='0',PROXYLANE_MITM_HOME=str(ca_dir),
             PROXYLANE_MITM_CRL_PORT=str(free_port()),PROXYLANE_TEST_PROTOCOL='1',PROXYLANE_TEST_SKIP_UPSTREAM='1',
             PROXYLANE_PROTOCOL_CACHE_ROOT=str(work/'cache'))
    for key in list(env):
        if key.lower() in ('http_proxy','https_proxy','all_proxy'):del env[key]
    try:
        for bits in ('32','64'):
            curl=Path(os.environ['WINDIR'])/('SysWOW64' if bits=='32' else 'System32')/'curl.exe'
            port=origin.server_address[1]
            command=[str(curl),'--silent','--show-error','--noproxy','*','--max-time','15',
                     '--resolve',f'mitm.test:{port}:203.0.113.10',f'https://mitm.test:{port}/arch-{bits}']
            result=subprocess.run([str(work/'mitm_host64.exe'),str(proxy.server_address[1]),'SOCKS5',
                                   subprocess.list2cmdline(command)],cwd=work,env=env,capture_output=True,timeout=30)
            (work/f'{bits}.stdout').write_bytes(result.stdout);(work/f'{bits}.stderr').write_bytes(result.stderr)
            assert result.returncode==0,(bits,result.returncode,result.stderr.decode(errors='replace'))
            assert b'ProxyLane MITM verified' in result.stdout
            pid=int(re.search(rb'CHILD pid=(\d+)',result.stderr).group(1))
            records=[]
            for line in result.stdout.splitlines():
                if line.startswith(b'PROTOCOL_JSON '):
                    records.extend(json.loads(line[len(b'PROTOCOL_JSON '):]).get('records',[]))
            assert any(r.get('connection',{}).get('pid')==pid and r['connection'].get('decrypted') and
                       r.get('type')=='exchange' and r['exchange']['request']['method']=='GET' and
                       r['exchange']['request']['target']==f'/arch-{bits}' and
                       r['exchange']['response']['status']==200 for r in records), 'No decrypted exchange with target PID'
            print(f'PASS: x64 host + x{bits} curl, TLS decryption, HTTP reconstruction and PID association')
        assert (ca_dir/'ca.json').read_bytes()==saved_ca,'Existing CA must remain unchanged'
        assert json.loads(subprocess.check_output([str(tool),'status'],text=True))['trusted_current_user']
    finally:
        proxy.shutdown();proxy.server_close();origin.shutdown();origin.server_close()
    print(work)


if __name__=='__main__':main()
