"""Real 32-bit UI with only the x64 bootstrap bypassed; no optional DLLs/CA.

Owns every window/process/INI it touches. This exercises architecture policy,
not actual Windows XP compatibility.
"""
import argparse
import configparser
import ctypes as c
from ctypes import wintypes as w
import os
from pathlib import Path
import shutil
import subprocess
import time
import uuid
from MonitorLayoutE2ETests import u, CALLBACK, send, screenshot


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary-directory', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    work = root/'build/qa'/('legacy-ui-'+uuid.uuid4().hex[:10])
    work.mkdir()
    for name in ('ProxyLane.exe', 'ProxyLaneHook32.dll'):
        shutil.copy2(args.binary_directory/name, work/name)
    (work / 'portable.flag').touch()
    ini = work/'ProxyLane.ini'
    ini.write_text('''[options]
language=en-US
lastselected=Encrypted
MitmSkipUpstreamVerify=1
[mitm]
EntryMiB=48
TotalMiB=768
[proxy_Encrypted]
Type=SOCKS5
Host=127.0.0.1
Port=9
Transport=GONC_TLS_PSK
PSK=test-existing-psk
[proxy_Plain]
Type=SOCKS5
Host=127.0.0.1
Port=9
Transport=PLAIN
''')
    env=dict(os.environ, PROXYLANE_MITM='1')
    process=subprocess.Popen([str(work/'ProxyLane.exe')],cwd=work,env=env)
    def wait(predicate):
        for _ in range(100):
            value=predicate()
            if value:return value
            assert process.poll() is None, ('host exited',process.returncode)
            time.sleep(.05)
        raise AssertionError('Timed out waiting for owned UI')
    def windows():
        result=[]
        @CALLBACK
        def collect(hwnd,_):
            pid=w.DWORD();u.GetWindowThreadProcessId(hwnd,c.byref(pid))
            if pid.value==process.pid and u.IsWindowVisible(hwnd):result.append(hwnd)
            return True
        u.EnumWindows(collect,0)
        return result
    def text(hwnd):
        value=c.create_unicode_buffer(4096);send(hwnd,0xD,len(value),c.addressof(value));return value.value
    try:
        main_window=wait(lambda:next((h for h in windows() if u.GetDlgItem(h,0x1006)),None))
        nav=u.GetDlgItem(main_window,0x1006)
        panels=[]
        @CALLBACK
        def collect(hwnd,_):
            if u.GetDlgItem(hwnd,1068) or u.GetDlgItem(hwnd,1086):panels.append(hwnd)
            return True
        u.EnumChildWindows(nav,collect,0)
        profile=next(h for h in panels if u.GetDlgItem(h,1068))
        monitor=next(h for h in panels if u.GetDlgItem(h,1086))
        transport=u.GetDlgItem(profile,1068)
        assert send(transport,0x147)==1, 'Existing encrypted mode was silently downgraded'
        assert not u.IsWindowEnabled(transport) and not u.IsWindowEnabled(u.GetDlgItem(profile,1070))
        for ident in (1086,1011):assert not u.IsWindowEnabled(u.GetDlgItem(monitor,ident))
        time.sleep(.3)
        assert windows()==[main_window], 'Persisted MITM settings caused an error dialog'
        screenshot(main_window,work/'encrypted-profile-disabled.png')
        # Start rejects an encrypted profile before any connection can be made.
        u.PostMessageW(profile,0x111,1,u.GetDlgItem(profile,1))
        error=wait(lambda:next((h for h in windows() if h!=main_window),None))
        message=text(u.GetDlgItem(error,0xffff))
        assert '64-bit ProxyLane' in message and 'not been changed' in message,message
        u.PostMessageW(error,0x111,1,0)
        saved=configparser.ConfigParser();saved.read(ini)
        assert saved['proxy_Encrypted']['Transport']=='GONC_TLS_PSK'
        assert saved['proxy_Encrypted']['PSK']=='test-existing-psk'
        assert saved['options']['MitmSkipUpstreamVerify']=='1'
        assert saved['mitm']['EntryMiB']=='48'
    finally:
        if process.poll() is None:process.terminate();process.wait(5)
    # Automation fails explicitly as well; it must not launch the target.
    result=subprocess.run([str(work/'ProxyLane.exe'),'--auto','--profile','Encrypted',
                           '--run',os.environ['COMSPEC'],'--','/c','exit','0'],cwd=work,env=env,timeout=20)
    assert result.returncode==4, ('encrypted automation must fail',result.returncode)
    # Ordinary proxy startup/injection remains functional on the 32-bit host.
    target=Path(os.environ['WINDIR'])/'SysWOW64/cmd.exe'
    marker=work/'plain-started.txt'
    process=subprocess.Popen([str(work/'ProxyLane.exe'),'--auto','--profile','Plain',
                              '--run',str(target),'--','/c',f'echo legacy-host-ok>{marker}'],cwd=work,env=env)
    try:
        wait(lambda:marker.exists())
        assert marker.read_text().strip()=='legacy-host-ok'
        assert process.poll() is None, 'The ordinary proxy should remain running'
    finally:
        if process.poll() is None:process.terminate();process.wait(5)
    print('PASS: 32-bit controls disabled, encrypted config preserved/rejected, MITM settings ignored, plain proxy startup and injection',work)


if __name__=='__main__':main()
