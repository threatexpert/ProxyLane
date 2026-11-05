"""Owned GUI: explicit HTTPS startup fails closed; no certificate trust changes."""
import ctypes as c
from ctypes import wintypes as w
import os
from pathlib import Path
import shutil
import subprocess
import time
import uuid
from MonitorLayoutE2ETests import u, CALLBACK, send, screenshot


def run(root, decrypt, missing_module):
    work = root/'build/qa'/('monitor-start-'+uuid.uuid4().hex[:10])
    work.mkdir()
    for name in ('ProxyLane64.exe', 'ProxyLaneHook64.dll', 'ProxyLaneHook32.dll',
                 'ProxyLaneMitm64.dll', 'ProxyLaneSecureTransport64.dll'):
        if missing_module and name == 'ProxyLaneMitm64.dll': continue
        shutil.copy2(root/'bin'/name, work/name)
    ini = (root/'examples/ProxyLane.ini').read_text(encoding='utf-8')
    ini = ini.replace('[options]', '[options]\nlanguage=zh-CN\nDecryptHTTPS='+str(int(decrypt)))
    (work / 'portable.flag').touch()
    (work/'ProxyLane.ini').write_text(ini, encoding='utf-8')
    env = dict(os.environ, PROXYLANE_MITM='0', PROXYLANE_MITM_HOME=str(work/'pki'),
               PROXYLANE_PROTOCOL_CACHE_ROOT=str(work/'cache'))
    process = subprocess.Popen([str(work/'ProxyLane64.exe')], cwd=work, env=env)
    def wait(predicate, message):
        deadline = time.monotonic()+15
        while time.monotonic()<deadline:
            assert process.poll() is None, ('GUI exited', process.returncode, work)
            value=predicate()
            if value: return value
            time.sleep(.1)
        for i,h in enumerate(windows()):
            screenshot(h,work/('failure-'+str(i)+'.png'))
            title=c.create_unicode_buffer(512);u.GetWindowTextW(h,title,512)
            print('WINDOW',h,title.value,flush=True)
        raise AssertionError((message, work))
    def windows():
        found=[]
        @CALLBACK
        def collect(h, _):
            pid=w.DWORD();u.GetWindowThreadProcessId(h,c.byref(pid))
            if pid.value==process.pid and u.IsWindowVisible(h): found.append(h)
            return True
        u.EnumWindows(collect,0)
        return found
    try:
        main=wait(lambda:next((h for h in windows() if u.GetDlgItem(h,0x1006)),None),'main')
        nav=u.GetDlgItem(main,0x1006);pages=[]
        @CALLBACK
        def find(h,_):
            if u.GetDlgItem(h,1086):pages.append(h)
            return True
        u.EnumChildWindows(nav,find,0);assert len(pages)==1
        page=pages[0];scale=u.GetDpiForWindow(nav)/96
        x,y=round(50*scale),round((78+3*44+20)*scale)
        send(nav,0x201,1,(y<<16)|x);send(nav,0x202,0,(y<<16)|x)
        assert not u.GetDlgItem(page,1085), 'Main page must have only one switch'
        monitor=u.GetDlgItem(page,1011)
        send(monitor,0xF1,1);u.PostMessageW(page,0x111,1011,monitor)
        if decrypt:
            popup=wait(lambda:next((h for h in windows() if h!=main),None),'startup result')
            is_options=bool(u.GetDlgItem(popup,1107))
            assert is_options == (not missing_module), 'Missing CA must guide; missing module must fail'
            if is_options:
                wait(lambda:u.IsWindowEnabled(u.GetDlgItem(popup,1)), 'CA query')
                assert send(u.GetDlgItem(popup,1085),0xF0)==1
            assert send(monitor,0xF0)==0, 'Failed start must remain unchecked'
            screenshot(popup,work/'startup-result.png')
            u.PostMessageW(popup,0x10,0,0)
            wait(lambda:not u.IsWindow(popup),'close startup result')
            time.sleep(.5)
            assert send(monitor,0xF0)==0 and u.IsWindowEnabled(monitor)
            assert len(windows())==1, 'Repeated error or guide'
        else:
            wait(lambda:u.IsWindowEnabled(monitor),'plain monitoring start')
            assert send(monitor,0xF0)==1 and len(windows())==1
            send(monitor,0xF1,0);u.PostMessageW(page,0x111,1011,monitor)
            wait(lambda:u.IsWindowEnabled(monitor) and send(monitor,0xF0)==0,'stop monitoring')
        assert not (work/'pki/ca.json').exists(), 'This test must not initialize or install a CA'
        print('PASS', {'decrypt':decrypt,'missing_module':missing_module}, work, flush=True)
    finally:
        if process.poll() is None:process.terminate();process.wait(5)


if __name__=='__main__':
    u.SetProcessDPIAware()
    root=Path(__file__).resolve().parents[1]
    for case in ((True,False),(True,True),(False,False)):
        run(root,*case)
