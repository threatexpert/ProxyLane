"""Verify MITM verification preference survives actual GUI exits/restarts in an isolated directory."""
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
import psutil
from MonitorLayoutE2ETests import u, k, CALLBACK, send, screenshot

def wait(predicate, message):
    for _ in range(150):
        value=predicate()
        if value:return value
        time.sleep(.1)
    raise AssertionError(message)

def main():
    parser=argparse.ArgumentParser();parser.add_argument("--language",default="zh-CN",choices=["zh-CN","en-US"]);args=parser.parse_args()
    root=Path(__file__).resolve().parents[1]
    work=root/'build/qa'/('mitm-persistence-'+uuid.uuid4().hex[:10]);work.mkdir()
    k.GetModuleHandleW.argtypes=[w.LPCWSTR];k.GetModuleHandleW.restype=w.HMODULE
    module=k.GetModuleHandleW('ProxyLaneHook64.dll')
    if module:assert c.WinDLL('ProxyLaneHook64.dll',handle=module).gp_UnhookWinsock()
    u.SetProcessDPIAware()
    for pattern in ('ProxyLane*.exe','ProxyLane*.dll'):
        for source in (root/'bin').glob(pattern):shutil.copy2(source,work/source.name)
    (work / 'portable.flag').touch()
    ini=work/'ProxyLane.ini';ini.write_text((root/'examples/ProxyLane.ini').read_text().replace('DecryptHTTPS=1','DecryptHTTPS=0').replace('DecryptQUIC=1','DecryptQUIC=0').replace('[options]', '[options]\nlanguage='+args.language),encoding='utf-8')
    config=configparser.ConfigParser();config.read(ini,encoding='utf-8-sig')
    if not config.has_section('mitm'):config.add_section('mitm')
    config.set('mitm','PreviewKiB','128')
    with ini.open('w',encoding='utf-8') as output:config.write(output)
    env=dict(os.environ,PROXYLANE_MITM='0',PROXYLANE_MITM_HOME=str(work/'pki'))
    for phase,(expected,new_value,action) in enumerate([
        (False,True,'cancel'),(False,True,'close'),(False,True,'save'),
        (True,False,'cancel'),(True,False,'save'),(False,None,'cancel')]):
        process=subprocess.Popen([str(work/'ProxyLane64.exe')],cwd=work,env=env)
        def windows():
            found=[]
            @CALLBACK
            def collect(hwnd,_):
                pid=w.DWORD();u.GetWindowThreadProcessId(hwnd,c.byref(pid))
                if pid.value==process.pid and u.IsWindowVisible(hwnd):found.append(hwnd)
                return True
            u.EnumWindows(collect,0);return found
        try:
            main_window=wait(lambda:next((h for h in windows() if u.GetDlgItem(h,0x1006)),None),'main window missing')
            time.sleep(.7)
            assert not any(Path(m.path).name.lower()=='proxylanemitm64.dll' for m in psutil.Process(process.pid).memory_maps()),'Saved options must not load MITM on startup'
            nav=u.GetDlgItem(main_window,0x1006);pages=[]
            @CALLBACK
            def find(hwnd,_):
                if u.GetDlgItem(hwnd,1086):pages.append(hwnd)
                return True
            u.EnumChildWindows(nav,find,0);page=pages[0]
            scale=u.GetDpiForWindow(nav)/96;x,y=round(50*scale),round((78+3*44+20)*scale)
            send(nav,0x201,1,(y<<16)|x);send(nav,0x202,0,(y<<16)|x)
            assert u.PostMessageW(page,0x111,1086,u.GetDlgItem(page,1086))
            dialog=wait(lambda:next((h for h in windows() if u.GetDlgItem(h,1107) and u.IsWindowEnabled(u.GetDlgItem(h,1))),None),'MITM options missing')
            control=u.GetDlgItem(dialog,1107)
            assert send(control,0xF0)==int(expected),('Restored preference mismatch',phase,expected)
            original=ini.read_bytes()
            if new_value is not None:
                send(control,0xF1,int(new_value));send(dialog,0x111,1107,control)
                assert send(control,0xF0)==int(new_value)
                assert ini.read_bytes()==original,'Draft must not change INI'
            screenshot(dialog,work/('options-phase-'+str(phase)+'.png'))
            if phase==0:
                send(dialog,0x111,1300,u.GetDlgItem(dialog,1300))
                screenshot(dialog,work/'options-expanded.png')
            assert u.PostMessageW(dialog,0x10 if action=='close' else 0x111,1301 if action=='save' else 1,0)
            wait(lambda:not u.IsWindow(dialog),'options did not close')
            if action=='save':
                saved=configparser.ConfigParser();saved.read(ini,encoding='utf-8-sig')
                assert saved.getboolean('options','MitmSkipUpstreamVerify')==new_value
                assert saved.get('options','lastselected')=='Test','Other settings overwritten'
            else:
                assert ini.read_bytes()==original,'Cancel/X must not save any draft'
            assert not (work/'pki/ca.json').exists(),'Preference must not initialize/install CA'
        finally:
            for hwnd in windows():u.PostMessageW(hwnd,0x10,0,0)
            try:process.wait(timeout=8)
            except subprocess.TimeoutExpired:process.kill();process.wait()
        assert process.returncode==0,('GUI exit failed',process.returncode)
    print('PASS MITM options: drafts, Cancel/X discard, save and close, restart restore',work,flush=True)

if __name__=='__main__':main()
