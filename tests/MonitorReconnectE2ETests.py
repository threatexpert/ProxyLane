"""Owned GUI/injected sockets: reconnect choices; uses an existing trusted CA without changing trust."""
import ctypes as c
from ctypes import wintypes as w
import json, os, shutil, socket, socketserver, subprocess, sys, time, uuid
from pathlib import Path
from MonitorLayoutE2ETests import u, k, CALLBACK, send, screenshot

def wait(predicate, message, seconds=20):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        value=predicate()
        if value: return value
        time.sleep(.1)
    raise AssertionError(message)

def client(port, folder, name):
    path=Path(folder)
    for generation in range(2):
        with socket.create_connection(('203.0.113.10',int(port)),20) as stream:
            (path/(name+'-'+str(generation))).write_text('connected')
            while stream.recv(4096): pass
        (path/(name+'-closed-'+str(generation))).write_text('closed')

class Origin(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(45)
        try:
            while self.request.recv(4096): pass
        except OSError: pass

def main():
    root=Path(__file__).resolve().parents[1]
    sys.path.insert(0,str(root/'tests/e2e'))
    from mitm_e2e import Proxy,start
    k.GetModuleHandleW.argtypes=[w.LPCWSTR];k.GetModuleHandleW.restype=w.HMODULE
    module=k.GetModuleHandleW('ProxyLaneHook64.dll')
    if module: assert c.WinDLL('ProxyLaneHook64.dll',handle=module).gp_UnhookWinsock()
    u.SetProcessDPIAware()
    origin,relay=start(Origin),start(Proxy)
    work=root/'build/qa'/('monitor-reconnect-'+uuid.uuid4().hex[:10]);work.mkdir()
    for pattern in ('ProxyLane*.exe','ProxyLane*.dll'):
        for source in (root/'bin').glob(pattern): shutil.copy2(source,work/source.name)
    profile='Reconnect'+uuid.uuid4().hex[:8]
    config=(root/'examples/ProxyLane.ini').read_text().replace('Test',profile).replace('Port=1080','Port='+str(relay.server_address[1]))
    (work / 'portable.flag').touch()
    (work/'ProxyLane.ini').write_text(config.replace('[options]','[options]\nlanguage=zh-CN'))
    ca=Path(os.environ['LOCALAPPDATA'])/'ProxyLane'
    ca_snapshot=(ca/'ca.json').read_bytes()
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1',0));crl_port=reserve.getsockname()[1]
    env=dict(os.environ,PROXYLANE_MITM='0',PROXYLANE_MITM_HOME=str(ca),PROXYLANE_MITM_CRL_PORT=str(crl_port),PROXYLANE_PROTOCOL_CACHE_ROOT=str(work/'cache'))
    process=subprocess.Popen([str(work/'ProxyLane64.exe')],cwd=work,env=env)
    launches=[]
    def windows():
        found=[]
        @CALLBACK
        def collect(hwnd,_):
            pid=w.DWORD();u.GetWindowThreadProcessId(hwnd,c.byref(pid))
            if pid.value==process.pid and u.IsWindowVisible(hwnd):found.append(hwnd)
            return True
        u.EnumWindows(collect,0);return found
    def launch(name):
        p=subprocess.Popen([str(work/'ProxyLane64.exe'),'--auto','--profile',profile,'--run',sys.executable,'--',str(Path(__file__).resolve()),'--client',str(origin.server_address[1]),str(work),name],cwd=work,env=env)
        launches.append(p);wait(lambda:(work/(name+'-0')).exists(),'client did not connect')
    try:
        hwnd=wait(lambda:next((h for h in windows() if u.GetDlgItem(h,0x1006)),None),'main window missing')
        nav=u.GetDlgItem(hwnd,0x1006);pages={}
        @CALLBACK
        def find(h,_):
            if u.GetDlgItem(h,1086):pages['monitor']=h
            if u.GetDlgItem(h,1005) and u.GetDlgItem(h,1):pages['proxy']=h
            return True
        u.EnumChildWindows(nav,find,0);page=pages['monitor']
        send(pages['proxy'],0x111,1,u.GetDlgItem(pages['proxy'],1));time.sleep(.5)
        scale=u.GetDpiForWindow(nav)/96;x,y=round(50*scale),round((78+3*44+20)*scale)
        send(nav,0x201,1,(y<<16)|x);send(nav,0x202,0,(y<<16)|x)
        monitor=u.GetDlgItem(page,1011)
        k.WritePrivateProfileStringW.argtypes=[w.LPCWSTR,w.LPCWSTR,w.LPCWSTR,w.LPCWSTR]
        def decrypt(value):
            assert k.WritePrivateProfileStringW('options','DecryptHTTPS',str(int(value)),str(work/'ProxyLane.ini'))
        def settled(on):
            wait(lambda:u.IsWindowEnabled(monitor) and send(monitor,0xF0)==int(on),'monitor did not settle')
        def toggle(on):
            send(monitor,0xF1,int(on));assert u.PostMessageW(page,0x111,1011,monitor)
        def prompt():
            for h in windows():
                labels=[]
                @CALLBACK
                def label(ch,_):
                    value=c.create_unicode_buffer(2048);u.GetWindowTextW(ch,value,2048);labels.append(value.value);return True
                u.EnumChildWindows(h,label,0)
                if all(u.GetDlgItem(h,button) for button in (6,7,2)) and any('是否断开这些连接' in text for text in labels):return h
            return None
        decrypt(True);toggle(True);time.sleep(.2);settled(True)
        assert not prompt() and len(windows())==1,'No connections must not prompt'
        toggle(False);time.sleep(.2);settled(False)
        decrypt(False)
        launch('old');time.sleep(.5)
        toggle(True);time.sleep(.2);settled(True)
        assert not prompt() and len(windows())==1,'Plain monitoring must not prompt for existing TCP connections'
        assert not (work/'old-closed-0').exists(),'Plain monitoring disconnected existing TCP'
        toggle(False);time.sleep(.2);settled(False)
        decrypt(True)
        for choice in (7,2): # New only, then cancel: neither may close the existing connection.
            toggle(True);dialog=wait(prompt,'expected reconnect choice')
            assert send(dialog,0x400)==0x534B0007, 'Default button should be No'
            title=c.create_unicode_buffer(128);u.GetWindowTextW(dialog,title,128)
            assert title.value=='开始监视',title.value
            assert u.PostMessageW(dialog,0x111,choice,u.GetDlgItem(dialog,choice))
            wait(lambda:not u.IsWindow(dialog),'choice did not close');time.sleep(.4)
            assert not (work/'old-closed-0').exists()
            assert send(monitor,0xF0)==(choice==7)
            if choice==7:toggle(False);time.sleep(.2)
        toggle(True);dialog=wait(prompt,'expected disconnect choice')
        screenshot(dialog,work/'reconnect-prompt.png')
        launch('new') # Created after snapshot; must survive confirmation.
        assert u.PostMessageW(dialog,0x111,6,u.GetDlgItem(dialog,6))
        wait(lambda:(work/'old-1').exists(),'old socket not disconnected/reconnected')
        assert not (work/'new-closed-0').exists(),'snapshot disconnected a newer socket'
        listing=u.GetDlgItem(page,1098)
        wait(lambda:send(listing,0x1004)==1,'idle reconnected socket missing or duplicated')
        screenshot(hwnd,work/'idle-session.png')
        print('PASS reconnect: plain monitoring skips prompt; decryption prompts only with existing TCP; title, default No, cancel, snapshot',work,flush=True)
    finally:
        # Only the isolated GUI and its launched jobs belong to this test.
        for h in windows():u.PostMessageW(h,0x10,0,0)
        try:process.wait(timeout=8)
        except subprocess.TimeoutExpired:process.kill();process.wait()
        for p in launches:
            try:p.wait(timeout=5)
            except subprocess.TimeoutExpired:p.kill();p.wait()
        origin.shutdown();relay.shutdown()
        assert (ca/'ca.json').read_bytes()==ca_snapshot,'CA identity changed'

if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--client':client(*sys.argv[2:])
    else:main()
