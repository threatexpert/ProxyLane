"""Regression for monitor activation/zero-size layout messages in an owned GUI.

Copies release files and a sample profile to build/qa. No proxy is started and
no CA trust is changed. Requires an unlocked Windows desktop and Python/Pillow.
"""
import argparse
import ctypes as c
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import time
import uuid

u, k, g = c.windll.user32, c.windll.kernel32, c.windll.gdi32
CALLBACK = c.WINFUNCTYPE(w.BOOL, w.HWND, w.LPARAM)
u.EnumWindows.argtypes = [CALLBACK, w.LPARAM]
u.EnumChildWindows.argtypes = [w.HWND, CALLBACK, w.LPARAM]
u.GetWindowThreadProcessId.argtypes = [w.HWND, c.POINTER(w.DWORD)]
u.GetDlgItem.argtypes = [w.HWND, c.c_int]; u.GetDlgItem.restype = w.HWND
u.GetClientRect.argtypes = [w.HWND, c.POINTER(w.RECT)]
u.GetWindowRect.argtypes = [w.HWND, c.POINTER(w.RECT)]
u.MapWindowPoints.argtypes = [w.HWND, w.HWND, c.c_void_p, w.UINT]
u.IsWindowVisible.argtypes = [w.HWND]
u.IsWindow.argtypes = [w.HWND]
u.IsWindowEnabled.argtypes = [w.HWND]
u.GetWindowTextW.argtypes = [w.HWND, w.LPWSTR, c.c_int]
u.SendMessageTimeoutW.argtypes = [w.HWND, w.UINT, w.WPARAM, w.LPARAM, w.UINT, w.UINT, c.POINTER(c.c_size_t)]
u.PostMessageW.argtypes = [w.HWND, w.UINT, w.WPARAM, w.LPARAM]
u.SetWindowPos.argtypes = [w.HWND, w.HWND, c.c_int, c.c_int, c.c_int, c.c_int, w.UINT]
u.GetDpiForWindow.argtypes = [w.HWND]
u.GetDC.argtypes = [w.HWND]; u.GetDC.restype = w.HDC
u.ReleaseDC.argtypes = [w.HWND, w.HDC]
u.PrintWindow.argtypes = [w.HWND, w.HDC, w.UINT]
g.CreateCompatibleDC.argtypes = [w.HDC]; g.CreateCompatibleDC.restype = w.HDC
g.CreateCompatibleBitmap.argtypes = [w.HDC, c.c_int, c.c_int]; g.CreateCompatibleBitmap.restype = w.HBITMAP
g.SelectObject.argtypes = [w.HDC, w.HANDLE]; g.SelectObject.restype = w.HANDLE
g.GetDIBits.argtypes = [w.HDC, w.HBITMAP, w.UINT, w.UINT, c.c_void_p, c.c_void_p, w.UINT]
g.DeleteObject.argtypes = [w.HANDLE]; g.DeleteDC.argtypes = [w.HDC]

def send(hwnd, message, wp=0, lp=0):
    result = c.c_size_t()
    assert u.SendMessageTimeoutW(hwnd, message, wp, lp, 2, 3000, c.byref(result)), 'Unresponsive window'
    return result.value

def rect(hwnd, parent=None):
    r = w.RECT(); u.GetWindowRect(hwnd, c.byref(r))
    if parent: u.MapWindowPoints(None, parent, c.byref(r), 2)
    return [r.left, r.top, r.right, r.bottom]


def screenshot(hwnd, path):
    from PIL import Image
    r = rect(hwnd); width, height = r[2]-r[0], r[3]-r[1]
    dc = u.GetDC(hwnd); memory = g.CreateCompatibleDC(dc)
    bitmap = g.CreateCompatibleBitmap(dc, width, height); old = g.SelectObject(memory, bitmap)
    try:
        assert u.PrintWindow(hwnd, memory, 2), 'PrintWindow failed'
        g.SelectObject(memory, old)
        # BITMAPINFOHEADER, followed by unused color entries for 32-bit RGB.
        info = (c.c_uint32 * 11)(); info[0] = 40; info[1] = width; info[2] = c.c_uint32(-height).value
        info[3] = 1 | (32 << 16)
        pixels = c.create_string_buffer(width*height*4)
        assert g.GetDIBits(memory, bitmap, 0, height, pixels, c.byref(info), 0) == height
        Image.frombytes('RGB', (width,height), pixels.raw, 'raw', 'BGRX').save(path)
    finally:
        g.SelectObject(memory, old); g.DeleteObject(bitmap); g.DeleteDC(memory); u.ReleaseDC(hwnd, dc)

def ca_guidance(process, page, main_window, work, verify_read_error=False):
    """Exercise real GUI onboarding using only this test's unique CA."""
    def wait(predicate, message):
        for _ in range(150):
            value = predicate()
            if value: return value
            assert process.poll() is None, ('GUI exited', process.returncode, str(work))
            time.sleep(.1)
        raise AssertionError((message, str(work)))
    def read(hwnd):
        buf = c.create_unicode_buffer(8192)
        send(hwnd, 0xD, len(buf), c.addressof(buf)); return buf.value
    def dialogs(ca):
        found = []
        @CALLBACK
        def collect(hwnd, _):
            pid = w.DWORD(); u.GetWindowThreadProcessId(hwnd, c.byref(pid))
            if pid.value == process.pid and hwnd != main_window and u.IsWindowVisible(hwnd):
                is_ca = bool(u.GetDlgItem(hwnd, 1107))
                if is_ca == ca and u.GetDlgItem(hwnd, 1): found.append(hwnd)
            return True
        u.EnumWindows(collect, 0)
        return found[0] if found else None
    # The saved preference controls the next monitoring start.
    ini=work/'ProxyLane.ini'
    text=ini.read_text();text=text.replace('DecryptHTTPS=0','DecryptHTTPS=1')
    if 'DecryptHTTPS=1' not in text:text=text.replace('[options]','[options]\nDecryptHTTPS=1')
    ini.write_text(text)
    decrypt = u.GetDlgItem(page, 1011)
    def toggle(enabled):
        send(decrypt, 0xF1, int(enabled))
        send(page, 0x111, 1011, decrypt)  # Finish reading the checkbox before toggling it again.
    def ready(dialog):
        return u.IsWindowEnabled(u.GetDlgItem(dialog, 1))
    def open_guide():
        toggle(True)
        def detect():
            assert not dialogs(False), 'Missing CA incorrectly opened an error message'
            return dialogs(True)
        dialog = wait(detect, 'CA guidance did not open')
        wait(lambda: ready(dialog), 'CA query did not finish')
        assert read(u.GetDlgItem(dialog,1096)) == 'ProxyLane CA / TLS', 'CA section heading'
        assert not u.GetDlgItem(dialog, 1092), 'Removed initialization button remains'
        instruction = read(u.GetDlgItem(dialog, 1087))
        assert 'HTTPS' in instruction and ('当前系统用户' in instruction or 'current Windows user' in instruction), instruction
        return dialog
    def close(dialog, message=0x10, wp=0):
        assert u.PostMessageW(dialog, message, wp, 0)
        wait(lambda: not u.IsWindow(dialog), 'CA dialog did not close')

    dialog = open_guide()
    close(dialog, 0x111, 2)  # Cancel before installing: remain off, no repeated guide.
    assert send(decrypt, 0xF0) == 0
    time.sleep(.3); assert not dialogs(True) and not dialogs(False)
    dialog = open_guide()
    assert not (work/'pki/ca.json').exists(), 'Guidance should not create the CA before installation'
    screenshot(dialog, work/'ca-install-guidance.png')
    assert u.PostMessageW(dialog, 0x111, 1093, u.GetDlgItem(dialog, 1093))
    try:
        wait(lambda: u.IsWindowEnabled(u.GetDlgItem(dialog, 1094)) and ready(dialog), 'CA installation failed')
    except AssertionError:
        screenshot(dialog, work/'ca-install-failure.png')
        print('CA details:', read(u.GetDlgItem(dialog, 1087)), 'status:', read(u.GetDlgItem(dialog, 1087)), flush=True)
        raise
    close(dialog,0x111,1301)  # Only Save and close resumes the requested start.
    wait(lambda: send(decrypt, 0xF0) == 1 and u.IsWindowEnabled(decrypt), 'Decryption did not resume after installation')
    assert send(u.GetDlgItem(page, 1011), 0xF0) == 1, 'Monitoring did not start'
    assert not dialogs(False)
    screenshot(main_window, work/'ca-guidance-enabled.png')
    toggle(False); wait(lambda: send(decrypt, 0xF0) == 0, 'Disable failed')
    if not verify_read_error: return
    # Corruption is a real failure: it must still show an error rather than
    # disguising it as a missing certificate. Restore for exact-CA cleanup.
    path = work/'pki/ca.json'; original = path.read_bytes()
    try:
        path.write_text('{invalid')
        toggle(True)
        error = wait(lambda: dialogs(False), 'Real CA error was not reported')
        assert not dialogs(True)
        assert u.PostMessageW(error, 0x111, 1, 0)
        wait(lambda: not u.IsWindow(error), 'Error did not close')
        assert send(decrypt, 0xF0) == 0
    finally:
        path.write_bytes(original)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary-directory', default='bin')
    parser.add_argument('--language', choices=['zh-CN','en-US'], default='zh-CN')
    parser.add_argument('--ca-guidance', action='store_true', help='Install and finally remove a unique temporary CA to verify onboarding')
    parser.add_argument('--ca-read-error', action='store_true', help='With --ca-guidance, deliberately display a CA read error dialog')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    source = (root / args.binary_directory).resolve()
    work = root / 'build/qa' / ('monitor-layout-' + uuid.uuid4().hex[:10]); work.mkdir()
    k.GetModuleHandleW.argtypes = [w.LPCWSTR]; k.GetModuleHandleW.restype = w.HMODULE
    module = k.GetModuleHandleW('ProxyLaneHook64.dll')
    if module: assert c.WinDLL('ProxyLaneHook64.dll', handle=module).gp_UnhookWinsock()
    u.SetProcessDPIAware()
    for name in ['ProxyLane64.exe','ProxyLaneHook64.dll','ProxyLaneHook32.dll','ProxyLaneMitm64.dll','ProxyLaneSecureTransport64.dll']:
        shutil.copy2(source/name, work/name)
    if args.ca_guidance:
        shutil.copy2(root/'build/tools/ProxyLaneMitm64.exe', work/'ProxyLaneMitm64.exe')
    config = (root/'examples/ProxyLane.ini').read_text().replace('[options]', '[options]\nlanguage=' + args.language)
    (work / 'portable.flag').touch()
    (work/'ProxyLane.ini').write_text(config)
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1',0)); port = reservation.getsockname()[1]
    env = dict(os.environ,PROXYLANE_MITM='0',PROXYLANE_MITM_HOME=str(work/'pki'),PROXYLANE_MITM_CRL_PORT=str(port))
    process = subprocess.Popen([str(work/'ProxyLane64.exe')], cwd=work, env=env)
    def wait(predicate, message):
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            assert process.poll() is None, ('GUI exited',process.returncode,str(work))
            value=predicate()
            if value:return value
            time.sleep(.1)
        raise AssertionError((message,str(work)))
    try:
        main_window = None
        for _ in range(100):
            assert process.poll() is None, ('GUI exited during initialization',process.returncode,str(work))
            windows = []
            @CALLBACK
            def collect(hwnd, _):
                pid=w.DWORD(); u.GetWindowThreadProcessId(hwnd,c.byref(pid))
                if pid.value == process.pid and u.IsWindowVisible(hwnd):
                    title=c.create_unicode_buffer(256);u.GetWindowTextW(hwnd,title,256)
                    if title.value.startswith('ProxyLane '): windows.append(hwnd)
                return True
            u.EnumWindows(collect,0)
            if len(windows)==1: main_window=windows[0];break
            time.sleep(.1)
        assert main_window, 'Main window did not appear'
        nav=u.GetDlgItem(main_window,0x1006); assert nav
        pages=[]
        @CALLBACK
        def find_page(hwnd,_):
            if u.GetDlgItem(hwnd,1086): pages.append(hwnd)
            return True
        u.EnumChildWindows(nav,find_page,0); assert len(pages)==1
        page=pages[0]; scale=u.GetDpiForWindow(nav)/96
        records=[]
        def activate(index):
            x,y=round(50*scale),round((78+index*44+20)*scale)
            send(nav,0x201,1,(y<<16)|x); send(nav,0x202,0,(y<<16)|x)
            time.sleep(.2)
        def keyboard_regression():
            for index, identifiers in [(1,(1007,1009)),(2,(1000,1044)),(3,(1104,1098,1100,1099,1105))]:
                matches=[]
                @CALLBACK
                def find_panel(h,_):
                    if u.GetDlgItem(h,identifiers[0]): matches.append(h)
                    return True
                u.EnumChildWindows(nav,find_panel,0)
                assert len(matches)==1, ('page not found',index,matches)
                panel=matches[0];activate(index)
                for ident in identifiers:
                    control=u.GetDlgItem(panel,ident)
                    assert control and u.IsWindowVisible(control), (index,ident)
                    if ident==1104:
                        query=c.create_unicode_buffer('curl');send(control,0xC,0,c.addressof(query))
                    send(panel,0x28,control,1)  # WM_NEXTDLGCTL: give this owned control focus.
                    for key in (0x1B,0x0D):
                        assert u.PostMessageW(control,0x100,key,1)
                        assert u.PostMessageW(control,0x101,key,0xC0000001)
                        time.sleep(.15)
                        assert process.poll() is None and u.IsWindowVisible(main_window)
                        assert u.IsWindow(panel) and u.IsWindowVisible(panel), ('key hid embedded page',index,ident,key)
                    if ident==1104:
                        query=c.create_unicode_buffer(256);send(control,0xD,256,c.addressof(query))
                        assert query.value=='curl', 'Enter/Escape changed the filter'
                        query=c.create_unicode_buffer('');send(control,0xC,0,c.addressof(query))
                # Also reject default dialog completion commands without hiding the page.
                for command in (1,2):
                    send(panel,0x111,command,0)
                    assert u.IsWindowVisible(panel), ('completion command hid page',index,command)
                activate(0);activate(index)
                assert u.IsWindowVisible(panel), ('page cannot reactivate',index)
            activate(3)
            kind=u.GetDlgItem(page,1105)
            send(page,0x28,kind,1);send(kind,0x14F,1)  # CB_SHOWDROPDOWN
            assert send(kind,0x157), 'combo did not open'
            assert u.PostMessageW(kind,0x100,0x1B,1)
            time.sleep(.15)
            assert not send(kind,0x157) and u.IsWindowVisible(page), 'Escape must close combo only'
            records.append({'case':'Esc/Enter keep process, log and monitor pages visible; combo Escape preserved'})
        def validate(label):
            assert u.IsWindowVisible(page), 'Monitor page not activated'
            client=w.RECT();u.GetClientRect(page,c.byref(client))
            controls={}
            for ident in (1085,1042,1087,1088,1089,1090,1097,1000,1012):
                assert not u.GetDlgItem(page,ident), ('Removed control still exists',ident)
            for name, ident in [('ca',1086),('monitor',1011),('hex',1102),('clear',1021),
                                ('filter',1104),('follow',1109),('kind',1105),('requests',1098),('detail_tabs',1099),('detail',1100)]:
                h=u.GetDlgItem(page,ident); assert h and u.IsWindowVisible(h), name
                r=rect(h,page); controls[name]=r
                assert 0<=r[0]<r[2]<=client.right and 0<=r[1]<r[3]<=client.bottom, (label,name,r,[client.right,client.bottom])
                assert r[2]-r[0]>=40 and r[3]-r[1]>=14, (label,name,'collapsed',r)
            assert controls['detail'][3]-controls['detail'][1]>=100
            assert controls['requests'][3] < controls['detail_tabs'][1] < controls['detail'][1]
            assert rect(u.GetDlgItem(page,1041),page)[3] <= controls['monitor'][1], 'Title overlaps controls'
            toolbar = [controls[name] for name in ('monitor','ca','clear')]
            assert len({r[1] for r in toolbar}) == 1, 'Toolbar must occupy one row'
            assert all(left[2] <= right[0] for left,right in zip(toolbar,toolbar[1:])), ('Toolbar overlaps',controls)
            assert controls['hex'][1] == controls['detail_tabs'][1], 'HEX belongs beside request/response tabs'
            assert controls['filter'][2] <= controls['follow'][0] < controls['follow'][2] <= controls['kind'][0], 'Follow control overlaps filter'
            assert controls['detail_tabs'][2] <= controls['hex'][0], 'HEX overlaps tabs'
            records.append({'case':label,'controls':controls})
        keyboard_regression()
        activate(3); validate('activation')
        screenshot(main_window,work/'monitor.png')
        # Monitor indicator remains visible on another page, and disappears on stop.
        from PIL import Image
        def monitor_dot(name):
            path=work/name; screenshot(nav,path)
            im=Image.open(path)
            area=im.crop((0,round((78+3*44)*scale),round(185*scale),round((78+3*44+40)*scale)))
            return sum(1 for r,g,b in area.getdata() if abs(r-22)<5 and abs(g-163)<5 and abs(b-74)<5)
        assert monitor_dot('monitor-stopped.png')==0, 'Unexpected active monitor indicator'
        monitor=u.GetDlgItem(page,1011)
        send(monitor,0xF1,1); send(page,0x111,1011,monitor)
        wait(lambda:u.IsWindowEnabled(monitor),'monitor start did not finish')
        assert send(monitor,0xF0)==1
        activate(0)
        assert monitor_dot('monitor-active-other-page.png')>5, 'Monitor indicator missing on another page'
        activate(3)
        assert monitor_dot('monitor-active.png')>5, 'Monitor indicator missing on its own page'
        send(monitor,0xF1,0); send(page,0x111,1011,monitor)
        activate(0)
        assert monitor_dot('monitor-stopped-other-page.png')==0, 'Monitor indicator remains after stop'
        activate(3)
        wait(lambda:u.IsWindowEnabled(monitor),'monitor stop did not finish')
        send(page,5,0,0); validate('parameterless WM_SIZE')
        for width,height in [(800,610),(1200,900)]:
            assert u.SetWindowPos(main_window,None,0,0,width,height,0x16)
            time.sleep(.15); validate(f'resize {width}x{height}')
            activate(0); activate(3); validate(f'reactivate {width}x{height}')
        # Open only the test-owned CA dialog. Status is read from a fresh data
        # directory; no install/remove trust buttons are ever invoked.
        assert u.PostMessageW(page,0x111,1086,u.GetDlgItem(page,1086))  # BN_CLICKED
        ca_dialog=None
        for _ in range(50):
            dialogs=[]
            @CALLBACK
            def find_ca(hwnd,_):
                pid=w.DWORD();u.GetWindowThreadProcessId(hwnd,c.byref(pid))
                if pid.value==process.pid and u.GetDlgItem(hwnd,1107): dialogs.append(hwnd)
                return True
            u.EnumWindows(find_ca,0)
            if len(dialogs)==1:
                details=c.create_unicode_buffer(4096)
                send(u.GetDlgItem(dialogs[0],1087),0xD,4096,c.addressof(details))
                if 'HTTPS' in details.value and u.IsWindowEnabled(u.GetDlgItem(dialogs[0],1)): ca_dialog=dialogs[0];break
            time.sleep(.1)
        assert ca_dialog, ('CA status dialog did not initialize', dialogs, details.value if dialogs else '')
        heading=c.create_unicode_buffer(128);send(u.GetDlgItem(ca_dialog,1096),0xD,128,c.addressof(heading))
        assert heading.value=='ProxyLane CA / TLS', 'CA section heading'
        assert not u.GetDlgItem(ca_dialog,1092), 'Removed CA initialization button still exists'
        bounds=w.RECT();u.GetClientRect(ca_dialog,c.byref(bounds))
        for ident in (1085,1087,1093,1094,1095,1107,1108,1):
            control=u.GetDlgItem(ca_dialog,ident); r=rect(control,ca_dialog)
            assert u.IsWindowVisible(control) and 0<=r[0]<r[2]<=bounds.right and 0<=r[1]<r[3]<=bounds.bottom, (ident,r)
        assert not u.GetDlgItem(ca_dialog,1091), 'Large diagnostic edit must be removed'
        skip=u.GetDlgItem(ca_dialog,1107)
        assert send(skip,0xF0)==0, 'Certificate verification must default to strict'
        send(skip,0xF1,1);send(ca_dialog,0x111,1107,skip)
        assert send(skip,0xF0)==1
        screenshot(ca_dialog,work/'ca-management.png')
        assert not u.IsWindowVisible(u.GetDlgItem(ca_dialog,1314)), 'Advanced fields start collapsed'
        send(ca_dialog,0x111,1300,u.GetDlgItem(ca_dialog,1300))
        assert u.IsWindowVisible(u.GetDlgItem(ca_dialog,1318))
        new_options=[48,768,1024,128,8,64,16,512,30]
        for i,value in enumerate(new_options):
            control=u.GetDlgItem(ca_dialog,1310+i)
            text=c.create_unicode_buffer(str(value));send(control,0xC,0,c.addressof(text))
        bounds=w.RECT();u.GetClientRect(ca_dialog,c.byref(bounds))
        for ident in [*range(1310,1319),1300,1301,1302,1]:
            r=rect(u.GetDlgItem(ca_dialog,ident),ca_dialog)
            assert 0<=r[0]<r[2]<=bounds.right and 0<=r[1]<r[3]<=bounds.bottom,(ident,r,bounds.bottom)
        time.sleep(.3)
        screenshot(ca_dialog,work/'mitm-options-advanced.png')
        send(ca_dialog,0x111,1301,u.GetDlgItem(ca_dialog,1301))
        wait(lambda:not u.IsWindow(ca_dialog),'Save must close the options')
        assert 'EntryMiB=48' in (work/'ProxyLane.ini').read_text(), 'INI was not saved'
        assert u.PostMessageW(page,0x111,1086,u.GetDlgItem(page,1086))
        def options_ready(d):
            status=c.create_unicode_buffer(2048)
            send(u.GetDlgItem(d,1087),0xD,len(status),c.addressof(status))
            return 'HTTPS' in status.value and u.IsWindowEnabled(u.GetDlgItem(d,1301))
        def ready_options():
            nonlocal dialogs
            dialogs=[];u.EnumWindows(find_ca,0)
            return next((d for d in dialogs if options_ready(d)),None)
        ca_dialog=wait(ready_options,'reopen saved options')
        skip=u.GetDlgItem(ca_dialog,1107)
        saved_ini=(work/'ProxyLane.ini').read_bytes()
        defaults=[32,512,512,64,4,32,8,256,15]
        send(ca_dialog,0x111,1302,u.GetDlgItem(ca_dialog,1302))
        for i,value in enumerate(defaults):
            text=c.create_unicode_buffer(32);send(u.GetDlgItem(ca_dialog,1310+i),0xD,32,c.addressof(text))
            assert text.value==str(value),('default draft',i,text.value,value)
        assert send(skip,0xF0)==0
        assert (work/'ProxyLane.ini').read_bytes()==saved_ini, 'Restore must not save automatically'
        time.sleep(.3)
        screenshot(ca_dialog,work/'mitm-defaults-pending.png')

        assert u.PostMessageW(u.GetDlgItem(ca_dialog,1107),0x100,0x1B,1)  # Escape still closes a real dialog.
        for _ in range(50):
            if not u.IsWindow(ca_dialog): break
            time.sleep(.1)
        assert u.PostMessageW(page,0x111,1086,u.GetDlgItem(page,1086))
        reopened=None
        for _ in range(50):
            dialogs=[];u.EnumWindows(find_ca,0)
            if dialogs and options_ready(dialogs[0]):
                reopened=dialogs[0];break
            time.sleep(.1)
        assert reopened, 'MITM options did not reopen'
        for i,value in enumerate(new_options):
            text=c.create_unicode_buffer(32);send(u.GetDlgItem(reopened,1310+i),0xD,32,c.addressof(text))
            assert text.value==str(value),('option did not persist',i,text.value,value)
        assert not u.IsWindowVisible(u.GetDlgItem(reopened,1314)), 'Advanced area resets to collapsed'

        skip=u.GetDlgItem(reopened,1107)
        assert send(skip,0xF0)==1, 'Native/Rust option was not retained in this instance'
        send(reopened,0x111,1302,u.GetDlgItem(reopened,1302))
        assert send(skip,0xF0)==0, 'Restore defaults must uncheck verification bypass'
        assert (work/'ProxyLane.ini').read_bytes()==saved_ini
        send(reopened,0x111,1301,u.GetDlgItem(reopened,1301))
        wait(lambda:not u.IsWindow(reopened),'Save defaults must close the dialog')
        new_options=defaults
        ini=(work/'ProxyLane.ini').read_text()
        assert 'EntryMiB=32' in ini and 'MitmSkipUpstreamVerify=0' in ini
        for _ in range(50):
            if not u.IsWindow(reopened): break
            time.sleep(.1)
        assert not u.IsWindow(reopened), 'Save no longer closes the options dialog'
        ca_dialog=reopened
        records.append({'case':'Compact MITM options, CA status, strict default and retained verification option'})
        if not args.ca_guidance:
            process.terminate();process.wait(5)
            process=subprocess.Popen([str(work/'ProxyLane64.exe')],cwd=work,env=env)
            main_window=None
            for _ in range(100):
                assert process.poll() is None,('restart failed',process.returncode)
                windows=[];u.EnumWindows(collect,0)
                if len(windows)==1:main_window=windows[0];break
                time.sleep(.1)
            assert main_window,'main window missing after restart'
            nav=u.GetDlgItem(main_window,0x1006);pages=[];u.EnumChildWindows(nav,find_page,0)
            assert len(pages)==1;page=pages[0];activate(3)
            assert u.PostMessageW(page,0x111,1086,u.GetDlgItem(page,1086))
            restored=None
            for _ in range(50):
                dialogs=[];u.EnumWindows(find_ca,0)
                if dialogs and options_ready(dialogs[0]):restored=dialogs[0];break
                time.sleep(.1)
            assert restored,'options failed to open after restart'
            for i,value in enumerate(new_options):
                text=c.create_unicode_buffer(32);send(u.GetDlgItem(restored,1310+i),0xD,32,c.addressof(text))
                assert text.value==str(value),('option lost on restart',i,text.value,value)
            assert send(u.GetDlgItem(restored,1107),0xF0)==0, 'Restored strict verification must survive restart'
            send(restored,0x111,1,u.GetDlgItem(restored,1))
            records.append({'case':'All nine MITM options persisted across GUI restart'})

        if args.ca_guidance:
            for _ in range(50):
                if not u.IsWindow(ca_dialog): break
                time.sleep(.1)
            ca_guidance(process,page,main_window,work,args.ca_read_error)
            records.append({'case':'CA guidance, cancel, direct install and resume', 'read_error':args.ca_read_error})
        (work/'results.json').write_text(json.dumps(records,indent=2))
        print('PASS',args.language,work,flush=True)
    finally:
        if process.poll() is None: process.terminate(); process.wait(5)
        if args.ca_guidance and (work/'pki/ca.json').exists():
            subprocess.run([str(work/'ProxyLaneMitm64.exe'),'remove'],env=env,check=True,stdout=subprocess.PIPE,timeout=10)
            print('Temporary CA removed',flush=True)

if __name__=='__main__': main()
