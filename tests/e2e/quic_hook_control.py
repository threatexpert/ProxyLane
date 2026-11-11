"""Test-only x64 controller; injects only descendants of an owned profile process."""
import ctypes as C
from ctypes import wintypes as W
import hashlib
from pathlib import Path
import pefile
import psutil

class Event(C.Structure):
    _fields_ = [('ready',C.c_int32),('input',C.c_int32),('output',C.c_int32),
                ('status',C.c_uint32),('flags',C.c_uint32),('port',C.c_uint16),('count',C.c_uint16),
                ('host',C.c_char*128),('leaf',C.c_ubyte*32),('root',C.c_ubyte*32)]
class Control(C.Structure):
    _fields_ = [('magic',C.c_uint32),('pid',C.c_uint32),('birth',C.c_uint64),('deadline',C.c_uint64),
                ('enabled',C.c_int32),('epoch',C.c_int32),('initialized',C.c_int32),('error',C.c_int32),('count',C.c_int32),
                ('reserved',C.c_uint32),('moduleHash',C.c_ubyte*32),('root',C.c_ubyte*32),('events',Event*128)]
k=C.WinDLL('kernel32',use_last_error=True)
def api(name, restype, *args):
    f=getattr(k,name); f.restype=restype; f.argtypes=args; return f
ptr=C.c_void_p; u64=C.c_uint64; size=C.c_size_t
OpenProcess=api('OpenProcess',ptr,W.DWORD,W.BOOL,W.DWORD)
CloseHandle=api('CloseHandle',W.BOOL,ptr)
CreateFileMapping=api('CreateFileMappingW',ptr,ptr,ptr,W.DWORD,W.DWORD,W.DWORD,W.LPCWSTR)
MapViewOfFile=api('MapViewOfFile',ptr,ptr,W.DWORD,W.DWORD,W.DWORD,size)
UnmapViewOfFile=api('UnmapViewOfFile',W.BOOL,ptr)
DuplicateHandle=api('DuplicateHandle',W.BOOL,ptr,ptr,ptr,C.POINTER(ptr),W.DWORD,W.BOOL,W.DWORD)
Current=api('GetCurrentProcess',ptr)
Ticks=api('GetTickCount64',u64)
Times=api('GetProcessTimes',W.BOOL,ptr,ptr,ptr,ptr,ptr)
Alloc=api('VirtualAllocEx',ptr,ptr,ptr,size,W.DWORD,W.DWORD)
Free=api('VirtualFreeEx',W.BOOL,ptr,ptr,size,W.DWORD)
Write=api('WriteProcessMemory',W.BOOL,ptr,ptr,ptr,size,ptr)
Thread=api('CreateRemoteThread',ptr,ptr,ptr,size,ptr,ptr,W.DWORD,ptr)
Wait=api('WaitForSingleObject',W.DWORD,ptr,W.DWORD)
Exit=api('GetExitCodeThread',W.BOOL,ptr,C.POINTER(W.DWORD))
Module=api('GetModuleHandleW',ptr,W.LPCWSTR)
Address=api('GetProcAddress',ptr,ptr,C.c_char_p)
EnumModules=C.WinDLL('psapi').EnumProcessModules
EnumModules.argtypes=[ptr,ptr,W.DWORD,C.POINTER(W.DWORD)]; EnumModules.restype=W.BOOL
ModuleName=C.WinDLL('psapi').GetModuleFileNameExW
ModuleName.argtypes=[ptr,ptr,W.LPWSTR,W.DWORD]; ModuleName.restype=W.DWORD

def check(x):
    if not x: raise C.WinError(C.get_last_error())
    return x

def network_process(browser):
    # Ownership is established from the exact root PID, never browser name alone.
    for child in psutil.Process(browser.pid).children(recursive=True):
        try:
            if any('--utility-sub-type=network.mojom.NetworkService' in a for a in child.cmdline()):
                return child.pid
        except (psutil.NoSuchProcess,psutil.AccessDenied): pass
    raise RuntimeError('Owned browser NetworkService process not found')

class Hook:
    def __init__(self,browser,dll,root,*,enabled=True,bad_hash=False):
        self.pid=network_process(browser)
        self.process=check(OpenProcess(0x1fffff,False,self.pid))
        self.mapping=check(CreateFileMapping(ptr(-1),None,4,0,C.sizeof(Control),None))
        self.view=check(MapViewOfFile(self.mapping,0xf001f,0,0,C.sizeof(Control)))
        self.c=Control.from_address(self.view)
        self.c.magic=0x51484b31; self.c.pid=self.pid
        birth=u64(); other=[u64() for _ in range(3)]
        check(Times(self.process,C.byref(birth),*[C.byref(v) for v in other]))
        self.c.birth=birth.value; self.c.deadline=Ticks()+180000; self.c.epoch=1; self.c.enabled=int(enabled)
        self.c.root[:]=bytes.fromhex(root)
        modules=self.modules()
        target=next(p for base,p in modules if Path(p).name.lower() in ('chrome.dll','msedge.dll'))
        digest=hashlib.sha256(Path(target).read_bytes()).digest()
        self.c.moduleHash[:]=bytes(32) if bad_hash else digest
        self.module={'path':target,'sha256':digest.hex(),'pid':self.pid,'birth':birth.value}
        remote_map=self.duplicate(self.mapping)
        # SYNCHRONIZE only: hook expires immediately if the controller dies.
        owned=check(OpenProcess(0x100000,False,psutil.Process().pid))
        remote_owner=self.duplicate(owned); CloseHandle(owned)
        load=Address(Module('kernel32.dll'),b'LoadLibraryW')
        self.remote(load,(str(dll.resolve())+'\0').encode('utf-16-le'))
        base=next((base for base,p in self.modules() if Path(p).name.lower()==dll.name.lower()),None)
        if not base: raise RuntimeError('Probe DLL not loaded (browser code integrity/sandbox may reject it)')
        pe=pefile.PE(str(dll),fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
        rva=next(s.address for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.name==b'InitializeProbe')
        handles=(u64*2)(remote_map,remote_owner)
        self.init_result=self.remote(base+rva,bytes(handles))
        if not bad_hash:
            assert self.c.initialized==1 and self.c.error==0,(self.init_result,self.c.error)

    def modules(self):
        bases=(ptr*2048)(); needed=W.DWORD()
        check(EnumModules(self.process,bases,C.sizeof(bases),C.byref(needed)))
        result=[]
        for base in list(bases)[:needed.value//C.sizeof(ptr)]:
            name=C.create_unicode_buffer(32768)
            if ModuleName(self.process,base,name,len(name)): result.append((base,name.value))
        return result
    def duplicate(self,handle):
        out=ptr(); check(DuplicateHandle(Current(),handle,self.process,C.byref(out),0,False,2)); return out.value
    def remote(self,address,data):
        memory=check(Alloc(self.process,None,len(data),0x3000,4))
        check(Write(self.process,memory,C.c_char_p(data),len(data),None))
        thread=check(Thread(self.process,None,0,address,memory,0,None))
        wait=Wait(thread,30000)
        if wait!=0: raise TimeoutError('Owned process remote call did not complete; stop the test profile')
        result=W.DWORD(); check(Exit(thread,C.byref(result)))
        CloseHandle(thread); Free(self.process,memory,0,0x8000)
        return result.value
    def stop(self):
        # Atomic aligned 32-bit stores on this x64-only test. Disabled first.
        self.c.enabled=0; self.c.epoch+=1
    def events(self):
        return [dict(input=e.input,output=e.output,status=e.status,flags=e.flags,port=e.port,
            chain_length=e.count,host=e.host.decode(errors='replace'),leaf=bytes(e.leaf).hex(),root=bytes(e.root).hex())
            for e in list(self.c.events)[:min(self.c.count,128)] if e.ready]
    def close(self):
        self.stop()
        del self.c
        UnmapViewOfFile(self.view); CloseHandle(self.mapping); CloseHandle(self.process)
