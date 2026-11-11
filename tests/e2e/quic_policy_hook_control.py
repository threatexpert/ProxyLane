"""Single-Hook controller. QUIC policy is independent and disabled by default."""
import ctypes as C
from pathlib import Path
import sys
import quic_hook_control as old
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'quic-mitm'))
from locate_policy_hook import locate

LABEL = '解密 QUIC（实验性）'
DESCRIPTION = 'Chromium 内核浏览器可能拒绝 QUIC 使用已受信任的本地或企业 CA。开启后将尝试放宽此限制，以支持 QUIC 解密，仍保留正常证书校验。'

class Event(C.Structure):
    _fields_=[(n,C.c_int32) for n in ('ready','enabled','original','allowed','caller_matched')]
class Control(C.Structure):
    _fields_=[('magic',C.c_uint32),('pid',C.c_uint32),('birth',C.c_uint64),('deadline',C.c_uint64),
        *[(n,C.c_int32) for n in ('enabled','epoch','initialized','error','count')],
        *[(n,C.c_uint32) for n in ('complete_rva','complete_size','allow_rva','allow_size','caller_return_rva')],
        ('module_hash',C.c_ubyte*32),('complete_hash',C.c_ubyte*32),('allow_hash',C.c_ubyte*32),('events',Event*128)]

class Hook(old.Hook):
    def __init__(self,browser,dll,*,quic_decryption=False,bad_hash=False,bad_code=False):
        self.pid=old.network_process(browser)
        self.process=old.check(old.OpenProcess(0x1fffff,False,self.pid))
        self.mapping=self.view=None
        try:
            target=next(p for _,p in self.modules() if Path(p).name.lower() in ('chrome.dll','msedge.dll'))
            self.descriptor=locate_cached(target)
            self.mapping=old.check(old.CreateFileMapping(old.ptr(-1),None,4,0,C.sizeof(Control),None))
            self.view=old.check(old.MapViewOfFile(self.mapping,0xf001f,0,0,C.sizeof(Control)))
            self.c=Control.from_address(self.view)
            self.c.magic=0x51504f31;self.c.pid=self.pid
            birth=old.u64();other=[old.u64() for _ in range(3)]
            old.check(old.Times(self.process,C.byref(birth),*[C.byref(v) for v in other]))
            self.c.birth=birth.value;self.c.deadline=old.Ticks()+180000;self.c.epoch=1
            for key in ('complete_rva','complete_size','allow_rva','allow_size','caller_return_rva'):
                setattr(self.c,key,self.descriptor[key])
            for key in ('module_hash','complete_hash','allow_hash'):
                getattr(self.c,key)[:]=bytes.fromhex(self.descriptor[key])
            if bad_hash:self.c.module_hash[:]=bytes(32)
            if bad_code:self.c.allow_hash[:]=bytes(32)
            self.module=dict(path=target,sha256=self.descriptor['module_hash'],pid=self.pid,birth=birth.value)
            remote_map=self.duplicate(self.mapping)
            owner=old.check(old.OpenProcess(0x100000,False,old.psutil.Process().pid))
            try:remote_owner=self.duplicate(owner)
            finally:old.CloseHandle(owner)
            self.remote(old.Address(old.Module('kernel32.dll'),b'LoadLibraryW'),(str(dll.resolve())+'\0').encode('utf-16-le'))
            base=next((b for b,p in self.modules() if Path(p).name.lower()==dll.name.lower()),None)
            if not base:raise RuntimeError('Policy DLL not loaded')
            pe=old.pefile.PE(str(dll),fast_load=True)
            pe.parse_data_directories(directories=[old.pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
            rva=next(s.address for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.name==b'InitializeProbe')
            self.init_result=self.remote(base+rva,bytes((old.u64*2)(remote_map,remote_owner)))
            if not (bad_hash or bad_code):
                assert self.c.initialized==1 and self.c.error==0,(self.init_result,self.c.error)
                if quic_decryption:self.set_enabled(True)
        except BaseException:
            if self.view:self.close()
            else:
                if self.mapping:old.CloseHandle(self.mapping)
                old.CloseHandle(self.process)
            raise
    def set_enabled(self,value):
        if type(value) is not bool:raise ValueError('quic_decryption must be boolean')
        if value:
            assert self.c.initialized==1
            self.c.deadline=old.Ticks()+180000
            self.c.enabled=1
        else:self.stop()
    def events(self):
        return [{k:int(getattr(e,k)) for k in ('enabled','original','allowed','caller_matched')}
                for e in list(self.c.events)[:max(0,min(self.c.count,128))] if e.ready]

_cache={}
def locate_cached(path):
    # Cache analysis in the controller only. The DLL checks full file and live
    # function digests each installation, including after a browser replacement.
    stat=Path(path).stat();key=(str(path),stat.st_size,stat.st_mtime_ns)
    if key not in _cache:_cache[key]=locate(path)
    return _cache[key]
