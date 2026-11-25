// Opt-in experiment only. The production Hook does not pre-create Shell objects.
// Install on the first real Shell objects, then test actual callback execution
// on later objects/apartments without discovery or repatching.
namespace SharedTableProbe {
struct Slot { void** address; void* original; void* callback; };
static Slot slots[12];
static unsigned count;
static volatile LONG calls, misses;
static const DISPID marker = -987654;
static const wchar_t fileMarker[] = L"ProxyLane.SharedTable.Probe";
static void* Original(void** address) {
    for (unsigned i=0;i<count;++i) if (slots[i].address == address) return slots[i].original;
    return NULL;
}
static HRESULT STDMETHODCALLTYPE Execute(IShellDispatch2* self, BSTR file, VARIANT a, VARIANT d, VARIANT v, VARIANT s) {
    if (file && !wcscmp(file, fileMarker)) { InterlockedIncrement(&calls); return E_ABORT; }
    auto original = reinterpret_cast<decltype(self->lpVtbl->ShellExecute)>(Original((void**)&self->lpVtbl->ShellExecute));
    return original ? original(self,file,a,d,v,s) : E_UNEXPECTED;
}
static HRESULT STDMETHODCALLTYPE Invoke(IDispatch* self, DISPID id, REFIID iid, LCID locale, WORD flags,
    DISPPARAMS* params, VARIANT* result, EXCEPINFO* exception, UINT* error) {
    if (id == marker) { InterlockedIncrement(&calls); return E_ABORT; }
    auto original = reinterpret_cast<decltype(self->lpVtbl->Invoke)>(Original((void**)&self->lpVtbl->Invoke));
    return original ? original(self,id,iid,locale,flags,params,result,exception,error) : E_UNEXPECTED;
}
static bool Swap(void** slot, void* expected, void* value) {
    DWORD protection, ignored;
    if (!VirtualProtect(slot,sizeof(void*),PAGE_READWRITE,&protection)) return false;
    bool ok = false;
    __try { ok = InterlockedCompareExchangePointer(slot,value,expected) == expected; }
    __except(EXCEPTION_EXECUTE_HANDLER) {}
    VirtualProtect(slot,sizeof(void*),protection,&ignored); return ok;
}
static bool Patch(void** slot, void* callback) {
    for (unsigned i=0;i<count;++i) if (slots[i].address == slot) return *slot == callback;
    if (count == _countof(slots)) return false;
    slots[count] = {slot,*slot,callback};
    if (!Swap(slot,slots[count].original,callback)) return false;
    ++count; return true;
}
static bool Install(IShellDispatch2* shell) {
    ComPtr<IDispatch> dispatch;
    if (FAILED(shell->lpVtbl->QueryInterface(shell,IID_IDispatch,(void**)&dispatch.p))) return false;
    return Patch((void**)&shell->lpVtbl->ShellExecute,(void*)Execute) &&
        Patch((void**)&shell->lpVtbl->Invoke,(void*)Invoke) && Patch((void**)&dispatch.p->lpVtbl->Invoke,(void*)Invoke);
}
static void Inspect(const char* label, IShellDispatch2* shell) {
    ComPtr<IDispatch> dispatch;
    HRESULT hr = shell->lpVtbl->QueryInterface(shell,IID_IDispatch,(void**)&dispatch.p);
    const bool execute = (void*)shell->lpVtbl->ShellExecute == (void*)Execute;
    const bool inherited = (void*)shell->lpVtbl->Invoke == (void*)Invoke;
    const bool queried = SUCCEEDED(hr) && (void*)dispatch.p->lpVtbl->Invoke == (void*)Invoke;
    printf("%s execute=%d inherited-invoke=%d queried-invoke=%d\n",label,execute,inherited,queried);
    // Never call a missing hook with a fictitious executable (could show UI).
    Variant file(fileMarker), empty; DISPPARAMS params = {};
    LONG before = calls, expected = 0;
    if (execute) { ++expected; shell->lpVtbl->ShellExecute(shell,file.v.bstrVal,empty.v,empty.v,empty.v,empty.v); }
    if (inherited) { ++expected; shell->lpVtbl->Invoke(shell,marker,IID_NULL,0,DISPATCH_METHOD,&params,NULL,NULL,NULL); }
    if (queried) { ++expected; dispatch.p->lpVtbl->Invoke(dispatch.p,marker,IID_NULL,0,DISPATCH_METHOD,&params,NULL,NULL,NULL); }
    if (calls-before != expected || expected != 3) InterlockedIncrement(&misses);
}
static void Sample(const char* label) {
    ComPtr<IShellDispatch2> remote, local;
    if (SUCCEEDED(ExplorerDispatch(&remote.p))) Inspect(label,remote.p); else InterlockedIncrement(&misses);
    if (SUCCEEDED(CoCreateInstance(CLSID_Shell,NULL,CLSCTX_INPROC_SERVER,IID_IShellDispatch2,(void**)&local.p)))
        Inspect(label,local.p); else InterlockedIncrement(&misses);
}
static DWORD WINAPI Worker(void* mode) {
    if (FAILED(CoInitializeEx(NULL,(DWORD)(ULONG_PTR)mode))) return 1;
    Sample((DWORD)(ULONG_PTR)mode == COINIT_MULTITHREADED ? "MTA" : "STA-worker");
    CoUninitialize(); return 0;
}
static bool PumpWait(HANDLE thread) {
    DWORD start=GetTickCount();
    while (GetTickCount()-start < 20000) {
        DWORD wait=MsgWaitForMultipleObjects(1,&thread,FALSE,20000-(GetTickCount()-start),QS_ALLINPUT);
        if (wait==WAIT_OBJECT_0) { DWORD code=1; GetExitCodeThread(thread,&code); return code==0; }
        if (wait!=WAIT_OBJECT_0+1) return false;
        MSG msg; while (PeekMessageW(&msg,NULL,0,0,PM_REMOVE)) { TranslateMessage(&msg); DispatchMessageW(&msg); }
    }
    return false;
}
static int Run() {
    // This disposable probe must not combine the product's patches with its own.
    HMODULE hook=GetModuleHandleW(sizeof(void*)==8?L"ProxyLaneHook64.dll":L"ProxyLaneHook32.dll");
    if (hook) {
        auto unhook=reinterpret_cast<BOOL(WINAPI*)()>(GetProcAddress(hook,"gp_UnhookWinsock"));
        if (!unhook || !unhook()) return 2;
    }
    if (FAILED(CoInitializeEx(NULL,COINIT_APARTMENTTHREADED))) return 3;
    {
        ComPtr<IShellDispatch2> remote,local;
        if (FAILED(ExplorerDispatch(&remote.p)) ||
            FAILED(CoCreateInstance(CLSID_Shell,NULL,CLSCTX_INPROC_SERVER,IID_IShellDispatch2,(void**)&local.p)) ||
            !Install(remote.p) || !Install(local.p)) return 4;
        Sample("same-STA");
        DWORD models[]={COINIT_APARTMENTTHREADED,COINIT_MULTITHREADED,COINIT_APARTMENTTHREADED};
        for (DWORD model:models) {
            HANDLE worker=CreateThread(NULL,0,Worker,(void*)(ULONG_PTR)model,0,NULL);
            if (!worker || !PumpWait(worker)) ExitProcess(5);
            CloseHandle(worker);
        }
    }
    CoUninitialize();
    if (FAILED(CoInitializeEx(NULL,COINIT_APARTMENTTHREADED))) return 6;
    Sample("release-and-reinitialize");
    for (unsigned i=0;i<count;++i) Swap(slots[i].address,slots[i].callback,slots[i].original);
    CoUninitialize();
    printf("Shared table experiment: callbacks=%ld misses=%ld (this OS only)\n",calls,misses);
    return misses ? 1 : 0;
}
}
