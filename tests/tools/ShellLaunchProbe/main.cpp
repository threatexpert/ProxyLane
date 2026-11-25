// Standalone experiment: no changes to Explorer or the product Hook DLL.
// C interface declarations expose the exact SDK vtable layout (no magic slot).
#define CINTERFACE
#ifndef _WIN32_IE
#define _WIN32_IE 0x0600
#endif
#include <windows.h>
#include <shlobj.h>
#include <shldisp.h>
#include <exdisp.h>
#include <shlguid.h>
#include <servprov.h>
#include <tlhelp32.h>
#include <detours.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <algorithm>

template<class T> struct ComPtr {
    T* p = NULL;
    ~ComPtr() { if (p) p->lpVtbl->Release(p); }
};
struct Variant {
    VARIANT v;
    Variant() { VariantInit(&v); }
    explicit Variant(const wchar_t* s) { VariantInit(&v); v.vt = VT_BSTR; v.bstrVal = SysAllocString(s); }
    explicit Variant(LONG n) { VariantInit(&v); v.vt = VT_I4; v.lVal = n; }
    ~Variant() { VariantClear(&v); }
};
struct Options {
#ifdef PROXYLANE_XP_PROBE
    std::wstring api = L"local", target, args, cwd, pl, output, profile = L"Test", verb = L"open";
#else
    std::wstring api = L"com", target = L"D:\\tools\\test.exe", args, cwd, pl, output, profile = L"Test", verb = L"open";
#endif
    bool invoke = false, waitExit = false, named = false, byref = false, dispatchView = false;
    int shellVersion = 2;
} options;
static unsigned rewrites;
static IShellDispatch2* watchedDispatch;
static decltype(IShellDispatch2Vtbl::ShellExecute) realDispatch;
static decltype(IShellDispatch2Vtbl::Invoke) realInvoke;
static DISPID shellExecuteId;
static decltype(&ShellExecuteExW) realShellExecuteExW = ShellExecuteExW;

static std::wstring Quote(const std::wstring& s)
{
    std::wstring out = L"\"";
    size_t slashes = 0;
    for (wchar_t c : s) {
        if (c == L'\\') { ++slashes; continue; }
        out.append(c == L'"' ? slashes * 2 + 1 : slashes, L'\\');
        out += c; slashes = 0;
    }
    out.append(slashes * 2, L'\\');
    return out + L"\"";
}

static std::wstring LauncherArguments(const wchar_t* target, const wchar_t* args, const wchar_t* cwd, const wchar_t* verb)
{
    std::wstring result = L"--auto --profile " + Quote(options.profile) + L" --run " + Quote(target);
    if (options.waitExit) result += L" --wait-exit";
    if (cwd && *cwd) result += L" --working-directory " + Quote(cwd);
    // The existing CLI can forward to an unelevated host. Preserve the target's
    // elevation request too. This is a probe, not a claim of one-prompt semantics.
    if (verb && !_wcsicmp(verb, L"runas")) result += L" --elevated";
    if (args && *args) result += L" -- " + std::wstring(args);
    return result;
}
static const wchar_t* Text(const VARIANT& v)
{
    return v.vt == VT_BSTR && v.bstrVal ? v.bstrVal : L"";
}
static bool Match(const wchar_t* file, const wchar_t* verb)
{
    return !options.pl.empty() && file && !_wcsicmp(file, options.target.c_str()) &&
        (!verb || !*verb || !_wcsicmp(verb, L"open") || !_wcsicmp(verb, L"runas"));
}
static void TraceRewrite(const wchar_t* source, const std::wstring& args)
{
    ++rewrites;
    wprintf(L"INTERCEPT %s: file=%s\n  -> %s %s\n", source, options.target.c_str(), options.pl.c_str(), args.c_str());
    fflush(stdout);
}

static HRESULT STDMETHODCALLTYPE RedirectDispatch(IShellDispatch2* self, BSTR file, VARIANT args,
    VARIANT directory, VARIANT operation, VARIANT show)
{
    if (self != watchedDispatch || !Match(file, Text(operation)))
        return realDispatch(self, file, args, directory, operation, show);
    if ((args.vt != VT_EMPTY && args.vt != VT_BSTR) || (directory.vt != VT_EMPTY && directory.vt != VT_BSTR))
        return E_INVALIDARG; // The experiment deliberately supports string arguments only.
    try {
        const std::wstring command = LauncherArguments(file, Text(args), Text(directory), Text(operation));
        Variant replacement(options.pl.c_str()), parameters(command.c_str());
        if (!replacement.v.bstrVal || !parameters.v.bstrVal) return E_OUTOFMEMORY;
        TraceRewrite(L"IShellDispatch2::ShellExecute", command);
        return realDispatch(self, replacement.v.bstrVal, parameters.v, directory, operation, show);
    } catch (...) { return E_OUTOFMEMORY; }
}

static HRESULT STDMETHODCALLTYPE RedirectInvoke(IShellDispatch2* self, DISPID id, REFIID iid, LCID locale,
    WORD flags, DISPPARAMS* params, VARIANT* result, EXCEPINFO* exception, UINT* argError)
{
    // This controlled caller supplies all five positional arguments, reversed
    // per IDispatch rules. Production code must also handle omitted/named/byref arguments.
    if (self != watchedDispatch || id != shellExecuteId || !params || params->cArgs != 5 ||
        params->cNamedArgs || !(flags & DISPATCH_METHOD) || params->rgvarg[4].vt != VT_BSTR ||
        !Match(Text(params->rgvarg[4]), Text(params->rgvarg[1])))
        return realInvoke(self, id, iid, locale, flags, params, result, exception, argError);
    for (unsigned i = 1; i <= 3; ++i)
        if (params->rgvarg[i].vt != VT_EMPTY && params->rgvarg[i].vt != VT_BSTR) return E_INVALIDARG;
    try {
        const std::wstring command = LauncherArguments(Text(params->rgvarg[4]), Text(params->rgvarg[3]),
            Text(params->rgvarg[2]), Text(params->rgvarg[1]));
        Variant replacement(options.pl.c_str()), parameters(command.c_str());
        if (!replacement.v.bstrVal || !parameters.v.bstrVal) return E_OUTOFMEMORY;
        VARIANTARG copied[5]; CopyMemory(copied, params->rgvarg, sizeof(copied));
        copied[4] = replacement.v; copied[3] = parameters.v;
        DISPPARAMS changed = *params; changed.rgvarg = copied;
        TraceRewrite(L"IDispatch::Invoke(ShellExecute)", command);
        return realInvoke(self, id, iid, locale, flags, &changed, result, exception, argError);
    } catch (...) { return E_OUTOFMEMORY; }
}

static BOOL WINAPI RedirectShell(SHELLEXECUTEINFOW* info)
{
    if (!info || info->cbSize != sizeof(*info) || !Match(info->lpFile, info->lpVerb))
        return realShellExecuteExW(info);
    // lpFile replacement is not enough when PIDLs or explicit classes select
    // the target. Refuse those forms in this probe, rather than pretend to support them.
    if (info->fMask & (SEE_MASK_INVOKEIDLIST | SEE_MASK_CLASSNAME | SEE_MASK_CLASSKEY)) {
        SetLastError(ERROR_NOT_SUPPORTED); return FALSE;
    }
    try {
        const std::wstring command = LauncherArguments(info->lpFile, info->lpParameters, info->lpDirectory, info->lpVerb);
        SHELLEXECUTEINFOW changed = *info;
        changed.lpFile = options.pl.c_str(); changed.lpParameters = command.c_str();
        TraceRewrite(L"ShellExecuteExW", command);
        const BOOL ok = realShellExecuteExW(&changed);
        const DWORD error = GetLastError();
        info->hInstApp = changed.hInstApp; info->hProcess = changed.hProcess;
        // hProcess now identifies the PL launcher. Deliberately visible in output;
        // this probe does NOT claim that WaitForExit/ExitCode target semantics survive.
        SetLastError(error); return ok;
    } catch (...) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
}

static HRESULT ExplorerDispatch(IShellDispatch2** output, std::vector<void*>* untouched = NULL, int creation = 0)
{
    ComPtr<IShellWindows> windows;
    HRESULT hr;
    if (creation == 1) {
        ComPtr<IClassFactory> factory;
        hr = CoGetClassObject(CLSID_ShellWindows, CLSCTX_LOCAL_SERVER, NULL, IID_IClassFactory, (void**)&factory.p);
        if (SUCCEEDED(hr)) hr = factory.p->lpVtbl->CreateInstance(factory.p, NULL, IID_IShellWindows, (void**)&windows.p);
    } else if (creation == 2) {
        MULTI_QI query = {&IID_IShellWindows, NULL, E_FAIL};
        hr = CoCreateInstanceEx(CLSID_ShellWindows, NULL, CLSCTX_LOCAL_SERVER, NULL, 1, &query);
        if (SUCCEEDED(hr)) { hr = query.hr; windows.p = reinterpret_cast<IShellWindows*>(query.pItf); }
    } else if (creation == 3) {
        ComPtr<IDispatch> dispatch;
        hr = CoCreateInstance(CLSID_ShellWindows, NULL, CLSCTX_LOCAL_SERVER, IID_IDispatch, (void**)&dispatch.p);
        if (SUCCEEDED(hr)) hr = dispatch.p->lpVtbl->QueryInterface(dispatch.p, IID_IShellWindows, (void**)&windows.p);
    } else hr = CoCreateInstance(CLSID_ShellWindows, NULL, CLSCTX_LOCAL_SERVER, IID_IShellWindows, (void**)&windows.p);
    if (FAILED(hr)) return hr;
    if (untouched) { untouched->push_back((void*)windows.p->lpVtbl->QueryInterface); untouched->push_back((void*)windows.p->lpVtbl->FindWindowSW); }
    Variant desktop((LONG)CSIDL_DESKTOP), empty;
    long hwnd = 0;
    ComPtr<IDispatch> found;
    hr = windows.p->lpVtbl->FindWindowSW(windows.p, &desktop.v, &empty.v, SWC_DESKTOP, &hwnd, SWFO_NEEDDISPATCH, &found.p);
    if (FAILED(hr) || !found.p) return FAILED(hr) ? hr : E_NOINTERFACE;
    if (untouched) untouched->push_back((void*)found.p->lpVtbl->QueryInterface);
    DWORD explorerPid = 0;
    GetWindowThreadProcessId((HWND)(LONG_PTR)hwnd, &explorerPid);
    wprintf(L"Desktop Explorer PID=%lu; caller PID=%lu; bits=%u\n", explorerPid, GetCurrentProcessId(), (unsigned)(sizeof(void*) * 8));
    ComPtr<IServiceProvider> provider;
    hr = found.p->lpVtbl->QueryInterface(found.p, IID_IServiceProvider, (void**)&provider.p);
    if (FAILED(hr)) return hr;
    if (untouched) { untouched->push_back((void*)provider.p->lpVtbl->QueryInterface); untouched->push_back((void*)provider.p->lpVtbl->QueryService); }
    ComPtr<IShellBrowser> browser;
    hr = provider.p->lpVtbl->QueryService(provider.p, SID_STopLevelBrowser, IID_IShellBrowser, (void**)&browser.p);
    if (FAILED(hr)) return hr;
    if (untouched) { untouched->push_back((void*)browser.p->lpVtbl->QueryInterface); untouched->push_back((void*)browser.p->lpVtbl->QueryActiveShellView); }
    ComPtr<IShellView> view;
    hr = browser.p->lpVtbl->QueryActiveShellView(browser.p, &view.p);
    if (FAILED(hr)) return hr;
    if (untouched) { untouched->push_back((void*)view.p->lpVtbl->QueryInterface); untouched->push_back((void*)view.p->lpVtbl->GetItemObject); }
    ComPtr<IDispatch> background;
    hr = view.p->lpVtbl->GetItemObject(view.p, SVGIO_BACKGROUND, IID_IDispatch, (void**)&background.p);
    if (FAILED(hr)) return hr;
    if (untouched) untouched->push_back((void*)background.p->lpVtbl->QueryInterface);
    ComPtr<IShellFolderViewDual> folder;
    hr = background.p->lpVtbl->QueryInterface(background.p, IID_IShellFolderViewDual, (void**)&folder.p);
    if (FAILED(hr)) return hr;
    if (untouched) { untouched->push_back((void*)folder.p->lpVtbl->QueryInterface); untouched->push_back((void*)folder.p->lpVtbl->get_Application); }
    ComPtr<IDispatch> application;
    hr = folder.p->lpVtbl->get_Application(folder.p, &application.p);
    if (FAILED(hr)) return hr;
    if (untouched) untouched->push_back((void*)application.p->lpVtbl->QueryInterface);
    return application.p->lpVtbl->QueryInterface(application.p, IID_IShellDispatch2, (void**)output);
}

#include "SharedTableProbe.h"

static DWORD ParentPid()
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W entry = {sizeof(entry)}; DWORD parent = 0;
    if (Process32FirstW(snapshot, &entry)) do {
        if (entry.th32ProcessID == GetCurrentProcessId()) { parent = entry.th32ParentProcessID; break; }
    } while (Process32NextW(snapshot, &entry));
    CloseHandle(snapshot); return parent;
}
static int Record(const wchar_t* path)
{
    wchar_t cwd[32768] = {}, image[32768] = {};
    GetCurrentDirectoryW(_countof(cwd), cwd); GetModuleFileNameW(NULL, image, _countof(image));
    FILE* file = NULL;
    if (_wfopen_s(&file, path, L"wt, ccs=UTF-8") || !file) return 1;
    fwprintf(file, L"pid=%lu\nparent=%lu\nhook=%u\nimage=%s\ncwd=%s\ncommand=%s\n",
        GetCurrentProcessId(), ParentPid(), GetModuleHandleW(sizeof(void*) == 8 ? L"ProxyLaneHook64.dll" : L"ProxyLaneHook32.dll") != NULL,
        image, cwd, GetCommandLineW());
    STARTUPINFOW startup = {sizeof(startup)}; GetStartupInfoW(&startup);
    fwprintf(file, L"startflags=%lu\nshow=%u\n", startup.dwFlags, startup.wShowWindow);
    fclose(file); return 0;
}

struct LifecycleContext { std::wstring directory; int thread, count; LONG failed; };
static DWORD WINAPI LifecycleThread(void* parameter)
{
    LifecycleContext& ctx = *static_cast<LifecycleContext*>(parameter);
    wchar_t image[32768] = {}; GetModuleFileNameW(NULL, image, _countof(image));
    for (int i = 0; i < ctx.count; ++i) {
        HRESULT hr = CoInitializeEx(NULL, ctx.thread ? COINIT_MULTITHREADED : COINIT_APARTMENTTHREADED);
        if (FAILED(hr)) { ctx.failed = 1; break; }
        {
            ComPtr<IShellDispatch2> dispatch;
            hr = ExplorerDispatch(&dispatch.p);
            if (SUCCEEDED(hr)) {
                std::wstring report = ctx.directory + L"\\life-" + std::to_wstring(ctx.thread) + L"-" + std::to_wstring(i) + L".txt";
                Variant file(image), args((L"--record " + Quote(report)).c_str()), empty, verb(L"open"), show((LONG)SW_HIDE);
                hr = dispatch.p->lpVtbl->ShellExecute(dispatch.p, file.v.bstrVal, args.v, empty.v, verb.v, show.v);
            }
        }
        CoUninitialize();
        if (FAILED(hr)) { ctx.failed = 1; break; }
    }
    return 0;
}
static int Lifecycle(const wchar_t* directory, int count)
{
    if (count < 1 || count > 30) return 2;
    LifecycleContext contexts[2] = {{directory, 0, count, 0}, {directory, 1, count, 0}};
    HANDLE threads[2] = {};
    for (int i=0;i<2;++i) threads[i] = CreateThread(NULL, 0, LifecycleThread, &contexts[i], 0, NULL);
    for (int i=0;i<2;++i) { if (!threads[i]) return 3; WaitForSingleObject(threads[i], INFINITE); CloseHandle(threads[i]); }
    if (contexts[0].failed || contexts[1].failed) return 4;
    // All test callers and apartments are quiescent before explicit removal.
    HMODULE hook = GetModuleHandleW(sizeof(void*) == 8 ? L"ProxyLaneHook64.dll" : L"ProxyLaneHook32.dll");
    typedef BOOL(WINAPI* Unhook)();
    Unhook unhook = hook ? reinterpret_cast<Unhook>(GetProcAddress(hook, "gp_UnhookWinsock")) : NULL;
    if (!unhook || !unhook()) return 5;
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    HRESULT hr;
    {
        ComPtr<IShellDispatch2> dispatch; hr = ExplorerDispatch(&dispatch.p);
        if (SUCCEEDED(hr)) {
            wchar_t image[32768] = {}; GetModuleFileNameW(NULL, image, _countof(image));
            Variant args((L"--record " + Quote(std::wstring(directory) + L"\\after-unhook.txt")).c_str()), empty, show((LONG)SW_HIDE);
            Variant file(image);
            hr = dispatch.p->lpVtbl->ShellExecute(dispatch.p, file.v.bstrVal, args.v, empty.v, empty.v, show.v);
        }
    }
    if (SUCCEEDED(hr)) {
        HMODULE storage = GetModuleHandleW(L"Windows.Storage.dll");
        auto execute = storage ? reinterpret_cast<decltype(realShellExecuteExW)>(GetProcAddress(storage, "ShellExecuteExW")) : NULL;
        if (execute) {
            wchar_t image[32768] = {}; GetModuleFileNameW(NULL, image, _countof(image));
            const std::wstring args = L"--record " + Quote(std::wstring(directory) + L"\\storage-after-unhook.txt");
            SHELLEXECUTEINFOW info = {sizeof(info)};
            info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
            info.lpFile = image; info.lpParameters = args.c_str(); info.nShow = SW_HIDE;
            if (!execute(&info)) hr = HRESULT_FROM_WIN32(GetLastError());
            if (info.hProcess) { WaitForSingleObject(info.hProcess, 10000); CloseHandle(info.hProcess); }
        }
    }
    CoUninitialize(); return FAILED(hr) ? 6 : 0;
}

static HRESULT STDMETHODCALLTYPE MissingDesktop(IShellWindows*, VARIANT*, VARIANT*, int, long*, int, IDispatch** output)
{
    if (output) *output = NULL;
    return E_ACCESSDENIED;
}
static int AuditActiveDiscovery(const wchar_t* dll, const wchar_t* pipe)
{
    if (FAILED(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED))) return 1;
    int result = [&]() -> int {
        ComPtr<IShellDispatch2> before, after, again;
        ComPtr<IShellWindows> windows;
        std::vector<void*> original, current;
        if (FAILED(ExplorerDispatch(&before.p, &original))) return 2;
        if (FAILED(CoCreateInstance(CLSID_ShellWindows,NULL,CLSCTX_LOCAL_SERVER,IID_IShellWindows,(void**)&windows.p))) return 3;
        const auto execute = before.p->lpVtbl->ShellExecute;
        const auto invoke = before.p->lpVtbl->Invoke;
        HMODULE module = LoadLibraryW(dll);
        auto enable = module ? reinterpret_cast<BOOL(WINAPI*)(LPCSTR)>(GetProcAddress(module,"gp_HookWinsock")) : NULL;
        auto disable = module ? reinterpret_cast<BOOL(WINAPI*)()>(GetProcAddress(module,"gp_UnhookWinsock")) : NULL;
        char pipeName[MAX_PATH] = {};
        WideCharToMultiByte(CP_ACP,0,pipe,-1,pipeName,sizeof(pipeName),NULL,NULL);
        if (!enable || !disable || !enable(pipeName)) return 4;
        // Hook initialization must not discover/patch a Shell object on its own.
        if (before.p->lpVtbl->ShellExecute != execute || before.p->lpVtbl->Invoke != invoke) return 5;
        void** getter = (void**)&windows.p->lpVtbl->FindWindowSW;
        void* find = *getter;
        if (!SharedTableProbe::Swap(getter,find,(void*)MissingDesktop)) return 6;
        IShellWindows* failed = NULL;
        HRESULT hr = CoCreateInstance(CLSID_ShellWindows,NULL,CLSCTX_LOCAL_SERVER,IID_IShellWindows,(void**)&failed);
        if (!SharedTableProbe::Swap(getter,(void*)MissingDesktop,find)) return 7;
        if (hr != E_ACCESSDENIED || failed) { if (failed) failed->lpVtbl->Release(failed); return 8; }
        if (FAILED(ExplorerDispatch(&after.p,&current))) return 9;
        if (original != current) return 10;
        const auto hooked = after.p->lpVtbl->ShellExecute;
        if (hooked == execute || after.p->lpVtbl->Invoke == invoke) return 11;
        // Simulate a slot losing its patch, without freeing any live COM object.
        if (!SharedTableProbe::Swap((void**)&after.p->lpVtbl->ShellExecute,(void*)hooked,(void*)execute)) return 12;
        if (FAILED(ExplorerDispatch(&again.p)) || again.p->lpVtbl->ShellExecute != hooked) return 13;
        if (!disable() || again.p->lpVtbl->ShellExecute != execute || again.p->lpVtbl->Invoke != invoke) return 14;
        printf("PASS active discovery: no eager initialization, intermediate slots unchanged, failure returned, slot repaired, unhook restored\n");
        return 0;
    }();
    CoUninitialize();
    return result;
}

static int InjectChild(const wchar_t* dll, const wchar_t* pipe, const wchar_t* target, const wchar_t* args, bool denyWrite)
{
    HMODULE hook = LoadLibraryW(dll);
    typedef BOOL(WINAPI* Inject)(const PROCESS_INFORMATION*, LPCWSTR, LPCWSTR, LPCSTR);
    Inject inject = hook ? reinterpret_cast<Inject>(GetProcAddress(hook, "gp_InjectAndResumeShellChild")) : NULL;
    if (!inject) return 90;
    char pipeName[MAX_PATH] = {};
    if (!WideCharToMultiByte(CP_ACP, 0, pipe, -1, pipeName, sizeof(pipeName), NULL, NULL)) return 91;
    std::wstring command = Quote(target) + L" " + args;
    STARTUPINFOW startup = {sizeof(startup)}; PROCESS_INFORMATION child = {};
    if (!CreateProcessW(target, &command[0], NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startup, &child)) return 92;
    PROCESS_INFORMATION input = child;
    if (denyWrite && !DuplicateHandle(GetCurrentProcess(), child.hProcess, GetCurrentProcess(), &input.hProcess,
        PROCESS_QUERY_INFORMATION | SYNCHRONIZE, FALSE, 0)) {
        TerminateProcess(child.hProcess, 96); CloseHandle(child.hThread); CloseHandle(child.hProcess); return 96;
    }
    const BOOL ok = inject(&input, target, command.c_str(), pipeName);
    const DWORD error = GetLastError();
    if (denyWrite) CloseHandle(input.hProcess);
    if (!ok) {
        // A failed preparation must not have released the original suspension.
        const DWORD previous = SuspendThread(child.hThread);
        TerminateProcess(child.hProcess, 93);
        WaitForSingleObject(child.hProcess, 5000);
        CloseHandle(child.hThread); CloseHandle(child.hProcess);
        printf("inject failed error=%lu suspension=%lu\n", error, previous);
        return previous == 1 ? 1 : 94;
    }
    CloseHandle(child.hThread);
    DWORD code = 95;
    if (WaitForSingleObject(child.hProcess, 45000) == WAIT_OBJECT_0) GetExitCodeProcess(child.hProcess, &code);
    else TerminateProcess(child.hProcess, 95);
    CloseHandle(child.hProcess);
    printf("inject prepared; target exit=%lu\n", code);
    return static_cast<int>(code);
}

static int Benchmark(const wchar_t* output)
{
    FILE* log = NULL;
    if (_wfopen_s(&log, output, L"wt") || FAILED(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED))) return 1;
    LARGE_INTEGER frequency; QueryPerformanceFrequency(&frequency);
    for (int kind=0;kind<3;++kind) {
        std::vector<double> samples;
        for (int i=0;i<110;++i) {
            LARGE_INTEGER begin,end; QueryPerformanceCounter(&begin);
            IUnknown* object = NULL;
            HRESULT hr = kind==2 ? ExplorerDispatch((IShellDispatch2**)&object) :
                CoCreateInstance(kind==0?CLSID_ShellLink:CLSID_Shell,NULL,CLSCTX_INPROC_SERVER,
                    kind==0?IID_IShellLinkW:IID_IShellDispatch2,(void**)&object);
            if (object) object->lpVtbl->Release(object);
            QueryPerformanceCounter(&end);
            if (FAILED(hr)) { fclose(log); CoUninitialize(); return 2; }
            if (i>=10) samples.push_back(1e6*(end.QuadPart-begin.QuadPart)/frequency.QuadPart);
        }
        std::sort(samples.begin(),samples.end());
        fprintf(log,"%s median_us=%.2f p95_us=%.2f\n",kind==0?"unrelated-ShellLink":kind==1?"local-Shell":"Explorer-chain",samples[50],samples[94]);
    }
    fclose(log); CoUninitialize(); return 0;
}

int wmain(int argc, wchar_t** argv)
{
    if (argc == 4 && !wcscmp(argv[1], L"--audit-active")) return AuditActiveDiscovery(argv[2], argv[3]);
    if (argc == 3 && !wcscmp(argv[1], L"--com-benchmark")) return Benchmark(argv[2]);
    if (argc == 2 && !wcscmp(argv[1], L"--shared-tables")) return SharedTableProbe::Run();
    if (argc == 6 && (!wcscmp(argv[1], L"--inject-child") || !wcscmp(argv[1], L"--inject-child-deny-write")))
        return InjectChild(argv[2], argv[3], argv[4], argv[5], !wcscmp(argv[1], L"--inject-child-deny-write"));
    if (argc == 4 && !wcscmp(argv[1], L"--com-lifecycle")) return Lifecycle(argv[2], _wtoi(argv[3]));
    if (argc >= 3 && !wcscmp(argv[1], L"--record")) return Record(argv[2]);
    if (argc == 5 && !wcscmp(argv[1], L"--wait-child")) {
        HANDLE release = OpenEventW(SYNCHRONIZE, FALSE, argv[3]);
        if (!release || Record(argv[2])) return 100;
        const DWORD waited = WaitForSingleObject(release, 60000);
        CloseHandle(release);
        ExitProcess(waited == WAIT_OBJECT_0 ? wcstoul(argv[4], NULL, 0) : 101);
    }
    for (int i = 1; i < argc; ++i) {
        const std::wstring key = argv[i];
        if (key == L"--invoke") { options.invoke = true; continue; }
        if (key == L"--dispatch-view") { options.invoke = options.dispatchView = true; continue; }
        if (key == L"--named") { options.invoke = options.named = true; continue; }
        if (key == L"--byref") { options.invoke = options.byref = true; continue; }
        if (key == L"--wait-exit") { options.waitExit = true; continue; }
        if (key == L"--help") {
#ifdef PROXYLANE_XP_PROBE
            puts("XP SP3 x86 probe: default is CLSID_Shell -> system notepad.exe.\n"
                 "  --api local [--invoke] : direct Shell.Application\n"
                 "  --api shell           : ShellExecuteExW\n"
                 "  --target path --args raw --output log\n"
                 "Run through ProxyLane to test interception.\n"
                 "The --api com desktop Explorer path requires Vista or later.");
#else
            puts("ShellLaunchProbe [--api com|shell|storage] [--target path] [--args raw] [--cwd directory]\n"
                 "  [--redirect ProxyLane64.exe --profile name] [--verb open|runas] [--invoke] [--wait-exit]\n"
                 "Default: Explorer COM launch of D:\\tools\\test.exe. --invoke tests IDispatch.\n"
                 "Experimental redirects change handle/exit/error semantics; see README.md.");
#endif
            return 0;
        }
        if (i + 1 >= argc) return 2;
        const std::wstring value = argv[++i];
        if (key == L"--api") options.api = value;
        else if (key == L"--target") options.target = value;
        else if (key == L"--args") options.args = value;
        else if (key == L"--cwd") options.cwd = value;
        else if (key == L"--redirect") options.pl = value;
        else if (key == L"--profile") options.profile = value;
        else if (key == L"--verb") options.verb = value;
        else if (key == L"--output") options.output = value;
        else if (key == L"--shell-version") options.shellVersion = _wtoi(value.c_str());
        else return 2;
    }
#ifdef PROXYLANE_XP_PROBE
    if (options.target.empty()) {
        wchar_t system[MAX_PATH] = {};
        UINT length = GetSystemDirectoryW(system, _countof(system));
        if (!length || length >= _countof(system)) return 2;
        options.target = std::wstring(system) + L"\\notepad.exe";
    }
#endif
    if ((options.api != L"com" && options.api != L"com-factory" && options.api != L"com-extended" && options.api != L"com-dispatch" && options.api != L"local" && options.api != L"factory" && options.api != L"extended" && options.api != L"shell" && options.api != L"storage") || (options.verb != L"open" && options.verb != L"runas")) return 2;
    if (!options.output.empty()) { FILE* stream = NULL; if (_wfreopen_s(&stream, options.output.c_str(), L"w", stdout)) return 2; }
    printf("Caller hook=%u\n", GetModuleHandleW(sizeof(void*) == 8 ? L"ProxyLaneHook64.dll" : L"ProxyLaneHook32.dll") != NULL);
    fflush(stdout);
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) { printf("CoInitializeEx: 0x%08lX\n", hr); return 1; }
    int exitCode = 0;
    {
        if (options.api != L"shell" && options.api != L"storage") {
            ComPtr<IShellDispatch2> dispatch;
            if (options.api == L"com" || options.api == L"com-factory" || options.api == L"com-extended" || options.api == L"com-dispatch")
                hr = ExplorerDispatch(&dispatch.p, NULL, options.api == L"com-factory" ? 1 : options.api == L"com-extended" ? 2 : options.api == L"com-dispatch" ? 3 : 0);
            else if (options.api == L"local") {
                ComPtr<IUnknown> view;
                const IID& iid = options.shellVersion == 1 ? IID_IShellDispatch : options.shellVersion == 5 ? IID_IShellDispatch5 : IID_IShellDispatch2;
                hr = CoCreateInstance(CLSID_Shell, NULL, CLSCTX_INPROC_SERVER, iid, (void**)&view.p);
                if (SUCCEEDED(hr)) hr = view.p->lpVtbl->QueryInterface(view.p, IID_IShellDispatch2, (void**)&dispatch.p);
            }
            else if (options.api == L"factory") {
                ComPtr<IClassFactory> factory;
                hr = CoGetClassObject(CLSID_Shell, CLSCTX_INPROC_SERVER, NULL, IID_IClassFactory, (void**)&factory.p);
                if (SUCCEEDED(hr)) hr = factory.p->lpVtbl->CreateInstance(factory.p, NULL, IID_IShellDispatch2, (void**)&dispatch.p);
            } else {
                MULTI_QI query = {&IID_IShellDispatch2, NULL, E_FAIL};
                hr = CoCreateInstanceEx(CLSID_Shell, NULL, CLSCTX_INPROC_SERVER, NULL, 1, &query);
                if (SUCCEEDED(hr)) { hr = query.hr; dispatch.p = reinterpret_cast<IShellDispatch2*>(query.pItf); }
            }
            if (SUCCEEDED(hr)) {
                wchar_t method[] = L"ShellExecute"; LPOLESTR name = method;
                hr = dispatch.p->lpVtbl->GetIDsOfNames(dispatch.p, IID_NULL, &name, 1, LOCALE_USER_DEFAULT, &shellExecuteId);
                if (SUCCEEDED(hr)) {
                    // Keep the proxy vtable intact: stubless COM marshalling reads
                    // metadata BEFORE that table. A bare vtable clone crashes.
                    // Hook only the local entry point; filter by this exact pointer.
                    watchedDispatch = dispatch.p;
                    realDispatch = dispatch.p->lpVtbl->ShellExecute;
                    realInvoke = dispatch.p->lpVtbl->Invoke;
                    if (!options.pl.empty()) {
                        LONG error = DetourTransactionBegin();
                        if (!error) error = DetourUpdateThread(GetCurrentThread());
                        if (!error) error = options.invoke
                            ? DetourAttach((PVOID*)&realInvoke, (PVOID)RedirectInvoke)
                            : DetourAttach((PVOID*)&realDispatch, (PVOID)RedirectDispatch);
                        if (!error) error = DetourTransactionCommit(); else DetourTransactionAbort();
                        if (error) { printf("COM detour attach error=%ld\n", error); hr = HRESULT_FROM_WIN32(error); }
                    }
                    Variant file(options.target.c_str()), args(options.args.c_str()), directory(options.cwd.c_str()),
                        operation(options.verb.c_str()), show((LONG)SW_SHOWNORMAL), result;
                    if (SUCCEEDED(hr) && options.invoke) {
                        VARIANTARG values[] = {show.v, operation.v, directory.v, args.v, file.v};
                        VARIANTARG references[5] = {};
                        if (options.byref) for (unsigned i=0;i<5;++i) { references[i].vt = VT_VARIANT | VT_BYREF; references[i].pvarVal = &values[i]; }
                        DISPPARAMS parameters = {values, NULL, _countof(values), 0};
                        if (options.byref) parameters.rgvarg = references;
                        wchar_t f[] = L"File", a[] = L"vArgs", d[] = L"vDir", o[] = L"vOperation", s[] = L"vShow";
                        LPOLESTR names[] = {method, s, o, d, a, f}; DISPID ids[6] = {};
                        if (options.named) {
                            hr = dispatch.p->lpVtbl->GetIDsOfNames(dispatch.p, IID_NULL, names, 6, LOCALE_USER_DEFAULT, ids);
                            parameters.rgdispidNamedArgs = ids + 1; parameters.cNamedArgs = 5;
                        }
                        if (SUCCEEDED(hr) && options.dispatchView) {
                            ComPtr<IDispatch> view;
                            hr = dispatch.p->lpVtbl->QueryInterface(dispatch.p, IID_IDispatch, (void**)&view.p);
                            if (SUCCEEDED(hr)) hr = view.p->lpVtbl->Invoke(view.p, shellExecuteId, IID_NULL, LOCALE_USER_DEFAULT,
                                DISPATCH_METHOD, &parameters, &result.v, NULL, NULL);
                        } else if (SUCCEEDED(hr)) hr = dispatch.p->lpVtbl->Invoke(dispatch.p, shellExecuteId, IID_NULL, LOCALE_USER_DEFAULT,
                                DISPATCH_METHOD, &parameters, &result.v, NULL, NULL);
                    } else if (SUCCEEDED(hr)) hr = dispatch.p->lpVtbl->ShellExecute(dispatch.p, file.v.bstrVal, args.v, directory.v, operation.v, show.v);
                    // Leave the hook in this short-lived, single-caller experiment
                    // until process exit. No live target pointer remains after this.
                    watchedDispatch = NULL;
                }
            }
            printf("COM result=0x%08lX; rewrites=%u (acceptance, not proof of target injection)\n", hr, rewrites);
            exitCode = FAILED(hr) ? 1 : 0;
        } else {
            if (options.api == L"storage") {
                wchar_t system[MAX_PATH] = {};
                if (!GetSystemDirectoryW(system, _countof(system))) return 2;
                const std::wstring path = std::wstring(system) + L"\\Windows.Storage.dll";
                HMODULE module = LoadLibraryW(path.c_str());
                realShellExecuteExW = module ? reinterpret_cast<decltype(realShellExecuteExW)>(GetProcAddress(module, "ShellExecuteExW")) : NULL;
                if (!realShellExecuteExW) { puts("SKIP: Windows.Storage ShellExecuteExW unavailable"); CoUninitialize(); return 77; }
            }
            if (!options.pl.empty()) {
                LONG error = DetourTransactionBegin();
                if (!error) error = DetourUpdateThread(GetCurrentThread());
                if (!error) error = DetourAttach((PVOID*)&realShellExecuteExW, (PVOID)RedirectShell);
                if (!error) error = DetourTransactionCommit(); else DetourTransactionAbort();
                if (error) { printf("Detour attach error=%ld\n", error); CoUninitialize(); return 1; }
            }
            SHELLEXECUTEINFOW info = {sizeof(info)};
            info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
            info.lpVerb = options.verb.c_str(); info.lpFile = options.target.c_str();
            info.lpParameters = options.args.c_str(); info.lpDirectory = options.cwd.empty() ? NULL : options.cwd.c_str();
            info.nShow = SW_SHOWNORMAL;
            // The Storage entry models callers that bypass shell32's export.
            // In the experimental mode its trampoline must still enter the detour.
            const BOOL ok = options.api == L"storage" ?
                reinterpret_cast<decltype(realShellExecuteExW)>(GetProcAddress(GetModuleHandleW(L"Windows.Storage.dll"), "ShellExecuteExW"))(&info) : ShellExecuteExW(&info);
            const DWORD error = ok ? 0 : GetLastError();
            const DWORD pid = info.hProcess ? GetProcessId(info.hProcess) : 0;
            printf("Shell result=%d error=%lu hProcessPID=%lu rewrites=%u%s\n", ok, error, pid, rewrites,
                options.pl.empty() ? "" : " (handle belongs to PL launcher, NOT the target)");
            exitCode = ok ? 0 : 1;
            if (info.hProcess) {
                if (options.waitExit) {
                    DWORD code = 1;
                    if (WaitForSingleObject(info.hProcess, 60000) == WAIT_OBJECT_0)
                        GetExitCodeProcess(info.hProcess, &code);
                    printf("Shell waited exitCode=%lu\n", code);
                    exitCode = static_cast<int>(code);
                }
                CloseHandle(info.hProcess);
            }
            // Probe lifetime is short. Keep the detour/state until process exit;
            // do not attempt concurrent proxy/API teardown while COM is active.
        }
    }
    CoUninitialize();
    return exitCode;
}
