// Do not use the ATL PCH: the SDK's C declarations supply typed vtable slots.
#define CINTERFACE
#ifndef _WIN32_IE
#define _WIN32_IE 0x0600 // The XP SDK's Win7 library helpers assume C++ COM interfaces.
#endif
#include "ShellLaunchHooks.h"
#include <shellapi.h>
#include <shlobj.h>
#include <shldisp.h>
#include <exdisp.h>
#include <shlguid.h>
#include <servprov.h>
#include <shlwapi.h>
#include <detours.h>
#include <new>
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "uuid.lib")
#pragma comment(lib, "shlwapi.lib")

namespace ShellLaunchHooks
{
namespace
{
    BuildCommand buildCommand;
    ReportFailure reportFailure;
    DWORD guardTls = TLS_OUT_OF_INDEXES;
    CRITICAL_SECTION lock;
    bool initialized;
    struct Slot { void** address; void* original; void* replacement; };
    // No COM objects/apartment references are retained. RPC vtables may disappear
    // at CoUninitialize, so all table reads/restores below tolerate unmapped memory.
    Slot slots[512];
    size_t slotCount;
    decltype(&ShellExecuteExW) realShell;
    decltype(&ShellExecuteExW) realStorageShell;
    decltype(&CoCreateInstance) realCreate;
    decltype(&CoCreateInstanceEx) realCreateEx;
    decltype(&CoGetClassObject) realClass;

    struct Guard {
        bool entered;
        Guard() : entered(guardTls != TLS_OUT_OF_INDEXES && !TlsGetValue(guardTls) &&
            TlsSetValue(guardTls, reinterpret_cast<void*>(1))) {}
        ~Guard() { if (entered) TlsSetValue(guardTls, NULL); }
    };
    struct Lock {
        Lock() { EnterCriticalSection(&lock); }
        ~Lock() { LeaveCriticalSection(&lock); }
    };
    template<class F> HRESULT CallCom(F call) {
        // COM creation and Shell getters can internally unmarshal/query objects
        // before their outer operation has finished. Discover only after that
        // operation returns, not while it still owns COM's internal locks.
        Guard guard;
        return call();
    }
    // Keep SEH in trivial functions, separate from C++ destructors.
    bool ReadSlot(void** address, void*& value) {
        __try { value = *address; return true; }
        __except(EXCEPTION_EXECUTE_HANDLER) { return false; }
    }
    bool SwapSlot(void** address, void* expected, void* replacement) {
        DWORD protection, ignored;
        if (!VirtualProtect(address, sizeof(void*), PAGE_READWRITE, &protection)) return false;
        bool changed = false;
        __try { changed = InterlockedCompareExchangePointer(address, replacement, expected) == expected; }
        __except(EXCEPTION_EXECUTE_HANDLER) {}
        VirtualProtect(address, sizeof(void*), protection, &ignored);
        return changed;
    }
    HRESULT Patch(void** address, void* replacement) {
        Lock held;
        void* current = NULL;
        if (!ReadSlot(address, current) || !current) return E_POINTER;
        size_t i = 0;
        for (; i < slotCount; ++i) if (slots[i].address == address) break;
        if (current == replacement) return i < slotCount && slots[i].replacement == replacement ? S_OK : E_UNEXPECTED;
        if (i == _countof(slots)) return E_OUTOFMEMORY;
        const Slot previous = slots[i];
        slots[i] = { address, current, replacement };
        // Publish the original BEFORE publishing the callback. Atomic slot writes
        // preserve the stubless RPC metadata preceding the table and never patch
        // shared Ndr entry code used by methods with other calling conventions.
        if (SwapSlot(address, current, replacement)) { if (i == slotCount) ++slotCount; return S_OK; }
        slots[i] = previous; return E_FAIL;
    }
    template<class F> F Original(F* address) {
        Lock held;
        for (size_t i = 0; i < slotCount; ++i)
            if (slots[i].address == reinterpret_cast<void**>(address)) return reinterpret_cast<F>(slots[i].original);
        return NULL;
    }
    template<class F> HRESULT PatchMethod(F* address, F callback) { return Patch(reinterpret_cast<void**>(address), reinterpret_cast<void*>(callback)); }
    template<class T> struct ComPtr {
        T* p;
        ComPtr() : p(NULL) {}
        ~ComPtr() { if (p) p->lpVtbl->Release(p); }
        HRESULT Query(IUnknown* object, REFIID iid) {
            if (!object) return E_POINTER;
            HRESULT hr = object->lpVtbl->QueryInterface(object, iid, reinterpret_cast<void**>(&p));
            return SUCCEEDED(hr) && !p ? E_NOINTERFACE : hr;
        }
    private:
        ComPtr(const ComPtr&);
        ComPtr& operator=(const ComPtr&);
    };
    enum Discovery { AnyShell, ShellRoot, WindowsRoot, ClassFactory };
    HRESULT DiscoverSafely(IUnknown* object, REFIID iid, Discovery source);
    bool ShellClass(REFCLSID clsid) { return IsEqualCLSID(clsid, CLSID_Shell) || IsEqualCLSID(clsid, CLSID_ShellWindows); }
    HRESULT DiscoverResult(HRESULT hr, REFIID iid, void** output, Discovery source) {
        if (SUCCEEDED(hr) && output && *output) {
            const HRESULT discovery = DiscoverSafely(static_cast<IUnknown*>(*output), iid, source);
            if (FAILED(discovery)) {
                // A related object must not escape with an unobserved launch path.
                static_cast<IUnknown*>(*output)->lpVtbl->Release(static_cast<IUnknown*>(*output));
                *output = NULL; return discovery;
            }
        }
        return hr;
    }
    HRESULT STDMETHODCALLTYPE Factory(IClassFactory* self, IUnknown* outer, REFIID iid, void** output) {
        auto original = Original(&self->lpVtbl->CreateInstance);
        if (!original) return E_UNEXPECTED;
        HRESULT hr = CallCom([&] { return original(self, outer, iid, output); });
        // Factory tables can be shared with unrelated classes. Recognize the
        // returned object's Shell interfaces rather than inferring its class.
        return DiscoverResult(hr, iid, output, AnyShell);
    }
    struct Value {
        VARIANT value;
        Value() { VariantInit(&value); }
        ~Value() { VariantClear(&value); }
        bool Copy(const VARIANT& source) { return SUCCEEDED(VariantCopyInd(&value, const_cast<VARIANT*>(&source))); }
        bool String() {
            if (value.vt == VT_EMPTY || (value.vt == VT_ERROR && value.scode == DISP_E_PARAMNOTFOUND)) return true;
            return value.vt == VT_BSTR; // Other coercions/errors remain the original COM method's responsibility.
        }
        LPCWSTR Text() const { return value.vt == VT_BSTR && value.bstrVal ? value.bstrVal : L""; }
        bool Set(const std::wstring& s) { value.vt = VT_BSTR; value.bstrVal = SysAllocStringLen(s.data(), static_cast<UINT>(s.size())); return value.bstrVal != NULL; }
    };
    HRESULT Build(BSTR file, VARIANT args, VARIANT directory, VARIANT verb, VARIANT show, std::wstring& helper, std::wstring& command) {
        Value a, d, v, s;
        if (!buildCommand || !file || !a.Copy(args) || !d.Copy(directory) || !v.Copy(verb) || !s.Copy(show) || !a.String() || !d.String() || !v.String()) return E_INVALIDARG;
        int nShow = SW_SHOWNORMAL;
        if (s.value.vt != VT_EMPTY && !(s.value.vt == VT_ERROR && s.value.scode == DISP_E_PARAMNOTFOUND)) {
            if (FAILED(VariantChangeType(&s.value, &s.value, 0, VT_I4))) return DISP_E_TYPEMISMATCH;
            nShow = s.value.lVal;
        }
        return buildCommand(file, a.Text(), d.Text(), v.Text(), nShow, helper, command);
    }
    HRESULT STDMETHODCALLTYPE Execute(IShellDispatch2* self, BSTR file, VARIANT args, VARIANT directory, VARIANT verb, VARIANT show) {
        auto original = Original(&self->lpVtbl->ShellExecute);
        if (!original) return E_UNEXPECTED;
        Guard guard;
        try {
            std::wstring helper, command;
            HRESULT decision = guard.entered ? Build(file, args, directory, verb, show, helper, command) : S_FALSE;
            if (FAILED(decision)) { if (reportFailure) reportFailure(file, decision); return decision; }
            if (decision == S_OK) {
                Value replacement, parameters;
                if (!replacement.Set(helper) || !parameters.Set(command)) return E_OUTOFMEMORY;
                return original(self, replacement.value.bstrVal, parameters.value, directory, verb, show);
            }
        } catch (...) { return E_OUTOFMEMORY; }
        return original(self, file, args, directory, verb, show);
    }
    HRESULT STDMETHODCALLTYPE Invoke(IDispatch* self, DISPID id, REFIID iid, LCID locale, WORD flags,
        DISPPARAMS* params, VARIANT* result, EXCEPINFO* exception, UINT* argError) {
        auto original = Original(&self->lpVtbl->Invoke);
        if (!original) return E_UNEXPECTED;
        Guard guard;
        try {
            // Resolve the name on this object, not on an earlier object's cached
            // DISPID. Shared IDispatch vtables can serve unrelated automation objects.
            WCHAR name[] = L"ShellExecute"; LPOLESTR names[] = { name }; DISPID executeId = DISPID_UNKNOWN;
            if (guard.entered && (flags & DISPATCH_METHOD) && params && params->rgvarg && params->cArgs >= 1 && params->cArgs <= 5 &&
                params->cNamedArgs <= params->cArgs && SUCCEEDED(self->lpVtbl->GetIDsOfNames(self, IID_NULL, names, 1, locale, &executeId)) && id == executeId) {
                IShellDispatch2* shell = NULL;
                if (SUCCEEDED(self->lpVtbl->QueryInterface(self, IID_IShellDispatch2, reinterpret_cast<void**>(&shell)))) {
                    shell->lpVtbl->Release(shell);
                    Value values[5]; bool valid = true; bool assigned[5] = {};
                    if (params->cNamedArgs) {
                        WCHAR fileName[] = L"File", argsName[] = L"vArgs", dirName[] = L"vDir", verbName[] = L"vOperation", showName[] = L"vShow";
                        LPOLESTR argumentNames[] = {name, fileName, argsName, dirName, verbName, showName};
                        DISPID ids[6] = {};
                        valid = params->rgdispidNamedArgs && SUCCEEDED(self->lpVtbl->GetIDsOfNames(self, IID_NULL, argumentNames, 6, locale, ids));
                        for (UINT i = 0; valid && i < params->cNamedArgs; ++i) {
                            UINT position = 0;
                            while (position < 5 && ids[position+1] != params->rgdispidNamedArgs[i]) ++position;
                            if (position == 5 || assigned[position]) valid = false;
                            else { assigned[position] = true; valid = values[position].Copy(params->rgvarg[i]); }
                        }
                    }
                    UINT position = 0;
                    for (UINT i = params->cArgs; valid && i > params->cNamedArgs; --i) {
                        while (position < 5 && assigned[position]) ++position;
                        if (position == 5) valid = false;
                        else { assigned[position] = true; valid = values[position++].Copy(params->rgvarg[i-1]); }
                    }
                    std::wstring helper, command;
                    if (!valid || values[0].value.vt != VT_BSTR) return DISP_E_TYPEMISMATCH;
                    HRESULT decision = Build(values[0].value.bstrVal, values[1].value,
                        values[2].value, values[3].value, values[4].value, helper, command);
                    if (FAILED(decision)) { if (reportFailure) reportFailure(values[0].value.bstrVal, decision); return decision; }
                    if (decision == S_OK) {
                        Value replacement, parameters;
                        if (!replacement.Set(helper) || !parameters.Set(command)) return E_OUTOFMEMORY;
                        VARIANTARG changed[] = { values[4].value, values[3].value, values[2].value, parameters.value, replacement.value };
                        DISPPARAMS call = { changed, NULL, 5, 0 };
                        return original(self, id, iid, locale, flags, &call, result, exception, argError);
                    }
                }
            }
        } catch (...) { return E_OUTOFMEMORY; }
        return original(self, id, iid, locale, flags, params, result, exception, argError);
    }
    HRESULT InstallShell(IShellDispatch2* shell) {
        ComPtr<IDispatch> dispatch;
        HRESULT hr = dispatch.Query(reinterpret_cast<IUnknown*>(shell), IID_IDispatch);
        if (FAILED(hr)) return hr;
        hr = PatchMethod(&shell->lpVtbl->ShellExecute, Execute);
        if (FAILED(hr)) return hr;
        // The inherited Invoke and QI(IDispatch) may use different shared tables.
        hr = PatchMethod(&reinterpret_cast<IDispatch*>(shell)->lpVtbl->Invoke, Invoke);
        return FAILED(hr) ? hr : PatchMethod(&dispatch.p->lpVtbl->Invoke, Invoke);
    }
    HRESULT DiscoverExplorer(IShellWindows* windows) {
        // Use the application's existing ShellWindows object. No CoInitialize,
        // extra CoCreateInstance, retained object, worker or getter hook is needed.
        VARIANT desktop = {}, empty = {}; desktop.vt = VT_I4; desktop.lVal = CSIDL_DESKTOP;
        long hwnd = 0;
        ComPtr<IDispatch> found, background, application;
        ComPtr<IServiceProvider> provider;
        ComPtr<IShellBrowser> browser;
        ComPtr<IShellView> view;
        ComPtr<IShellFolderViewDual> folder;
        ComPtr<IShellDispatch2> shell;
        HRESULT hr = windows->lpVtbl->FindWindowSW(windows, &desktop, &empty, SWC_DESKTOP, &hwnd, SWFO_NEEDDISPATCH, &found.p);
        if (FAILED(hr) || !found.p) return FAILED(hr) ? hr : E_NOINTERFACE;
        hr = provider.Query(reinterpret_cast<IUnknown*>(found.p), IID_IServiceProvider);
        if (FAILED(hr)) return hr;
        hr = provider.p->lpVtbl->QueryService(provider.p, SID_STopLevelBrowser, IID_IShellBrowser, reinterpret_cast<void**>(&browser.p));
        if (FAILED(hr) || !browser.p) return FAILED(hr) ? hr : E_NOINTERFACE;
        hr = browser.p->lpVtbl->QueryActiveShellView(browser.p, &view.p);
        if (FAILED(hr) || !view.p) return FAILED(hr) ? hr : E_NOINTERFACE;
        hr = view.p->lpVtbl->GetItemObject(view.p, SVGIO_BACKGROUND, IID_IDispatch, reinterpret_cast<void**>(&background.p));
        if (FAILED(hr)) return hr;
        hr = folder.Query(reinterpret_cast<IUnknown*>(background.p), IID_IShellFolderViewDual);
        if (FAILED(hr)) return hr;
        hr = folder.p->lpVtbl->get_Application(folder.p, &application.p);
        if (FAILED(hr)) return hr;
        hr = shell.Query(reinterpret_cast<IUnknown*>(application.p), IID_IShellDispatch2);
        if (FAILED(hr)) return hr;
        hr = InstallShell(shell.p);
        // Also cover the exact automation view returned by get_Application.
        return FAILED(hr) ? hr : PatchMethod(&application.p->lpVtbl->Invoke, Invoke);
    }
    HRESULT Discover(IUnknown* object, REFIID iid, Discovery source) {
        if (source == ClassFactory) {
            ComPtr<IClassFactory> factory;
            HRESULT hr = factory.Query(object, IID_IClassFactory);
            return FAILED(hr) ? hr : PatchMethod(&factory.p->lpVtbl->CreateInstance, Factory);
        }
        if (source != WindowsRoot) {
            ComPtr<IShellDispatch2> shell;
            HRESULT hr = shell.Query(object, IID_IShellDispatch2);
            if (SUCCEEDED(hr)) {
                hr = InstallShell(shell.p);
                if (FAILED(hr)) return hr;
                if (IsEqualIID(iid, IID_IDispatch) || IsEqualIID(iid, IID_IShellDispatch) ||
                    IsEqualIID(iid, IID_IShellDispatch2) || IsEqualIID(iid, IID_IShellDispatch3) ||
                    IsEqualIID(iid, IID_IShellDispatch4) || IsEqualIID(iid, IID_IShellDispatch5))
                    return PatchMethod(&reinterpret_cast<IDispatch*>(object)->lpVtbl->Invoke, Invoke);
                return S_OK;
            }
            if (source == ShellRoot || hr != E_NOINTERFACE) return hr;
        }
        ComPtr<IShellWindows> windows;
        HRESULT hr = windows.Query(object, IID_IShellWindows);
        if (source == AnyShell && hr == E_NOINTERFACE) return S_FALSE;
        return FAILED(hr) ? hr : DiscoverExplorer(windows.p);
    }
    HRESULT DiscoverSafely(IUnknown* object, REFIID iid, Discovery source) {
        Guard guard;
        if (!guard.entered || !object) return S_FALSE;
        HRESULT hr;
        try { hr = Discover(object, iid, source); } catch (...) { hr = E_OUTOFMEMORY; }
        if (FAILED(hr) && reportFailure) reportFailure(L"Shell COM discovery", hr);
        return hr;
    }
    HRESULT WINAPI Create(REFCLSID clsid, IUnknown* outer, DWORD context, REFIID iid, void** output) {
        if (!ShellClass(clsid)) return realCreate(clsid, outer, context, iid, output);
        HRESULT hr = CallCom([&] { return realCreate(clsid, outer, context, iid, output); });
        return DiscoverResult(hr, iid, output, IsEqualCLSID(clsid, CLSID_Shell) ? ShellRoot : WindowsRoot);
    }
    HRESULT WINAPI CreateEx(REFCLSID clsid, IUnknown* outer, DWORD context, COSERVERINFO* server, DWORD count, MULTI_QI* results) {
        if (!ShellClass(clsid) || server) return realCreateEx(clsid, outer, context, server, count, results);
        HRESULT hr = CallCom([&] { return realCreateEx(clsid, outer, context, server, count, results); });
        if (SUCCEEDED(hr) && results) {
            for (DWORD i=0; i<count; ++i) if (SUCCEEDED(results[i].hr) && results[i].pIID) {
                HRESULT found = DiscoverSafely(results[i].pItf, *results[i].pIID, IsEqualCLSID(clsid, CLSID_Shell) ? ShellRoot : WindowsRoot);
                if (FAILED(found)) {
                    for (DWORD j=0; j<count; ++j) {
                        if (results[j].pItf) results[j].pItf->lpVtbl->Release(results[j].pItf);
                        results[j].pItf = NULL; results[j].hr = found;
                    }
                    return found;
                }
            }
        }
        return hr;
    }
    HRESULT WINAPI Class(REFCLSID clsid, DWORD context, LPVOID server, REFIID iid, void** output) {
        if (!ShellClass(clsid) || server) return realClass(clsid, context, server, iid, output);
        HRESULT hr = CallCom([&] { return realClass(clsid, context, server, iid, output); });
        return DiscoverResult(hr, iid, output, ClassFactory);
    }
    // CoUnmarshalInterface is intentionally not intercepted. Unmarshalling-only
    // paths depend on an already covered shared table, not additional discovery.
    BOOL ExecuteShell(SHELLEXECUTEINFOW* info, decltype(realShell) original) {
        if (!info || info->cbSize != sizeof(*info)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
        Guard guard;
        try {
            std::wstring helper, command;
            HRESULT decision = guard.entered && buildCommand ? buildCommand(info->lpFile, info->lpParameters, info->lpDirectory, info->lpVerb, info->nShow, helper, command) : S_FALSE;
            // Never silently let an unsupported Shell representation launch via
            // Explorer. Ordinary lpFile requests, of any extension, use PL.
            if (decision == S_OK && (info->fMask & (SEE_MASK_INVOKEIDLIST | SEE_MASK_CLASSNAME | SEE_MASK_CLASSKEY | SEE_MASK_DOENVSUBST)))
                decision = HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
            if (FAILED(decision)) {
                if (reportFailure) reportFailure(info->lpFile, decision);
                info->hInstApp = reinterpret_cast<HINSTANCE>(SE_ERR_ACCESSDENIED);
                info->hProcess = NULL;
                SetLastError(HRESULT_FACILITY(decision) == FACILITY_WIN32 ? HRESULT_CODE(decision) : ERROR_INVALID_PARAMETER);
                return FALSE;
            }
            if (decision == S_OK) {
                SHELLEXECUTEINFOW changed = *info;
                changed.lpFile = helper.c_str(); changed.lpParameters = command.c_str();
                const BOOL ok = original(&changed); const DWORD error = GetLastError();
                info->hInstApp = changed.hInstApp; info->hProcess = changed.hProcess;
                SetLastError(error); return ok;
            }
        } catch (...) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
        return original(info);
    }
    BOOL WINAPI Shell(SHELLEXECUTEINFOW* info) { return ExecuteShell(info, realShell); }
    BOOL WINAPI StorageShell(SHELLEXECUTEINFOW* info) { return ExecuteShell(info, realStorageShell); }

    bool ResolveStorageShell() {
        realStorageShell = NULL;
        // Recent Windows routes ShellExecuteA/W through Windows.Storage and
        // calls its ExW internally, bypassing shell32's delay-import thunk.
        // Use the system directory, not the application's DLL search path.
        WCHAR directory[MAX_PATH];
        UINT length = GetSystemDirectoryW(directory, _countof(directory));
        if (!length || length >= _countof(directory)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return false; }
        const std::wstring path = std::wstring(directory) + L"\\Windows.Storage.dll";
        if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) {
            const DWORD error = GetLastError();
            // XP has no Windows.Storage. Its shell32 hook remains sufficient.
            return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
        }
        HMODULE storage = LoadLibraryW(path.c_str());
        if (!storage) return false;
        auto target = reinterpret_cast<decltype(realStorageShell)>(GetProcAddress(storage, "ShellExecuteExW"));
        if (!target) { FreeLibrary(storage); return true; }
        HMODULE pinned = NULL;
        const BOOL pinnedOk = GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_PIN | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
            reinterpret_cast<LPCWSTR>(storage), &pinned);
        const DWORD error = GetLastError();
        FreeLibrary(storage);
        if (!pinnedOk) { SetLastError(error); return false; }
        // Compare the addresses Detours will actually patch, not just exports.
        // Some systems forward/alias both names to one implementation.
        if (DetourCodeFromPointer(reinterpret_cast<PVOID>(target), NULL) !=
            DetourCodeFromPointer(reinterpret_cast<PVOID>(realShell), NULL)) realStorageShell = target;
        return true;
    }
}

bool Initialize(BuildCommand build, ReportFailure report) {
    if (initialized) { buildCommand = build; reportFailure = report; return true; }
    HMODULE shell = NULL, ole = NULL;
    if (!LoadLibraryW(L"shell32.dll") || !LoadLibraryW(L"ole32.dll") ||
        !GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_PIN, L"shell32.dll", &shell) ||
        !GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_PIN, L"ole32.dll", &ole)) return false;
    realShell = reinterpret_cast<decltype(realShell)>(GetProcAddress(shell, "ShellExecuteExW"));
    realCreate = reinterpret_cast<decltype(realCreate)>(GetProcAddress(ole, "CoCreateInstance"));
    realCreateEx = reinterpret_cast<decltype(realCreateEx)>(GetProcAddress(ole, "CoCreateInstanceEx"));
    realClass = reinterpret_cast<decltype(realClass)>(GetProcAddress(ole, "CoGetClassObject"));
    if (!realShell || !realCreate || !realCreateEx || !realClass) return false;
    if (!ResolveStorageShell()) return false;
    guardTls = TlsAlloc(); if (guardTls == TLS_OUT_OF_INDEXES) return false;
    InitializeCriticalSection(&lock); slotCount = 0; buildCommand = build; reportFailure = report; initialized = true;
    return true;
}
void AppendBindings(std::vector<DetourHookBinding>& bindings) {
    if (!initialized) return;
#define BIND(original, callback) bindings.push_back({ reinterpret_cast<PVOID*>(&original), reinterpret_cast<PVOID>(callback) });
    BIND(realShell, Shell) BIND(realCreate, Create) BIND(realCreateEx, CreateEx) BIND(realClass, Class)
    if (realStorageShell) BIND(realStorageShell, StorageShell)
#undef BIND
}
bool RestoreInterfaces() {
    if (!initialized) return true;
    Lock held;
    for (size_t i = slotCount; i; --i) {
        Slot& slot = slots[i-1]; void* current = NULL;
        if (ReadSlot(slot.address, current) && current == slot.replacement && !SwapSlot(slot.address, current, slot.original)) return false;
    }
    return true;
}
void Shutdown() {
    if (!initialized) return;
    buildCommand = NULL; reportFailure = NULL; slotCount = 0; initialized = false;
    TlsFree(guardTls); guardTls = TLS_OUT_OF_INDEXES; DeleteCriticalSection(&lock);
}
std::wstring Quote(const std::wstring& text) {
    std::wstring out = L"\""; size_t slashes = 0;
    for (wchar_t c : text) {
        if (c == L'\\') { ++slashes; continue; }
        out.append(c == L'"' ? slashes*2+1 : slashes, L'\\'); out += c; slashes = 0;
    }
    out.append(slashes*2, L'\\'); return out + L'"';
}
bool MightBeHelper(LPCWSTR path, LPCWSTR host) {
    if (!path || !*path || !host || !*host) return false;
    if (*path == L'"') ++path;
    LPCWSTR name = PathFindFileNameW(path);
    size_t length = wcslen(name);
    if (length && name[length-1] == L'"') --length;
    // Let full resolution handle possible short names and Win32 normalization.
    if (wcsstr(name, L"~") || (length && (name[length-1] == L'.' || name[length-1] == L' '))) return true;
    LPCWSTR names[] = { PathFindFileNameW(host), L"ProxyLane.exe", L"ProxyLane64.exe", L"ProxyLaneARM64.exe" };
    for (LPCWSTR expected : names) {
        const size_t n = wcslen(expected);
        if (length == n && !_wcsnicmp(name, expected, n)) return true;
        // SearchPath may add .exe for an extensionless command.
        if (n > 4 && length == n-4 && !_wcsicmp(expected+n-4, L".exe") && !_wcsnicmp(name, expected, length)) return true;
    }
    return false;
}
bool IsHelper(LPCWSTR path, LPCWSTR host) {
    if (!path || !host || !*host) return false;
    if (!_wcsicmp(path, host)) return true;
    const WCHAR* name = wcsrchr(path, L'\\'); const WCHAR* hostName = wcsrchr(host, L'\\');
    return name && hostName && name-path == hostName-host && !_wcsnicmp(path, host, name-path) &&
        (!_wcsicmp(name+1,L"ProxyLane.exe") || !_wcsicmp(name+1,L"ProxyLane64.exe") || !_wcsicmp(name+1,L"ProxyLaneARM64.exe"));
}
bool ResolveFile(LPCWSTR file, LPCWSTR directory, std::wstring& path) {
    if (!file || !*file) return false;
    std::wstring candidate(file);
    if (candidate.size()>1 && candidate.front()==L'"' && candidate.back()==L'"') candidate=candidate.substr(1,candidate.size()-2);
    if (candidate.find(L"://")!=std::wstring::npos) return false;
    WCHAR full[32768] = {}; DWORD length = 0;
    if (PathIsRelativeW(candidate.c_str()) && directory && *directory) {
        std::wstring relative = std::wstring(directory) + L"\\" + candidate;
        if (GetFileAttributesW(relative.c_str()) != INVALID_FILE_ATTRIBUTES) candidate = relative;
    }
    if (candidate.find_first_of(L"\\/") == std::wstring::npos)
        length = SearchPathW(NULL, candidate.c_str(), L".exe", _countof(full), full, NULL);
    else length = GetFullPathNameW(candidate.c_str(), _countof(full), full, NULL);
    if (!length || length>=_countof(full)) return false;
    DWORD attrs = GetFileAttributesW(full);
    if (attrs==INVALID_FILE_ATTRIBUTES || (attrs&FILE_ATTRIBUTE_DIRECTORY)) return false;
    path = full; return true;
}
bool ResolveExecutable(LPCWSTR file, LPCWSTR directory, std::wstring& path) {
    return ResolveFile(file, directory, path) && !_wcsicmp(PathFindExtensionW(path.c_str()), L".exe");
}
}
