#include "stdafx.h"
#include "BrowserQuicPolicy.h"
#include "PRCPipeClient.h"
#include "AppContainerPipeAccess.h"
#include "../ProxyLaneMitm/ProxyLaneMitm.h"
#include "../../third_party/nlohmann/json.hpp"
#include <tlhelp32.h>
#include <wincrypt.h>
#include <intrin.h>
#include <atomic>
#include <mutex>
#include <map>
#include <tuple>
#include <thread>
#include <vector>
#include "detours.h"
#pragma comment(lib,"crypt32.lib")
namespace BrowserQuicPolicy {
static std::atomic<bool> preference{false};
void SetPreference(bool enabled) {
#if defined(_M_X64) && !defined(_M_ARM64EC)
    preference.store(enabled);
#endif
}
bool Preference() {return preference.load();}
// No monitoring thread: only explicit registration/report messages populate this
// bounded table. Entries for other PRC instances and recycled PIDs never match.
struct Entry { DWORD status, updated; };
static std::mutex reportsMutex;
static std::map<std::tuple<const void*,DWORD,ULONGLONG>,Entry> reports;
void Observe(const void* owner,DWORD pid,const Report& r) {
    if(!pid||!r.birth||r.status<Pending||r.status>Unavailable)return;
    std::lock_guard<std::mutex> guard(reportsMutex);
    auto key=std::make_tuple(owner,pid,r.birth); auto it=reports.find(key);
    if(it!=reports.end() && it->second.status!=Pending && r.status==Pending)return;
    if(it==reports.end() && reports.size()>=4096) {
        auto oldest=reports.begin();DWORD now=GetTickCount();
        for(auto i=reports.begin();i!=reports.end();++i)
            if(now-i->second.updated>now-oldest->second.updated)oldest=i;
        reports.erase(oldest);
    }
    reports[key]={r.status,GetTickCount()};
}
DWORD Lookup(const void* owner,DWORD pid,ULONGLONG birth,DWORD fallback) {
    std::lock_guard<std::mutex> guard(reportsMutex);
    auto it=reports.find(std::make_tuple(owner,pid,birth));
    return it==reports.end()?fallback:it->second.status;
}
void Forget(const void* owner) {
    std::lock_guard<std::mutex> guard(reportsMutex);
    for(auto i=reports.begin();i!=reports.end();)if(std::get<0>(i->first)==owner)i=reports.erase(i);else ++i;
}
// The browser locator decodes x64 instructions and x64 unwind tables only.
#if !defined(_M_X64) || defined(_M_ARM64EC)
void Initialize(LPCTSTR,bool) {} bool Enabled(){return false;} void SetupFailed(){}
void ModuleLoaded(LPCWSTR,DWORD){} DWORD OnUdp(){return None;}
bool NeedsPublish(){return false;} void Publish(CPRCPipeClient&){}
#else
using Json=nlohmann::json;
// Process-local immutable decision. Rebinding PRC and stopping capture do not
// reset it. No remote owner, heartbeat, shared mapping or detach operation.
enum State { Uninitialized, Disabled, Waiting, Working, Installed, Failed };
static std::atomic<int> state{Uninitialized};
static std::atomic<unsigned> moduleHint{0};
static std::atomic<DWORD> published{None};
static ULONGLONG birth=0;
static std::wstring locatorPath;
static std::wstring endpoint;

using Allow=bool(__fastcall*)(void*,const void*);
static Allow originalAllow=nullptr;
static BYTE* browserImage=nullptr;
static DWORD callerReturn=0;
// Separate overlapped pipe: optional compatibility must never monopolize the
// normal forwarding client or wait indefinitely for an old/unavailable PRC.
class Pipe {
    HANDLE handle=INVALID_HANDLE_VALUE;
public:
    explicit Pipe(const wchar_t* name) {
        const DWORD started=GetTickCount();
        do {
            handle=CreateFileW(name,PROXYLANE_PIPE_CLIENT_ACCESS,FILE_SHARE_READ|FILE_SHARE_WRITE,
                nullptr,OPEN_EXISTING,FILE_FLAG_OVERLAPPED|SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION,nullptr);
            if(handle!=INVALID_HANDLE_VALUE || GetLastError()!=ERROR_PIPE_BUSY)break;
            DWORD elapsed=GetTickCount()-started;
            if(elapsed>=500 || !WaitNamedPipeW(name,500-elapsed))break;
        }while(GetTickCount()-started<500);
    }
    ~Pipe(){if(handle!=INVALID_HANDLE_VALUE)CloseHandle(handle);}
    bool Io(bool write,void* data,DWORD size,DWORD timeout) {
        if(handle==INVALID_HANDLE_VALUE)return false;
        OVERLAPPED ov={};ov.hEvent=CreateEvent(nullptr,TRUE,FALSE,nullptr);if(!ov.hEvent)return false;
        DWORD done=0;BOOL ok=write?WriteFile(handle,data,size,&done,&ov):ReadFile(handle,data,size,&done,&ov);
        if(!ok&&GetLastError()==ERROR_IO_PENDING) {
            if(WaitForSingleObject(ov.hEvent,timeout)==WAIT_OBJECT_0)ok=GetOverlappedResult(handle,&ov,&done,FALSE);
            else {CancelIo(handle);GetOverlappedResult(handle,&ov,&done,TRUE);ok=FALSE;}
        }
        CloseHandle(ov.hEvent);return ok&&done==size;
    }
    bool ReportState(DWORD status) {
        Report r={birth,status,0};PRCPipeDataHead hdr={};hdr.action=PRCPD_QUIC_STATUS;hdr.flag=1;hdr.dataSize=sizeof(r);
        return Io(true,&hdr,sizeof(hdr),200)&&Io(true,&r,sizeof(r),200)&&Io(false,&hdr,sizeof(hdr),200)
            &&hdr.action==PRCPD_REPLY&&hdr.flag==1&&hdr.dataSize==0;
    }
    void Log(const std::wstring& text) {
        DWORD size=FIELD_OFFSET(HookLogtext,str)+(DWORD)((text.size()+1)*sizeof(wchar_t));
        std::vector<BYTE> bytes(size);auto info=(HookLogtext*)bytes.data();
        info->dwProcessId=GetCurrentProcessId();info->len=(int)((text.size()+1)*sizeof(wchar_t));
        memcpy(info->str,text.c_str(),info->len);
        PRCPipeDataHead hdr={};hdr.action=PRCPD_Logtext;hdr.flag=1;hdr.dataSize=size;
        // Wait for delivery acknowledgment before closing this short-lived
        // connection; otherwise the server may observe a broken pipe first.
        if(Io(true,&hdr,sizeof(hdr),500)&&Io(true,bytes.data(),size,500))Io(false,&hdr,sizeof(hdr),500);
    }
};
static void Log(const wchar_t* message) noexcept {try {Pipe pipe(endpoint.c_str());pipe.Log(message);}catch(...) {}}
static bool Hash(const BYTE* b,size_t n,BYTE* out) {
    HCRYPTPROV provider=0;HCRYPTHASH hash=0;bool ok=false;
    if(CryptAcquireContext(&provider,NULL,NULL,PROV_RSA_AES,CRYPT_VERIFYCONTEXT)) {
        if(CryptCreateHash(provider,CALG_SHA_256,0,0,&hash)) {DWORD size=32;ok=n<=MAXDWORD&&CryptHashData(hash,b,(DWORD)n,0)&&CryptGetHashParam(hash,HP_HASHVAL,out,&size,0);CryptDestroyHash(hash);}
        CryptReleaseContext(provider,0);
    }return ok;
}
static bool __fastcall HookedAllow(void* job,const void* host) {
    void* caller=_ReturnAddress();
    return originalAllow(job,host) || caller==browserImage+callerReturn;
}
static bool FunctionMatches(DWORD rva,DWORD size,const BYTE* hash,DWORD imageSize) {
    if(rva>=imageSize||size<16||size>16384||size>imageSize-rva)return false;
    DWORD64 base=0;auto f=RtlLookupFunctionEntry((DWORD64)(browserImage+rva),&base,nullptr);BYTE actual[32];
    return f&&base==(DWORD64)browserImage&&f->BeginAddress==rva&&f->EndAddress==rva+size&&Hash(browserImage+rva,size,actual)&&!memcmp(hash,actual,32);
}
static void Hex(const std::string& s,BYTE* out) {if(s.size()!=64)throw std::runtime_error("invalid SHA256 descriptor");for(size_t i=0;i<32;++i)out[i]=(BYTE)std::stoul(s.substr(i*2,2),NULL,16);}

static void Install(const Json& d,HMODULE module) {
    if(d.contains("error"))throw std::runtime_error(d["error"].get<std::string>());
    BYTE expected[32];
    browserImage=(BYTE*)module;auto dos=(IMAGE_DOS_HEADER*)module;
    auto nt=(IMAGE_NT_HEADERS64*)(browserImage+dos->e_lfanew);DWORD size=nt->OptionalHeader.SizeOfImage;
    DWORD complete=d.at("complete_rva"),completeSize=d.at("complete_size"),allow=d.at("allow_rva"),allowSize=d.at("allow_size");
    Hex(d.at("complete_hash"),expected);
    if(!FunctionMatches(complete,completeSize,expected,size))throw std::runtime_error("Completion function validation failed");
    Hex(d.at("allow_hash"),expected);
    if(!FunctionMatches(allow,allowSize,expected,size))throw std::runtime_error("Unknown-root function validation failed");
    DWORD ret=d.at("caller_return_rva");
    if(ret<complete+5||ret>complete+completeSize||browserImage[ret-5]!=0xe8
        ||(int64_t)ret+*(int32_t*)(browserImage+ret-4)!=allow)throw std::runtime_error("Call site validation failed");
    // All callback data is initialized before publishing the detour. It is
    // immutable afterwards and neither forwarding nor verification takes a lock.
    callerReturn=ret;originalAllow=(Allow)(browserImage+allow);
    std::vector<HANDLE> threads;HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);
    if(snap==INVALID_HANDLE_VALUE)throw std::runtime_error("Cannot enumerate local threads");
    THREADENTRY32 e={sizeof(e)};DWORD error=0;
    if(!Thread32First(snap,&e))error=GetLastError();
    else do {if(e.th32OwnerProcessID==GetCurrentProcessId()&&e.th32ThreadID!=GetCurrentThreadId()) {
        HANDLE t=OpenThread(THREAD_SUSPEND_RESUME|THREAD_GET_CONTEXT|THREAD_SET_CONTEXT|THREAD_QUERY_INFORMATION,FALSE,e.th32ThreadID);
        if(!t){if(GetLastError()!=ERROR_INVALID_PARAMETER){error=GetLastError();break;}}
        else threads.push_back(t);
    }}while(Thread32Next(snap,&e));CloseHandle(snap);
    if(!error) {error=DetourTransactionBegin();if(!error){
        error=DetourAttach((PVOID*)&originalAllow,HookedAllow);
        for(HANDLE t:threads)if(!error)error=DetourUpdateThread(t);
        if(!error)error=DetourTransactionCommit();else DetourTransactionAbort();
    }}
    for(HANDLE t:threads)CloseHandle(t);
    if(error)throw std::runtime_error("Local detour transaction failed: "+std::to_string(error));
}
// Snapshot readable image sections from this process, never a remote process or
// disk file. The retained HMODULE prevents unload; RPM fails safely on protection
// changes. No full-file SHA; only the two small selected functions are rechecked.
static Json LocateLocal(HMODULE module,HMODULE locator) {
    BYTE headers[4096];SIZE_T got=0;
    if(!ReadProcessMemory(GetCurrentProcess(),module,headers,sizeof(headers),&got)||got!=sizeof(headers))throw std::runtime_error("Unreadable image header");
    auto dos=(IMAGE_DOS_HEADER*)headers;
    if(dos->e_magic!=IMAGE_DOS_SIGNATURE||dos->e_lfanew<0||dos->e_lfanew>2048)throw std::runtime_error("Invalid image header");
    auto nt=(IMAGE_NT_HEADERS64*)(headers+dos->e_lfanew);
    if(nt->Signature!=IMAGE_NT_SIGNATURE||nt->FileHeader.Machine!=IMAGE_FILE_MACHINE_AMD64||nt->OptionalHeader.Magic!=IMAGE_NT_OPTIONAL_HDR64_MAGIC
        ||nt->OptionalHeader.SizeOfImage<4096||nt->OptionalHeader.SizeOfImage>=1024*1024*1024||nt->FileHeader.NumberOfSections>32)throw std::runtime_error("Invalid x64 image");
    auto section=IMAGE_FIRST_SECTION(nt);
    if((BYTE*)(section+nt->FileHeader.NumberOfSections)>headers+sizeof(headers))throw std::runtime_error("Invalid section headers");
    std::vector<BYTE> snapshot(nt->OptionalHeader.SizeOfImage);memcpy(snapshot.data(),headers,sizeof(headers));
    for(unsigned i=0;i<nt->FileHeader.NumberOfSections;++i) {
        size_t at=section[i].VirtualAddress,n=section[i].Misc.VirtualSize;
        if(at>snapshot.size()||n>snapshot.size()-at)throw std::runtime_error("Invalid section extent");
        // Discardable relocation/debug sections are not used by the locator.
        if(section[i].Characteristics&IMAGE_SCN_MEM_DISCARDABLE)continue;
        while(n) {
            MEMORY_BASIC_INFORMATION mi={};
            if(!VirtualQuery((BYTE*)module+at,&mi,sizeof(mi)))throw std::runtime_error("Image region unavailable");
            size_t count=min(n,(size_t)((BYTE*)mi.BaseAddress+mi.RegionSize-((BYTE*)module+at)));
            if(!count||mi.AllocationBase!=module||mi.State!=MEM_COMMIT||(mi.Protect&(PAGE_NOACCESS|PAGE_GUARD))
                ||!ReadProcessMemory(GetCurrentProcess(),(BYTE*)module+at,snapshot.data()+at,count,&got)||got!=count)throw std::runtime_error("Image region unreadable");
            at+=count;n-=count;
        }
    }
    auto locate=(PLM_QUIC_LOCATE_IMAGE_FN)GetProcAddress(locator,"plm_quic_locate_image");
    if(!locate)throw std::runtime_error("Missing local QUIC locator");
    char output[4096]={};int count=locate(snapshot.data(),snapshot.size(),output,sizeof(output));
    if(count<=0||count>sizeof(output))throw std::runtime_error(output[0]?output:"Local QUIC locator failed");
    return Json::parse(output);
}
static DWORD CurrentStatus() {
    switch(state.load()) {case Working:return Pending;case Installed:return Ready;case Failed:return Unavailable;default:return None;}
}
static void Worker(HMODULE module) {
    DWORD started=GetTickCount();HMODULE locator=nullptr;
    try {
        locator=LoadLibraryExW(locatorPath.c_str(),nullptr,LOAD_WITH_ALTERED_SEARCH_PATH);
        if(!locator)throw std::runtime_error("Cannot load local QUIC locator: "+std::to_string(GetLastError()));
        DWORD loaded=GetTickCount();auto d=LocateLocal(module,locator);DWORD located=GetTickCount();
        Install(d,module);state.store(Installed);
        Pipe pipe(endpoint.c_str());pipe.ReportState(Ready);
        Log((std::wstring(L"QUIC browser compatibility installed; retained until target process exits. load_ms=")+std::to_wstring(loaded-started)
            +L" locate_ms="+std::to_wstring(located-loaded)+L" install_ms="+std::to_wstring(GetTickCount()-located)
            +L" total_ms="+std::to_wstring(GetTickCount()-started)).c_str());
        // Keep both modules alive. Unloading Rust here would execute TLS teardown
        // in a host we do not own; no runtime/capture was initialized by locating.
    }catch(const std::exception& e) {
        state.store(Failed);FreeLibrary(module);
        Pipe pipe(endpoint.c_str());pipe.ReportState(Unavailable);
        try {Log((std::wstring(L"QUIC browser compatibility unavailable: ")+std::wstring(CA2W(e.what(),CP_UTF8))).c_str());}catch(...) {}
    }catch(...) {state.store(Failed);FreeLibrary(module);Pipe pipe(endpoint.c_str());pipe.ReportState(Unavailable);}
}
void SetupFailed(){int expected=Waiting;state.compare_exchange_strong(expected,Failed);}
bool Enabled(){return state.load()!=Uninitialized&&state.load()!=Disabled;}
void ModuleLoaded(LPCWSTR name,DWORD flags) {
    // Called after LoadLibraryExW, possibly still under a nested loader lock.
    // Only an atomic hint here: no handles, allocation, RPC or installation.
    if(!name||!Enabled()||(flags&(LOAD_LIBRARY_AS_DATAFILE|LOAD_LIBRARY_AS_IMAGE_RESOURCE|0x40|DONT_RESOLVE_DLL_REFERENCES)))return;
    const wchar_t* file=wcsrchr(name,L'\\');file=file?file+1:name;
    if(!_wcsicmp(file,L"chrome.dll"))moduleHint.store(1);
    else if(!_wcsicmp(file,L"msedge.dll"))moduleHint.store(2);
}
DWORD OnUdp() {
    if(state.load()!=Waiting)return CurrentStatus();
    DWORD error=GetLastError();HMODULE module=nullptr;
    // Also check on eligible sends: static imports / direct LdrLoadDll can bypass
    // LoadLibraryExW. GetModuleHandleEx is a cheap lookup and retains the image.
    bool edge=moduleHint.load()==2;
    if(GetModuleHandleExW(0,edge?L"msedge.dll":L"chrome.dll",&module)||GetModuleHandleExW(0,edge?L"chrome.dll":L"msedge.dll",&module)) {
        int expected=Waiting;
        if(state.compare_exchange_strong(expected,Working)) {
            try {std::thread(Worker,module).detach();}
            catch(...) {FreeLibrary(module);state.store(Failed);}
        }else FreeLibrary(module);
    }
    DWORD result=CurrentStatus();SetLastError(error);return result;
}
bool NeedsPublish(){DWORD s=CurrentStatus();return s!=None&&s!=published.load();}
void Publish(CPRCPipeClient& pipe) {
    DWORD status=CurrentStatus();
    if(status==None||status==published.load())return;
    Report r={birth,status,0};
    if(pipe.PRCReportQuicStatus(r))published.store(status);
}
void Initialize(LPCTSTR pipeName,bool enabled) {
    int expected=Uninitialized;
    if(!state.compare_exchange_strong(expected,Disabled))return;
    if(!enabled)return;
    DWORD error=GetLastError();
    try {
        HMODULE pinned=nullptr;
        if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_PIN|GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,(LPCWSTR)&Initialize,&pinned))throw std::runtime_error("Cannot retain Hook module");
        wchar_t path[32768]={};DWORD n=GetModuleFileNameW(pinned,path,_countof(path));
        if(!n||n>=_countof(path))throw std::runtime_error("Missing Hook path");
        locatorPath=path;auto slash=locatorPath.find_last_of(L"\\");
        if(slash==std::wstring::npos)throw std::runtime_error("Missing module directory");
        locatorPath.resize(slash+1);locatorPath+=L"ProxyLaneMitm64.dll";
        endpoint=pipeName;
        FILETIME created,exited,kernel,user;
        if(!GetProcessTimes(GetCurrentProcess(),&created,&exited,&kernel,&user))throw std::runtime_error("Missing process identity");
        birth=((ULONGLONG)created.dwHighDateTime<<32)|created.dwLowDateTime;
        state.store(Waiting);
    }catch(...) {state.store(Disabled);}
    SetLastError(error);
}
#endif
}
