// Test-only process-level QUIC local-root policy. One detour, no certificate ABI.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <bcrypt.h>
#include <intrin.h>
#include <stdint.h>
#include <vector>
#include "detours.h"
#pragma comment(lib, "bcrypt.lib")

struct Event { LONG ready, enabled, original, allowed, callerMatched; };
struct Control {
    ULONG magic, pid; ULONGLONG birth, deadline;
    volatile LONG enabled, epoch, initialized, error, count;
    ULONG completeRva, completeSize, allowRva, allowSize, callerReturnRva;
    BYTE moduleHash[32], completeHash[32], allowHash[32];
    Event events[128];
};
static Control* ctl;
static HANDLE owner;
static BCRYPT_ALG_HANDLE sha;
static BYTE* image;
using Allow = bool (__fastcall *)(void*, const void*);
static Allow originalAllow;
static bool hash(const BYTE* data, ULONG size, BYTE* out) {
    return BCryptHash(sha, nullptr, 0, const_cast<BYTE*>(data), size, out, 32) >= 0;
}
static bool fileHash(const wchar_t* path, BYTE* out) {
    HANDLE f=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,0,nullptr);
    if(f==INVALID_HANDLE_VALUE) return false;
    BCRYPT_HASH_HANDLE h=nullptr;
    bool ok=BCryptCreateHash(sha,&h,nullptr,0,nullptr,0,0)>=0;
    BYTE data[65536]; DWORD n;
    while(ok) {
        if(!ReadFile(f,data,sizeof(data),&n,nullptr)) {ok=false;break;}
        if(!n) break;
        ok=BCryptHashData(h,data,n,0)>=0;
    }
    if(ok) ok=BCryptFinishHash(h,out,32,0)>=0;
    if(h) BCryptDestroyHash(h);
    CloseHandle(f);return ok;
}
static bool live(LONG epoch) {
    return InterlockedCompareExchange(&ctl->enabled,0,0)==1 &&
        InterlockedCompareExchange(&ctl->epoch,0,0)==epoch &&
        GetTickCount64()<ctl->deadline && WaitForSingleObject(owner,0)==WAIT_TIMEOUT;
}
static bool __fastcall hookedAllow(void* job,const void* host) {
    void* caller=_ReturnAddress();
    LONG epoch=InterlockedCompareExchange(&ctl->epoch,0,0);
    bool original=originalAllow(job,host);
    bool matched=caller==image+ctl->callerReturnRva;
    bool enabled=live(epoch);
    bool allowed=original || (matched && enabled);
    LONG index=InterlockedIncrement(&ctl->count)-1;
    if(index>=0 && index<128) {
        Event& e=ctl->events[index];
        e.enabled=enabled;e.original=original;e.allowed=allowed;e.callerMatched=matched;
        InterlockedExchange(&e.ready,1);
    }
    return allowed;
}
static bool functionMatches(ULONG rva,ULONG size,const BYTE* expected,ULONG imageSize) {
    if(rva>=imageSize || size<16 || size>16384 || size>imageSize-rva) return false;
    DWORD64 base=0;
    auto f=RtlLookupFunctionEntry((DWORD64)(image+rva),&base,nullptr);
    BYTE digest[32];
    return f && base==(DWORD64)image && f->BeginAddress==rva && f->EndAddress==rva+size &&
        hash(image+rva,size,digest) && !memcmp(digest,expected,32);
}
struct Init { HANDLE mapping,owner; };
extern "C" __declspec(dllexport) DWORD WINAPI InitializeProbe(Init* init) {
    if(ctl) return 1;
    ctl=(Control*)MapViewOfFile(init->mapping,FILE_MAP_ALL_ACCESS,0,0,sizeof(Control));
    CloseHandle(init->mapping);owner=init->owner;
    if(!ctl || ctl->magic!=0x51504f31) return 2;
    FILETIME creation,exit,kernel,user;
    if(!GetProcessTimes(GetCurrentProcess(),&creation,&exit,&kernel,&user) ||
       ctl->pid!=GetCurrentProcessId() || ctl->birth!=*(ULONGLONG*)&creation || ctl->enabled!=0) return ctl->error=3;
    if(BCryptOpenAlgorithmProvider(&sha,BCRYPT_SHA256_ALGORITHM,nullptr,0)<0) return ctl->error=4;
    HMODULE module=GetModuleHandleW(L"chrome.dll");
    if(!module) module=GetModuleHandleW(L"msedge.dll");
    wchar_t path[32768];BYTE digest[32];
    if(!module || !GetModuleFileNameW(module,path,32768) || !fileHash(path,digest) ||
       memcmp(digest,ctl->moduleHash,32)) return ctl->error=5;
    image=(BYTE*)module;
    auto dos=(IMAGE_DOS_HEADER*)image;
    auto nt=(IMAGE_NT_HEADERS64*)(image+dos->e_lfanew);
    if(nt->Signature!=IMAGE_NT_SIGNATURE || nt->FileHeader.Machine!=IMAGE_FILE_MACHINE_AMD64) return ctl->error=6;
    ULONG size=nt->OptionalHeader.SizeOfImage;
    if(!functionMatches(ctl->completeRva,ctl->completeSize,ctl->completeHash,size) ||
       !functionMatches(ctl->allowRva,ctl->allowSize,ctl->allowHash,size)) return ctl->error=7;
    // Revalidate the direct caller. Only this recognized call site gains the exception.
    ULONG ret=ctl->callerReturnRva;
    if(ret<ctl->completeRva+5 || ret>ctl->completeRva+ctl->completeSize || image[ret-5]!=0xe8 ||
       (int64_t)ret+*(int32_t*)(image+ret-4)!=ctl->allowRva) return ctl->error=8;
    originalAllow=(Allow)(image+ctl->allowRva);
    std::vector<HANDLE> threads;
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);
    if(snap==INVALID_HANDLE_VALUE) return ctl->error=9;
    THREADENTRY32 entry{sizeof(entry)};
    if(Thread32First(snap,&entry)) do {
        if(entry.th32OwnerProcessID==GetCurrentProcessId() && entry.th32ThreadID!=GetCurrentThreadId()) {
            HANDLE t=OpenThread(THREAD_SUSPEND_RESUME|THREAD_GET_CONTEXT|THREAD_SET_CONTEXT|THREAD_QUERY_INFORMATION,FALSE,entry.th32ThreadID);
            if(!t) {CloseHandle(snap);for(HANDLE h:threads) CloseHandle(h);return ctl->error=10;}
            threads.push_back(t);
        }
    } while(Thread32Next(snap,&entry));
    CloseHandle(snap);
    LONG error=DetourTransactionBegin();
    if(!error) error=DetourAttach((PVOID*)&originalAllow,hookedAllow);
    for(HANDLE t:threads) if(!error) error=DetourUpdateThread(t);
    if(!error) error=DetourTransactionCommit();else DetourTransactionAbort();
    for(HANDLE t:threads) CloseHandle(t);
    if(error) return ctl->error=error;
    InterlockedExchange(&ctl->initialized,1);return 0;
}
BOOL WINAPI DllMain(HINSTANCE,DWORD,LPVOID) {return TRUE;}
