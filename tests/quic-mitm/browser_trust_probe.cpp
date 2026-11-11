// Exact-build, test-only QUIC trust gate. Never shipped or loaded into user profiles.
// The controller owns the duplicated anonymous mapping and isolated browser process.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <bcrypt.h>
#include <stdint.h>
#include <stdio.h>
#include <vector>
#include "detours.h"
#pragma comment(lib, "bcrypt.lib")

struct Event {
    LONG ready; int input, output; ULONG status, flags; USHORT port, count;
    char host[128]; BYTE leaf[32], root[32];
};
struct Control {
    ULONG magic, pid; ULONGLONG birth, deadline;
    volatile LONG enabled, epoch, initialized, error, count;
    ULONG reserved;
    BYTE moduleHash[32], root[32];
    Event events[128];
};
static Control* ctl;
static BCRYPT_ALG_HANDLE sha;
static HANDLE owner;
typedef int (__fastcall *Complete)(void*, int);
typedef bool (__fastcall *Allow)(void*, const void*);
static Complete originalComplete;
static Allow originalAllow;
struct Scope { void* job; LONG epoch; bool eligible; Event* event; };
static thread_local Scope scope{};

static bool hash(const BYTE* data, size_t size, BYTE* out) {
    return size <= 1024 * 1024 && BCryptHash(sha, nullptr, 0,
        const_cast<BYTE*>(data), (ULONG)size, out, 32) >= 0;
}
template<class T> static T read(const void* p, size_t offset) {
    return *reinterpret_cast<const T*>(static_cast<const BYTE*>(p) + offset);
}
static bool bufferHash(const void* buffer, BYTE* out) {
    // Pinned Chromium/BoringSSL build: pool handle, data pointer, length.
    const BYTE* data = read<const BYTE*>(buffer, 8);
    size_t size = read<size_t>(buffer, 16);
    return size >= 128 && size <= 65536 && data && data[0] == 0x30 && hash(data, size, out);
}
static bool inspect(void* job, int result, Event* e) {
    __try {
        auto details = read<const void*>(job, 0);
        e->status = read<ULONG>(details, 0x10);
        if (read<BYTE>(details, 0x30)) e->flags |= 1; // original known-root bit
        e->port = read<USHORT>(job, 0x48);
        signed char length = read<signed char>(job, 0x47);
        size_t size = length < 0 ? read<size_t>(job, 0x38) : length;
        const char* host = length < 0 ? read<const char*>(job, 0x30) : (const char*)job + 0x30;
        if (size == 0 || size >= sizeof(e->host)) return false;
        memcpy(e->host, host, size); e->host[size] = 0;
        // Only inspect the VERIFIED chain, never the peer's unverified chain.
        const void* cert = read<const void*>(details, 8);
        const void* const* begin = read<const void* const*>(cert, 8);
        // This build's hardened vector ABI stores pointer, size, capacity.
        size_t count = read<size_t>(cert, 16), capacity = read<size_t>(cert, 24);
        if (!begin || count < 1 || count > 16 || capacity < count || capacity > 64) return false;
        e->count = (USHORT)count;
        if (!bufferHash(begin[0], e->leaf) || !bufferHash(begin[e->count - 1], e->root)) return false;
        e->flags |= 2; // parsed verified chain
        if (memcmp(e->root, ctl->root, 32) == 0) e->flags |= 4;
        // Process-wide CA exception. Hostname/expiry/signature validation stays
        // with Chromium; no leaf, host, port or MITM connection authorization.
        return result == 0 && e->status == 0 && (e->flags & 6) == 6;
    } __except(EXCEPTION_EXECUTE_HANDLER) { e->flags |= 128; return false; }
}
static bool live(LONG epoch) {
    return ctl && InterlockedCompareExchange(&ctl->enabled, 0, 0) == 1 &&
        InterlockedCompareExchange(&ctl->epoch, 0, 0) == epoch &&
        GetTickCount64() < ctl->deadline && WaitForSingleObject(owner, 0) == WAIT_TIMEOUT;
}
static bool __fastcall hookedAllow(void* job, const void* host) {
    bool original = originalAllow(job, host);
    if (original) return true;
    if (scope.job == job && scope.eligible && live(scope.epoch)) {
        if (scope.event) scope.event->flags |= 32;
        return true;
    }
    return false;
}
static int __fastcall hookedComplete(void* job, int result) {
    Event local{};
    LONG index = InterlockedIncrement(&ctl->count) - 1;
    Event* e = index >= 0 && index < 128 ? &ctl->events[index] : &local;
    e->input = result;
    Scope previous = scope;
    LONG epoch = InterlockedCompareExchange(&ctl->epoch, 0, 0);
    scope = {job, epoch, inspect(job, result, e) && live(epoch), e};
    int answer = originalComplete(job, result);
    scope = previous;
    e->output = answer;
    InterlockedExchange(&e->ready, 1);
    return answer;
}
static bool fileHash(const wchar_t* path, BYTE* out) {
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;
    BCRYPT_HASH_HANDLE h = nullptr;
    bool ok = BCryptCreateHash(sha, &h, nullptr, 0, nullptr, 0, 0) >= 0;
    BYTE data[65536]; DWORD n;
    while (ok) {
        if (!ReadFile(f, data, sizeof(data), &n, nullptr)) { ok = false; break; }
        if (!n) break;
        ok = BCryptHashData(h, data, n, 0) >= 0;
    }
    if (ok) ok = BCryptFinishHash(h, out, 32, 0) >= 0;
    if (h) BCryptDestroyHash(h);
    CloseHandle(f); return ok;
}
struct Init { HANDLE mapping, owner; };
extern "C" __declspec(dllexport) DWORD WINAPI InitializeProbe(Init* init) {
    if (ctl) return 1;
    ctl = (Control*)MapViewOfFile(init->mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(Control));
    CloseHandle(init->mapping);
    owner = init->owner;
    if (!ctl || ctl->magic != 0x51484b31) return 2;
    FILETIME creation, exit, kernel, user;
    if (!GetProcessTimes(GetCurrentProcess(), &creation, &exit, &kernel, &user) ||
        ctl->pid != GetCurrentProcessId() || ctl->birth != *(ULONGLONG*)&creation) return ctl->error = 3;
    if (BCryptOpenAlgorithmProvider(&sha, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) return ctl->error = 4;
    HMODULE module = GetModuleHandleW(L"chrome.dll");
    bool edge = false;
    if (!module) { module = GetModuleHandleW(L"msedge.dll"); edge = true; }
    wchar_t path[32768]; BYTE digest[32];
    if (!module || !GetModuleFileNameW(module, path, 32768) || !fileHash(path, digest) ||
        memcmp(digest, ctl->moduleHash, 32)) return ctl->error = 5;
    // Hash whitelist, independently enforced inside the DLL.
    const char* expected = edge ? "1906b766460da798672a9845e2772130674f7d3d866e8c63140ed88a1fe1c88d" :
        "7cc644c8a146d804ac175ff59277124cd63a4ccf15ea75f796e90f06e4dadfcd";
    for (int i = 0; i < 32; ++i) {
        unsigned v; if (sscanf_s(expected + i * 2, "%2x", &v) != 1 || digest[i] != v) return ctl->error = 6;
    }
    BYTE* complete = (BYTE*)module + (edge ? 0xf2f56b0 : 0xd995500);
    BYTE* allow = (BYTE*)module + (edge ? 0xf2f5aa0 : 0xd9958e0);
    const BYTE c[] = {0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x56,0x57,0x55,0x53,0x48,0x81,0xec,0xc8,0,0,0};
    const BYTE a[] = {0x41,0x56,0x56,0x57,0x53,0x48,0x83,0xec,0x58,0x0f,0x29,0x74,0x24,0x40};
    if (memcmp(complete, c, sizeof(c)) || memcmp(allow, a, sizeof(a))) return ctl->error = 7;
    originalComplete = (Complete)complete; originalAllow = (Allow)allow;
    // Installed once per network-service process. Detours
    // suspends/enlists every existing thread and adjusts PCs before resuming them.
    std::vector<HANDLE> threads;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return ctl->error = 8;
    THREADENTRY32 entry{sizeof(entry)};
    if (Thread32First(snapshot, &entry)) do {
        if (entry.th32OwnerProcessID == GetCurrentProcessId() && entry.th32ThreadID != GetCurrentThreadId()) {
            HANDLE t = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, entry.th32ThreadID);
            if (!t) { CloseHandle(snapshot); for (HANDLE h : threads) CloseHandle(h); return ctl->error = 9; }
            threads.push_back(t);
        }
    } while (Thread32Next(snapshot, &entry));
    CloseHandle(snapshot);
    LONG error = DetourTransactionBegin();
    if (!error) error = DetourAttach((PVOID*)&originalComplete, hookedComplete);
    if (!error) error = DetourAttach((PVOID*)&originalAllow, hookedAllow);
    for (HANDLE t : threads) if (!error) error = DetourUpdateThread(t);
    if (!error) error = DetourTransactionCommit(); else DetourTransactionAbort();
    for (HANDLE t : threads) CloseHandle(t);
    if (error) return ctl->error = error;
    InterlockedExchange(&ctl->initialized, 1);
    return 0;
}
BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) { return TRUE; }
