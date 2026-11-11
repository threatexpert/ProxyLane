#include "DetourHooks.h"
#include "HookFailureDiagnostics.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>

namespace {
void Check(bool ok, const char* message)
{
    if (!ok) { std::fprintf(stderr, "Detours: %s (error %lu)\n", message, GetLastError()); ExitProcess(1); }
}
typedef ULONG_PTR (WINAPI *Function)();
Function original;
ULONG_PTR WINAPI Replacement() { return original() + 1; }
ULONG_PTR WINAPI WrongReplacement() { return 0; }
struct Code {
    BYTE* bytes;
    bool installed;
    Code() : bytes(static_cast<BYTE*>(VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))), installed(false)
    { Check(bytes != NULL, "allocate code"); }
    // Never release an executable target while its patch is still installed.
    ~Code() { if (!installed) VirtualFree(bytes, 0, MEM_RELEASE); }
    void Seal() {
        DWORD old;
        Check(VirtualProtect(bytes, 4096, PAGE_EXECUTE_READ, &old) != FALSE, "protect code");
        FlushInstructionCache(GetCurrentProcess(), bytes, 4096);
    }
    void CheckProtection() {
        MEMORY_BASIC_INFORMATION info = {};
        Check(VirtualQuery(bytes, &info, sizeof(info)) != 0 && info.Protect == PAGE_EXECUTE_READ,
            "restore page protection");
    }
};
void Exercise(const BYTE* instructions, size_t size, bool addressResult)
{
    Code code;
    std::memcpy(code.bytes, instructions, size);
    const BYTE destination[] = { 0xb8, 42, 0, 0, 0, 0xc3 };
    std::memcpy(code.bytes + 128, destination, sizeof(destination));
    code.Seal();
    Function entry = reinterpret_cast<Function>(code.bytes);
    original = entry;
    ULONG_PTR expected = addressResult ? reinterpret_cast<ULONG_PTR>(code.bytes + 128) : 42;
    Check(entry() == expected, "original code result");
    DetourHookBinding binding = { reinterpret_cast<PVOID*>(&original), Replacement };
    for (int cycle = 0; cycle < 3; ++cycle) {
        Check(InstallDetourHooks(&binding, 1) == NO_ERROR, "attach relocated code");
        code.installed = true;
        for (int i = 0; i < 1000; ++i)
            Check(entry() == expected + 1 && original() == expected, "hook and trampoline results");
        code.CheckProtection();
        // This test has no concurrent callers. Detach does not stop them for us.
        Check(RemoveDetourHooks(&binding, 1) == NO_ERROR, "explicit quiescent detach");
        code.installed = false;
        Check(original == entry && entry() == expected, "restore original pointer and behavior");
        Check(std::memcmp(code.bytes, instructions, size) == 0, "restore entry bytes");
        code.CheckProtection();
    }
}
struct WorkerState { Function entry; volatile LONG failures; };
DWORD WINAPI CallWorker(void* parameter)
{
    WorkerState* state = static_cast<WorkerState*>(parameter);
    for (int i = 0; i < 50000; ++i) {
        if (state->entry() != 43 || original() != 42) InterlockedIncrement(&state->failures);
    }
    return 0;
}
void ConcurrentCalls()
{
    Code code;
    const BYTE constant[] = { 0xb8, 42, 0, 0, 0, 0xc3 };
    std::memcpy(code.bytes, constant, sizeof(constant)); code.Seal();
    original = reinterpret_cast<Function>(code.bytes);
    WorkerState state = { original, 0 };
    DetourHookBinding binding = { reinterpret_cast<PVOID*>(&original), Replacement };
    Check(InstallDetourHooks(&binding, 1) == NO_ERROR, "install before concurrent calls");
    code.installed = true;
    // Exercise steady-state concurrency, not atomic publication (not guaranteed).
    HANDLE workers[4];
    for (int i = 0; i < 4; ++i) {
        workers[i] = CreateThread(NULL, 0, CallWorker, &state, 0, NULL);
        Check(workers[i] != NULL, "start worker");
    }
    Check(WaitForMultipleObjects(4, workers, TRUE, 10000) == WAIT_OBJECT_0, "join callers");
    for (int i = 0; i < 4; ++i) CloseHandle(workers[i]);
    Check(state.failures == 0, "concurrent persistent hook results");
    // The caller joins every worker before changing entry code or freeing trampolines.
    Check(RemoveDetourHooks(&binding, 1) == NO_ERROR, "detach after joining callers");
    code.installed = false;
    Check(state.entry() == 42 && original == state.entry, "native call after joined detach");
}

void DetachRollback()
{
    Code code;
    const BYTE constant[] = { 0xb8, 42, 0, 0, 0, 0xc3 };
    std::memcpy(code.bytes, constant, sizeof(constant));
    std::memcpy(code.bytes + 128, constant, sizeof(constant));
    code.Seal();
    Function entry = reinterpret_cast<Function>(code.bytes);
    Function secondEntry = reinterpret_cast<Function>(code.bytes + 128);
    original = entry;
    Function second = secondEntry;
    DetourHookBinding bindings[] = {
        { reinterpret_cast<PVOID*>(&original), Replacement },
        { reinterpret_cast<PVOID*>(&second), WrongReplacement }
    };
    Check(InstallDetourHooks(bindings, 2) == NO_ERROR, "install detach rollback batch");
    code.installed = true;
    Function firstTrampoline = original, secondTrampoline = second;
    BYTE patched[16];
    std::memcpy(patched, code.bytes, sizeof(patched));
    DetourHookBinding wrong[] = { bindings[0], { bindings[1].original, Replacement } };
    DetourHookFailure failure = {};
    Check(RemoveDetourHooks(wrong, 2, &failure) != NO_ERROR, "reject second mismatched detach");
    Check(failure.bindingIndex == 1 && !std::strcmp(failure.stage, "DetourDetach"), "identify failed detach binding");
    Check(original == firstTrampoline && second == secondTrampoline, "failed detach preserves pointers");
    Check(std::memcmp(code.bytes, patched, sizeof(patched)) == 0, "failed detach preserves first patch");
    Check(entry() == 43 && secondEntry() == 0 && second() == 42, "failed detach preserves both hooks");
    code.CheckProtection();
    Check(RemoveDetourHooks(bindings, 2) == NO_ERROR, "retry correct detach batch");
    code.installed = false;
    Check(original == entry && second == secondEntry && entry() == 42 && secondEntry() == 42,
        "successful detach restores both functions");
    Check(std::memcmp(code.bytes, constant, sizeof(constant)) == 0 &&
        std::memcmp(code.bytes + 128, constant, sizeof(constant)) == 0, "restore both entry patches");
}
void Rollback()
{
    Code code;
    const BYTE constant[] = { 0xb8, 42, 0, 0, 0, 0xc3 };
    std::memcpy(code.bytes, constant, sizeof(constant));
    code.bytes[128] = 0xc3; // Too short, followed by non-padding bytes.
    code.Seal();
    original = reinterpret_cast<Function>(code.bytes);
    Function tooShort = reinterpret_cast<Function>(code.bytes + 128);
    DetourHookBinding bindings[] = { { reinterpret_cast<PVOID*>(&original), Replacement }, { reinterpret_cast<PVOID*>(&tooShort), WrongReplacement } };
    DetourHookFailure failure = {};
    Check(InstallDetourHooks(NULL, 1, &failure) == ERROR_INVALID_PARAMETER, "reject missing bindings");
    Check(failure.bindingIndex == size_t(-1) && !std::strcmp(failure.stage, "validate-bindings"), "identify invalid batch");
    DetourHookBinding duplicates[] = { bindings[0], bindings[0] };
    Check(InstallDetourHooks(duplicates, 2, &failure) == ERROR_INVALID_PARAMETER, "reject duplicate binding");
    Check(failure.bindingIndex == 1 && !std::strcmp(failure.stage, "validate-bindings"), "identify duplicate binding");
    Check(InstallDetourHooks(bindings, 2, &failure) == ERROR_INVALID_BLOCK, "reject unrelocatable batch");
    Check(failure.bindingIndex == 1 && !std::strcmp(failure.stage, "DetourAttach"), "identify unrelocatable API");
    HookFailureDiagnostics diagnostic;
    diagnostic.Set(ERROR_INVALID_BLOCK, failure.stage, "test.dll", "TooShort");
    SetLastError(ERROR_ACCESS_DENIED); // Cleanup must not change the recorded failure.
    WCHAR message[1536] = {};
    diagnostic.Format(message, _countof(message), L"C:\\test\\Antigravity.exe", 58660);
    Check(wcsstr(message, L"Antigravity.exe (58660)") && wcsstr(message, L"stage=DetourAttach") &&
        wcsstr(message, L"module=test.dll") && wcsstr(message, L"API=TooShort") &&
        wcsstr(message, L"error=9 (0x00000009)"), "complete immutable diagnostic");
    diagnostic.Set(0, "allocate-tls", "kernel32.dll", "TlsAlloc");
    diagnostic.Format(message, _countof(message), L"test.exe", 1);
    Check(wcsstr(message, L"No error code supplied"), "do not invent an original error code");
    Check(original == reinterpret_cast<Function>(code.bytes) && original() == 42, "abort leaves first pointer unchanged");
    Check(tooShort == reinterpret_cast<Function>(code.bytes + 128), "abort leaves second pointer unchanged");
    Check(std::memcmp(code.bytes, constant, sizeof(constant)) == 0, "abort leaves code unchanged");
    code.CheckProtection();
    Check(InstallDetourHooks(bindings, 1) == NO_ERROR, "retry valid installation after abort");
    code.installed = true;
    Check(reinterpret_cast<Function>(code.bytes)() == 43 && original() == 42, "retry hook and trampoline results");
}
void RunCase(const char* name)
{
    char executable[MAX_PATH] = {};
    DWORD length = GetModuleFileNameA(NULL, executable, MAX_PATH);
    Check(length > 0 && length < MAX_PATH, "test executable path");
    char command[MAX_PATH + 80];
    sprintf_s(command, "\"%s\" --detours-case %s", executable, name);
    STARTUPINFOA startup = { sizeof(startup) };
    PROCESS_INFORMATION process = {};
    Check(CreateProcessA(executable, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process) != FALSE,
        "start isolated Detours case");
    DWORD wait = WaitForSingleObject(process.hProcess, 15000);
    if (wait != WAIT_OBJECT_0) TerminateProcess(process.hProcess, 1);
    DWORD result = 1;
    GetExitCodeProcess(process.hProcess, &result);
    CloseHandle(process.hThread); CloseHandle(process.hProcess);
    Check(wait == WAIT_OBJECT_0 && result == 0, name);
}
}
int DetourHooksTestCase(const char* name)
{
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    const BYTE call[] = { 0xe8, 123, 0, 0, 0, 0xc3 };
    const BYTE shortBranch[] = { 0x31, 0xc0, 0x74, 124, 0x90, 0xc3 };
    const BYTE nearBranch[] = { 0x31, 0xc0, 0x0f, 0x84, 120, 0, 0, 0, 0xc3 };
    if (!std::strcmp(name, "call")) Exercise(call, sizeof(call), false);
    else if (!std::strcmp(name, "short-branch")) Exercise(shortBranch, sizeof(shortBranch), false);
    else if (!std::strcmp(name, "near-branch")) Exercise(nearBranch, sizeof(nearBranch), false);
#ifdef _WIN64
    else if (!std::strcmp(name, "rip-lea")) {
        const BYTE lea[] = { 0x48, 0x8d, 0x05, 121, 0, 0, 0, 0xc3 };
        Exercise(lea, sizeof(lea), true);
    }
    else if (!std::strcmp(name, "rip-mov")) {
        const BYTE mov[] = { 0x8b, 0x05, 123, 0, 0, 0, 0xc3 };
        Exercise(mov, sizeof(mov), false);
    }
#endif
    else if (!std::strcmp(name, "rollback")) Rollback();
    else if (!std::strcmp(name, "detach-rollback")) DetachRollback();
    else if (!std::strcmp(name, "concurrent")) ConcurrentCalls();
    else return 2;
    return 0;
}
int DetourHooksTestsMain()
{
    RunCase("call"); RunCase("short-branch"); RunCase("near-branch");
#ifdef _WIN64
    RunCase("rip-lea"); RunCase("rip-mov");
#endif
    RunCase("rollback"); RunCase("detach-rollback"); RunCase("concurrent");
    std::puts("Detours relocation, attach/detach rollback, quiescent cycles and concurrent callers passed");
    return 0;
}
