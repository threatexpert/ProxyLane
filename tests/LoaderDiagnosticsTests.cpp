#include "../src/ProxyLane/LoaderDiagnosticCapture.h"
#include "../src/remotecode/remoteCode.h"
#include "../src/ProxyLaneHook/HookFailureDiagnostics.h"
#include <stdio.h>
#include <wchar.h>
#ifdef _WIN64
#include "../src/remotecode/remoteCode.x64.inc"
#else
#include "../src/remotecode/remoteCode.x86.inc"
#endif

static void Check(bool ok, const char* text)
{
    if (!ok) { fprintf(stderr, "FAIL: %s (error %lu)\n", text, GetLastError()); ExitProcess(1); }
}

static void ExecuteLoader(const wchar_t* path, bool success)
{
    myapi api = {};
    api.LoadLibraryW = LoadLibraryW;
    api.GetProcAddress = GetProcAddress;
    api.GetLastError = GetLastError;
    api.FormatMessageA = FormatMessageA;
    api.OutputDebugStringA = OutputDebugStringA;
    api.noSleep = true;
    api.retval = 0x12345678;
    wcscpy_s(api.szMyDll, path);
    strcpy_s(api.loadFailureFormat, "[ProxyLane.Loader.v1] stage=LoadLibraryW error=%1!08X!\n");
    void* code = VirtualAlloc(NULL, sizeof(sc_ldr), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    Check(code != NULL, "allocate copied loader");
    memcpy(code, sc_ldr, sizeof(sc_ldr));
    DWORD old;
    Check(VirtualProtect(code, sizeof(sc_ldr), PAGE_EXECUTE_READ, &old) != FALSE, "protect loader");
    FlushInstructionCache(GetCurrentProcess(), code, sizeof(sc_ldr));
    auto run = reinterpret_cast<DWORD_PTR (WINAPI*)(LPVOID)>(code);
    Check(run(&api) == api.retval, "copied loader return value");
    Check((api.status == 1) == success, "copied loader status");
    VirtualFree(code, 0, MEM_RELEASE);
}

static DWORD Child(const wchar_t* executable, const wchar_t* arguments)
{
    wchar_t command[2048];
    swprintf_s(command, L"\"%s\" %s", executable, arguments);
    STARTUPINFOW startup = { sizeof(startup) };
    PROCESS_INFORMATION process = {};
    Check(CreateProcessW(NULL, command, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL,
        &startup, &process) != FALSE, "create test sender");
    Check(WaitForSingleObject(process.hProcess, 10000) == WAIT_OBJECT_0, "sender completion");
    DWORD exitCode;
    Check(GetExitCodeProcess(process.hProcess, &exitCode) && exitCode == 0, "sender exit");
    DWORD pid = process.dwProcessId;
    CloseHandle(process.hThread); CloseHandle(process.hProcess);
    return pid;
}

int wmain(int argc, wchar_t** argv)
{
    if (argc > 2 && !wcscmp(argv[1], L"--target")) {
        Check(GetModuleHandleW(argv[2]) != NULL, "real injected Hook loaded before entry point");
        return 0;
    }
    if (argc == 4 && !wcscmp(argv[1], L"--inject")) {
        HMODULE hook = LoadLibraryW(argv[2]);
        Check(hook != NULL, "load injector from Unicode path");
        typedef DWORD (WINAPI *Attach)(DWORD, DWORD, LPCSTR);
        Attach attach = reinterpret_cast<Attach>(GetProcAddress(hook, "AttachToI"));
        Check(attach != NULL, "resolve actual injector");
        wchar_t command[2048];
        swprintf_s(command, L"\"%s\" --target \"%s\"", argv[3], argv[2]);
        STARTUPINFOW startup = { sizeof(startup) };
        PROCESS_INFORMATION process = {};
        Check(CreateProcessW(NULL, command, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW,
            NULL, NULL, &startup, &process) != FALSE, "create suspended target");
        DWORD result = attach(process.dwProcessId, process.dwThreadId,
            "\\\\.\\pipe\\ProxyLane.LoaderDiagnostics.NoServer");
        if (result != 0xFF01) TerminateProcess(process.hProcess, 1);
        Check(result == 0xFF01, "actual injector prepared");
        Check(ResumeThread(process.hThread) != DWORD(-1), "release target");
        DWORD wait = WaitForSingleObject(process.hProcess, 10000);
        if (wait != WAIT_OBJECT_0) TerminateProcess(process.hProcess, 1);
        Check(wait == WAIT_OBJECT_0, "injected target resumed and exited");
        DWORD exitCode;
        Check(GetExitCodeProcess(process.hProcess, &exitCode) && !exitCode, "real injection result");
        CloseHandle(process.hThread); CloseHandle(process.hProcess);
        FreeLibrary(hook);
        puts("PASS: real Hook injection/trampoline from Unicode path");
        return 0;
    }
    if (argc > 1 && !wcscmp(argv[1], L"--emit")) {
        OutputDebugStringA("unrelated application output\n");
        OutputDebugStringA("[ProxyLane.Loader.v1] stage=LoadLibraryW error=NOTHEX!!\n");
        ExecuteLoader(L"Z:\\ProxyLane-不存在-9B53\\missing.dll", false);
        HookFailureDiagnostics failure;
        failure.Set(ERROR_ACCESS_DENIED, "connect-control-pipe", "kernel32.dll", "CreateFile/WaitNamedPipe");
        WCHAR message[1536];
        failure.Format(message, _countof(message), L"C:\\测试\\fixture.exe", GetCurrentProcessId());
        Check(wcsncmp(message, L"[ProxyLane.Hook.v1] ", 20) == 0, "sender uses namespaced Hook prefix");
        OutputDebugStringW(message);
        OutputDebugStringW(L"[Hook failure] legacy.exe (1) | stage=read-startup-info | module=PRC | API=GetPRCStartupInfo | error=87 (0x00000057) | Legacy report");
        return 0;
    }
    if (argc > 2 && !wcscmp(argv[1], L"--load")) {
        ExecuteLoader(argv[2], true);
        printf("Unicode load OK; ACP=%u\n", GetACP());
        return 0;
    }
    Check(argc == 3, "pass both architecture sender paths");
    LoaderDiagnosticCapture capture;
    DWORD error = capture.Start();
    if (error) { fprintf(stderr, "Cannot own DBWIN channel (close other monitors): %lu\n", error); return 1; }
    LoaderDiagnosticCapture other;
    Check(other.Start() == ERROR_ALREADY_EXISTS, "second monitor must not steal channel");
    for (int i = 1; i <= 2; ++i) {
        DWORD pid = Child(argv[i], L"--emit");
        LoaderDiagnosticCapture::Record records[8];
        unsigned count = 0, dropped = 0;
        for (int j = 0; j < 100 && count < 2; ++j) {
            count += capture.Drain(records + count, 8 - count, dropped);
            if (count < 2) Sleep(10);
        }
        Check(count == 2 && dropped == 0, "only namespaced loader and Hook reports accepted");
        Check(records[0].processId == pid, "DBWIN sender PID");
        Check(records[0].error == ERROR_MOD_NOT_FOUND, "original LoadLibrary error preserved");
        Check(!records[0].hookFailure && records[1].hookFailure && records[1].processId == pid,
            "diagnostic type and real sender identity");
        Check(records[1].error == ERROR_ACCESS_DENIED &&
            !strcmp(records[1].stage, "connect-control-pipe") &&
            !strcmp(records[1].module, "kernel32.dll") &&
            !strcmp(records[1].api, "CreateFile/WaitNamedPipe"), "actual Hook failure formatter parsed");
    }
    LoaderDiagnosticCapture::Record invalid = {};
    char unterminated[4092]; memset(unterminated, 'x', sizeof(unterminated));
    memcpy(unterminated, "[ProxyLane.Hook.v1] ", 20);
    Check(!capture.ParseHookFailure(unterminated, sizeof(unterminated), invalid), "unterminated report rejected");
    const char overflow[] = "[ProxyLane.Hook.v1] x (1) | stage=a | module=b | API=c | error=4294967296 (0x00000000) | text";
    Check(!capture.ParseHookFailure(overflow, sizeof(overflow), invalid), "overflow error rejected");
    const char unknownVersion[] = "[ProxyLane.Hook.v2] x (1) | stage=a | module=b | API=c | error=5 (0x00000005) | text";
    Check(!capture.ParseHookFailure(unknownVersion, sizeof(unknownVersion), invalid), "unknown Hook version rejected");
    const char oldPrefix[] = "[Hook failure] x (1) | stage=a | module=b | API=c | error=5 (0x00000005) | text";
    Check(!capture.ParseHookFailure(oldPrefix, sizeof(oldPrefix), invalid), "old Hook prefix rejected");
    // Bounded queue under a burst, without a consuming UI thread.
    for (int i = 0; i < 256; ++i)
        OutputDebugStringA("[ProxyLane.Loader.v1] stage=LoadLibraryW error=0000007E\n");
    Sleep(50);
    LoaderDiagnosticCapture::Record records[256];
    unsigned dropped;
    Check(capture.Drain(records, 256, dropped) == 128 && dropped == 128, "bounded burst queue");
    capture.Stop();
    for (int i = 0; i < 10; ++i) {
        Check(capture.Start() == ERROR_SUCCESS, "restart capture");
        DWORD start = GetTickCount();
        capture.Stop();
        Check(GetTickCount() - start < 1000, "stop idle capture promptly");
    }
    // Existing individual event must also be treated as occupied, untouched.
    HANDLE event = CreateEventW(NULL, TRUE, FALSE, L"DBWIN_DATA_READY");
    Check(event != NULL, "occupancy fixture");
    Check(capture.Start() == ERROR_ALREADY_EXISTS, "partial occupied channel");
    Check(WaitForSingleObject(event, 0) == WAIT_TIMEOUT, "foreign event not signaled");
    CloseHandle(event);
    Check(capture.Start() == ERROR_SUCCESS, "cleanup after failed startup");
    capture.Stop();
    puts("PASS: copied x86/x64 loaders, real cross-process capture, filtering, contention, bounded queue, lifecycle");
    return 0;
}
