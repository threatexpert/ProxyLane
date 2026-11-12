// Run ONLY on Windows ARM64. Exercises the production injector against our own
// disposable child and a minimal fixture DLL, independently of GUI/PRC/network.
#include "InjectionFixture.h"
#include "../../src/ProxyLaneHook/InjectDllArm64.h"
#include "../../src/remotecode/arm64/BootstrapBytes.h"
#include <iostream>
#include <string>
#include <stdexcept>

static void Check(bool ok, const char* what)
{
    if (!ok) throw std::runtime_error(std::string(what) + " (Win32=" + std::to_string(GetLastError()) + ")");
}

struct Child
{
    PROCESS_INFORMATION pi = {};
    HANDLE mapping = NULL, ready = NULL, hook = NULL, finish = NULL;
    InjectionFixtureState* state = NULL;
    std::string name;
    ~Child()
    {
        if (pi.hProcess)
        {
            if (WaitForSingleObject(pi.hProcess, 0) == WAIT_TIMEOUT)
            {
                // Only terminate the disposable child created by this test.
                TerminateProcess(pi.hProcess, 99);
                WaitForSingleObject(pi.hProcess, 5000);
            }
            CloseHandle(pi.hProcess);
        }
        if (pi.hThread) CloseHandle(pi.hThread);
        if (state) UnmapViewOfFile(state);
        if (mapping) CloseHandle(mapping);
        if (ready) CloseHandle(ready);
        if (hook) CloseHandle(hook);
        if (finish) CloseHandle(finish);
    }
    void Start(int sequence, bool suspended, LONG result, LONG expectedAtMain,
        LPCWSTR application = NULL, LPCWSTR arguments = NULL)
    {
        name = "Local\\ProxyLaneArm64Injection-" + std::to_string(GetCurrentProcessId()) + "-" + std::to_string(sequence);
        mapping = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(*state), name.c_str());
        Check(mapping != NULL, "CreateFileMapping");
        state = static_cast<InjectionFixtureState*>(MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(*state)));
        Check(state != NULL, "MapViewOfFile");
        state->hookResult = result;
        state->expectedCallsAtMain = expectedAtMain;
        ready = CreateEventA(NULL, TRUE, FALSE, (name + "Ready").c_str());
        hook = CreateEventA(NULL, TRUE, FALSE, (name + "Hook").c_str());
        finish = CreateEventA(NULL, TRUE, FALSE, (name + "Finish").c_str());
        Check(ready && hook && finish, "CreateEvent");
        WCHAR self[32768];
        DWORD length = GetModuleFileNameW(NULL, self, _countof(self));
        Check(length && length < _countof(self), "GetModuleFileName");
        std::wstring command = L"\"" + std::wstring(self) + L"\" --child " + std::wstring(name.begin(), name.end());
        if (application) command = L"\"" + std::wstring(application) + L"\" " + (arguments ? arguments : L"");
        STARTUPINFOW si = { sizeof(si) };
        Check(CreateProcessW(application ? application : self, &command[0], NULL, NULL, FALSE, suspended ? CREATE_SUSPENDED : 0,
            NULL, NULL, &si, &pi) != FALSE, "CreateProcess");
        if (!suspended) WaitReady();
    }
    void WaitReady() { Check(WaitForSingleObject(ready, 15000) == WAIT_OBJECT_0, "Child main did not run"); }
    void Complete()
    {
        SetEvent(finish);
        Check(WaitForSingleObject(pi.hProcess, 15000) == WAIT_OBJECT_0, "Child exit timeout");
        DWORD code = 99;
        Check(GetExitCodeProcess(pi.hProcess, &code) && code == 0, "Child state/order or execution was corrupted");
    }
};

static int ChildMain(const char* name)
{
    HANDLE mapping = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, name);
    if (!mapping) return 10;
    InjectionFixtureState* state = static_cast<InjectionFixtureState*>(
        MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(InjectionFixtureState)));
    if (!state) { CloseHandle(mapping); return 11; }
    bool ok = state->calls == state->expectedCallsAtMain;
    InterlockedExchange(&state->mainEntered, 1);
    HANDLE ready = OpenEventA(EVENT_MODIFY_STATE, FALSE, (std::string(name) + "Ready").c_str());
    HANDLE finish = OpenEventA(SYNCHRONIZE, FALSE, (std::string(name) + "Finish").c_str());
    if (ready) SetEvent(ready);
    ok = finish && WaitForSingleObject(finish, 30000) == WAIT_OBJECT_0 && ok;
    if (ready) CloseHandle(ready);
    if (finish) CloseHandle(finish);
    UnmapViewOfFile(state);
    CloseHandle(mapping);
    return ok ? 0 : 12;
}

static ULONG64 ReadRemoteQword(HANDLE process, ULONG64 address)
{
    ULONG64 value = 0;
    SIZE_T read = 0;
    Check(ReadProcessMemory(process, reinterpret_cast<void*>(address), &value, sizeof(value), &read) &&
        read == sizeof(value), "ReadProcessMemory");
    return value;
}

struct SmallStackInjection
{
    HANDLE process, thread;
    LPCWSTR dll;
    LPCSTR pipe;
    int result;
    DWORD error;
};

static DWORD WINAPI InjectOnSmallStack(void* parameter)
{
    SmallStackInjection& call = *static_cast<SmallStackInjection*>(parameter);
    try
    {
        call.result = InjectDllArm64W(call.process, call.thread, call.dll, call.pipe);
        call.error = GetLastError();
        return 0;
    }
    catch (...)
    {
        return 1;
    }
}

static void ScheduleOnSmallStack(HANDLE process, HANDLE thread, LPCWSTR dll, LPCSTR pipe)
{
    SmallStackInjection call = { process, thread, dll, pipe, -1, ERROR_SUCCESS };
    // The old resolver alone used over 192 KiB. Reserve only 128 KiB so this
    // exercises the production injector under a constrained caller stack.
    HANDLE worker = CreateThread(NULL, 128 * 1024, InjectOnSmallStack, &call,
        STACK_SIZE_PARAM_IS_A_RESERVATION, NULL);
    Check(worker != NULL, "Create small-stack injection thread");
    DWORD wait = WaitForSingleObject(worker, INFINITE);
    DWORD exitCode = 1;
    BOOL gotExitCode = GetExitCodeThread(worker, &exitCode);
    CloseHandle(worker);
    Check(wait == WAIT_OBJECT_0 && gotExitCode && exitCode == 0, "Small-stack worker failed");
    SetLastError(call.error);
    Check(call.result == 1, "Schedule injection from 128 KiB stack");
}

int main(int argc, char** argv)
{
    if (argc == 3 && std::string(argv[1]) == "--child") return ChildMain(argv[2]);
    try
    {
        WCHAR self[32768];
        DWORD length = GetModuleFileNameW(NULL, self, _countof(self));
        Check(length && length < _countof(self), "GetModuleFileName");
        std::wstring directory(self);
        directory.resize(directory.find_last_of(L'\\') + 1);
        std::wstring dll = directory + L"InjectionFixtureARM64.dll";
        WCHAR system[32768];
        length = GetSystemDirectoryW(system, _countof(system));
        Check(length && length < _countof(system), "GetSystemDirectory");
        std::wstring noExport = std::wstring(system) + L"\\ntdll.dll";
        int sequence = 0;
        for (int mode = 0; mode < 2; ++mode)
        {
            // startup: success, DLL missing, export missing, hook returned false.
            // running: success and false; emulator covers remaining error states.
            for (int failure = 0; failure < 4; ++failure)
            {
                if (mode == 1 && (failure == 1 || failure == 2)) continue;
                bool startup = mode == 0;
                LONG expectedCalls = failure == 0 || failure == 3 ? 1 : 0;
                Child child;
                child.Start(++sequence, startup, failure != 3, startup ? expectedCalls : 0);
                std::wstring path = failure == 1 ? directory + L"MissingFixture.dll" : failure == 2 ? noExport : dll;
                Check(InjectDllArm64W(child.pi.hProcess, startup ? child.pi.hThread : NULL,
                    path.c_str(), child.name.c_str()) == 1, "Schedule injection");
                ULONG64 parameters = 0;
                if (startup)
                {
                    CONTEXT context = {};
                    context.ContextFlags = CONTEXT_CONTROL;
                    Check(GetThreadContext(child.pi.hThread, &context) != FALSE, "GetThreadContext");
                    parameters = ReadRemoteQword(child.pi.hProcess,
                        context.Pc - Arm64Bootstrap::StartupOffset + Arm64Bootstrap::ParameterAddressOffset);
                    MEMORY_BASIC_INFORMATION code = {}, data = {};
                    Check(VirtualQueryEx(child.pi.hProcess, reinterpret_cast<void*>(context.Pc), &code, sizeof(code)) &&
                        code.Protect == PAGE_EXECUTE_READ, "Code must be RX");
                    Check(VirtualQueryEx(child.pi.hProcess, reinterpret_cast<void*>(parameters), &data, sizeof(data)) &&
                        data.Protect == PAGE_READWRITE, "Parameters must be RW");
                    Check(ResumeThread(child.pi.hThread) == 1, "Caller suspension was changed");
                    child.WaitReady();
                    DWORD state = static_cast<DWORD>(ReadRemoteQword(child.pi.hProcess, parameters + 72));
                    DWORD expected = failure == 0 ? 5 : failure == 1 ? 2 : failure == 2 ? 3 : 4;
                    Check(state == expected, "Unexpected bootstrap state");
                }
                if (expectedCalls) Check(WaitForSingleObject(child.hook, 15000) == WAIT_OBJECT_0, "Hook callback timeout");
                Check(child.state->calls == expectedCalls && child.state->mainEntered == 1, "Callback count/main entry");
                child.Complete();
                std::cout << (startup ? "startup" : "running") << " case " << failure << " passed\n";
            }
        }
        // Firefox's child-creation hook executes on a caller-owned thread.
        // Test both startup and running attachment with a small caller stack,
        // then verify the real remote callback and the child's normal exit.
        for (int mode = 0; mode < 2; ++mode)
        {
            bool startup = mode == 0;
            Child child;
            child.Start(++sequence, startup, TRUE, startup ? 1 : 0);
            ScheduleOnSmallStack(child.pi.hProcess, startup ? child.pi.hThread : NULL,
                dll.c_str(), child.name.c_str());
            if (startup)
            {
                Check(ResumeThread(child.pi.hThread) == 1, "Small-stack injection changed suspension");
                child.WaitReady();
            }
            Check(WaitForSingleObject(child.hook, 15000) == WAIT_OBJECT_0, "Small-stack callback timeout");
            Check(child.state->calls == 1 && child.state->mainEntered == 1, "Small-stack callback/main entry");
            child.Complete();
            std::cout << (startup ? "startup" : "running") << " injection on 128 KiB stack passed\n";
        }
        // Regress the real system ARM64X executables in their native ARM64
        // execution mode, not merely a pure-ARM64 test executable. The fixture
        // signals from gp_HookWinsock; both shells must then exit normally.
        const wchar_t* shells[] = { L"\\cmd.exe", L"\\WindowsPowerShell\\v1.0\\powershell.exe" };
        const wchar_t* arguments[] = { L"/d /c exit /b 0", L"-NoLogo -NoProfile -NonInteractive -Command \"exit 0\"" };
        for (int i = 0; i < 2; ++i)
        {
            std::wstring shell = std::wstring(system) + shells[i];
            Child child;
            child.Start(++sequence, true, TRUE, 0, shell.c_str(), arguments[i]);
            Check(InjectDllArm64W(child.pi.hProcess, child.pi.hThread, dll.c_str(), child.name.c_str()) == 1,
                "Schedule native system shell injection");
            Check(ResumeThread(child.pi.hThread) == 1, "System shell suspension changed");
            Check(WaitForSingleObject(child.hook, 15000) == WAIT_OBJECT_0, "System shell hook callback timeout");
            Check(child.state->calls == 1, "System shell callback count");
            child.Complete();
            std::cout << (i ? "powershell.exe" : "cmd.exe") << " native injection passed\n";
        }
        // A thread belonging to another process must not redirect either child.
        Child first, second;
        first.Start(++sequence, true, TRUE, 0);
        second.Start(++sequence, true, TRUE, 0);
        Check(InjectDllArm64W(first.pi.hProcess, second.pi.hThread, dll.c_str(), first.name.c_str()) == -1 &&
            GetLastError() == ERROR_INVALID_PARAMETER, "Reject mismatched process/thread");
        Check(InjectDllArm64W(first.pi.hProcess, first.pi.hThread, L"relative.dll", first.name.c_str()) == -1 &&
            GetLastError() == ERROR_INVALID_PARAMETER, "Reject relative DLL path");
        Check(ResumeThread(first.pi.hThread) == 1 && ResumeThread(second.pi.hThread) == 1, "Failure changed suspension");
        first.WaitReady(); second.WaitReady();
        first.Complete(); second.Complete();
        std::cout << "ARM64 native injection tests passed\n";
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << "FAILED: " << error.what() << '\n';
        return 1;
    }
}
