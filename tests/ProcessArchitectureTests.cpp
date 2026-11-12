#include "ProcessArchitecture.h"
#include <iostream>

namespace
{
    using namespace ProcessArchitecture;
    USHORT processMachine, nativeMachine, processor;
    DWORD major, build;
    BOOL modernSuccess, legacySuccess, wow;
    int legacyCalls;
    BOOL WINAPI Modern(HANDLE, USHORT* process, USHORT* native)
    {
        if (!modernSuccess) { SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
        *process = processMachine; *native = nativeMachine;
        return TRUE;
    }
    BOOL WINAPI Legacy(HANDLE, PBOOL value)
    {
        ++legacyCalls;
        if (!legacySuccess) { SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
        *value = wow;
        return TRUE;
    }
    VOID WINAPI System(LPSYSTEM_INFO info) { info->wProcessorArchitecture = processor; }
    LONG WINAPI Version(OSVERSIONINFOW* info)
    {
        info->dwMajorVersion = major; info->dwBuildNumber = build;
        return 0;
    }
    LONG WINAPI FailedVersion(OSVERSIONINFOW*) { return -1; }
}

int ProcessArchitectureTestsMain()
{
    using namespace ProcessArchitecture;
    int failures = 0;
#define CHECK(expression) do { if (!(expression)) { \
    std::cerr << "Architecture check failed at line " << __LINE__ << ": " << #expression << std::endl; \
    ++failures; } } while (0)
    Api api = { Modern, Legacy, System, Version };
    modernSuccess = legacySuccess = TRUE;
    major = 6; build = 7601; processor = PROCESSOR_ARCHITECTURE_AMD64;
    ProcessInfo info;
    const USHORT machines[] = { 0x014c, 0x8664, 0xaa64 };
    const Architecture architectures[] = { X86, X64, Arm64 };
    for (int native = 0; native < 3; ++native)
    {
        nativeMachine = machines[native];
        processMachine = 0; // A native process is reported as UNKNOWN, not nativeMachine.
        CHECK(Query(GetCurrentProcess(), info, api));
        CHECK(info.process == architectures[native] && info.native == architectures[native]);
    }
    // x86 and x64 emulation on ARM64 must remain distinct from native ARM64.
    nativeMachine = 0xaa64;
    for (int process = 0; process < 2; ++process)
    {
        processMachine = machines[process];
        CHECK(Query(GetCurrentProcess(), info, api));
        CHECK(info.process == architectures[process] && info.native == Arm64);
    }
    nativeMachine = 0x8664; processMachine = 0x014c;
    CHECK(Query(GetCurrentProcess(), info, api));
    CHECK(info.process == X86 && info.native == X64);
    modernSuccess = FALSE; legacyCalls = 0;
    CHECK(!Query(GetCurrentProcess(), info, api));
    CHECK(GetLastError() == ERROR_ACCESS_DENIED);
    CHECK(info.process == Unknown && info.native == Unknown && legacyCalls == 0);
    modernSuccess = TRUE;
    const USHORT unsupported[] = { 0xa641, 0xa64e, 0x01c4, 0xffff };
    for (int i = 0; i < _countof(unsupported); ++i)
    {
        processMachine = unsupported[i];
        CHECK(!Query(GetCurrentProcess(), info, api));
        CHECK(GetLastError() == ERROR_NOT_SUPPORTED && info.process == Unknown);
    }
    nativeMachine = 0; processMachine = 0x8664;
    CHECK(!Query(GetCurrentProcess(), info, api));
    CHECK(info.native == Unknown && info.process == Unknown);
    CHECK(!Query(NULL, info, api));
    CHECK(GetLastError() == ERROR_INVALID_HANDLE);

    api.wow64Process2 = NULL;
    wow = TRUE;
    CHECK(Query(GetCurrentProcess(), info, api));
    CHECK(info.process == X86 && info.native == X64);
    wow = FALSE;
    CHECK(Query(GetCurrentProcess(), info, api));
    CHECK(info.process == X64 && info.native == X64);
    processor = PROCESSOR_ARCHITECTURE_INTEL; major = 5;
    CHECK(Query(GetCurrentProcess(), info, api));
    CHECK(info.process == X86 && info.native == X86);
    wow = TRUE; // Impossible pair: don't guess.
    CHECK(!Query(GetCurrentProcess(), info, api));
    wow = FALSE; legacySuccess = FALSE;
    CHECK(!Query(GetCurrentProcess(), info, api));
    CHECK(GetLastError() == ERROR_ACCESS_DENIED && info.process == Unknown);
    legacySuccess = TRUE; processor = 12; // ARM64 SYSTEM_INFO cannot use the old fallback.
    CHECK(!Query(GetCurrentProcess(), info, api));
    processor = PROCESSOR_ARCHITECTURE_AMD64; major = 10; build = 16298;
    CHECK(Query(GetCurrentProcess(), info, api));
    build = 16299; legacyCalls = 0;
    CHECK(!Query(GetCurrentProcess(), info, api));
    CHECK(GetLastError() == ERROR_NOT_SUPPORTED && legacyCalls == 0);
    major = 6; api.version = FailedVersion;
    CHECK(!Query(GetCurrentProcess(), info, api));
    api.version = NULL;
    CHECK(!Query(GetCurrentProcess(), info, api));
    api.version = Version; api.wow64Process = NULL;
    CHECK(!Query(GetCurrentProcess(), info, api));
    api.wow64Process = Legacy; api.nativeSystemInfo = NULL;
    CHECK(!Query(GetCurrentProcess(), info, api));

    info.native = X64;
    info.process = X86;
    CHECK(Route(X86, info) == Direct && Route(X64, info) == Helper);
    CHECK(_tcscmp(LegacyRundllDirectory(info), _T("SysWOW64")) == 0);
    info.process = X64;
    CHECK(Route(X64, info) == Direct && Route(X86, info) == Helper);
    CHECK(_tcscmp(LegacyRundllDirectory(info), _T("System32")) == 0);
    info.native = X86;
    CHECK(Route(X64, info) == Unsupported && LegacyRundllDirectory(info) == NULL);
    info.process = X86;
    CHECK(Route(X86, info) == Direct);
    CHECK(_tcscmp(LegacyRundllDirectory(info), _T("System32")) == 0);
    // Enable only the native same-architecture route on Windows on ARM.
    info.native = Arm64;
    for (int source = 0; source < 3; ++source)
        for (int target = 0; target < 3; ++target)
        {
            info.process = architectures[target];
            CHECK(Route(architectures[source], info) ==
                (source == 2 && target == 2 ? Direct : Unsupported));
            CHECK(LegacyRundllDirectory(info) == NULL);
        }
    info.native = X64; info.process = Unknown;
    CHECK(Route(X64, info) == Unsupported);
    info.process = X64;
    CHECK(Route(Unknown, info) == Unsupported);
    info.native = Unknown;
    CHECK(Route(X64, info) == Unsupported);
    CHECK(HookFileName(Unknown) == NULL && ApplicationFileName(Unknown) == NULL && TransportFileName(Unknown) == NULL);
    CHECK(_tcscmp(HookFileName(X86), _T("ProxyLaneHook32.dll")) == 0);
    CHECK(_tcscmp(HookFileName(X64), _T("ProxyLaneHook64.dll")) == 0);
    CHECK(_tcscmp(HookFileName(Arm64), _T("ProxyLaneHookARM64.dll")) == 0);
    CHECK(_tcscmp(ApplicationFileName(Arm64), _T("ProxyLaneARM64.exe")) == 0);
    CHECK(_tcscmp(TransportFileName(Arm64), _T("ProxyLaneSecureTransportARM64.dll")) == 0);

    CHECK(MitmFileName(Unknown) == NULL && MitmFileName(X86) == NULL);
    CHECK(_tcscmp(MitmFileName(X64), _T("ProxyLaneMitm64.dll")) == 0);
    CHECK(_tcscmp(MitmFileName(Arm64), _T("ProxyLaneMitmARM64.dll")) == 0);

    CHECK(SshFileName(Unknown) == NULL && SshFileName(X86) == NULL);
    CHECK(_tcscmp(SshFileName(X64), _T("ProxyLaneSsh64.dll")) == 0);
    CHECK(_tcscmp(SshFileName(Arm64), _T("ProxyLaneSshARM64.dll")) == 0);
    CHECK(ElevatedHelperFileName(Unknown) == NULL && ElevatedHelperFileName(X86) == NULL && ElevatedHelperFileName(X64) == NULL);
    CHECK(_tcscmp(ElevatedHelperFileName(Arm64), _T("ProxyLaneElevatedARM64.exe")) == 0);

    // Exercise the actual dynamically-resolved Windows API as well as mocks.
    CHECK(Query(GetCurrentProcess(), info));
    CHECK(info.process == CurrentModule() && info.native != Unknown);
    CHECK(!Query(reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(0x1234)), info));
    CHECK(info.process == Unknown && info.native == Unknown);
    std::cout << "Process architecture detection and injection routing " << (failures ? "FAILED" : "passed") << std::endl;
#undef CHECK
    return failures ? 1 : 0;
}
