#include "ProcessArchitecture.h"
#include <iostream>

namespace
{
    using namespace ProcessArchitecture;
    USHORT processMachine, nativeMachine, processor;
    DWORD major, build;
    BOOL modernSuccess, legacySuccess, wow;
    int legacyCalls;
    USHORT activeMachine;
    BOOL machineQuerySuccess;
    BOOL WINAPI MachineInfo(HANDLE, int infoClass, void* output, DWORD size)
    {
        if (infoClass != 9 || size != 8 || !machineQuerySuccess)
        { SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
        static_cast<MachineInformation*>(output)->machine = activeMachine;
        return TRUE;
    }
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
    Api api = { Modern, Legacy, System, Version, MachineInfo };
    machineQuerySuccess = TRUE; activeMachine = 0xaa64;
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
        processMachine = machines[process]; activeMachine = machines[process];
        CHECK(Query(GetCurrentProcess(), info, api));
        CHECK(info.process == architectures[process] && info.native == Arm64);
    }
    // Active ABI wins over ambiguous ARM64X/IsWow64Process2 reports.
    processMachine = 0; activeMachine = 0x8664;
    CHECK(Query(GetCurrentProcess(), info, api) && info.process == X64);
    activeMachine = 0xaa64;
    CHECK(Query(GetCurrentProcess(), info, api) && info.process == Arm64);
    activeMachine = 0xa641;
    CHECK(!Query(GetCurrentProcess(), info, api) && GetLastError() == ERROR_NOT_SUPPORTED);
    machineQuerySuccess = FALSE;
    CHECK(!Query(GetCurrentProcess(), info, api) && GetLastError() == ERROR_ACCESS_DENIED);
    machineQuerySuccess = TRUE; activeMachine = 0xaa64;
    api.processInformation = NULL;
    CHECK(!Query(GetCurrentProcess(), info, api) && GetLastError() == ERROR_NOT_SUPPORTED);
    api.processInformation = MachineInfo;
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
    CHECK(!NeedsPublicCreateProcessHook(info)); // WOW64 on Intel is not ARM emulation.
    CHECK(Route(X86, info) == Direct && Route(X64, info) == Helper);
    CHECK(_tcscmp(SystemRundllDirectory(info), _T("SysWOW64")) == 0);
    info.process = X64;
    CHECK(!NeedsPublicCreateProcessHook(info));
    CHECK(Route(X64, info) == Direct && Route(X86, info) == Helper);
    CHECK(_tcscmp(SystemRundllDirectory(info), _T("System32")) == 0);
    info.native = X86;
    CHECK(Route(X64, info) == Unsupported && SystemRundllDirectory(info) == NULL);
    info.process = X86;
    CHECK(Route(X86, info) == Direct);
    CHECK(!NeedsPublicCreateProcessHook(info));
    CHECK(_tcscmp(SystemRundllDirectory(info), _T("System32")) == 0);
    // All nine Windows 11 ARM routes; only matching ABIs inject directly.
    info.native = Arm64;
    info.process = X86;
    CHECK(NeedsPublicCreateProcessHook(info));
    info.process = X64;
    CHECK(NeedsPublicCreateProcessHook(info));
    info.process = Arm64;
    CHECK(!NeedsPublicCreateProcessHook(info));
    info.process = Unknown;
    CHECK(!NeedsPublicCreateProcessHook(info));
    CHECK(!NeedsPublicCreateProcessHook(ProcessInfo()));
    for (int source = 0; source < 3; ++source)
        for (int target = 0; target < 3; ++target)
        {
            info.process = architectures[target];
            CHECK(Route(architectures[source], info) ==
                (source == target ? Direct : Helper));
            CHECK(_tcscmp(SystemRundllDirectory(info),
                info.process == X86 ? _T("SysWOW64") : _T("System32")) == 0);
            CHECK(RundllMachine(info) == (info.process == X86 ? 0x14c : info.process == X64 ? 0x8664 : 0xaa64));
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
    info.process = Arm64; info.native = X64;
    CHECK(SystemRundllDirectory(info) == NULL);
    info.native = Unknown;
    CHECK(SystemRundllDirectory(info) == NULL);
    info.process = Unknown; info.native = Arm64;
    CHECK(SystemRundllDirectory(info) == NULL);

    // An ARM64X PE is acceptable only with positive native-ABI confirmation.
    machineQuerySuccess = TRUE; activeMachine = 0xaa64;
    CHECK(RequireNativeArm64Hybrid(GetCurrentProcess(), MachineInfo));
    const USHORT incompatibleViews[] = { 0, 0x8664, 0x014c, 0xa641, 0xa64e, 0xffff };
    for (int i = 0; i < _countof(incompatibleViews); ++i)
    {
        activeMachine = incompatibleViews[i];
        CHECK(!RequireNativeArm64Hybrid(GetCurrentProcess(), MachineInfo));
        CHECK(GetLastError() == ERROR_EXE_MACHINE_TYPE_MISMATCH);
    }
    machineQuerySuccess = FALSE; activeMachine = 0xaa64;
    CHECK(!RequireNativeArm64Hybrid(GetCurrentProcess(), MachineInfo));
    CHECK(GetLastError() == ERROR_ACCESS_DENIED);
    CHECK(!RequireNativeArm64Hybrid(GetCurrentProcess(), NULL));
    CHECK(GetLastError() == ERROR_NOT_SUPPORTED);

    // Exercise the actual dynamically-resolved Windows API as well as mocks.
    CHECK(Query(GetCurrentProcess(), info));
    CHECK(info.process == CurrentModule() && info.native != Unknown);
    CHECK(!Query(reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(0x1234)), info));
    CHECK(info.process == Unknown && info.native == Unknown);
    std::cout << "Process architecture detection and injection routing " << (failures ? "FAILED" : "passed") << std::endl;
#undef CHECK
    return failures ? 1 : 0;
}
