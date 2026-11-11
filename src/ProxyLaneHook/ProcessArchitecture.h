#pragma once
#include <windows.h>
#include <tchar.h>

// Shared by the GUI, injection helper and tests. No modern Windows imports:
// the x86/x64 products still support XP through their existing toolsets.
namespace ProcessArchitecture
{
    enum Architecture { Unknown, X86, X64, Arm64 };
    struct ProcessInfo
    {
        Architecture process;
        Architecture native;
        ProcessInfo() : process(Unknown), native(Unknown) {}
    };

    inline Architecture FromMachine(USHORT machine)
    {
        switch (machine)
        {
        case 0x014c: return X86;
        case 0x8664: return X64;
        case 0xaa64: return Arm64;
        default: return Unknown; // ARM32, ARM64EC/ARM64X and future values.
        }
    }

    inline Architecture CurrentModule()
    {
#if defined(_M_ARM64EC)
        return Unknown;
#elif defined(_M_ARM64)
        return Arm64;
#elif defined(_M_X64)
        return X64;
#elif defined(_M_IX86)
        return X86;
#else
        return Unknown;
#endif
    }

    typedef BOOL (WINAPI* Wow64Process2Fn)(HANDLE, USHORT*, USHORT*);
    typedef BOOL (WINAPI* Wow64ProcessFn)(HANDLE, PBOOL);
    typedef VOID (WINAPI* NativeSystemInfoFn)(LPSYSTEM_INFO);
    typedef LONG (WINAPI* VersionFn)(OSVERSIONINFOW*);
    struct Api
    {
        Wow64Process2Fn wow64Process2;
        Wow64ProcessFn wow64Process;
        NativeSystemInfoFn nativeSystemInfo;
        VersionFn version;
    };

    inline Api SystemApi()
    {
        HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
        Api api = {
            reinterpret_cast<Wow64Process2Fn>(GetProcAddress(kernel, "IsWow64Process2")),
            reinterpret_cast<Wow64ProcessFn>(GetProcAddress(kernel, "IsWow64Process")),
            reinterpret_cast<NativeSystemInfoFn>(GetProcAddress(kernel, "GetNativeSystemInfo")),
            reinterpret_cast<VersionFn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion"))
        };
        return api;
    }

    inline BOOL Query(HANDLE process, ProcessInfo& result, const Api& api)
    {
        result = ProcessInfo();
        if (!process) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
        if (api.wow64Process2)
        {
            USHORT machine = 0, nativeMachine = 0;
            // A failed modern query must not fall back to a guessed bitness.
            if (!api.wow64Process2(process, &machine, &nativeMachine)) return FALSE;
            ProcessInfo detected;
            detected.native = FromMachine(nativeMachine);
            detected.process = FromMachine(machine ? machine : nativeMachine);
            if (detected.process != Unknown && detected.native != Unknown)
            {
                result = detected;
                return TRUE;
            }
        }
        else if (api.version && api.nativeSystemInfo && api.wow64Process)
        {
            OSVERSIONINFOW version = { sizeof(version) };
            // GetNativeSystemInfo may report an emulated architecture on ARM.
            // Only use the old API on systems predating Windows on ARM64 and
            // IsWow64Process2. RtlGetVersion avoids manifest version spoofing.
            if (api.version(&version) >= 0 &&
                (version.dwMajorVersion < 10 ||
                 (version.dwMajorVersion == 10 && version.dwBuildNumber < 16299)))
            {
                SYSTEM_INFO system = { 0 };
                api.nativeSystemInfo(&system);
                Architecture native = system.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL ? X86 :
                    system.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? X64 : Unknown;
                if (native != Unknown)
                {
                    BOOL wow64 = FALSE;
                    if (!api.wow64Process(process, &wow64)) return FALSE;
                    if (!(native == X86 && wow64))
                    {
                        result.native = native;
                        result.process = wow64 ? X86 : native;
                        return TRUE;
                    }
                }
            }
        }
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }

    inline BOOL Query(HANDLE process, ProcessInfo& result)
    {
        return Query(process, result, SystemApi());
    }

    inline LPCTSTR HookFileName(Architecture arch)
    {
        switch (arch)
        {
        case X86: return _T("ProxyLaneHook32.dll");
        case X64: return _T("ProxyLaneHook64.dll");
        case Arm64: return _T("ProxyLaneHookARM64.dll");
        default: return NULL;
        }
    }

    inline LPCTSTR ApplicationFileName(Architecture arch)
    {
        switch (arch)
        {
        case X86: return _T("ProxyLane.exe");
        case X64: return _T("ProxyLane64.exe");
        case Arm64: return _T("ProxyLaneARM64.exe");
        default: return NULL;
        }
    }

    inline LPCTSTR TransportFileName(Architecture arch)
    {
        switch (arch)
        {
        case X86: return _T("ProxyLaneSecureTransport32.dll");
        case X64: return _T("ProxyLaneSecureTransport64.dll");
        case Arm64: return _T("ProxyLaneSecureTransportARM64.dll");
        default: return NULL;
        }
    }

    inline LPCTSTR MitmFileName(Architecture arch)
    {
        switch (arch)
        {
        case X64: return _T("ProxyLaneMitm64.dll");
        case Arm64: return _T("ProxyLaneMitmARM64.dll");
        default: return NULL;
        }
    }

    enum InjectionRoute { Unsupported, Direct, Helper };
    inline InjectionRoute Route(Architecture source, const ProcessInfo& target)
    {
        // Only pure native ARM64 -> ARM64 is implemented on Windows on ARM.
        // The injector additionally checks the target PE for hybrid metadata.
        if (source == Arm64 && target.process == Arm64 && target.native == Arm64)
            return Direct;
        if ((source != X86 && source != X64) ||
            (target.process != X86 && target.process != X64) ||
            (target.native != X86 && target.native != X64) ||
            (target.native == X86 && (source != X86 || target.process != X86)))
            return Unsupported;
        return source == target.process ? Direct : Helper;
    }

    inline LPCTSTR LegacyRundllDirectory(const ProcessInfo& target)
    {
        if (Route(X86, target) == Unsupported) return NULL;
        return target.process == target.native ? _T("System32") : _T("SysWOW64");
    }

    inline BOOL RequireDirectInjection(HANDLE process)
    {
        ProcessInfo target;
        if (!Query(process, target)) return FALSE;
        if (Route(CurrentModule(), target) == Direct) return TRUE;
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }
}
