#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include "DetourHooks.h"

namespace ShellLaunchHooks
{
    // S_OK: helper command; S_FALSE: explicitly excluded; failure: do not launch.
    typedef HRESULT (*BuildCommand)(LPCWSTR file, LPCWSTR args, LPCWSTR directory,
        LPCWSTR verb, int show, std::wstring& helper, std::wstring& command);
    // Lifecycle follows the existing Hook's quiescent install/remove contract.
    typedef void (*ReportFailure)(LPCWSTR file, HRESULT error);
    bool Initialize(BuildCommand build, ReportFailure report);
    void AppendBindings(std::vector<DetourHookBinding>& bindings);
    bool RestoreInterfaces();
    void Shutdown();
    std::wstring Quote(const std::wstring& text);
    bool ResolveExecutable(LPCWSTR file, LPCWSTR directory, std::wstring& path);
    bool ResolveFile(LPCWSTR file, LPCWSTR directory, std::wstring& path);
    bool IsHelper(LPCWSTR path, LPCWSTR host);
    bool MightBeHelper(LPCWSTR path, LPCWSTR host);
}
