#include <windows.h>
#include <vector>
#include "../ProxyLaneHook/ProcessArchitecture.h"
#include "../ProxyLaneHook/ElevatedLaunchProtocol.h"

// A pure native host for the existing elevated-launch implementation. The GUI
// requests UAC through ShellExecuteEx("runas"); ElevatedLaunch checks the token
// again before creating a suspended target. No implicit elevation on startup.
int WINAPI wWinMain(HINSTANCE, HINSTANCE, LPWSTR commandLine, int)
{
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX);
    const size_t maximum = 10 + ProxyLaneBase64UrlEncodedLength(PROXYLANE_ELEVATED_MAX_WIRE_BYTES);
    std::vector<char> request;
    for (size_t i = 0; commandLine && commandLine[i]; ++i)
    {
        // The wire envelope is ASCII Base64URL; UTF-8 paths live inside it.
        // Never let code-page conversion turn non-ASCII input into valid bytes.
        if (i >= maximum || commandLine[i] > 0x7f)
            return PROXYLANE_ELEVATED_INVALID_REQUEST;
        request.push_back(static_cast<char>(commandLine[i]));
    }
    if (request.empty()) return PROXYLANE_ELEVATED_INVALID_REQUEST;
    request.push_back('\0');

    const wchar_t* hook = ProcessArchitecture::HookFileName(ProcessArchitecture::CurrentModule());
    if (!hook) return PROXYLANE_ELEVATED_INTERNAL_ERROR;
    std::vector<wchar_t> path(32768);
    const DWORD length = GetModuleFileNameW(NULL, path.data(), static_cast<DWORD>(path.size()));
    if (!length || length >= path.size()) return PROXYLANE_ELEVATED_INTERNAL_ERROR;
    wchar_t* slash = wcsrchr(path.data(), L'\\');
    if (!slash || wcscpy_s(slash + 1, path.size() - (slash + 1 - path.data()), hook))
        return PROXYLANE_ELEVATED_INTERNAL_ERROR;
    // Use only the helper's own directory and system dependencies, even when
    // launched from a different working directory under an elevated token.
    HMODULE module = LoadLibraryExW(path.data(), NULL,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!module) return PROXYLANE_ELEVATED_INTERNAL_ERROR;
    typedef void (CALLBACK* Entry)(HWND, HINSTANCE, LPSTR, int);
    Entry launch = reinterpret_cast<Entry>(GetProcAddress(module, "ElevatedLaunch"));
    if (launch) launch(NULL, NULL, request.data(), SW_HIDE);
    // The shared entry point always terminates this process with a protocol
    // exit code. An absent export or an unexpected return is a helper failure.
    FreeLibrary(module);
    return PROXYLANE_ELEVATED_INTERNAL_ERROR;
}
