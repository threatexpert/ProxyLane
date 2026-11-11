#pragma once
#include <string>

// Update downloads run in a short-lived, windowless copy of ProxyLane. When a
// proxy is running the host injects ProxyLaneHook into that process, so the
// download uses the active profile (SOCKS5/HTTP, authentication, encrypted
// transport and target rules) without a second proxy implementation.
namespace UpdateHelper
{
enum Kind { RELEASE_METADATA, INSTALLER };
enum ExitCode
{
    EXIT_OK = 0,
    EXIT_BAD_ARGUMENTS = 1,
    EXIT_NETWORK = 2,
    EXIT_HTTP_STATUS = 3,
    EXIT_TOO_LARGE = 4,
    EXIT_WRITE_FAILED = 5
};

// Child side. Returns true only for the private --update-helper mode.
bool Run(LPCWSTR commandLine, DWORD& exitCode);

// Parent side helpers.
// The parent appends --direct when it injects the helper.
CString BuildArguments(Kind kind, const CString& assetPath, const CString& output);
CString WorkDirectory();
// Deletes setup programs and partial/metadata files left in WorkDirectory by
// earlier runs, except `keep`. Recent files (10 minutes) may belong to another
// ProxyLane window that is still downloading, and files in use cannot be deleted.
void CleanWorkDirectory(const CString& keep);
bool ReadSmallFile(const CString& path, std::string& bytes, size_t limit);
bool Sha256File(const CString& path, std::string& hex, unsigned long long& size);
// True for a copy installed by the setup program (it has Inno Setup's uninstaller).
bool IsInstalledCopy();
CString InstallerParameters();
}
