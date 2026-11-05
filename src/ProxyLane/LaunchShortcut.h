#pragma once
#include "AutomationOptions.h"
#include "RecentApplications.h"
#include <functional>

namespace LaunchShortcut
{
enum DecodeResult { NotManaged, Decoded, Invalid };
CString ExecutablePath();
BOOL IsProxyLaneExecutable(const CString& path);
// Accepts both an unresolved .lnk and a Shell-resolved application. Never launches anything.
DecodeResult Decode(const InstalledApplications::Application& source,
    InstalledApplications::Application& target, AutomationOptions& options);
HRESULT Create(const CString& destination, const CString& profile,
    const RecentApplications::Entry& entry);
BOOL PromptCreate(CWnd* owner, const CString& profile, const RecentApplications::Entry& entry,
    const std::function<BOOL()>& stillCurrent);
BOOL Start(const AutomationOptions& options);
int ChooseProfile(HWND owner, const CString& shortcutProfile, const CString& currentProfile);
void ReportFailure(const AutomationOptions& options, int exitCode);
}
