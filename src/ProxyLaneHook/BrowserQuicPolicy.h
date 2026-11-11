#pragma once
#include "structinfo.h"
class CPRCPipeClient;
namespace BrowserQuicPolicy {
enum Status : DWORD { None=0, Pending=1, Ready=2, Unavailable=3 };
struct Report { ULONGLONG birth; DWORD status; DWORD reserved; };
void SetPreference(bool enabled);
bool Preference();
// First injection only. Never performs locating or hooks under the loader lock.
void Initialize(LPCTSTR pipeName, bool enabled);
bool Enabled();
void SetupFailed();
void ModuleLoaded(LPCWSTR name, DWORD flags);
DWORD OnUdp();
bool NeedsPublish();
void Publish(CPRCPipeClient& pipe);
// Host: isolated by PRC owner, identity includes PID reuse protection.
void Observe(const void* owner, DWORD pid, const Report& report);
DWORD Lookup(const void* owner, DWORD pid, ULONGLONG birth, DWORD fallback);
void Forget(const void* owner);
}
