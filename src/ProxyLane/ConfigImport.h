#pragma once
#include <afxwin.h>
#include <vector>

#define WM_CONFIG_IMPORT_RESTART (WM_APP + 313)

namespace ConfigImport
{
// Owns only its uniquely named staging file and its prepared restart process.
// Imports leave their source untouched. Storage switches change only the flag.
class Pending
{
public:
    Pending() = default;
    ~Pending();
    bool Prepare(const CString& source, CString& error);
    bool PrepareStorageSwitch(bool portable, CString& error);
    bool ArmRestart(CString& error);
    void FinishAfterShutdown();
    CString source, destination, backup;
    UINT profiles = 0;
private:
    Pending(const Pending&) = delete;
    Pending& operator=(const Pending&) = delete;
    CString staged, token, executable, readyName;
    std::vector<BYTE> contents, previous;
    bool hadPrevious = false;
    bool switchStorage = false, usePortable = false;
    PROCESS_INFORMATION child = {};
    HANDLE ready = NULL;
    bool Launch(bool suspended);
    bool Restore();
    void FinishStorageSwitch();
};
CString ErrorText(DWORD error);
}
