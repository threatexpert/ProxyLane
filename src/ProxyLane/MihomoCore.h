#pragma once
#include "../ProxyLaneHook/structinfo.h"
#include <memory>

class MihomoCore
{
public:
    MihomoCore() = default;
    MihomoCore(const MihomoCore&) = delete;
    MihomoCore& operator=(const MihomoCore&) = delete;
    ~MihomoCore();
    bool Start(const CString& uri, ProxyInfo& endpoint, CString& errorKey, CString* errorDetail = NULL);
    bool Alive() const;
    CString LastError() const;
    void SetEndpoint(ProxyInfo& endpoint) const;
    static CString InstalledPath();
    static CString TargetPath();
    static bool Browse(HWND owner, const CString& path);
    static bool Install(const CString& source, CString& path, CString& error);
private:
    HANDLE m_job = NULL;
    HANDLE m_process = NULL;
    CString m_directory, m_password;
    unsigned m_port = 0;
};
