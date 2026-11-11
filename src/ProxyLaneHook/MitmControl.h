#pragma once
#include "ProxyModule.h"

// Internal implementation; clients use IGlobalProxy::GetTlsControl().
class CMitmControl : public IProxyTlsControl
{
public:
    static CMitmControl& Instance();
    int ManageCA(CaAction action, char* output, size_t capacity) override;
    BOOL SetEnabled(BOOL enabled, char* error, size_t capacity) override;
    BOOL IsEnabled() override;
    int QueryProtocol(const char* request, char* output, size_t capacity) override;
    void ShutdownProtocol(); // after PRC sessions are destroyed, outside DllMain
private:
    CMitmControl() = default;
};
