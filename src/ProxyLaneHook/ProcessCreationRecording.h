#pragma once
#include "ProxyModule.h"
#include "../../third_party/nlohmann/json.hpp"

// Only pipe-client or launcher threads call this. No network callback, new
// export, disk I/O, lazy MITM loading, or additional child pipe round trip.
inline void RecordProcessCreation(IProxyTlsControl* tls,
    const HookProcessCreationNotice& notice, const char* source)
{
#ifdef _WIN64
    if (!tls) return;
    nlohmann::json request = {{"type", "recording_process_created"},
        {"parent", {{"pid", notice.parent.dwProcessId}, {"process_start", notice.parent.processCreateTime},
            {"path", std::string(CW2A(notice.parent.szAppPath, CP_UTF8))}}},
        {"child", {{"pid", notice.child.dwProcessId}, {"process_start", notice.child.processCreateTime},
            {"path", std::string(CW2A(notice.child.szAppPath, CP_UTF8))}}}, {"source", source}};
    char result[1024] = {};
    if (tls->QueryProtocol(request.dump().c_str(), result, sizeof(result)) < 0)
        OutputDebugStringA(result); // Recording worker also publishes capacity/write failures.
#endif
}
