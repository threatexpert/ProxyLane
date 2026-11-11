#pragma once
#include "structinfo.h"
#include <string>
#include <vector>

namespace DohPolicy {
inline bool DnsDestination(const _SockAddr& address) {
    if (address.GetPort() != 53 || address.IsAny() || address.IsLoopback()) return false;
    if (address.IsIPv4() || address.IsIPv4Mapped()) {
        const DWORD ip = address.GetdwIP();
        return reinterpret_cast<const BYTE*>(&ip)[0] < 224;
    }
    return address.IsIPv6() && address.GetAddr6()->u.Byte[0] != 0xff;
}
inline bool Intercept(const PRCClient& client, ProxyInfo& proxy) {
    return proxy.dohEnabled && proxy.GetProxyType() != PROXYTYPE_NOPROXY &&
        (DnsDestination(client.dstAddr) || (client.szDomainName[0] && client.dstAddr.GetPort() == 53));
}
inline bool Parse(const char* url, const char* bootstrap, bool blockIPv6,
    std::vector<_SockAddr>& endpoints) {
    endpoints.clear();
    std::string u(url ? url : ""), ips(bootstrap ? bootstrap : "");
    if (u.size() > 1023 || u.compare(0, 8, "https://") != 0 || ips.empty() || ips.size() > 511) return false;
    for (unsigned char c : u) if (c <= 32 || c >= 127 || c == '#' || c == '\\') return false;
    const size_t end = u.find_first_of("/?", 8);
    std::string authority = u.substr(8, end == std::string::npos ? end : end - 8);
    if (authority.empty() || authority.find('@') != std::string::npos) return false;
    std::string host = authority, port;
    if (authority[0] == '[') {
        size_t close = authority.find(']');
        if (close == std::string::npos) return false;
        host = authority.substr(1, close - 1);
        _SockAddr ip; ip.Clear();
        if (!ip.SetIP(host.c_str()) || !ip.IsIPv6()) return false;
        if (close + 1 < authority.size()) {
            if (authority[close + 1] != ':') return false;
            port = authority.substr(close + 2);
            if (port.empty()) return false;
        }
    } else {
        size_t colon = authority.find(':');
        if (colon != std::string::npos) { host = authority.substr(0, colon); port = authority.substr(colon + 1); if (port.empty()) return false; }
        if (host.empty()) return false;
        for (unsigned char c : host) if (!isalnum(c) && c != '.' && c != '-') return false;
    }
    unsigned number = 443;
    if (!port.empty()) {
        if (port.size() > 5) return false;
        number = 0;
        for (char c : port) { if (c < '0' || c > '9') return false; number = number * 10 + c - '0'; }
        if (!number || number > 65535) return false;
    }
    size_t at = 0;
    while ((at = ips.find_first_not_of(" ,;\t\r\n", at)) != std::string::npos) {
        size_t next = ips.find_first_of(" ,;\t\r\n", at);
        const std::string value = ips.substr(at, next == std::string::npos ? next : next - at);
        _SockAddr address; address.Clear();
        if (!address.SetIP(value.c_str()) || address.IsAny() || address.IsIPv4Mapped()) return false;
        if (address.IsIPv4() && reinterpret_cast<const BYTE*>(&reinterpret_cast<const SOCKADDR_IN*>(&address)->sin_addr)[0] >= 224) return false;
        if (address.IsIPv6() && (blockIPv6 || address.GetAddr6()->u.Byte[0] == 0xff)) return false;
        address.SetPort((WORD)number); endpoints.push_back(address);
        if (endpoints.size() > 8) return false;
        if (next == std::string::npos) break;
        at = next;
    }
    return !endpoints.empty();
}
inline bool Needed(const PRCClient& client, ProxyInfo& proxy) {
    return proxy.dohEnabled && proxy.GetProxyType() != PROXYTYPE_NOPROXY && client.szDomainName[0];
}
}
