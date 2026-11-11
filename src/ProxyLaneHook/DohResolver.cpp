#include "stdafx.h"
#include "DohResolver.h"
#include "DohCache.h"
#include "DohPolicy.h"
#include "ProxyLog.h"
#include "MitmBridge.h"
#include "ProxyReceptionCentre.h"
#include "PlatformSupport.h"
#include "../ProxyLaneMitm/ProxyLaneMitm.h"
#include "../../third_party/nlohmann/json.hpp"
#include <map>
#include <algorithm>

extern HMODULE ProxyMitmModule();
namespace {
using Json = nlohmann::json;
const DWORD DOH_CONNECT_TIMEOUT = 12000;
struct Queries {
    std::map<std::string, std::weak_ptr<CDohQuery>> active;
    std::unique_ptr<CDohCache> cache;
};
thread_local Queries queries;
void KeyPart(std::string& key, const char* part) {
    size_t n = strlen(part); key += std::to_string(n); key += ':'; key.append(part, n);
}
std::string Hex(const std::vector<unsigned char>& bytes) {
    const char* digits = "0123456789abcdef"; std::string result; result.reserve(bytes.size()*2);
    for (unsigned char c : bytes) { result += digits[c >> 4]; result += digits[c & 15]; }
    return result;
}
std::vector<unsigned char> Unhex(const std::string& text) {
    if (text.size() > 131070 || text.size() % 2) throw std::runtime_error("Invalid DNS message length");
    std::vector<unsigned char> result;
    auto digit = [](char c) -> unsigned { if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; throw std::runtime_error("Invalid DNS hex"); };
    for (size_t i=0;i<text.size();i+=2) result.push_back((unsigned char)((digit(text[i])<<4)|digit(text[i+1])));
    return result;
}
bool DnsMessage(const Json& request, Json& response) {
    typedef int (__cdecl *Fn)(const char*, char*, size_t);
    HMODULE module = ProxyMitmModule();
    Fn fn = module ? (Fn)GetProcAddress(module, "plm_dns_message") : NULL;
    if (!fn) { response = Json{{"unavailable", true}}; return false; }
    std::vector<char> output(140000);
    if (fn(request.dump().c_str(), output.data(), output.size()) < 0) return false;
    try { response = Json::parse(output.data()); return response.is_object(); } catch (...) { return false; }
}
void LogDohResult(DWORD pid, const CStringA& name, const CStringA& type,
    CStringA summary, DWORD started, bool cacheHit, bool shared, bool local,
    const CDohQuery* query) {
    // DNS text and transport errors are untrusted; keep one bounded log line.
    summary.Replace('\r', ' '); summary.Replace('\n', ' '); summary.Replace('\t', ' ');
    if (summary.GetLength() > 1024) summary = summary.Left(1021) + "...";
    CStringA tail;
    // Reuse the status prefix from Rust's formatter, not another DNS parser.
    // Valid negative responses and locally generated errors are not successes.
    if (!cacheHit && !local && query && query->Succeeded() &&
        (summary == "NOERROR" || summary.Left(8) == "NOERROR;")) {
        tail.Format("; cache_ttl=%lus", query->CacheLifetime());
        summary += tail;
    }
    tail.Format("; elapsed=%lums", GetTickCount() - started);
    summary += tail;
    if (local) summary += "; source=local";
    else if (cacheHit) summary += "; cache=hit";
    else if (shared) summary += "; shared=yes";
    LogDnsRelay(pid, name.Left(512), type, summary);
}
}
CDohQuery::CDohQuery() : m_wakeup(std::make_shared<CDohWakeup>(GetHwnd())) {}
CDohQuery::~CDohQuery() { m_wakeup->Cancel(); KillTimer(1); ResetTransport(); }
void CDohQuery::ClearCache() { queries.cache.reset(); queries.active.clear(); }
void CDohQuery::RemoveAllLayers() { CAsyncSocketEx::RemoveAllLayers(); m_layers.Free(); }
void CDohQuery::ResetTransport() {
    Close();
    if (m_tls && m_free) m_free(m_tls);
    m_tls = NULL; m_connected = false; m_outputSize = m_outputSent = 0;
    m_addresses.clear(); m_wireAnswer.clear(); m_ttl = 0;
    m_summaryText.clear();
}
std::shared_ptr<CDohQuery> CDohQuery::Resolve(const PRCClient& client, const ProxyInfo& proxy, const ProxyChain* chain, bool test, DohQueryLogInfo* log, TestProgress progress) {
    if (log) {
        log->started = GetTickCount();
        LogDnsRelay(client.dwPid, client.szDomainName, client.dstAddr.IsIPv6() ? "AAAA" : "A", "query started");
    }
    return Start(client, proxy, chain, test, {}, log ? &log->cacheHit : NULL, log ? &log->shared : NULL, std::move(progress));
}
void CDohQuery::LogAddressResult(const PRCClient& client, const DohQueryLogInfo& log) const {
    CStringA summary;
    if (!Succeeded()) {
        summary = "ERROR; reason="; summary += m_error;
    } else {
        // Rust uses the same concise formatter for both resolution paths.
        // The cache lifetime is already known in C++; no extra DNS parsing.
        summary = m_summaryText.empty() ? "NOERROR; summary unavailable" : m_summaryText.c_str();
    }
    LogDohResult(client.dwPid, client.szDomainName, client.dstAddr.IsIPv6() ? "AAAA" : "A",
        summary, log.started, log.cacheHit, log.shared, false, this);
}
std::shared_ptr<CDohQuery> CDohQuery::Exchange(const PRCClient& client, const ProxyInfo& proxy, const ProxyChain* chain, const std::vector<unsigned char>& wire, bool* cacheHit, bool* shared) {
    return Start(client, proxy, chain, false, wire, cacheHit, shared);
}
std::shared_ptr<CDohQuery> CDohQuery::Start(const PRCClient& client, const ProxyInfo& proxy, const ProxyChain* chain, bool test, const std::vector<unsigned char>& wire, bool* cacheHit, bool* shared, TestProgress progress) {
    if (cacheHit) *cacheHit = false;
    if (shared) *shared = false;
    auto result = std::shared_ptr<CDohQuery>(new CDohQuery);
    result->m_proxy = proxy;
    result->m_test = test;
    result->m_testProgress = std::move(progress);
    result->m_route = chain && !chain->empty() ? *chain : ProxyChain(1, proxy);
    result->m_name = client.szDomainName; result->m_name.MakeLower();
    result->m_ipv6 = client.dstAddr.IsIPv6();
    result->m_wireQuery = wire;
    if (!wire.empty()) result->m_ipv6 = false; // Resolver transport family is independent of the original DNS endpoint.
    std::string& key = result->m_key;
    key = test ? "test" : "business";
    KeyPart(key, proxy.dohUrl.szbuf); KeyPart(key, proxy.dohBootstrap.szbuf);
    if (wire.empty()) { KeyPart(key, "address"); KeyPart(key, result->m_name); key += result->m_ipv6 ? "6" : "4"; }
    else { KeyPart(key, "wire"); KeyPart(key, Hex(wire).c_str()); }
    key += proxy.dohBlockIPv6 ? "B" : "A";
    for (auto& hop : result->m_route) {
        KeyPart(key, hop.strProxyType.szbuf); KeyPart(key, hop.strProxyHost.szbuf);
        KeyPart(key, std::to_string(hop.nProxyPort).c_str());
        KeyPart(key, hop.strProxyUser.szbuf); KeyPart(key, hop.strProxyPass.szbuf);
        KeyPart(key, std::to_string(hop.reserved).c_str()); KeyPart(key, hop.strTransportPsk.szbuf);
        KeyPart(key, std::to_string(hop.sshAuth).c_str()); KeyPart(key, hop.strSshKeyFile.szbuf); KeyPart(key, hop.strSshKeyDigest.szbuf);
    }
    const DWORD now = GetTickCount();
    const auto* cached = !test && queries.cache ? queries.cache->Find(key) : NULL;
    if (cached) {
        if (cacheHit) *cacheHit = true;
        result->m_addresses = cached->addresses; result->m_wireAnswer = cached->wire;
        result->m_summaryText = cached->summaryText;
        result->m_answerStored = cached->stored; result->m_done = true; return result;
    }
    for (auto it = queries.active.begin(); it != queries.active.end();) {
        if (it->second.expired()) it = queries.active.erase(it); else ++it;
    }
    auto existing = queries.active.find(key);
    if (!test && existing != queries.active.end()) if (auto active = existing->second.lock()) {
        if (shared) *shared = true;
        return active;
    }
    if (queries.active.size() >= 64) { result->m_error = "DoH query capacity reached"; result->m_done = true; return result; }
    if (!ProxySupportsOptionalModules() || (result->m_ipv6 && proxy.dohBlockIPv6)) {
        result->m_error = "DoH requires a supported 64-bit host and an allowed address family";
        result->m_done = true; return result;
    }
    if (!DohPolicy::Parse(proxy.dohUrl.szbuf, proxy.dohBootstrap.szbuf, proxy.dohBlockIPv6 != FALSE, result->m_bootstrap)) {
        result->m_error = "Invalid DoH URL or required bootstrap IP"; result->m_done = true; return result;
    }
    HMODULE module = ProxyMitmModule();
    auto version = module ? (PLM_VERSION_FN)GetProcAddress(module, "plm_abi_version") : NULL;
    result->m_create = module ? (CreateFn)GetProcAddress(module, "plm_doh_create") : NULL;
    result->m_io = module ? (IoFn)GetProcAddress(module, "plm_doh_io") : NULL;
    result->m_free = module ? (FreeFn)GetProcAddress(module, "plm_doh_free") : NULL;
    if (!version || version() != PLM_ABI_VERSION || !result->m_create || !result->m_io || !result->m_free) {
        result->m_error = "Compatible ProxyLaneMitm64.dll with DoH support is unavailable"; result->m_done = true; return result;
    }
    result->m_started = now;
    if (!test) queries.active[key] = result;
    if (!result->SetTimer(1, 1000)) { result->m_done = true; result->m_error = "Cannot create DoH deadline timer"; queries.active.erase(key); }
    else result->Begin();
    return result;
}
bool CDohQuery::Begin() {
    m_retry = false; m_attemptStarted = GetTickCount();
    m_failureCode = PROXYERROR_DOH_FAILED; m_failedHop = -1; m_failureDetail.Empty();
    m_testHop = 0; m_testStage = PTS_CONNECTING;
    if (m_testProgress) m_testProgress(LAYERCALLBACK_DOHTEST, DTS_CONNECTING, m_endpoint, m_attemptStarted);
    char error[1024] = {};
    const std::string query = (m_wireQuery.empty() ? Json{{"name", (LPCSTR)m_name}, {"ipv6", m_ipv6}, {"probe", m_test}} : Json{{"wire", Hex(m_wireQuery)}}).dump();
    if (m_create(m_proxy.dohUrl.szbuf, query.c_str(), &m_tls, error, sizeof(error)) != 0) { Fail(error); return false; }
    if (!m_layers.Add(*this, m_route.data(), (int)m_route.size(), m_test ? SshSessionUse::Test : SshSessionUse::Business)) { Fail("Cannot build DoH proxy chain"); return false; }
    m_layers.Top()->BypassHook(TRUE);
    if (!Create(0, SOCK_STREAM, FD_READ | FD_WRITE | FD_CONNECT | FD_CLOSE, NULL, FALSE, AF_INET)) {
        Fail("Cannot create DoH proxy socket"); return false;
    }
    const auto& address = m_bootstrap[m_endpoint];
    if (!Connect(&address, address.Size()) && WSAGetLastError() != WSAEWOULDBLOCK) {
        Fail("Cannot connect to DoH bootstrap IP through proxy chain"); return false;
    }
    return true;
}
void CDohQuery::Fail(const char* text) {
    if (m_done || m_retry) return;
    m_error = text;
    // Changing the resolver IP cannot fix proxy authentication, host trust,
    // or an unreachable intermediate node. Test only retries once the last
    // proxy is opening the resolver tunnel (or the DoH exchange has begun).
    const bool resolverFailure = m_connected ||
        (m_testHop == (int)m_route.size() - 1 &&
            (m_testStage == PTS_OPENING || m_testStage == PTS_PASSED) &&
            (m_failureCode == PROXYERROR_DOH_FAILED || m_failureCode == PROXYERROR_NOCONN ||
                m_failureCode == PROXYERROR_REQUESTFAILED));
    if ((!m_test || resolverFailure) && m_endpoint + 1 < m_bootstrap.size() && GetTickCount() - m_started < 60000) {
        m_retry = true;
        if (ScheduleWork()) return;
        m_retry = false; m_error = "Cannot dispatch DoH retry";
    }
    if (m_test && !m_connected && m_failedHop < 0) m_failedHop = m_layers.StalledHop();
    m_done = true; KillTimer(1); queries.active.erase(m_key); NotifyWaiters();
}
void CDohQuery::Complete() {
    m_error.Empty(); m_done = true; KillTimer(1); queries.active.erase(m_key);
    m_answerStored = GetTickCount();
    // This is the effective cache lifetime after Rust's DNS/HTTP limits and
    // the host cap. Keep zero when the answer could not actually be cached.
    m_ttl = min(m_ttl, (DWORD)3600);
    if (!m_test && m_ttl) {
        if (!queries.cache) queries.cache.reset(new CDohCache);
        // Capping only shortens the DNS TTL; zero-TTL answers never enter cache.
        if (!queries.cache->Store(m_key, CDohCache::Entry{m_addresses, m_wireAnswer, m_answerStored, m_ttl * 1000, m_summaryText}))
            m_ttl = 0;
    }
    NotifyWaiters();
}
void CDohQuery::Pump() {
    if (m_done || m_retry || !m_connected || m_pumping) return;
    m_pumping = true;
    unsigned char buffer[16384];
    for (int iteration = 0; iteration < 32 && !m_done && !m_retry; ++iteration) {
        bool progress = false;
        if (m_outputSent == m_outputSize) {
            m_outputSent = 0;
            m_outputSize = m_io(m_tls, 1, m_output, sizeof(m_output));
            if (m_outputSize < 0) { Fail((char*)m_output); break; }
        }
        if (m_outputSent < m_outputSize) {
            int sent = Send(m_output + m_outputSent, m_outputSize - m_outputSent);
            if (sent > 0) { m_outputSent += sent; progress = true; }
            else if (sent == 0 || WSAGetLastError() != WSAEWOULDBLOCK) { Fail("DoH tunnel write failed"); break; }
        }
        int received = Receive(buffer, sizeof(buffer));
        if (received > 0) {
            int consumed = m_io(m_tls, 0, buffer, received);
            if (consumed < 0) { Fail((char*)buffer); break; }
            if (consumed != received) { Fail("DoH TLS input was not fully consumed"); break; }
            progress = true;
        } else if (received == 0) {
            if (m_io(m_tls, 2, buffer, sizeof(buffer)) < 0) { Fail((char*)buffer); break; }
        } else if (WSAGetLastError() != WSAEWOULDBLOCK) { Fail("DoH tunnel read failed"); break; }
        int ready = m_io(m_tls, 3, buffer, sizeof(buffer));
        if (ready < 0) { Fail((char*)buffer); break; }
        if (ready > 0) {
            try {
                if (ready > 140000) throw std::runtime_error("DoH result too large");
                std::vector<unsigned char> large;
                const char* json = (char*)buffer;
                if (ready > sizeof(buffer)) {
                    large.resize(ready);
                    if (m_io(m_tls, 3, large.data(), large.size()) != ready) throw std::runtime_error("Invalid DoH result");
                    json = (char*)large.data();
                }
                auto value = Json::parse(json);
                if (m_test) {
                    if (!value.value("probe_ok", false)) throw std::runtime_error("DoH client did not return a connectivity probe result");
                    m_probeSucceeded = true; Complete(); break;
                }
                if (!m_wireQuery.empty()) {
                    m_wireAnswer = Unhex(value.at("wire").get<std::string>());
                    if (m_wireAnswer.size() < 12) throw std::runtime_error("Invalid DNS reply");
                    m_ttl = value.at("ttl").get<DWORD>(); Complete(); break;
                }
                for (auto& item : value.at("addresses")) {
                    _SockAddr ip; ip.Clear();
                    if (!ip.SetIP(item.get<std::string>().c_str()) || ip.IsAny() || ip.IsIPv4Mapped() || (ip.IsIPv6() != FALSE) != m_ipv6)
                        throw std::runtime_error("Invalid address in DoH answer");
                    m_addresses.push_back(ip);
                }
                if (m_addresses.empty()) throw std::runtime_error("DoH answer has no usable addresses");
                if (value.contains("summary") && value["summary"].is_string())
                    m_summaryText = value["summary"].get<std::string>();
                m_ttl = value.at("ttl").get<DWORD>(); Complete();
            } catch (const std::exception& error) { Fail(error.what()); }
            break;
        }
        if (!progress) break;
        // Continue only when the work budget was exhausted while progressing.
        // Otherwise wait for a socket event, not a periodic wakeup.
        if (iteration == 31 && !m_done && !m_retry && !ScheduleWork())
            Fail("Cannot dispatch DoH continuation");
    }
    m_pumping = false;
}
void CDohQuery::OnConnect(int error) {
    if (m_done || m_retry) return;
    if (error) {
        CStringA text; text.Format("DoH proxy tunnel connection failed (socket error %d)", error); Fail(text);
    } else {
        m_connected = true;
        if (m_testProgress) m_testProgress(LAYERCALLBACK_DOHTEST, DTS_QUERYING, 0, GetTickCount());
        Pump();
    }
}
void CDohQuery::OnReceive(int error) { if (error) Fail("DoH tunnel receive failed"); else Pump(); }
void CDohQuery::OnSend(int error) { if (error) Fail("DoH tunnel send failed"); else Pump(); }
void CDohQuery::OnClose(int) { Pump(); if (!m_done) Fail("DoH tunnel closed before a complete answer"); }
void CDohQuery::OnTimer(UINT_PTR) {
    if (m_done) return;
    if (GetTickCount() - m_started >= 60000) { m_retry = false; m_endpoint = m_bootstrap.size(); Fail("DoH query timed out"); return; }
    // Includes proxy negotiation and SSH direct-tcpip OPEN: OnConnect only
    // succeeds once the selected route has established the target tunnel.
    if (!m_connected && GetTickCount() - m_attemptStarted >= DOH_CONNECT_TIMEOUT) {
        Fail("DoH proxy tunnel connection timed out (12 s)"); return;
    }
    if (m_bootstrap.size() > 1 && GetTickCount() - m_attemptStarted >= 15000) { Fail("DoH bootstrap IP timed out"); return; }
}
bool CDohQuery::NotifyWhenReady(const std::shared_ptr<CDohWakeup>& waiter) {
    if (m_done) return waiter->Notify();
    for (auto it=m_waiters.begin();it!=m_waiters.end();) {
        auto live=it->lock();
        if (!live) it=m_waiters.erase(it);
        else { if (live==waiter) return true; ++it; }
    }
    m_waiters.push_back(waiter); return true;
}
void CDohQuery::NotifyWaiters() {
    auto waiters=std::move(m_waiters);
    for (auto& weak:waiters) if (auto waiter=weak.lock()) {
        if (!waiter->Notify()) PrintText(_T("DoH completion notification failed; waiter will fail closed.\r\n"));
    }
}
bool CDohQuery::ScheduleWork() { return m_wakeup->Notify(); }
void CDohQuery::OnMessage(UINT message, WPARAM low, LPARAM high, BOOL& handled) {
    if (!m_wakeup->Accept(message,low,high)) return;
    handled=TRUE;
    if (m_done) return;
    if (m_retry) { ResetTransport(); ++m_endpoint; m_error.Empty(); Begin(); return; }
    Pump();
}

int CDohQuery::OnLayerCallback(const CAsyncSocketExLayer* layer, int type, int code, WPARAM param, LPARAM detail) {
    if (m_done || m_retry) return 1;
    if (type == LAYERCALLBACK_TESTPROGRESS && m_test) {
        const int hop = (int)param >= 0 ? (int)param : m_layers.HopOf(layer);
        if (hop >= 0) { m_testHop = hop; m_testStage = code; }
        if (m_testProgress) m_testProgress(type, code, hop, detail);
        return 1;
    }
    if (type == LAYERCALLBACK_LAYERSPECIFIC && code != PROXYERROR_NOERROR && code != PROXYSTATUS_LISTENSOCKETCREATED) {
        if (m_test) {
            m_failedHop = m_layers.HopOf(layer); m_failureCode = code;
            m_failureDetail = detail ? (const char*)detail : "";
        }
        CStringA text; text.Format("DoH proxy handshake failed (%d): %s", code, detail ? (const char*)detail : ""); Fail(text);
    }
    return 1;
}

bool CDnsDohRequest::Begin(const PRCClient& client, const ProxyInfo& proxy, const ProxyChain* chain, const char* data, int length) {
    m_started = GetTickCount();
    if (!data || length < 12 || length > 65535) {
        LogDnsRelayRoute(&client, "rejected DNS message: invalid length");
        return false;
    }
    m_pid = client.dwPid;
    m_query.assign(data, data + length);
    Json info;
    if (!DnsMessage(Json{{"query", Hex(m_query)}, {"validate", true}}, info)) {
        // Explicit FORMERR for malformed/unsupported requests; never forward
        // their payload to the original resolver or any plain-DNS endpoint.
        m_rejected.assign(12, 0); m_rejected[0] = m_query[0]; m_rejected[1] = m_query[1];
        m_rejected[2] = 0x80 | (m_query[2] & 0x79);
        const bool unavailable = info.is_object() && info.value("unavailable", false);
        m_rejected[3] = unavailable ? 0x82 : 0x81;
        LogResult(unavailable ? "SERVFAIL; reason=DoH DNS adapter unavailable; no DNS fallback" : "FORMERR; reason=invalid or unsupported DNS query", true);
        return true;
    }
    m_name = info.value("name", "").c_str(); m_type = info.value("type", "").c_str();
    // This also covers cached/shared queries and local refusals; do not imply
    // that every application request starts another upstream exchange.
    LogDnsRelay(m_pid, m_name, m_type, "query started");
    if (info.contains("local_reply")) {
        try { m_rejected = Unhex(info.at("local_reply").get<std::string>()); }
        catch (...) { LogResult("ERROR; reason=invalid local DNS reply", true); return false; }
        CStringA summary(info.value("summary", "REFUSED").c_str());
        summary += "; reason=private IPv4 reverse lookup";
        LogResult(summary, true);
        return true;
    }
    auto canonical = m_query; canonical[0] = canonical[1] = 0;
    m_exchange = CDohQuery::Exchange(client, proxy, chain, canonical, &m_cacheHit, &m_shared);
    return true;
}
bool CDnsDohRequest::NotifyWhenReady(const std::shared_ptr<CDohWakeup>& waiter) {
    return !m_rejected.empty() ? waiter->Notify() : m_exchange && m_exchange->NotifyWhenReady(waiter);
}
void CDnsDohRequest::LogResult(CStringA summary, bool local) {
    if (m_resultLogged) return;
    m_resultLogged = true;
    LogDohResult(m_pid, m_name, m_type, summary, m_started, m_cacheHit, m_shared, local, m_exchange.get());
}
bool CDnsDohRequest::TryBuildReply(bool udp, std::vector<unsigned char>& response) {
    if (!m_rejected.empty()) { response = m_rejected; return true; }
    if (!m_exchange || !m_exchange->Done()) return false;
    Json input = {{"query", Hex(m_query)}, {"udp", udp}};
    if (m_exchange->Succeeded()) {
        input["answer"] = Hex(m_exchange->WireAnswer()); input["age"] = m_exchange->AnswerAge();
    }
    Json output;
    CStringA summary("DNS response; summary unavailable");
    if (DnsMessage(input, output)) {
        try { response = Unhex(output.at("wire").get<std::string>()); } catch (...) { response.clear(); }
        if (output.contains("summary") && output["summary"].is_string())
            summary = output["summary"].get<std::string>().c_str();
    }
    if (response.empty()) {
        response.assign(12, 0); response[0] = m_query[0]; response[1] = m_query[1];
        response[2] = 0x80 | (m_query[2] & 1); response[3] = 0x82;
        summary = "SERVFAIL; reason=DNS reply construction failed";
    }
    if (!m_exchange->Succeeded()) {
        // The application receives SERVFAIL; retain the actual transport cause.
        summary = "SERVFAIL; reason=";
        summary += m_exchange->Error();
    }
    LogResult(summary);
    return true;
}

CDnsDohTcp::CDnsDohTcp(const PRCClient& client, const ProxyInfo& proxy, const ProxyChain* chain, CProxyReceptionCentre* host)
    : m_client(client), m_proxy(proxy), m_host(host) {
    m_wakeup=std::make_shared<CDohWakeup>(GetHwnd(), [this] { m_noticeFailed = true; });

    if (chain) m_chain = *chain;
    if (CProtocolTap::Enabled()) { m_capture.reset(new CProtocolTap(client, false)); m_capture->Connected(0); }
}
CDnsDohTcp::~CDnsDohTcp() { m_wakeup->Cancel(); KillTimer(1); Close(); if (m_capture) { m_capture->Eof(0); m_capture->Eof(1); } }
void CDnsDohTcp::OnReceive(int error) { if (error) Close(); else Pump(); }
void CDnsDohTcp::OnSend(int error) { if (error) Close(); else Pump(); }
void CDnsDohTcp::OnClose(int error) { if (error) Close(); else Pump(); }
void CDnsDohTcp::Pump() {
    if (m_pumping || GetSocketHandle() == INVALID_SOCKET) return;
    m_pumping = true;
    char bytes[8192];
    bool readBudgetExhausted = false;
    for (int n = 0; n < 16 && !m_eof; ++n) {
        const int count = Receive(bytes, sizeof(bytes));
        if (count > 0) {
            if (m_capture) m_capture->Data(0, bytes, count);
            if (m_host) m_host->RecordTraffic(false, count);
            m_input.insert(m_input.end(), bytes, bytes + count); m_activity = GetTickCount();
        }
        else if (count == 0) { m_eof = true; break; }
        else { if (WSAGetLastError() != WSAEWOULDBLOCK) Close(); break; }
        if (m_input.size() > 256*1024) { Close(); break; }
        if (n == 15) readBudgetExhausted = true;
    }
    while (GetSocketHandle() != INVALID_SOCKET && m_input.size() >= 2 && m_pending.size() < 32) {
        const size_t length = (m_input[0] << 8) | m_input[1];
        if (length < 12) { Close(); break; }
        if (m_input.size() < length + 2) break;
        CDnsDohRequest request;
        if (!request.Begin(m_client, m_proxy, m_chain.empty() ? NULL : &m_chain, (char*)m_input.data()+2, (int)length)) { Close(); break; }
        m_pending.push_back(std::move(request));
        if (!m_pending.back().NotifyWhenReady(m_wakeup)) { Close(); break; }
        m_input.erase(m_input.begin(), m_input.begin()+length+2);
    }
    for (auto it = m_pending.begin(); it != m_pending.end() && m_output.size() < 256*1024;) {
        std::vector<unsigned char> reply;
        if (!it->TryBuildReply(false, reply)) { ++it; continue; }
        if (reply.size() > 65535) { Close(); break; }
        m_output.push_back((unsigned char)(reply.size() >> 8)); m_output.push_back((unsigned char)reply.size());
        m_output.insert(m_output.end(), reply.begin(), reply.end());
        it = m_pending.erase(it);
    }
    const bool replyBudgetExhausted = !m_pending.empty() && m_output.size() >= 256*1024;
    while (GetSocketHandle() != INVALID_SOCKET && m_sent < m_output.size()) {
        const int sent = Send(m_output.data()+m_sent, (int)(m_output.size()-m_sent));
        if (sent > 0) {
            if (m_capture) m_capture->Data(1, m_output.data()+m_sent, sent);
            if (m_host) m_host->RecordTraffic(true, sent);
            m_sent += sent; m_activity = GetTickCount();
        }
        else { if (!sent || WSAGetLastError() != WSAEWOULDBLOCK) Close(); break; }
    }
    if (m_sent == m_output.size()) { m_output.clear(); m_sent = 0; }
    const bool completeInput = m_input.size() >= 2 && m_input.size() >= (size_t)((m_input[0] << 8) | m_input[1]) + 2;
    if (m_eof && m_pending.empty() && m_output.empty() && !completeInput) Close();
    if (GetSocketHandle() != INVALID_SOCKET && (readBudgetExhausted || (replyBudgetExhausted && m_output.empty()) ||
        (completeInput && m_pending.size()<32 && m_output.size()<256*1024))) m_wakeup->Notify();
    if (GetSocketHandle() == INVALID_SOCKET) { m_pending.clear(); m_input.clear(); m_output.clear(); }
    m_pumping = false;
}

void CDnsDohTcp::OnMessage(UINT message, WPARAM low, LPARAM high, BOOL& handled) {
    if (!m_wakeup->Accept(message,low,high)) return;
    handled=TRUE; Pump();
}
void CDnsDohTcp::OnTimer(UINT_PTR) {
    if (m_noticeFailed || GetTickCount()-m_activity > 90000) { KillTimer(1); Close(); }
}
