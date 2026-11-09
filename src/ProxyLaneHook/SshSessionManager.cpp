#include "stdafx.h"
#include "SshSessionManager.h"
#include "ProxyChainLayers.h"
#include "asynsocket/AsyncSshSocketLayer.h"
#include "TimerQueue.h"
#include "PlatformSupport.h"
#include "../../third_party/libssh2/include/libssh2.h"
#include <deque>
#include <algorithm>
#include <unordered_set>
#include <errno.h>

namespace {
const UINT WM_SSH_PUMP = WM_APP + 73;
const size_t CHANNEL_BUFFER = 256 * 1024;
const size_t WIRE_HIGH_WATER = 512 * 1024;
const size_t MAX_PENDING_OPENS = 32;
const DWORD RESPONSE_TIMEOUT = 60000, KEEPALIVE_INTERVAL = 15000;

// A private, version-pinned backend loaded only when SSH is requested. No
// import from this DLL is added to the injected hook's loader dependency set.
struct SshApi {
    HMODULE module = NULL;
#define SSH_APIS(X) \
    X(init) X(session_init_ex) X(session_callback_set2) X(session_set_blocking) \
    X(session_handshake) X(hostkey_hash) X(userauth_password_ex) \
    X(channel_direct_tcpip_begin) X(channel_open_poll) X(channel_open_cancel) \
    X(channel_read_ex) X(channel_write_ex) \
    X(channel_eof) X(channel_send_eof) X(channel_close) X(channel_free) \
    X(session_last_errno) X(session_free) X(keepalive_config) X(keepalive_send)
#define DECLARE_SSH(name) decltype(&libssh2_##name) name = NULL;
    SSH_APIS(DECLARE_SSH)
#undef DECLARE_SSH
    int (__cdecl* pump)(LIBSSH2_SESSION*) = NULL;
    SshApi() {
#ifndef _WIN64
        return;
#endif
        // RtlGetVersion reports the real version without a Windows 10 manifest.
        typedef LONG (WINAPI* VersionFunction)(OSVERSIONINFOW*);
        VersionFunction versionFunction = reinterpret_cast<VersionFunction>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion"));
        OSVERSIONINFOW version = {}; version.dwOSVersionInfoSize = sizeof(version);
        if (!versionFunction || versionFunction(&version) || version.dwMajorVersion < 10) return;
        TCHAR path[MAX_PATH];
        const DWORD size = GetModuleFileName(NULL, path, _countof(path));
        if (!size || size >= _countof(path)) return;
        TCHAR* slash = _tcsrchr(path, _T('\\'));
        if (!slash) return;
#ifdef _WIN64
        _tcscpy_s(slash + 1, _countof(path) - (slash + 1 - path), L"ProxyLaneSsh64.dll");
#else
        _tcscpy_s(slash + 1, _countof(path) - (slash + 1 - path), L"ProxyLaneSsh32.dll");
#endif
        module = LoadLibrary(path);
        if (!module) return;
        bool valid = true;
#define LOAD_SSH(name) name = reinterpret_cast<decltype(name)>(GetProcAddress(module, "libssh2_" #name)); valid = valid && name;
        SSH_APIS(LOAD_SSH)
#undef LOAD_SSH
#undef SSH_APIS
        pump = reinterpret_cast<decltype(pump)>(GetProcAddress(module, "plssh_pump"));
        if (!valid || !pump || init(0)) { FreeLibrary(module); module = NULL; }
        // The backend remains loaded for process lifetime, like the other
        // optional transports. Sessions are explicitly freed before WSACleanup.
    }
};
SshApi& Api() {
    // The hook is built with /Zc:threadSafeInit- for XP compatibility. The
    // tester and PRC threads may load the backend concurrently.
    static volatile LONG state = 0;
    static SshApi* api = NULL;
    if (InterlockedCompareExchange(&state, 1, 0) == 0) {
        api = new SshApi;
        InterlockedExchange(&state, 2);
    } else {
        while (InterlockedCompareExchange(&state, 2, 2) != 2) Sleep(0);
    }
    return *api;
}

// Chunks retain their addresses across EAGAIN; libssh2 requires retries of
// channel_write to use the same buffer and size. Both plaintext and wire
// queues have explicit bounds.
struct Buffer {
    std::deque<std::vector<char>> chunks;
    size_t offset = 0, size = 0;
    void Push(const void* data, size_t length) {
        if (!length) return;
        const char* bytes = static_cast<const char*>(data);
        chunks.emplace_back(bytes, bytes + length); size += length;
    }
    size_t FrontSize() const { return chunks.empty() ? 0 : chunks.front().size() - offset; }
    const char* Front() const { return chunks.front().data() + offset; }
    void Consume(size_t length) {
        offset += length; size -= length;
        if (offset == chunks.front().size()) { chunks.pop_front(); offset = 0; }
    }
    void Clear() { chunks.clear(); offset = size = 0; }
};

CStringA Fingerprint(const char* digest) {
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    CStringA result("SHA256:");
    unsigned value = 0; int bits = 0;
    for (int i = 0; i < 32; ++i) {
        value = (value << 8) | static_cast<unsigned char>(digest[i]); bits += 8;
        while (bits >= 6) { bits -= 6; result += alphabet[(value >> bits) & 63]; }
    }
    if (bits) result += alphabet[(value << (6 - bits)) & 63];
    return result;
}

std::string RouteKey(const ProxyChain& route) {
    std::string key;
    auto add = [&key](const char* s) { key += std::to_string(strlen(s)); key += ':'; key += s; };
    for (const auto& hop : route) {
        add(hop.strProxyType.szbuf); add(hop.strProxyHost.szbuf);
        add(std::to_string(hop.nProxyPort).c_str());
        add(hop.strProxyUser.szbuf); add(hop.strProxyPass.szbuf);
        add(std::to_string(hop.reserved).c_str()); add(hop.strTransportPsk.szbuf);
    }
    return key;
}
class Pool;
Pool& CurrentPool();
}

struct SshChannel::State {
    std::weak_ptr<SshSession> session;
    CAsyncSshSocketLayer* observer = NULL;
    bool internalTransport = false;
    LIBSSH2_CHANNEL* handle = NULL;
    LIBSSH2_CHANNEL_OPEN* openOperation = NULL;
    CStringA target;
    int port = 0, error = 0, failedHop = -1;
    Buffer incoming, outgoing;
    bool ready = false, eof = false, shutdown = false, eofSent = false, closed = false;
    bool readNotified = false, writeBlocked = false;
    DWORD started = GetTickCount();
};

class SshSession : public CAsyncSocketEx, public std::enable_shared_from_this<SshSession>
{
public:
    SshSession(const ProxyChain& route, const std::string& key, SshSessionUse use)
        : route(route), key(key), use(use), lifetime(use) {}
    ~SshSession() override { Dispose(); if (!key.empty()) SecureZeroMemory(&key[0], key.size()); SecureZeroMemory(route.data(), route.size()*sizeof(ProxyInfo)); }
    ProxyChain route;
    std::string key;
    std::vector<std::shared_ptr<SshChannel>> channels;
    bool failed = false;
    SshSessionUse use;
    SshSessionLifetime lifetime;
    std::weak_ptr<SshSession> lowerSession;
    void Start();
    void Drive();
    void Schedule();
    void Fail(int code, int error, const CStringA& detail, int hop = -1);
    void Dispose();
    bool HasObservers() const { for (const auto& c : channels) if (c->m->observer) return true; return false; }
    bool HasClients() const {
        for (const auto& c : channels)
            if (c->m->observer && !c->m->internalTransport) return true;
        return false;
    }
    void OnConnect(int error) override;
    void OnReceive(int error) override;
    void OnSend(int error) override;
    void OnClose(int error) override;
    int OnLayerCallback(const CAsyncSocketExLayer*, int type, int code, WPARAM error, LPARAM detail) override;
    void RemoveAllLayers() override { CAsyncSocketEx::RemoveAllLayers(); lower.Free(); }
private:
    enum Phase { TRANSPORT, HANDSHAKE, AUTH, READY } phase = TRANSPORT;
    CProxyChainLayers lower;
    CAsyncProxySocketLayer direct;
    LIBSSH2_SESSION* session = NULL;
    Buffer wire;
    bool disposed = false, transportReady = false;
    DWORD started = GetTickCount(), lastReceive = GetTickCount(), nextKeepalive = 0;
    size_t nextChannel = 0;
    bool Flush();
    void ChannelFailure(SshChannel::State& channel, int code, int error, const CStringA& detail, int hop);
    static ssize_t SendCallback(libssh2_socket_t, const void*, size_t, int, void**);
    static ssize_t ReceiveCallback(libssh2_socket_t, void*, size_t, int, void**);
};

namespace {
class Pool : public CWndTimer {
public:
    std::vector<std::shared_ptr<SshSession>> sessions;
    bool scheduled = false, pumping = false, deferred = false;
    Pool() { SetTimer(1, 1000); }
    void Schedule() { if (!scheduled) { scheduled = true; PostMessage(GetHwnd(), WM_SSH_PUMP, 0, 0); } }
    void OnTimer(UINT_PTR) override { Schedule(); }
    void Collect() {
        // Internal tunnels are dependencies, not business connections. Mark
        // all ancestors of actual clients, so an unused chain starts ONE idle
        // period instead of another 30 minutes for each SSH hop.
        std::unordered_set<SshSession*> needed, expired;
        for (const auto& candidate : sessions) {
            if (!candidate->HasClients()) continue;
            auto current = candidate;
            while (current && needed.insert(current.get()).second)
                current = current->lowerSession.lock();
        }
        const DWORD now = GetTickCount();
        std::vector<std::shared_ptr<SshSession>> retiring;
        for (const auto& session : sessions) {
            session->lifetime.Observe(needed.count(session.get()) != 0, now);
            if (session->lifetime.Expired(now) || (session->failed && !session->HasObservers())) {
                retiring.push_back(session); expired.insert(session.get());
            }
        }
        std::sort(retiring.begin(), retiring.end(), [](const std::shared_ptr<SshSession>& a,
            const std::shared_ptr<SshSession>& b) { return a->route.size() > b->route.size(); });
        for (const auto& session : retiring) session->Dispose();
        sessions.erase(std::remove_if(sessions.begin(), sessions.end(),
            [&expired](const std::shared_ptr<SshSession>& session) {
                return expired.count(session.get()) != 0;
            }), sessions.end());
    }
    void OnMessage(UINT message, WPARAM, LPARAM, BOOL& handled) override {
        if (message != WM_SSH_PUMP) return;
        handled = TRUE; scheduled = false;
        if (pumping) { deferred = true; return; }
        pumping = true;
        Collect(); // A completed/cancelled test must not continue its handshake.
        // Opening an SSH lower route can append another session to the pool.
        const auto snapshot = sessions;
        for (auto& session : snapshot) session->Drive();
        Collect();
        pumping = false;
        if (deferred) { deferred = false; Schedule(); }
    }
    ~Pool() {
        KillTimer(1);
        // Close dependants before their lower transports. Dispose does not
        // notify business layers during engine shutdown.
        for (auto& session : sessions) session->Dispose();
        sessions.clear();
    }
};
DWORD PoolSlot() {
    // Dynamic TLS keeps the injected hook loadable on legacy Windows. Cleanup
    // is explicit on the PRC/tester owning thread, before WSACleanup.
    static volatile LONG state = 0;
    static DWORD slot = TLS_OUT_OF_INDEXES;
    if (InterlockedCompareExchange(&state, 1, 0) == 0) {
        slot = TlsAlloc(); InterlockedExchange(&state, 2);
    } else while (InterlockedCompareExchange(&state, 2, 2) != 2) Sleep(0);
    return slot;
}
Pool* ExistingPool() { return static_cast<Pool*>(TlsGetValue(PoolSlot())); }
Pool& CurrentPool() {
    Pool* result = ExistingPool();
    if (!result) {
        std::unique_ptr<Pool> created(new Pool);
        if (!TlsSetValue(PoolSlot(), created.get())) throw std::bad_alloc();
        result = created.release();
    }
    return *result;
}
}

std::shared_ptr<SshChannel> SshSessionManager::Open(const ProxyChain& route,
    const CStringA& target, int port, CAsyncSshSocketLayer* observer,
    SshSessionUse use, SshSession* dependent)
{
    Pool& owner = CurrentPool();
    const std::string key = RouteKey(route);
    std::shared_ptr<SshSession> session;
    // Test probes own fresh sessions, including their lower SSH transports.
    // They never borrow a business session or revive a completed test.
    if (use == SshSessionUse::Business) for (const auto& candidate : owner.sessions)
        if (!candidate->failed && candidate->use == use && candidate->key == key) { session = candidate; break; }
    if (!session) {
        session = std::make_shared<SshSession>(route, key, use);
        owner.sessions.push_back(session);
    }
    auto channel = std::shared_ptr<SshChannel>(new SshChannel);
    channel->m->session = session; channel->m->observer = observer;
    channel->m->internalTransport = dependent != NULL;
    if (dependent) dependent->lowerSession = session;
    channel->m->target = target; channel->m->port = port;
    session->channels.push_back(channel);
    session->lifetime.Observe(true, GetTickCount());
    owner.Schedule(); // Never notify synchronously inside layer.Connect().
    return channel;
}
void SshSessionManager::ShutdownCurrentThread() {
    Pool* current = ExistingPool();
    TlsSetValue(PoolSlot(), NULL); delete current;
}

SshChannel::SshChannel() : m(new State) {}
SshChannel::~SshChannel() {}
int SshChannel::Send(const void* data, int length) {
    if (length < 0) { WSASetLastError(WSAEINVAL); return SOCKET_ERROR; }
    if (m->error || m->closed || m->shutdown) { WSASetLastError(m->error ? m->error : WSAESHUTDOWN); return SOCKET_ERROR; }
    if (!m->ready) { WSASetLastError(WSAEWOULDBLOCK); return SOCKET_ERROR; }
    if (!length) return 0;
    const size_t count = min(static_cast<size_t>(length), CHANNEL_BUFFER - m->outgoing.size);
    if (!count) { m->writeBlocked = true; WSASetLastError(WSAEWOULDBLOCK); return SOCKET_ERROR; }
    // Keep individual writes bounded for fair channel scheduling.
    const size_t accepted = min(count, static_cast<size_t>(32768));
    m->outgoing.Push(data, accepted);
    if (accepted < static_cast<size_t>(length)) m->writeBlocked = true;
    if (auto session = m->session.lock()) session->Schedule();
    return static_cast<int>(accepted);
}
int SshChannel::Receive(void* data, int length, int flags) {
    if (length < 0 || (flags & ~MSG_PEEK)) { WSASetLastError(WSAEINVAL); return SOCKET_ERROR; }
    if (!length) return 0;
    m->readNotified = false;
    if (m->incoming.size) {
        const size_t count = min(static_cast<size_t>(length), m->incoming.FrontSize());
        memcpy(data, m->incoming.Front(), count);
        if (!(flags & MSG_PEEK)) m->incoming.Consume(count);
        if (auto session = m->session.lock()) session->Schedule();
        return static_cast<int>(count);
    }
    if (m->error) { WSASetLastError(m->error); return SOCKET_ERROR; }
    if (m->eof || m->closed) return 0;
    WSASetLastError(WSAEWOULDBLOCK); return SOCKET_ERROR;
}
void SshChannel::Shutdown() { m->shutdown = true; if (auto s = m->session.lock()) s->Schedule(); }
void SshChannel::Detach() { m->observer = NULL; m->shutdown = true; m->incoming.Clear(); if (auto s = m->session.lock()) s->Schedule(); }
bool SshChannel::PendingRead() const { return m->incoming.size || (m->eof && !m->readNotified); }
int SshChannel::FailedHop() const { return m->failedHop; }

void SshSession::Schedule() { if (Pool* current = ExistingPool()) current->Schedule(); }
void SshSession::Start() {
    if (!Api().module) { Fail(PROXYERROR_SSH_UNAVAILABLE, WSAEPROTONOSUPPORT, "SSH backend unavailable"); return; }
    if (route.empty()) { Fail(PROXYERROR_REQUESTFAILED, WSAEINVAL, "Empty SSH route"); return; }
    const ProxyInfo& endpoint = route.back();
    if (route.size() > 1) {
        if (!lower.Add(*this, route.data(), static_cast<int>(route.size()-1), use, this)) {
            Fail(PROXYERROR_REQUESTFAILED, WSAGetLastError(), "Invalid SSH lower route"); return;
        }
    } else {
        direct.SetProxy(PROXYTYPE_NOPROXY); AddLayer(&direct);
    }
    _SockAddr numeric; numeric.Clear();
    const int family = route.size() == 1 && numeric.SetIP(endpoint.strProxyHost.szbuf) && numeric.IsIPv6() ? AF_INET6 : AF_INET;
    if (!Create(0, SOCK_STREAM, FD_CONNECT | FD_READ | FD_WRITE | FD_CLOSE, NULL, FALSE, family)) {
        Fail(PROXYERROR_NOCONN, WSAGetLastError(), "Cannot create SSH transport"); return;
    }
    const BOOL connected = family == AF_INET6
        ? (numeric.SetPort(static_cast<WORD>(endpoint.nProxyPort)), Connect(&numeric, numeric.Size()))
        : Connect(endpoint.strProxyHost.szbuf, endpoint.nProxyPort);
    if (!connected && WSAGetLastError() != WSAEWOULDBLOCK)
        Fail(PROXYERROR_NOCONN, WSAGetLastError(), "Cannot connect SSH transport");
}
void SshSession::OnConnect(int error) {
    if (error) Fail(PROXYERROR_NOCONN, error, "SSH transport connection failed");
    else transportReady = true;
    Schedule();
}
void SshSession::OnReceive(int error) { if (error) Fail(PROXYERROR_NOCONN, error, "SSH transport read failed"); Schedule(); }
void SshSession::OnSend(int error) { if (error) Fail(PROXYERROR_NOCONN, error, "SSH transport write failed"); Schedule(); }
void SshSession::OnClose(int error) { Fail(PROXYERROR_NOCONN, error ? error : WSAECONNRESET, "SSH transport disconnected"); }
int SshSession::OnLayerCallback(const CAsyncSocketExLayer* layer, int type, int code, WPARAM error, LPARAM detail) {
    if (type == LAYERCALLBACK_LAYERSPECIFIC && code && code != PROXYSTATUS_LISTENSOCKETCREATED) {
        const int hop = lower.HopOf(layer);
        Fail(code, error ? static_cast<int>(error) : WSAECONNREFUSED,
            detail ? CStringA(reinterpret_cast<LPCSTR>(detail)) : CStringA("SSH lower route failed"), hop);
    }
    return 0;
}
ssize_t SshSession::SendCallback(libssh2_socket_t, const void* data, size_t length, int, void** abstract) {
    auto& self = **reinterpret_cast<SshSession**>(abstract);
    if (self.disposed || self.failed) return -EIO;
    if (self.wire.size + length > WIRE_HIGH_WATER * 4) return -ENOBUFS;
    self.wire.Push(data, length);
    return static_cast<ssize_t>(length);
}
ssize_t SshSession::ReceiveCallback(libssh2_socket_t, void* data, size_t length, int, void** abstract) {
    auto& self = **reinterpret_cast<SshSession**>(abstract);
    if (self.disposed || self.failed) return -EIO;
    const int received = self.Receive(data, static_cast<int>(min(length, static_cast<size_t>(65536))));
    if (received > 0) self.lastReceive = GetTickCount();
    if (received == SOCKET_ERROR) return WSAGetLastError() == WSAEWOULDBLOCK ? -EAGAIN : -EIO;
    return received;
}
bool SshSession::Flush() {
    size_t budget = WIRE_HIGH_WATER;
    while (wire.size && budget) {
        const int sent = Send(wire.Front(), static_cast<int>(min(wire.FrontSize(), budget)));
        if (sent == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) return false;
        if (sent <= 0) { Fail(PROXYERROR_NOCONN, WSAECONNRESET, "SSH transport write failed"); return false; }
        wire.Consume(sent); budget -= sent;
    }
    if (wire.size) Schedule();
    return !wire.size;
}
void SshSession::ChannelFailure(SshChannel::State& c, int code, int error, const CStringA& detail, int hop) {
    if (c.error) return;
    c.error = error; c.failedHop = hop;
    auto* observer = c.observer;
    if (observer) observer->Failed(code, error, detail);
}
void SshSession::Fail(int code, int error, const CStringA& detail, int hop) {
    if (failed) return;
    failed = true;
    if (hop < 0) hop = static_cast<int>(route.size()) - 1;
    const auto snapshot = channels;
    for (auto& channel : snapshot) ChannelFailure(*channel->m, code, error, detail, hop);
    Schedule();
}
void SshSession::Dispose() {
    if (disposed) return;
    disposed = true;
    Close();
    if (session) { Api().session_free(session); session = NULL; }
    for (auto& c : channels) { c->m->handle = NULL; c->m->openOperation = NULL; c->m->closed = true; c->m->error = WSAECONNRESET; }
    wire.Clear();
}

void SshSession::Drive() {
    if (disposed || failed) return;
    if (GetSocketHandle() == INVALID_SOCKET) { Start(); if (failed) return; }
    const DWORD now = GetTickCount();
    if (phase != READY && now - started > 60000) { Fail(PROXYERROR_NOCONN, WSAETIMEDOUT, "SSH handshake timed out"); return; }
    if (!transportReady) return;
    SshApi& api = Api();
    if (!session) {
        session = api.session_init_ex(NULL, NULL, NULL, this);
        if (!session) { Fail(PROXYERROR_REQUESTFAILED, WSAENOBUFS, "Cannot allocate SSH session"); return; }
        api.session_set_blocking(session, 0);
        api.session_callback_set2(session, LIBSSH2_CALLBACK_SEND, reinterpret_cast<libssh2_cb_generic*>(SendCallback));
        api.session_callback_set2(session, LIBSSH2_CALLBACK_RECV, reinterpret_cast<libssh2_cb_generic*>(ReceiveCallback));
        phase = HANDSHAKE;
    }
    Flush(); if (failed) return;
    if (wire.size >= WIRE_HIGH_WATER && phase != READY) return;
    const ProxyInfo& endpoint = route.back();
    if (phase == HANDSHAKE) {
        const int result = api.session_handshake(session, GetSocketHandle());
        Flush(); if (failed || result == LIBSSH2_ERROR_EAGAIN) return;
        if (result) { Fail(PROXYERROR_REQUESTFAILED, WSAEPROTONOSUPPORT, "SSH key exchange failed"); return; }
        const char* digest = api.hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA256);
        if (!digest) { Fail(PROXYERROR_REQUESTFAILED, WSAEACCES, "SSH host key unavailable"); return; }
        const CStringA fingerprint = Fingerprint(digest);
        if (!endpoint.strTransportPsk.szbuf[0]) {
            Fail(PROXYERROR_SSH_HOSTKEY_UNKNOWN, WSAEACCES, fingerprint); return;
        }
        if (fingerprint != endpoint.strTransportPsk.szbuf) {
            Fail(PROXYERROR_SSH_HOSTKEY_CHANGED, WSAEACCES, fingerprint); return;
        }
        phase = AUTH;
    }
    if (phase == AUTH) {
        const int result = api.userauth_password_ex(session, endpoint.strProxyUser.szbuf,
            static_cast<unsigned int>(strlen(endpoint.strProxyUser.szbuf)), endpoint.strProxyPass.szbuf,
            static_cast<unsigned int>(strlen(endpoint.strProxyPass.szbuf)), NULL);
        Flush(); if (failed || result == LIBSSH2_ERROR_EAGAIN) return;
        if (result) { Fail(PROXYERROR_AUTHFAILED, WSAEACCES, "SSH password authentication failed"); return; }
        phase = READY; lastReceive = now; nextKeepalive = now + KEEPALIVE_INTERVAL;
        api.keepalive_config(session, 1, KEEPALIVE_INTERVAL / 1000);
    }
    const int pumped = api.pump(session);
    if (pumped < 0) { Fail(PROXYERROR_NOCONN, WSAECONNRESET, "SSH session disconnected"); return; }
    if (pumped > 0) Schedule();
    // Pump may update lastReceive after the tick sampled above. Resample to
    // avoid unsigned underflow falsely expiring a busy, healthy connection.
    if (GetTickCount() - lastReceive >= RESPONSE_TIMEOUT) {
        Fail(PROXYERROR_NOCONN, WSAETIMEDOUT, "SSH keepalive response timed out"); return;
    }
    if (wire.size < WIRE_HIGH_WATER && static_cast<LONG>(now - nextKeepalive) >= 0) {
        int next = 15;
        if (api.keepalive_send(session, &next)) { Fail(PROXYERROR_NOCONN, WSAECONNRESET, "SSH keepalive failed"); return; }
        nextKeepalive = now + max(1, next) * 1000;
    }
    // A blocked outgoing stream must not bypass liveness/open deadlines.
    const auto snapshot = channels;
    size_t pending = 0;
    for (const auto& item : snapshot) if (item->m->openOperation) ++pending;
    for (const auto& item : snapshot) {
        auto& c = *item->m;
        if (c.ready || c.closed) continue;
        if (!c.error && c.observer && GetTickCount() - c.started >= 60000)
            ChannelFailure(c, PROXYERROR_REQUESTFAILED, WSAETIMEDOUT,
                "SSH channel open timed out", static_cast<int>(route.size())-1);
        if (c.openOperation && (!c.observer || c.error)) api.channel_open_cancel(c.openOperation);
        if (wire.size >= WIRE_HIGH_WATER) continue;
        if (!c.openOperation && !c.error && c.observer && pending < MAX_PENDING_OPENS) {
            c.openOperation = api.channel_direct_tcpip_begin(session, c.target, c.port, "127.0.0.1", 0);
            if (!c.openOperation) {
                ChannelFailure(c, PROXYERROR_REQUESTFAILED, WSAENOBUFS,
                    "Cannot allocate SSH channel open", static_cast<int>(route.size())-1);
                continue;
            }
            ++pending;
        }
        if (!c.openOperation) continue;
        // Cancellation cannot retract an SSH OPEN already on the wire. Keep
        // polling its operation to close a late confirmation. It still counts
        // against the bound, so a peer withholding replies cannot leak memory.
        const int result = api.channel_open_poll(c.openOperation, &c.handle);
        if (result == LIBSSH2_ERROR_EAGAIN) continue;
        c.openOperation = NULL; --pending;
        if (!result) {
            c.ready = true;
            if (c.observer) c.observer->Ready();
        } else if (result == LIBSSH2_ERROR_CHANNEL_FAILURE || result == LIBSSH2_ERROR_CHANNEL_CLOSED) {
            c.closed = true;
            if (!c.error && c.observer)
                ChannelFailure(c, PROXYERROR_REQUESTFAILED, WSAECONNREFUSED,
                    "SSH forwarding denied or target unreachable", static_cast<int>(route.size())-1);
        } else {
            Fail(PROXYERROR_NOCONN, WSAECONNRESET, "SSH channel transport failed"); return;
        }
        Schedule();
    }
    // Rotate the first channel to keep a busy stream from monopolizing output.
    for (size_t j = 0; j < snapshot.size() && wire.size < WIRE_HIGH_WATER; ++j) {
        auto& c = *snapshot[(nextChannel+j) % snapshot.size()]->m;
        if (!c.handle || c.closed) continue;
        if (c.error) {
            if (!c.observer && api.channel_free(c.handle) != LIBSSH2_ERROR_EAGAIN) {
                c.handle = NULL; c.closed = true;
            }
            continue;
        }
        if (c.outgoing.size) {
            const ssize_t sent = api.channel_write_ex(c.handle, 0, c.outgoing.Front(), c.outgoing.FrontSize());
            if (sent > 0) {
                c.outgoing.Consume(static_cast<size_t>(sent)); Schedule();
                if (c.writeBlocked && c.outgoing.size < CHANNEL_BUFFER) {
                    c.writeBlocked = false; if (c.observer) c.observer->Writable();
                }
            } else if (sent < 0 && sent != LIBSSH2_ERROR_EAGAIN) {
                ChannelFailure(c, PROXYERROR_REQUESTFAILED, WSAECONNRESET, "SSH channel write failed", static_cast<int>(route.size())-1); continue;
            }
        }
        if (!c.eof && c.incoming.size < CHANNEL_BUFFER) {
            char buffer[32768];
            const ssize_t received = api.channel_read_ex(c.handle, 0, buffer, min(sizeof(buffer), CHANNEL_BUFFER-c.incoming.size));
            if (received > 0) { if (c.observer) c.incoming.Push(buffer, received); Schedule(); }
            else if (received < 0 && received != LIBSSH2_ERROR_EAGAIN) {
                ChannelFailure(c, PROXYERROR_REQUESTFAILED, WSAECONNRESET, "SSH channel read failed", static_cast<int>(route.size())-1); continue;
            }
            if (api.channel_eof(c.handle)) c.eof = true;
        }
        if (c.observer && !c.readNotified && (c.incoming.size || c.eof)) {
            c.readNotified = true; c.observer->Readable();
        }
        if (c.shutdown && !c.outgoing.size && !c.eofSent) {
            const int result = api.channel_send_eof(c.handle);
            if (result != LIBSSH2_ERROR_EAGAIN) c.eofSent = true;
        }
        if (!c.observer && !c.outgoing.size && c.eofSent) {
            const int result = api.channel_free(c.handle);
            if (result != LIBSSH2_ERROR_EAGAIN) { c.handle = NULL; c.closed = true; }
        }
    }
    if (!snapshot.empty()) nextChannel = (nextChannel + 1) % snapshot.size();
    channels.erase(std::remove_if(channels.begin(), channels.end(), [](const std::shared_ptr<SshChannel>& c) {
        return !c->m->observer && !c->m->openOperation && (!c->m->handle || c->m->closed);
    }), channels.end());
    Flush();
}
