#include "stdafx.h"
#include "MihomoCore.h"
#include "ConfigStorage.h"
#include "ExtensionUri.h"
#include "../../third_party/nlohmann/json.hpp"
#include <winhttp.h>
#include <iphlpapi.h>
#include <shellapi.h>
#include <vector>
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")

namespace
{
    CString CorePath(const CString& ini)
    {
        if (ini.IsEmpty()) return CString();
        return ConfigStorage::Directory(ini) + L"\\extensions\\upstream\\mihomo\\mihomo.exe";
    }

    enum ProviderState { ProviderPending, ProviderEmpty, ProviderReady };

    bool IsPseudoProxyType(const std::string& type)
    {
        return type.empty() || !_stricmp(type.c_str(), "direct") || !_stricmp(type.c_str(), "reject") ||
            !_stricmp(type.c_str(), "rejectdrop") || !_stricmp(type.c_str(), "pass") ||
            !_stricmp(type.c_str(), "compatible") || !_stricmp(type.c_str(), "dns");
    }

    CString ExtractLogError(const CString& logPath)
    {
        if (logPath.IsEmpty()) return CString();
        HANDLE file = CreateFile(logPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (file == INVALID_HANDLE_VALUE) return CString();
        LARGE_INTEGER size = {};
        std::string content;
        if (GetFileSizeEx(file, &size) && size.QuadPart > 0) {
            const DWORD maxRead = 16384;
            if (size.QuadPart > maxRead) SetFilePointer(file, -static_cast<LONG>(maxRead), NULL, FILE_END);
            std::vector<char> buffer(maxRead);
            DWORD read = 0;
            if (ReadFile(file, buffer.data(), maxRead, &read, NULL) && read)
                content.assign(buffer.data(), read);
        }
        CloseHandle(file);
        if (content.empty()) return CString();

        auto extractMsg = [](const std::string& line) -> std::string {
            const size_t pos = line.find("msg=\"");
            if (pos == std::string::npos) return line;
            std::string msg;
            for (size_t i = pos + 5; i < line.size(); ++i) {
                if (line[i] == '\\' && i + 1 < line.size()) {
                    const char next = line[++i];
                    msg.push_back(next == 'n' || next == 'r' ? ' ' : next);
                } else if (line[i] == '"') {
                    break;
                } else {
                    msg.push_back(line[i]);
                }
            }
            return msg;
        };

        std::string fatal, error, warning, fallback;
        size_t start = 0;
        while (start < content.size()) {
            size_t end = content.find_first_of("\r\n", start);
            if (end == std::string::npos) end = content.size();
            std::string line = content.substr(start, end - start);
            while (end < content.size() && (content[end] == '\r' || content[end] == '\n')) ++end;
            start = end;
            if (line.empty()) continue;
            if (line.find("level=fatal") != std::string::npos) fatal = extractMsg(line);
            else if (line.find("level=error") != std::string::npos) error = extractMsg(line);
            else if (line.find("level=warning") != std::string::npos) warning = extractMsg(line);
            else if (line.find("level=info") == std::string::npos) fallback = line;
        }
        std::string chosen = !fatal.empty() ? fatal : !error.empty() ? error : !warning.empty() ? warning : fallback;
        if (chosen.empty()) return CString();
        if (chosen.size() > 360) chosen = chosen.substr(0, 357) + "...";
        return CString(CA2W(chosen.c_str(), CP_UTF8));
    }

    CString UniqueId()
    {
        GUID id;
        wchar_t buffer[40];
        if (FAILED(CoCreateGuid(&id)) || !StringFromGUID2(id, buffer, _countof(buffer))) return CString();
        return CString(buffer + 1, 36);
    }

    bool WriteUtf8(const CString& path, const CString& text)
    {
        CStringA bytes(CW2A(text, CP_UTF8));
        HANDLE file = CreateFile(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        if (file == INVALID_HANDLE_VALUE) return false;
        DWORD written = 0;
        const bool ok = WriteFile(file, bytes.GetString(), bytes.GetLength(), &written, NULL) &&
            written == static_cast<DWORD>(bytes.GetLength());
        CloseHandle(file);
        return ok;
    }

    // Keep both ephemeral port reservations until the child is about to run.
    struct Port
    {
        SOCKET socketHandle = INVALID_SOCKET;
        unsigned number = 0;
        ~Port() { Release(); }
        void Release() {
            if (socketHandle != INVALID_SOCKET) closesocket(socketHandle);
            socketHandle = INVALID_SOCKET;
        }
        bool Reserve(int type = SOCK_STREAM, unsigned port = 0) {
            socketHandle = socket(AF_INET, type, 0);
            if (socketHandle != INVALID_SOCKET)
                SetHandleInformation(reinterpret_cast<HANDLE>(socketHandle), HANDLE_FLAG_INHERIT, 0);
            sockaddr_in address = {};
            address.sin_family = AF_INET;
            address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            address.sin_port = htons(static_cast<u_short>(port));
            int length = sizeof(address);
            if (socketHandle == INVALID_SOCKET || ::bind(socketHandle, (sockaddr*)&address, length) ||
                getsockname(socketHandle, (sockaddr*)&address, &length)) return false;
            number = ntohs(address.sin_port);
            return true;
        }
    };

    bool ReserveSocksPort(Port& tcp, Port& udp)
    {
        for (int attempt = 0; attempt < 8; ++attempt) {
            if (!tcp.Reserve()) return false;
            if (udp.Reserve(SOCK_DGRAM, tcp.number)) return true;
            tcp.Release();
            udp.Release();
        }
        return false;
    }

    struct HttpHandle
    {
        HINTERNET handle;
        explicit HttpHandle(HINTERNET value) : handle(value) {}
        ~HttpHandle() { if (handle) WinHttpCloseHandle(handle); }
    };

    // A live listener alone is insufficient: a malformed file provider can
    // leave Mihomo running with an empty group. Check the parsed provider.
    ProviderState QueryNodeProvider(HINTERNET connection, const CString& secret)
    {
        HttpHandle request(WinHttpOpenRequest(connection, L"GET", L"/providers/proxies/node",
            NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0));
        const CString header = L"Authorization: Bearer " + secret;
        DWORD disable = WINHTTP_DISABLE_REDIRECTS;
        if (!request.handle || !WinHttpSetOption(request.handle, WINHTTP_OPTION_DISABLE_FEATURE, &disable, sizeof(disable)) ||
            !WinHttpSendRequest(request.handle, header, -1, NULL, 0, 0, 0) ||
            !WinHttpReceiveResponse(request.handle, NULL)) return ProviderPending;
        DWORD status = 0, size = sizeof(status);
        if (!WinHttpQueryHeaders(request.handle, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            NULL, &status, &size, NULL) || status != 200) return ProviderPending;
        std::string body;
        char buffer[2048];
        DWORD count;
        do {
            if (!WinHttpReadData(request.handle, buffer, sizeof(buffer), &count)) return ProviderPending;
            body.append(buffer, count);
            if (body.size() > 65536) return ProviderEmpty;
        } while (count);
        auto data = nlohmann::json::parse(body, nullptr, false);
        if (!data.is_object() || !data.contains("proxies") || !data["proxies"].is_array()) return ProviderPending;
        if (data["proxies"].empty()) return ProviderEmpty;
        if (data["proxies"].size() != 1) return ProviderEmpty;
        const auto& parsed = data["proxies"][0];
        if (!parsed.is_object() || !parsed.contains("type") || !parsed["type"].is_string()) return ProviderEmpty;
        return IsPseudoProxyType(parsed["type"].get_ref<const std::string&>()) ? ProviderEmpty : ProviderReady;
    }

    // Another process can acquire a reserved port between release and bind.
    // Verify both listeners before sending the API secret or publishing SOCKS.
    bool OwnsListeners(DWORD pid, unsigned socks, unsigned controller)
    {
        // Resolve on demand so ordinary profiles retain their XP import surface.
        wchar_t system[MAX_PATH];
        const UINT length = GetSystemDirectoryW(system, _countof(system));
        if (!length || length >= _countof(system)) return false;
        HMODULE library = LoadLibraryW(CString(system) + L"\\iphlpapi.dll");
        if (!library) return false;
        auto query = reinterpret_cast<decltype(&GetExtendedTcpTable)>(GetProcAddress(library, "GetExtendedTcpTable"));
        ULONG size = 0;
        std::vector<BYTE> buffer;
        bool data = false, api = false;
        if (query && query(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0) == ERROR_INSUFFICIENT_BUFFER) {
            buffer.resize(size);
            if (query(buffer.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0) == NO_ERROR) {
                const auto table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buffer.data());
                for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                    const auto& row = table->table[i];
                    if (row.dwOwningPid != pid || row.dwLocalAddr != htonl(INADDR_LOOPBACK)) continue;
                    const unsigned port = ntohs(static_cast<u_short>(row.dwLocalPort));
                    if (port == socks) data = true;
                    if (port == controller) api = true;
                }
            }
        }
        auto queryUdp = reinterpret_cast<decltype(&GetExtendedUdpTable)>(GetProcAddress(library, "GetExtendedUdpTable"));
        bool relay = false;
        size = 0;
        if (data && api && queryUdp && queryUdp(NULL, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == ERROR_INSUFFICIENT_BUFFER) {
            buffer.resize(size);
            if (queryUdp(buffer.data(), &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
                const auto table = reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(buffer.data());
                for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                    const auto& row = table->table[i];
                    if (row.dwOwningPid == pid && row.dwLocalAddr == htonl(INADDR_LOOPBACK) &&
                        ntohs(static_cast<u_short>(row.dwLocalPort)) == socks) { relay = true; break; }
                }
            }
        }
        FreeLibrary(library);
        return relay;
    }

    bool Spawn(const CString& exe, const CString& directory, PROCESS_INFORMATION& process)
    {
        CString command = L"\"" + exe + L"\" -d \"" + directory + L"\" -f \"" + directory + L"\\config.yaml\"";
        // Isolate profiles from CLASH_CONFIG_STRING, CLASH_POST_UP, etc. inherited
        // from a separately installed core. Ordinary Windows variables remain.
        std::vector<wchar_t> environment;
        LPWCH block = GetEnvironmentStringsW();
        if (!block) return false;
        for (LPCWSTR p = block; *p; p += wcslen(p) + 1) {
            if (_wcsnicmp(p, L"CLASH_", 6) && _wcsnicmp(p, L"MIHOMO_", 7))
                environment.insert(environment.end(), p, p + wcslen(p) + 1);
        }
        FreeEnvironmentStringsW(block);
        environment.push_back(0);
        STARTUPINFO si = {sizeof(si)};
        DWORD flags = CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT;
        HANDLE token = NULL;
        TOKEN_ELEVATION elevation = {};
        DWORD length = 0;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
        bool ok = false;
        if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &length)) {
            if (elevation.TokenIsElevated) {
                // The executable is user-installed. Run it with the paired
                // standard token even when ProxyLane was started as administrator.
                TOKEN_LINKED_TOKEN linked = {};
                if (GetTokenInformation(token, TokenLinkedToken, &linked, sizeof(linked), &length)) {
                    auto launch = reinterpret_cast<decltype(&CreateProcessWithTokenW)>(
                        GetProcAddress(GetModuleHandleW(L"advapi32.dll"), "CreateProcessWithTokenW"));
                    ok = launch && launch(linked.LinkedToken, 0, exe, command.GetBuffer(), flags,
                        environment.data(), directory, &si, &process);
                    CloseHandle(linked.LinkedToken);
                }
            } else {
                SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
                HANDLE logFile = CreateFileW(directory + L"\\mihomo.log", GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                if (logFile != INVALID_HANDLE_VALUE) {
                    si.dwFlags |= STARTF_USESTDHANDLES;
                    si.hStdOutput = logFile;
                    si.hStdError = logFile;
                    si.hStdInput = INVALID_HANDLE_VALUE;
                }
                // Limit inherited handles on Vista+ so unrelated threads' handles cannot leak into mihomo.
                HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
                auto initList = kernel ? reinterpret_cast<decltype(&InitializeProcThreadAttributeList)>(
                    GetProcAddress(kernel, "InitializeProcThreadAttributeList")) : NULL;
                auto updateList = kernel ? reinterpret_cast<decltype(&UpdateProcThreadAttribute)>(
                    GetProcAddress(kernel, "UpdateProcThreadAttribute")) : NULL;
                auto deleteList = kernel ? reinterpret_cast<decltype(&DeleteProcThreadAttributeList)>(
                    GetProcAddress(kernel, "DeleteProcThreadAttributeList")) : NULL;
                std::vector<BYTE> attrBuffer;
                STARTUPINFOEXW siEx = { si };
                bool useAttrList = false;
                if (logFile != INVALID_HANDLE_VALUE && initList && updateList && deleteList) {
                    SIZE_T attrSize = 0;
                    initList(NULL, 1, 0, &attrSize);
                    if (attrSize) {
                        attrBuffer.resize(attrSize);
                        auto list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attrBuffer.data());
                        if (initList(list, 1, 0, &attrSize) &&
                            updateList(list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &logFile, sizeof(logFile), NULL, NULL)) {
                            siEx.StartupInfo.cb = sizeof(siEx);
                            siEx.lpAttributeList = list;
                            useAttrList = true;
                        }
                    }
                }
                ok = CreateProcessW(exe, command.GetBuffer(), NULL, NULL, logFile != INVALID_HANDLE_VALUE,
                    flags | (useAttrList ? EXTENDED_STARTUPINFO_PRESENT : 0),
                    environment.data(), directory, &siEx.StartupInfo, &process) != FALSE;
                if (useAttrList) deleteList(siEx.lpAttributeList);
                if (logFile != INVALID_HANDLE_VALUE) CloseHandle(logFile);
            }
        }
        CloseHandle(token);
        return ok;
    }
}

CString MihomoCore::TargetPath()
{
    return CorePath(ConfigStorage::Path());
}

CString MihomoCore::InstalledPath()
{
    CString exe = CorePath(ConfigStorage::Path());
    if (!exe.IsEmpty() && GetFileAttributes(exe) != INVALID_FILE_ATTRIBUTES) return exe;
    const CString userExe = CorePath(ConfigStorage::UserPath());
    if (!userExe.IsEmpty() && GetFileAttributes(userExe) != INVALID_FILE_ATTRIBUTES) return userExe;
    return CString();
}

bool MihomoCore::Browse(HWND owner, const CString& path)
{
    if (path.IsEmpty()) return false;
    if (GetFileAttributes(path) != INVALID_FILE_ATTRIBUTES) {
        const CString args = L"/select,\"" + path + L"\"";
        if (reinterpret_cast<INT_PTR>(ShellExecuteW(owner, L"open", L"explorer.exe", args, NULL, SW_SHOWNORMAL)) > 32)
            return true;
    }
    const CString directory = ConfigStorage::Directory(path);
    return !directory.IsEmpty() &&
        reinterpret_cast<INT_PTR>(ShellExecuteW(owner, L"open", directory, NULL, NULL, SW_SHOWNORMAL)) > 32;
}

bool MihomoCore::Install(const CString& source, CString& path, CString& error)
{
    path = CorePath(ConfigStorage::Path());
    const CString id = UniqueId();
    if (source.CompareNoCase(path) == 0) return true;
    if (!path.IsEmpty() && !id.IsEmpty() && ConfigStorage::EnsureDirectory(ConfigStorage::Directory(path))) {
        CString staged = path + L"." + id + L".tmp";
        if (CopyFile(source, staged, TRUE)) {
            if (MoveFileEx(staged, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) return true;
            const DWORD code = GetLastError();
            DeleteFile(staged);
            SetLastError(code);
        }
    }
    error = ConfigStorage::ErrorText(GetLastError());
    return false;
}

bool MihomoCore::Alive() const
{
    return m_process && WaitForSingleObject(m_process, 0) == WAIT_TIMEOUT;
}

MihomoCore::~MihomoCore()
{
    if (m_job) CloseHandle(m_job); // KILL_ON_JOB_CLOSE also handles host crashes.
    if (m_process) { WaitForSingleObject(m_process, 2000); CloseHandle(m_process); }
    if (!m_directory.IsEmpty()) {
        for (LPCWSTR file : {L"node.txt", L"config.yaml", L"cache.db", L"mihomo.log"})
            DeleteFile(m_directory + L"\\" + file);
        RemoveDirectory(m_directory);
    }
}

CString MihomoCore::LastError() const
{
    if (m_directory.IsEmpty()) return CString();
    return ExtractLogError(m_directory + L"\\mihomo.log");
}

void MihomoCore::SetEndpoint(ProxyInfo& endpoint) const
{
    endpoint.strProxyType = L"SOCKS5";
    endpoint.strProxyHost = L"127.0.0.1";
    endpoint.nProxyPort = m_port;
    endpoint.strProxyUser = L"pl";
    endpoint.strProxyPass = m_password;
    endpoint.extensionEndpoint = TRUE;
}

bool MihomoCore::Start(const CString& uri, ProxyInfo& endpoint, CString& errorKey, CString* errorDetail)
{
    if (errorDetail) errorDetail->Empty();
    errorKey = L"extension.invalid";
    if (!ExtensionUri::Valid(uri.GetString(), uri.GetLength())) return false;
    const CString userIni = ConfigStorage::UserPath();
    CString exe = InstalledPath();
    errorKey = L"extension.missing";
    if (exe.IsEmpty()) return false;

    errorKey = L"extension.start_failed";
    WSADATA winsock;
    if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) return false;
    struct WinsockScope { ~WinsockScope() { WSACleanup(); } } winsockScope;
    Port socks, udp, control;
    const CString id = UniqueId(), password = UniqueId(), secret = UniqueId();
    if (userIni.IsEmpty() || id.IsEmpty() || password.IsEmpty() || secret.IsEmpty() ||
        !ReserveSocksPort(socks, udp) || !control.Reserve()) return false;
    const CString parent = ConfigStorage::Directory(userIni) + L"\\runtime";
    const CString directory = parent + L"\\" + id;
    if (!ConfigStorage::EnsureDirectory(parent) || !CreateDirectory(directory, NULL)) return false;
    m_directory = directory;
    CString config;
    config.Format(L"mode: rule\nlog-level: warning\nipv6: true\nfind-process-mode: off\n"
        L"sniffer:\n"
        L"  enable: true\n"
        L"  force-dns-mapping: true\n"
        L"  parse-pure-ip: true\n"
        L"  override-destination: true\n"
        L"  sniff:\n"
        L"    HTTP: {ports: [80, 8080-8880], override-destination: true}\n"
        L"    TLS: {ports: [443, 8443]}\n"
        L"    QUIC: {ports: [443, 8443]}\n"
        L"external-controller: 127.0.0.1:%u\nsecret: '%s'\nprofile: {store-selected: false}\n"
        L"listeners:\n  - name: local\n    type: socks\n    listen: 127.0.0.1\n    port: %u\n"
        L"    udp: true\n    users: [{username: pl, password: '%s'}]\n    proxy: PL-Node\n"
        L"proxy-providers:\n  node: {type: file, path: ./node.txt, interval: 0}\n"
        L"proxy-groups:\n  - {name: PL-Node, type: select, use: [node], empty-fallback: REJECT}\n"
        L"rules: ['MATCH,REJECT']\n", control.number, secret.GetString(), socks.number, password.GetString());
    if (!WriteUtf8(directory + L"\\node.txt", uri + L"\n") ||
        !WriteUtf8(directory + L"\\config.yaml", config)) return false;

    m_job = CreateJobObject(NULL, NULL);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!m_job || !SetInformationJobObject(m_job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) return false;
    PROCESS_INFORMATION child = {};
    if (!Spawn(exe, directory, child)) return false;
    m_process = child.hProcess;
    socks.Release(); udp.Release(); control.Release();
    bool started = AssignProcessToJobObject(m_job, m_process) && ResumeThread(child.hThread) != DWORD(-1);
    CloseHandle(child.hThread);
    if (!started) { TerminateProcess(m_process, 1); return false; }

    HttpHandle session(WinHttpOpen(L"ProxyLane", WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, 0));
    if (!session.handle || !WinHttpSetTimeouts(session.handle, 300, 300, 400, 400)) return false;
    HttpHandle connection(WinHttpConnect(session.handle, L"127.0.0.1", static_cast<INTERNET_PORT>(control.number), 0));
    if (!connection.handle) return false;
    const DWORD before = GetTickCount();
    do {
        if (WaitForSingleObject(m_process, 50) != WAIT_TIMEOUT) break;
        if (OwnsListeners(child.dwProcessId, socks.number, control.number) && Alive()) {
            const ProviderState state = QueryNodeProvider(connection.handle, secret);
            if (state == ProviderReady) {
                m_port = socks.number;
                m_password = password;
                SetEndpoint(endpoint);
                return true;
            }
            if (state == ProviderEmpty) break;
        }
    } while (GetTickCount() - before < 4500);
    if (errorDetail) *errorDetail = LastError();
    errorKey = L"extension.not_ready";
    return false;
}
