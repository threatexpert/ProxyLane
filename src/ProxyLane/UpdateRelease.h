#pragma once
#include "../../third_party/nlohmann/json.hpp"
#include <array>
#include <string>

namespace UpdateRelease
{
#ifdef PROXYLANE_UPDATE_LOCAL_TEST
// Test builds only (compile with /DPROXYLANE_UPDATE_LOCAL_TEST): use the local
// server from scripts/serve-update-test.py instead of the download site.
static const wchar_t ApiUrl[] = L"http://127.0.0.1:8765/api/tools/proxylane/release";
static const wchar_t AssetOrigin[] = L"http://127.0.0.1:8765";
#else
static const wchar_t ApiUrl[] = L"https://10000.download/api/tools/proxylane/release";
// Installer downloads are fetched from this fixed origin only; metadata supplies
// a path below AssetPathPrefix, never a host.
static const wchar_t AssetOrigin[] = L"https://10000.download";
#endif
static const wchar_t DownloadUrl[] = L"https://10000.download/tools";
static const wchar_t SiteUrl[] = L"https://10000.download/";
static const char AssetPathPrefix[] = "/d/proxylane/";
static const size_t MaxResponseBytes = 1024 * 1024;
static const unsigned long long MaxInstallerBytes = 256ULL * 1024 * 1024;
using VersionParts = std::array<unsigned, 4>;

struct Installer
{
    std::string name;   // ProxyLane-<version>-Setup.exe
    std::string path;   // /d/proxylane/<id>
    std::string sha256; // 64 lowercase hex digits
    unsigned long long size = 0;
    bool Available() const { return !path.empty(); }
};

inline bool Version(const std::string& text, VersionParts& parts)
{
    parts = {};
    size_t start = !text.empty() && (text[0] == 'v' || text[0] == 'V') ? 1 : 0;
    unsigned count = 0;
    while (start < text.size()) {
        size_t end = text.find('.', start);
        if (end == std::string::npos) end = text.size();
        if (count == parts.size() || end == start || end - start > 5) return false;
        unsigned value = 0;
        for (size_t i = start; i < end; ++i) {
            if (text[i] < '0' || text[i] > '9') return false;
            value = value * 10 + text[i] - '0';
        }
        parts[count++] = value;
        start = end + 1;
    }
    return count >= 2 && text.back() != '.';
}

inline std::string PlainVersion(const std::string& tag)
{
    return !tag.empty() && (tag[0] == 'v' || tag[0] == 'V') ? tag.substr(1) : tag;
}

inline std::string InstallerName(const std::string& tag)
{
    return "ProxyLane-" + PlainVersion(tag) + "-Setup.exe";
}

inline bool IsAssetPath(const std::string& path)
{
    const size_t prefix = sizeof(AssetPathPrefix) - 1;
    if (path.size() <= prefix || path.size() > prefix + 64 || path.compare(0, prefix, AssetPathPrefix) != 0) return false;
    for (size_t i = prefix; i < path.size(); ++i) {
        const char c = path[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-' || c == '_')) return false;
    }
    return true;
}

inline bool NormalizeSha256(std::string value, std::string& digest)
{
    digest.clear();
    // Accept GitHub's asset "digest" form as well as a bare hex value.
    if (value.size() == 71 && value.compare(0, 7, "sha256:") == 0) value.erase(0, 7);
    if (value.size() != 64) return false;
    for (char& c : value) {
        if (c >= 'A' && c <= 'F') c = static_cast<char>(c - 'A' + 'a');
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    digest = value;
    return true;
}

// The installer asset is optional. It is accepted only with an exact file name
// for the advertised version, a fixed-origin asset path, a size and a SHA-256.
inline void ParseInstaller(const nlohmann::json& value, const std::string& tag, Installer& installer)
{
    installer = Installer();
    if (!value.contains("assets") || !value.at("assets").is_array()) return;
    const std::string expected = InstallerName(tag);
    for (const auto& asset : value.at("assets")) {
        if (!asset.is_object()) continue;
        const auto name = asset.find("name");
        const auto path = asset.find("path");
        const auto size = asset.find("size");
        if (name == asset.end() || !name->is_string() || name->get<std::string>() != expected) continue;
        if (path == asset.end() || !path->is_string() || !IsAssetPath(path->get<std::string>())) continue;
        if (size == asset.end() || !size->is_number_unsigned()) continue;
        const unsigned long long bytes = size->get<unsigned long long>();
        if (!bytes || bytes > MaxInstallerBytes) continue;
        std::string digest;
        const auto sha = asset.find("sha256");
        const auto github = asset.find("digest");
        if (!((sha != asset.end() && sha->is_string() && NormalizeSha256(sha->get<std::string>(), digest)) ||
              (github != asset.end() && github->is_string() && NormalizeSha256(github->get<std::string>(), digest)))) continue;
        installer.name = expected;
        installer.path = path->get<std::string>();
        installer.sha256 = digest;
        installer.size = bytes;
        return;
    }
}

// The download service returns only stable releases. Never open URLs supplied
// by metadata: version checking and browsing use the fixed site URLs above,
// and installer downloads combine AssetOrigin with a validated asset path.
inline bool Parse(const std::string& body, std::string& tag, Installer* installer = nullptr)
{
    tag.clear();
    if (installer) *installer = Installer();
    if (body.size() > MaxResponseBytes) return false;
    try {
        const auto value = nlohmann::json::parse(body);
        if (!value.is_object() || !value.contains("version") || !value.at("version").is_string()) return false;
        const std::string candidate = value.at("version").get<std::string>();
        VersionParts parts;
        if (!Version(candidate, parts)) return false;
        tag = candidate;
        if (installer) ParseInstaller(value, candidate, *installer);
        return true;
    } catch (const nlohmann::json::exception&) { return false; }
}
}
