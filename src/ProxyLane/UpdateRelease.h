#pragma once
#include "../../third_party/nlohmann/json.hpp"
#include <array>
#include <string>

namespace UpdateRelease
{
static const wchar_t ApiUrl[] = L"https://10000.download/api/tools/proxylane/release";
static const wchar_t DownloadUrl[] = L"https://10000.download/tools";
static const wchar_t SiteUrl[] = L"https://10000.download/";
static const size_t MaxResponseBytes = 1024 * 1024;
using VersionParts = std::array<unsigned, 4>;

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

// The download service returns only stable releases. Never open URLs supplied
// by metadata: version checking and browsing use the fixed site URLs above.
inline bool Parse(const std::string& body, std::string& tag)
{
    tag.clear();
    if (body.size() > MaxResponseBytes) return false;
    try {
        const auto value = nlohmann::json::parse(body);
        if (!value.is_object() || !value.contains("version") || !value.at("version").is_string()) return false;
        const std::string candidate = value.at("version").get<std::string>();
        VersionParts parts;
        if (!Version(candidate, parts)) return false;
        tag = candidate;
        return true;
    } catch (const nlohmann::json::exception&) { return false; }
}
}
