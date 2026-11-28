#pragma once
#include <cstddef>
#include <initializer_list>
#include <string>

namespace ExtensionUri
{
    enum { MaxLength = 8192 };

    // The core parses protocol options. Accept one single-line proxy URL only;
    // reject http(s)/file URLs, whitespace, control characters and multi-line YAML.
    template<class Char>
    bool Valid(const Char* uri, size_t length)
    {
        if (!uri || !length || length > MaxLength * (sizeof(Char) == 1 ? 4 : 1)) return false;
        size_t split = 0;
        for (size_t i = 0; i < length; ++i) {
            const unsigned ch = static_cast<unsigned>(uri[i]);
            if (ch <= 0x20 || ch == 0x7f) return false;
            if (!split && i + 2 < length && uri[i] == ':' && uri[i + 1] == '/' && uri[i + 2] == '/')
                split = i;
        }
        if (!split || split + 3 >= length) return false;
        auto asciiLower = [](Char c) -> char {
            return c >= 'A' && c <= 'Z' ? static_cast<char>(c + ('a' - 'A')) : static_cast<char>(c);
        };
        const char first = asciiLower(uri[0]);
        if (first < 'a' || first > 'z') return false;
        std::string scheme;
        scheme.reserve(split);
        for (size_t i = 0; i < split; ++i) {
            if (static_cast<unsigned>(uri[i]) > 0x7f) return false;
            const char c = asciiLower(uri[i]);
            const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.';
            if (!ok) return false;
            scheme.push_back(c);
        }
        return scheme != "http" && scheme != "https" && scheme != "file";
    }

    // Credential-free display summary for chain cards and menus.
    inline std::wstring Summary(const wchar_t* uri, size_t length)
    {
        if (!Valid(uri, length)) return std::wstring();
        const std::wstring text(uri, length);
        const size_t split = text.find(L"://");
        if (split == std::wstring::npos) return std::wstring();
        std::wstring scheme = text.substr(0, split + 3);
        for (wchar_t& c : scheme)
            if (c >= L'A' && c <= L'Z') c += L'a' - L'A';
        const size_t start = split + 3;
        const size_t end = text.find_first_of(L"?#/", start);
        const size_t limit = end == std::wstring::npos ? text.size() : end;
        const size_t at = text.find(L'@', start);
        if (at != std::wstring::npos && at < limit && at + 1 < limit)
            return scheme + text.substr(at + 1, limit - at - 1);
        return scheme + L"...";
    }
}
