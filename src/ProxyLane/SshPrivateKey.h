#pragma once
#include <string>
#include <algorithm>

// Bound and identify supported textual containers before storing/sharing them.
// libssh2/OpenSSL validates the actual key and passphrase during authentication.
namespace SshPrivateKey {
static const size_t Capacity = 16384;
inline bool Supported(const std::string& key) {
    std::string type;
    for (const char* candidate : {"RSA PRIVATE KEY", "EC PRIVATE KEY", "OPENSSH PRIVATE KEY", "PRIVATE KEY", "ENCRYPTED PRIVATE KEY"}) {
        const std::string header = std::string("-----BEGIN ") + candidate + "-----";
        if (key.compare(0, header.size(), header) == 0) { type = candidate; break; }
    }
    if (type.empty()) return false;
    const std::string begin = "-----BEGIN " + type + "-----";
    const std::string end = "-----END " + type + "-----";
    if (key.empty() || key.size() >= Capacity || key.compare(0, begin.size(), begin) != 0 ||
        key.find('\0') != std::string::npos) return false;
    const size_t finish = key.find(end, begin.size());
    if (finish == std::string::npos || key.find_first_not_of("\r\n \t", finish + end.size()) != std::string::npos) return false;
    for (unsigned char c : key)
        if ((c < 32 && c != '\r' && c != '\n' && c != '\t') || c > 126 || c == '|') return false;
    if (key.find("Proc-Type:") != std::string::npos) {
        if (type != "RSA PRIVATE KEY" && type != "EC PRIVATE KEY") return false;
        std::string text = key; text.erase(std::remove(text.begin(), text.end(), '\r'), text.end());
        const std::string prefix = begin + "\nProc-Type: 4,ENCRYPTED\nDEK-Info: ";
        if (text.compare(0, prefix.size(), prefix) != 0) return false;
        const size_t comma = text.find(',', prefix.size()), newline = text.find('\n', prefix.size());
        if (comma == std::string::npos || newline == std::string::npos || comma > newline) return false;
        const auto cipher = text.substr(prefix.size(), comma-prefix.size());
        const size_t block = cipher == "AES-128-CBC" || cipher == "AES-192-CBC" || cipher == "AES-256-CBC" ? 16 : cipher == "DES-EDE3-CBC" ? 8 : 0;
        const auto iv = text.substr(comma+1, newline-comma-1);
        if (!block || iv.size() != block*2 || iv.find_first_not_of("0123456789ABCDEF") != std::string::npos) return false;
        size_t encoded = 0, padding = 0;
        const size_t footer = text.find(end, newline);
        if (footer == std::string::npos) return false;
        for (size_t i = newline+1; i < footer; ++i) {
            const char c = text[i];
            if (c == '\n' || c == ' ' || c == '\t') continue;
            if (c == '=') { if (++padding > 2) return false; }
            else if (padding || std::string("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/").find(c) == std::string::npos) return false;
            ++encoded;
        }
        if (encoded < (type == "RSA PRIVATE KEY" ? 344u : 24u) || encoded % 4 || ((encoded/4*3-padding) % block)) return false;
    } else if (type != "RSA PRIVATE KEY") {
        size_t encoded = 0, padding = 0;
        for (size_t i = begin.size(); i < finish; ++i) {
            const char c = key[i];
            if (c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
            if (c == '=') { if (++padding > 2) return false; }
            else if (padding || std::string("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/").find(c) == std::string::npos) return false;
            ++encoded;
        }
        if (encoded < 64 || encoded % 4) return false;
    }
    return true;
}
}
