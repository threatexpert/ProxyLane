#pragma once
#include <windows.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include "../ProxyLane/SshPrivateKey.h"
#pragma comment(lib, "advapi32.lib")

namespace SshKeyFile {
inline std::string Digest(const std::string& bytes) {
    HCRYPTPROV provider = 0; HCRYPTHASH hash = 0;
    unsigned char result[32]; DWORD size = sizeof(result);
    bool ok = CryptAcquireContextW(&provider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) != FALSE;
    if (ok) ok = CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash) != FALSE;
    if (ok) ok = CryptHashData(hash, reinterpret_cast<const BYTE*>(bytes.data()), static_cast<DWORD>(bytes.size()), 0) != FALSE;
    if (ok) ok = CryptGetHashParam(hash, HP_HASHVAL, result, &size, 0) != FALSE && size == 32;
    if (hash) CryptDestroyHash(hash);
    if (provider) CryptReleaseContext(provider, 0);
    std::string value;
    if (ok) for (unsigned char c : result) { value += "0123456789abcdef"[c >> 4]; value += "0123456789abcdef"[c & 15]; }
    return value;
}
inline std::wstring Wide(const char* utf8) {
    const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1, NULL, 0);
    if (!size) return std::wstring();
    std::vector<wchar_t> value(size);
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1, value.data(), size);
    return value.data();
}
class Snapshot {
    HANDLE file = INVALID_HANDLE_VALUE;
public:
    std::string bytes, digest;
    ~Snapshot() { Close(); }
    Snapshot() = default;
    Snapshot(const Snapshot&) = delete;
    Snapshot& operator=(const Snapshot&) = delete;
    void Close() {
        if (file != INVALID_HANDLE_VALUE) { CloseHandle(file); file = INVALID_HANDLE_VALUE; }
        if (!bytes.empty()) SecureZeroMemory(&bytes[0], bytes.size());
        bytes.clear(); digest.clear();
    }
    bool Open(const std::wstring& path) {
        Close();
        file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (file == INVALID_HANDLE_VALUE) return false;
        LARGE_INTEGER size = {}; DWORD read = 0;
        bool ok = GetFileSizeEx(file, &size) && size.QuadPart > 0 && size.QuadPart < SshPrivateKey::Capacity;
        if (ok) { bytes.resize(static_cast<size_t>(size.QuadPart)); ok = ReadFile(file, &bytes[0], static_cast<DWORD>(bytes.size()), &read, NULL) && read == bytes.size(); }
        if (ok) ok = SshPrivateKey::Supported(bytes);
        if (ok) { digest = Digest(bytes); ok = !digest.empty(); }
        if (ok) {
            const auto name = path.substr(path.find_last_of(L"\\/") + 1);
            if (name.size() == 68 && name.substr(64) == L".pem" && name.substr(0,64).find_first_not_of(L"0123456789abcdef") == std::wstring::npos)
                ok = std::wstring(digest.begin(), digest.end()) == name.substr(0,64);
        }
        if (!ok) Close();
        return ok;
    }
};
}
