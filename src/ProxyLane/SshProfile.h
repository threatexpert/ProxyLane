#pragma once
#include "SshPrivateKey.h"

// SSH credentials are UTF-8 on the wire. Do not change legacy protocols'
// credential encoding or the packed ProxyInfo pipe prefix.
namespace SshProfile {
template<size_t N> bool Encode(const CString& text, char (&output)[N]) {
    const int bytes = WideCharToMultiByte(CP_UTF8, 0, text, -1, NULL, 0, NULL, NULL);
    if (bytes <= 0 || bytes > N) return false;
    return WideCharToMultiByte(CP_UTF8, 0, text, -1, output, N, NULL, NULL) != 0;
}
inline CString Decode(const char* text) {
    CString result;
    const int chars = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, NULL, 0);
    if (chars > 0) {
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, result.GetBuffer(chars), chars);
        result.ReleaseBuffer();
    }
    return result;
}
inline bool ValidFingerprint(const CString& text) {
    if (text.IsEmpty()) return true; // Test discovers the key without authenticating.
    if (text.GetLength() != 50 || text.Left(7) != L"SHA256:") return false;
    for (int i=7; i<text.GetLength(); ++i) {
        wchar_t c = text[i];
        if (!((c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z') ||
            (c >= L'0' && c <= L'9') || c == L'+' || c == L'/')) return false;
    }
    return true;
}
}
