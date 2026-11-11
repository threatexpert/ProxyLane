#pragma once
#include <string>
#include <stddef.h>

namespace MonitorLog {
    const size_t PreviewBytes = 2048;
    const size_t HistoryRecords = 128;
    const int TextLimit = 128 * 1024;
    const int TextKeep = 80 * 1024;
    const int BatchCharacters = 24 * 1024;
    const unsigned BatchRecords = 8;
    const unsigned BatchMilliseconds = 8;
    // Fixed-width offset, two groups of eight bytes, then ASCII. Never interpret
    // binary bytes as a NUL-terminated string or locale-dependent characters.
    inline std::wstring Hex(const unsigned char* bytes, size_t length) {
        static const wchar_t digits[] = L"0123456789ABCDEF";
        std::wstring out;
        out.reserve(((length + 15) / 16) * 80);
        for (size_t offset = 0; offset < length; offset += 16) {
            for (int shift = 28; shift >= 0; shift -= 4) out += digits[(offset >> shift) & 15];
            out += L"  ";
            for (size_t col = 0; col < 16; ++col) {
                if (col == 8) out += L' ';
                if (offset + col < length) {
                    unsigned char byte = bytes[offset + col];
                    out += digits[byte >> 4]; out += digits[byte & 15]; out += L' ';
                } else out += L"   ";
            }
            out += L" |";
            for (size_t col = 0; col < 16; ++col) {
                if (offset + col >= length) out += L' ';
                else {
                    unsigned char byte = bytes[offset + col];
                    out += byte >= 0x20 && byte <= 0x7e ? (wchar_t)byte : L'.';
                }
            }
            out += L"|\r\n";
        }
        return out;
    }
}
