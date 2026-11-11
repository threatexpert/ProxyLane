#ifdef NDEBUG
#undef NDEBUG
#endif
#include "MonitorLogFormat.h"
#include <cassert>
#include <iostream>
#include <vector>

int MonitorLogFormatTestsMain()
{
    const unsigned char sample[] = {0x41, 0, 0x20, 0x7e, 0x7f, 0x80, 0x0d, 0xff, 0x42};
    std::wstring text = MonitorLog::Hex(sample, sizeof(sample));
    assert(text.find(L"00000000  41 00 20 7E 7F 80 0D FF  42 ") == 0);
    assert(text.find(L"|A. ~....B       |\r\n") != std::wstring::npos);
    std::vector<unsigned char> bytes(256);
    for (unsigned i = 0; i < bytes.size(); ++i) bytes[i] = (unsigned char)i;
    text = MonitorLog::Hex(bytes.data(), bytes.size());
    assert(text.find(L"00000010  10 11 12 13 14 15 16 17  18 19 1A 1B 1C 1D 1E 1F  |................|") != std::wstring::npos);
    assert(text.find(L"| !\"#$%&'()*+,-./|") != std::wstring::npos);
    assert(MonitorLog::Hex(nullptr, 0).empty());
    const size_t lineWidth = text.find(L"\r\n") + 2;
    for (size_t offset = 0; offset < text.size(); offset += lineWidth)
        assert(text.substr(offset, lineWidth).find(L"\r\n") == lineWidth - 2);
    bytes.resize(MonitorLog::PreviewBytes, 'Z');
    const size_t largest = MonitorLog::Hex(bytes.data(), bytes.size()).size() + 1024;
    assert(MonitorLog::TextKeep + MonitorLog::BatchCharacters + largest < MonitorLog::TextLimit);
    std::cout << "Monitor HEX layout and display budget tests passed\n";
    return 0;
}
