#include "../src/ProxyLane/stdafx.h"
#include "../src/ProxyLane/SshKeyStore.h"
#include <iostream>

int wmain(int argc, wchar_t** argv)
{
    AfxWinInit(GetModuleHandle(NULL), NULL, GetCommandLine(), 0);
    if (argc != 4) return 1;
    SshKeyFile::Snapshot source;
    if (!source.Open(argv[2])) return 2;
    const DWORD start = GetTickCount();
    while (GetFileAttributesW(argv[3]) == INVALID_FILE_ATTRIBUTES) {
        if (GetTickCount()-start > 15000) return 3;
        Sleep(5);
    }
    if (SshKeyStore::ValidReference(L"..\\private.pem") || !SshKeyStore::Path(L"..\\private.pem").IsEmpty()) return 4;
    CString reference;
    const bool imported = SshKeyStore::Import(source.bytes, reference);
    if (wcscmp(argv[1], L"--reject") == 0) return imported ? 5 : 0;
    if (!imported) return 6;
    std::string read;
    if (!SshKeyStore::Read(reference, read) || read != source.bytes) return 7;
    if (reference != SshProfile::Decode(source.digest.c_str()) + L".pem") return 8;
    SecureZeroMemory(&read[0], read.size());
    return 0;
}
