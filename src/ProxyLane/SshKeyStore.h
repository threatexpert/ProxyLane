#pragma once
#include "ConfigStorage.h"
#include "SshProfile.h"
#include "../ProxyLaneHook/SshKeyFile.h"

namespace SshKeyStore {
inline CString Directory() {
    const CString user = ConfigStorage::UserPath();
    return user.IsEmpty() ? CString() : ConfigStorage::Directory(user) + L"\\keys";
}
inline bool ValidReference(const CString& reference) {
    return reference.GetLength() == 68 && reference.Right(4) == L".pem" &&
        reference.Left(64).SpanIncluding(L"0123456789abcdef") == reference.Left(64);
}
inline CString Path(const CString& reference) {
    const CString directory = Directory();
    return ValidReference(reference) && !directory.IsEmpty() ? directory + L"\\" + reference : CString();
}
inline CString Reference(const char* utf8Path) {
    const CString path = SshProfile::Decode(utf8Path);
    const CString name = path.Mid(path.ReverseFind(L'\\') + 1);
    return ValidReference(name) && path.CompareNoCase(Path(name)) == 0 ? name : CString();
}
inline bool Read(const CString& reference, std::string& bytes) {
    SshKeyFile::Snapshot key;
    const CString path = Path(reference);
    if (path.IsEmpty() || !key.Open((LPCWSTR)path) || SshProfile::Decode(key.digest.c_str()) != reference.Left(64)) return false;
    bytes = key.bytes; return true;
}
inline bool Import(const std::string& bytes, CString& reference) {
    if (!SshPrivateKey::Supported(bytes)) return false;
    const std::string digest = SshKeyFile::Digest(bytes);
    if (digest.empty()) return false;
    const CString name = SshProfile::Decode(digest.c_str()) + L".pem";
    const CString path = Path(name), directory = Directory();
    if (path.IsEmpty() || !ConfigStorage::EnsureDirectory(directory)) return false;
    ConfigStorage::Lock lock(path);
    if (!lock.Valid()) return false;
    if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES) {
        std::string existing;
        const bool same = Read(name, existing) && existing == bytes;
        if (!existing.empty()) SecureZeroMemory(&existing[0], existing.size());
        if (!same) return false; // Never overwrite an existing key, even if damaged.
        reference = name; return true;
    }
    GUID id; wchar_t guid[40];
    if (FAILED(CoCreateGuid(&id)) || !StringFromGUID2(id, guid, _countof(guid))) return false;
    const CString staged = path + L"." + guid + L".tmp";
    HANDLE file = CreateFileW(staged, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    bool ok = WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, NULL) && written == bytes.size() && FlushFileBuffers(file);
    CloseHandle(file);
    if (ok) ok = MoveFileExW(staged, path, MOVEFILE_WRITE_THROUGH) != FALSE;
    if (!ok) { DeleteFileW(staged); return false; }
    reference = name; return true;
}
}
