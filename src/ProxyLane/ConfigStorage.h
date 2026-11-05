#pragma once
#include <afxwin.h>
#include <functional>

namespace ConfigStorage
{
// Shared with recent-history writers; recursive within a thread.
class Lock
{
    HANDLE handle = NULL;
    bool owned = false;
public:
    explicit Lock(const CString& path);
    ~Lock();
    bool Valid() const { return owned; }
};
CString Path();
CString PortablePath();
CString UserPath();
CString Directory(const CString& path);
bool Initialize();
bool EnsureDirectory(const CString& directory);
bool SetPortable(bool enabled); // Changes only portable.flag; takes effect on restart.
// Edits a private staging copy, then atomically replaces the original.
bool Update(const CString& path, const std::function<bool(const CString&)>& edit);
BOOL WriteValue(LPCTSTR section, LPCTSTR key, LPCTSTR value, const CString& path);
CString ErrorText(DWORD error);
}
