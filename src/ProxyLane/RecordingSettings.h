#pragma once
#include "Localization.h"
#include "../../third_party/nlohmann/json.hpp"
#include <atomic>

namespace RecordingSettings {
struct Values {bool enabled=false;CString directory;unsigned capacityMiB=8192,reserveMiB=512;};
// Explicit opt-in belongs to this GUI process only, never to the shared INI.
// Ignore legacy Enabled values as well, including after an abnormal exit.
inline std::atomic<bool>& SessionEnabled() {static std::atomic<bool> enabled{false};return enabled;}
inline CString DefaultDirectory() {
    wchar_t path[32768]={};GetEnvironmentVariableW(L"LOCALAPPDATA",path,_countof(path));
    return CString(path)+L"\\ProxyLane\\Recordings";
}
inline CString ReadPath(LPCWSTR key,LPCWSTR fallback=L"") {
    wchar_t path[32768]={};GetPrivateProfileStringW(L"recording",key,fallback,path,_countof(path),Localization::SettingsPath());return path;
}
inline Values Load() {
    Values v;v.enabled=SessionEnabled().load();
    v.directory=ReadPath(L"Directory",DefaultDirectory());
    v.capacityMiB=GetPrivateProfileIntW(L"recording",L"CapacityMiB",8192,Localization::SettingsPath());
    v.reserveMiB=GetPrivateProfileIntW(L"recording",L"ReserveMiB",512,Localization::SettingsPath());
    if(v.capacityMiB<16 || v.capacityMiB>1048576)v.capacityMiB=8192;
    if(v.reserveMiB<16 || v.reserveMiB>1048576)v.reserveMiB=512;
    return v;
}
inline CString BrowseDirectory() {
    auto normalized=[](CString path) {
        if(path.Left(8)==L"\\\\?\\UNC\\")path=L"\\\\"+path.Mid(8);
        else if(path.Left(4)==L"\\\\?\\")path=path.Mid(4);
        path.Replace(L'/',L'\\');
        wchar_t full[32768]={};DWORD n=GetFullPathNameW(path,_countof(full),full,nullptr);
        if(n && n<_countof(full))path=full;
        while(path.GetLength()>3 && path.Right(1)==L"\\")path=path.Left(path.GetLength()-1);
        return path;
    };
    auto exists=[](const CString& path) {DWORD a=GetFileAttributesW(path);return a!=INVALID_FILE_ATTRIBUTES && (a&FILE_ATTRIBUTE_DIRECTORY)!=0;};
    CString root=normalized(Load().directory);
    if(!exists(root))root=normalized(DefaultDirectory());
    CString last=normalized(ReadPath(L"LastDirectory"));
    // A changed save location must not send the picker back to an old root.
    CString prefix=root.Right(1)==L"\\"?root:root+L"\\";
    if(last.GetLength()>prefix.GetLength() && last.Left(prefix.GetLength()).CompareNoCase(prefix)==0 && exists(last))return last;
    return root;
}
inline std::string Utf8(const CString& text) {
    int n=WideCharToMultiByte(CP_UTF8,0,text,text.GetLength(),nullptr,0,nullptr,nullptr);
    std::string out(n,'\0');if(n)WideCharToMultiByte(CP_UTF8,0,text,text.GetLength(),&out[0],n,nullptr,nullptr);return out;
}
inline nlohmann::json Json(const Values& v) {
    return {{"enabled",v.enabled},{"directory",Utf8(v.directory)},{"capacity_mib",v.capacityMiB},{"reserve_mib",v.reserveMiB}};
}
inline bool Save(const Values& v) {
    CString text;text.Format(L"Directory=%s\nCapacityMiB=%u\nReserveMiB=%u\nLastDirectory=%s\n",
        (LPCWSTR)v.directory,v.capacityMiB,v.reserveMiB,(LPCWSTR)ReadPath(L"LastDirectory"));
    std::wstring section(text);for(auto& c:section)if(c==L'\n')c=0;section.push_back(0);
    if(!WritePrivateProfileSectionW(L"recording",section.c_str(),Localization::SettingsPath()))return false;
    SessionEnabled().store(v.enabled);
    return true;
}
}
