#pragma once
#include "Localization.h"
#include "../../third_party/nlohmann/json.hpp"
#include <array>
#include "RecordingSettings.h"

namespace MitmSettings {
struct Field { const char* key; const wchar_t* ini; const wchar_t* label; unsigned initial, minimum, maximum; };
inline const std::array<Field,9>& Fields() {
    static const std::array<Field,9> fields = {{
        {"entry_mib",L"EntryMiB",L"mitm.entry",32,1,1024},
        {"total_mib",L"TotalMiB",L"mitm.total",512,16,8192},
        {"history_rows",L"HistoryRows",L"mitm.rows",512,128,10000},
        {"preview_kib",L"PreviewKiB",L"mitm.preview",64,16,1024},
        {"decode_mib",L"DecodeMiB",L"mitm.decode",4,1,64},
        {"connections",L"Connections",L"mitm.connections",128,1,256},
        {"pending_requests",L"PendingRequests",L"mitm.pending",8,1,256},
        {"udp_packets",L"UdpPackets",L"mitm.packets",256,16,4096},
        {"handshake_seconds",L"HandshakeSeconds",L"mitm.timeout",15,5,120},
    }};
    return fields;
}
inline bool DecryptHTTPS() { return GetPrivateProfileInt(L"options",L"DecryptHTTPS",0,Localization::SettingsPath())==1; }
inline bool DecryptQUIC() { return GetPrivateProfileInt(L"options",L"DecryptQUIC",0,Localization::SettingsPath())==1; }
inline bool SaveDecryptQUIC(bool enabled) { return WritePrivateProfileString(L"options",L"DecryptQUIC",enabled ? L"1":L"0",Localization::SettingsPath())!=FALSE; }
inline bool SaveDecryptHTTPS(bool enabled) { return WritePrivateProfileString(L"options",L"DecryptHTTPS",enabled ? L"1":L"0",Localization::SettingsPath())!=FALSE; }
using Values=std::array<unsigned,9>;
inline Values Defaults() {
    Values values;for(size_t i=0;i<values.size();++i) values[i]=Fields()[i].initial;return values;
}
inline Values Load(const CString& path=Localization::SettingsPath()) {
    Values values; const auto& fields=Fields();
    for(size_t i=0;i<fields.size();++i) {
        const auto& f=fields[i];
        unsigned n=GetPrivateProfileInt(L"mitm",f.ini,f.initial,path);
        values[i]=n>=f.minimum && n<=f.maximum ? n : f.initial;
    }
    if(values[0]>values[1]) {values[0]=fields[0].initial;values[1]=fields[1].initial;}
    return values;
}
inline nlohmann::json Json(const Values& values) {
    nlohmann::json result=nlohmann::json::object();
    for(size_t i=0;i<values.size();++i) result[Fields()[i].key]=values[i];
    result["recording"]=RecordingSettings::Json(RecordingSettings::Load());
    return result;
}
inline bool Save(const Values& values,const CString& path=Localization::SettingsPath()) {
    // Replace this dedicated section in one operation, preserving other settings.
    std::wstring section;
    for(size_t i=0;i<values.size();++i) {
        section+=Fields()[i].ini;section+=L"=";section+=std::to_wstring(values[i]);section.push_back(0);
    }
    section.push_back(0);
    return WritePrivateProfileSection(L"mitm",section.c_str(),path)!=FALSE;
}
}
