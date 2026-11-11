// Standalone sender probe, built only under build/process-recording.
#include "../../src/ProxyLaneHook/ProcessCreationSnapshot.h"
#include "../../third_party/nlohmann/json.hpp"
#include <iostream>
#include <thread>
#include <vector>
#include <cassert>
static_assert(sizeof(HookNewProcessInfo)==1056,"child ABI");
static_assert(sizeof(HookProcessCreationNotice)==1588,"32/64-bit notification ABI");
int main()
{
    std::string go;std::getline(std::cin,go);if(go!="start")return 2;
    std::vector<HookProcessSnapshot> snapshots(16);
    std::vector<std::thread> threads;
    for(size_t i=0;i<snapshots.size();++i)threads.emplace_back([&,i] {snapshots[i]=CurrentCreationSender();});
    for(auto& t:threads)t.join();
    const auto parent=CurrentCreationSender();
    for(const auto& s:snapshots)if(s.dwProcessId!=GetCurrentProcessId() ||
        s.processCreateTime!=parent.processCreateTime || wcscmp(s.szAppPath,parent.szAppPath))return 3;
    nlohmann::json result={{"pid",parent.dwProcessId},{"process_start",parent.processCreateTime},{"children",nlohmann::json::array()}};
    for(int i=0;i<8;++i) {
        WCHAR path[MAX_PATH]={};GetSystemDirectoryW(path,MAX_PATH);wcscat_s(path,L"\\cmd.exe");
        WCHAR command[]=L"cmd.exe /D /C exit 0";STARTUPINFOW si={sizeof(si)};PROCESS_INFORMATION pi={};
        if(!CreateProcessW(path,command,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi))return 4;
        FILETIME c={},e={},k={},u={};if(!GetProcessTimes(pi.hProcess,&c,&e,&k,&u))return 5;
        result["children"].push_back({{"pid",pi.dwProcessId},{"process_start",(ULONGLONG(c.dwHighDateTime)<<32)|c.dwLowDateTime}});
        if(WaitForSingleObject(pi.hProcess,30000)!=WAIT_OBJECT_0)return 6;
        CloseHandle(pi.hThread);CloseHandle(pi.hProcess);
    }
    std::cout<<result.dump()<<std::endl;
}
