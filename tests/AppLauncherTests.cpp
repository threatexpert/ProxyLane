#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include "../src/ProxyLaneHook/AppLauncherProtocol.h"
static void Check(bool condition,const char* label) { if(!condition) { printf("FAIL %s\n",label); ExitProcess(1); } }
int wmain()
{
    using namespace AppLauncherProtocol;
    WCHAR path[MAX_PATH];GetWindowsDirectoryW(path,MAX_PATH);wcscat_s(path,L"\\explorer.exe");
    std::wstring command=L"\"";command+=path;command+=L"\" \"shell:AppsFolder\\ProxyLane.Test_123!App\"";
    std::wstring aumid;
    Check(ParseExplorerLaunch(path,command.c_str(),aumid) && aumid==L"ProxyLane.Test_123!App","exact Explorer request");
    Check(ParseExplorerLaunch(NULL,command.c_str(),aumid),"command-only request");
    Check(ParseExplorerLaunch(NULL,L"explorer.exe shell:AppsFolder\\Claude_pzs8sxrjxfjjc!Claude",aumid),"bare Explorer request, including WOW64 resolution");
    WCHAR wowExplorer[MAX_PATH]; GetWindowsDirectoryW(wowExplorer,MAX_PATH); wcscat_s(wowExplorer,L"\\SysWOW64\\explorer.exe");
    if(GetFileAttributesW(wowExplorer)!=INVALID_FILE_ATTRIBUTES)
        Check(ParseExplorerLaunch(wowExplorer,command.c_str(),aumid),"system WOW64 Explorer");
    Check(!ParseExplorerLaunch(L"C:\\not-system\\explorer.exe",command.c_str(),aumid),"reject other Explorer image");
    Check(!ParseExplorerLaunch(path,(command+L" /select").c_str(),aumid),"reject extra options");
    Check(!ParseExplorerLaunch(path,L"explorer.exe C:\\",aumid),"ordinary Explorer untouched");
    Check(!ValidAumid(L"family!App!Other") && !ValidAumid(L"family!App/Other") && !ValidAumid(L"family!") && !ValidAumid(L"!App"),"invalid AUMIDs");
    Check(ValidId(L"{12345678-1234-1234-1234-123456789abc}") && !ValidId(L"arbitrary"),"request ID");
    Check(sizeof(AppLauncherHostInfo)==536 && sizeof(AppLauncherRequest)==624 && sizeof(AppLauncherResult)==12,"wire layout");
    Check(ProcessTime(GetCurrentProcess())!=0,"process identity");
    puts("PASS AppsFolder parser and wire records");return 0;
}
