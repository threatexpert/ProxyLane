#include "stdafx.h"
#include "AppLauncher.h"
#include "..\ProxyLaneHook\structinfo.h"

namespace
{
    bool Number(LPCWSTR text, ULONGLONG& number)
    {
        if(!text || !*text) return false;
        number=0;
        for(;*text;++text) {
            if(*text<L'0' || *text>L'9' || number>(~0ULL-(*text-L'0'))/10) return false;
            number=number*10+(*text-L'0');
        }
        return number!=0;
    }
    bool Transfer(HANDLE pipe, bool write, void* bytes, DWORD length, DWORD timeout)
    {
        OVERLAPPED operation={}; operation.hEvent=CreateEvent(NULL,TRUE,FALSE,NULL);
        if(!operation.hEvent) return false;
        DWORD count=0;
        BOOL ok=write?WriteFile(pipe,bytes,length,&count,&operation):ReadFile(pipe,bytes,length,&count,&operation);
        DWORD error=ok?ERROR_SUCCESS:GetLastError();
        if(!ok && error==ERROR_IO_PENDING) {
            DWORD wait=WaitForSingleObject(operation.hEvent,timeout);
            if(wait==WAIT_OBJECT_0) { ok=GetOverlappedResult(pipe,&operation,&count,FALSE); error=ok?0:GetLastError(); }
            else {
                CancelIo(pipe); // Same thread issued this operation; XP-compatible cancellation.
                GetOverlappedResult(pipe,&operation,&count,TRUE);
                error=WAIT_TIMEOUT; ok=FALSE;
            }
        }
        CloseHandle(operation.hEvent); SetLastError(error); return ok && count==length;
    }
    DWORD Execute(LPCWSTR pipeName, AppLauncherRequest& request)
    {
        request.submittedTime=AppLauncherProtocol::Now();
        DWORD start=GetTickCount();
        while(GetTickCount()-start<45000) {
            HANDLE pipe=CreateFileW(pipeName,GENERIC_READ|FILE_WRITE_DATA|FILE_WRITE_ATTRIBUTES,0,NULL,
                OPEN_EXISTING,FILE_FLAG_OVERLAPPED|SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION,NULL);
            if(pipe==INVALID_HANDLE_VALUE) {
                DWORD error=GetLastError();
                if(error!=ERROR_PIPE_BUSY) return error;
                WaitNamedPipeW(pipeName,200); continue;
            }
            auto transfer=[&](bool write,void* data,DWORD size) {
                DWORD elapsed=GetTickCount()-start;
                if(elapsed>=45000) { SetLastError(WAIT_TIMEOUT); return false; }
                return Transfer(pipe,write,data,size,45000-elapsed);
            };
            PRCPipeDataHead header={PRCPD_LAUNCH_PACKAGED_APP,0,sizeof(request)};
            AppLauncherResult result={};
            bool ok=transfer(true,&header,sizeof(header)) &&
                transfer(true,&request,sizeof(request)) &&
                transfer(false,&header,sizeof(header)) &&
                header.action==PRCPD_REPLY && header.flag==1 && header.dataSize==sizeof(result) &&
                transfer(false,&result,sizeof(result));
            DWORD error=ok?result.error:GetLastError(); CloseHandle(pipe);
            if(ok && error!=ERROR_IO_PENDING) return error;
            if(!ok && error!=ERROR_BROKEN_PIPE && error!=ERROR_NO_DATA && error!=WAIT_TIMEOUT) return error?error:ERROR_INVALID_DATA;
            // Same request ID and timestamp on every retry; never fall back to
            // Explorer after a potentially accepted request (avoids double activation).
            Sleep(100);
        }
        return WAIT_TIMEOUT;
    }
}

bool RunInternalAppLauncher(LPCWSTR commandLine, DWORD& exitCode)
{
    int count=0; LPWSTR* args=CommandLineToArgvW(commandLine,&count);
    if(!args) return false;
    if(count<2 || wcscmp(args[1],L"--internal-launch-app")) { LocalFree(args); return false; }
    exitCode=ERROR_INVALID_PARAMETER;
    const WCHAR prefix[]=L"\\\\.\\pipe\\PRCPipeName";
    if(count==9 && !wcsncmp(args[2],prefix,_countof(prefix)-1) &&
        wcslen(args[2])<MAX_PATH && AppLauncherProtocol::ValidId(args[3]) && AppLauncherProtocol::ValidAumid(args[4])) {
        ULONGLONG hostPid=0,hostTime=0,parentPid=0,parentTime=0;
        if(Number(args[5],hostPid) && hostPid<=MAXDWORD && Number(args[6],hostTime) &&
            Number(args[7],parentPid) && parentPid<=MAXDWORD && Number(args[8],parentTime)) {
            AppLauncherRequest request={}; wcscpy_s(request.id,args[3]); wcscpy_s(request.aumid,args[4]);
            request.hostPid=(DWORD)hostPid; request.hostCreationTime=hostTime;
            request.parentPid=(DWORD)parentPid; request.parentCreationTime=parentTime;
            exitCode=Execute(args[2],request);
        }
    }
    LocalFree(args); return true;
}
