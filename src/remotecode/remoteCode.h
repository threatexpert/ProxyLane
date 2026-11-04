#pragma once


typedef HMODULE
WINAPI
_Def_LoadLibraryW(
				  LPCWSTR lpLibFileName
				  );

typedef
FARPROC WINAPI _Def_GetProcAddress (  HMODULE hModule,  LPCSTR lpProcName );
typedef VOID WINAPI _Def_Sleep(  DWORD dwMilliseconds );
typedef BOOL WINAPI _Def_SetEvent(  HANDLE hEvent );
typedef BOOL WINAPI _Def_CloseHandle(  HANDLE hObject );

typedef DWORD WINAPI _Def_Onload(LPVOID p);

struct myapi
{
	_Def_LoadLibraryW* LoadLibraryW;
	_Def_GetProcAddress* GetProcAddress;
	_Def_Sleep* Sleep;
	_Def_SetEvent* SetEvent;
	_Def_CloseHandle* CloseHandle;

	HANDLE hEvent;
	DWORD status;
	WCHAR szMyDll[MAX_PATH];
	CHAR szMyEntry[64];
	void *EntryParam;
	bool noSleep;
	DWORD_PTR retval;
    DWORD (WINAPI *GetLastError)();
    DWORD (WINAPI *FormatMessageA)(DWORD, LPCVOID, DWORD, DWORD, LPSTR, DWORD, va_list*);
    VOID (WINAPI *OutputDebugStringA)(LPCSTR);
    CHAR loadFailureFormat[96];
};

DWORD_PTR WINAPI remoteCode(LPVOID lParam);
