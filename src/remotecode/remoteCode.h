#pragma once


typedef HMODULE
WINAPI
_Def_LoadLibraryA(
				  LPCSTR lpLibFileName
				  );

typedef
FARPROC WINAPI _Def_GetProcAddress (  HMODULE hModule,  LPCSTR lpProcName );
typedef VOID WINAPI _Def_Sleep(  DWORD dwMilliseconds );
typedef BOOL WINAPI _Def_SetEvent(  HANDLE hEvent );
typedef BOOL WINAPI _Def_CloseHandle(  HANDLE hObject );

typedef DWORD WINAPI _Def_Onload(LPVOID p);

struct myapi
{
	_Def_LoadLibraryA* LoadLibraryA;
	_Def_GetProcAddress* GetProcAddress;
	_Def_Sleep* Sleep;
	_Def_SetEvent* SetEvent;
	_Def_CloseHandle* CloseHandle;

	HANDLE hEvent;
	DWORD status;
	CHAR szMyDll[MAX_PATH];
	CHAR szMyEntry[64];
	void *EntryParam;
	bool noSleep;
	DWORD_PTR retval;
};

DWORD_PTR WINAPI remoteCode(LPVOID lParam);
