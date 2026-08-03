#include <windows.h>
#include "remoteCode.h"



DWORD_PTR WINAPI remoteCode(LPVOID lParam)
{
	myapi *api = (myapi*)lParam;
// 	while (lParam)
// 	{
// 		api->Sleep(10);
// 	}

	HMODULE hMod = api->LoadLibraryA(api->szMyDll);
	if (hMod != NULL)
	{
		if (api->szMyEntry[0])
		{
			_Def_Onload* pfnOnload = (_Def_Onload*)api->GetProcAddress(hMod, api->szMyEntry);
			if (pfnOnload)
			{
				pfnOnload(api->EntryParam);
				api->status = 1;
			}
		}else
			api->status = 1;
	}else
	{
	}

	if (api->hEvent)
	{
		api->SetEvent(api->hEvent);
		api->CloseHandle(api->hEvent);
	}

	if (api->status == 1 && !api->noSleep)
	{
		api->Sleep(-1);
	}

	return api->retval;
}



