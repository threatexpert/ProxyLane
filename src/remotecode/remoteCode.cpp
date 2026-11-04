#include <windows.h>
#include "remoteCode.h"



DWORD_PTR WINAPI remoteCode(LPVOID lParam)
{
	myapi *api = (myapi*)lParam;
// 	while (lParam)
// 	{
// 		api->Sleep(10);
// 	}

	HMODULE hMod = api->LoadLibraryW(api->szMyDll);
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
        // No pipe connection, reply wait, or dependency on the Hook DLL.
        DWORD error = api->GetLastError();
        if (api->FormatMessageA && api->OutputDebugStringA) {
            char message[128];
            DWORD_PTR arguments[1];
            arguments[0] = error;
            if (api->FormatMessageA(FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ARGUMENT_ARRAY,
                api->loadFailureFormat, 0, 0, message, sizeof(message),
                reinterpret_cast<va_list*>(arguments)))
                api->OutputDebugStringA(message);
        }
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



