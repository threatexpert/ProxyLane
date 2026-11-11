#include <windows.h>
#include <stdio.h>
#include "remoteCode.h"


int main2()
{
	printf("main\r\n");

	myapi api;

	memset(&api, 0, sizeof(api));

	api.LoadLibraryW = LoadLibraryW;
	api.GetLastError = GetLastError;
	api.GetProcAddress = GetProcAddress;

	DWORD_PTR ret = remoteCode(&api);

	return 0;
}