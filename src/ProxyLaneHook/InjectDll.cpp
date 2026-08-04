#include "stdafx.h"
#include "InjectDll.h"
#include "../remotecode/remoteCode.h"



int compareApiName(const char *p1, const char *p2)
{
	while (*p1 && *p2)
	{
		if (*p1 != *p2)
			return 0;

		p1++;
		p2++;
	}
	return *p1 == *p2;
}

FARPROC get_proc_address2(void* hDll, LPCSTR fname)
{
	PIMAGE_DOS_HEADER        pDosHeader = NULL;
	PIMAGE_FILE_HEADER        pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER    pOptionalHeader = NULL;

	pDosHeader = (PIMAGE_DOS_HEADER)hDll;
	pFileHeader = (PIMAGE_FILE_HEADER)(((PBYTE)hDll) + pDosHeader->e_lfanew + 4);
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)(pFileHeader + 1);

	DWORD dwExpRVA = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (dwExpRVA)
	{
		PBYTE pb = (PBYTE)hDll;
		PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(pb + dwExpRVA);
		PDWORD pNamesRVA = (PDWORD)(pb + pExportDir->AddressOfNames);
		PDWORD pFuncRVA = (PDWORD)(pb + pExportDir->AddressOfFunctions);
		PWORD ord = (PWORD)(pb + pExportDir->AddressOfNameOrdinals);

		DWORD dwFunc = pExportDir->NumberOfNames;
		for (DWORD i = 0; i < dwFunc; i++)
		{
			PCHAR name = ((PCHAR)(pb + pNamesRVA[i]));
			if (compareApiName(fname, name))
				return (FARPROC)(pb + pFuncRVA[ord[i]]);
		}
	}

	return NULL;
}


#ifdef _WIN64

unsigned char sc_ldr[112] = {
	0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xD9, 0x48, 0x83, 0xC1, 0x34, 0xFF, 0x13, 0x48,
	0x85, 0xC0, 0x74, 0x27, 0x48, 0x8D, 0x93, 0x38, 0x01, 0x00, 0x00, 0x80, 0x3A, 0x00, 0x74, 0x14,
	0x48, 0x8B, 0xC8, 0xFF, 0x53, 0x08, 0x48, 0x85, 0xC0, 0x74, 0x10, 0x48, 0x8B, 0x8B, 0x78, 0x01,
	0x00, 0x00, 0xFF, 0xD0, 0xC7, 0x43, 0x30, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x4B, 0x28, 0x48,
	0x85, 0xC9, 0x74, 0x0A, 0xFF, 0x53, 0x18, 0x48, 0x8B, 0x4B, 0x28, 0xFF, 0x53, 0x20, 0x83, 0x7B,
	0x30, 0x01, 0x75, 0x0F, 0x80, 0xBB, 0x80, 0x01, 0x00, 0x00, 0x00, 0x75, 0x06, 0x83, 0xC9, 0xFF,
	0xFF, 0x53, 0x10, 0x48, 0x8B, 0x83, 0x88, 0x01, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3
};


int InjectDll(HANDLE hProc, HANDLE hThread, LPCSTR lpMyDll, LPCSTR lpszPipeName)
{
	int bOK(-1);
	myapi param_myapi;
	ZeroMemory(&param_myapi, sizeof(param_myapi));

	HMODULE hKernel = GetModuleHandleA("kernel32.dll");
	*(FARPROC*)&param_myapi.LoadLibraryA = get_proc_address2(hKernel, "LoadLibraryA");
	*(FARPROC*)&param_myapi.GetProcAddress = get_proc_address2(hKernel, "GetProcAddress");
	*(FARPROC*)&param_myapi.Sleep = get_proc_address2(hKernel, "Sleep");
	*(FARPROC*)&param_myapi.SetEvent = get_proc_address2(hKernel, "SetEvent");
	*(FARPROC*)&param_myapi.CloseHandle = get_proc_address2(hKernel, "CloseHandle");
	//WideCharToMultiByte(0, 0, lpMyDll, -1, param_myapi.szMyDll, MAX_PATH, 0, 0);
	strcpy(param_myapi.szMyDll, lpMyDll);
	strcpy(param_myapi.szMyEntry, "gp_HookWinsock");
	param_myapi.noSleep = true;

	LPVOID lpParam = NULL;
	LPVOID lpSC = NULL;
	LPVOID lpJmper = NULL;
	LPVOID lpROnldParam = NULL;
	CONTEXT ctx;

#pragma pack(push, 1)


	unsigned char lvJmper[46] = {
		0x48, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x1F, 0x50, 0x51, 0x52, 0x41, 0x50, 0x41,
		0x51, 0x48, 0xB9, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x1F, 0x48, 0xB8, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0x1F, 0xFF, 0xD0, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0xC3
	};
#pragma pack(pop)


	ctx.ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(hThread, &ctx))
	{
		goto __CleanUp;
	}

	//改变EIP到remoteCode函数执行完后返回这个值，用意就是恢复之前的EAX
	param_myapi.retval = ctx.Rax;

	lpParam = VirtualAllocEx(hProc, 0, sizeof(myapi), MEM_COMMIT, PAGE_READWRITE);
	lpSC = VirtualAllocEx(hProc, 0, sizeof(sc_ldr), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	lpJmper = VirtualAllocEx(hProc, 0, sizeof(lvJmper), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	lpROnldParam = VirtualAllocEx(hProc, 0, MAX_PATH, MEM_COMMIT, PAGE_READWRITE);
	if (!lpParam || !lpSC || !lpJmper || !lpROnldParam)
	{
		goto __CleanUp;
	}

	if (WriteProcessMemory(hProc, lpROnldParam, lpszPipeName, strlen(lpszPipeName) + 1, NULL))
	{
		param_myapi.EntryParam = lpROnldParam;
	}

	if (!WriteProcessMemory(hProc, lpParam, &param_myapi, sizeof(myapi), NULL))
	{
		goto __CleanUp;
	}

	if (!WriteProcessMemory(hProc, lpSC, sc_ldr, sizeof(sc_ldr), NULL))
	{
		goto __CleanUp;
	}

	//准备更改主线程的eip，先执行我的一个函数
	//先配置一段跳转并调用remoteCode的代码

	*(DWORD_PTR*)&lvJmper[2] = (DWORD_PTR)ctx.Rip;
	*(DWORD_PTR*)&lvJmper[0x13] = (DWORD_PTR)lpParam;
	*(DWORD_PTR*)&lvJmper[0x1d] = (DWORD_PTR)lpSC;


	if (!WriteProcessMemory(hProc, lpJmper, &lvJmper, sizeof(lvJmper), NULL))
	{
		goto __CleanUp;
	}

	ctx.Rip = (DWORD_PTR)lpJmper;

	if (!SetThreadContext(hThread, &ctx))
	{
		goto __CleanUp;
	}

	bOK = 1;

__CleanUp:
	if (!bOK)
	{
		if (lpSC)
			VirtualFreeEx(hProc, lpSC, 0, MEM_RELEASE);
		if (lpParam)
			VirtualFreeEx(hProc, lpParam, 0, MEM_RELEASE);
		if (lpROnldParam)
			VirtualFreeEx(hProc, lpROnldParam, 0, MEM_RELEASE);
		if (lpJmper)
			VirtualFreeEx(hProc, lpJmper, 0, MEM_RELEASE);
	}

	return bOK;
}


#else

static unsigned char sc_ldr[116] = {
	0x55, 0x8B, 0xEC, 0x56, 0x8B, 0x75, 0x08, 0x8D, 0x46, 0x1C, 0x50, 0x8B, 0x06, 0xFF, 0xD0, 0x8B,
	0xC8, 0x85, 0xC9, 0x74, 0x29, 0x80, 0xBE, 0x20, 0x01, 0x00, 0x00, 0x00, 0x8D, 0x86, 0x20, 0x01,
	0x00, 0x00, 0x74, 0x13, 0x50, 0x8B, 0x46, 0x04, 0x51, 0xFF, 0xD0, 0x85, 0xC0, 0x74, 0x0F, 0xFF,
	0xB6, 0x60, 0x01, 0x00, 0x00, 0xFF, 0xD0, 0xC7, 0x46, 0x18, 0x01, 0x00, 0x00, 0x00, 0x8B, 0x46,
	0x14, 0x85, 0xC0, 0x74, 0x0E, 0x50, 0x8B, 0x46, 0x0C, 0xFF, 0xD0, 0xFF, 0x76, 0x14, 0x8B, 0x46,
	0x10, 0xFF, 0xD0, 0x83, 0x7E, 0x18, 0x01, 0x75, 0x10, 0x80, 0xBE, 0x64, 0x01, 0x00, 0x00, 0x00,
	0x75, 0x07, 0x8B, 0x4E, 0x08, 0x6A, 0xFF, 0xFF, 0xD1, 0x8B, 0x86, 0x68, 0x01, 0x00, 0x00, 0x5E,
	0x5D, 0xC2, 0x04, 0x00
};


int InjectDll(HANDLE hProc, HANDLE hThread, LPCSTR lpMyDll, LPCSTR lpszPipeName)
{
	int bOK(-1);
	myapi param_myapi;
	ZeroMemory(&param_myapi, sizeof(param_myapi));

	HMODULE hKernel = GetModuleHandleA("kernel32.dll");
	*(FARPROC*)&param_myapi.LoadLibraryA = get_proc_address2(hKernel, "LoadLibraryA");
	*(FARPROC*)&param_myapi.GetProcAddress = get_proc_address2(hKernel, "GetProcAddress");
	*(FARPROC*)&param_myapi.Sleep = get_proc_address2(hKernel, "Sleep");
	*(FARPROC*)&param_myapi.SetEvent = get_proc_address2(hKernel, "SetEvent");
	*(FARPROC*)&param_myapi.CloseHandle = get_proc_address2(hKernel, "CloseHandle");
	//WideCharToMultiByte(0, 0, lpMyDll, -1, param_myapi.szMyDll, MAX_PATH, 0, 0);
	strcpy(param_myapi.szMyDll, lpMyDll);
	strcpy(param_myapi.szMyEntry, "gp_HookWinsock");
	param_myapi.noSleep = true;

	LPVOID lpParam = NULL;
	LPVOID lpSC = NULL;
	LPVOID lpJmper = NULL;
	LPVOID lpROnldParam = NULL;
	CONTEXT ctx;

#pragma pack(push, 1)

	struct _JMPER
	{
		BYTE pushAddr1; DWORD addr1;
		BYTE pushAddr2; DWORD addr2;
		BYTE pushAddr3; DWORD addr3;
		BYTE retn;
	}lvJmper;
#pragma pack(pop)


	ctx.ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(hThread, &ctx))
	{
		goto __CleanUp;
	}

	//改变EIP到remoteCode函数执行完后返回这个值，用意就是恢复之前的EAX
	param_myapi.retval = ctx.Eax;

	lpParam = VirtualAllocEx(hProc, 0, sizeof(myapi), MEM_COMMIT, PAGE_READWRITE);
	lpSC = VirtualAllocEx(hProc, 0, sizeof(sc_ldr), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	lpJmper = VirtualAllocEx(hProc, 0, sizeof(_JMPER), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	lpROnldParam = VirtualAllocEx(hProc, 0, MAX_PATH, MEM_COMMIT, PAGE_READWRITE);
	if (!lpParam || !lpSC || !lpJmper || !lpROnldParam)
	{
		goto __CleanUp;
	}

	if (WriteProcessMemory(hProc, lpROnldParam, lpszPipeName, strlen(lpszPipeName) + 1, NULL))
	{
		param_myapi.EntryParam = lpROnldParam;
	}

	if (!WriteProcessMemory(hProc, lpParam, &param_myapi, sizeof(myapi), NULL))
	{
		goto __CleanUp;
	}

	if (!WriteProcessMemory(hProc, lpSC, sc_ldr, sizeof(sc_ldr), NULL))
	{
		goto __CleanUp;
	}

	//准备更改主线程的eip，先执行我的一个函数
	//先配置一段跳转并调用remoteCode的代码
	lvJmper.pushAddr1 = 0x68;
	lvJmper.addr1 = (DWORD)lpParam;
	lvJmper.pushAddr2 = 0x68;
	lvJmper.addr2 = (DWORD)ctx.Eip;//!!这里是返回地址
	lvJmper.pushAddr3 = 0x68;
	lvJmper.addr3 = (DWORD)lpSC;
	lvJmper.retn = 0xc3;//不用call，而是用push ret，所以上面的addr2是返回地址,返回到原来的eip

	if (!WriteProcessMemory(hProc, lpJmper, &lvJmper, sizeof(lvJmper), NULL))
	{
		goto __CleanUp;
	}

	ctx.Eip = (DWORD)lpJmper;

	if (!SetThreadContext(hThread, &ctx))
	{
		goto __CleanUp;
	}

	bOK = 1;

__CleanUp:
	if (!bOK)
	{
		if (lpSC)
			VirtualFreeEx(hProc, lpSC, 0, MEM_RELEASE);
		if (lpParam)
			VirtualFreeEx(hProc, lpParam, 0, MEM_RELEASE);
		if (lpROnldParam)
			VirtualFreeEx(hProc, lpROnldParam, 0, MEM_RELEASE);
		if (lpJmper)
			VirtualFreeEx(hProc, lpJmper, 0, MEM_RELEASE);
	}

	return bOK;
}

#endif

