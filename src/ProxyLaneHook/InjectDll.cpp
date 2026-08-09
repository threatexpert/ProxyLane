#include "stdafx.h"
#include "InjectDll.h"
#include "../remotecode/remoteCode.h"


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
			if (!strcmp(fname, name))
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

	unsigned char lvJmper[78] = {
		0x9C,                                           // 00: pushfq (保存 CPU 状态标志 RFLAGS)
		0x55,                                           // 01: push rbp
		0x48, 0x89, 0xE5,                               // 02: mov rbp, rsp (建立标准栈帧，保存原始 RSP)
		0x48, 0x83, 0xE4, 0xF0,                         // 05: and rsp, 0xFFFFFFFFFFFFFFF0 (强制栈 16 字节对齐，防止崩溃)

		0x51, 0x52, 0x41, 0x50, 0x41, 0x51,             // 09-14: push rcx, rdx, r8, r9
		0x41, 0x52, 0x41, 0x53,                         // 15-18: push r10, r11 (额外保护 r10 和 r11 免受 remoteCode 破坏)
		0x48, 0x83, 0xEC, 0x20,                         // 19-22: sub rsp, 0x20 (分配 32 字节 Shadow Space)

		0x48, 0xB9, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x1F, // 23-32: mov rcx, lpParam (Offset 25)
		0x48, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x1F, // 33-42: mov rax, lpSC    (Offset 35)
		0xFF, 0xD0,                                                 // 43-44: call rax

		0x48, 0x83, 0xC4, 0x20,                         // 45-48: add rsp, 0x20 (清理 Shadow Space)
		0x41, 0x5B, 0x41, 0x5A,                         // 49-52: pop r11, r10
		0x41, 0x59, 0x41, 0x58, 0x5A, 0x59,             // 53-58: pop r9, r8, rdx, rcx

		0x48, 0x89, 0xEC,                               // 59-61: mov rsp, rbp (恢复原始栈顶，清除所有对齐操作带来的偏移)
		0x5D,                                           // 62:    pop rbp
		0x9D,                                           // 63:    popfq (恢复 CPU 状态标志 RFLAGS)

		// ---- 绕过 CET 的绝对跳转核心 ----
		0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,             // 64-69: jmp qword ptr [rip + 0]
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x1F  // 70-77: [Original_RIP] 占位符 (Offset 70)
	};


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

	*(DWORD_PTR*)&lvJmper[25] = (DWORD_PTR)lpParam;
	*(DWORD_PTR*)&lvJmper[35] = (DWORD_PTR)lpSC;
	*(DWORD_PTR*)&lvJmper[70] = (DWORD_PTR)ctx.Rip;

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
		BYTE  pushfd_op;      // 0x9C (pushfd - 保护状态标志)
		BYTE  push_ecx;       // 0x51 (push ecx - 保护易失寄存器)
		BYTE  push_edx;       // 0x52 (push edx - 保护易失寄存器)

		BYTE  push_param_op;  // 0x68 (push lpParam - 压入参数)
		DWORD lpParam;        // 参数地址

		BYTE  mov_eax_op;     // 0xB8 (mov eax, lpSC)
		DWORD lpSC;           // 目标函数地址
		BYTE  call_eax[2];    // 0xFF 0xD0 (call eax - 真正的Call，完美满足影子栈)

		BYTE  pop_edx;        // 0x5A (pop edx - 恢复易失寄存器)
		BYTE  pop_ecx;        // 0x59 (pop ecx - 恢复易失寄存器)
		BYTE  popfd_op;       // 0x9D (popfd - 恢复状态标志)

		BYTE  jmp_rel_op;     // 0xE9 (jmp rel32 - 相对跳转，无需 ret，不触发影子栈检查)
		DWORD jmp_offset;     // 距离原 EIP 的偏移量
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


	// 初始化结构体指令
	lvJmper.pushfd_op = 0x9C;
	lvJmper.push_ecx = 0x51;
	lvJmper.push_edx = 0x52;

	lvJmper.push_param_op = 0x68;
	lvJmper.lpParam = (DWORD)lpParam;

	lvJmper.mov_eax_op = 0xB8;
	lvJmper.lpSC = (DWORD)lpSC;

	lvJmper.call_eax[0] = 0xFF;
	lvJmper.call_eax[1] = 0xD0;

	lvJmper.pop_edx = 0x5A;
	lvJmper.pop_ecx = 0x59;
	lvJmper.popfd_op = 0x9D;

	lvJmper.jmp_rel_op = 0xE9;

	// 计算相对跳转偏移量
	// 公式：目标绝对地址 - JMP指令的下一条指令绝对地址
	// JMP 指令的下一条指令地址，正好就是这块内存 (lpJmper) 的末尾处
	lvJmper.jmp_offset = (DWORD)ctx.Eip - ((DWORD)lpJmper + sizeof(_JMPER));

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

