// Page3.cpp : 实现文件
//

#include "stdafx.h"
#include "ProxyLane.h"
#include "Page3.h"
#include "MainTab.h"
#include "Page2.h"
#include "AutomationOptions.h"
#include "..\ProxyLaneHook\token.h"

#include "..\ProxyLaneHook\ProxyModule.h"

#include <list>

using namespace std;

#include <windows.h>
#include <Dbghelp.h>
#include <psapi.h>
#include <atlfile.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <Dbghelp.h>
#include <shlobj.h>

#pragma comment (lib,"Advapi32.lib")
#pragma comment (lib,"shlwapi.lib")
#pragma comment (lib, "psapi.lib")
#pragma comment(lib, "Dbghelp.lib")

#include <vector>
#include <algorithm>
#include "Page1.h"

// 由 Page1.cpp 定义的子进程注入过滤运行时快照
struct ChildInjectFilterSnapshot
{
	BOOL bEnabled;
	int  nMode;
	std::vector<CString> patterns;
};
extern ChildInjectFilterSnapshot g_ChildInjectFilter;


using namespace ATL;


int compareApiName(char *p1, char *p2)
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

DWORD get_proc_address2(LPVOID pBase, char *pApiName)
{
	PIMAGE_DOS_HEADER        pDosHeader;
	PIMAGE_FILE_HEADER        pFileHeader;
	PIMAGE_OPTIONAL_HEADER    pOptionalHeader;

	pDosHeader=(PIMAGE_DOS_HEADER)pBase;
	pFileHeader=(PIMAGE_FILE_HEADER)(((PBYTE)pBase)+pDosHeader->e_lfanew+4);
	pOptionalHeader=(PIMAGE_OPTIONAL_HEADER)(pFileHeader+1);

	DWORD dwExpRVA = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY pExportDir=(PIMAGE_EXPORT_DIRECTORY)((PBYTE)pBase+dwExpRVA);
	PDWORD pNamesRVA=(PDWORD)((PBYTE)pBase+pExportDir->AddressOfNames);
	PDWORD pFuncRVA=(PDWORD)((PBYTE)pBase+pExportDir->AddressOfFunctions);
	PWORD ord=(PWORD)((PBYTE)pBase+pExportDir->AddressOfNameOrdinals);

	DWORD dwFunc=pExportDir->NumberOfNames;
	for (DWORD i=0; i<dwFunc; i++)
	{
		PCHAR name =((PCHAR)((PBYTE)pBase+pNamesRVA[i]));
		if (compareApiName((CHAR*)name, pApiName))
			return (DWORD)((PBYTE)pBase+pFuncRVA[ord[i]]);
	}

	return 0;
}

BOOL DebugPrivilege(TCHAR *PName,BOOL bEnable)
{
	BOOL              bResult = TRUE;
	HANDLE            hToken;
	TOKEN_PRIVILEGES  TokenPrivileges;

	if(::OpenProcessToken(::GetCurrentProcess(),TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,&hToken) == 0)
	{
		//		printf("OpenProcessToken Error: %d\n",GetLastError());
		bResult = FALSE;
	}
	TokenPrivileges.PrivilegeCount           = 1;
	TokenPrivileges.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;
	::LookupPrivilegeValue(NULL,PName,&TokenPrivileges.Privileges[0].Luid);
	bResult = ::AdjustTokenPrivileges(hToken,FALSE,&TokenPrivileges,sizeof(TOKEN_PRIVILEGES),NULL,NULL);
	if(!bResult)
	{
		bResult = FALSE;
	}
	CloseHandle(hToken);

	return bResult;
}

BOOL GetProcessFullPath(HANDLE hProc, LPTSTR buf, DWORD size)
{
	typedef
	BOOL WINAPI __QueryFullProcessImageName(
		HANDLE hProcess,
		DWORD dwFlags,
		LPTSTR lpExeName,
		PDWORD lpdwSize
		);

	static __QueryFullProcessImageName * QFIN = NULL;
	if (!QFIN)
	{
		QFIN = (__QueryFullProcessImageName*)GetProcAddress(
			GetModuleHandle(TEXT("kernel32")), 
#ifdef _UNICODE
			"QueryFullProcessImageNameW"
#else
			"QueryFullProcessImageNameA"
#endif
			);
	}

	if (QFIN)
	{
		return QFIN(hProc, 0, buf, &size);
	}
	else
	{
		HMODULE hMod;
		TCHAR procName[255] = { 0 };
		unsigned long cbNeeded;

		if (!EnumProcessModules(hProc, &hMod, sizeof(hMod), &cbNeeded))
			return 0;
		
		return GetModuleFileNameEx(hProc, hMod, buf, size) > 0;
	}
}

// 保存进程创建时间，并同时生成列表中的本地时间文本。
static BOOL SetProcessStartTime(ULONGLONG startTimeValue, _myPROCESSINFO& processInfo)
{
	ULARGE_INTEGER timeValue;
	timeValue.QuadPart = startTimeValue;
	FILETIME creationTime;
	creationTime.dwLowDateTime = timeValue.LowPart;
	creationTime.dwHighDateTime = timeValue.HighPart;

	FILETIME localTime;
	SYSTEMTIME systemTime;
	if (!FileTimeToLocalFileTime(&creationTime, &localTime)
		|| !FileTimeToSystemTime(&localTime, &systemTime))
	{
		return FALSE;
	}

	processInfo.hasStartTime = TRUE;
	processInfo.startTimeValue = startTimeValue;
	_sntprintf(processInfo.startTimeText, _countof(processInfo.startTimeText) - 1,
		_T("%04u-%02u-%02u %02u:%02u:%02u"),
		systemTime.wYear, systemTime.wMonth, systemTime.wDay,
		systemTime.wHour, systemTime.wMinute, systemTime.wSecond);
	processInfo.startTimeText[_countof(processInfo.startTimeText) - 1] = _T('\0');
	return TRUE;
}

// 读取单个已打开进程的创建时间，作为旧系统和异常情况下的回退路径。
static BOOL GetProcessStartTime(HANDLE hProcess, _myPROCESSINFO& processInfo)
{
	FILETIME creationTime;
	FILETIME exitTime;
	FILETIME kernelTime;
	FILETIME userTime;
	if (!GetProcessTimes(hProcess, &creationTime, &exitTime, &kernelTime, &userTime))
		return FALSE;

	ULARGE_INTEGER timeValue;
	timeValue.LowPart = creationTime.dwLowDateTime;
	timeValue.HighPart = creationTime.dwHighDateTime;
	return SetProcessStartTime(timeValue.QuadPart, processInfo);
}

// SYSTEM_PROCESS_INFORMATION 的固定前缀。创建时间位于偏移 32，父 PID 紧随进程 PID。
// 这里只读取 XP 至今保持稳定的字段，不依赖较新 SDK 中不断扩展的后续成员。
struct ProcessSnapshotEntryPrefix
{
	ULONG nextEntryOffset;
	BYTE reservedBeforeImageName[52];
	PVOID reservedImageNameAndPriority[3];
	HANDLE processId;
	PVOID parentProcessId;
};

static BOOL GetSnapshotProcessStartTimes(std::map<DWORD, ULONGLONG>& startTimes)
{
	typedef LONG (WINAPI* NtQuerySystemInformationProc)(
		ULONG systemInformationClass,
		PVOID systemInformation,
		ULONG systemInformationLength,
		PULONG returnLength);

	HMODULE ntdll = GetModuleHandle(_T("ntdll.dll"));
	NtQuerySystemInformationProc querySystemInformation = ntdll
		? reinterpret_cast<NtQuerySystemInformationProc>(
			GetProcAddress(ntdll, "NtQuerySystemInformation"))
		: NULL;
	if (!querySystemInformation)
		return FALSE;

	const ULONG systemProcessInformation = 5;
	const LONG statusInfoLengthMismatch = static_cast<LONG>(0xC0000004L);
	ULONG bufferSize = 64 * 1024;
	std::vector<BYTE> buffer;
	LONG status = statusInfoLengthMismatch;
	for (int attempt = 0; attempt < 8 && status == statusInfoLengthMismatch; ++attempt)
	{
		buffer.resize(bufferSize);
		ULONG requiredSize = 0;
		status = querySystemInformation(
			systemProcessInformation,
			&buffer[0],
			bufferSize,
			&requiredSize);
		if (status == statusInfoLengthMismatch)
		{
			bufferSize = requiredSize > bufferSize
				? requiredSize + 64 * 1024
				: bufferSize * 2;
		}
	}
	if (status < 0 || buffer.empty())
		return FALSE;

	BYTE* entryAddress = &buffer[0];
	for (;;)
	{
		ProcessSnapshotEntryPrefix* entry =
			reinterpret_cast<ProcessSnapshotEntryPrefix*>(entryAddress);
		DWORD pid = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(entry->processId));
		LARGE_INTEGER* creationTime = reinterpret_cast<LARGE_INTEGER*>(entryAddress + 32);
		if (pid != 0 && creationTime->QuadPart > 0)
			startTimes[pid] = static_cast<ULONGLONG>(creationTime->QuadPart);

		if (entry->nextEntryOffset == 0)
			break;
		entryAddress += entry->nextEntryOffset;
	}
	return !startTimes.empty();
}

int GetProcessList(list<_myPROCESSINFO> &ls)
{
	int nCount = 0;
	PROCESSENTRY32 pe;
	DWORD dwRet;
	_myPROCESSINFO mypi;
	std::map<DWORD, ULONGLONG> snapshotStartTimes;
	GetSnapshotProcessStartTimes(snapshotStartTimes);

	//
	// 通过 TOOHLP32 函数枚举进程
	//

	HANDLE hSP = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSP != INVALID_HANDLE_VALUE)
	{
		pe.dwSize = sizeof(pe);

		for (dwRet = Process32First(hSP, &pe);
			dwRet;
			dwRet = Process32Next(hSP, &pe))
		{
			ZeroMemory(&mypi, sizeof(mypi));

			mypi.pid = pe.th32ProcessID;
			mypi.parentPid = pe.th32ParentProcessID;
			// 保持原界面逐项插入到列表首行时形成的默认顺序。
			mypi.defaultOrder = -nCount;
			mypi.treeOrder = -1;
			_tcsncpy(mypi.proname, pe.szExeFile, MAX_PATH);
			mypi.proname[MAX_PATH - 1] = _T('\0');
			std::map<DWORD, ULONGLONG>::const_iterator snapshotTime =
				snapshotStartTimes.find(mypi.pid);
			if (snapshotTime != snapshotStartTimes.end())
				SetProcessStartTime(snapshotTime->second, mypi);

			HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
			BOOL canReadPath = hProcess != NULL;
			if (!hProcess)
			{
				// 某些进程不允许读取内存，但仍可能允许查询启动时间。
				hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
			}
			if (hProcess)
			{
				if (canReadPath)
					GetProcessFullPath(hProcess, mypi.propath, MAX_PATH);
				if (!mypi.hasStartTime)
					GetProcessStartTime(hProcess, mypi);
				CloseHandle(hProcess);
			}

			ls.push_back(mypi);

			nCount++;
		}

		::CloseHandle(hSP);
	}

	return nCount;
}

int GetProcessList_old(list<_myPROCESSINFO> &ls)
{
	int nCount = 0;
	unsigned int i;
	DWORD aProcesses[1024], cbNeeded;
	HANDLE hProcess;

	_myPROCESSINFO mypi;

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
	{
		return 0;
	}

	for ( i = 0; i < cbNeeded / sizeof(DWORD); i++ )
	{
		hProcess = OpenProcess( PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, FALSE, aProcesses[i]);

		if ( hProcess )
		{
			HMODULE hMod;
			char procName[255]={0};
			unsigned long cbNeeded;

			ZeroMemory(&mypi, sizeof(mypi));

			if(EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
			{
				mypi.pid = aProcesses[i];
				GetModuleBaseName(hProcess, hMod, mypi.proname, _countof(mypi.proname));
				GetModuleFileNameEx(hProcess, hMod, mypi.propath, _countof(mypi.propath));
				ls.push_back(mypi);
				nCount++;
			}


			CloseHandle( hProcess );
		}

	}

	return nCount;
}

BOOL InjectDll2(HANDLE hProc, DWORD dwPid, DWORD dwTid, LPCSTR lpszPipeName)
{
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi;
	PVOID WowRedirOldValue = NULL;

	si.cb = sizeof(si);

	BOOL bOK;
	CString strInjectCmd;
	CString strProxyLaneHook, strRundll;

	strProxyLaneHook = ChooseProxyLaneHookModule(hProc);
	strRundll = ChooseRundll32(strProxyLaneHook);

	strInjectCmd.Format(_T("%s \"%s\",AttachTo --pid=%lu --tid=%lu --pipe=%s"),
		strRundll, strProxyLaneHook, dwPid, dwTid, (LPCTSTR)(CString)lpszPipeName);

	myWow64DisableWow64FsRedirection(&WowRedirOldValue);

	bOK = CreateProcess(NULL, (LPTSTR)(LPCTSTR)strInjectCmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);

	myWow64RevertWow64FsRedirection(WowRedirOldValue);

	if (!bOK)
		return FALSE;

	DWORD dwEC = 0;

	WaitForSingleObject(pi.hProcess, INFINITE);
	GetExitCodeProcess(pi.hProcess, &dwEC);

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return dwEC == 0xFF01;
}

BOOL InjectDll(HANDLE hProc, DWORD dwPid, DWORD dwTid, LPCSTR lpszPipeName)
{
#ifdef _WIN64
	if (is64Process(hProc))
		return AttachToI(dwPid, dwTid, lpszPipeName) == 0xFF01;
	else
		return InjectDll2(hProc, dwPid, dwTid, lpszPipeName);
#else
	if (!is64Process(hProc))
		return AttachToI(dwPid, dwTid, lpszPipeName) == 0xFF01;
	else
		return InjectDll2(hProc, dwPid, dwTid, lpszPipeName);
#endif
}

BOOL HookProcess(DWORD pid, LPCSTR pipeName)
{
	BOOL bOK = FALSE;
	HANDLE hRemoteProcess = NULL;

	hRemoteProcess = ::OpenProcess(
		PROCESS_ALL_ACCESS,	FALSE, pid);

	if(hRemoteProcess == NULL)
	{
		ATLTRACE("OpenProcess Error. %d\r\n", GetLastError());
		return 0;
	}

	do 
	{
		if (!InjectDll(hRemoteProcess, pid, 0, pipeName))
			break;

		bOK = TRUE;
	} while (FALSE);

	if (hRemoteProcess)
		CloseHandle(hRemoteProcess);
	
	return bOK;
}

CString GetProxyLaneHookModulePath()
{
	HMODULE hModule = GetModuleHandle(_T("ProxyLaneHook.dll"));
	if(!hModule)
		return _T("");

	CString szRet;

	szRet.GetBuffer(MAX_PATH);
	GetModuleFileName(hModule, szRet.GetBuffer(), MAX_PATH-1);
	szRet.ReleaseBuffer();

	return szRet;
}

CString GetProxyLaneHookModule32Path()
{
	CString szCurrDir;

	szCurrDir.GetBuffer(MAX_PATH);
	GetModuleFileName(NULL, szCurrDir.GetBuffer(), MAX_PATH - 1);
	szCurrDir.ReleaseBuffer();

	szCurrDir = szCurrDir.Left(szCurrDir.ReverseFind('\\'));

	return szCurrDir + _T("\\ProxyLaneHook32.dll");
}

CString GetProxyLaneHookModule64Path()
{
	CString szCurrDir;

	szCurrDir.GetBuffer(MAX_PATH);
	GetModuleFileName(NULL, szCurrDir.GetBuffer(), MAX_PATH - 1);
	szCurrDir.ReleaseBuffer();

	szCurrDir = szCurrDir.Left(szCurrDir.ReverseFind('\\'));

	return szCurrDir + _T("\\ProxyLaneHook64.dll");
}

BOOL myWow64DisableWow64FsRedirection(__out PVOID *OldValue)
{
	typedef BOOL WINAPI __Wow64DisableWow64FsRedirection(
		_Out_  PVOID *OldValue
		);

	static __Wow64DisableWow64FsRedirection *FN = NULL;
	if (!FN)
	{
		FN = (__Wow64DisableWow64FsRedirection*)GetProcAddress(
			GetModuleHandle(TEXT("kernel32")), "Wow64DisableWow64FsRedirection");

		if (!FN)
			return FALSE;
	}

	return FN(OldValue);
}

BOOL myWow64RevertWow64FsRedirection( _In_  PVOID OldValue )
{
	typedef BOOL WINAPI __Wow64RevertWow64FsRedirection(
		_In_  PVOID OldValue
		);

	static __Wow64RevertWow64FsRedirection *FN = NULL;

	if (!FN)
	{
		FN = (__Wow64RevertWow64FsRedirection*)GetProcAddress(
			GetModuleHandle(TEXT("kernel32")), "Wow64RevertWow64FsRedirection");

		if (!FN)
			return FALSE;
	}

	return FN(OldValue);
}

BOOL IsWow64(HANDLE hProc)
{
	typedef BOOL(WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);

	LPFN_ISWOW64PROCESS fnIsWow64Process;

	BOOL bIsWow64 = FALSE;

	//IsWow64Process is not available on all supported versions of Windows.
	//Use GetModuleHandle to get a handle to the DLL that contains the function
	//and GetProcAddress to get a pointer to the function if available.

	fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(
		GetModuleHandle(TEXT("kernel32")), "IsWow64Process");

	if (NULL != fnIsWow64Process)
	{
		if (!fnIsWow64Process(hProc, &bIsWow64))
		{
			//handle error
		}
	}
	return bIsWow64;

}

BOOL is64Process(HANDLE hProc)
{
#ifdef _WIN64
	if (IsWow64(hProc))
		return FALSE;
	else
		return TRUE;
#else
	if (IsWow64(GetCurrentProcess()))
	{
		if (IsWow64(hProc))
			return FALSE;
		else
			return TRUE;
	}
	else
	{
		return FALSE;
	}
#endif
}

CString ChooseProxyLaneHookModule(HANDLE hProc)
{
	if (is64Process(hProc))
		return GetProxyLaneHookModule64Path();
	else
		return GetProxyLaneHookModule32Path();
}

CString ChooseRundll32(CString &strDllPath)
{
	BOOL is64 = strDllPath.Right(6).CompareNoCase(_T("64.dll")) == 0;
	CString strPath;

	GetWindowsDirectory(strPath.GetBuffer(MAX_PATH), MAX_PATH);
	strPath.ReleaseBuffer();

	//SysWOW64, System32

#ifdef _WIN64
	if (is64)
		return strPath + _T("\\System32\\rundll32.exe");
	else
		return strPath + _T("\\SysWOW64\\rundll32.exe");
#else
	if (IsWow64(GetCurrentProcess()))
	{
		if (is64)
			return strPath + _T("\\System32\\rundll32.exe");
		else
			return strPath + _T("\\SysWOW64\\rundll32.exe");
	}
	else
	{
		return strPath + _T("\\System32\\rundll32.exe");
	}
#endif
}


static BOOL ResolveChildAppPath(HANDLE hChildProc, LPWSTR szOut, DWORD cchOut)
{
	if (!szOut || cchOut == 0)
		return FALSE;

	szOut[0] = L'\0';

	typedef BOOL(WINAPI* PFN_QFIN)(HANDLE, DWORD, LPWSTR, PDWORD);
	static PFN_QFIN s_pQFIN = (PFN_QFIN)-1;
	if (s_pQFIN == (PFN_QFIN)-1)
	{
		HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
		s_pQFIN = hK32 ? (PFN_QFIN)GetProcAddress(hK32, "QueryFullProcessImageNameW") : NULL;
	}
	if (s_pQFIN)
	{
		DWORD cch = cchOut;
		if (s_pQFIN(hChildProc, 0, szOut, &cch) && szOut[0])
			return TRUE;
		szOut[0] = L'\0';
	}

	// 2) 回退：psapi GetModuleFileNameExW（NT4+，但子进程刚 spawn 模块表可能还没就绪，作为次选）
	HMODULE hMod = NULL;
	DWORD cbNeeded = 0;
	if (EnumProcessModules(hChildProc, &hMod, sizeof(hMod), &cbNeeded))
	{
		if (GetModuleFileNameExW(hChildProc, hMod, szOut, cchOut) > 0)
		{
			szOut[cchOut - 1] = L'\0';
			if (szOut[0])
				return TRUE;
		}
		szOut[0] = L'\0';
	}
	return FALSE;

}

BOOL GetProcessBaseName(DWORD dwPid, HANDLE hProcess, LPTSTR szProcName)
{
	PROCESSENTRY32 pe;  
	DWORD dwRet;
	BOOL bFound = FALSE;

	TCHAR szName[MAX_PATH];
	DWORD cch = MAX_PATH;
	if (ResolveChildAppPath(hProcess, szName, cch)) {
		TCHAR* pName = _tcsrchr(szName, '\\');
		if (pName) {
			_tcscpy(szProcName, pName + 1);
		}
		else {
			_tcscpy(szProcName, szName);
		}
		return TRUE;
	}

	//
	// 通过 TOOHLP32 函数枚举进程
	//

	HANDLE hSP =  ::CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
	if ( hSP )
	{
		pe.dwSize = sizeof( pe );

		for ( dwRet = Process32First( hSP, &pe );
			dwRet;
			dwRet = Process32Next( hSP, &pe ) )
		{

			if (dwPid == pe.th32ProcessID )
			{

				_tcscpy(szProcName, pe.szExeFile);

				bFound = TRUE;
				break;
			}
		}

		::CloseHandle( hSP );
	}

	return bFound;
}


// CPage3 对话框

IMPLEMENT_DYNAMIC(CPage3, CModernDialog)

CPage3::CPage3(CWnd* pParent /*=NULL*/)
	: CModernDialog(CPage3::IDD, pParent)
	, m_evlock()
	, m_sortColumn(-1)
	, m_sortState(PROCESS_SORT_NONE)
	, m_processNameSearchTick(0)
{
	//m_pEdit = NULL;
	//m_pEdit = new CMyEdit;
	m_evlock.SetEvent();

}

CPage3::~CPage3()
{
}

void CPage3::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_PSLIST, m_ListCtrl);
	DDX_Control(pDX, IDC_REFRESH, m_btnRefresh);
	DDX_Control(pDX, IDC_INJECTDLL, m_btnInject);

	//DDX_Control(pDX, IDC_CHECK1, m_btnAuto);
}

BOOL CPage3::OnInitDialog()
{
	CModernDialog::OnInitDialog();
	DragAcceptFiles(FALSE);
	m_ListCtrl.DragAcceptFiles(FALSE);
	m_btnRefresh.SetVisualStyle(CModernButton::STYLE_SECONDARY);
	m_btnInject.SetVisualStyle(CModernButton::STYLE_PRIMARY);
	SetDlgItemText(
		IDC_STATIC_PAGE_SUBTITLE,
		_T("选择运行中的进程（按住 Ctrl 或 Shift 可多选），或拖入程序/快捷方式启动并代理"));
	// 资源模板为兼容旧版本仍可能带有单选样式，初始化时统一启用多选。
	m_ListCtrl.ModifyStyle(LVS_SINGLESEL, 0);

	m_ListCtrl.InsertColumn(0, _T("PID"), 0, 50);
	m_ListCtrl.InsertColumn(1, _T("进程名"), 0, 180);
	m_ListCtrl.InsertColumn(2, _T("启动时间"), 0, 150);
	m_ListCtrl.InsertColumn(3, _T("路径"), 0, 200);

	DWORD dwStyle = m_ListCtrl.GetExtendedStyle();
	dwStyle |= LVS_EX_FULLROWSELECT;
	m_ListCtrl.SetExtendedStyle(dwStyle);

	DebugPrivilege(SE_DEBUG_NAME, TRUE);

	UpdatePslist(TRUE);
	SetTimer(TIMER_PSLIST, 2000, NULL);

	m_ListCtrl.ThrowUnhandledMessage(TRUE);

	// snapshot for adaptive layout
	CRect rcClient;
	GetClientRect(&rcClient);
	m_szInit = rcClient.Size();

	if (m_ListCtrl.GetSafeHwnd())
	{
		CRect rc;
		m_ListCtrl.GetWindowRect(&rc);
		ScreenToClient(&rc);
		m_rcListInit = rc;
	}
	if (CWnd *pBtn = GetDlgItem(IDC_INJECTDLL))
	{
		CRect rc;
		pBtn->GetWindowRect(&rc);
		ScreenToClient(&rc);
		m_rcBtnInjectInit = rc;
	}
	if (CWnd *pHint = GetDlgItem(IDC_HINT_DROPFILE))
	{
		CRect rc;
		pHint->GetWindowRect(&rc);
		ScreenToClient(&rc);
		m_rcHintInit = rc;
	}

	return TRUE;
}

BOOL CPage3::PreTranslateMessage(MSG* message)
{
	if (!message || !m_ListCtrl.GetSafeHwnd() || message->hwnd != m_ListCtrl.m_hWnd)
		return CModernDialog::PreTranslateMessage(message);

	if (message->message == WM_LBUTTONDOWN
		|| message->message == WM_RBUTTONDOWN
		|| message->message == WM_MBUTTONDOWN)
	{
		// 鼠标重新定位后，下一次字符输入应当开始新的搜索。
		m_processNameSearchText.Empty();
		m_processNameSearchTick = 0;
		return CModernDialog::PreTranslateMessage(message);
	}

	if (message->message != WM_CHAR)
		return CModernDialog::PreTranslateMessage(message);

	TCHAR inputCharacter = static_cast<TCHAR>(message->wParam);
	DWORD currentTick = GetTickCount();
	const DWORD searchTimeout = 1500;
	if (m_processNameSearchTick == 0
		|| currentTick - m_processNameSearchTick > searchTimeout)
	{
		m_processNameSearchText.Empty();
	}
	m_processNameSearchTick = currentTick;

	if (inputCharacter == VK_ESCAPE)
	{
		m_processNameSearchText.Empty();
		m_processNameSearchTick = 0;
		return TRUE;
	}

	if (inputCharacter == VK_BACK)
	{
		if (!m_processNameSearchText.IsEmpty())
			m_processNameSearchText.Delete(m_processNameSearchText.GetLength() - 1);
		if (!m_processNameSearchText.IsEmpty())
			SelectFirstProcessByNamePrefix(m_processNameSearchText);
		return TRUE;
	}

	if (inputCharacter < _T(' ')
		|| (GetKeyState(VK_CONTROL) & 0x8000) != 0
		|| (GetKeyState(VK_MENU) & 0x8000) != 0)
	{
		return CModernDialog::PreTranslateMessage(message);
	}

	m_processNameSearchText.AppendChar(inputCharacter);
	SelectFirstProcessByNamePrefix(m_processNameSearchText);
	// 阻止列表控件继续按第一列 PID 执行默认增量搜索。
	return TRUE;
}

BOOL CPage3::SelectFirstProcessByNamePrefix(const CString& prefix)
{
	if (prefix.IsEmpty())
		return FALSE;

	for (int item = 0; item < m_ListCtrl.GetItemCount(); ++item)
	{
		DWORD pid = static_cast<DWORD>(m_ListCtrl.GetItemData(item));
		std::map<DWORD, _myPROCESSINFO>::const_iterator process = m_processSortData.find(pid);
		if (process == m_processSortData.end())
			continue;

		CString processName(process->second.proname);
		if (processName.GetLength() < prefix.GetLength()
			|| processName.Left(prefix.GetLength()).CompareNoCase(prefix) != 0)
		{
			continue;
		}

		// 键盘定位表示一次新的目标选择，不保留此前的多选状态。
		m_ListCtrl.SetItemState(-1, 0, LVIS_SELECTED | LVIS_FOCUSED);
		m_ListCtrl.SetItemState(
			item,
			LVIS_SELECTED | LVIS_FOCUSED,
			LVIS_SELECTED | LVIS_FOCUSED);
		m_ListCtrl.SetSelectionMark(item);
		m_ListCtrl.EnsureVisible(item, FALSE);
		return TRUE;
	}
	return FALSE;
}

BEGIN_MESSAGE_MAP(CPage3, CModernDialog)
	ON_WM_SIZE()
	ON_BN_CLICKED(IDC_REFRESH, &CPage3::OnBnClickedRefresh)
	ON_BN_CLICKED(IDC_INJECTDLL, &CPage3::OnBnClickedInjectdll)
	ON_NOTIFY(LVN_COLUMNCLICK, IDC_PSLIST, &CPage3::OnLvnColumnClickProcessList)
	ON_NOTIFY(NM_CUSTOMDRAW, IDC_PSLIST, &CPage3::OnNMCustomdrawProcessList)
	ON_MESSAGE(WM_ON_REFRESHPS, &CPage3::OnRefreshPslist)
	ON_WM_TIMER()
END_MESSAGE_MAP()


// CPage3 消息处理程序

void CPage3::OnSize(UINT nType, int cx, int cy)
{
	CModernDialog::OnSize(nType, cx, cy);
	CRect rcClient;
	GetClientRect(&rcClient);
	if (rcClient.Width() <= 0 || rcClient.Height() <= 0)
		return;

	if (m_ListCtrl.GetSafeHwnd())
	{
		int margin = UiTheme::ScaleForWindow(m_hWnd, 8);
		int top = UiTheme::ScaleForWindow(m_hWnd, 58);
		int bottom = UiTheme::ScaleForWindow(m_hWnd, 8);
		CRect rc(margin, top, rcClient.right - margin, rcClient.bottom - bottom);
		m_ListCtrl.MoveWindow(&rc);
		int pathWidth = rc.Width() - UiTheme::ScaleForWindow(m_hWnd, 445);
		if (pathWidth > UiTheme::ScaleForWindow(m_hWnd, 140))
			m_ListCtrl.SetColumnWidth(3, pathWidth);
	}

	int margin = UiTheme::ScaleForWindow(m_hWnd, 8);
	int gap = UiTheme::ScaleForWindow(m_hWnd, 6);
	int refreshWidth = UiTheme::ScaleForWindow(m_hWnd, 70);
	int injectWidth = UiTheme::ScaleForWindow(m_hWnd, 96);
	int buttonHeight = UiTheme::ScaleForWindow(m_hWnd, 30);
	int buttonTop = UiTheme::ScaleForWindow(m_hWnd, 12);
	if (m_btnInject.GetSafeHwnd())
		m_btnInject.MoveWindow(rcClient.right - margin - injectWidth, buttonTop, injectWidth, buttonHeight);
	if (m_btnRefresh.GetSafeHwnd())
		m_btnRefresh.MoveWindow(rcClient.right - margin - injectWidth - gap - refreshWidth,
			buttonTop, refreshWidth, buttonHeight);
}

int CPage3::UpdatePslist(BOOL bRefresh)
{
	CSingleLock lc(&m_evlock, TRUE);

	list<_myPROCESSINFO> psls;

	//查询当前所有进程
	int nPsCount = GetProcessList(psls);

	// 保存本次快照，排序比较时直接使用原始数据，避免按显示文本错误排序。
	m_processSortData.clear();
	for (list<_myPROCESSINFO>::const_iterator it = psls.begin(); it != psls.end(); ++it)
		m_processSortData[it->pid] = *it;
	BuildProcessTree();

	int nItemCount = m_ListCtrl.GetItemCount();
	TCHAR szPath[MAX_PATH];

	//listctrl中逐个item的查看是否在psls中， 如果在则将psls中的节点移除， 不在则将item移除
	for(int nItem=0; nItem<nItemCount; nItem++)
	{
		LVITEM lvitem;
		lvitem.mask = LVIF_PARAM | LVIF_TEXT;
		lvitem.iItem = nItem;
		lvitem.pszText = szPath;
		lvitem.cchTextMax = MAX_PATH;
		lvitem.iSubItem = 3;

		//
		szPath[0] = 0;

		if(m_ListCtrl.GetItem(&lvitem))
		{
			DWORD dwPid = (DWORD)lvitem.lParam;

			BOOL bLive = FALSE;
			for(list<_myPROCESSINFO>::iterator it = psls.begin(); it!=psls.end();)
			{
				if(it->pid == dwPid)
				{
					BOOL sameProcess = TRUE;
					std::map<DWORD, ULONGLONG>::const_iterator displayedTime =
						m_displayedStartTimes.find(dwPid);
					if (displayedTime != m_displayedStartTimes.end()
						&& displayedTime->second != 0
						&& it->hasStartTime
						&& displayedTime->second != it->startTimeValue)
					{
						// PID 已被新进程复用，先删除旧行，再按新进程重新插入。
						sameProcess = FALSE;
					}

					if (!sameProcess)
						break;

					m_ListCtrl.SetItemText(nItem, 1, it->proname);
					m_ListCtrl.SetItemText(nItem, 2, it->startTimeText);
					if (szPath[0] == 0)
					{
						if (it->propath[0] != _T('\0'))
						{
							m_ListCtrl.SetItemText(nItem, 3, it->propath);
						}
					}

					m_displayedStartTimes[dwPid] = it->hasStartTime ? it->startTimeValue : 0;
					psls.erase(it++);
					bLive = TRUE;
					break;
				}else
				{
					it++;
				}
			}

			if(bLive == FALSE)
			{
				m_displayedStartTimes.erase(dwPid);
				m_ListCtrl.DeleteItem(nItem--);
				nItemCount--;
			}
		}
	}

	//list有剩的则是新的进程
	for(list<_myPROCESSINFO>::iterator it = psls.begin(); it!=psls.end(); it++)
	{
		CString szPid;
		szPid.Format(_T("%d"), it->pid);

		LVITEM lvitem;

		lvitem.mask = LVIF_PARAM|LVIF_TEXT;

		lvitem.pszText = szPid.GetBuffer();
		lvitem.lParam = it->pid;

		lvitem.iSubItem = 0;
		lvitem.iItem = 0;

		m_ListCtrl.InsertItem(&lvitem);
		m_ListCtrl.SetItemText(0, 1, it->proname);
		m_ListCtrl.SetItemText(0, 2, it->startTimeText);
		m_ListCtrl.SetItemText(0, 3, it->propath);
		m_displayedStartTimes[it->pid] = it->hasStartTime ? it->startTimeValue : 0;

		//if(!bRefresh && m_btnAuto.GetCheck() == BST_CHECKED)
		//{
		//	ProxyProcess(it->pid);
		//}

	}

	// 自动刷新后继续保持用户选择的排序状态。
	ApplyProcessSort();

	m_evlock.SetEvent();
	lc.Unlock();
	return 0;
}

int CALLBACK CPage3::CompareProcessItems(LPARAM leftParam, LPARAM rightParam, LPARAM sortParam)
{
	CPage3* page = reinterpret_cast<CPage3*>(sortParam);
	if (!page)
		return 0;

	DWORD leftPid = static_cast<DWORD>(leftParam);
	DWORD rightPid = static_cast<DWORD>(rightParam);
	std::map<DWORD, _myPROCESSINFO>::const_iterator leftIt =
		page->m_processSortData.find(leftPid);
	std::map<DWORD, _myPROCESSINFO>::const_iterator rightIt =
		page->m_processSortData.find(rightPid);

	// 快照中缺失的项目统一排在末尾，下一次刷新时会被移除。
	if (leftIt == page->m_processSortData.end()
		|| rightIt == page->m_processSortData.end())
	{
		if (leftIt == rightIt)
			return 0;
		return leftIt == page->m_processSortData.end() ? 1 : -1;
	}

	const _myPROCESSINFO& left = leftIt->second;
	const _myPROCESSINFO& right = rightIt->second;
	int result = 0;

	if (page->m_sortState == PROCESS_SORT_NONE || page->m_sortColumn < 0)
	{
		if (left.treeOrder < right.treeOrder)
			result = -1;
		else if (left.treeOrder > right.treeOrder)
			result = 1;
	}
	else
	{
		switch (page->m_sortColumn)
		{
		case 0:
			if (left.pid < right.pid)
				result = -1;
			else if (left.pid > right.pid)
				result = 1;
			break;

		case 1:
			result = _tcsicmp(left.proname, right.proname);
			break;

		case 2:
			// 无法读取启动时间的进程始终放在有时间的进程之后。
			if (left.hasStartTime != right.hasStartTime)
				return left.hasStartTime ? -1 : 1;
			if (left.hasStartTime)
			{
				if (left.startTimeValue < right.startTimeValue)
					result = -1;
				else if (left.startTimeValue > right.startTimeValue)
					result = 1;
			}
			break;

		case 3:
			result = _tcsicmp(left.propath, right.propath);
			break;
		}

		if (page->m_sortState == PROCESS_SORT_DESCENDING)
			result = -result;
	}

	// 主排序值相同时使用 PID 保持结果稳定。
	if (result == 0)
	{
		if (left.pid < right.pid)
			result = -1;
		else if (left.pid > right.pid)
			result = 1;
	}
	return result;
}

namespace
{
	// 父子树中的同级进程沿用原列表的默认顺序。
	struct ProcessDefaultOrderLess
	{
		const std::map<DWORD, _myPROCESSINFO>* processData;

		bool operator()(DWORD leftPid, DWORD rightPid) const
		{
			std::map<DWORD, _myPROCESSINFO>::const_iterator left = processData->find(leftPid);
			std::map<DWORD, _myPROCESSINFO>::const_iterator right = processData->find(rightPid);
			if (left == processData->end() || right == processData->end())
				return leftPid < rightPid;
			if (left->second.defaultOrder != right->second.defaultOrder)
				return left->second.defaultOrder < right->second.defaultOrder;
			return leftPid < rightPid;
		}
	};
}

void CPage3::BuildProcessTree()
{
	m_processTreePrefixes.clear();

	std::map<DWORD, std::vector<DWORD> > children;
	std::vector<DWORD> roots;
	for (std::map<DWORD, _myPROCESSINFO>::iterator it = m_processSortData.begin();
		it != m_processSortData.end(); ++it)
	{
		_myPROCESSINFO& process = it->second;
		process.treeOrder = -1;

		std::map<DWORD, _myPROCESSINFO>::const_iterator parent =
			m_processSortData.find(process.parentPid);
		BOOL validParent = process.parentPid != 0
			&& process.parentPid != process.pid
			&& parent != m_processSortData.end();

		// PID 可能在父进程退出后被复用；能读取到时间时排除明显无效的父子关系。
		if (validParent
			&& parent->second.hasStartTime
			&& process.hasStartTime
			&& parent->second.startTimeValue > process.startTimeValue)
		{
			validParent = FALSE;
		}

		if (validParent)
			children[process.parentPid].push_back(process.pid);
		else
			roots.push_back(process.pid);
	}

	ProcessDefaultOrderLess orderLess;
	orderLess.processData = &m_processSortData;
	std::sort(roots.begin(), roots.end(), orderLess);
	for (std::map<DWORD, std::vector<DWORD> >::iterator it = children.begin();
		it != children.end(); ++it)
	{
		std::sort(it->second.begin(), it->second.end(), orderLess);
	}

	std::set<DWORD> visited;
	int nextTreeOrder = 0;
	for (size_t rootIndex = 0; rootIndex < roots.size(); ++rootIndex)
	{
		AppendProcessTree(
			roots[rootIndex], _T(""), _T(""), children, visited, nextTreeOrder);
	}

	// 极少数异常快照可能形成循环；将未访问进程作为新的根节点，保证每行都能显示。
	std::vector<DWORD> remaining;
	for (std::map<DWORD, _myPROCESSINFO>::const_iterator it = m_processSortData.begin();
		it != m_processSortData.end(); ++it)
	{
		if (visited.find(it->first) == visited.end())
			remaining.push_back(it->first);
	}
	std::sort(remaining.begin(), remaining.end(), orderLess);
	for (size_t index = 0; index < remaining.size(); ++index)
	{
		if (visited.find(remaining[index]) == visited.end())
			AppendProcessTree(
				remaining[index], _T(""), _T(""), children, visited, nextTreeOrder);
	}
}

void CPage3::AppendProcessTree(
	DWORD pid,
	const CString& displayPrefix,
	const CString& childPrefix,
	std::map<DWORD, std::vector<DWORD> >& children,
	std::set<DWORD>& visited,
	int& treeOrder)
{
	if (visited.find(pid) != visited.end())
		return;

	std::map<DWORD, _myPROCESSINFO>::iterator process = m_processSortData.find(pid);
	if (process == m_processSortData.end())
		return;

	visited.insert(pid);
	process->second.treeOrder = treeOrder++;
	m_processTreePrefixes[pid] = displayPrefix;

	std::map<DWORD, std::vector<DWORD> >::iterator childList = children.find(pid);
	if (childList == children.end())
		return;

	for (size_t index = 0; index < childList->second.size(); ++index)
	{
		DWORD childPid = childList->second[index];
		if (visited.find(childPid) != visited.end())
			continue;

		BOOL isLastChild = index + 1 == childList->second.size();
		CString childDisplayPrefix = childPrefix
			+ (isLastChild ? _T("└─ ") : _T("├─ "));
		CString nextChildPrefix = childPrefix
			+ (isLastChild ? _T("   ") : _T("│  "));
		AppendProcessTree(
			childPid,
			childDisplayPrefix,
			nextChildPrefix,
			children,
			visited,
			treeOrder);
	}
}

void CPage3::ApplyProcessSort()
{
	if (m_ListCtrl.GetSafeHwnd() && m_ListCtrl.GetItemCount() > 1)
		m_ListCtrl.SortItems(CompareProcessItems, reinterpret_cast<LPARAM>(this));
	UpdateProcessNameDisplay();
	// 新进程的背景色会随时间衰减，定时刷新时强制重绘可及时切换颜色阶段。
	if (m_ListCtrl.GetSafeHwnd())
		m_ListCtrl.Invalidate(FALSE);
}

void CPage3::UpdateProcessNameDisplay()
{
	if (!m_ListCtrl.GetSafeHwnd())
		return;

	for (int item = 0; item < m_ListCtrl.GetItemCount(); ++item)
	{
		DWORD pid = static_cast<DWORD>(m_ListCtrl.GetItemData(item));
		std::map<DWORD, _myPROCESSINFO>::const_iterator process = m_processSortData.find(pid);
		if (process == m_processSortData.end())
			continue;

		CString displayName;
		if (m_sortState == PROCESS_SORT_NONE)
		{
			std::map<DWORD, CString>::const_iterator prefix = m_processTreePrefixes.find(pid);
			if (prefix != m_processTreePrefixes.end())
				displayName = prefix->second;
		}
		displayName += process->second.proname;
		m_ListCtrl.SetItemText(item, 1, displayName);
	}
}

void CPage3::UpdateSortIndicator()
{
	CHeaderCtrl* header = m_ListCtrl.GetHeaderCtrl();
	if (!header || !header->GetSafeHwnd())
		return;

	for (int column = 0; column < header->GetItemCount(); ++column)
	{
		HDITEM item;
		ZeroMemory(&item, sizeof(item));
		item.mask = HDI_FORMAT;
		if (!header->GetItem(column, &item))
			continue;

		item.fmt &= ~(HDF_SORTUP | HDF_SORTDOWN);
		if (column == m_sortColumn)
		{
			if (m_sortState == PROCESS_SORT_ASCENDING)
				item.fmt |= HDF_SORTUP;
			else if (m_sortState == PROCESS_SORT_DESCENDING)
				item.fmt |= HDF_SORTDOWN;
		}
		header->SetItem(column, &item);
	}
}

void CPage3::OnLvnColumnClickProcessList(NMHDR* notifyHeader, LRESULT* result)
{
	NM_LISTVIEW* listView = reinterpret_cast<NM_LISTVIEW*>(notifyHeader);
	if (!listView || listView->iSubItem < 0 || listView->iSubItem > 3)
	{
		if (result)
			*result = 0;
		return;
	}

	const int clickedColumn = listView->iSubItem;
	if (m_sortColumn != clickedColumn || m_sortState == PROCESS_SORT_NONE)
	{
		m_sortColumn = clickedColumn;
		m_sortState = PROCESS_SORT_ASCENDING;
	}
	else if (m_sortState == PROCESS_SORT_ASCENDING)
	{
		m_sortState = PROCESS_SORT_DESCENDING;
	}
	else
	{
		m_sortColumn = -1;
		m_sortState = PROCESS_SORT_NONE;
	}

	UpdateSortIndicator();
	ApplyProcessSort();
	if (result)
		*result = 0;
}

void CPage3::OnNMCustomdrawProcessList(NMHDR* notifyHeader, LRESULT* result)
{
	if (!result)
		return;

	NMLVCUSTOMDRAW* customDraw = reinterpret_cast<NMLVCUSTOMDRAW*>(notifyHeader);
	if (!customDraw)
	{
		*result = CDRF_DODEFAULT;
		return;
	}

	if (customDraw->nmcd.dwDrawStage == CDDS_PREPAINT)
	{
		*result = CDRF_NOTIFYITEMDRAW;
		return;
	}

	if (customDraw->nmcd.dwDrawStage != CDDS_ITEMPREPAINT
		|| m_sortState != PROCESS_SORT_NONE)
	{
		*result = CDRF_DODEFAULT;
		return;
	}

	int item = static_cast<int>(customDraw->nmcd.dwItemSpec);
	if (item < 0
		|| item >= m_ListCtrl.GetItemCount()
		|| (m_ListCtrl.GetItemState(item, LVIS_SELECTED) & LVIS_SELECTED) != 0)
	{
		// 被选中的行继续使用系统高亮色，避免自定义背景掩盖选择状态。
		*result = CDRF_DODEFAULT;
		return;
	}

	DWORD pid = static_cast<DWORD>(m_ListCtrl.GetItemData(item));
	std::map<DWORD, _myPROCESSINFO>::const_iterator process = m_processSortData.find(pid);
	if (process == m_processSortData.end() || !process->second.hasStartTime)
	{
		*result = CDRF_DODEFAULT;
		return;
	}

	FILETIME currentFileTime;
	GetSystemTimeAsFileTime(&currentFileTime);
	ULARGE_INTEGER currentTime;
	currentTime.LowPart = currentFileTime.dwLowDateTime;
	currentTime.HighPart = currentFileTime.dwHighDateTime;
	if (currentTime.QuadPart < process->second.startTimeValue)
	{
		*result = CDRF_DODEFAULT;
		return;
	}

	const ULONGLONG unitsPerSecond = 10000000ULL;
	ULONGLONG age = currentTime.QuadPart - process->second.startTimeValue;
	if (age < 5 * unitsPerSecond)
		customDraw->clrTextBk = RGB(255, 236, 179); // 刚刚出现：浅金黄色
	else if (age < 10 * unitsPerSecond)
		customDraw->clrTextBk = RGB(220, 243, 228); // 新进程：浅绿色
	else if (age < 20 * unitsPerSecond)
		customDraw->clrTextBk = RGB(229, 240, 252); // 近期进程：浅蓝色

	*result = CDRF_DODEFAULT;
}

void CPage3::OnBnClickedRefresh()
{
	// TODO: 在此添加控件通知处理程序代码
	m_ListCtrl.DeleteAllItems();
	m_displayedStartTimes.clear();
	UpdatePslist(TRUE);
}

void CPage3::OnBnClickedInjectdll()
{
	if(!m_ListCtrl.GetSelectedCount())
	{
		MessageBox(_T("请先在列表中选择一个进程。"), _T("未选择进程"), MB_ICONINFORMATION);
		return;
	}

	// 先保存全部选中目标，防止处理期间列表刷新导致行号和选择状态变化。
	struct SelectedProcessTarget
	{
		DWORD pid;
		CString name;
	};
	std::vector<SelectedProcessTarget> targets;
	int unreadableCount = 0;
	POSITION pos = m_ListCtrl.GetFirstSelectedItemPosition();
	while (pos)
	{
		int item = m_ListCtrl.GetNextSelectedItem(pos);
		LVITEM listItem;
		ZeroMemory(&listItem, sizeof(listItem));
		listItem.mask = LVIF_PARAM;
		listItem.iItem = item;
		listItem.iSubItem = 0;
		if (!m_ListCtrl.GetItem(&listItem))
		{
			++unreadableCount;
			continue;
		}

		SelectedProcessTarget target;
		target.pid = static_cast<DWORD>(listItem.lParam);
		target.name = m_ListCtrl.GetItemText(item, 1);
		std::map<DWORD, _myPROCESSINFO>::const_iterator process =
			m_processSortData.find(target.pid);
		if (process != m_processSortData.end())
			target.name = process->second.proname;
		targets.push_back(target);
	}

	if (targets.empty())
	{
		MessageBox(_T("无法读取所选进程，请刷新列表后重试。"), _T("进程不可用"), MB_ICONERROR);
		return;
	}

	char szPipeName[MAX_PATH] = "\0";
	IProxyReceptionCentre *pPRC = NULL;
	if(!g_GlobalProxy || !(pPRC = g_GlobalProxy->GetPRCInstance()))
	{
		MessageBox(_T("请先在“代理设置”页面启动代理。"), _T("代理未启动"), MB_ICONINFORMATION);
		return;
	}
	if(!pPRC->GetPRCPipeName(szPipeName, MAX_PATH))
	{
		MessageBox(_T("无法获取代理通信通道，请停止代理后重新启动。"), _T("代理状态异常"), MB_ICONERROR);
		return;
	}

	int successCount = 0;
	int failedCount = unreadableCount;
	int skippedCount = 0;
	std::vector<CString> failedProcesses;
	DWORD currentPid = GetCurrentProcessId();
	for (size_t index = 0; index < targets.size(); ++index)
	{
		const SelectedProcessTarget& target = targets[index];
		if (target.pid == currentPid)
		{
			++skippedCount;
			continue;
		}

		if (HookProcess(target.pid, szPipeName))
		{
			++successCount;
		}
		else
		{
			++failedCount;
			CString failedProcess;
			failedProcess.Format(_T("%s (%lu)"),
				target.name.IsEmpty() ? _T("未知进程") : static_cast<LPCTSTR>(target.name),
				target.pid);
			failedProcesses.push_back(failedProcess);
		}
	}

	CString resultText;
	int totalCount = static_cast<int>(targets.size()) + unreadableCount;
	resultText.Format(
		_T("已处理 %d 个进程：成功 %d 个，失败 %d 个，跳过 %d 个。"),
		totalCount,
		successCount,
		failedCount,
		skippedCount);

	if (failedCount > 0)
	{
		resultText += _T("\r\n\r\n代理失败的进程：");
		const size_t maxFailureDetails = 10;
		for (size_t index = 0;
			index < failedProcesses.size() && index < maxFailureDetails;
			++index)
		{
			resultText += _T("\r\n");
			resultText += failedProcesses[index];
		}
		if (failedProcesses.size() > maxFailureDetails)
		{
			CString remainingText;
			remainingText.Format(
				_T("\r\n以及另外 %u 个进程。"),
				static_cast<unsigned int>(failedProcesses.size() - maxFailureDetails));
			resultText += remainingText;
		}
		if (unreadableCount > 0)
			resultText += _T("\r\n另有选中项无法从列表中读取。");
	}
	if (skippedCount > 0)
		resultText += _T("\r\n\r\n已跳过 ProxyLane 自身进程。");

	MessageBox(
		resultText,
		failedCount > 0 ? _T("部分进程代理失败") : _T("操作完成"),
		failedCount > 0 ? MB_ICONWARNING : MB_ICONINFORMATION);
}

void CPage3::OnTimer(UINT_PTR nIDEvent)
{
	// TODO: 在此添加消息处理程序代码和/或调用默认值
	switch(nIDEvent)
	{
	case TIMER_PSLIST:
		{
			UpdatePslist(FALSE);
		}
		break;
	}

}

LRESULT CPage3::OnRefreshPslist(WPARAM w, LPARAM l)
{
	UpdatePslist(w);

	return 1;
}


void CPage3::OnNewProcess(LPHookNewProcessInfo lphnpi)
{
	InjectNewProcess(lphnpi);
}

BOOL CPage3::InjectNewProcess(LPHookNewProcessInfo lphnpi)
{
	SendMessage(WM_ON_REFRESHPS, TRUE);

	HookNewProcessInfo hnpi = *lphnpi;
	HANDLE hProcess;
	int bRet;
	char szPipeName[MAX_PATH] = "\0";
	IProxyReceptionCentre *pPRC = NULL;

	if(!g_GlobalProxy || !(pPRC = g_GlobalProxy->GetPRCInstance()))
	{
		return FALSE;
	}
	if(!pPRC->GetPRCPipeName(szPipeName, MAX_PATH))
	{
		return FALSE;
	}

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, hnpi.dwProcessId);

	if (!hProcess)
		return FALSE;

	CPage2 *pPage2 = g_MainTab->GetPage2();

	TCHAR procName[MAX_PATH]={0};
	GetProcessBaseName(hnpi.dwProcessId, hProcess, procName);

	CString szText;

	// 子进程注入过滤：按 profile 配置决定是否调用 InjectDll
	if (g_ChildInjectFilter.bEnabled && !g_ChildInjectFilter.patterns.empty())
	{
		BOOL bMatched = FALSE;
		if (hnpi.szAppPath[0])
		{
			for (size_t i = 0; i < g_ChildInjectFilter.patterns.size(); i++)
			{
				if (PathMatchSpecW(hnpi.szAppPath, g_ChildInjectFilter.patterns[i]))
				{
					bMatched = TRUE;
					break;
				}
			}
		}

		BOOL bShouldInject = (g_ChildInjectFilter.nMode == CHILDFILTER_MODE_INCLUDE) ? bMatched : !bMatched;
		if (!bShouldInject)
		{
			szText.Format(_T("New Process: %d | %s Skipped by filter\r\n"), hnpi.dwProcessId, procName);
			pPage2->AddLogText(szText);
			CloseHandle(hProcess);
			return FALSE;
		}
	}

	bRet = InjectDll(hProcess, hnpi.dwProcessId, hnpi.dwThreadId, szPipeName);

	if (bRet > 0)
		szText.Format(_T("New Process: %d | %s Hooked\r\n"), hnpi.dwProcessId, procName);
	else
		szText.Format(_T("New Process: %d | %s InjectDll Failed\r\n"), hnpi.dwProcessId, procName);

	pPage2->AddLogText(szText);

	CloseHandle(hProcess);
	return bRet > 0;
}

void CPage3::LogNewProxyTask(const LPPRCClient lpC)
{

}

void CPage3::LogText(LPCWSTR lpText)
{
}

// GetLinkInfo() fills the filename and path buffer
// with relevant information.
// hWnd         - calling application's window handle.
//
// lpszLinkName - name of the link file passed into the function.
//
// lpszPath     - the buffer that receives the file's path name.
//
// lpszDescription - the buffer that receives the file's
// description.
HRESULT
GetLinkInfo( HWND    hWnd,
			LPCTSTR lpszLinkName,
			LPTSTR   lpszPath,
			LPTSTR   lpszDir,
			LPTSTR   lpszArgs,
			int ccArgs)
{

	HRESULT hres;
	IShellLink *pShLink;
	WIN32_FIND_DATA wfd;

	// Initialize the return parameters to null strings.
	*lpszPath = '\0';
	//*lpszDescription = '\0';

	// Call CoCreateInstance to obtain the IShellLink
	// Interface pointer. This call fails if
	// CoInitialize is not called, so it is assumed that
	// CoInitialize has been called.
	hres = CoCreateInstance( CLSID_ShellLink,
		NULL,
		CLSCTX_INPROC_SERVER,
		IID_IShellLink,
		(LPVOID *)&pShLink );

	if (SUCCEEDED(hres))
	{
		IPersistFile *ppf;

		// The IShellLink Interface supports the IPersistFile
		// interface. Get an interface pointer to it.
		hres = pShLink->QueryInterface(IID_IPersistFile,
			(LPVOID *)&ppf );
		if (SUCCEEDED(hres))
		{
#ifdef _UNICODE
			// Load the file.
			hres = ppf->Load(lpszLinkName, STGM_READ);
#else
			WCHAR wsz[MAX_PATH];

			// Convert the given link name string to a wide character string.
			MultiByteToWideChar(CP_ACP, 0,
				lpszLinkName,
				-1, wsz, MAX_PATH);
			// Load the file.
			hres = ppf->Load(wsz, STGM_READ);
#endif
			if (SUCCEEDED(hres))
			{
				// Resolve the link by calling the Resolve() interface function.
				// This enables us to find the file the link points to even if
				// it has been moved or renamed.
				hres = pShLink->Resolve(hWnd,
					SLR_ANY_MATCH | SLR_NO_UI);
				if (SUCCEEDED(hres))
				{
					// Get the path of the file the link points to.
					hres = pShLink->GetPath( lpszPath,
						MAX_PATH,
						&wfd,
						0 );

					if (lpszDir)
					{
						pShLink->GetWorkingDirectory(lpszDir, MAX_PATH);
					}

					if (lpszArgs)
					{
						pShLink->GetArguments(lpszArgs, ccArgs);
					}

					// Only get the description if we successfully got the path
					// (We can't return immediately because we need to release ppf &
					//  pShLink.)
// 					if(SUCCEEDED(hres))
// 					{
// 						// Get the description of the link.
// 						hres = pShLink->GetDescription(lpszDescription,
// 							MAX_PATH );
// 					}
				}
			}
			ppf->Release();
		}
		pShLink->Release();
	}
	return hres;
}

BOOL IsLnk(LPCTSTR pFileName)
{
	int nLen = _tcslen(pFileName);

	if (nLen > 3)
	{
		if (_tcsicmp(_T(".lnk"), &pFileName[nLen-4]) == 0)
		{
			return TRUE;
		}
	}

	return FALSE;
}


int GetAppFolderPath(TCHAR *pAppPath, TCHAR *pDirBuf)
{
	TCHAR szAppPath[MAX_PATH];
	TCHAR *pLastSlash = NULL;

	if (!PathCanonicalize(szAppPath, pAppPath))
		return 0;

	pLastSlash = _tcsrchr(szAppPath, '\\');
	if (!pLastSlash)
		return 0;

	*pLastSlash = '\0';

	return _stprintf(pDirBuf, szAppPath);
}


void CPage3::OnDropAppFile(TCHAR *pFileName)
{
	std::vector<CString> noExtraArguments;
	LaunchAndProxyApp(pFileName, noExtraArguments, FALSE);
}

AppLaunchResult CPage3::LaunchAndProxyApp(
	LPCTSTR fileName,
	const std::vector<CString>& extraArguments,
	BOOL strictInjection)
{
	if (!fileName || !fileName[0])
		return APP_LAUNCH_INVALID_TARGET;

	STARTUPINFO si = {0};
	si.cb = sizeof(si);

	PROCESS_INFORMATION pi = {0};
	int ret;

	HookNewProcessInfo hnpi = {0};
	TCHAR szTargetPath[MAX_PATH+1024];
	TCHAR szArgs[1024];
	TCHAR szBaseDir[MAX_PATH] = _T("\0");
	PVOID WowRedirOldValue = NULL;

	ZeroMemory(szTargetPath, sizeof(szTargetPath));
	ZeroMemory(szArgs, sizeof(szArgs));

	myWow64DisableWow64FsRedirection(&WowRedirOldValue);

	if (IsLnk(fileName))
	{
		TCHAR szTmp[MAX_PATH] = _T("\0");
		if (FAILED(GetLinkInfo(
			*this,
			fileName,
			szTargetPath,
			szTmp,
			szArgs,
			_countof(szArgs))))
		{
			myWow64RevertWow64FsRedirection(WowRedirOldValue);
			return APP_LAUNCH_INVALID_TARGET;
		}
		ExpandEnvironmentStrings(szTmp, szBaseDir, MAX_PATH);
	}else
	{
		_tcsncpy(szTargetPath, fileName, _countof(szTargetPath) - 1);
		GetAppFolderPath(szTargetPath, szBaseDir);
	}

	DWORD targetAttributes = GetFileAttributes(szTargetPath);
	if (!szTargetPath[0] ||
		targetAttributes == INVALID_FILE_ATTRIBUTES ||
		(targetAttributes & FILE_ATTRIBUTE_DIRECTORY))
	{
		myWow64RevertWow64FsRedirection(WowRedirOldValue);
		return APP_LAUNCH_INVALID_TARGET;
	}

	if (!szBaseDir[0])
		GetAppFolderPath(szTargetPath, szBaseDir);

	CString commandLine = QuoteCommandLineArgument(szTargetPath);
	if (szArgs[0])
	{
		commandLine += _T(" ");
		commandLine += szArgs;
	}
	for (size_t i = 0; i < extraArguments.size(); ++i)
	{
		commandLine += _T(" ");
		commandLine += QuoteCommandLineArgument(extraArguments[i]);
	}

	LPTSTR mutableCommandLine = commandLine.GetBuffer();
	ret = CreateProcess(
		szTargetPath,
		mutableCommandLine,
		0,
		0,
		0,
		CREATE_SUSPENDED,
		0,
		szBaseDir[0] == 0 ? NULL : szBaseDir,
		&si,
		&pi);
	commandLine.ReleaseBuffer();

	myWow64RevertWow64FsRedirection(WowRedirOldValue);

	if (!ret)
	{
		return APP_LAUNCH_CREATE_PROCESS_FAILED;
	}

	hnpi.dwProcessId = pi.dwProcessId;
	hnpi.dwThreadId = pi.dwThreadId;

#ifdef UNICODE
	wcsncpy(hnpi.szCommandLine, commandLine, MAX_PATH - 1);
#else
#error unicode required
#endif
	ResolveChildAppPath(pi.hProcess, hnpi.szAppPath, MAX_PATH);

	BOOL injectionSucceeded = InjectNewProcess(&hnpi);
	if (!injectionSucceeded && strictInjection)
	{
		TerminateProcess(pi.hProcess, AUTOMATION_EXIT_INJECTION_FAILED);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return APP_LAUNCH_INJECTION_FAILED;
	}

	if (ResumeThread(pi.hThread) == (DWORD)-1)
	{
		TerminateProcess(pi.hProcess, AUTOMATION_EXIT_CREATE_PROCESS_FAILED);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return APP_LAUNCH_CREATE_PROCESS_FAILED;
	}

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	return APP_LAUNCH_SUCCESS;
}


