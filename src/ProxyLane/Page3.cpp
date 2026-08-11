// Page3.cpp : 实现文件
//

#include "stdafx.h"
#include "ProxyLane.h"
#include "Page3.h"
#include "MainTab.h"
#include "Page2.h"
#include "AutomationOptions.h"
#include "Localization.h"
#include "..\ProxyLaneHook\token.h"
#include "..\ProxyLaneHook\ElevatedLaunchProtocol.h"

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
#include <shellapi.h>

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
extern CCriticalSection g_childFilterLock;


using namespace ATL;

BEGIN_MESSAGE_MAP(CWindowFinderOverlay, CWnd)
	ON_WM_PAINT()
	ON_WM_ERASEBKGND()
	ON_WM_NCHITTEST()
END_MESSAGE_MAP()

CWindowFinderOverlay::CWindowFinderOverlay()
	: m_transparentColor(RGB(255, 0, 255))
{
}

BOOL CWindowFinderOverlay::ShowForWindow(HWND targetWindow, CWnd* ownerWindow)
{
	if (!targetWindow || !::IsWindow(targetWindow))
		return FALSE;

	CRect targetRect;
	if (!::GetWindowRect(targetWindow, &targetRect) || targetRect.IsRectEmpty())
		return FALSE;

	if (!GetSafeHwnd())
	{
		CString className = AfxRegisterWndClass(
			CS_HREDRAW | CS_VREDRAW,
			::LoadCursor(NULL, IDC_ARROW),
			NULL,
			NULL);
		CWnd* topLevelOwner = ownerWindow
			? ownerWindow->GetTopLevelParent()
			: NULL;
		CRect emptyRect(0, 0, 0, 0);
		if (!CreateEx(
			WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW |
				WS_EX_NOACTIVATE | WS_EX_TOPMOST,
			className,
			_T(""),
			WS_POPUP,
			emptyRect,
			topLevelOwner,
			0))
		{
			return FALSE;
		}
		::SetLayeredWindowAttributes(
			m_hWnd,
			m_transparentColor,
			255,
			LWA_COLORKEY);
		// WindowFromPoint 会忽略禁用窗口，确保覆盖层不会成为查找目标。
		EnableWindow(FALSE);
	}

	SetWindowPos(
		&wndTopMost,
		targetRect.left,
		targetRect.top,
		targetRect.Width(),
		targetRect.Height(),
		SWP_NOACTIVATE | SWP_SHOWWINDOW);
	Invalidate(FALSE);
	UpdateWindow();
	return TRUE;
}

void CWindowFinderOverlay::HideOverlay()
{
	if (GetSafeHwnd())
		ShowWindow(SW_HIDE);
}

void CWindowFinderOverlay::OnPaint()
{
	CPaintDC dc(this);
	CRect clientRect;
	GetClientRect(&clientRect);
	dc.FillSolidRect(clientRect, m_transparentColor);

	CBrush borderBrush(UiTheme::Accent());
	const int thickness = UiTheme::ScaleForWindow(m_hWnd, 3);
	CRect borderRect(clientRect);
	for (int index = 0; index < thickness && !borderRect.IsRectEmpty(); ++index)
	{
		dc.FrameRect(borderRect, &borderBrush);
		borderRect.DeflateRect(1, 1);
	}
}

BOOL CWindowFinderOverlay::OnEraseBkgnd(CDC*)
{
	return TRUE;
}

LRESULT CWindowFinderOverlay::OnNcHitTest(CPoint)
{
	return HTTRANSPARENT;
}

IMPLEMENT_DYNAMIC(CWindowFinderButton, CModernButton)

CWindowFinderButton::CWindowFinderButton()
	: m_tracking(FALSE)
{
}

BOOL CWindowFinderButton::IsTracking() const
{
	return m_tracking;
}

BEGIN_MESSAGE_MAP(CWindowFinderButton, CModernButton)
	ON_WM_LBUTTONDOWN()
	ON_WM_LBUTTONUP()
	ON_WM_MOUSEMOVE()
	ON_WM_CAPTURECHANGED()
	ON_WM_KEYDOWN()
	ON_WM_SETCURSOR()
END_MESSAGE_MAP()

void CWindowFinderButton::DrawItem(LPDRAWITEMSTRUCT info)
{
	CModernButton::DrawItem(info);

	CDC dc;
	dc.Attach(info->hDC);
	CRect rect(info->rcItem);
	const int centerX = rect.CenterPoint().x;
	const int centerY = rect.CenterPoint().y;
	const int radius = UiTheme::ScaleForWindow(m_hWnd, 5);
	const int arm = UiTheme::ScaleForWindow(m_hWnd, 9);
	COLORREF color = IsWindowEnabled()
		? (m_tracking || m_hot ? UiTheme::Accent() : UiTheme::TextPrimary())
		: RGB(160, 166, 177);
	CPen pen(PS_SOLID, UiTheme::ScaleForWindow(m_hWnd, 1), color);
	CPen* oldPen = dc.SelectObject(&pen);
	CBrush* oldBrush = static_cast<CBrush*>(dc.SelectStockObject(NULL_BRUSH));
	dc.Ellipse(centerX - radius, centerY - radius,
		centerX + radius + 1, centerY + radius + 1);
	dc.MoveTo(centerX - arm, centerY);
	dc.LineTo(centerX + arm + 1, centerY);
	dc.MoveTo(centerX, centerY - arm);
	dc.LineTo(centerX, centerY + arm + 1);
	dc.SelectObject(oldBrush);
	dc.SelectObject(oldPen);
	dc.Detach();
}

void CWindowFinderButton::OnLButtonDown(UINT, CPoint)
{
	if (!IsWindowEnabled() || m_tracking)
		return;

	SetFocus();
	m_tracking = TRUE;
	SetCapture();
	::SetCursor(::LoadCursor(NULL, IDC_CROSS));
	Invalidate(FALSE);
	if (GetParent())
		GetParent()->SendMessage(WM_WINDOW_FINDER_BEGIN);
}

void CWindowFinderButton::OnMouseMove(UINT flags, CPoint point)
{
	if (!m_tracking)
	{
		CModernButton::OnMouseMove(flags, point);
		return;
	}

	POINT cursorPoint = { 0 };
	::GetCursorPos(&cursorPoint);
	HWND targetWindow = ::WindowFromPoint(cursorPoint);
	::SetCursor(::LoadCursor(NULL, IDC_CROSS));
	if (GetParent())
		GetParent()->SendMessage(
			WM_WINDOW_FINDER_UPDATE,
			0,
			reinterpret_cast<LPARAM>(targetWindow));
}

void CWindowFinderButton::OnLButtonUp(UINT, CPoint)
{
	if (!m_tracking)
		return;

	POINT cursorPoint = { 0 };
	::GetCursorPos(&cursorPoint);
	HWND targetWindow = ::WindowFromPoint(cursorPoint);
	m_tracking = FALSE;
	if (GetCapture() == this)
		ReleaseCapture();
	Invalidate(FALSE);
	if (GetParent())
		GetParent()->SendMessage(
			WM_WINDOW_FINDER_COMPLETE,
			0,
			reinterpret_cast<LPARAM>(targetWindow));
}

void CWindowFinderButton::CancelTracking()
{
	if (!m_tracking)
		return;
	m_tracking = FALSE;
	if (GetCapture() == this)
		ReleaseCapture();
	Invalidate(FALSE);
	if (GetParent())
		GetParent()->SendMessage(WM_WINDOW_FINDER_CANCEL);
}

void CWindowFinderButton::OnCaptureChanged(CWnd* window)
{
	if (m_tracking)
	{
		m_tracking = FALSE;
		Invalidate(FALSE);
		if (GetParent())
			GetParent()->SendMessage(WM_WINDOW_FINDER_CANCEL);
	}
	CModernButton::OnCaptureChanged(window);
}

void CWindowFinderButton::OnKeyDown(UINT character, UINT repeatCount, UINT flags)
{
	if (character == VK_ESCAPE && m_tracking)
	{
		CancelTracking();
		return;
	}
	CModernButton::OnKeyDown(character, repeatCount, flags);
}

BOOL CWindowFinderButton::OnSetCursor(CWnd* window, UINT hitTest, UINT message)
{
	if (m_tracking)
	{
		::SetCursor(::LoadCursor(NULL, IDC_CROSS));
		return TRUE;
	}
	return CModernButton::OnSetCursor(window, hitTest, message);
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
	if (!hProc || !buf || size == 0)
		return FALSE;
	buf[0] = _T('\0');

	typedef
	BOOL WINAPI __QueryFullProcessImageName(
		HANDLE hProcess,
		DWORD dwFlags,
		LPTSTR lpExeName,
		PDWORD lpdwSize
		);

	static __QueryFullProcessImageName * QFIN = (__QueryFullProcessImageName*)-1;
	if (QFIN == (__QueryFullProcessImageName*)-1)
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
		DWORD pathSize = size;
		if (QFIN(hProc, 0, buf, &pathSize) && buf[0])
			return TRUE;
		buf[0] = _T('\0');
	}

	// XP 兼容回退；hModule 为 NULL 时直接查询目标进程的主程序路径。
	if (GetModuleFileNameEx(hProc, NULL, buf, size) > 0)
	{
		buf[size - 1] = _T('\0');
		return buf[0] != _T('\0');
	}
	buf[0] = _T('\0');
	return FALSE;
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
			if (!hProcess)
			{
				// Vista+ 的路径 API 以及启动时间只需要进程查询权限。
				hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
			}
			if (hProcess)
			{
				// 新系统优先 QueryFullProcessImageName；XP 自动回退到 PSAPI。
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

CString GetProxyLaneHookModule32Path()
{
	TCHAR modulePath[MAX_PATH] = { 0 };
	if (!GetModuleFileName(NULL, modulePath, _countof(modulePath)))
		return CString();
	modulePath[_countof(modulePath) - 1] = _T('\0');
	CString directory(modulePath);
	const int slash = directory.ReverseFind(_T('\\'));
	if (slash < 0)
		return CString();
	return directory.Left(slash) + _T("\\ProxyLaneHook32.dll");
}

CString GetProxyLaneHookModule64Path()
{
	TCHAR modulePath[MAX_PATH] = { 0 };
	if (!GetModuleFileName(NULL, modulePath, _countof(modulePath)))
		return CString();
	modulePath[_countof(modulePath) - 1] = _T('\0');
	CString directory(modulePath);
	const int slash = directory.ReverseFind(_T('\\'));
	if (slash < 0)
		return CString();
	return directory.Left(slash) + _T("\\ProxyLaneHook64.dll");
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
	return GetProcessFullPath(hChildProc, szOut, cchOut);
}


// CPage3 对话框

IMPLEMENT_DYNAMIC(CPage3, CModernDialog)

CPage3::CPage3(CWnd* pParent /*=NULL*/)
	: CModernDialog(CPage3::IDD, pParent)
	, m_evlock()
	, m_sortColumn(-1)
	, m_sortState(PROCESS_SORT_NONE)
	, m_processNameSearchTick(0)
	, m_finderTargetWindow(NULL)
{
	//m_pEdit = NULL;
	//m_pEdit = new CMyEdit;
	m_evlock.SetEvent();

}

CPage3::~CPage3()
{
	ClearWindowFinderHighlight();
}

void CPage3::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_PSLIST, m_ListCtrl);
	DDX_Control(pDX, IDC_WINDOW_FINDER, m_btnWindowFinder);
	DDX_Control(pDX, IDC_REFRESH, m_btnRefresh);
	DDX_Control(pDX, IDC_INJECTDLL, m_btnInject);

	//DDX_Control(pDX, IDC_CHECK1, m_btnAuto);
}

BOOL CPage3::OnInitDialog()
{
	CModernDialog::OnInitDialog();
	DragAcceptFiles(FALSE);
	m_ListCtrl.DragAcceptFiles(FALSE);
	m_btnWindowFinder.SetVisualStyle(CModernButton::STYLE_SECONDARY);
	m_btnRefresh.SetVisualStyle(CModernButton::STYLE_SECONDARY);
	m_btnInject.SetVisualStyle(CModernButton::STYLE_PRIMARY);
	RestoreProcessPageSubtitle();
	if (m_windowFinderToolTip.Create(this, TTS_ALWAYSTIP | TTS_NOPREFIX))
	{
		m_windowFinderToolTip.AddTool(
			&m_btnWindowFinder,
			Localization::Get(_T("page3.finder_tip")));
		m_windowFinderToolTip.SetMaxTipWidth(UiTheme::ScaleForWindow(m_hWnd, 320));
	}
	// 资源模板为兼容旧版本仍可能带有单选样式，初始化时统一启用多选。
	m_ListCtrl.ModifyStyle(LVS_SINGLESEL, 0);

	m_ListCtrl.InsertColumn(0, _T("PID"), 0, 50);
	m_ListCtrl.InsertColumn(1, Localization::Get(_T("page3.column_process")), 0, 180);
	m_ListCtrl.InsertColumn(2, Localization::Get(_T("page3.column_started")), 0, 150);
	m_ListCtrl.InsertColumn(3, Localization::Get(_T("page3.column_path")), 0, 200);

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

static AppLaunchResult LaunchElevatedAndProxy(
	HWND ownerWindow,
	LPCTSTR targetPath,
	LPCTSTR commandLine,
	LPCTSTR workingDirectory)
{
	if (!targetPath || !commandLine ||
		_tcslen(targetPath) >= PROXYLANE_ELEVATED_TARGET_CCH ||
		_tcslen(commandLine) >= PROXYLANE_ELEVATED_COMMAND_CCH ||
		(workingDirectory &&
		 _tcslen(workingDirectory) >= PROXYLANE_ELEVATED_DIRECTORY_CCH))
	{
		return APP_LAUNCH_INVALID_TARGET;
	}

	IProxyReceptionCentre* receptionCentre = NULL;
	char pipeName[PROXYLANE_ELEVATED_PIPE_CCH] = { 0 };
	if (!g_GlobalProxy ||
		!(receptionCentre = g_GlobalProxy->GetPRCInstance()) ||
		!receptionCentre->GetPRCPipeName(pipeName, _countof(pipeName)))
	{
		return APP_LAUNCH_ELEVATED_HELPER_FAILED;
	}

	const WCHAR* wideFields[] =
	{
		targetPath,
		commandLine,
		workingDirectory ? workingDirectory : L""
	};
	std::vector<BYTE> utf8Fields[_countof(wideFields)];
	for (size_t index = 0; index < _countof(wideFields); ++index)
	{
		const int wideLength = static_cast<int>(wcslen(wideFields[index]));
		if (!wideLength)
			continue;
		const int utf8Length = WideCharToMultiByte(
			CP_UTF8,
			WC_ERR_INVALID_CHARS,
			wideFields[index],
			wideLength,
			NULL,
			0,
			NULL,
			NULL);
		if (utf8Length <= 0)
			return APP_LAUNCH_ELEVATED_HELPER_FAILED;
		utf8Fields[index].resize(utf8Length);
		if (WideCharToMultiByte(
			CP_UTF8,
			WC_ERR_INVALID_CHARS,
			wideFields[index],
			wideLength,
			reinterpret_cast<char*>(&utf8Fields[index][0]),
			utf8Length,
			NULL,
			NULL) != utf8Length)
		{
			return APP_LAUNCH_ELEVATED_HELPER_FAILED;
		}
	}

	const size_t pipeNameLength = strlen(pipeName);
	const size_t wireSize = sizeof(ProxyLaneElevatedLaunchWireHeader) +
		utf8Fields[0].size() + utf8Fields[1].size() + utf8Fields[2].size() +
		pipeNameLength;
	if (wireSize > PROXYLANE_ELEVATED_MAX_WIRE_BYTES || wireSize > MAXDWORD)
		return APP_LAUNCH_ELEVATED_HELPER_FAILED;

	ProxyLaneElevatedLaunchWireHeader header = { 0 };
	header.magic = PROXYLANE_ELEVATED_REQUEST_MAGIC;
	header.version = PROXYLANE_ELEVATED_REQUEST_VERSION;
	header.headerSize = sizeof(header);
	header.totalSize = static_cast<DWORD>(wireSize);
	header.targetPathBytes = static_cast<DWORD>(utf8Fields[0].size());
	header.commandLineBytes = static_cast<DWORD>(utf8Fields[1].size());
	header.workingDirectoryBytes = static_cast<DWORD>(utf8Fields[2].size());
	header.pipeNameBytes = static_cast<DWORD>(pipeNameLength);

	std::vector<BYTE> wireRequest(wireSize);
	size_t wireOffset = 0;
	memcpy(&wireRequest[wireOffset], &header, sizeof(header));
	wireOffset += sizeof(header);
	for (size_t index = 0; index < _countof(utf8Fields); ++index)
	{
		if (!utf8Fields[index].empty())
		{
			memcpy(&wireRequest[wireOffset], &utf8Fields[index][0], utf8Fields[index].size());
			wireOffset += utf8Fields[index].size();
		}
	}
	memcpy(&wireRequest[wireOffset], pipeName, pipeNameLength);

	const size_t encodedLength = ProxyLaneBase64UrlEncodedLength(wireRequest.size());
	CStringA encodedRequest;
	char* encodedBuffer = encodedRequest.GetBuffer(static_cast<int>(encodedLength));
	size_t actualEncodedLength = 0;
	if (!ProxyLaneBase64UrlEncode(
		&wireRequest[0],
		wireRequest.size(),
		encodedBuffer,
		encodedLength + 1,
		&actualEncodedLength) || actualEncodedLength != encodedLength)
	{
		encodedRequest.ReleaseBuffer(0);
		return APP_LAUNCH_ELEVATED_HELPER_FAILED;
	}
	encodedRequest.ReleaseBuffer(static_cast<int>(actualEncodedLength));

#ifdef _WIN64
	CString hookPath = GetProxyLaneHookModule64Path();
#else
	CString hookPath = GetProxyLaneHookModule32Path();
#endif
	if (hookPath.Find(_T(',')) >= 0)
		return APP_LAUNCH_ELEVATED_HELPER_FAILED;
	const DWORD hookAttributes = GetFileAttributes(hookPath);
	if (hookAttributes == INVALID_FILE_ATTRIBUTES ||
		(hookAttributes & FILE_ATTRIBUTE_DIRECTORY))
	{
		return APP_LAUNCH_ELEVATED_HELPER_FAILED;
	}

	CString rundllPath = ChooseRundll32(hookPath);
	CString encodedRequestWide;
	WCHAR* encodedWideBuffer = encodedRequestWide.GetBuffer(encodedRequest.GetLength());
	const int convertedLength = MultiByteToWideChar(
		CP_ACP,
		0,
		encodedRequest,
		encodedRequest.GetLength(),
		encodedWideBuffer,
		encodedRequest.GetLength());
	encodedRequestWide.ReleaseBuffer(convertedLength > 0 ? convertedLength : 0);
	if (convertedLength <= 0)
		return APP_LAUNCH_ELEVATED_HELPER_FAILED;

	CString parameters;
	parameters.Format(
		_T("\"%s\",ElevatedLaunch --request=%s"),
		(LPCTSTR)hookPath,
		(LPCTSTR)encodedRequestWide);

	SHELLEXECUTEINFO shellInfo = { 0 };
	shellInfo.cbSize = sizeof(shellInfo);
	shellInfo.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
	shellInfo.hwnd = ownerWindow;
	shellInfo.lpVerb = _T("runas");
	shellInfo.lpFile = rundllPath;
	shellInfo.lpParameters = parameters;
	shellInfo.nShow = SW_HIDE;

	if (!ShellExecuteEx(&shellInfo))
	{
		return GetLastError() == ERROR_CANCELLED
			? APP_LAUNCH_UAC_CANCELLED
			: APP_LAUNCH_ELEVATED_HELPER_FAILED;
	}
	if (!shellInfo.hProcess)
		return APP_LAUNCH_ELEVATED_HELPER_FAILED;

	const DWORD waitResult = WaitForSingleObject(shellInfo.hProcess, INFINITE);
	DWORD helperExitCode = PROXYLANE_ELEVATED_INTERNAL_ERROR;
	const BOOL gotExitCode = waitResult == WAIT_OBJECT_0 &&
		GetExitCodeProcess(shellInfo.hProcess, &helperExitCode);
	CloseHandle(shellInfo.hProcess);
	if (!gotExitCode)
		return APP_LAUNCH_ELEVATED_HELPER_FAILED;

	if (helperExitCode == PROXYLANE_ELEVATED_SUCCESS)
		return APP_LAUNCH_SUCCESS;
	if (helperExitCode == PROXYLANE_ELEVATED_INVALID_TARGET)
		return APP_LAUNCH_INVALID_TARGET;
	if (helperExitCode == PROXYLANE_ELEVATED_INJECTION_FAILED)
		return APP_LAUNCH_INJECTION_FAILED;
	if (helperExitCode == PROXYLANE_ELEVATED_CREATE_FAILED)
		return APP_LAUNCH_CREATE_PROCESS_FAILED;
	return APP_LAUNCH_ELEVATED_HELPER_FAILED;
}

BOOL CPage3::PreTranslateMessage(MSG* message)
{
	if (message && m_windowFinderToolTip.GetSafeHwnd())
		m_windowFinderToolTip.RelayEvent(message);

	if (message && m_btnWindowFinder.IsTracking() &&
		(message->message == WM_KEYDOWN || message->message == WM_SYSKEYDOWN) &&
		message->wParam == VK_ESCAPE)
	{
		m_btnWindowFinder.CancelTracking();
		return TRUE;
	}

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
	ON_MESSAGE(WM_WINDOW_FINDER_BEGIN, &CPage3::OnWindowFinderBegin)
	ON_MESSAGE(WM_WINDOW_FINDER_UPDATE, &CPage3::OnWindowFinderUpdate)
	ON_MESSAGE(WM_WINDOW_FINDER_COMPLETE, &CPage3::OnWindowFinderComplete)
	ON_MESSAGE(WM_WINDOW_FINDER_CANCEL, &CPage3::OnWindowFinderCancel)
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
	int finderWidth = UiTheme::ScaleForWindow(m_hWnd, 30);
	int refreshWidth = UiTheme::ScaleForWindow(m_hWnd, 70);
	int injectWidth = UiTheme::ScaleForWindow(m_hWnd, 96);
	int buttonHeight = UiTheme::ScaleForWindow(m_hWnd, 30);
	int buttonTop = UiTheme::ScaleForWindow(m_hWnd, 8);
	const int toolbarLeft = rcClient.right - margin - injectWidth - gap
		- refreshWidth - gap - finderWidth;
	if (CWnd* title = GetDlgItem(IDC_STATIC_PAGE_TITLE))
	{
		CRect titleRect;
		title->GetWindowRect(&titleRect);
		ScreenToClient(&titleRect);
		title->MoveWindow(titleRect.left, titleRect.top,
			max(0, toolbarLeft - gap - titleRect.left), titleRect.Height());
	}
	if (m_btnInject.GetSafeHwnd())
		m_btnInject.MoveWindow(rcClient.right - margin - injectWidth, buttonTop, injectWidth, buttonHeight);
	if (m_btnRefresh.GetSafeHwnd())
		m_btnRefresh.MoveWindow(rcClient.right - margin - injectWidth - gap - refreshWidth,
			buttonTop, refreshWidth, buttonHeight);
	if (m_btnWindowFinder.GetSafeHwnd())
		m_btnWindowFinder.MoveWindow(
			rcClient.right - margin - injectWidth - gap - refreshWidth - gap - finderWidth,
			buttonTop,
			finderWidth,
			buttonHeight);
}

static BOOL ResolveWindowFinderTarget(
	HWND targetWindow,
	DWORD& processId,
	HWND& highlightWindow)
{
	processId = 0;
	highlightWindow = NULL;
	if (!targetWindow || !::IsWindow(targetWindow))
		return FALSE;

	::GetWindowThreadProcessId(targetWindow, &processId);
	if (processId <= 4 || processId == ::GetCurrentProcessId())
		return FALSE;

	highlightWindow = ::GetAncestor(targetWindow, GA_ROOT);
	if (!highlightWindow)
		highlightWindow = targetWindow;
	if (highlightWindow == ::GetDesktopWindow() ||
		highlightWindow == ::GetShellWindow())
	{
		return FALSE;
	}

	TCHAR className[64] = { 0 };
	::GetClassName(highlightWindow, className, _countof(className));
	if (_tcsicmp(className, _T("Shell_TrayWnd")) == 0 ||
		_tcsicmp(className, _T("Progman")) == 0 ||
		_tcsicmp(className, _T("WorkerW")) == 0)
	{
		return FALSE;
	}
	return TRUE;
}

void CPage3::ClearWindowFinderHighlight()
{
	m_finderOverlay.HideOverlay();
	m_finderTargetWindow = NULL;
}

void CPage3::UpdateWindowFinderHighlight(HWND targetWindow)
{
	DWORD processId = 0;
	HWND highlightWindow = NULL;
	if (!ResolveWindowFinderTarget(targetWindow, processId, highlightWindow))
	{
		ClearWindowFinderHighlight();
		return;
	}

	m_finderTargetWindow = targetWindow;
	if (!m_finderOverlay.ShowForWindow(highlightWindow, this))
		ClearWindowFinderHighlight();
}

BOOL CPage3::SelectProcessByPid(DWORD processId)
{
	std::vector<DWORD> processIds;
	if (processId)
		processIds.push_back(processId);
	return SelectProcessesByPid(processIds);
}

BOOL CPage3::SelectProcessesByPid(const std::vector<DWORD>& processIds)
{
	if (processIds.empty() || !m_ListCtrl.GetSafeHwnd())
		return FALSE;

	std::set<DWORD> targetIds(processIds.begin(), processIds.end());
	m_ListCtrl.SetItemState(-1, 0, LVIS_SELECTED | LVIS_FOCUSED);
	int firstSelectedItem = -1;
	int selectedCount = 0;
	const int itemCount = m_ListCtrl.GetItemCount();
	for (int item = 0; item < itemCount; ++item)
	{
		DWORD itemProcessId = static_cast<DWORD>(m_ListCtrl.GetItemData(item));
		if (targetIds.find(itemProcessId) == targetIds.end())
			continue;
		m_ListCtrl.SetItemState(
			item,
			LVIS_SELECTED | (firstSelectedItem < 0 ? LVIS_FOCUSED : 0),
			LVIS_SELECTED | LVIS_FOCUSED);
		if (firstSelectedItem < 0)
			firstSelectedItem = item;
		++selectedCount;
	}
	if (firstSelectedItem >= 0)
	{
		m_ListCtrl.SetSelectionMark(firstSelectedItem);
		m_ListCtrl.EnsureVisible(firstSelectedItem, FALSE);
		m_ListCtrl.SetFocus();
	}
	return selectedCount > 0;
}

void CPage3::CollectDescendantProcessIds(
	DWORD rootProcessId,
	std::vector<DWORD>& descendants) const
{
	descendants.clear();
	if (!rootProcessId ||
		m_processSortData.find(rootProcessId) == m_processSortData.end())
	{
		return;
	}

	std::map<DWORD, std::vector<DWORD> > children;
	for (std::map<DWORD, _myPROCESSINFO>::const_iterator process =
		m_processSortData.begin(); process != m_processSortData.end(); ++process)
	{
		const _myPROCESSINFO& child = process->second;
		std::map<DWORD, _myPROCESSINFO>::const_iterator parent =
			m_processSortData.find(child.parentPid);
		BOOL validParent = child.parentPid != 0
			&& child.parentPid != child.pid
			&& parent != m_processSortData.end();
		if (validParent && parent->second.hasStartTime && child.hasStartTime &&
			parent->second.startTimeValue > child.startTimeValue)
		{
			validParent = FALSE;
		}
		if (validParent)
			children[child.parentPid].push_back(child.pid);
	}

	std::set<DWORD> visited;
	visited.insert(rootProcessId);
	std::vector<DWORD> pending;
	pending.push_back(rootProcessId);
	for (size_t pendingIndex = 0; pendingIndex < pending.size(); ++pendingIndex)
	{
		std::map<DWORD, std::vector<DWORD> >::const_iterator childList =
			children.find(pending[pendingIndex]);
		if (childList == children.end())
			continue;
		for (size_t childIndex = 0;
			childIndex < childList->second.size(); ++childIndex)
		{
			DWORD childProcessId = childList->second[childIndex];
			if (!visited.insert(childProcessId).second)
				continue;
			descendants.push_back(childProcessId);
			pending.push_back(childProcessId);
		}
	}

	std::sort(
		descendants.begin(),
		descendants.end(),
		[this](DWORD leftProcessId, DWORD rightProcessId)
		{
			std::map<DWORD, _myPROCESSINFO>::const_iterator left =
				m_processSortData.find(leftProcessId);
			std::map<DWORD, _myPROCESSINFO>::const_iterator right =
				m_processSortData.find(rightProcessId);
			if (left != m_processSortData.end() && right != m_processSortData.end() &&
				left->second.treeOrder != right->second.treeOrder)
			{
				return left->second.treeOrder < right->second.treeOrder;
			}
			return leftProcessId < rightProcessId;
		});
}

void CPage3::RestoreProcessPageSubtitle()
{
	SetDlgItemText(
		IDC_STATIC_PAGE_SUBTITLE,
		Localization::Get(_T("page3.list_tip")));
}

LRESULT CPage3::OnWindowFinderBegin(WPARAM, LPARAM)
{
	KillTimer(TIMER_PSLIST);
	ClearWindowFinderHighlight();
	if (m_windowFinderToolTip.GetSafeHwnd())
		m_windowFinderToolTip.Pop();
	SetDlgItemText(
		IDC_STATIC_PAGE_SUBTITLE,
		Localization::Get(_T("page3.finder_active_tip")));
	return 0;
}

LRESULT CPage3::OnWindowFinderUpdate(WPARAM, LPARAM parameter)
{
	UpdateWindowFinderHighlight(reinterpret_cast<HWND>(parameter));
	return 0;
}

LRESULT CPage3::OnWindowFinderComplete(WPARAM, LPARAM parameter)
{
	HWND targetWindow = reinterpret_cast<HWND>(parameter);
	ClearWindowFinderHighlight();
	RestoreProcessPageSubtitle();
	SetTimer(TIMER_PSLIST, 2000, NULL);

	DWORD processId = 0;
	HWND highlightWindow = NULL;
	if (!ResolveWindowFinderTarget(targetWindow, processId, highlightWindow))
	{
		MessageBox(
			Localization::Get(_T("page3.no_window")),
			Localization::Get(_T("page3.no_target_title")),
			MB_ICONINFORMATION);
		return 0;
	}

	UpdatePslist(TRUE);
	if (!SelectProcessByPid(processId))
	{
		MessageBox(
			Localization::Get(_T("page3.target_exited")),
			Localization::Get(_T("page3.target_unavailable")),
			MB_ICONWARNING);
		return 0;
	}

	std::vector<DWORD> descendantProcessIds;
	CollectDescendantProcessIds(processId, descendantProcessIds);
	if (!descendantProcessIds.empty())
	{
		CString targetName = Localization::Get(_T("page3.unknown_process"));
		std::map<DWORD, _myPROCESSINFO>::const_iterator targetProcess =
			m_processSortData.find(processId);
		if (targetProcess != m_processSortData.end() &&
			targetProcess->second.proname[0])
		{
			targetName = targetProcess->second.proname;
		}

		CString confirmationText;
		confirmationText = Localization::Format(
			_T("page3.children_header"),
			(LPCTSTR)targetName,
			processId,
			static_cast<unsigned int>(descendantProcessIds.size()));
		const size_t maxDisplayedChildren = 5;
		for (size_t index = 0;
			index < descendantProcessIds.size() && index < maxDisplayedChildren;
			++index)
		{
			DWORD childProcessId = descendantProcessIds[index];
			CString childName = Localization::Get(_T("page3.unknown_process"));
			std::map<DWORD, _myPROCESSINFO>::const_iterator childProcess =
				m_processSortData.find(childProcessId);
			if (childProcess != m_processSortData.end() &&
				childProcess->second.proname[0])
			{
				childName = childProcess->second.proname;
			}
			CString childLine;
			childLine = Localization::Format(
				_T("page3.child_line"),
				static_cast<unsigned int>(index + 1),
				(LPCTSTR)childName,
				childProcessId);
			confirmationText += childLine;
		}
		if (descendantProcessIds.size() > maxDisplayedChildren)
		{
			CString omittedText;
			omittedText = Localization::Format(
				_T("page3.children_more"),
				static_cast<unsigned int>(
					descendantProcessIds.size() - maxDisplayedChildren));
			confirmationText += omittedText;
		}
		confirmationText += Localization::Get(_T("page3.children_question"));

		const int confirmation = MessageBox(
			confirmationText,
			Localization::Get(_T("page3.children_title")),
			MB_YESNOCANCEL | MB_ICONQUESTION);
		if (confirmation == IDCANCEL)
			return 0;
		if (confirmation == IDYES)
		{
			std::vector<DWORD> processesToProxy;
			processesToProxy.push_back(processId);
			processesToProxy.insert(
				processesToProxy.end(),
				descendantProcessIds.begin(),
				descendantProcessIds.end());
			SelectProcessesByPid(processesToProxy);
		}
	}

	OnBnClickedInjectdll();
	return 0;
}

LRESULT CPage3::OnWindowFinderCancel(WPARAM, LPARAM)
{
	ClearWindowFinderHighlight();
	RestoreProcessPageSubtitle();
	SetTimer(TIMER_PSLIST, 2000, NULL);
	return 0;
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
		MessageBox(Localization::Get(_T("page3.select_first")),
			Localization::Get(_T("page3.none_selected")), MB_ICONINFORMATION);
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
		MessageBox(Localization::Get(_T("page3.read_failed")),
			Localization::Get(_T("page3.target_unavailable")), MB_ICONERROR);
		return;
	}

	char szPipeName[MAX_PATH] = "\0";
	IProxyReceptionCentre *pPRC = NULL;
	if(!g_GlobalProxy || !(pPRC = g_GlobalProxy->GetPRCInstance()))
	{
		MessageBox(Localization::Get(_T("page3.start_proxy_first")),
			Localization::Get(_T("status.proxy_stopped")), MB_ICONINFORMATION);
		return;
	}
	if(!pPRC->GetPRCPipeName(szPipeName, MAX_PATH))
	{
		MessageBox(Localization::Get(_T("page3.channel_failed")),
			Localization::Get(_T("page3.proxy_state_error")), MB_ICONERROR);
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
				target.name.IsEmpty() ? static_cast<LPCTSTR>(Localization::Get(_T("page3.unknown_process"))) : static_cast<LPCTSTR>(target.name),
				target.pid);
			failedProcesses.push_back(failedProcess);
		}
	}

	CString resultText;
	int totalCount = static_cast<int>(targets.size()) + unreadableCount;
	resultText = Localization::Format(
		_T("page3.result_summary"),
		totalCount,
		successCount,
		failedCount,
		skippedCount);

	if (failedCount > 0)
	{
		resultText += Localization::Get(_T("page3.failed_processes"));
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
			remainingText = Localization::Format(
				_T("page3.more_processes"),
				static_cast<unsigned int>(failedProcesses.size() - maxFailureDetails));
			resultText += remainingText;
		}
		if (unreadableCount > 0)
			resultText += Localization::Get(_T("page3.unreadable_selection"));
	}
	if (skippedCount > 0)
		resultText += Localization::Get(_T("page3.skipped_self"));

	MessageBox(
		resultText,
		Localization::Get(failedCount > 0 ? _T("page3.partial_failure") : _T("page3.completed")),
		failedCount > 0 ? MB_ICONWARNING : MB_ICONINFORMATION);
}

void CPage3::OnTimer(UINT_PTR nIDEvent)
{
	// TODO: 在此添加消息处理程序代码和/或调用默认值
	switch(nIDEvent)
	{
	case TIMER_PSLIST:
		{
			if (!m_btnWindowFinder.IsTracking())
				UpdatePslist(FALSE);
		}
		break;
	}

}

BOOL CPage3::ShouldInjectNewProcess(LPHookNewProcessInfo lphnpi)
{
	return ShouldProxyChildProcess(lphnpi);
}

BOOL CPage3::ShouldProxyChildProcess(LPHookNewProcessInfo lphnpi)
{
	BOOL bShouldInject = TRUE;
	{
		CSingleLock filterLock(&g_childFilterLock, TRUE);
		if (g_ChildInjectFilter.bEnabled && !g_ChildInjectFilter.patterns.empty())
		{
			BOOL bMatched = FALSE;
			if (lphnpi->szAppPath[0])
			{
				for (size_t i = 0; i < g_ChildInjectFilter.patterns.size(); i++)
				{
					if (PathMatchSpecW(lphnpi->szAppPath, g_ChildInjectFilter.patterns[i]))
					{
						bMatched = TRUE;
						break;
					}
				}
			}

			bShouldInject = (g_ChildInjectFilter.nMode == CHILDFILTER_MODE_INCLUDE)
				? bMatched : !bMatched;
		}
	}

	if (!bShouldInject)
	{
		CString processName = lphnpi->szAppPath;
		const int slash = processName.ReverseFind(_T('\\'));
		if (slash >= 0)
			processName = processName.Mid(slash + 1);
		CString text;
		text.Format(
			_T("New Process: %d | %s Skipped by filter\r\n"),
			lphnpi->dwProcessId,
			(LPCTSTR)processName);
		CPage2* page2 = g_MainTab ? g_MainTab->GetPage2() : NULL;
		if (page2)
			page2->AddLogText(text);
	}
	return bShouldInject;
}

BOOL CPage3::InjectNewProcess(LPHookNewProcessInfo lphnpi)
{
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

	if (!ShouldProxyChildProcess(&hnpi))
	{
		CloseHandle(hProcess);
		return FALSE;
	}

	CPage2 *pPage2 = g_MainTab->GetPage2();
	CString procName = hnpi.szAppPath;
	const int nameSlash = procName.ReverseFind(_T('\\'));
	if (nameSlash >= 0)
		procName = procName.Mid(nameSlash + 1);
	if (procName.IsEmpty())
		procName = _T("Unknown");
	CString szText;

	bRet = InjectDll(hProcess, hnpi.dwProcessId, hnpi.dwThreadId, szPipeName);

	if (bRet > 0)
		szText.Format(_T("New Process: %d | %s Hooked\r\n"), hnpi.dwProcessId, (LPCTSTR)procName);
	else
		szText.Format(_T("New Process: %d | %s InjectDll Failed\r\n"), hnpi.dwProcessId, (LPCTSTR)procName);

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
	size_t nLen = _tcslen(pFileName);

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
	const DWORD createProcessError = ret ? ERROR_SUCCESS : GetLastError();
	commandLine.ReleaseBuffer();

	myWow64RevertWow64FsRedirection(WowRedirOldValue);

	if (!ret)
	{
		if (createProcessError == ERROR_ELEVATION_REQUIRED)
		{
			return LaunchElevatedAndProxy(
				GetSafeHwnd(),
				szTargetPath,
				commandLine,
				szBaseDir[0] == 0 ? NULL : szBaseDir);
		}
		return APP_LAUNCH_CREATE_PROCESS_FAILED;
	}

	hnpi.dwProcessId = pi.dwProcessId;
	hnpi.dwThreadId = pi.dwThreadId;

#ifdef UNICODE
	wcsncpy(hnpi.szCommandLine, commandLine, MAX_PATH - 1);
#else
#error unicode required
#endif
	if (!ResolveChildAppPath(pi.hProcess, hnpi.szAppPath, MAX_PATH) ||
		!hnpi.szAppPath[0])
	{
		// XP 下挂起进程的模块信息可能尚未就绪；回退显示用户传入的文件名。
#ifdef UNICODE
		wcsncpy(hnpi.szAppPath, fileName, MAX_PATH - 1);
		hnpi.szAppPath[MAX_PATH - 1] = L'\0';
#else
#error unicode required
#endif
	}

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


