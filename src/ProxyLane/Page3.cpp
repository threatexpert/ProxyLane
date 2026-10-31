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
#include "PackagedAppSupport.h"
#include "ApplicationPicker.h"
#include "ProcessActions.h"
#include "ProcessImagePath.h"
#include "ProcessCommandLine.h"
#include "BrowserReuseDialog.h"
#include "ProxyLaneDlg.h"
#include "../ProxyLaneHook/ProcessCreationRecording.h"
#include "../ProxyLaneHook/ProcessCreationSnapshot.h"
#include "ScopedProcessSuspension.h"

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

int GetProcessList(list<_myPROCESSINFO> &ls)
{
	ProxyProcessIdentity::Snapshot snapshot;
	if (!ProxyProcessIdentity::QuerySnapshot(snapshot)) return -1;
	const BOOL queryByPid = IsVistaOrLater();
	ProcessImagePath::Resolver pathResolver;
	if (queryByPid) pathResolver.Refresh();
	list<_myPROCESSINFO> rows;
	int count = 0;
	for (size_t i = 0; i < snapshot.processes.size(); ++i)
	{
		const ProxyProcessIdentity::Process& process = snapshot.processes[i];
		_myPROCESSINFO info = {};
		info.pid = process.pid;
		info.parentPid = process.parentPid;
		// Keep the previous insertion-at-head order using the native snapshot.
		info.defaultOrder = -count;
		info.treeOrder = -1;
		const CString name = !process.name.empty() ? CString(process.name.c_str()) :
			(process.pid == 0 ? CString(_T("[System Process]")) : Localization::Get(_T("page3.unknown_process")));
		_tcsncpy_s(info.proname, _countof(info.proname), name, _TRUNCATE);
		if (process.creationTime) SetProcessStartTime(process.creationTime, info);

		if (queryByPid)
		{
			std::wstring nativePath;
			if (process.creationTime && ProcessImagePath::Query(process.pid, nativePath))
			{
				const CString path(pathResolver.Convert(nativePath).c_str());
				// Do not expose a truncated path as an actionable executable path.
				if (path.GetLength() < _countof(info.propath))
					_tcscpy_s(info.propath, _countof(info.propath), path);
			}
		}
		else
		{
			// XP/Server 2003 compatibility only. Modern path queries never open a process.
			HANDLE handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process.pid);
			if (!handle) handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, process.pid);
			if (handle)
			{
				if (process.creationTime && ProcessActions::CreationTime(handle) == process.creationTime)
					GetProcessFullPath(handle, info.propath, MAX_PATH);
				CloseHandle(handle);
			}
		}
		rows.push_back(info);
		++count;
	}
	if (queryByPid)
	{
		// One batch recheck after all PID-only queries, not a snapshot per row.
		// A failed recheck leaves names/times available but discards unverified paths.
		ProxyProcessIdentity::Snapshot after;
		ProxyProcessIdentity::QuerySnapshot(after);
		for (auto row = rows.begin(); row != rows.end(); ++row)
		{
			const auto found = after.creationTimes.find(row->pid);
			if (!after.complete || !row->startTimeValue || found == after.creationTimes.end() ||
				found->second != row->startTimeValue) row->propath[0] = _T('\0');
		}
	}
	ls.splice(ls.end(), rows);
	return count;
}

void CPage3::OnHookWsock(LPHookWSockResult)
{
	// The pipe server updates the shared registry before notifying observers.
}

BOOL CPage3::GetRunningHookedProcesses(std::vector<_myPROCESSINFO>& processes)
{
	processes.clear();
	if (!m_processRegistry) return FALSE;
	// Fetch anew every round so hooks registered while the dialog is open are
	// included. Retry a growing registry without accepting a truncated snapshot.
	std::vector<HookProcessIdentityInfo> identities(64);
	bool complete = false;
	for (int attempt = 0; attempt < 8; ++attempt)
	{
		const DWORD count = m_processRegistry->SnapshotHooked(&identities[0],
			static_cast<DWORD>(identities.size()));
		if (count <= identities.size())
		{
			identities.resize(count);
			complete = true;
			break;
		}
		identities.resize(static_cast<size_t>(count) + 64);
	}
	if (!complete) return FALSE;
	ProxyProcessIdentity::Snapshot snapshot;
	if (!identities.empty() && !ProxyProcessIdentity::QuerySnapshot(snapshot)) return FALSE;
	for (size_t i = 0; i < identities.size(); ++i)
	{
		const HookProcessIdentityInfo& identity = identities[i];
		if (snapshot.HasExited(identity)) continue;
		_myPROCESSINFO process = {};
		process.pid = identity.dwProcessId;
		process.hasStartTime = TRUE;
		process.startTimeValue = identity.processCreateTime;
		_tcsncpy_s(process.propath, _countof(process.propath), identity.szAppPath, _TRUNCATE);
		const TCHAR* name = _tcsrchr(process.propath, _T('\\'));
		name = name ? name + 1 : process.propath;
		const CString displayName = *name ? CString(name) : Localization::Get(_T("page3.unknown_process"));
		_tcsncpy_s(process.proname, _countof(process.proname), displayName, _TRUNCATE);
		processes.push_back(process);
	}
	return TRUE;
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
	IProxyReceptionCentre *prc = g_GlobalProxy ? g_GlobalProxy->GetPRCInstance() : NULL;
	if (!prc || !prc->AuthorizeProcessPipeAccess(hProc))
	{
		const DWORD error = prc ? GetLastError() : ERROR_PIPE_NOT_CONNECTED;
		CString text;
		text.Format(_T("Failed to authorize PRC pipe access: PID %lu, error %lu.\r\n"),
			dwPid, error);
		if (g_GlobalProxy) g_GlobalProxy->GetLogInstance()->LogText(text);
		SetLastError(error);
		return FALSE;
	}
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

BOOL HookProcess(DWORD pid, LPCSTR pipeName, ULONGLONG expectedCreationTime = 0)
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
		// Browser warning actions refer to the displayed lifetime, never a new
		// process that has since acquired its PID. Hold this handle through injection.
		if (expectedCreationTime && (ProcessActions::CreationTime(hRemoteProcess) != expectedCreationTime ||
			WaitForSingleObject(hRemoteProcess, 0) != WAIT_TIMEOUT))
		{
			SetLastError(ERROR_NOT_FOUND);
			break;
		}
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
	, m_terminating(FALSE)
	, m_launchedProcessId(0)
	, m_launchedProcessTime(0)
	, m_launchSelectionTick(0)
	, m_processRegistry(NULL)
	, m_processesExpanded(FALSE)
	, m_recentLoad(NULL)
	, m_recentConsumed(TRUE)
	, m_recentReadFailed(FALSE)
	, m_recentLaunching(FALSE)
{
	//m_pEdit = NULL;
	//m_pEdit = new CMyEdit;
	m_evlock.SetEvent();

}

CPage3::~CPage3()
{
	ClearWindowFinderHighlight();
	if (m_recentLoad) m_recentLoad->Release();
	RecentApplications::ReleaseIcons(m_recentEntries);
}

void CPage3::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_PSLIST, m_ListCtrl);
	DDX_Control(pDX, IDC_WINDOW_FINDER, m_btnWindowFinder);
	DDX_Control(pDX, IDC_REFRESH, m_btnRefresh);
	DDX_Control(pDX, IDC_INJECTDLL, m_btnInject);
	DDX_Control(pDX, IDC_SELECT_APP, m_btnSelectApp);
	DDX_Control(pDX, IDC_TERMINATE_PROCESS, m_btnTerminate);

	//DDX_Control(pDX, IDC_CHECK1, m_btnAuto);
}

BOOL CPage3::OnInitDialog()
{
	CModernDialog::OnInitDialog();
	// Acquire the module-lifetime registry once; never consult the transient
	// g_GlobalProxy pointer from cleanup workers or drawing after service stop.
	IGlobalProxy* proxy = GetGlobalProxyInstance();
	if (proxy)
	{
		m_processRegistry = proxy->GetProcessRegistry();
		ReleaseGlobalProxyInstance();
	}
	SetTimer(TIMER_PROCESS_REGISTRY, 30000, NULL);
	DragAcceptFiles(FALSE);
	m_ListCtrl.DragAcceptFiles(FALSE);
	m_btnWindowFinder.SetVisualStyle(CModernButton::STYLE_SECONDARY);
	m_btnRefresh.SetVisualStyle(CModernButton::STYLE_SECONDARY);
	m_btnSelectApp.SetVisualStyle(CModernButton::STYLE_PRIMARY);
	m_btnSelectApp.SetBackdropColor(UiTheme::Surface());
	m_btnInject.SetVisualStyle(CModernButton::STYLE_SECONDARY);
	m_btnTerminate.SetVisualStyle(CModernButton::STYLE_DANGER);
	m_btnTerminate.EnableWindow(FALSE);
	RestoreProcessPageSubtitle();

	// The launch panel paints itself; without this the page background erase
	// would wipe it whenever the page is invalidated after the panel painted.
	ModifyStyle(0, WS_CLIPCHILDREN);
	m_processToggle.Create(Localization::Get(_T("launch.processes_show")),
		WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
		CRect(0, 0, 0, 0), this, IDC_PROCESS_TOGGLE);
	m_processToggle.SetFont(&m_uiFont, FALSE);
	m_processToggle.SetVisualStyle(CModernButton::STYLE_SECONDARY);
	// Lets the user stop the proxy where they started it from.
	m_btnStopProxy.Create(Localization::Get(_T("action.stop_proxy")),
		WS_CHILD | WS_TABSTOP | BS_OWNERDRAW, CRect(0, 0, 0, 0), this, IDC_STOP_PROXY_APP);
	m_btnStopProxy.SetFont(&m_uiFont, FALSE);
	m_btnStopProxy.SetVisualStyle(CModernButton::STYLE_SECONDARY);
	m_btnStopProxy.SetBackdropColor(UiTheme::Surface());
	if (m_launchPanel.Create(this, IDC_LAUNCH_PANEL))
		m_launchPanel.SetWindowPos(&wndBottom, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
	SetTimer(TIMER_LAUNCH_PANEL, 500, NULL);
	RefreshLaunchPanel();
	SetProcessesExpanded(FALSE);
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

	// Do not call a message handler directly from WM_INITDIALOG: MFC's
	// OnSize base implementation calls Default() for the *current* message,
	// which would dispatch WM_INITDIALOG again and recurse until stack overflow.
	LayoutProcessPage();
	return TRUE;
}

static AppLaunchResult LaunchElevatedAndProxy(
	HWND ownerWindow,
	LPCTSTR targetPath,
	LPCTSTR commandLine,
	LPCTSTR workingDirectory,
	DWORD& launchedPid,
	ULONGLONG& launchedTime)
{
	launchedPid = 0;
	launchedTime = 0;
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
	const DWORD utf8ConversionFlags = IsVistaOrLater()
		? WC_ERR_INVALID_CHARS
		: 0;
	for (size_t index = 0; index < _countof(wideFields); ++index)
	{
		const int wideLength = static_cast<int>(wcslen(wideFields[index]));
		if (!wideLength)
			continue;
		const int utf8Length = WideCharToMultiByte(
			CP_UTF8,
			utf8ConversionFlags,
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
			utf8ConversionFlags,
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
	if (gotExitCode && helperExitCode == PROXYLANE_ELEVATED_SUCCESS)
	{
		// Keep the helper handle alive while matching its immediate child.
		// A process name alone is not a safe launch identity.
		const DWORD helperPid = GetProcessId(shellInfo.hProcess);
		const ULONGLONG helperTime = ProcessActions::CreationTime(shellInfo.hProcess);
		list<_myPROCESSINFO> processes;
		GetProcessList(processes);
		for (list<_myPROCESSINFO>::const_iterator it = processes.begin(); it != processes.end(); ++it)
		{
			if (helperPid && helperTime && it->parentPid == helperPid && it->hasStartTime &&
				it->startTimeValue >= helperTime && _tcsicmp(it->propath, targetPath) == 0)
			{
				launchedPid = it->pid;
				launchedTime = it->startTimeValue;
				break;
			}
		}
	}
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
	if (message->message == WM_LBUTTONDOWN || message->message == WM_RBUTTONDOWN ||
		message->message == WM_MBUTTONDOWN || message->message == WM_KEYDOWN)
		CancelLaunchSelection();

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
	ON_BN_CLICKED(IDC_SELECT_APP, &CPage3::OnBnClickedSelectApp)
	ON_BN_CLICKED(IDC_TERMINATE_PROCESS, &CPage3::OnBnClickedTerminateProcess)
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_PSLIST, &CPage3::OnProcessSelectionChanged)
	ON_NOTIFY(LVN_COLUMNCLICK, IDC_PSLIST, &CPage3::OnLvnColumnClickProcessList)
	ON_NOTIFY(NM_CUSTOMDRAW, IDC_PSLIST, &CPage3::OnNMCustomdrawProcessList)
	ON_MESSAGE(WM_LAUNCH_PANEL_TILE, &CPage3::OnLaunchPanelTile)
	ON_BN_CLICKED(IDC_PROCESS_TOGGLE, &CPage3::OnBnClickedProcessToggle)
	ON_BN_CLICKED(IDC_STOP_PROXY_APP, &CPage3::OnBnClickedStopProxy)
	ON_MESSAGE(WM_RECENT_APPLICATIONS_CHANGED, &CPage3::OnRecentApplicationsChanged)
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
	LayoutProcessPage();
}

void CPage3::LayoutProcessPage()
{
	if (!GetSafeHwnd()) return;
	LayoutPageHeader();
	CRect rcClient;
	GetClientRect(&rcClient);
	if (rcClient.Width() <= 0 || rcClient.Height() <= 0)
		return;

	const int margin = UiTheme::ScaleForWindow(m_hWnd, 8);
	const int gap = UiTheme::ScaleForWindow(m_hWnd, 6);
	const int buttonHeight = UiTheme::ScaleForWindow(m_hWnd, 30);
	const int padding = UiTheme::ScaleForWindow(m_hWnd, 16);

	auto textWidth = [this](CModernButton& button, int minimum)
	{
		if (!button.GetSafeHwnd()) return UiTheme::ScaleForWindow(m_hWnd, minimum);
		CString text;
		button.GetWindowText(text);
		CClientDC dc(&button);
		CFont* font = button.GetFont();
		CFont* oldFont = font ? dc.SelectObject(font) : NULL;
		const int width = max(UiTheme::ScaleForWindow(m_hWnd, minimum),
			dc.GetTextExtent(text).cx + UiTheme::ScaleForWindow(m_hWnd, 28));
		if (oldFont) dc.SelectObject(oldFont);
		return width;
	};

	// Launch panel with the primary action inside it.
	int top = UiTheme::ScaleForWindow(m_hWnd, 66);
	if (m_launchPanel.GetSafeHwnd())
	{
		const int panelHeight = m_launchPanel.PreferredHeight();
		CRect panel(margin, top, rcClient.right - margin, top + panelHeight);
		m_launchPanel.MoveWindow(&panel);
		const int actionWidth = textWidth(m_btnSelectApp, 150);
		m_launchPanel.SetActionWidth(actionWidth);
		const int actionHeight = UiTheme::ScaleForWindow(m_hWnd, 34);
		CRect slot = m_launchPanel.ActionSlot(actionWidth, actionHeight);
		if (m_btnSelectApp.GetSafeHwnd())
			m_btnSelectApp.MoveWindow(panel.left + slot.left, panel.top + slot.top, actionWidth, actionHeight);
		if (m_btnStopProxy.GetSafeHwnd())
		{
			const int stopWidth = textWidth(m_btnStopProxy, 96);
			m_btnStopProxy.MoveWindow(panel.left + slot.left - stopWidth - UiTheme::ScaleForWindow(m_hWnd, 10),
				panel.top + slot.top, stopWidth, actionHeight);
			m_launchPanel.SetActionWidth(actionWidth + stopWidth + UiTheme::ScaleForWindow(m_hWnd, 10));
		}
		top = panel.bottom + UiTheme::ScaleForWindow(m_hWnd, 16);
	}

	// Process section: heading on the left, tools on the right.
	const int finderWidth = UiTheme::ScaleForWindow(m_hWnd, 30);
	const int refreshWidth = textWidth(m_btnRefresh, 70);
	const int injectWidth = textWidth(m_btnInject, 96);
	const int terminateWidth = textWidth(m_btnTerminate, 90);
	const int toolbarWidth = finderWidth + refreshWidth + injectWidth + terminateWidth + gap * 3;
	const int headingWidth = textWidth(m_processToggle, 150);
	const BOOL separateRow = rcClient.Width() - margin * 2 < toolbarWidth + headingWidth + gap;

	if (m_processToggle.GetSafeHwnd())
		m_processToggle.MoveWindow(margin, top, headingWidth, buttonHeight);
	if (!m_processesExpanded)
		return;
	int left = separateRow ? margin : rcClient.right - margin - toolbarWidth;
	int toolbarTop = top;
	if (separateRow)
		toolbarTop = top + buttonHeight + gap;
	CWnd* buttons[] = { &m_btnWindowFinder, &m_btnRefresh, &m_btnInject, &m_btnTerminate };
	const int widths[] = { finderWidth, refreshWidth, injectWidth, terminateWidth };
	for (int i = 0; i < _countof(buttons); ++i)
	{
		if (separateRow && left > margin && left + widths[i] > rcClient.right - margin)
		{
			left = margin;
			toolbarTop += buttonHeight + gap;
		}
		if (buttons[i]->GetSafeHwnd()) buttons[i]->MoveWindow(left, toolbarTop, widths[i], buttonHeight);
		left += widths[i] + gap;
	}
	const int listTop = toolbarTop + buttonHeight + gap + UiTheme::ScaleForWindow(m_hWnd, 2);

	if (m_ListCtrl.GetSafeHwnd())
	{
		CRect rc(margin, listTop, rcClient.right - margin, max(listTop, rcClient.bottom - margin));
		m_ListCtrl.MoveWindow(&rc);
		int pathWidth = rc.Width() - UiTheme::ScaleForWindow(m_hWnd, 445);
		if (pathWidth > UiTheme::ScaleForWindow(m_hWnd, 140)) m_ListCtrl.SetColumnWidth(3, pathWidth);
	}
	(void)padding;
}

void CPage3::OnProcessSelectionChanged(NMHDR*, LRESULT* result)
{
	if (m_ListCtrl.GetSelectedCount() > 0 && !m_btnWindowFinder.IsTracking()) RestoreProcessPageSubtitle();
	if (m_btnTerminate.GetSafeHwnd())
		m_btnTerminate.EnableWindow(!m_terminating && m_ListCtrl.GetSelectedCount() > 0);
	*result = 0;
}

void CPage3::OnBnClickedTerminateProcess()
{
	if (m_terminating) return;
	CancelLaunchSelection();
	struct Target { DWORD pid; CString name; HANDLE handle; DWORD error; };
	std::vector<Target> targets;
	struct Cleanup
	{
		std::vector<Target>& targets;
		BOOL& busy;
		CWnd& button;
		CListCtrl& list;
		Cleanup(std::vector<Target>& t, BOOL& b, CWnd& c, CListCtrl& l)
			: targets(t), busy(b), button(c), list(l) { busy = TRUE; button.EnableWindow(FALSE); }
		~Cleanup() { for (size_t i = 0; i < targets.size(); ++i)
			if (targets[i].handle) CloseHandle(targets[i].handle);
			busy = FALSE; button.EnableWindow(list.GetSelectedCount() > 0); }
	} cleanup(targets, m_terminating, m_btnTerminate, m_ListCtrl);
	POSITION position = m_ListCtrl.GetFirstSelectedItemPosition();
	while (position)
	{
		const int item = m_ListCtrl.GetNextSelectedItem(position);
		const DWORD pid = static_cast<DWORD>(m_ListCtrl.GetItemData(item));
		std::map<DWORD, _myPROCESSINFO>::const_iterator it = m_processSortData.find(pid);
		if (it == m_processSortData.end()) continue;
		Target target = { pid, CString(it->second.proname), NULL, ERROR_SUCCESS };
		targets.push_back(target);
		Target& stored = targets.back();
		stored.handle = ProcessActions::OpenForTermination(pid,
			it->second.hasStartTime ? it->second.startTimeValue : 0);
		if (!stored.handle) stored.error = GetLastError();
	}
	if (targets.empty()) return;
	CString names;
	for (size_t i = 0; i < targets.size() && i < 10; ++i)
	{
		CString line;
		line.Format(_T("%s (PID %lu)\r\n"), static_cast<LPCTSTR>(targets[i].name), targets[i].pid);
		names += line;
	}
	if (targets.size() > 10) names += _T("...\r\n");
	if (MessageBox(Localization::Format(_T("page3.end_confirm"),
		static_cast<int>(targets.size()), static_cast<LPCTSTR>(names)),
		Localization::Get(_T("action.end_process")), MB_YESNO | MB_DEFBUTTON2 | MB_ICONWARNING) != IDYES)
		return;
	int succeeded = 0, failed = 0;
	CString errors;
	for (size_t i = 0; i < targets.size(); ++i)
	{
		Target& target = targets[i];
		if (target.handle)
		{
			if (WaitForSingleObject(target.handle, 0) == WAIT_OBJECT_0 || TerminateProcess(target.handle, 1))
			{ ++succeeded; continue; }
			target.error = GetLastError();
		}
		++failed;
		if (failed <= 10) errors += Localization::Format(_T("page3.end_error"),
			static_cast<LPCTSTR>(target.name), target.pid, target.error);
	}
	CString summary = Localization::Format(_T("page3.end_summary"), succeeded, failed);
	if (failed) MessageBox(summary + _T("\r\n\r\n") + errors,
		Localization::Get(_T("action.end_process")), MB_OK | MB_ICONWARNING);
	else if (g_MainTab) g_MainTab->ShowTransientStatus(summary, CStatusLabel::TONE_SUCCESS);
	UpdatePslist(FALSE);
}

void CPage3::ReloadRecentApplications(BOOL force)
{
	// Mirrors the shared cache protocol used by the proxy page: the cache owns
	// background loading; this page only clones what is ready to show.
	const CString profile = g_MainTab && g_MainTab->IsProxyRunning() ? g_MainTab->GetRunningProfileName() : CString();
	const CString identity = g_MainTab ? g_MainTab->GetRunningRecentProfileId() : CString();
	BOOL changed = force || identity != m_recentProfileId;
	if (identity != m_recentProfileId)
	{
		RecentApplications::ReleaseIcons(m_recentEntries);
		m_recentEntries.clear();
		if (m_recentLoad) { m_recentLoad->Release(); m_recentLoad = NULL; }
		m_recentProfileId = identity;
		m_recentConsumed = TRUE;
		m_recentReadFailed = FALSE;
	}
	if (!identity.IsEmpty())
	{
		RecentApplications::Load* latest = RecentApplications::AcquireLoad(profile, RecentApplications::DefaultPath(), identity);
		if (latest != m_recentLoad)
		{
			RecentApplications::Load* ready = RecentApplications::AcquireReadyLoad(profile, RecentApplications::DefaultPath(), identity);
			if (ready)
			{
				RecentApplications::ReleaseIcons(m_recentEntries);
				m_recentEntries.clear();
				RecentApplications::Clone(ready->entries, m_recentEntries, 7);
				ready->Release();
			}
			if (m_recentLoad) m_recentLoad->Release();
			m_recentLoad = latest;
			m_recentConsumed = FALSE;
			changed = TRUE;
		}
		else latest->Release();
		EnterCriticalSection(&m_recentLoad->lock);
		const BOOL done = m_recentLoad->done;
		LeaveCriticalSection(&m_recentLoad->lock);
		if (done && !m_recentConsumed)
		{
			m_recentReadFailed = !m_recentLoad->succeeded;
			if (!m_recentReadFailed)
			{
				RecentApplications::ReleaseIcons(m_recentEntries);
				m_recentEntries.clear();
				RecentApplications::Clone(m_recentLoad->entries, m_recentEntries, 7);
			}
			m_recentConsumed = TRUE;
			changed = TRUE;
		}
	}
	if (!changed) return;

	std::vector<CLaunchPanel::Tile> tiles;
	for (size_t i = 0; i < m_recentEntries.size(); ++i)
	{
		CLaunchPanel::Tile tile;
		tile.icon = m_recentEntries[i].app.icon;
		tile.name = m_recentEntries[i].app.name;
		tile.tip = RecentApplications::Description(m_recentEntries[i], profile);
		tiles.push_back(tile);
	}
	m_launchPanel.SetTiles(tiles);
}

BOOL CPage3::HasConfiguredProxy() const
{
	return g_MainTab && g_MainTab->GetPage1() && g_MainTab->GetPage1()->m_cfgls.GetCount() > 0;
}

void CPage3::RefreshLaunchPanel()
{
	if (!m_launchPanel.GetSafeHwnd()) return;
	const BOOL running = g_MainTab && g_MainTab->IsProxyRunning();
	const BOOL configured = HasConfiguredProxy();
	ReloadRecentApplications(FALSE);
	CString empty = Localization::Get(!m_recentConsumed ? L"apps.loading_list" :
		(m_recentReadFailed ? L"recent.read_failed" : L"recent.empty"));
	LPCTSTR titleKey = running ? _T("launch.title_ready") : (configured ? _T("launch.title_offline") : _T("launch.title_unconfigured"));
	LPCTSTR bodyKey = running ? _T("launch.body_ready") : (configured ? _T("launch.body_offline") : _T("launch.body_unconfigured"));
	m_launchPanel.SetText(Localization::Get(titleKey), Localization::Get(bodyKey),
		Localization::Get(_T("recent.title")), empty);
	m_launchPanel.SetEnabledState(running);
	if (m_btnStopProxy.GetSafeHwnd())
		m_btnStopProxy.ShowWindow(running ? SW_SHOW : SW_HIDE);

	// One action button whose meaning follows the state of the proxy.
	LPCTSTR actionKey = running ? _T("apps.select") : (configured ? _T("action.start_proxy") : _T("launch.goto_proxy"));
	const CString actionText = Localization::Get(actionKey);
	CString current;
	m_btnSelectApp.GetWindowText(current);
	if (current != actionText)
	{
		m_btnSelectApp.SetWindowText(actionText);
		LayoutProcessPage();
	}
}

void CPage3::OnBnClickedStopProxy()
{
	if (g_MainTab && g_MainTab->GetPage1())
		g_MainTab->GetPage1()->OnBnClickedCancel();
}

void CPage3::OnBnClickedProcessToggle()
{
	SetProcessesExpanded(!m_processesExpanded);
}

void CPage3::SetProcessesExpanded(BOOL expanded)
{
	m_processesExpanded = expanded;
	RestoreProcessPageSubtitle();
	if (m_processToggle.GetSafeHwnd())
		m_processToggle.SetWindowText(Localization::Get(expanded ? _T("launch.processes_hide") : _T("launch.processes_show")));
	const int show = expanded ? SW_SHOW : SW_HIDE;
	m_ListCtrl.ShowWindow(show);
	m_btnWindowFinder.ShowWindow(show);
	m_btnRefresh.ShowWindow(show);
	m_btnInject.ShowWindow(show);
	m_btnTerminate.ShowWindow(show);
	LayoutProcessPage();
	if (expanded)
		UpdatePslist(TRUE);
}

LRESULT CPage3::OnLaunchPanelTile(WPARAM index, LPARAM)
{
	if (m_recentLaunching || !g_MainTab || !g_MainTab->IsProxyRunning()) return 0;
	if (index >= m_recentEntries.size()) return 0;
	const RecentApplications::Entry entry = m_recentEntries[index];
	m_recentLaunching = TRUE;
	struct Reset { BOOL& flag; ~Reset() { flag = FALSE; } } reset = { m_recentLaunching };
	LaunchRecentApplication(entry);
	return 0;
}

LRESULT CPage3::OnRecentApplicationsChanged(WPARAM, LPARAM)
{
	ReloadRecentApplications(TRUE);
	return 0;
}

void CPage3::OnBnClickedSelectApp()
{
	if (!g_MainTab || !g_MainTab->IsProxyRunning())
	{
		// Not running: start the configured proxy, or lead the user to configure one.
		if (HasConfiguredProxy())
			g_MainTab->GetPage1()->OnBnClickedOk();
		else if (g_MainTab)
			g_MainTab->SelectPage(CMainTab::PAGE_PROXY);
		return;
	}
	CApplicationPicker picker(this);
	if (picker.DoModal() != IDOK) return;
	if (!picker.m_selectedRecent.id.IsEmpty())
	{
		LaunchRecentApplication(picker.m_selectedRecent);
		return;
	}
	const InstalledApplications::Application& app = picker.m_selectedApplication;
	ShowApplicationLaunchResult(app.name, LaunchInteractiveApplication(app));
}

AppLaunchResult CPage3::LaunchInteractiveApplication(const InstalledApplications::Application& app,
	AppLaunchElevationMode elevationMode, const RecentApplications::Entry* saved)
{
	if (!g_MainTab || !g_MainTab->IsProxyRunning()) return APP_LAUNCH_CREATE_PROCESS_FAILED;
	const CString runningProfile = g_MainTab->GetRunningProfileName();
	const CString runningIdentity = g_MainTab->GetRunningRecentProfileId();
	RecentApplications::Entry entry = saved ? *saved : RecentApplications::FromApplication(app,
		elevationMode == APP_LAUNCH_ELEVATION_FORCE_ADMIN);
	InstalledApplications::Application resolved;
	if (!RecentApplications::Resolve(entry, resolved)) return APP_LAUNCH_INVALID_TARGET;
	const CString name = entry.app.name;
	entry.app = resolved;
	entry.app.icon = NULL;
	if (entry.app.name.IsEmpty()) entry.app.name = name;
	std::vector<CString> arguments;
	const AppLaunchResult result = resolved.IsPackaged() ?
		LaunchPackagedAppById(resolved.aumid, resolved.arguments) :
		LaunchAndProxyApp(resolved.path, arguments, TRUE, elevationMode, resolved.arguments, resolved.workingDirectory);
	if (result == APP_LAUNCH_SUCCESS)
	{
		if (!runningIdentity.IsEmpty() && !RecentApplications::Store(runningProfile, RecentApplications::DefaultPath(), runningIdentity).Remember(entry))
		{
			CString text;
			text.Format(L"Failed to save recently launched application: error %lu.\r\n", GetLastError());
			g_MainTab->AddLogText(0, text);
		}
		g_MainTab->GetPage1()->PostMessage(WM_RECENT_APPLICATIONS_CHANGED);
		PostMessage(WM_RECENT_APPLICATIONS_CHANGED);
	}
	return result;
}

void CPage3::LaunchRecentApplication(const RecentApplications::Entry& entry)
{
	if (!g_MainTab || !g_MainTab->IsProxyRunning()) return;
	if (entry.profileId != g_MainTab->GetRunningRecentProfileId()) return;
	const AppLaunchResult result = LaunchInteractiveApplication(entry.app,
		entry.elevated ? APP_LAUNCH_ELEVATION_FORCE_ADMIN : APP_LAUNCH_ELEVATION_AUTO, &entry);
	if (result == APP_LAUNCH_INVALID_TARGET)
	{
		MessageBox(Localization::Get(L"recent.unavailable"), Localization::Get(L"recent.title"), MB_OK | MB_ICONWARNING);
		return;
	}
	ShowApplicationLaunchResult(entry.app.name, result);
}

void CPage3::ShowApplicationLaunchResult(const CString& name, AppLaunchResult result)
{
	if (result == APP_LAUNCH_SUCCESS)
	{
		g_MainTab->ShowTransientStatus(Localization::Format(_T("dialog.started_proxy"),
			static_cast<LPCTSTR>(name)), CStatusLabel::TONE_SUCCESS);
		return;
	}
	LPCTSTR messageKey = _T("dialog.drop_launch_failed");
	if (result == APP_LAUNCH_INVALID_TARGET) messageKey = _T("dialog.drop_invalid");
	else if (result == APP_LAUNCH_UAC_CANCELLED) messageKey = _T("dialog.drop_uac_cancelled");
	else if (result == APP_LAUNCH_ELEVATED_HELPER_FAILED) messageKey = _T("dialog.drop_elevated_failed");
	else if (result == APP_LAUNCH_INJECTION_FAILED)
		messageKey = _T("dialog.drop_inject_failed");
	else if (result == APP_LAUNCH_PACKAGED_INJECTION_FAILED)
		messageKey = _T("apps.packaged_injection_failed");
	MessageBox(Localization::Get(messageKey), Localization::Get(_T("dialog.drop_failed_title")),
		MB_OK | MB_ICONERROR);
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
	if (!m_processesExpanded) SetProcessesExpanded(TRUE);
	std::vector<DWORD> processIds;
	if (processId)
		processIds.push_back(processId);
	return SelectProcessesByPid(processIds);
}

BOOL CPage3::IsBrowserCandidateHooked(const BrowserLaunchWatch::Identity& identity) const
{
	HookProcessIdentityInfo record = {};
	return m_processRegistry && m_processRegistry->Get(identity.pid, identity.time, &record) &&
		record.hookState == PROCESS_HOOK_STATE_SUCCEEDED;
}

static std::vector<BrowserLaunchWatch::Node> ReadBrowserNodes(
	const ProxyProcessIdentity::Snapshot& snapshot, const std::wstring& path, DWORD sessionId,
	unsigned* unreadable = NULL)
{
	std::vector<BrowserLaunchWatch::Node> nodes;
	if (unreadable) *unreadable = 0;
	if (!snapshot.complete) return nodes;
	const std::wstring name = path.substr(path.find_last_of(L"\\/") + 1);
	const BOOL modern = IsVistaOrLater();
	ProcessImagePath::Resolver resolver;
	if (modern) resolver.Refresh();
	for (const auto& process : snapshot.processes)
	{
		if (!process.creationTime || process.sessionId != sessionId || _wcsicmp(process.name.c_str(), name.c_str())) continue;
		std::wstring actualPath;
		if (modern)
		{
			if (!ProcessImagePath::Query(process.pid, actualPath))
			{
				if (unreadable) ++*unreadable;
				continue;
			}
			actualPath = resolver.Convert(actualPath);
		}
		else
		{
			ProcessCommandLine::Handle handle(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process.pid));
			TCHAR buffer[MAX_PATH] = {};
			if (!handle.value || !ProcessCommandLine::SameLifetime(handle.value, process.creationTime) ||
				!GetProcessFullPath(handle.value, buffer, _countof(buffer)))
			{
				if (unreadable) ++*unreadable;
				continue;
			}
			actualPath = buffer;
		}
		if (_wcsicmp(actualPath.c_str(), path.c_str())) continue;
		std::wstring commandLine;
		const auto role = ProcessCommandLine::Query(process.pid, process.creationTime, commandLine) ?
			BrowserLaunchWatch::Classify(commandLine) : BrowserLaunchWatch::Unknown;
		nodes.push_back({ {process.pid, process.creationTime}, process.parentPid, process.sessionId, actualPath, role });
	}
	// Path queries use a PID. Discard exited/reused identities after enrichment.
	ProxyProcessIdentity::Snapshot after;
	ProxyProcessIdentity::QuerySnapshot(after);
	nodes.erase(std::remove_if(nodes.begin(), nodes.end(), [&](const BrowserLaunchWatch::Node& node) {
		return !BrowserLaunchWatch::Matches(after, node.identity);
	}), nodes.end());
	return nodes;
}

BrowserLaunchWatch::Observation CPage3::CaptureBrowserCandidates(LPCTSTR path)
{
	BrowserLaunchWatch::Observation observation;
	if (!BrowserLaunchWatch::Supported(path) || !m_processRegistry ||
		theApp.GetAutomationOptions().enabled || !g_MainTab || !g_MainTab->IsProxyRunning()) return observation;
	TCHAR fullPath[MAX_PATH];
	const DWORD length = GetFullPathName(path, _countof(fullPath), fullPath, NULL);
	if (!length || length >= _countof(fullPath)) return observation;
	ProxyProcessIdentity::Snapshot snapshot;
	if (!ProxyProcessIdentity::QuerySnapshot(snapshot))
	{
		g_MainTab->AddLogText(0, Localization::Get(_T("browser_reuse.log_scan_failed")));
		return observation;
	}
	bool foundSession = false;
	for (const auto& process : snapshot.processes)
	{
		if (process.pid != GetCurrentProcessId()) continue;
		observation.sessionId = process.sessionId;
		foundSession = true;
		break;
	}
	if (!foundSession) return observation;
	observation.path = fullPath;
	// Keep already-hooked roots too: their existing/restarted network service may not be hooked.
	unsigned unreadable = 0;
	for (const auto& instance : BrowserLaunchWatch::Instances(ReadBrowserNodes(snapshot, observation.path, observation.sessionId, &unreadable)))
		observation.candidates.push_back(instance.main.identity);
	g_MainTab->AddLogText(0, Localization::Format(_T("browser_reuse.log_candidates"),
		fullPath, static_cast<unsigned>(observation.candidates.size()), unreadable));
	return observation;
}

void CPage3::WatchBrowserLaunch(BrowserLaunchWatch::Observation observation,
	DWORD pid, ULONGLONG time, DWORD started)
{
	if (!pid || !time || observation.candidates.empty()) return;
	observation.launched = { pid, time };
	observation.started = started;
	m_browserLaunches.push_back(observation);
	SetTimer(TIMER_BROWSER_LAUNCH, 250, NULL);
}

void CPage3::CheckBrowserLaunches()
{
	if (m_showingBrowserWarning) return;
	if (!g_MainTab || !g_MainTab->IsProxyRunning())
	{
		ClearBrowserNotifications();
		KillTimer(TIMER_BROWSER_LAUNCH);
		return;
	}
	if (!m_browserLaunches.empty())
	{
		ProxyProcessIdentity::Snapshot snapshot;
		ProxyProcessIdentity::QuerySnapshot(snapshot);
		const auto hooked = [this](const BrowserLaunchWatch::Identity& identity) { return IsBrowserCandidateHooked(identity); };
		for (size_t index = 0; index < m_browserLaunches.size();)
		{
			std::vector<BrowserLaunchWatch::Identity> candidates;
			const auto result = BrowserLaunchWatch::Evaluate(m_browserLaunches[index], GetTickCount(), snapshot, candidates);
			if (result == BrowserLaunchWatch::Pending) { ++index; continue; }
			auto observation = m_browserLaunches[index];
			m_browserLaunches.erase(m_browserLaunches.begin() + index);
			if (result != BrowserLaunchWatch::Suggest)
			{
				g_MainTab->AddLogText(0, Localization::Format(_T("browser_reuse.log_discarded"), observation.path.c_str()));
				continue;
			}
			const auto instances = BrowserLaunchWatch::IncompleteInstances(
				ReadBrowserNodes(snapshot, observation.path, observation.sessionId), candidates, hooked);
			if (instances.empty())
			{
				g_MainTab->AddLogText(0, Localization::Format(_T("browser_reuse.log_resolved"), observation.path.c_str()));
				continue;
			}
			g_MainTab->AddLogText(0, Localization::Format(_T("browser_reuse.log_risk"), observation.path.c_str()));
			observation.candidates.clear();
			for (const auto& instance : instances) observation.candidates.push_back(instance.main.identity);
			// Merge repeated launches into the same still-visible notification only
			// when the browser lifetime is shared. A restarted browser is a new event.
			bool merged = false;
			for (auto& notice : m_browserNotifications)
			{
				if (notice.sessionId != observation.sessionId || _wcsicmp(notice.path.c_str(), observation.path.c_str())) continue;
				bool overlap = false;
				for (const auto& a : notice.candidates)
					for (const auto& b : observation.candidates) overlap |= a.pid == b.pid && a.time == b.time;
				if (!overlap) continue;
				for (const auto& identity : observation.candidates)
				{
					const auto found = std::find_if(notice.candidates.begin(), notice.candidates.end(),
						[&](const BrowserLaunchWatch::Identity& old) { return old.pid == identity.pid && old.time == identity.time; });
					if (found == notice.candidates.end()) notice.candidates.push_back(identity);
				}
				merged = true;
				break;
			}
			if (!merged) m_browserNotifications.push_back(observation);
		}
	}
	if (!m_browserNotificationActive && !m_browserNotifications.empty())
	{
		const auto& notice = m_browserNotifications.front();
		const CString name(notice.path.substr(notice.path.find_last_of(L"\\/") + 1).c_str());
		m_browserNotificationActive = TRUE;
		CProxyLaneDlg* owner = static_cast<CProxyLaneDlg*>(GetTopLevelParent());
		if (!owner || !owner->ShowBrowserNotification(name)) DismissBrowserNotification();
	}
	// Waiting for a notification click/timeout does not poll system processes.
	if (m_browserLaunches.empty() && (m_browserNotificationActive || m_browserNotifications.empty()))
		KillTimer(TIMER_BROWSER_LAUNCH);
}

void CPage3::DismissBrowserNotification()
{
	if (!m_browserNotificationActive) return;
	m_browserNotificationActive = FALSE;
	if (!m_browserNotifications.empty()) m_browserNotifications.erase(m_browserNotifications.begin());
	if (!m_browserNotifications.empty()) SetTimer(TIMER_BROWSER_LAUNCH, 250, NULL);
}

void CPage3::ClearBrowserNotifications()
{
	const BOOL active = m_browserNotificationActive;
	m_browserNotificationActive = FALSE;
	m_browserNotifications.clear();
	m_browserLaunches.clear();
	if (active)
	{
		CProxyLaneDlg* owner = static_cast<CProxyLaneDlg*>(GetTopLevelParent());
		if (owner) owner->HideBrowserNotification();
	}
}

void CPage3::OpenBrowserNotification()
{
	if (!m_browserNotificationActive || m_browserNotifications.empty()) return;
	const auto observation = m_browserNotifications.front();
	DismissBrowserNotification();
	static_cast<CProxyLaneDlg*>(GetTopLevelParent())->HideBrowserNotification();
	CWnd* owner = GetTopLevelParent();
	if (!owner || !owner->IsWindowEnabled() || m_showingBrowserWarning || m_terminating ||
		m_btnWindowFinder.IsTracking() || !g_MainTab || !g_MainTab->IsProxyRunning()) return;
	ProxyProcessIdentity::Snapshot snapshot;
	ProxyProcessIdentity::QuerySnapshot(snapshot);
	if (!snapshot.complete)
	{
		MessageBox(Localization::Get(_T("browser_reuse.check_failed")),
			Localization::Get(_T("browser_reuse.title")), MB_OK | MB_ICONINFORMATION);
		return;
	}
	const auto hooked = [this](const BrowserLaunchWatch::Identity& identity) { return IsBrowserCandidateHooked(identity); };
	const auto candidates = observation.candidates;
	const auto nodes = ReadBrowserNodes(snapshot, observation.path, observation.sessionId);
	const auto instances = BrowserLaunchWatch::IncompleteInstances(nodes, candidates, hooked);
	if (instances.empty())
	{
		MessageBox(Localization::Get(_T("browser_reuse.resolved")),
			Localization::Get(_T("browser_reuse.title")), MB_OK | MB_ICONINFORMATION);
		return;
	}
	CString details;
	const CString name(observation.path.substr(observation.path.find_last_of(L"\\/") + 1).c_str());
	const auto append = [&](const BrowserLaunchWatch::Identity& identity, LPCTSTR role, bool child) {
		if (child) details += _T("   ");
		details += Localization::Format(_T("browser_reuse.process"), static_cast<LPCTSTR>(name),
			identity.pid, static_cast<LPCTSTR>(Localization::Get(role)), static_cast<LPCTSTR>(Localization::Get(hooked(identity) ?
				_T("browser_reuse.hooked") : _T("browser_reuse.unhooked"))));
	};
	for (const auto& instance : instances)
	{
		append(instance.main.identity, instance.main.role == BrowserLaunchWatch::Main ?
			_T("browser_reuse.main") : _T("browser_reuse.unknown_root"), false);
		for (const auto& network : instance.networks) append(network, _T("browser_reuse.network"), true);
		if (instance.networks.empty()) details += Localization::Get(_T("browser_reuse.unknown_network"));
		details += _T("\r\n");
	}
	m_showingBrowserWarning = TRUE;
	CBrowserReuseDialog dialog(name, details, owner);
	const INT_PTR choice = dialog.DoModal();
	if (choice == IDC_BROWSER_REUSE_TERMINATE || choice == IDC_BROWSER_REUSE_PROXY)
	{
		// Freeze the scope to the main/network identities actually shown. Do
		// not add new children or another browser instance after the user clicks.
		std::vector<BrowserLaunchWatch::Identity> targets;
		for (const auto& instance : instances)
		{
			targets.push_back(instance.main.identity);
			targets.insert(targets.end(), instance.networks.begin(), instance.networks.end());
		}
		g_MainTab->HideTransientStatus();
		ApplyBrowserProcessAction(name, targets, choice == IDC_BROWSER_REUSE_TERMINATE);
	}
	if (choice == IDOK)
	{
		g_MainTab->HideTransientStatus();
		CancelLaunchSelection();
		g_MainTab->SelectPage(CMainTab::PAGE_APPLICATIONS);
		UpdatePslist(FALSE);
		ProxyProcessIdentity::Snapshot current;
		ProxyProcessIdentity::QuerySnapshot(current);
		std::vector<DWORD> selected;
		const auto remaining = BrowserLaunchWatch::IncompleteInstances(
			ReadBrowserNodes(current, observation.path, observation.sessionId), candidates, hooked);
		for (const auto& instance : remaining)
		{
			std::vector<BrowserLaunchWatch::Identity> related = instance.networks;
			related.push_back(instance.main.identity);
			for (const auto& candidate : related)
			{
				const auto row = m_processSortData.find(candidate.pid);
				if (row != m_processSortData.end() && row->second.startTimeValue == candidate.time)
					selected.push_back(candidate.pid);
			}
		}
		m_ListCtrl.SetItemState(-1, 0, LVIS_SELECTED | LVIS_FOCUSED);
		SelectProcessesByPid(selected);
		SetDlgItemText(IDC_STATIC_PAGE_SUBTITLE, Localization::Get(selected.empty() ?
			_T("browser_reuse.gone") : _T("browser_reuse.selected")));
	}
	m_showingBrowserWarning = FALSE;
}

void CPage3::ApplyBrowserProcessAction(const CString& name,
	const std::vector<BrowserLaunchWatch::Identity>& targets, BOOL terminate)
{
	CWnd* owner = GetTopLevelParent();
	const CString title = Localization::Get(terminate ? _T("browser_reuse.terminate") : _T("browser_reuse.proxy"));
	ProxyProcessIdentity::Snapshot snapshot;
	if (!ProxyProcessIdentity::QuerySnapshot(snapshot))
	{
		owner->MessageBox(Localization::Get(_T("page3.read_failed")), title, MB_OK | MB_ICONWARNING);
		return;
	}
	std::vector<BrowserLaunchWatch::Identity> active;
	int skipped = 0;
	for (const auto& target : targets)
	{
		if (!BrowserLaunchWatch::Matches(snapshot, target) || (!terminate && IsBrowserCandidateHooked(target)))
			++skipped;
		else active.push_back(target);
	}
	if (terminate && !active.empty())
	{
		CString names;
		for (size_t i = 0; i < active.size() && i < 10; ++i)
		{
			CString line;
			line.Format(_T("%s (PID %lu)\r\n"), static_cast<LPCTSTR>(name), active[i].pid);
			names += line;
		}
		if (active.size() > 10) names += _T("...\r\n");
		if (owner->MessageBox(Localization::Format(_T("page3.end_confirm"),
			static_cast<int>(active.size()), static_cast<LPCTSTR>(names)), title,
			MB_YESNO | MB_DEFBUTTON2 | MB_ICONWARNING) != IDYES) return;
	}
	std::vector<DWORD> errors;
	if (terminate)
	{
		std::vector<ProcessActions::TerminationTarget> exact;
		for (const auto& target : active) exact.push_back({ target.pid, target.time });
		errors = ProcessActions::TerminateExactProcesses(exact);
	}
	else if (!active.empty())
	{
		char pipe[MAX_PATH] = {};
		IProxyReceptionCentre* prc = g_GlobalProxy ? g_GlobalProxy->GetPRCInstance() : NULL;
		if (!g_MainTab->IsProxyRunning() || !prc || !prc->GetPRCPipeName(pipe, MAX_PATH))
		{
			owner->MessageBox(Localization::Get(_T("page3.start_proxy_first")), title, MB_OK | MB_ICONWARNING);
			return;
		}
		for (const auto& target : active)
		{
			SetLastError(ERROR_SUCCESS);
			const BOOL hooked = HookProcess(target.pid, pipe, target.time);
			const DWORD error = GetLastError();
			errors.push_back(hooked ? ERROR_SUCCESS : (error ? error : ERROR_GEN_FAILURE));
		}
	}
	int succeeded = 0, failed = 0;
	CString failures;
	for (size_t i = 0; i < errors.size(); ++i)
	{
		if (!errors[i]) ++succeeded;
		else if (++failed <= 10) failures += Localization::Format(_T("page3.end_error"),
			static_cast<LPCTSTR>(name), active[i].pid, errors[i]);
	}
	CString summary = Localization::Format(_T("page3.result_summary"),
		static_cast<int>(targets.size()), succeeded, failed, skipped);
	if (skipped) summary += _T("\r\n") + Localization::Get(_T("browser_reuse.skipped"));
	if (failed) summary += _T("\r\n\r\n") + failures;
	summary += _T("\r\n\r\n") + Localization::Get(terminate ?
		_T("browser_reuse.restart") : _T("browser_reuse.connections"));
	owner->MessageBox(summary, title, MB_OK | (failed ? MB_ICONWARNING : MB_ICONINFORMATION));
	UpdatePslist(FALSE);
}

void CPage3::CancelLaunchSelection()
{
	KillTimer(TIMER_LAUNCHED_PROCESS);
	m_launchedProcessId = 0;
	m_launchedProcessTime = 0;
}

BOOL CPage3::TrySelectLaunchedProcess()
{
	if (!IsWindowVisible() || !m_ListCtrl.IsWindowVisible())
	{
		CancelLaunchSelection();
		return FALSE;
	}
	std::map<DWORD, _myPROCESSINFO>::const_iterator process =
		m_processSortData.find(m_launchedProcessId);
	if (process == m_processSortData.end() || !process->second.hasStartTime ||
		process->second.startTimeValue != m_launchedProcessTime) return FALSE;
	const DWORD pid = m_launchedProcessId;
	CancelLaunchSelection();
	return SelectProcessByPid(pid);
}

void CPage3::RefreshLaunchedProcess(DWORD pid, HANDLE process, ULONGLONG creationTime)
{
	CancelLaunchSelection();
	// Launching from another page or a background instance must not switch
	// pages, enumerate hidden processes, or schedule a later forced selection.
	if (!IsWindowVisible() || !m_ListCtrl.IsWindowVisible()) return;
	HANDLE queried = NULL;
	if (pid && !process && !creationTime)
	{
		queried = OpenProcess(0x1000, FALSE, pid);
		if (!queried) queried = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
		process = queried;
	}
	if (!creationTime && process) creationTime = ProcessActions::CreationTime(process);
	if (queried) CloseHandle(queried);
	m_launchedProcessId = pid;
	m_launchedProcessTime = creationTime;
	m_launchSelectionTick = GetTickCount();
	UpdatePslist(FALSE);
	if (!pid || !creationTime || TrySelectLaunchedProcess()) CancelLaunchSelection();
	else SetTimer(TIMER_LAUNCHED_PROCESS, 150, NULL);
}

BOOL CPage3::SelectProcessesByPid(const std::vector<DWORD>& processIds)
{
	if (!m_processesExpanded) SetProcessesExpanded(TRUE);
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
	// The selection tip only makes sense while the process list is shown.
	SetDlgItemText(
		IDC_STATIC_PAGE_SUBTITLE,
		Localization::Get(m_processesExpanded ? _T("page3.list_tip") : _T("page3.subtitle")));
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
	if (nPsCount < 0) return 0; // Keep the previous list when the snapshot fails.
	if (bRefresh)
	{
		m_ListCtrl.DeleteAllItems();
		m_displayedStartTimes.clear();
	}

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

	if (customDraw->nmcd.dwDrawStage != CDDS_ITEMPREPAINT)
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

	HookProcessIdentityInfo identity = { 0 };
	if (m_processRegistry && m_processRegistry->Get(pid, process->second.startTimeValue, &identity))
	{
		switch (identity.hookState)
		{
		case PROCESS_HOOK_STATE_SUCCEEDED:
			customDraw->clrText = RGB(112, 48, 160);
			break;
		case PROCESS_HOOK_STATE_FAILED:
			customDraw->clrText = RGB(200, 0, 0);
			break;
		case PROCESS_HOOK_STATE_PENDING:
			customDraw->clrText = RGB(180, 110, 0);
			break;
		default:
			break;
		}
	}

	// The background age hint is meaningful only in the default process-tree
	// order.  Hook-result text color remains visible in every sort mode.
	if (m_sortState != PROCESS_SORT_NONE)
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
			Localization::Get(_T("status.proxy_stopped")), MB_ICONERROR);
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
	if (nIDEvent == TIMER_BROWSER_LAUNCH) { CheckBrowserLaunches(); return; }
	if (nIDEvent == TIMER_LAUNCH_PANEL)
	{
		if (IsWindowVisible() && !m_recentLaunching) RefreshLaunchPanel();
		return;
	}
	// TODO: 在此添加消息处理程序代码和/或调用默认值
	switch(nIDEvent)
	{
	case TIMER_PROCESS_REGISTRY:
		if (m_processRegistry) m_processRegistry->PruneExited();
		break;
	case TIMER_PSLIST:
		{
			// Hidden pages and a hidden top-level window still receive WM_TIMER.
			// Avoid enumerating every process while the list cannot be seen.
			if (IsWindowVisible() && m_processesExpanded && !m_btnWindowFinder.IsTracking() && !m_terminating)
				UpdatePslist(FALSE);
		}
		break;
	case TIMER_LAUNCHED_PROCESS:
		if (!IsWindowVisible() || !m_ListCtrl.IsWindowVisible())
		{
			CancelLaunchSelection();
			break;
		}
		if (!m_terminating && m_launchedProcessId)
		{
			if (GetTickCount() - m_launchSelectionTick >= 2000) CancelLaunchSelection();
			else { UpdatePslist(FALSE); TrySelectLaunchedProcess(); }
		}
		break;
	}

}

void CPage3::OnPageActivated()
{
	if (!m_btnWindowFinder.IsTracking())
		UpdatePslist(TRUE);
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
		CPage2* page2 = g_MainTab ? g_MainTab->GetPage2() : NULL;
		if (page2)
			page2->LogProcessEvent(lphnpi->dwProcessId, lphnpi->szAppPath,
				_T("log.process_skipped"));
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
	bRet = InjectDll(hProcess, hnpi.dwProcessId, hnpi.dwThreadId, szPipeName);
	pPage2->OnChildInjectionResult(&hnpi, bRet > 0);

	CloseHandle(hProcess);
	return bRet > 0;
}

void CPage3::LogNewProxyTask(const LPPRCClient lpC)
{

}

void CPage3::LogText(LPCWSTR lpText)
{
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
	BOOL strictInjection,
	AppLaunchElevationMode elevationMode,
	const CString& initialArguments,
	const CString& initialWorkingDirectory)
{
	if (!fileName || !fileName[0])
		return APP_LAUNCH_INVALID_TARGET;

	STARTUPINFO si = {0};
	si.cb = sizeof(si);

	PROCESS_INFORMATION pi = {0};
	int ret;

	HookNewProcessInfo hnpi = {0};
	TCHAR szTargetPath[MAX_PATH+1024];
	CString launchArguments = initialArguments;
	TCHAR szBaseDir[MAX_PATH] = _T("\0");
	PVOID WowRedirOldValue = NULL;

	ZeroMemory(szTargetPath, sizeof(szTargetPath));
	if (initialWorkingDirectory.GetLength() >= _countof(szBaseDir))
		return APP_LAUNCH_INVALID_TARGET;
	_tcscpy(szBaseDir, initialWorkingDirectory);

	myWow64DisableWow64FsRedirection(&WowRedirOldValue);

	if (IsLnk(fileName))
	{
		InstalledApplications::Application shortcut;
		if (!InstalledApplications::ResolveShortcut(fileName, shortcut))
		{
			myWow64RevertWow64FsRedirection(WowRedirOldValue);
			return APP_LAUNCH_INVALID_TARGET;
		}
		launchArguments = shortcut.arguments;
		if (shortcut.IsPackaged())
		{
			for (size_t i = 0; i < extraArguments.size(); ++i)
			{
				if (!launchArguments.IsEmpty()) launchArguments += _T(" ");
				launchArguments += QuoteCommandLineArgument(extraArguments[i]);
			}
			myWow64RevertWow64FsRedirection(WowRedirOldValue);
			return LaunchPackagedAppById(shortcut.aumid, launchArguments);
		}
		if (shortcut.path.GetLength() >= _countof(szTargetPath) ||
			shortcut.workingDirectory.GetLength() >= _countof(szBaseDir))
		{
			myWow64RevertWow64FsRedirection(WowRedirOldValue);
			return APP_LAUNCH_INVALID_TARGET;
		}
		_tcscpy(szTargetPath, shortcut.path);
		_tcscpy(szBaseDir, shortcut.workingDirectory);
	}else
	{
		_tcsncpy(szTargetPath, fileName, _countof(szTargetPath) - 1);
		if (!szBaseDir[0]) GetAppFolderPath(szTargetPath, szBaseDir);
	}

	DWORD targetAttributes = GetFileAttributes(szTargetPath);
	if (!szTargetPath[0] ||
		targetAttributes == INVALID_FILE_ATTRIBUTES ||
		(targetAttributes & FILE_ATTRIBUTE_DIRECTORY))
	{
		myWow64RevertWow64FsRedirection(WowRedirOldValue);
		return APP_LAUNCH_INVALID_TARGET;
	}

	CString manifestDir;
	if (PackagedAppSupport::IsPackagedAppPath(szTargetPath, manifestDir))
	{
		AppLaunchResult pkgResult = LaunchPackagedAppAndProxy(szTargetPath, manifestDir, extraArguments, launchArguments);
		if (pkgResult == APP_LAUNCH_SUCCESS)
		{
			myWow64RevertWow64FsRedirection(WowRedirOldValue);
			return APP_LAUNCH_SUCCESS;
		}
		if (pkgResult == APP_LAUNCH_PACKAGED_INJECTION_FAILED)
		{
			myWow64RevertWow64FsRedirection(WowRedirOldValue);
			return pkgResult;
		}
		// 若包模式激活失败（如未向系统注册/解压目录），自动降级尝试下方常规 CreateProcess
	}

	if (!szBaseDir[0])
		GetAppFolderPath(szTargetPath, szBaseDir);

	CString commandLine = QuoteCommandLineArgument(szTargetPath);
	if (!launchArguments.IsEmpty())
	{
		commandLine += _T(" ");
		commandLine += launchArguments;
	}
	for (size_t i = 0; i < extraArguments.size(); ++i)
	{
		commandLine += _T(" ");
		commandLine += QuoteCommandLineArgument(extraArguments[i]);
	}

	const BrowserLaunchWatch::Observation browserObservation = CaptureBrowserCandidates(szTargetPath);
	if (elevationMode == APP_LAUNCH_ELEVATION_FORCE_ADMIN)
	{
		myWow64RevertWow64FsRedirection(WowRedirOldValue);
		DWORD launchedPid;
		ULONGLONG launchedTime;
		const DWORD started = GetTickCount();
		AppLaunchResult result = LaunchElevatedAndProxy(
			GetSafeHwnd(),
			szTargetPath,
			commandLine,
			szBaseDir[0] == 0 ? NULL : szBaseDir, launchedPid, launchedTime);
		if (result == APP_LAUNCH_SUCCESS)
		{
			WatchBrowserLaunch(browserObservation, launchedPid, launchedTime, started);
			RefreshLaunchedProcess(launchedPid, NULL, launchedTime);
		}
		return result;
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
			DWORD launchedPid;
			ULONGLONG launchedTime;
			const DWORD started = GetTickCount();
			AppLaunchResult result = LaunchElevatedAndProxy(
				GetSafeHwnd(),
				szTargetPath,
				commandLine,
				szBaseDir[0] == 0 ? NULL : szBaseDir, launchedPid, launchedTime);
			if (result == APP_LAUNCH_SUCCESS)
			{
				WatchBrowserLaunch(browserObservation, launchedPid, launchedTime, started);
				RefreshLaunchedProcess(launchedPid, NULL, launchedTime);
			}
			return result;
		}
#ifndef APPMODEL_ERROR_NO_PACKAGE
#define APPMODEL_ERROR_NO_PACKAGE 15700L
#endif
		if (createProcessError == APPMODEL_ERROR_NO_PACKAGE)
		{
			CString fallbackManifestDir;
			if (PackagedAppSupport::FindManifestDir(szTargetPath, fallbackManifestDir))
			{
				AppLaunchResult pkgResult = LaunchPackagedAppAndProxy(
					szTargetPath,
					fallbackManifestDir,
					extraArguments,
					launchArguments);
				if (pkgResult == APP_LAUNCH_SUCCESS)
				{
					return APP_LAUNCH_SUCCESS;
				}
				if (pkgResult == APP_LAUNCH_PACKAGED_INJECTION_FAILED)
					return pkgResult;
			}
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

    hnpi.processCreateTime = ProcessActions::CreationTime(pi.hProcess);
    RecordProcessCreation(g_GlobalProxy ? g_GlobalProxy->GetTlsControl() : NULL,
        MakeProcessCreationNotice(hnpi), "launcher");
	BOOL injectionSucceeded = InjectNewProcess(&hnpi);
	if (!injectionSucceeded && strictInjection)
	{
		TerminateProcess(pi.hProcess, AUTOMATION_EXIT_INJECTION_FAILED);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return APP_LAUNCH_INJECTION_FAILED;
	}

	const DWORD resumedAt = GetTickCount();
	if (ResumeThread(pi.hThread) == (DWORD)-1)
	{
		TerminateProcess(pi.hProcess, AUTOMATION_EXIT_CREATE_PROCESS_FAILED);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return APP_LAUNCH_CREATE_PROCESS_FAILED;
	}

	if (injectionSucceeded)
		WatchBrowserLaunch(browserObservation, pi.dwProcessId, hnpi.processCreateTime, resumedAt);
	RefreshLaunchedProcess(pi.dwProcessId, pi.hProcess);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	return APP_LAUNCH_SUCCESS;
}

AppLaunchResult CPage3::LaunchPackagedAppAndProxy(
	LPCTSTR fileName,
	const CString& manifestDir,
	const std::vector<CString>& extraArguments,
	const CString& initialArguments)
{
	CString aumid, packageFullName;
	if (!PackagedAppSupport::ResolvePackagedAppAumid(fileName, manifestDir, aumid, packageFullName))
		return APP_LAUNCH_INVALID_TARGET;
	CString arguments = initialArguments;
	for (size_t i = 0; i < extraArguments.size(); ++i)
	{
		if (!arguments.IsEmpty()) arguments += _T(" ");
		arguments += QuoteCommandLineArgument(extraArguments[i]);
	}
	return LaunchPackagedAppById(aumid, arguments);
}

AppLaunchResult CPage3::LaunchPackagedAppById(LPCTSTR aumid, const CString& arguments, AppLauncherResult* outcome)
{
	if (outcome) { ZeroMemory(outcome,sizeof(*outcome)); outcome->error=ERROR_GEN_FAILURE; }
	if (!aumid || !aumid[0]) return APP_LAUNCH_INVALID_TARGET;
	TCHAR szModulePath[MAX_PATH] = { 0 };
	if (GetModuleFileName(NULL, szModulePath, _countof(szModulePath)))
	{
		szModulePath[_countof(szModulePath) - 1] = _T('\0');
		TCHAR szAppDir[MAX_PATH] = { 0 };
		GetAppFolderPath(szModulePath, szAppDir);
		PackagedAppSupport::EnsureAppContainerAccess(szAppDir);
	}

	char szPipeName[MAX_PATH] = "\0";
	IProxyReceptionCentre *pPRC = NULL;
	if (!g_GlobalProxy || !(pPRC = g_GlobalProxy->GetPRCInstance()) || !pPRC->GetPRCPipeName(szPipeName, MAX_PATH))
	{
		return APP_LAUNCH_CREATE_PROCESS_FAILED;
	}

	// 激活前解析函数；局部变量允许界面与 PRC 工作线程并发调用。
	typedef LONG (NTAPI *pfnNtSuspendProcess)(HANDLE ProcessHandle);
	typedef LONG (NTAPI *pfnNtResumeProcess)(HANDLE ProcessHandle);
	pfnNtSuspendProcess s_pfnNtSuspendProcess = NULL;
	pfnNtResumeProcess s_pfnNtResumeProcess = NULL;
	HMODULE hNtdll = GetModuleHandle(_T("ntdll.dll"));
	if (hNtdll)
	{
		s_pfnNtSuspendProcess = reinterpret_cast<pfnNtSuspendProcess>(
			GetProcAddress(hNtdll, "NtSuspendProcess"));
		s_pfnNtResumeProcess = reinterpret_cast<pfnNtResumeProcess>(
			GetProcAddress(hNtdll, "NtResumeProcess"));
	}

	DWORD processId = 0;
	HRESULT hr = PackagedAppSupport::ActivatePackagedApp(
		aumid,
		arguments.IsEmpty() ? NULL : static_cast<LPCTSTR>(arguments),
		&processId);

	if (FAILED(hr) || processId == 0)
	{
		if(outcome) outcome->error=FAILED(hr)?static_cast<DWORD>(hr):ERROR_GEN_FAILURE;
		return APP_LAUNCH_CREATE_PROCESS_FAILED;
	}
	if(outcome) { outcome->error=0; outcome->processId=processId; outcome->hookError=ERROR_GEN_FAILURE; }

	HANDLE hTargetProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	if (!hTargetProc)
	{
		if (outcome) outcome->hookError=GetLastError();
		if (!outcome) RefreshLaunchedProcess(processId);
		return APP_LAUNCH_PACKAGED_INJECTION_FAILED;
	}
	const ULONGLONG creationTime = ProcessActions::CreationTime(hTargetProc);
    if(outcome) {
        HookProcessIdentityInfo identity={};
        if(g_GlobalProxy->GetProcessRegistry()->Get(processId,creationTime,&identity) &&
            identity.hookState==PROCESS_HOOK_STATE_SUCCEEDED) {
            outcome->hookError=0; CloseHandle(hTargetProc); return APP_LAUNCH_SUCCESS;
        }
    }

    // Activation can return an existing process; do not invent a creation event.
    HookNewProcessInfo activated = {};
    activated.dwProcessId = processId;
    activated.processCreateTime = creationTime;
    ResolveChildAppPath(hTargetProc, activated.szAppPath, _countof(activated.szAppPath));
    activated.szAppPath[_countof(activated.szAppPath)-1] = L'\0';
    RecordProcessCreation(g_GlobalProxy->GetTlsControl(), MakeProcessCreationNotice(activated), "launcher_activation");
	// Authorization must finish before freezing the app. It used to query a
	// busy synchronous server pipe, stranding the app while the GUI waited.
	if (!pPRC->AuthorizeProcessPipeAccess(hTargetProc))
	{
		const DWORD error = GetLastError();
		CloseHandle(hTargetProc);
		if (outcome) outcome->hookError=error;
		CString text;
		text.Format(_T("Packaged app pipe authorization failed: PID %lu, error %lu.\r\n"), processId, error);
		g_GlobalProxy->GetLogInstance()->LogText(text);
		if (!outcome) RefreshLaunchedProcess(processId, NULL, creationTime);
		return APP_LAUNCH_PACKAGED_INJECTION_FAILED;
	}
    if(outcome && !ShouldProxyChildProcess(&activated)) {
        outcome->hookError=ERROR_ACCESS_DISABLED_BY_POLICY;
        CloseHandle(hTargetProc); return APP_LAUNCH_PACKAGED_INJECTION_FAILED;
    }
	CScopedProcessSuspension suspension(hTargetProc, s_pfnNtSuspendProcess, s_pfnNtResumeProcess);

	// This is post-activation attachment: minimize delay, but do not claim that
	// the application could not execute or send traffic before this point.
	BOOL injected = FALSE;
	const int maxAttempts = 15;
	for (int attempt = 0; attempt < maxAttempts; ++attempt)
	{
		if (HookProcess(processId, szPipeName))
		{
			injected = TRUE;
			break;
		}

		Sleep(attempt < 3 ? 5 : 15);
	}

	if (!suspension.Resume())
	{
		CString text;
		text.Format(_T("Failed to resume packaged app: PID %lu, NTSTATUS 0x%08lX.\r\n"),
			processId, static_cast<ULONG>(suspension.ResumeStatus()));
		g_GlobalProxy->GetLogInstance()->LogText(text);
		injected = FALSE;
	}

    if(outcome && injected) {
        // Wait only after resuming original threads: they may hold the loader lock.
        injected=FALSE; DWORD started=GetTickCount(); outcome->hookError=WAIT_TIMEOUT;
        while(GetTickCount()-started<10000) {
            HookProcessIdentityInfo identity={};
            if(g_GlobalProxy->GetProcessRegistry()->Get(processId,creationTime,&identity)) {
                if(identity.hookState==PROCESS_HOOK_STATE_SUCCEEDED) { injected=TRUE; outcome->hookError=0; break; }
                if(identity.hookState==PROCESS_HOOK_STATE_FAILED) { outcome->hookError=identity.hookError; break; }
            }
            if(WaitForSingleObject(hTargetProc,25)==WAIT_OBJECT_0) { outcome->hookError=ERROR_PROCESS_ABORTED; break; }
        }
    }
	if (!outcome) RefreshLaunchedProcess(processId, NULL, creationTime);
	if (!injected)
	{
		return APP_LAUNCH_PACKAGED_INJECTION_FAILED;
	}

	return APP_LAUNCH_SUCCESS;
}


BOOL CPage3::GetAppLauncherHostInfo(AppLauncherHostInfo* info)
{
    OSVERSIONINFO version={sizeof(version)};
    if(!info || !GetVersionEx(&version) || version.dwMajorVersion<6 ||
        (version.dwMajorVersion==6 && version.dwMinorVersion<2)) return FALSE;
    ZeroMemory(info,sizeof(*info));
    DWORD length=GetModuleFileNameW(NULL,info->executable,MAX_PATH);
    if(!length || length>=MAX_PATH) { ZeroMemory(info,sizeof(*info)); return FALSE; }
    info->version=1; info->processId=GetCurrentProcessId();
    info->creationTime=AppLauncherProtocol::ProcessTime(GetCurrentProcess());
    return info->creationTime!=0;
}

BOOL CPage3::LaunchAppFromShell(const AppLauncherRequest& request, AppLauncherResult& result)
{
    LaunchPackagedAppById(request.aumid,CString(),&result);
    CString message;
    message.Format(L"AppsFolder activation: %s, requester PID %lu, target PID %lu, launch error 0x%08lX, Hook error %lu.\r\n",
        request.aumid,request.parentPid,result.processId,result.error,result.hookError);
    ATLTRACE(L"%s", static_cast<LPCWSTR>(message));
    if (!result.error && !result.hookError && g_GlobalProxy)
    {
        auto processName = [&](DWORD pid, ULONGLONG creationTime, LPCWSTR fallback) {
            HookProcessIdentityInfo identity = {};
            if (!g_GlobalProxy->GetProcessRegistry()->Get(pid, creationTime, &identity) || !identity.szAppPath[0])
                return CString(fallback);
            CString path(identity.szAppPath);
            return path.Mid(path.ReverseFind(L'\\') + 1);
        };
        CString source = processName(request.parentPid, request.parentCreationTime,
            Localization::Get(_T("log.unknown_process")));
        CString target = processName(result.processId, 0, request.aumid);
        message = Localization::Format(_T("log.app_launch_success"),
            static_cast<LPCTSTR>(source), request.parentPid,
            static_cast<LPCTSTR>(target), result.processId);
    }
    if(g_GlobalProxy) g_GlobalProxy->GetLogInstance()->LogText(message);
    return TRUE;
}
