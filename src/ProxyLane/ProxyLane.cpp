// ProxyLane.cpp : 定义应用程序的类行为。
//

#include "stdafx.h"
#include "ProxyLane.h"
#include "ProxyLaneDlg.h"
#include "Page3.h"
#include "AutomationOptions.h"
#include "Localization.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CProxyLaneApp

BEGIN_MESSAGE_MAP(CProxyLaneApp, CWinApp)
	ON_COMMAND(ID_HELP, &CWinApp::OnHelp)
END_MESSAGE_MAP()


// CProxyLaneApp 构造

CProxyLaneApp::CProxyLaneApp()
	: m_automationExitCode(AUTOMATION_EXIT_SUCCESS)
{
	// TODO: 在此处添加构造代码，
	// 将所有重要的初始化放置在 InitInstance 中
}

static BOOL CreateBootstrapEventName(CString& eventName)
{
	GUID guid;
	if (CoCreateGuid(&guid) != S_OK)
		return FALSE;

	WCHAR guidText[64] = { 0 };
	if (!StringFromGUID2(guid, guidText, _countof(guidText)))
		return FALSE;

	eventName.Format(_T("Local\\ProxyLaneAutomation%s"), guidText);
	return TRUE;
}

static BOOL InitializeChildGuardMarker()
{
	GUID guid;
	if (CoCreateGuid(&guid) != S_OK)
		return FALSE;

	const BYTE *bytes = reinterpret_cast<const BYTE *>(&guid);
	WCHAR variableName[64] = L"PLCG";
	WCHAR *writeAt = variableName + 4;
	for (size_t i = 0; i < sizeof(guid); ++i)
	{
		// Letters only keep the name valid on every supported Windows version.
		*writeAt++ = static_cast<WCHAR>(L'A' + (bytes[i] >> 4));
		*writeAt++ = static_cast<WCHAR>(L'A' + (bytes[i] & 0x0f));
	}
	*writeAt = L'\0';

	FILETIME created, exited, kernel, user;
	if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user))
		return FALSE;
	const ULONGLONG generationTime =
		(static_cast<ULONGLONG>(created.dwHighDateTime) << 32) |
		created.dwLowDateTime;
	return SetProxyLaneChildGuardInfo(variableName, generationTime);
}

void CProxyLaneApp::SignalAutomationReady()
{
	if (m_automationOptions.bootstrapEventName.IsEmpty())
		return;

	HANDLE eventHandle = OpenEvent(
		EVENT_MODIFY_STATE,
		FALSE,
		m_automationOptions.bootstrapEventName);
	if (eventHandle)
	{
		SetEvent(eventHandle);
		CloseHandle(eventHandle);
	}
}

int CProxyLaneApp::ExitInstance()
{
	CWinApp::ExitInstance();
	return m_automationExitCode;
}


// 唯一的一个 CProxyLaneApp 对象

CProxyLaneApp theApp;


// CProxyLaneApp 初始化

BOOL CProxyLaneApp::InitInstance()
{
	// 如果一个运行在 Windows XP 上的应用程序清单指定要
	// 使用 ComCtl32.dll 版本 6 或更高版本来启用可视化方式，
	//则需要 InitCommonControlsEx()。否则，将无法创建窗口。
	INITCOMMONCONTROLSEX InitCtrls;
	InitCtrls.dwSize = sizeof(InitCtrls);
	// 将它设置为包括所有要在应用程序中使用的
	// 公共控件类。
	InitCtrls.dwICC = ICC_WIN95_CLASSES | ICC_LINK_CLASS;
	InitCommonControlsEx(&InitCtrls);

	CWinApp::InitInstance();
	Localization::Initialize();

	AfxEnableControlContainer();

	// 标准初始化
	// 如果未使用这些功能并希望减小
	// 最终可执行文件的大小，则应移除下列
	// 不需要的特定初始化例程
	// 更改用于存储设置的注册表项
	// TODO: 应适当修改该字符串，
	// 例如修改为公司或组织名
	SetRegistryKey(_T("ProxyLane"));

	AfxOleInit();
	CoInitializeEx(NULL, COINIT_MULTITHREADED);

	CString parseError;
	if (!ParseAutomationOptions(
		GetCommandLineW(),
		m_automationOptions,
		parseError))
	{
		CString message = _T("ProxyLane automation command line error: ");
		message += parseError;
		message += _T("\r\n");
		OutputDebugString(message);
		m_automationExitCode = AUTOMATION_EXIT_INVALID_COMMAND_LINE;
		return FALSE;
	}

#ifndef _WIN64
	if (IsWow64(GetCurrentProcess()))
	{
		CString strPath64;
		LPTSTR pathBuffer = strPath64.GetBuffer(MAX_PATH);
		const DWORD pathLength = ::GetModuleFileName(m_hInstance, pathBuffer, MAX_PATH);
		pathBuffer[MAX_PATH - 1] = _T('\0');
		strPath64.ReleaseBuffer();
		if (!pathLength || strPath64.GetLength() < 4)
		{
			m_automationExitCode = AUTOMATION_EXIT_ARCH_FORWARD_FAILED;
			return FALSE;
		}

		strPath64 = strPath64.Mid(0, strPath64.GetLength() - 4) + _T("64.exe");

		CString forwardedArguments(m_lpCmdLine);
		CString bootstrapEventName;
		HANDLE bootstrapEvent = NULL;
		if (m_automationOptions.enabled)
		{
			if (!CreateBootstrapEventName(bootstrapEventName))
			{
				m_automationExitCode = AUTOMATION_EXIT_ARCH_FORWARD_FAILED;
				return FALSE;
			}

			bootstrapEvent = CreateEvent(
				NULL,
				TRUE,
				FALSE,
				bootstrapEventName);
			if (!bootstrapEvent)
			{
				m_automationExitCode = AUTOMATION_EXIT_ARCH_FORWARD_FAILED;
				return FALSE;
			}
			forwardedArguments = BuildAutomationCommandLine(
				m_automationOptions,
				bootstrapEventName);
		}

		SHELLEXECUTEINFO ShExecInfo = { 0 };
		ShExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);
		ShExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
		ShExecInfo.hwnd = NULL;
		ShExecInfo.lpVerb = NULL;
		ShExecInfo.lpFile = strPath64;
		ShExecInfo.lpParameters = forwardedArguments;
		ShExecInfo.lpDirectory = NULL;
		ShExecInfo.nShow = m_automationOptions.enabled ? SW_HIDE : SW_SHOW;
		ShExecInfo.hInstApp = NULL;
		if (ShellExecuteEx(&ShExecInfo))
		{
			if (m_automationOptions.enabled)
			{
				HANDLE handles[] = { bootstrapEvent, ShExecInfo.hProcess };
				DWORD waitResult = WaitForMultipleObjects(
					_countof(handles),
					handles,
					FALSE,
					INFINITE);
				if (waitResult == WAIT_OBJECT_0)
				{
					m_automationExitCode = AUTOMATION_EXIT_SUCCESS;
				}
				else if (waitResult == WAIT_OBJECT_0 + 1)
				{
					DWORD childExitCode = AUTOMATION_EXIT_ARCH_FORWARD_FAILED;
					GetExitCodeProcess(ShExecInfo.hProcess, &childExitCode);
					m_automationExitCode = (int)childExitCode;
				}
				else
				{
					m_automationExitCode = AUTOMATION_EXIT_ARCH_FORWARD_FAILED;
				}
			}
			else
			{
				WaitForSingleObject(ShExecInfo.hProcess, INFINITE);
				DWORD childExitCode = 0;
				if (GetExitCodeProcess(ShExecInfo.hProcess, &childExitCode))
					m_automationExitCode = (int)childExitCode;
			}
			CloseHandle(ShExecInfo.hProcess);
			if (bootstrapEvent)
				CloseHandle(bootstrapEvent);
			return FALSE;
		}

		if (bootstrapEvent)
			CloseHandle(bootstrapEvent);
		m_automationExitCode = AUTOMATION_EXIT_ARCH_FORWARD_FAILED;
		return FALSE;
	}
#endif

	// Generate once per ProxyLane.exe lifetime.  Proxy start/stop cycles keep
	// the same marker so PRC can recognize descendants from this app instance.
	if (!InitializeChildGuardMarker())
		OutputDebugString(_T("ProxyLane child guard initialization failed.\r\n"));

	CProxyLaneDlg dlg;
	m_pMainWnd = &dlg;
	INT_PTR nResponse = dlg.DoModal();
	if (nResponse == IDOK)
	{
		// TODO: 在此处放置处理何时用“确定”来关闭
		//  对话框的代码
	}
	else if (nResponse == IDCANCEL)
	{
		// TODO: 在此放置处理何时用“取消”来关闭
		//  对话框的代码
	}

	// 由于对话框已关闭，所以将返回 FALSE 以便退出应用程序，
	//  而不是启动应用程序的消息泵。
	return FALSE;
}
