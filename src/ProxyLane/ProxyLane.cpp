// ProxyLane.cpp : 定义应用程序的类行为。
//

#include "stdafx.h"
#include "ConfigStorage.h"
#include "ProxyLane.h"
#include "ProxyLaneDlg.h"
#include "Page3.h"
#include "AutomationOptions.h"
#include "LaunchShortcut.h"
#include "Localization.h"
#include "AppVersion.h"
#include "AppLauncher.h"
#include "UpdateHelper.h"

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
	, m_requiresProfileCommandOwnership(FALSE)
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

void CProxyLaneApp::SignalAutomationReady()
{
	ReleaseAutomationLaunchGate();
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

BOOL CProxyLaneApp::PrepareAutomationCommandReceiver()
{
	if (!m_automationOptions.enabled)
		return TRUE;
	if (!m_profileCommandBroker.AcquireLaunchGate(m_automationOptions.profileName))
	{
		m_automationExitCode = AUTOMATION_EXIT_COMMAND_FORWARD_FAILED;
		return FALSE;
	}

	int forwardedExitCode = AUTOMATION_EXIT_COMMAND_FORWARD_FAILED;
	ProfileCommandForwardResult forwardResult = m_profileCommandBroker.Forward(
		m_automationOptions, forwardedExitCode);
	if (forwardResult == PROFILE_COMMAND_HANDLED)
	{
		m_automationExitCode = forwardedExitCode;
		m_profileCommandBroker.ReleaseLaunchGate();
		return FALSE;
	}
	if (forwardResult == PROFILE_COMMAND_TRANSPORT_FAILED)
	{
		m_automationExitCode = forwardedExitCode;
		m_profileCommandBroker.ReleaseLaunchGate();
		return FALSE;
	}

	m_requiresProfileCommandOwnership = TRUE;
	return TRUE;
}

BOOL CProxyLaneApp::ActivateProfileCommandServer(
	LPCTSTR profileName,
	HWND notifyWindow)
{
	return m_profileCommandBroker.StartServer(profileName, notifyWindow);
}

void CProxyLaneApp::DeactivateProfileCommandServer()
{
	m_profileCommandBroker.StopServer();
}

BOOL CProxyLaneApp::IsProfileCommandServerActive(LPCTSTR profileName) const
{
	return m_profileCommandBroker.IsServerActive(profileName);
}

void CProxyLaneApp::ReleaseAutomationLaunchGate()
{
	m_profileCommandBroker.ReleaseLaunchGate();
}

int CProxyLaneApp::ExitInstance()
{
	m_profileCommandBroker.StopServer();
	m_profileCommandBroker.ReleaseLaunchGate();
	if (m_configImport)
	{
		m_configImport->FinishAfterShutdown();
		m_configImport.reset();
	}
	LaunchShortcut::ReportFailure(m_automationOptions, m_automationExitCode);
	CWinApp::ExitInstance();
	return m_automationExitCode;
}


// 唯一的一个 CProxyLaneApp 对象

CProxyLaneApp theApp;


// CProxyLaneApp 初始化

BOOL CProxyLaneApp::InitInstance()
{
	// A real process for callers to wait/resume, without UI, configuration writes,
	// profile forwarding, or the normal x86-to-x64 bootstrap.
	DWORD launcherExitCode=0;
	if (RunInternalAppLauncher(GetCommandLineW(),launcherExitCode)) {
		m_automationExitCode=static_cast<int>(launcherExitCode);
		return FALSE;
	}
	// Windowless update download, possibly injected with the active profile.
	if (UpdateHelper::Run(GetCommandLineW(), launcherExitCode)) {
		m_automationExitCode=static_cast<int>(launcherExitCode);
		return FALSE;
	}
	// Lets the setup program wait until every ProxyLane window has exited. The
	// handle is intentionally kept open for the lifetime of the process.
	CreateMutex(NULL, FALSE, _T("ProxyLaneRunning"));
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
#ifndef _WIN64
	// On 64-bit Windows this process only forwards to ProxyLane64.exe, which sets
	// up storage itself; creating the INI here would hide the first run from it.
	const bool forwardsToX64 = IsWow64(GetCurrentProcess()) != FALSE;
#else
	const bool forwardsToX64 = false;
#endif
	const bool storageReady = forwardsToX64 || ConfigStorage::Initialize();
	const DWORD storageError = GetLastError();
	Localization::Initialize();
	if (!storageReady)
	{
		CString error = ConfigStorage::ErrorText(storageError);
		AfxMessageBox(Localization::Format(L"storage.save_failed", (LPCTSTR)error, (LPCTSTR)ConfigStorage::Path()), MB_ICONERROR);
		return FALSE;
	}

	AfxEnableControlContainer();

	// OLE drag-and-drop requires the UI thread to remain in the STA selected by
	// AfxOleInit.  A second MTA initialization only fails with
	// RPC_E_CHANGED_MODE and never changed the apartment in earlier builds.
	if (!AfxOleInit())
		return FALSE;

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
	if (m_automationOptions.showHelp)
	{
		::MessageBox(
			NULL,
			Localization::Get(_T("automation.command_line_help")),
			Localization::Get(_T("automation.command_line_help_title")),
			MB_OK | MB_ICONINFORMATION | MB_TASKMODAL);
		return FALSE;
	}

#ifndef _WIN64
	if (IsWow64(GetCurrentProcess()))
	{
		if (m_automationOptions.enabled)
		{
			int forwardedExitCode = AUTOMATION_EXIT_COMMAND_FORWARD_FAILED;
			ProfileCommandForwardResult forwardResult =
				m_profileCommandBroker.Forward(m_automationOptions, forwardedExitCode);
			if (forwardResult == PROFILE_COMMAND_HANDLED ||
				forwardResult == PROFILE_COMMAND_TRANSPORT_FAILED)
			{
				m_automationExitCode = forwardedExitCode;
				return FALSE;
			}
		}

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
			// The child reports shortcut failures; do not show the same error twice.
			m_automationOptions.shortcut = FALSE;
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

	if (!PrepareAutomationCommandReceiver())
		return FALSE;

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
