#include "stdafx.h"
#include "PRCUdpServer.h"
#include "ProxyReceptionCentre.h"
#include "GlobalProxy.h"
#include "ProxyLog.h"
#include "ProxySettings.h"
#include <psapi.h>

#pragma comment(lib, "psapi.lib")

static LPWSTR GetUdpProcessName(CProxyReceptionCentre *receptionCentre,
	DWORD processId, LPWSTR processPath, DWORD pathLength)
{
	if (!processPath || pathLength == 0)
		return NULL;
	processPath[0] = L'\0';

	if (!receptionCentre->GetProcessIdentity(processId, processPath, pathLength))
	{
		HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
			FALSE, processId);
		if (process)
		{
			GetModuleFileNameExW(process, NULL, processPath, pathLength);
			processPath[pathLength - 1] = L'\0';
			CloseHandle(process);
		}
	}

	LPWSTR name = wcsrchr(processPath, L'\\');
	return name ? name + 1 : processPath;
}

CPRCUdpServer::CPRCUdpServer(CProxyReceptionCentre *pPRC)
	: CPRCXServer(pPRC)
	, m_ProxyTaskMgr(pPRC)
{
	m_hWnd = NULL;
}

CPRCUdpServer::~CPRCUdpServer(void)
{
	if(m_hWnd)
		DestroyWnd();
}

BOOL CPRCUdpServer::InitWnd()
{
	WNDCLASS wndclass;
	memset(&wndclass, 0, sizeof(wndclass));
	wndclass.lpfnWndProc = CPRCUdpServer::WndProc;
	wndclass.lpszClassName = _T("CPRCUdpServer");

	RegisterClass(&wndclass);

	m_hWnd = CreateWindow(_T("CPRCUdpServer"), _T("PRCUdpServer"),
		WS_OVERLAPPEDWINDOW, 0, 0, 0, 0,
		NULL, NULL, NULL, NULL);

	if(m_hWnd == NULL)
		return FALSE;

	SetWindowLongPtr(m_hWnd, GWLP_USERDATA, (LONG_PTR)this);

	return TRUE;
};

BOOL CPRCUdpServer::DestroyWnd()
{
	if(m_hWnd)
	{
		if(::DestroyWindow(m_hWnd))
		{
			m_hWnd = NULL;
			return TRUE;
		}
	}
	return FALSE;
}

LRESULT CALLBACK CPRCUdpServer::WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	CPRCUdpServer *_this = (CPRCUdpServer*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
	switch(uMsg)
	{
	case WM_PRC_REG_CLIENT:
		{
			LPPRCClient lpPRCClient = (LPPRCClient)lParam;
			return _this->OnLocalThreadRegister(lpPRCClient);
		}
		break;
	case WM_PRC_UNREG_CLIENT:
		{
			LPPRCClient lpPRCClient = (LPPRCClient)lParam;
			return _this->OnLocalThreadUnregister(lpPRCClient);
		}
		break;

	default:
		break;
	}
	return DefWindowProc(hWnd, uMsg, wParam, lParam);
}


BOOL CPRCUdpServer::StartupServer()
{
	return InitWnd();
}


BOOL CPRCUdpServer::ShutdownServer()
{
	m_ProxyTaskMgr.RemoveAllTasks();
	return DestroyWnd();
}

BOOL CPRCUdpServer::OnRegister(LPPRCClient lpPRCClient)
{
	return SendMessage(m_hWnd, WM_PRC_REG_CLIENT, 0, (LPARAM)lpPRCClient);
}

BOOL CPRCUdpServer::OnLocalThreadRegister(LPPRCClient lpPRCClient)
{
	ATLASSERT(m_hWnd);

	ProxyInfo pisetting;
	memset(&pisetting, 0, sizeof(pisetting));

	IProxySettings *pProxySettings = m_pGlobalProxy->GetSettingsInstance();
	if(!pProxySettings->GetProxyInfo(lpPRCClient, &pisetting))
	{
		PrintText(_T("Failed to get proxy information.\r\n"));
		return FALSE;
	}

	if(!m_ProxyTaskMgr.OnNewTask(lpPRCClient, &pisetting))
	{
		PrintText(_T("Failed to add UDP proxy task.\r\n"));
		return FALSE;
	}

	LogNewProxyTask(lpPRCClient);

	WCHAR processPath[MAX_PATH];
	LPWSTR processName = GetUdpProcessName(m_pPRC, lpPRCClient->dwPid,
		processPath, _countof(processPath));
	LPCTSTR tag = pisetting.GetProxyType() == PROXYTYPE_NOPROXY
		? _T("[Bypassed] ") : _T("[Hooked] ");
	if (lpPRCClient->IsDNValid())
	{
#ifdef _UNICODE
		PrintText(_T("%sUDP PID: %d(%s), send to: %S:%d\r\n"), tag,
			lpPRCClient->dwPid, processName ? processName : L"",
			lpPRCClient->szDomainName, lpPRCClient->dstAddr.GetPort());
#else
		PrintText(_T("%sUDP PID: %d(%s), send to: %s:%d\r\n"), tag,
			lpPRCClient->dwPid, processName ? processName : L"",
			lpPRCClient->szDomainName, lpPRCClient->dstAddr.GetPort());
#endif
	}
	else
	{
		DWORD ip = lpPRCClient->dstAddr.GetdwIP();
		const BYTE *bytes = (const BYTE*)&ip;
		PrintText(_T("%sUDP PID: %d(%s), send to: %u.%u.%u.%u:%d\r\n"),
			tag, lpPRCClient->dwPid, processName ? processName : L"",
			bytes[0], bytes[1], bytes[2], bytes[3],
			lpPRCClient->dstAddr.GetPort());
	}
	return TRUE;
}


INT CPRCUdpServer::OnUnregister(LPPRCClient lpPRCClient)
{
	return SendMessage(m_hWnd, WM_PRC_UNREG_CLIENT, 0, (LPARAM)lpPRCClient);
}


BOOL CPRCUdpServer::OnLocalThreadUnregister(LPPRCClient lpPRCClient)
{
	return m_ProxyTaskMgr.KillTasks(lpPRCClient);
}

IProxyTaskMgr *CPRCUdpServer::GetPTMInstance()
{
	return &m_ProxyTaskMgr;
}

BOOL CPRCUdpServer::GetUDPPortState(UDPLocalProxyAddrInfo *pLPAI)
{
	return m_ProxyTaskMgr.GetUDPPortState(pLPAI);
}
