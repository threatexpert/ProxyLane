#include "stdafx.h"
#include "ProxyLane.h"
#include "ProxyController.h"

IGlobalProxy* g_GlobalProxy = NULL;

CProxyController::CProxyController()
{
}

BOOL CProxyController::Start(
	IProxySettings* settings,
	IProxyLog* logView,
	IProxyLog* processView)
{
	if (g_GlobalProxy)
		return TRUE;

	g_GlobalProxy = GetGlobalProxyInstance();
	if (!g_GlobalProxy)
		return FALSE;

	IProxyLog* proxyLog = g_GlobalProxy->GetLogInstance();
	if (proxyLog)
	{
		if (logView)
			proxyLog->AddInstance(logView);
		if (processView)
			proxyLog->AddInstance(processView);
	}

	IProxySettings* proxySettings = g_GlobalProxy->GetSettingsInstance();
	if (proxySettings && settings)
		proxySettings->AddInstance(settings);

	if (g_GlobalProxy->EnableProxy())
		return TRUE;

	ReleaseGlobalProxyInstance();
	g_GlobalProxy = NULL;
	return FALSE;
}

BOOL CProxyController::Stop()
{
	if (!g_GlobalProxy)
		return TRUE;

	if (!g_GlobalProxy->DisableProxy())
		return FALSE;

	ReleaseGlobalProxyInstance();
	g_GlobalProxy = NULL;
	return TRUE;
}

BOOL CProxyController::IsRunning() const
{
	return g_GlobalProxy != NULL;
}
