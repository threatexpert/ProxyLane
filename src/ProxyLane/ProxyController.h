#pragma once

#include "..\ProxyLaneHook\ProxyModule.h"

class CProxyController
{
public:
	CProxyController();

	BOOL Start(
		IProxySettings* settings,
		IProxyLog* logView,
		IProxyLog* processView);
	BOOL Stop();
	BOOL IsRunning() const;
	CString GetLastErrorText() const { return m_lastError; }

private:
	CString m_lastError;
};
