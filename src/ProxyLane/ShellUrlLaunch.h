#pragma once

// Resolve in the helper, before forwarding, using the caller's user/environment.
// S_FALSE means this is not an HTTP(S) URL. Failure never invokes the Shell.
namespace ShellUrlLaunch
{
	bool IsWebUrl(const CString& target);
	HRESULT Resolve(const CString& url, CString& executable, CString& arguments);
	HRESULT BuildCommand(const CString& url, const CString& executable,
		const CString& commandTemplate, CString& arguments);
}
