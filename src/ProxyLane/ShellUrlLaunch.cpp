#include "stdafx.h"
#include "ShellUrlLaunch.h"
#include "AutomationOptions.h"
#include <shlwapi.h>
#include <shellapi.h>

#pragma comment(lib, "shlwapi.lib")

namespace ShellUrlLaunch
{
	bool IsWebUrl(const CString& target)
	{
		return target.Left(7).CompareNoCase(L"http://") == 0 ||
			target.Left(8).CompareNoCase(L"https://") == 0;
	}

	static bool Placeholder(const CString& value)
	{
		return value == L"%1" || value == L"%l" || value == L"%L";
	}

	HRESULT BuildCommand(const CString& url, const CString& executable,
		const CString& commandTemplate, CString& arguments)
	{
		arguments.Empty();
		if (!IsWebUrl(url)) return E_INVALIDARG;
		const int authority = url.Find(L"://") + 3;
		if (authority >= url.GetLength() || url[authority] == L'/' || url[authority] == L'?' || url[authority] == L'#')
			return E_INVALIDARG;
		// Raw quotes/control characters are not valid URI data. Escaped URI bytes
		// remain opaque, including percent sequences that resemble environment names.
		for (int i = 0; i < url.GetLength(); ++i)
			if (url[i] < L' ' || url[i] == L'"') return E_INVALIDARG;

		int count = 0;
		LPWSTR* argv = CommandLineToArgvW(commandTemplate, &count);
		if (!argv) return HRESULT_FROM_WIN32(GetLastError());
		std::vector<CString> tokens;
		for (int i = 0; i < count; ++i) tokens.push_back(argv[i]);
		LocalFree(argv);
		if (tokens.size() < 2) return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
		CString image;
		if (!ExpandLaunchEnvironment(tokens[0], image)) return HRESULT_FROM_WIN32(GetLastError());
		// An unquoted executable with spaces, an indirect launcher, or a different
		// executable from the association is not a command we can safely reproduce.
		if (image.CompareNoCase(executable)) return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
		const CString name(PathFindFileNameW(executable));
		if (!name.CompareNoCase(L"rundll32.exe") || !name.CompareNoCase(L"explorer.exe") ||
			!name.CompareNoCase(L"cmd.exe") || !name.CompareNoCase(L"powershell.exe"))
			return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);

		CString result;
		unsigned substitutions = 0;
		for (size_t i = 1; i < tokens.size(); ++i)
		{
			if (!result.IsEmpty()) result += L" ";
			const CString& token = tokens[i];
			if (token == L"--single-argument" || token == L"--single-argument=%1")
			{
				// Chromium consumes the raw remainder, not Windows argv quoting.
				// Do not put quotes around the URL or append arguments after it.
				const bool separate = token == L"--single-argument";
				if (substitutions || (separate ? i + 2 != tokens.size() || !Placeholder(tokens[i + 1]) : i + 1 != tokens.size()))
					return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
				result += separate ? L"--single-argument " : L"--single-argument=";
				result += url;
				++substitutions;
				break;
			}
			if (Placeholder(token)) { result += QuoteCommandLineArgument(url); ++substitutions; }
			else
			{
				CString expanded;
				if (!ExpandLaunchEnvironment(token, expanded)) return HRESULT_FROM_WIN32(GetLastError());
				// Reject unknown/embedded Shell substitutions instead of inventing semantics.
				if (expanded.Find(L'%') >= 0) return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
				result += QuoteCommandLineArgument(expanded);
			}
		}
		if (substitutions != 1) return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
		if (executable.GetLength() + result.GetLength() + 4 >= 32767)
			return HRESULT_FROM_WIN32(ERROR_FILENAME_EXCED_RANGE);
		arguments = result;
		return S_OK;
	}

	static HRESULT Query(ASSOCF flags, ASSOCSTR kind, LPCWSTR protocol, CString& value)
	{
		DWORD length = 32768;
		std::vector<WCHAR> buffer(length);
		HRESULT hr = AssocQueryStringW(flags, kind, protocol, L"open", buffer.data(), &length);
		if (hr == S_OK && buffer[0]) { value = buffer.data(); return S_OK; }
		return FAILED(hr) ? hr : HRESULT_FROM_WIN32(ERROR_NO_ASSOCIATION);
	}

	HRESULT Resolve(const CString& url, CString& executable, CString& arguments)
	{
		executable.Empty(); arguments.Empty();
		if (!IsWebUrl(url)) return S_FALSE;
		OSVERSIONINFO version = { sizeof(version) };
		if (!GetVersionEx(&version)) return HRESULT_FROM_WIN32(GetLastError());
		const bool modern = version.dwMajorVersion > 6 || (version.dwMajorVersion == 6 && version.dwMinorVersion >= 2);
		// ASSOCF_IS_PROTOCOL is Windows 8+. XP uses the original association API.
		const ASSOCF flags = static_cast<ASSOCF>(ASSOCF_NOTRUNCATE | (modern ? 0x1000 : 0));
		CString protocol = url.Left(url.Find(L':'));
		protocol.MakeLower();
		CString image, command, delegate;
		HRESULT hr = Query(flags, ASSOCSTR_EXECUTABLE, protocol, image);
		if (FAILED(hr)) return hr;
		hr = Query(flags, ASSOCSTR_COMMAND, protocol, command);
		if (FAILED(hr)) return hr;
		// A delegate can override the command's meaning. Do not bypass it silently.
		if (modern)
		{
			const HRESULT delegateResult = Query(flags, static_cast<ASSOCSTR>(18), protocol, delegate);
			if (delegateResult == S_OK) return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
			if (delegateResult != HRESULT_FROM_WIN32(ERROR_NO_ASSOCIATION) &&
				delegateResult != HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) && delegateResult != HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND))
				return delegateResult;
		}
		CString expanded;
		if (!ExpandLaunchEnvironment(image, expanded)) return HRESULT_FROM_WIN32(GetLastError());
		DWORD binary = 0;
		if (PathIsRelativeW(expanded) || !GetBinaryTypeW(expanded, &binary))
			return HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT);
		hr = BuildCommand(url, expanded, command, arguments);
		if (SUCCEEDED(hr)) executable = expanded;
		return hr;
	}
}
