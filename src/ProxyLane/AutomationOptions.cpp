#include "stdafx.h"
#include "AutomationOptions.h"

#include <shellapi.h>

// argumentIndex 是系统解析结果中真正的 "--" 的下标，不是字符位置。
// 在空白处尝试截取前缀，由 CommandLineToArgvW 验证边界；不自行解释
// 引号或反斜杠。成功返回原文中应用参数的起点，失败返回 NULL。
static LPCWSTR RawTailAfterArgument(LPCWSTR commandLine, int argumentIndex)
{
	if (!commandLine || argumentIndex < 1) return NULL;
	int argc = 0;
	LPWSTR* argv = CommandLineToArgvW(commandLine, &argc);
	if (!argv) return NULL;
	if (argumentIndex >= argc || wcscmp(argv[argumentIndex], L"--") != 0)
	{
		LocalFree(argv);
		return NULL;
	}

	const WCHAR marker[] = L"PL_RAW_TAIL_MARKER";
	const int length = lstrlenW(commandLine);
	for (int offset = 0; offset <= length; ++offset)
	{
		// 只枚举候选边界，不判断空白是否在引号内；连续空白仅检查一次。
		if (offset < length && commandLine[offset] != L' ' && commandLine[offset] != L'\t') continue;
		if (offset > 0 && (commandLine[offset - 1] == L' ' || commandLine[offset - 1] == L'\t')) continue;
		CString probe(commandLine, offset);
		probe += L" ";
		probe += marker;
		int probeArgc = 0;
		LPWSTR* probeArgv = CommandLineToArgvW(probe, &probeArgc);
		if (!probeArgv)
		{
			LocalFree(argv);
			return NULL;
		}

		// 必须恰好是原来的 argv[0..argumentIndex] 加一个独立 marker。
		// 同时校验数量、每项内容和位置，因此 marker 不需要全局唯一。
		bool matched = probeArgc == argumentIndex + 2;
		if (matched)
		{
			for (int i = 0; i <= argumentIndex; ++i)
			{
				if (wcscmp(probeArgv[i], argv[i]) != 0) { matched = false; break; }
			}
		}
		if (matched) matched = wcscmp(probeArgv[argumentIndex + 1], marker) == 0;
		LocalFree(probeArgv);
		if (matched)
		{
			LocalFree(argv);
			LPCWSTR tail = commandLine + offset;
			while (*tail == L' ' || *tail == L'\t') ++tail;
			return tail; // 后面的文本不再拆分、去引号或重新转义。
		}
	}
	LocalFree(argv);
	return NULL;
}

BOOL ExpandLaunchEnvironment(const CString& source, CString& expanded)
{
	// One Windows expansion pass: unknown variables remain literal. Do not
	// expand while saving/decoding links, so they remain portable across users.
	DWORD required = ExpandEnvironmentStringsW(source, NULL, 0);
	while (required && required <= 32767)
	{
		std::vector<WCHAR> buffer(required);
		const DWORD written = ExpandEnvironmentStringsW(source, buffer.data(), required);
		if (!written) return FALSE;
		if (written <= required) { expanded = buffer.data(); return TRUE; }
		required = written;
	}
	if (required) SetLastError(ERROR_FILENAME_EXCED_RANGE);
	return FALSE;
}

static BOOL ReadOptionValue(
	int& index,
	int argc,
	LPWSTR* argv,
	CString& value,
	CString& errorMessage,
	LPCTSTR optionName)
{
	if (index + 1 >= argc)
	{
		errorMessage.Format(_T("%s requires a value"), optionName);
		return FALSE;
	}

	value = argv[++index];
	if (value.IsEmpty())
	{
		errorMessage.Format(_T("%s cannot be empty"), optionName);
		return FALSE;
	}
	return TRUE;
}

BOOL ParseAutomationOptions(
	LPCWSTR commandLine,
	AutomationOptions& options,
	CString& errorMessage)
{
	options = AutomationOptions();
	errorMessage.Empty();

	int argc = 0;
	LPWSTR* argv = CommandLineToArgvW(commandLine, &argc);
	if (!argv)
	{
		errorMessage = _T("CommandLineToArgvW failed");
		return FALSE;
	}
	for (int i = 1; i < argc; ++i)
	{
		CString argument(argv[i]);
		argument.MakeLower();
		if (argument == _T("--")) break;
		// Values are opaque; an application's argument may itself be "--help".
		if (argument == L"--profile" || argument == L"--run" || argument == L"--arguments" ||
			argument == L"--working-directory" || argument == L"--app-name" || argument == L"--bootstrap-event") { ++i; continue; }
		if (argument.CompareNoCase(_T("/?")) == 0 ||
			argument.CompareNoCase(_T("-?")) == 0 ||
			argument.CompareNoCase(_T("--help")) == 0)
		{
			options.showHelp = TRUE;
			LocalFree(argv);
			return TRUE;
		}
	}

	BOOL seenProfile = FALSE;
	BOOL seenRun = FALSE;
	BOOL seenBootstrapEvent = FALSE;
	BOOL seenArguments = FALSE, seenDirectory = FALSE, seenName = FALSE;
	CString unknownOption;

	for (int i = 1; i < argc; ++i)
	{
		CString argument(argv[i]);
		argument.MakeLower();

		if (argument == _T("--"))
		{
			LPCWSTR rawTail = RawTailAfterArgument(commandLine, i);
			if (!rawTail)
			{
				errorMessage = L"Cannot locate the application argument boundary";
				LocalFree(argv);
				return FALSE;
			}
			const CString tail(rawTail);
			if (!options.initialArguments.IsEmpty() && !tail.IsEmpty()) options.initialArguments += L" ";
			options.initialArguments += tail;
			break;
		}
		else if (argument.CompareNoCase(_T("--auto")) == 0)
		{
			if (options.enabled)
			{
				errorMessage = _T("--auto was specified more than once");
				LocalFree(argv);
				return FALSE;
			}
			options.enabled = TRUE;
		}
		else if (argument.CompareNoCase(_T("--profile")) == 0)
		{
			if (seenProfile ||
				!ReadOptionValue(i, argc, argv, options.profileName,
					errorMessage, _T("--profile")))
			{
				if (seenProfile)
					errorMessage = _T("--profile was specified more than once");
				LocalFree(argv);
				return FALSE;
			}
			seenProfile = TRUE;
		}
		else if (argument.CompareNoCase(_T("--run")) == 0)
		{
			if (seenRun ||
				!ReadOptionValue(i, argc, argv, options.targetPath,
					errorMessage, _T("--run")))
			{
				if (seenRun)
					errorMessage = _T("--run was specified more than once");
				LocalFree(argv);
				return FALSE;
			}
			seenRun = TRUE;
		}
		else if (argument == L"--elevated" || argument == L"--packaged" || argument == L"--shortcut")
		{
			BOOL& flag = argument == L"--elevated" ? options.elevated :
				(argument == L"--packaged" ? options.packaged : options.shortcut);
			if (flag) { errorMessage = L"Duplicate option: " + argument; LocalFree(argv); return FALSE; }
			flag = TRUE;
		}
		else if (argument == L"--arguments" || argument == L"--working-directory" || argument == L"--app-name")
		{
			BOOL& seen = argument == L"--arguments" ? seenArguments : (argument == L"--app-name" ? seenName : seenDirectory);
			CString& value = argument == L"--arguments" ? options.initialArguments : (argument == L"--app-name" ? options.applicationName : options.workingDirectory);
			if (seen || !ReadOptionValue(i, argc, argv, value, errorMessage, argument))
			{
				if (seen) errorMessage = L"Duplicate option: " + argument;
				LocalFree(argv); return FALSE;
			}
			seen = TRUE;
		}
		else if (argument.CompareNoCase(_T("--bootstrap-event")) == 0)
		{
			if (seenBootstrapEvent ||
				!ReadOptionValue(i, argc, argv, options.bootstrapEventName,
					errorMessage, _T("--bootstrap-event")))
			{
				if (seenBootstrapEvent)
					errorMessage = _T("--bootstrap-event was specified more than once");
				LocalFree(argv);
				return FALSE;
			}
			seenBootstrapEvent = TRUE;
		}
		else if (options.enabled)
		{
			errorMessage.Format(_T("Unknown option: %s"), (LPCTSTR)argument);
			LocalFree(argv);
			return FALSE;
		}
		else if (argument.Left(2) == _T("--"))
		{
			unknownOption = argument;
		}
	}

	LocalFree(argv);

	if (!options.enabled)
		return TRUE;

	if (!unknownOption.IsEmpty())
	{
		errorMessage.Format(_T("Unknown option: %s"), (LPCTSTR)unknownOption);
		return FALSE;
	}

	if (!seenProfile || !seenRun)
	{
		errorMessage = _T("--auto requires --profile and --run");
		return FALSE;
	}

	return TRUE;
}

CString QuoteCommandLineArgument(const CString& argument)
{
	if (argument.IsEmpty())
		return _T("\"\"");

	if (argument.FindOneOf(_T(" \t\"")) < 0)
		return argument;

	CString quoted(_T("\""));
	int backslashes = 0;
	for (int i = 0; i < argument.GetLength(); ++i)
	{
		TCHAR c = argument[i];
		if (c == _T('\\'))
		{
			++backslashes;
			continue;
		}

		if (c == _T('"'))
		{
			for (int j = 0; j < backslashes * 2 + 1; ++j)
				quoted += _T('\\');
			quoted += _T('"');
			backslashes = 0;
			continue;
		}

		for (int j = 0; j < backslashes; ++j)
			quoted += _T('\\');
		backslashes = 0;
		quoted += c;
	}

	for (int j = 0; j < backslashes * 2; ++j)
		quoted += _T('\\');
	quoted += _T('"');
	return quoted;
}

CString BuildAutomationCommandLine(
	const AutomationOptions& options,
	LPCTSTR bootstrapEventName)
{
	CString commandLine;
	commandLine = _T("--auto --profile ");
	commandLine += QuoteCommandLineArgument(options.profileName);
	commandLine += _T(" --run ");
	commandLine += QuoteCommandLineArgument(options.targetPath);
	if (!options.applicationName.IsEmpty()) commandLine += L" --app-name " + QuoteCommandLineArgument(options.applicationName);
	if (!options.workingDirectory.IsEmpty()) commandLine += L" --working-directory " + QuoteCommandLineArgument(options.workingDirectory);
	if (options.elevated) commandLine += L" --elevated";
	if (options.packaged) commandLine += L" --packaged";
	if (options.shortcut) commandLine += L" --shortcut";

	if (bootstrapEventName && bootstrapEventName[0])
	{
		commandLine += _T(" --bootstrap-event ");
		commandLine += QuoteCommandLineArgument(bootstrapEventName);
	}

	if (!options.initialArguments.IsEmpty() || !options.targetArguments.empty())
	{
		commandLine += _T(" --");
		if (!options.initialArguments.IsEmpty()) commandLine += L" " + options.initialArguments;
		for (size_t i = 0; i < options.targetArguments.size(); ++i)
		{
			commandLine += _T(" ");
			commandLine += QuoteCommandLineArgument(options.targetArguments[i]);
		}
	}
	return commandLine;
}
