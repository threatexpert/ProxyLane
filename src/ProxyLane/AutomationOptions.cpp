#include "stdafx.h"
#include "AutomationOptions.h"

#include <shellapi.h>

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
	BOOL targetArguments = FALSE;
	CString unknownOption;

	for (int i = 1; i < argc; ++i)
	{
		CString argument(argv[i]);
		if (targetArguments)
		{
			options.targetArguments.push_back(argument);
			continue;
		}
		argument.MakeLower();

		if (argument == _T("--"))
		{
			targetArguments = TRUE;
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
	if (!options.initialArguments.IsEmpty()) commandLine += L" --arguments " + QuoteCommandLineArgument(options.initialArguments);
	if (!options.workingDirectory.IsEmpty()) commandLine += L" --working-directory " + QuoteCommandLineArgument(options.workingDirectory);
	if (options.elevated) commandLine += L" --elevated";
	if (options.packaged) commandLine += L" --packaged";
	if (options.shortcut) commandLine += L" --shortcut";

	if (bootstrapEventName && bootstrapEventName[0])
	{
		commandLine += _T(" --bootstrap-event ");
		commandLine += QuoteCommandLineArgument(bootstrapEventName);
	}

	if (!options.targetArguments.empty())
	{
		commandLine += _T(" --");
		for (size_t i = 0; i < options.targetArguments.size(); ++i)
		{
			commandLine += _T(" ");
			commandLine += QuoteCommandLineArgument(options.targetArguments[i]);
		}
	}
	return commandLine;
}
