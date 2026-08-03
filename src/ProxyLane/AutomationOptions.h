#pragma once

#include <vector>

enum AutomationExitCode
{
	AUTOMATION_EXIT_SUCCESS = 0,
	AUTOMATION_EXIT_INVALID_COMMAND_LINE = 2,
	AUTOMATION_EXIT_PROFILE_INVALID = 3,
	AUTOMATION_EXIT_PROXY_START_FAILED = 4,
	AUTOMATION_EXIT_TARGET_INVALID = 5,
	AUTOMATION_EXIT_CREATE_PROCESS_FAILED = 6,
	AUTOMATION_EXIT_INJECTION_FAILED = 7,
	AUTOMATION_EXIT_ARCH_FORWARD_FAILED = 8
};

struct AutomationOptions
{
	AutomationOptions()
		: enabled(FALSE)
	{
	}

	BOOL enabled;
	CString profileName;
	CString targetPath;
	std::vector<CString> targetArguments;
	CString bootstrapEventName;
};

BOOL ParseAutomationOptions(
	LPCWSTR commandLine,
	AutomationOptions& options,
	CString& errorMessage);

CString QuoteCommandLineArgument(const CString& argument);
CString BuildAutomationCommandLine(
	const AutomationOptions& options,
	LPCTSTR bootstrapEventName);
