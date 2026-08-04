#pragma once

#include <windows.h>
#include <stddef.h>

// The UI and elevated rundll32 exchange a fixed-version request encoded as ASCII hex.
// This preserves Unicode paths without parsing nested command-line quoting in the elevated host.

#define PROXYLANE_ELEVATED_REQUEST_MAGIC   0x4C454C50UL // "PLEL"
#define PROXYLANE_ELEVATED_REQUEST_VERSION 1

#define PROXYLANE_ELEVATED_TARGET_CCH      (MAX_PATH + 1024)
#define PROXYLANE_ELEVATED_COMMAND_CCH     4096
#define PROXYLANE_ELEVATED_DIRECTORY_CCH   MAX_PATH
#define PROXYLANE_ELEVATED_PIPE_CCH        128

enum ProxyLaneElevatedLaunchExitCode
{
	PROXYLANE_ELEVATED_SUCCESS = 0,
	PROXYLANE_ELEVATED_INVALID_REQUEST = 10,
	PROXYLANE_ELEVATED_NOT_ELEVATED = 11,
	PROXYLANE_ELEVATED_INVALID_TARGET = 12,
	PROXYLANE_ELEVATED_CREATE_FAILED = 13,
	PROXYLANE_ELEVATED_INJECTION_FAILED = 14,
	PROXYLANE_ELEVATED_RESUME_FAILED = 15,
	PROXYLANE_ELEVATED_INTERNAL_ERROR = 16
};

#pragma pack(push, 1)
struct ProxyLaneElevatedLaunchRequest
{
	DWORD magic;
	DWORD version;
	DWORD structureSize;
	WCHAR targetPath[PROXYLANE_ELEVATED_TARGET_CCH];
	WCHAR commandLine[PROXYLANE_ELEVATED_COMMAND_CCH];
	WCHAR workingDirectory[PROXYLANE_ELEVATED_DIRECTORY_CCH];
	CHAR pipeName[PROXYLANE_ELEVATED_PIPE_CCH];
};
#pragma pack(pop)

inline int ProxyLaneHexDigitValue(char value)
{
	if (value >= '0' && value <= '9')
		return value - '0';
	if (value >= 'a' && value <= 'f')
		return value - 'a' + 10;
	if (value >= 'A' && value <= 'F')
		return value - 'A' + 10;
	return -1;
}

inline BOOL ProxyLaneEncodeElevatedRequest(
	const ProxyLaneElevatedLaunchRequest& request,
	char* output,
	size_t outputSize)
{
	static const char digits[] = "0123456789ABCDEF";
	const size_t byteCount = sizeof(request);
	if (!output || outputSize < byteCount * 2 + 1)
		return FALSE;

	const BYTE* bytes = reinterpret_cast<const BYTE*>(&request);
	for (size_t index = 0; index < byteCount; ++index)
	{
		output[index * 2] = digits[(bytes[index] >> 4) & 0x0F];
		output[index * 2 + 1] = digits[bytes[index] & 0x0F];
	}
	output[byteCount * 2] = '\0';
	return TRUE;
}

inline BOOL ProxyLaneDecodeElevatedRequest(
	const char* input,
	ProxyLaneElevatedLaunchRequest* request)
{
	if (!input || !request)
		return FALSE;

	const size_t byteCount = sizeof(*request);
	if (strlen(input) != byteCount * 2)
		return FALSE;

	BYTE* bytes = reinterpret_cast<BYTE*>(request);
	for (size_t index = 0; index < byteCount; ++index)
	{
		const int high = ProxyLaneHexDigitValue(input[index * 2]);
		const int low = ProxyLaneHexDigitValue(input[index * 2 + 1]);
		if (high < 0 || low < 0)
			return FALSE;
		bytes[index] = static_cast<BYTE>((high << 4) | low);
	}
	return TRUE;
}

inline BOOL ProxyLaneHasTerminatorW(const WCHAR* value, size_t count)
{
	if (!value || count == 0)
		return FALSE;
	for (size_t index = 0; index < count; ++index)
	{
		if (value[index] == L'\0')
			return TRUE;
	}
	return FALSE;
}

inline BOOL ProxyLaneHasTerminatorA(const CHAR* value, size_t count)
{
	if (!value || count == 0)
		return FALSE;
	for (size_t index = 0; index < count; ++index)
	{
		if (value[index] == '\0')
			return TRUE;
	}
	return FALSE;
}

inline BOOL ProxyLaneValidateElevatedRequest(
	const ProxyLaneElevatedLaunchRequest& request)
{
	if (request.magic != PROXYLANE_ELEVATED_REQUEST_MAGIC ||
		request.version != PROXYLANE_ELEVATED_REQUEST_VERSION ||
		request.structureSize != sizeof(request))
	{
		return FALSE;
	}

	if (!ProxyLaneHasTerminatorW(request.targetPath, _countof(request.targetPath)) ||
		!ProxyLaneHasTerminatorW(request.commandLine, _countof(request.commandLine)) ||
		!ProxyLaneHasTerminatorW(request.workingDirectory, _countof(request.workingDirectory)) ||
		!ProxyLaneHasTerminatorA(request.pipeName, _countof(request.pipeName)))
	{
		return FALSE;
	}

	if (!request.targetPath[0] || !request.commandLine[0] || !request.pipeName[0])
		return FALSE;

	// Never reinterpret a relative path in the elevated process.
	const BOOL targetDriveAbsolute =
		request.targetPath[0] != L'\0' &&
		request.targetPath[1] == L':' &&
		(request.targetPath[2] == L'\\' || request.targetPath[2] == L'/');
	const BOOL targetUncAbsolute =
		request.targetPath[0] == L'\\' && request.targetPath[1] == L'\\';
	if (!targetDriveAbsolute && !targetUncAbsolute)
		return FALSE;

	if (request.workingDirectory[0])
	{
		const BOOL directoryDriveAbsolute =
			request.workingDirectory[1] == L':' &&
			(request.workingDirectory[2] == L'\\' || request.workingDirectory[2] == L'/');
		const BOOL directoryUncAbsolute =
			request.workingDirectory[0] == L'\\' && request.workingDirectory[1] == L'\\';
		if (!directoryDriveAbsolute && !directoryUncAbsolute)
			return FALSE;
	}

	static const char pipePrefix[] = "\\\\.\\pipe\\PRCPipeName";
	return strncmp(request.pipeName, pipePrefix, sizeof(pipePrefix) - 1) == 0;
}
