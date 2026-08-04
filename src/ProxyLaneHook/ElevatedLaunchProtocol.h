#pragma once

#include <windows.h>
#include <stddef.h>
#include <string.h>

#ifndef WC_ERR_INVALID_CHARS
#define WC_ERR_INVALID_CHARS 0x00000080
#endif

// The UI and elevated rundll32 exchange a length-prefixed request encoded as
// unpadded Base64URL. Only the bytes used by each field are transmitted.

#define PROXYLANE_ELEVATED_REQUEST_MAGIC   0x4C454C50UL // "PLEL"
#define PROXYLANE_ELEVATED_REQUEST_VERSION 2

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
struct ProxyLaneElevatedLaunchWireHeader
{
	DWORD magic;
	WORD version;
	WORD headerSize;
	DWORD totalSize;
	DWORD targetPathBytes;
	DWORD commandLineBytes;
	DWORD workingDirectoryBytes;
	DWORD pipeNameBytes;
	DWORD flags;
};
#pragma pack(pop)

struct ProxyLaneElevatedLaunchRequestView
{
	const BYTE* targetPath;
	DWORD targetPathBytes;
	const BYTE* commandLine;
	DWORD commandLineBytes;
	const BYTE* workingDirectory;
	DWORD workingDirectoryBytes;
	const BYTE* pipeName;
	DWORD pipeNameBytes;
};

// A valid UTF-8 string uses at most three bytes per UTF-16 code unit. A
// surrogate pair uses four bytes for two code units and is therefore smaller.
#define PROXYLANE_ELEVATED_MAX_WIRE_BYTES \
	(sizeof(ProxyLaneElevatedLaunchWireHeader) + \
	 (PROXYLANE_ELEVATED_TARGET_CCH - 1) * 3 + \
	 (PROXYLANE_ELEVATED_COMMAND_CCH - 1) * 3 + \
	 (PROXYLANE_ELEVATED_DIRECTORY_CCH - 1) * 3 + \
	 (PROXYLANE_ELEVATED_PIPE_CCH - 1))

inline size_t ProxyLaneBase64UrlEncodedLength(size_t sourceSize)
{
	const size_t fullGroups = sourceSize / 3;
	const size_t remainder = sourceSize % 3;
	return fullGroups * 4 + (remainder ? remainder + 1 : 0);
}

inline size_t ProxyLaneBase64UrlDecodedLength(size_t sourceLength)
{
	const size_t remainder = sourceLength % 4;
	if (remainder == 1)
		return static_cast<size_t>(-1);
	return (sourceLength / 4) * 3 + (remainder ? remainder - 1 : 0);
}

inline int ProxyLaneBase64UrlDigitValue(char value)
{
	if (value >= 'A' && value <= 'Z')
		return value - 'A';
	if (value >= 'a' && value <= 'z')
		return value - 'a' + 26;
	if (value >= '0' && value <= '9')
		return value - '0' + 52;
	if (value == '-')
		return 62;
	if (value == '_')
		return 63;
	return -1;
}

inline BOOL ProxyLaneBase64UrlEncode(
	const BYTE* source,
	size_t sourceSize,
	char* destination,
	size_t destinationSize,
	size_t* destinationLength)
{
	static const char alphabet[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	const size_t requiredLength = ProxyLaneBase64UrlEncodedLength(sourceSize);
	if ((!source && sourceSize) || !destination ||
		destinationSize <= requiredLength)
	{
		return FALSE;
	}

	size_t sourceOffset = 0;
	size_t destinationOffset = 0;
	while (sourceSize - sourceOffset >= 3)
	{
		const BYTE first = source[sourceOffset++];
		const BYTE second = source[sourceOffset++];
		const BYTE third = source[sourceOffset++];
		destination[destinationOffset++] = alphabet[first >> 2];
		destination[destinationOffset++] = alphabet[((first & 0x03) << 4) | (second >> 4)];
		destination[destinationOffset++] = alphabet[((second & 0x0F) << 2) | (third >> 6)];
		destination[destinationOffset++] = alphabet[third & 0x3F];
	}

	const size_t remainder = sourceSize - sourceOffset;
	if (remainder)
	{
		const BYTE first = source[sourceOffset++];
		destination[destinationOffset++] = alphabet[first >> 2];
		if (remainder == 1)
		{
			destination[destinationOffset++] = alphabet[(first & 0x03) << 4];
		}
		else
		{
			const BYTE second = source[sourceOffset];
			destination[destinationOffset++] = alphabet[((first & 0x03) << 4) | (second >> 4)];
			destination[destinationOffset++] = alphabet[(second & 0x0F) << 2];
		}
	}

	destination[destinationOffset] = '\0';
	if (destinationLength)
		*destinationLength = destinationOffset;
	return TRUE;
}

inline BOOL ProxyLaneBase64UrlDecode(
	const char* source,
	size_t sourceLength,
	BYTE* destination,
	size_t destinationSize,
	size_t* destinationLength)
{
	const size_t requiredLength = ProxyLaneBase64UrlDecodedLength(sourceLength);
	if (!source || requiredLength == static_cast<size_t>(-1) ||
		(!destination && requiredLength) || destinationSize < requiredLength)
	{
		return FALSE;
	}

	size_t sourceOffset = 0;
	size_t destinationOffset = 0;
	while (sourceLength - sourceOffset >= 4)
	{
		const int first = ProxyLaneBase64UrlDigitValue(source[sourceOffset++]);
		const int second = ProxyLaneBase64UrlDigitValue(source[sourceOffset++]);
		const int third = ProxyLaneBase64UrlDigitValue(source[sourceOffset++]);
		const int fourth = ProxyLaneBase64UrlDigitValue(source[sourceOffset++]);
		if (first < 0 || second < 0 || third < 0 || fourth < 0)
			return FALSE;
		destination[destinationOffset++] = static_cast<BYTE>((first << 2) | (second >> 4));
		destination[destinationOffset++] = static_cast<BYTE>((second << 4) | (third >> 2));
		destination[destinationOffset++] = static_cast<BYTE>((third << 6) | fourth);
	}

	const size_t remainder = sourceLength - sourceOffset;
	if (remainder)
	{
		const int first = ProxyLaneBase64UrlDigitValue(source[sourceOffset++]);
		const int second = ProxyLaneBase64UrlDigitValue(source[sourceOffset++]);
		if (first < 0 || second < 0 || (remainder == 2 && (second & 0x0F) != 0))
			return FALSE;
		destination[destinationOffset++] = static_cast<BYTE>((first << 2) | (second >> 4));

		if (remainder == 3)
		{
			const int third = ProxyLaneBase64UrlDigitValue(source[sourceOffset]);
			if (third < 0 || (third & 0x03) != 0)
				return FALSE;
			destination[destinationOffset++] = static_cast<BYTE>((second << 4) | (third >> 2));
		}
	}

	if (destinationLength)
		*destinationLength = destinationOffset;
	return destinationOffset == requiredLength;
}

inline BOOL ProxyLaneParseElevatedRequest(
	const BYTE* data,
	size_t dataSize,
	ProxyLaneElevatedLaunchRequestView* request)
{
	if (!data || !request || dataSize < sizeof(ProxyLaneElevatedLaunchWireHeader) ||
		dataSize > PROXYLANE_ELEVATED_MAX_WIRE_BYTES)
	{
		return FALSE;
	}

	ProxyLaneElevatedLaunchWireHeader header;
	memcpy(&header, data, sizeof(header));
	if (header.magic != PROXYLANE_ELEVATED_REQUEST_MAGIC ||
		header.version != PROXYLANE_ELEVATED_REQUEST_VERSION ||
		header.headerSize != sizeof(header) ||
		header.totalSize != dataSize ||
		header.flags != 0 ||
		!header.targetPathBytes || !header.commandLineBytes || !header.pipeNameBytes)
	{
		return FALSE;
	}

	size_t offset = sizeof(header);
#define PROXYLANE_ASSIGN_WIRE_FIELD(pointerField, lengthField, headerLength) \
	do { \
		if ((headerLength) > dataSize - offset) return FALSE; \
		request->pointerField = data + offset; \
		request->lengthField = (headerLength); \
		offset += (headerLength); \
	} while (0)

	PROXYLANE_ASSIGN_WIRE_FIELD(targetPath, targetPathBytes, header.targetPathBytes);
	PROXYLANE_ASSIGN_WIRE_FIELD(commandLine, commandLineBytes, header.commandLineBytes);
	PROXYLANE_ASSIGN_WIRE_FIELD(workingDirectory, workingDirectoryBytes, header.workingDirectoryBytes);
	PROXYLANE_ASSIGN_WIRE_FIELD(pipeName, pipeNameBytes, header.pipeNameBytes);

#undef PROXYLANE_ASSIGN_WIRE_FIELD
	return offset == dataSize;
}
