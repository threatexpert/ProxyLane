#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stddef.h>
#include <string.h>
#include <wchar.h>

// InetPton/InetNtop are exported by Ws2_32.dll only on Vista and later.
// These wrappers use APIs available on Windows XP so binaries do not acquire
// a loader-time dependency on the newer entry points.

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4996) // XP-compatible Winsock conversion APIs.
#endif

inline INT ProxyStringToAddressA(LPSTR text, INT family,
	LPSOCKADDR address, LPINT addressLength)
{
	INT result = WSAStringToAddressA(text, family, NULL, address, addressLength);
	if (result != SOCKET_ERROR || WSAGetLastError() != WSANOTINITIALISED)
		return result;

	WSADATA data;
	INT startupError = WSAStartup(MAKEWORD(2, 2), &data);
	if (startupError)
	{
		WSASetLastError(startupError);
		return SOCKET_ERROR;
	}
	result = WSAStringToAddressA(text, family, NULL, address, addressLength);
	INT error = result == SOCKET_ERROR ? WSAGetLastError() : 0;
	WSACleanup();
	if (error)
		WSASetLastError(error);
	return result;
}

inline INT ProxyAddressToStringA(LPSOCKADDR address, DWORD addressLength,
	LPSTR text, LPDWORD textLength)
{
	INT result = WSAAddressToStringA(address, addressLength, NULL, text, textLength);
	if (result != SOCKET_ERROR || WSAGetLastError() != WSANOTINITIALISED)
		return result;

	WSADATA data;
	INT startupError = WSAStartup(MAKEWORD(2, 2), &data);
	if (startupError)
	{
		WSASetLastError(startupError);
		return SOCKET_ERROR;
	}
	result = WSAAddressToStringA(address, addressLength, NULL, text, textLength);
	INT error = result == SOCKET_ERROR ? WSAGetLastError() : 0;
	WSACleanup();
	if (error)
		WSASetLastError(error);
	return result;
}

inline INT ProxyAddressToStringW(LPSOCKADDR address, DWORD addressLength,
	LPWSTR text, LPDWORD textLength)
{
	INT result = WSAAddressToStringW(address, addressLength, NULL, text, textLength);
	if (result != SOCKET_ERROR || WSAGetLastError() != WSANOTINITIALISED)
		return result;

	WSADATA data;
	INT startupError = WSAStartup(MAKEWORD(2, 2), &data);
	if (startupError)
	{
		WSASetLastError(startupError);
		return SOCKET_ERROR;
	}
	result = WSAAddressToStringW(address, addressLength, NULL, text, textLength);
	INT error = result == SOCKET_ERROR ? WSAGetLastError() : 0;
	WSACleanup();
	if (error)
		WSASetLastError(error);
	return result;
}

inline BOOL ProxyIsNumericAddressTextA(INT family, LPCSTR text)
{
	if (!text || !text[0])
		return FALSE;

	for (LPCSTR current = text; *current; ++current)
	{
		const char ch = *current;
		if (family == AF_INET)
		{
			if ((ch < '0' || ch > '9') && ch != '.')
				return FALSE;
		}
		else if (family == AF_INET6)
		{
			const BOOL hex = (ch >= '0' && ch <= '9') ||
				(ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
			if (!hex && ch != ':' && ch != '.')
				return FALSE;
		}
		else
			return FALSE;
	}
	return TRUE;
}

inline INT ProxyInetPtonA(INT family, LPCSTR text, PVOID address)
{
	if (!address || !ProxyIsNumericAddressTextA(family, text))
	{
		WSASetLastError(WSAEINVAL);
		return 0;
	}

	const size_t textLength = strlen(text);
	if (textLength >= 64)
	{
		WSASetLastError(WSAEINVAL);
		return 0;
	}

	CHAR mutableText[64];
	CopyMemory(mutableText, text, textLength + 1);
	SOCKADDR_STORAGE storage = { 0 };
	INT storageLength = family == AF_INET
		? sizeof(SOCKADDR_IN) : sizeof(SOCKADDR_IN6);
	if (ProxyStringToAddressA(mutableText, family,
		reinterpret_cast<LPSOCKADDR>(&storage), &storageLength) == SOCKET_ERROR)
		return 0;

	if (family == AF_INET)
		CopyMemory(address,
			&reinterpret_cast<SOCKADDR_IN *>(&storage)->sin_addr,
			sizeof(IN_ADDR));
	else
		CopyMemory(address,
			&reinterpret_cast<SOCKADDR_IN6 *>(&storage)->sin6_addr,
			sizeof(IN6_ADDR));
	return 1;
}

inline BOOL ProxyCopyAddressTextA(INT family, LPCSTR socketText,
	LPSTR output, size_t outputLength)
{
	LPCSTR begin = socketText;
	size_t length = strlen(socketText);
	if (family == AF_INET6 && socketText[0] == '[')
	{
		LPCSTR closeBracket = strchr(socketText, ']');
		if (!closeBracket)
			return FALSE;
		begin = socketText + 1;
		length = static_cast<size_t>(closeBracket - begin);
	}
	else if (family == AF_INET)
	{
		LPCSTR colon = strrchr(socketText, ':');
		if (colon)
			length = static_cast<size_t>(colon - socketText);
	}

	if (!output || outputLength <= length)
	{
		WSASetLastError(WSAEFAULT);
		return FALSE;
	}
	CopyMemory(output, begin, length);
	output[length] = '\0';
	return TRUE;
}

inline BOOL ProxyCopyAddressTextW(INT family, LPCWSTR socketText,
	LPWSTR output, size_t outputLength)
{
	LPCWSTR begin = socketText;
	size_t length = wcslen(socketText);
	if (family == AF_INET6 && socketText[0] == L'[')
	{
		LPCWSTR closeBracket = wcschr(socketText, L']');
		if (!closeBracket)
			return FALSE;
		begin = socketText + 1;
		length = static_cast<size_t>(closeBracket - begin);
	}
	else if (family == AF_INET)
	{
		LPCWSTR colon = wcsrchr(socketText, L':');
		if (colon)
			length = static_cast<size_t>(colon - socketText);
	}

	if (!output || outputLength <= length)
	{
		WSASetLastError(WSAEFAULT);
		return FALSE;
	}
	CopyMemory(output, begin, length * sizeof(WCHAR));
	output[length] = L'\0';
	return TRUE;
}

inline LPCSTR ProxyInetNtopA(INT family, const VOID *address,
	LPSTR output, size_t outputLength)
{
	if (!address || (family != AF_INET && family != AF_INET6))
	{
		WSASetLastError(family == AF_INET || family == AF_INET6
			? WSAEFAULT : WSAEAFNOSUPPORT);
		return NULL;
	}

	SOCKADDR_STORAGE storage = { 0 };
	DWORD storageLength;
	if (family == AF_INET)
	{
		SOCKADDR_IN *socketAddress = reinterpret_cast<SOCKADDR_IN *>(&storage);
		socketAddress->sin_family = AF_INET;
		CopyMemory(&socketAddress->sin_addr, address, sizeof(IN_ADDR));
		storageLength = sizeof(*socketAddress);
	}
	else
	{
		SOCKADDR_IN6 *socketAddress = reinterpret_cast<SOCKADDR_IN6 *>(&storage);
		socketAddress->sin6_family = AF_INET6;
		CopyMemory(&socketAddress->sin6_addr, address, sizeof(IN6_ADDR));
		storageLength = sizeof(*socketAddress);
	}

	CHAR socketText[80] = { 0 };
	DWORD textLength = sizeof(socketText) / sizeof(socketText[0]);
	if (ProxyAddressToStringA(reinterpret_cast<LPSOCKADDR>(&storage),
		storageLength, socketText, &textLength) == SOCKET_ERROR ||
		!ProxyCopyAddressTextA(family, socketText, output, outputLength))
		return NULL;
	return output;
}

inline LPCWSTR ProxyInetNtopW(INT family, const VOID *address,
	LPWSTR output, size_t outputLength)
{
	if (!address || (family != AF_INET && family != AF_INET6))
	{
		WSASetLastError(family == AF_INET || family == AF_INET6
			? WSAEFAULT : WSAEAFNOSUPPORT);
		return NULL;
	}

	SOCKADDR_STORAGE storage = { 0 };
	DWORD storageLength;
	if (family == AF_INET)
	{
		SOCKADDR_IN *socketAddress = reinterpret_cast<SOCKADDR_IN *>(&storage);
		socketAddress->sin_family = AF_INET;
		CopyMemory(&socketAddress->sin_addr, address, sizeof(IN_ADDR));
		storageLength = sizeof(*socketAddress);
	}
	else
	{
		SOCKADDR_IN6 *socketAddress = reinterpret_cast<SOCKADDR_IN6 *>(&storage);
		socketAddress->sin6_family = AF_INET6;
		CopyMemory(&socketAddress->sin6_addr, address, sizeof(IN6_ADDR));
		storageLength = sizeof(*socketAddress);
	}

	WCHAR socketText[80] = { 0 };
	DWORD textLength = sizeof(socketText) / sizeof(socketText[0]);
	if (ProxyAddressToStringW(reinterpret_cast<LPSOCKADDR>(&storage),
		storageLength, socketText, &textLength) == SOCKET_ERROR ||
		!ProxyCopyAddressTextW(family, socketText, output, outputLength))
		return NULL;
	return output;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif
