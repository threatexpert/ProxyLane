#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <mswsock.h>
#include <ws2tcpip.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Mswsock.lib")

static int Fail(const char* operation, int error)
{
	fprintf(stderr, "CONNECTEX_INITIAL_DATA_FAIL %s error=%d\n", operation, error);
	return 1;
}

int __cdecl main(int argc, char** argv)
{
	const char* targetAddress = argc > 1 ? argv[1] : "203.0.113.10";
	const unsigned short targetPort = (unsigned short)(argc > 2 ? atoi(argv[2]) : 39003);
	const int payloadSize = argc > 3 ? atoi(argv[3]) : 16384;
	const char* expectedPrefix = argc > 4 ? argv[4] : "";
	if (payloadSize < 0 || payloadSize > 1024 * 1024)
		return Fail("invalid-payload-size", WSAEINVAL);

	WSADATA data;
	int error = WSAStartup(MAKEWORD(2, 2), &data);
	if (error != 0)
		return Fail("WSAStartup", error);

	SOCKET socketHandle = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP,
		NULL, 0, WSA_FLAG_OVERLAPPED);
	if (socketHandle == INVALID_SOCKET)
	{
		error = WSAGetLastError();
		WSACleanup();
		return Fail("WSASocket", error);
	}

	sockaddr_in localAddress;
	ZeroMemory(&localAddress, sizeof(localAddress));
	localAddress.sin_family = AF_INET;
	if (bind(socketHandle, (sockaddr*)&localAddress, sizeof(localAddress)) == SOCKET_ERROR)
	{
		error = WSAGetLastError();
		closesocket(socketHandle);
		WSACleanup();
		return Fail("bind", error);
	}

	GUID connectExGuid = WSAID_CONNECTEX;
	LPFN_CONNECTEX connectEx = NULL;
	DWORD bytes = 0;
	if (WSAIoctl(socketHandle, SIO_GET_EXTENSION_FUNCTION_POINTER,
		&connectExGuid, sizeof(connectExGuid), &connectEx, sizeof(connectEx),
		&bytes, NULL, NULL) == SOCKET_ERROR || !connectEx)
	{
		error = WSAGetLastError();
		closesocket(socketHandle);
		WSACleanup();
		return Fail("get-ConnectEx", error);
	}

	sockaddr_in remoteAddress;
	ZeroMemory(&remoteAddress, sizeof(remoteAddress));
	remoteAddress.sin_family = AF_INET;
	remoteAddress.sin_port = htons(targetPort);
	remoteAddress.sin_addr.s_addr = inet_addr(targetAddress);
	if (remoteAddress.sin_addr.s_addr == INADDR_NONE)
	{
		closesocket(socketHandle);
		WSACleanup();
		return Fail("invalid-target-address", WSAEINVAL);
	}

	std::vector<char> payload(payloadSize);
	for (int index = 0; index < payloadSize; ++index)
		payload[index] = (char)((index * 17 + 31) & 0xff);

	WSAOVERLAPPED overlapped;
	ZeroMemory(&overlapped, sizeof(overlapped));
	overlapped.hEvent = WSACreateEvent();
	if (overlapped.hEvent == WSA_INVALID_EVENT)
	{
		error = WSAGetLastError();
		closesocket(socketHandle);
		WSACleanup();
		return Fail("WSACreateEvent", error);
	}

	DWORD initiallySent = 0;
	BOOL connected = connectEx(socketHandle, (sockaddr*)&remoteAddress,
		sizeof(remoteAddress), payloadSize ? &payload[0] : NULL, payloadSize,
		&initiallySent, &overlapped);
	if (!connected)
	{
		error = WSAGetLastError();
		if (error != ERROR_IO_PENDING)
		{
			WSACloseEvent(overlapped.hEvent);
			closesocket(socketHandle);
			WSACleanup();
			return Fail("ConnectEx", error);
		}
		DWORD waitResult = WSAWaitForMultipleEvents(1, &overlapped.hEvent,
			TRUE, 15000, FALSE);
		if (waitResult != WSA_WAIT_EVENT_0)
		{
			error = waitResult == WSA_WAIT_TIMEOUT ? WSAETIMEDOUT : WSAGetLastError();
			WSACloseEvent(overlapped.hEvent);
			closesocket(socketHandle);
			WSACleanup();
			return Fail("wait-ConnectEx", error);
		}
		DWORD flags = 0;
		if (!WSAGetOverlappedResult(socketHandle, &overlapped, &initiallySent,
			FALSE, &flags))
		{
			error = WSAGetLastError();
			WSACloseEvent(overlapped.hEvent);
			closesocket(socketHandle);
			WSACleanup();
			return Fail("ConnectEx-result", error);
		}
	}

	setsockopt(socketHandle, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);
	WSACloseEvent(overlapped.hEvent);
	if (initiallySent != (DWORD)payloadSize)
	{
		closesocket(socketHandle);
		WSACleanup();
		return Fail("short-initial-send", WSAEMSGSIZE);
	}
	if (shutdown(socketHandle, SD_SEND) == SOCKET_ERROR)
	{
		error = WSAGetLastError();
		closesocket(socketHandle);
		WSACleanup();
		return Fail("shutdown", error);
	}

	DWORD timeout = 15000;
	setsockopt(socketHandle, SOL_SOCKET, SO_RCVTIMEO,
		(const char*)&timeout, sizeof(timeout));
	std::vector<char> reply;
	char buffer[8192];
	for (;;)
	{
		int received = recv(socketHandle, buffer, sizeof(buffer), 0);
		if (received == 0)
			break;
		if (received == SOCKET_ERROR)
		{
			error = WSAGetLastError();
			closesocket(socketHandle);
			WSACleanup();
			return Fail("recv", error);
		}
		reply.insert(reply.end(), buffer, buffer + received);
	}

	const char acknowledgement[] = "HALF-CLOSE-ACK:";
	const size_t prefixSize = strlen(expectedPrefix);
	const size_t acknowledgementSize = sizeof(acknowledgement) - 1;
	const size_t expectedSize = prefixSize + acknowledgementSize + payload.size();
	BOOL matches = reply.size() == expectedSize;
	if (matches && prefixSize)
		matches = memcmp(&reply[0], expectedPrefix, prefixSize) == 0;
	if (matches)
		matches = memcmp(&reply[prefixSize], acknowledgement,
			acknowledgementSize) == 0;
	if (matches && !payload.empty())
		matches = memcmp(&reply[prefixSize + acknowledgementSize],
			&payload[0], payload.size()) == 0;

	closesocket(socketHandle);
	WSACleanup();
	if (!matches)
	{
		fprintf(stderr,
			"CONNECTEX_INITIAL_DATA_FAIL reply-mismatch got=%u expected=%u\n",
			(unsigned int)reply.size(), (unsigned int)expectedSize);
		return 1;
	}
	printf("CONNECTEX_INITIAL_DATA_PASS bytes=%d prefix=%u\n", payloadSize,
		(unsigned int)prefixSize);
	return 0;
}
