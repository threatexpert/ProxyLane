#include "stdafx.h"
#include "AsyncSecureSocketLayer.h"
#include "..\ProxyLog.h"

namespace
{
	const int PLST_OK = 0;
	const int PLST_EOF = 1;
	const int PLST_WOULD_BLOCK = -2;
	const unsigned int PLST_ABI_VERSION = 2;
	const size_t TLS_CHUNK = 16 * 1024;
	const size_t PLAINTEXT_LOW_WATER = 256 * 1024;
	const size_t PLAINTEXT_HIGH_WATER = 512 * 1024;
	const size_t MAX_BUFFERED_DATA = 1024 * 1024;

	void SecureTrace(LPCTSTR format, int value1 = 0, int value2 = 0)
	{
		const DWORD savedError = GetLastError();
		TCHAR path[MAX_PATH] = { 0 };
		if (!GetEnvironmentVariable(_T("PROXYLANE_SECURE_TRACE"), path,
			_countof(path)))
		{
			SetLastError(savedError);
			return;
		}
		HANDLE file = CreateFile(path, FILE_APPEND_DATA,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS,
			FILE_ATTRIBUTE_NORMAL, NULL);
		if (file == INVALID_HANDLE_VALUE)
		{
			SetLastError(savedError);
			return;
		}
		TCHAR line[256];
		_stprintf_s(line, _countof(line), format, value1, value2);
		DWORD written = 0;
		WriteFile(file, line, (DWORD)(_tcslen(line) * sizeof(TCHAR)),
			&written, NULL);
		CloseHandle(file);
		SetLastError(savedError);
	}

	FARPROC LoadRequired(HMODULE module, LPCSTR name)
	{
		return module ? GetProcAddress(module, name) : NULL;
	}
}

CAsyncSecureSocketLayer::CAsyncSecureSocketLayer()
	: m_hTransport(NULL), m_session(NULL), m_pendingTlsOffset(0),
	  m_plaintextOffset(0), m_bUdpKeyReady(FALSE),
	  m_bHandshakeStarted(FALSE), m_bHandshakeReady(FALSE),
	  m_bConnectNotified(FALSE), m_bPeerReadClosed(FALSE),
	  m_bPeerEofDelivered(FALSE), m_bReceivePaused(FALSE),
	  m_pendingShutdown(-1),
	  m_sessionFree(NULL), m_sessionIsReady(NULL), m_sessionFeedTls(NULL),
	  m_sessionDrainTls(NULL), m_sessionWritePlain(NULL),
	  m_sessionReadPlain(NULL), m_sessionCloseNotify(NULL),
	  m_sessionExportKey(NULL), m_sessionLastError(NULL),
	  m_udpEncrypt(NULL), m_udpDecrypt(NULL), m_transportLoadError(0)
{
	ZeroMemory(m_udpKey, sizeof(m_udpKey));
}

CAsyncSecureSocketLayer::~CAsyncSecureSocketLayer()
{
	ResetTransport();
}

BOOL CAsyncSecureSocketLayer::Configure(const CStringA& psk,
	const CStringA& serverName)
{
	if (psk.IsEmpty())
	{
		WSASetLastError(WSAEINVAL);
		return FALSE;
	}
	m_psk = psk;
	m_serverName = serverName.IsEmpty() ? "localhost" : serverName;
	return TRUE;
}

BOOL CAsyncSecureSocketLayer::LoadTransport()
{
	if (m_hTransport)
		return TRUE;
	m_transportLoadError = 0;

	TCHAR path[MAX_PATH] = { 0 };
	DWORD length = GetModuleFileName(NULL, path, _countof(path));
	if (!length || length >= _countof(path))
		return FALSE;
	TCHAR* slash = _tcsrchr(path, _T('\\'));
	if (!slash)
		return FALSE;
#ifdef _WIN64
	_tcscpy_s(slash + 1, _countof(path) - (slash + 1 - path),
		_T("ProxyLaneSecureTransport64.dll"));
#else
	_tcscpy_s(slash + 1, _countof(path) - (slash + 1 - path),
		_T("ProxyLaneSecureTransport32.dll"));
#endif
	m_hTransport = LoadLibrary(path);
	if (!m_hTransport)
	{
		m_transportLoadError = GetLastError();
		return FALSE;
	}

	PFN_ABI_VERSION abiVersion = reinterpret_cast<PFN_ABI_VERSION>(
		LoadRequired(m_hTransport, "plst_abi_version"));
	PFN_SESSION_CREATE sessionCreate = reinterpret_cast<PFN_SESSION_CREATE>(
		LoadRequired(m_hTransport, "plst_session_create"));
	m_sessionFree = reinterpret_cast<PFN_SESSION_FREE>(LoadRequired(m_hTransport, "plst_session_free"));
	m_sessionIsReady = reinterpret_cast<PFN_SESSION_IS_READY>(LoadRequired(m_hTransport, "plst_session_is_ready"));
	m_sessionFeedTls = reinterpret_cast<PFN_SESSION_FEED_TLS>(LoadRequired(m_hTransport, "plst_session_feed_tls"));
	m_sessionDrainTls = reinterpret_cast<PFN_SESSION_DRAIN_TLS>(LoadRequired(m_hTransport, "plst_session_drain_tls"));
	m_sessionWritePlain = reinterpret_cast<PFN_SESSION_WRITE_PLAIN>(LoadRequired(m_hTransport, "plst_session_write_plain"));
	m_sessionReadPlain = reinterpret_cast<PFN_SESSION_READ_PLAIN>(LoadRequired(m_hTransport, "plst_session_read_plain"));
	m_sessionCloseNotify = reinterpret_cast<PFN_SESSION_CLOSE_NOTIFY>(LoadRequired(m_hTransport, "plst_session_send_close_notify"));
	m_sessionExportKey = reinterpret_cast<PFN_SESSION_EXPORT_KEY>(LoadRequired(m_hTransport, "plst_session_export_key"));
	m_sessionLastError = reinterpret_cast<PFN_SESSION_LAST_ERROR>(LoadRequired(m_hTransport, "plst_session_last_error"));
	m_udpEncrypt = reinterpret_cast<PFN_UDP_CRYPT>(LoadRequired(m_hTransport, "plst_udp_encrypt"));
	m_udpDecrypt = reinterpret_cast<PFN_UDP_CRYPT>(LoadRequired(m_hTransport, "plst_udp_decrypt"));
	if (!abiVersion || abiVersion() != PLST_ABI_VERSION || !sessionCreate ||
		!m_sessionFree || !m_sessionIsReady || !m_sessionFeedTls ||
		!m_sessionDrainTls || !m_sessionWritePlain || !m_sessionReadPlain ||
		!m_sessionCloseNotify || !m_sessionExportKey || !m_sessionLastError ||
		!m_udpEncrypt || !m_udpDecrypt)
	{
		m_transportLoadError = ERROR_PROC_NOT_FOUND;
		FreeLibrary(m_hTransport);
		m_hTransport = NULL;
		return FALSE;
	}

	const int result = sessionCreate(reinterpret_cast<const BYTE*>((LPCSTR)m_psk),
		m_psk.GetLength(), m_serverName, &m_session);
	if (result != PLST_OK || !m_session)
	{
		m_transportLoadError = ERROR_DLL_INIT_FAILED;
		FreeLibrary(m_hTransport);
		m_hTransport = NULL;
		return FALSE;
	}
	return TRUE;
}

BOOL CAsyncSecureSocketLayer::StartHandshake()
{
	if (m_bHandshakeStarted)
		return TRUE;
	if (!LoadTransport())
		return FALSE;
	m_bHandshakeStarted = TRUE;
	return FlushTls();
}

BOOL CAsyncSecureSocketLayer::HasPendingTls() const
{
	return m_pendingTlsOffset < m_pendingTls.size();
}

BOOL CAsyncSecureSocketLayer::HasPendingRead() const
{
	return BufferedPlaintext() != 0 ||
		(m_bPeerReadClosed && !m_bPeerEofDelivered);
}

size_t CAsyncSecureSocketLayer::BufferedPlaintext() const
{
	return m_plaintextOffset < m_plaintext.size() ?
		m_plaintext.size() - m_plaintextOffset : 0;
}

BOOL CAsyncSecureSocketLayer::FlushTls()
{
	while (m_session)
	{
		while (HasPendingTls())
		{
			int sent = SendNext(&m_pendingTls[m_pendingTlsOffset],
				(int)(m_pendingTls.size() - m_pendingTlsOffset));
			if (sent == SOCKET_ERROR)
				return WSAGetLastError() == WSAEWOULDBLOCK;
			if (sent <= 0)
			{
				WSASetLastError(WSAECONNRESET);
				return FALSE;
			}
			m_pendingTlsOffset += sent;
		}
		m_pendingTls.clear();
		m_pendingTlsOffset = 0;

		BYTE chunk[TLS_CHUNK];
		size_t written = 0;
		if (m_sessionDrainTls(m_session, chunk, sizeof(chunk), &written) != PLST_OK)
		{
			WSASetLastError(WSAECONNABORTED);
			return FALSE;
		}
		if (!written)
			break;
		m_pendingTls.assign(chunk, chunk + written);
	}
	return TRUE;
}

BOOL CAsyncSecureSocketLayer::DrainPlaintext()
{
	if (m_plaintextOffset)
	{
		m_plaintext.erase(m_plaintext.begin(),
			m_plaintext.begin() + m_plaintextOffset);
		m_plaintextOffset = 0;
	}

	BYTE chunk[TLS_CHUNK];
	for (;;)
	{
		const size_t buffered = BufferedPlaintext();
		if (buffered >= MAX_BUFFERED_DATA)
		{
			WSASetLastError(WSAENOBUFS);
			return FALSE;
		}
		const size_t capacity = min(sizeof(chunk),
			MAX_BUFFERED_DATA - buffered);
		size_t count = 0;
		int result = m_sessionReadPlain(m_session, chunk, capacity, &count);
		if (result == PLST_EOF)
		{
			m_bPeerReadClosed = TRUE;
			return TRUE;
		}
		if (result == PLST_WOULD_BLOCK)
		{
			if (BufferedPlaintext() >= PLAINTEXT_HIGH_WATER)
				m_bReceivePaused = TRUE;
			return TRUE;
		}
		if (result != PLST_OK)
		{
			WSASetLastError(WSAECONNABORTED);
			return FALSE;
		}
		if (!count)
			return TRUE;
		m_plaintext.insert(m_plaintext.end(), chunk, chunk + count);
	}
}

void CAsyncSecureSocketLayer::ResumeTlsReceive()
{
	if (!m_bReceivePaused || !m_session || m_bPeerReadClosed ||
		BufferedPlaintext() > PLAINTEXT_LOW_WATER)
		return;

	// PumpTls deliberately stops before recv() reaches WSAEWOULDBLOCK when
	// decrypted data reaches the high-water mark.  WSAAsyncSelect is therefore
	// not guaranteed to post another FD_READ.  Re-enter this layer through the
	// helper window after the upper layer has consumed enough plaintext.
	m_bReceivePaused = FALSE;
	if (!TriggerEvent(FD_READ, 0))
		m_bReceivePaused = TRUE;
}

BOOL CAsyncSecureSocketLayer::PumpTls()
{
	// Always empty rustls before accepting more TLS records.  rustls limits its
	// internal received-plaintext queue to 16 KiB and requires callers to read
	// processed plaintext before calling read_tls() again.
	if (!DrainPlaintext() || !FlushTls() || !FinishHandshake())
		return FALSE;
	if (m_bReceivePaused)
		return TRUE;

	BYTE chunk[TLS_CHUNK];
	for (;;)
	{
		int received = ReceiveNext(chunk, sizeof(chunk));
		if (received == SOCKET_ERROR)
		{
			if (WSAGetLastError() == WSAEWOULDBLOCK)
				break;
			return FALSE;
		}
		if (received == 0)
		{
			WSASetLastError(WSAECONNRESET);
			return FALSE;
		}
		size_t offset = 0;
		while (offset < (size_t)received)
		{
			size_t consumed = 0;
			const int result = m_sessionFeedTls(m_session, chunk + offset,
				received - offset, &consumed);
			if (result != PLST_OK || !consumed)
			{
				WSASetLastError(WSAECONNABORTED);
				return FALSE;
			}
			offset += consumed;
			if (!DrainPlaintext() || !FlushTls() || !FinishHandshake())
				return FALSE;
		}
		if (m_bReceivePaused)
			return TRUE;
	}
	return TRUE;
}

BOOL CAsyncSecureSocketLayer::FinishHandshake()
{
	if (m_bHandshakeReady)
		return TRUE;
	int ready = m_sessionIsReady(m_session);
	if (ready < 0)
	{
		WSASetLastError(WSAECONNABORTED);
		return FALSE;
	}
	if (!ready)
		return TRUE;
	m_bHandshakeReady = TRUE;
	if (m_sessionExportKey(m_session, m_udpKey, sizeof(m_udpKey)) == PLST_OK)
		m_bUdpKeyReady = TRUE;
	if (!m_bConnectNotified)
	{
		SecureTrace(_T("TLS ready, key=%d\r\n"), m_bUdpKeyReady);
		m_bConnectNotified = TRUE;
		TriggerEvent(FD_CONNECT, 0, TRUE);
	}
	return TRUE;
}

void CAsyncSecureSocketLayer::ReportFailure(LPCTSTR prefix)
{
	int winsockError = WSAGetLastError();
	if (!winsockError)
		winsockError = WSAECONNABORTED;
	SecureTrace(_T("TLS failure winsock=%d\r\n"), winsockError);
	char detail[512] = { 0 };
	if (m_session && m_sessionLastError)
		m_sessionLastError(m_session, detail, sizeof(detail));
	CString detailText(detail);
	const BOOL routineEstablishedClose = m_bHandshakeReady &&
		(winsockError == WSAECONNRESET ||
		 winsockError == WSAECONNABORTED ||
		 winsockError == WSAESHUTDOWN);
	if (!routineEstablishedClose)
		PrintText(_T("%s: %s (Winsock %d).\r\n"), prefix,
			detailText.IsEmpty() ? _T("secure transport error") : (LPCTSTR)detailText,
			winsockError);
	WSASetLastError(winsockError);
	const BOOL wasConnected = m_bConnectNotified;
	if (!wasConnected)
		TriggerEvent(FD_CONNECT,
			m_transportLoadError ? PROXYLANE_SECURE_LOAD_FAILED :
			PROXYLANE_SECURE_HANDSHAKE_FAILED, TRUE);
	else
		TriggerEvent(FD_CLOSE, WSAECONNABORTED, TRUE);
}

void CAsyncSecureSocketLayer::OnConnect(int nErrorCode)
{
	SecureTrace(_T("raw connect error=%d\r\n"), nErrorCode);
	if (nErrorCode)
	{
		TriggerEvent(FD_CONNECT, nErrorCode, TRUE);
		return;
	}
	if (!StartHandshake() || !FinishHandshake())
		ReportFailure(_T("Secure transport handshake failed"));
}

void CAsyncSecureSocketLayer::OnReceive(int nErrorCode)
{
	if (nErrorCode || !PumpTls())
	{
		if (nErrorCode)
			WSASetLastError(nErrorCode);
		ReportFailure(_T("Secure transport receive failed"));
		return;
	}
	if (m_bHandshakeReady && HasPendingRead())
	{
		SecureTrace(_T("TLS receive plain=%d\r\n"),
			(int)(m_plaintext.size() - m_plaintextOffset));
		TriggerEvent(FD_READ, 0, TRUE);
	}
}

void CAsyncSecureSocketLayer::OnSend(int nErrorCode)
{
	if (nErrorCode || !FlushTls() || !FinishHandshake())
	{
		if (nErrorCode)
			WSASetLastError(nErrorCode);
		ReportFailure(_T("Secure transport send failed"));
		return;
	}
	if (m_pendingShutdown >= 0 && !HasPendingTls())
	{
		int how = m_pendingShutdown;
		m_pendingShutdown = -1;
		ShutDownNext(how);
	}
	if (m_bConnectNotified)
		TriggerEvent(FD_WRITE, 0, TRUE);
}

void CAsyncSecureSocketLayer::OnClose(int nErrorCode)
{
	SecureTrace(_T("raw close error=%d\r\n"), nErrorCode);
	BOOL drainSucceeded = TRUE;
	if (!nErrorCode && m_session)
	{
		// CAsyncSocketEx marks the layer closed before calling OnClose(), so
		// ReceiveNext() rejects reads here.  Winsock FD_CLOSE can still have a
		// final TLS record queued; drain it directly before forwarding EOF.
		BYTE chunk[TLS_CHUNK];
		for (;;)
		{
			int received = recv(m_pOwnerSocket->GetSocketHandle(),
				reinterpret_cast<char*>(chunk), sizeof(chunk), 0);
			SecureTrace(_T("raw close drain=%d error=%d\r\n"), received,
				received == SOCKET_ERROR ? WSAGetLastError() : 0);
			if (received <= 0)
				break;
			size_t offset = 0;
			while (offset < (size_t)received)
			{
				size_t consumed = 0;
				if (m_sessionFeedTls(m_session, chunk + offset,
					received - offset, &consumed) != PLST_OK || !consumed)
				{
					WSASetLastError(WSAECONNABORTED);
					drainSucceeded = FALSE;
					offset = received;
					break;
				}
				offset += consumed;
				if (!DrainPlaintext())
				{
					drainSucceeded = FALSE;
					offset = received;
					break;
				}
			}
			if (!drainSucceeded)
				break;
		}
		if (drainSucceeded && !DrainPlaintext())
			drainSucceeded = FALSE;
		// A clean TCP FIN is also an EOF for the decrypted stream.  It may
		// follow close_notify later, or be the only close signal from a peer
		// that does not perform a graceful TLS shutdown.
		m_bPeerReadClosed = TRUE;
		SecureTrace(_T("raw close plain=%d\r\n"),
			(int)(m_plaintext.size() - m_plaintextOffset));
	}
	if (!drainSucceeded)
	{
		ReportFailure(_T("Secure transport close drain failed"));
		return;
	}
	if (!nErrorCode && m_bHandshakeReady && HasPendingRead())
		TriggerEvent(FD_READ, 0, TRUE);
	else if (nErrorCode)
		TriggerEvent(FD_CLOSE, nErrorCode, TRUE);
	else if (!m_bHandshakeReady)
		TriggerEvent(FD_CLOSE, 0, TRUE);
}

int CAsyncSecureSocketLayer::Send(const void* lpBuf, int nBufLen, int nFlags)
{
	UNREFERENCED_PARAMETER(nFlags);
	if (!m_bHandshakeReady || !m_session)
	{
		WSASetLastError(WSAEWOULDBLOCK);
		return SOCKET_ERROR;
	}
	if (nBufLen < 0 || (nBufLen && !lpBuf))
	{
		WSASetLastError(WSAEFAULT);
		return SOCKET_ERROR;
	}
	size_t written = 0;
	int result = m_sessionWritePlain(m_session,
		reinterpret_cast<const BYTE*>(lpBuf), nBufLen, &written);
	if (result == PLST_WOULD_BLOCK)
	{
		WSASetLastError(WSAEWOULDBLOCK);
		return SOCKET_ERROR;
	}
	if (result != PLST_OK || !FlushTls())
	{
		WSASetLastError(WSAECONNABORTED);
		return SOCKET_ERROR;
	}
	SecureTrace(_T("TLS send requested=%d written=%d\r\n"), nBufLen,
		(int)written);
	return (int)written;
}

int CAsyncSecureSocketLayer::Receive(void* lpBuf, int nBufLen, int nFlags)
{
	UNREFERENCED_PARAMETER(nFlags);
	if (nBufLen < 0 || (nBufLen && !lpBuf))
	{
		WSASetLastError(WSAEFAULT);
		return SOCKET_ERROR;
	}
	if (!m_bHandshakeReady)
	{
		WSASetLastError(WSAEWOULDBLOCK);
		return SOCKET_ERROR;
	}
	if (m_plaintextOffset >= m_plaintext.size())
	{
		if (m_bPeerReadClosed)
		{
			m_bPeerEofDelivered = TRUE;
			return 0;
		}
		WSASetLastError(WSAEWOULDBLOCK);
		return SOCKET_ERROR;
	}
	int count = (int)min((size_t)nBufLen,
		m_plaintext.size() - m_plaintextOffset);
	if (count)
		CopyMemory(lpBuf, &m_plaintext[m_plaintextOffset], count);
	m_plaintextOffset += count;
	if (m_plaintextOffset == m_plaintext.size())
	{
		m_plaintext.clear();
		m_plaintextOffset = 0;
		if (m_bPeerReadClosed && !m_bPeerEofDelivered)
			TriggerEvent(FD_READ, 0, TRUE);
	}
	else
	{
		// The SOCKS state machine intentionally reads replies in small stages
		// (first 4 bytes, then the address-dependent remainder).  TLS may have
		// already consumed the whole record from Winsock, so no second FD_READ
		// will arrive from the kernel.  Re-post it while decrypted bytes remain.
		TriggerEvent(FD_READ, 0, TRUE);
	}
	// Resume raw TLS reads only after the upper layer has relieved pressure.
	// If plaintext remains, its pass-through FD_READ was queued above first so
	// existing data is consumed before the resumed pump can refill the queue.
	ResumeTlsReceive();
	return count;
}

BOOL CAsyncSecureSocketLayer::ShutDown(int nHow)
{
	SecureTrace(_T("TLS shutdown how=%d\r\n"), nHow);
	if ((nHow == sends || nHow == both) && m_session)
	{
		if (m_sessionCloseNotify(m_session) != PLST_OK || !FlushTls())
			return FALSE;
		if (HasPendingTls())
		{
			m_pendingShutdown = nHow;
			return TRUE;
		}
	}
	return ShutDownNext(nHow);
}

int CAsyncSecureSocketLayer::EncryptUdp(const BYTE* plain, int plainLength,
	BYTE* output, int outputCapacity, int* outputLength)
{
	if (!m_bUdpKeyReady || !outputLength || plainLength < 0)
		return SOCKET_ERROR;
	size_t written = 0;
	int result = m_udpEncrypt(m_udpKey, sizeof(m_udpKey), plain, plainLength,
		output, outputCapacity, &written);
	*outputLength = (int)written;
	SecureTrace(_T("UDP encrypt plain=%d wire=%d\r\n"), plainLength,
		(int)written);
	return result == PLST_OK ? 0 : SOCKET_ERROR;
}

int CAsyncSecureSocketLayer::DecryptUdp(const BYTE* packet, int packetLength,
	BYTE* output, int outputCapacity, int* outputLength)
{
	if (!m_bUdpKeyReady || !outputLength || packetLength < 0)
		return SOCKET_ERROR;
	size_t written = 0;
	int result = m_udpDecrypt(m_udpKey, sizeof(m_udpKey), packet, packetLength,
		output, outputCapacity, &written);
	*outputLength = (int)written;
	return result == PLST_OK ? 0 : SOCKET_ERROR;
}

void CAsyncSecureSocketLayer::Close()
{
	ResetTransport();
	CloseNext();
}

void CAsyncSecureSocketLayer::ResetTransport()
{
	if (m_session && m_sessionFree)
		m_sessionFree(m_session);
	m_session = NULL;
	if (m_hTransport)
		FreeLibrary(m_hTransport);
	m_hTransport = NULL;
	if (!m_psk.IsEmpty())
	{
		LPSTR psk = m_psk.GetBuffer();
		SecureZeroMemory(psk, m_psk.GetLength());
		m_psk.ReleaseBuffer();
	}
	m_psk.Empty();
	m_serverName.Empty();
	SecureZeroMemory(m_udpKey, sizeof(m_udpKey));
	m_pendingTls.clear();
	m_plaintext.clear();
	m_pendingTlsOffset = m_plaintextOffset = 0;
	m_bUdpKeyReady = m_bHandshakeStarted = m_bHandshakeReady = FALSE;
	m_bConnectNotified = FALSE;
	m_bPeerReadClosed = FALSE;
	m_bPeerEofDelivered = FALSE;
	m_bReceivePaused = FALSE;
	m_pendingShutdown = -1;
}
