#pragma once

#include "AsyncSocketExLayer.h"
#include <vector>

// Optional gonc-compatible TLS-PSK transport.  The implementation is loaded
// dynamically so plain SOCKS operation retains the legacy OS dependency set.
class CAsyncSecureSocketLayer : public CAsyncSocketExLayer
{
public:
	CAsyncSecureSocketLayer();
	virtual ~CAsyncSecureSocketLayer();

	BOOL Configure(const CStringA& psk, const CStringA& serverName);
	BOOL HasUdpKey() const { return m_bUdpKeyReady; }
	int EncryptUdp(const BYTE* plain, int plainLength, BYTE* output,
		int outputCapacity, int* outputLength);
	int DecryptUdp(const BYTE* packet, int packetLength, BYTE* output,
		int outputCapacity, int* outputLength);

protected:
	virtual void Close();
	virtual int Send(const void* lpBuf, int nBufLen, int nFlags = 0);
	virtual int Receive(void* lpBuf, int nBufLen, int nFlags = 0);
	virtual BOOL ShutDown(int nHow = sends);
	virtual void OnClose(int nErrorCode);
	virtual void OnConnect(int nErrorCode);
	virtual void OnReceive(int nErrorCode);
	virtual void OnSend(int nErrorCode);

private:
	typedef void* PLST_SESSION;
	typedef unsigned int (__cdecl *PFN_ABI_VERSION)();
	typedef int (__cdecl *PFN_SESSION_CREATE)(const BYTE*, size_t,
		const char*, PLST_SESSION*);
	typedef void (__cdecl *PFN_SESSION_FREE)(PLST_SESSION);
	typedef int (__cdecl *PFN_SESSION_IS_READY)(PLST_SESSION);
	typedef int (__cdecl *PFN_SESSION_FEED_TLS)(PLST_SESSION, const BYTE*,
		size_t, size_t*);
	typedef int (__cdecl *PFN_SESSION_DRAIN_TLS)(PLST_SESSION, BYTE*,
		size_t, size_t*);
	typedef int (__cdecl *PFN_SESSION_WRITE_PLAIN)(PLST_SESSION, const BYTE*,
		size_t, size_t*);
	typedef int (__cdecl *PFN_SESSION_READ_PLAIN)(PLST_SESSION, BYTE*,
		size_t, size_t*);
	typedef int (__cdecl *PFN_SESSION_CLOSE_NOTIFY)(PLST_SESSION);
	typedef int (__cdecl *PFN_SESSION_EXPORT_KEY)(PLST_SESSION, BYTE*, size_t);
	typedef int (__cdecl *PFN_SESSION_LAST_ERROR)(PLST_SESSION, char*, size_t);
	typedef int (__cdecl *PFN_UDP_CRYPT)(const BYTE*, size_t, const BYTE*,
		size_t, BYTE*, size_t, size_t*);

	BOOL LoadTransport();
	BOOL StartHandshake();
	BOOL FlushTls();
	BOOL PumpTls();
	BOOL DrainPlaintext();
	BOOL FinishHandshake();
	void ReportFailure(LPCTSTR prefix);
	void ResetTransport();
	BOOL HasPendingTls() const;

	HMODULE m_hTransport;
	PLST_SESSION m_session;
	CStringA m_psk;
	CStringA m_serverName;
	std::vector<BYTE> m_pendingTls;
	size_t m_pendingTlsOffset;
	std::vector<BYTE> m_plaintext;
	size_t m_plaintextOffset;
	BYTE m_udpKey[32];
	BOOL m_bUdpKeyReady;
	BOOL m_bHandshakeStarted;
	BOOL m_bHandshakeReady;
	BOOL m_bConnectNotified;
	int m_pendingShutdown;

	PFN_SESSION_FREE m_sessionFree;
	PFN_SESSION_IS_READY m_sessionIsReady;
	PFN_SESSION_FEED_TLS m_sessionFeedTls;
	PFN_SESSION_DRAIN_TLS m_sessionDrainTls;
	PFN_SESSION_WRITE_PLAIN m_sessionWritePlain;
	PFN_SESSION_READ_PLAIN m_sessionReadPlain;
	PFN_SESSION_CLOSE_NOTIFY m_sessionCloseNotify;
	PFN_SESSION_EXPORT_KEY m_sessionExportKey;
	PFN_SESSION_LAST_ERROR m_sessionLastError;
	PFN_UDP_CRYPT m_udpEncrypt;
	PFN_UDP_CRYPT m_udpDecrypt;
};
