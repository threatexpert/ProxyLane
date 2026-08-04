// Page2.cpp : 实现文件
//

#include "stdafx.h"
#include "ProxyLane.h"
#include "Page4.h"
#include "Localization.h"


#define TMID_TASKCOUNT 1
// CPage4 对话框

IMPLEMENT_DYNAMIC(CPage4, CModernDialog)

CPage4::CPage4(CWnd* pParent /*=NULL*/)
	: CModernDialog(CPage4::IDD, pParent)
{
	m_bAttachedPDH = 0;
}

CPage4::~CPage4()
{
}

void CPage4::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT1, m_Edit);

	DDX_Control(pDX, IDC_CHECK1, m_btnMonitor);
	DDX_Control(pDX, IDC_CHECK_HEX, m_btnHex);
	DDX_Control(pDX, IDC_BTN_CLEAR, m_btnClear);
}


BOOL CPage4::OnInitDialog()
{
	CModernDialog::OnInitDialog();
	m_btnClear.SetVisualStyle(CModernButton::STYLE_SECONDARY);

	//
	m_Edit.SetLimitText(0);

	m_font.CreateFont(
		14,                        // nHeight
		0,                        // nWidth
		0,                        // nEscapement
		0,                        // nOrientation
		FW_NORMAL,                // nWeight
		FALSE,                    // bItalic
		FALSE,                    // bUnderline
		0,                        // cStrikeOut
		ANSI_CHARSET,              // nCharSet
		OUT_DEFAULT_PRECIS,        // nOutPrecision
		CLIP_DEFAULT_PRECIS,      // nClipPrecision
		DEFAULT_QUALITY,          // nQuality
		FIXED_PITCH|FF_MODERN,
		_T("Courier New")                    // nPitchAndFamily
		);              

	m_Edit.SetFont(&m_font);

	m_ShowFMT = m_btnHex.GetCheck()==BST_CHECKED?ShowFMT_HEX:ShowFMT_RAW;

	m_Edit.EmptyUndoBuffer();
	SetTimer(TMID_TASKCOUNT, 1000, NULL);

	return TRUE;
}

BEGIN_MESSAGE_MAP(CPage4, CModernDialog)
	ON_WM_SIZE()
	//ON_WM_ERASEBKGND()

	ON_BN_CLICKED(IDC_CHECK1, &CPage4::OnBnClickedCheck1)
	ON_BN_CLICKED(IDC_CHECK_HEX, &CPage4::OnBnClickedCheckHex)
	ON_WM_TIMER()
	ON_BN_CLICKED(IDC_BTN_CLEAR, &CPage4::OnBnClickedBtnClear)
END_MESSAGE_MAP()


// CPage4 消息处理程序

void CPage4::OnSize(UINT nType, int cx, int cy)
{
	CModernDialog::OnSize(nType, cx, cy);

	CRect rc;
	GetClientRect(rc);
	if (rc.Width() <= 0 || rc.Height() <= 0)
		return;

	const int margin = UiTheme::ScaleForWindow(m_hWnd, 8);
	const int gap = UiTheme::ScaleForWindow(m_hWnd, 8);
	const int toolbarTop = UiTheme::ScaleForWindow(m_hWnd, 62);
	const int toolbarHeight = UiTheme::ScaleForWindow(m_hWnd, 24);
	const int monitorWidth = UiTheme::ScaleForWindow(m_hWnd, 96);
	const int hexWidth = UiTheme::ScaleForWindow(m_hWnd, 82);
	const int clearWidth = UiTheme::ScaleForWindow(m_hWnd, 78);
	const int clearHeight = UiTheme::ScaleForWindow(m_hWnd, 30);

	int x = margin;
	if (m_btnMonitor.GetSafeHwnd())
	{
		m_btnMonitor.MoveWindow(x, toolbarTop, monitorWidth, toolbarHeight);
		x += monitorWidth + gap;
	}
	if (m_btnHex.GetSafeHwnd())
	{
		m_btnHex.MoveWindow(x, toolbarTop, hexWidth, toolbarHeight);
		x += hexWidth + gap;
	}

	const int clearLeft = rc.right - margin - clearWidth;
	if (CWnd* taskCount = GetDlgItem(IDC_STATIC_TASKCOUNT))
	{
		const int countRight = clearLeft - gap;
		taskCount->MoveWindow(x, toolbarTop + UiTheme::ScaleForWindow(m_hWnd, 3),
			max(0, countRight - x), toolbarHeight);
	}

	if (m_btnClear.GetSafeHwnd())
	{
		m_btnClear.MoveWindow(clearLeft,
			toolbarTop - UiTheme::ScaleForWindow(m_hWnd, 3), clearWidth, clearHeight);
	}

	if (m_Edit.GetSafeHwnd())
	{
		const int editTop = toolbarTop + toolbarHeight + gap;
		m_Edit.MoveWindow(margin, editTop,
			rc.right - margin * 2, max(0, rc.bottom - margin - editTop));
	}
}

BOOL CPage4::OnEraseBkgnd(CDC* pDC)
{
	// TODO: 在此添加消息处理程序代码和/或调用默认值

	CWnd *pParent = GetParent();

	CRect   rc;   
	GetClientRect(&rc);   
	pDC->FillSolidRect(&rc, pParent->GetDC()->GetBkColor());//填充红色
	return   TRUE;   

}

void CPage4::PrintText(LPCTSTR lpsz)
{
	int nLen= m_Edit.GetWindowTextLength();
	//m_Edit.SetFocus();
	m_Edit.SetSel(nLen, nLen);
	m_Edit.ReplaceSel(lpsz);
}

void CPage4::OnConnect(LPProxyPacketInfo lpppi)
{
	CString szType = lpppi->lpC->sType == SOCK_STREAM ? _T("TCP") : _T("UDP");
	CString szText;
	if(lpppi->lpC->IsDNValid())
	{
		szText.Format(_T("PID: %d, %s.connect to: %s:%d, state: %s\r\n"), lpppi->lpC->dwPid, szType, (LPCTSTR)(CString)lpppi->lpC->szDomainName, lpppi->lpC->dstAddr.GetPort(), !lpppi->errcode ? _T("success") : _T("failure"));
	}else
	{
		DWORD nIP = lpppi->lpC->dstAddr.GetdwIP();
		const BYTE* pucIP = (BYTE*)&nIP;
		szText.Format(_T("PID: %d, %s.connect to: %u.%u.%u.%u:%d, state: %s\r\n"), lpppi->lpC->dwPid, szType, pucIP[0], pucIP[1], pucIP[2], pucIP[3], lpppi->lpC->dstAddr.GetPort(), !lpppi->errcode ? _T("success"):_T("failure"));
	}

	PrintText(szText);
}

void Bin2HexFormat(const BYTE *pData, int len, CString &str)
{
	int lineIndex = 0;

	for (int i=0; i<len; )
	{
		int left = len-i;
		int n = min(16, left);

		TCHAR szLineIndex[10];
		TCHAR szLineHex[128];
		TCHAR szLineRaw[128];
		_stprintf(szLineIndex, _T("%.8X"), lineIndex*16);

		int m = 0;
		int j;
		for (j=0; j<n; j++)
		{
			if (j%8 == 0)
				m += _stprintf(szLineHex+m, _T("  %.2X"), pData[j]);
			else
				m += _stprintf(szLineHex+m, _T(" %.2X"), pData[j]);
		}
		while (m<50)
			szLineHex[m++] = ' ';

		szLineHex[m] = '\0';
		m = 0;
		szLineRaw[m++] = ' ';
		for (j=0; j<n; j++)
		{
			BYTE ch;
			if ((pData[j] < (BYTE)'\x20') ||
				(pData[j] > (BYTE)'\x7E') )
			{
				ch = '.';
			}else
			{
				ch = pData[j];
			}
			szLineRaw[m++] = ch;
		}

		while (m<17)
			szLineRaw[m++] = ' ';
		szLineRaw[m] = '\0';

		str += szLineIndex;
		str += szLineHex;
		str += szLineRaw;
		str += _T("\r\n");

		pData += n;
		len -= n;
		lineIndex++;
	}
}

void CPage4::OnEachPacket(LPProxyPacketInfo lpppi)
{
	CString szType = lpppi->lpC->sType == SOCK_STREAM ? _T("TCP") : _T("UDP");
	CString szAddr;
	if(lpppi->lpC->IsDNValid())
	{
		szAddr.Format(_T("%s.%s:%d"), szType, (LPCTSTR)(CString)lpppi->lpC->szDomainName, lpppi->lpC->dstAddr.GetPort());
	}else
	{
		DWORD nIP = lpppi->lpC->dstAddr.GetdwIP();
		const BYTE* pucIP = (BYTE*)&nIP;
		szAddr.Format(_T("%s.%u.%u.%u.%u:%d"), szType, pucIP[0], pucIP[1], pucIP[2], pucIP[3], lpppi->lpC->dstAddr.GetPort());
	}

	CString szFrom;

	if(lpppi->datafrom)
	{
		szFrom.Format(_T("PID: %d, Server: "), lpppi->lpC->dwPid);
	}else
	{
		szFrom.Format(_T("PID: %d, Client: "), lpppi->lpC->dwPid);
	}

	CString szText;
	if (m_ShowFMT == ShowFMT_RAW)
		szText.Format(_T("%s\r\n%s\r\n%s\r\n\r\n"), szAddr, szFrom, lpppi->pData?(CString)lpppi->pData:_T(""));
	else
	{
		if (lpppi->pData)
		{
			szText.Format(_T("%s\r\n%s\r\n"), szAddr, szFrom);
			Bin2HexFormat((const BYTE*)lpppi->pData, lpppi->datalen, szText);
			szText += _T("\r\n\r\n");
		}else
		{
			szText.Format(_T("%s\r\n%s\r\n%s\r\n\r\n"), szAddr, szFrom, lpppi->pData?(CString)lpppi->pData:_T(""));
		}
	}

	PrintText(szText);
}

void CPage4::OnClose(LPProxyPacketInfo lpppi)
{
	CString szAddr;
	if(lpppi->lpC->IsDNValid())
	{
		szAddr.Format(_T("%s:%d"), (CString)lpppi->lpC->szDomainName, lpppi->lpC->dstAddr.GetPort());
	}else
	{
		DWORD nIP = lpppi->lpC->dstAddr.GetdwIP();
		const BYTE* pucIP = (BYTE*)&nIP;
		szAddr.Format(_T("%u.%u.%u.%u:%d"), pucIP[0], pucIP[1], pucIP[2], pucIP[3], lpppi->lpC->dstAddr.GetPort());
	}

	CString szText;
	szText.Format(_T("Connection [%s] Closed\r\n"), szAddr);

	PrintText(szText);
}

void CPage4::OnLayerCallback(LPProxyPacketInfo lpppi, int nType, int nCode, WPARAM wParam, LPARAM lParam)
{

}

void CPage4::OnBnClickedCheck1()
{
	// TODO: 在此添加控件通知处理程序代码

	UpdateMonitorStatus();
}

void CPage4::UpdateMonitorStatus()
{

	if(g_GlobalProxy)
	{
		IProxyDataHandle *pPDH = g_GlobalProxy->GetPRCInstance()->GetPDHInstance();
		if(m_btnMonitor.GetCheck() == BST_CHECKED)
		{
			if (!m_bAttachedPDH)
			{
				m_bAttachedPDH = 1;
				pPDH->AddInstance(this);
			}
		}else
		{
			IProxyDataHandle::Detach();
			m_bAttachedPDH = 0;
		}
	}else
	{
		m_bAttachedPDH = 0;
	}
}

void CPage4::OnBnClickedCheckHex()
{
	m_ShowFMT = m_btnHex.GetCheck()==BST_CHECKED?ShowFMT_HEX:ShowFMT_RAW;
}

void CPage4::OnTimer(UINT_PTR nIDEvent)
{
	// TODO: 在此添加消息处理程序代码和/或调用默认值
	switch (nIDEvent)
	{
	case TMID_TASKCOUNT:
		{
			if (g_GlobalProxy)
			{
				IProxyReceptionCentre* pPRC = g_GlobalProxy->GetPRCInstance();
				if (pPRC)
				{
					CString strText;
					DWORD dwTcpCount = 0;
					DWORD dwUdpCount = 0;
					IProxyTaskMgr* pTaskMgr = pPRC->GetPTMInstance(0);
					if (pTaskMgr)
					{
						pTaskMgr->GetTaskCount(&dwTcpCount);
					}
					pTaskMgr = pPRC->GetPTMInstance(1);
					if (pTaskMgr)
					{
						pTaskMgr->GetTaskCount(&dwUdpCount);
					}

					strText = Localization::Format(_T("page4.connections"), dwTcpCount, dwUdpCount);

					SetDlgItemText(IDC_STATIC_TASKCOUNT, strText);
				}
			}
		}
		break;
	}

	__super::OnTimer(nIDEvent);
}

void CPage4::OnBnClickedBtnClear()
{
	// TODO: 在此添加控件通知处理程序代码
	m_Edit.SetWindowText(_T(""));

// 	// Initialize the new local handle.
// 	HLOCAL h = ::LocalAlloc(LHND, 4);
// 	LPTSTR lpszText = (LPTSTR) ::LocalLock(h);
// 	memset(lpszText, 0, 4);
// 	::LocalUnlock(h);
// 
// 	// Free the current text handle of the edit control.
// 	::LocalFree(m_Edit.GetHandle());
// 
// 	// Set the new text handle.
// 	m_Edit.SetHandle(h);
}
