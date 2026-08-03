#pragma once

#include "..\ProxyLaneHook\ProxyModule.h"
#include <list>
#include "afxwin.h"
#include "ModernUI.h"

using namespace std;
// CPage4 对话框

class CPage4 : public CModernDialog
	, public IProxyDataHandle
{
	DECLARE_DYNAMIC(CPage4)

public:
	CPage4(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CPage4();

	////重载IProxyDataHandle
	void OnConnect(LPProxyPacketInfo lpppi);
	void OnEachPacket(LPProxyPacketInfo lpppi);
	void OnClose(LPProxyPacketInfo lpppi);
	void OnLayerCallback(LPProxyPacketInfo lpppi, int nType, int nCode, WPARAM wParam, LPARAM lParam);
	void PrintText(LPCTSTR lpsz);
	void UpdateMonitorStatus();

public:
	CEdit m_Edit;
	CButton m_btnMonitor;
	CButton m_btnHex;
	CModernButton m_btnClear;

	BOOL m_bAttachedPDH;
	list<CString> m_textls;
	enum{
		ShowFMT_RAW,
		ShowFMT_HEX,
	};
	int m_ShowFMT;
	CFont m_font;

// 对话框数据
	enum { IDD = IDD_Page4 };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持
	virtual BOOL OnInitDialog();

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnSize(UINT nType, int cx, int cy);
	afx_msg BOOL OnEraseBkgnd(CDC* pDC);

	afx_msg void OnBnClickedCheck1();
	afx_msg void OnBnClickedCheckHex();
	afx_msg void OnTimer(UINT_PTR nIDEvent);
	afx_msg void OnBnClickedBtnClear();
};
