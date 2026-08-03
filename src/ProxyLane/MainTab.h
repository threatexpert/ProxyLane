#pragma once

#include "Page1.h"
#include "Page2.h"
#include "Page3.h"
#include "Page4.h"
#include "Page5.h"

#define WM_PROXY_STATUS_CHANGED (WM_APP + 102)

class CMainTab;
extern CMainTab* g_MainTab;

class CMainTab : public CWnd
{
	DECLARE_DYNAMIC(CMainTab)

public:
	enum PageIndex
	{
		PAGE_PROXY = 0,
		PAGE_APPLICATIONS,
		PAGE_LOG,
		PAGE_MONITOR,
		PAGE_ABOUT,
		PAGE_COUNT
	};

	CMainTab();
	virtual ~CMainTab();

	BOOL CreateTabCtrl(CWnd* parent);
	void PositionWnd();
	void SelectPage(int pageIndex);
	void SetPageAttention(int pageIndex, BOOL attention);
	void ShowTransientStatus(LPCTSTR text, CStatusLabel::Tone tone);
	void SetRunningProfile(LPCTSTR profileName, BOOL running);
	BOOL IsProxyRunning() const { return m_proxyRunning; }
	CString GetRunningProfileName() const { return m_runningProfileName; }

	CPage1* GetPage1() { return &m_page1; }
	CPage2* GetPage2() { return &m_page2; }
	CPage3* GetPage3() { return &m_page3; }
	CPage4* GetPage4() { return &m_page4; }

	void AddLogText(int uFlag, LPCTSTR text);
	void CopyText();
	void ClearText();

protected:
	int HitTestNavigation(CPoint point) const;
	CRect NavigationItemRect(int index) const;
	int NavigationWidth() const;

	int m_currentPage;
	int m_hoverPage;
	int m_attentionPage;
	BOOL m_proxyRunning;
	CString m_runningProfileName;
	CPage1 m_page1;
	CPage2 m_page2;
	CPage3 m_page3;
	CPage4 m_page4;
	CPage5 m_page5;
	CDialog* m_pages[PAGE_COUNT];
	CFont m_navigationFont;
	CFont m_brandFont;
	CStatusLabel m_sidebarStatus;
	CStatusLabel m_transientStatus;
	CToolTipCtrl m_sidebarTooltip;

	afx_msg void OnPaint();
	afx_msg BOOL OnEraseBkgnd(CDC* dc);
	afx_msg void OnSize(UINT type, int cx, int cy);
	afx_msg void OnLButtonDown(UINT flags, CPoint point);
	afx_msg void OnMouseMove(UINT flags, CPoint point);
	afx_msg void OnTimer(UINT_PTR eventId);
	afx_msg LRESULT OnMouseLeave(WPARAM, LPARAM);

	DECLARE_MESSAGE_MAP()
};
