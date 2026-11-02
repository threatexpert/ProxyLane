#pragma once

#include "ModernUI.h"
#include "resource.h"
#include <vector>

struct DashboardTraffic
{
	double uploadRate, downloadRate;
	double uploadPeak, downloadPeak;
	ULONGLONG uploadTotal, downloadTotal;
};

// Round start/stop button in the status card.
class CPowerButton : public CModernButton
{
public:
	CPowerButton() : m_running(FALSE) {}
	void SetRunning(BOOL running);

protected:
	virtual void DrawItem(LPDRAWITEMSTRUCT drawItemStruct);
	BOOL m_running;
};

// One-click recent application row.
class CAppTileButton : public CModernButton
{
public:
	CAppTileButton() : m_icon(NULL) {}
	void SetContent(const CString& name, const CString& detail, HICON icon); // Takes ownership of icon.
	virtual ~CAppTileButton() { if (m_icon) ::DestroyIcon(m_icon); }

protected:
	virtual void DrawItem(LPDRAWITEMSTRUCT drawItemStruct);
	CString m_name;
	CString m_detail;
	HICON m_icon;
};

class CDashboardPage : public CModernDialog
{
	DECLARE_DYNAMIC(CDashboardPage)

public:
	enum { IDD = IDD_PageDashboard };
	CDashboardPage(CWnd* parent = NULL);
	virtual ~CDashboardPage();

	void Refresh();
	void SetTraffic(const DashboardTraffic& traffic);
	void ResetTraffic();

	struct Connection
	{
		CString process;
		CString target;
		CString protocol;
		DWORD pid;
		ULONGLONG createTime;
	};

protected:
	virtual BOOL OnInitDialog();
	virtual void OnOK() {}
	virtual void OnCancel() {}
	virtual COLORREF BackdropForChild(CWnd* child);
	virtual BOOL OnCommand(WPARAM wParam, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg BOOL OnEraseBkgnd(CDC* dc);
	afx_msg void OnSize(UINT type, int cx, int cy);
	afx_msg void OnTimer(UINT_PTR timer);
	afx_msg void OnShowWindow(BOOL show, UINT status);

	void Layout();
	void RebuildProfiles();
	void RebuildRecent();
	void CollectConnections();
	int Scale(int value) const { return UiTheme::ScaleForWindow(m_hWnd, value); }
	void DrawLabel(CDC& dc, CFont& font, const CString& text, const CRect& rect, COLORREF color, UINT format = DT_LEFT | DT_VCENTER);
	void DrawHeading(CDC& dc, UiTheme::Glyph glyph, const CString& text, const CRect& card, COLORREF glyphColor);

	CFont m_bodyFont;
	CFont m_smallFont;
	CFont m_boldFont;
	CFont m_headlineFont;
	CFont m_kpiFont;
	CFont m_kpiSmallFont;

	CPowerButton m_power;
	CModernButton m_testButton;
	CModernButton m_allProcesses;
	CModernButton m_pickApp;
	CToggleButton m_childToggle;
	CToggleButton m_ipv6Toggle;
	std::vector<CModernButton*> m_profileButtons;
	std::vector<CString> m_profileNames;
	std::vector<CAppTileButton*> m_tileButtons;

	CRect m_statusCard, m_uploadCard, m_downloadCard, m_profileCard, m_childCard, m_ipv6Card;
	CRect m_upstreamCard, m_hookedCard, m_connectionsCard, m_recentCard;

	DashboardTraffic m_traffic;
	std::vector<Connection> m_connections;
	DWORD m_tcpCount, m_udpCount, m_hookedCount;
	DWORD m_runningSince;
	BOOL m_wasRunning;
	CString m_recentKey;

	DECLARE_MESSAGE_MAP()
};
