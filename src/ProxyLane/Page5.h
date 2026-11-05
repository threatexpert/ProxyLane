#pragma once

#include "ModernUI.h"
#include "AsyncSnapshot.h"

class CPage5 : public CModernDialog
{
	DECLARE_DYNAMIC(CPage5)

public:
	CPage5(CWnd* parent = NULL);
	virtual ~CPage5();

	enum { IDD = IDD_Page5 };

protected:
	CToolTipCtrl m_projectTooltip;
	CSoftCombo m_languageCombo;
	CCardFrame m_openSourceCard;
	HICON m_aboutIcon;
	void LayoutAboutPage();
 CModernButton m_settingsButtons[5];
 CCardFrame m_configCard, m_preferencesCard;
 CFont m_smallFont, m_boldFont;
 CStatic m_storageMode, m_storagePath, m_transferTitle, m_transferInfo;
 CStatic m_downloadLabel;
 CLinkCtrl m_downloadLink, m_updateInfo;
 AsyncSnapshot<CString> m_updateQuery;
 bool m_updateFound = false, m_updateFailed = false, m_layout = false;
 int m_scroll = 0;
 afx_msg void OnSettingsAction(UINT id);
 afx_msg void OnTimer(UINT_PTR id);
 afx_msg void OnVScroll(UINT code, UINT position, CScrollBar* bar);
 afx_msg BOOL OnMouseWheel(UINT flags, short delta, CPoint point);
 void ReportStorageError(DWORD error, const CString& path = CString());
 void SwitchStorage();
 void SetUpdateStatus(const CString& text, bool found = false, bool failed = false);
 afx_msg HBRUSH OnCtlColor(CDC* dc, CWnd* wnd, UINT ctlColor);
 afx_msg void OnUpdateLink(NMHDR* notifyHeader, LRESULT* result);

	virtual void DoDataExchange(CDataExchange* dataExchange);
	virtual BOOL OnInitDialog();
	virtual BOOL UsesSecondaryText(UINT controlId) const;
	virtual BOOL PreTranslateMessage(MSG* message);
	afx_msg void OnSize(UINT type, int cx, int cy);
	afx_msg void OnProjectLink(NMHDR* notifyHeader, LRESULT* result);
 afx_msg void OnDownloadLink(NMHDR* notifyHeader, LRESULT* result);
	afx_msg void OnLanguageChanged();

	DECLARE_MESSAGE_MAP()
};
