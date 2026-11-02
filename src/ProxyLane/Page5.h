#pragma once

#include "ModernUI.h"

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
	CCardFrame m_cardConfig;
	CCardFrame m_cardStartup;
	CStatic m_rowTitle[6];
	CStatic m_rowDetail[6];
	CModernButton m_btnOpenDir;
	CModernButton m_btnRestore;
	CModernButton m_btnImport;
	CModernButton m_btnExport;
	CModernButton m_btnCheckUpdate;
	CToggleButton m_toggleAutostart;
	CToggleButton m_toggleAutoEnable;
	CToggleButton m_radioDark;
	CToggleButton m_radioLight;
	CFont m_smallFont;
	CFont m_boldFont;
	BOOL m_updateFound;
	void SyncThemeButtons();
	HICON m_aboutIcon;
	void LayoutAboutPage();

	virtual void DoDataExchange(CDataExchange* dataExchange);
	virtual BOOL OnInitDialog();
	virtual BOOL UsesSecondaryText(UINT controlId) const;
	virtual BOOL PreTranslateMessage(MSG* message);
	afx_msg void OnSize(UINT type, int cx, int cy);
	afx_msg void OnProjectLink(NMHDR* notifyHeader, LRESULT* result);
	afx_msg void OnLanguageChanged();
	afx_msg void OnShowWindow(BOOL show, UINT status);
	afx_msg void OnOpenDirectory();
	afx_msg void OnRestoreBackup();
	afx_msg void OnImportAll();
	afx_msg void OnExportAll();
	afx_msg void OnAutostart();
	afx_msg void OnAutoEnable();
	afx_msg void OnThemeChanged();
	afx_msg void OnCheckUpdate();
	afx_msg LRESULT OnUpdateResult(WPARAM, LPARAM);

	DECLARE_MESSAGE_MAP()
};
