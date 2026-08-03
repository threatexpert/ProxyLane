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

	virtual void DoDataExchange(CDataExchange* dataExchange);
	virtual BOOL OnInitDialog();
	virtual BOOL PreTranslateMessage(MSG* message);
	afx_msg void OnProjectLink(NMHDR* notifyHeader, LRESULT* result);

	DECLARE_MESSAGE_MAP()
};
