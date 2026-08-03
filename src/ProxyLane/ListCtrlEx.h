#pragma once


// CListCtrlEx

class CListCtrlEx : public CListCtrl
{
	DECLARE_DYNAMIC(CListCtrlEx)

public:
	CListCtrlEx();
	virtual ~CListCtrlEx();

	void ThrowUnhandledMessage(BOOL bEnable)
	{
		m_bThrowMsg = bEnable;
	}

protected:

	BOOL m_bThrowMsg;
protected:
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnDropFiles(HDROP hDropInfo);
};


