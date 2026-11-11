#pragma once
#include <memory>
#include "ProcessListAccessibility.h"


// CListCtrlEx

class CListCtrlEx : public CListCtrl
{
	DECLARE_DYNAMIC(CListCtrlEx)

public:
	CListCtrlEx();
	virtual ~CListCtrlEx();
	void EnableSnapshotAccessibility() { m_snapshotAccessibility = true; }
	ProcessListAccessibility::Bridge* AccessibilityBridge() const { return m_accessibility.get(); }
	void AcknowledgeAccessibilityUpdate() { m_accessibilityUpdatePending = false; }

	void ThrowUnhandledMessage(BOOL bEnable)
	{
		m_bThrowMsg = bEnable;
	}

protected:

	BOOL m_bThrowMsg;
	bool m_snapshotAccessibility = false;
	bool m_accessibilityUpdatePending = false;
	bool m_destroying = false;
	std::unique_ptr<ProcessListAccessibility::Bridge> m_accessibility;
	virtual LRESULT WindowProc(UINT message, WPARAM wParam, LPARAM lParam);
protected:
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnDropFiles(HDROP hDropInfo);
};


