// ListCtrlEx.cpp : 实现文件
//

#include "stdafx.h"
#include "ListCtrlEx.h"
#include <UIAutomation.h>


// CListCtrlEx

IMPLEMENT_DYNAMIC(CListCtrlEx, CListCtrl)

CListCtrlEx::CListCtrlEx()
{
	m_bThrowMsg = FALSE;
}

CListCtrlEx::~CListCtrlEx()
{
}

LRESULT CListCtrlEx::WindowProc(UINT message, WPARAM wParam, LPARAM lParam)
{
	if (message == WM_DESTROY) { m_destroying = true; m_accessibility.reset(); }
	if (message == ProcessListAccessibility::RequestMessage && !m_destroying)
	{
		GetParent()->PostMessage(message);
		return 0;
	}
	if (message == WM_GETOBJECT && static_cast<LONG>(lParam) == UiaRootObjectId &&
		m_snapshotAccessibility && !m_destroying)
	{
		try {
			if (!m_accessibility)
			{
				m_accessibility.reset(new ProcessListAccessibility::Bridge(m_hWnd));
				if (m_accessibility->Available())
					GetParent()->SendMessage(ProcessListAccessibility::ChangedMessage, 1);
			}
			if (m_accessibility->Available()) return m_accessibility->GetObject(wParam, lParam);
		} catch (...) {} // Optional on systems without a usable UI Automation runtime.
	}
	LRESULT result = CListCtrl::WindowProc(message, wParam, lParam);
	if (m_accessibility && !m_accessibilityUpdatePending &&
		(message == WM_VSCROLL || message == WM_HSCROLL || message == WM_MOUSEWHEEL ||
		 message == WM_MOUSEHWHEEL || message == WM_LBUTTONUP || message == WM_RBUTTONUP || message == WM_KEYUP ||
		 message == WM_SIZE || message == WM_WINDOWPOSCHANGED || message == WM_SETFOCUS ||
		 message == WM_KILLFOCUS || message == WM_SHOWWINDOW || message == WM_ENABLE ||
		 message == WM_NOTIFY || message == LVM_SCROLL || message == LVM_ENSUREVISIBLE ||
		 message == LVM_SETITEMSTATE))
	{
		m_accessibilityUpdatePending = true;
		GetParent()->PostMessage(ProcessListAccessibility::ChangedMessage);
	}
	return result;
}


BEGIN_MESSAGE_MAP(CListCtrlEx, CListCtrl)
	ON_WM_DROPFILES()
END_MESSAGE_MAP()



// CListCtrlEx 消息处理程序



void CListCtrlEx::OnDropFiles(HDROP hDropInfo)
{
	// TODO: 在此添加消息处理程序代码和/或调用默认值

	if (m_bThrowMsg)
	{
		GetParent()->PostMessage(WM_DROPFILES, (WPARAM)hDropInfo, 0);
	}
	//CListCtrl::OnDropFiles(hDropInfo);
}
