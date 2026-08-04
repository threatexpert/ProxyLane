// ListCtrlEx.cpp : 实现文件
//

#include "stdafx.h"
#include "ListCtrlEx.h"


// CListCtrlEx

IMPLEMENT_DYNAMIC(CListCtrlEx, CListCtrl)

CListCtrlEx::CListCtrlEx()
{
	m_bThrowMsg = FALSE;
}

CListCtrlEx::~CListCtrlEx()
{
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
