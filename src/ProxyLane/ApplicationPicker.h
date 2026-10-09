#pragma once

#include "ModernUI.h"
#include "InstalledApplications.h"
#include "RecentApplications.h"

struct ApplicationCatalogLoad;

class CApplicationPicker : public CModernDialog
{
public:
	CApplicationPicker(CWnd* parent);
	virtual ~CApplicationPicker();
	InstalledApplications::Application m_selectedApplication;
	RecentApplications::Entry m_selectedRecent;

protected:
	virtual void DoDataExchange(CDataExchange* exchange);
	virtual BOOL OnInitDialog();
	virtual BOOL PreTranslateMessage(MSG* message);
	virtual BOOL OnNotify(WPARAM wParam, LPARAM lParam, LRESULT* result);
	virtual void OnOK();
	afx_msg void OnSearchChanged();
	afx_msg void OnRefresh();
	afx_msg void OnSelectionChanged(NMHDR* header, LRESULT* result);
	afx_msg void OnDoubleClick(NMHDR* header, LRESULT* result);
	afx_msg void OnListCustomDraw(NMHDR* header, LRESULT* result);
	afx_msg void OnTimer(UINT_PTR timer);
	afx_msg void OnDestroy();
	afx_msg void OnContextMenu(CWnd* window, CPoint point);
	afx_msg void OnRemoveRecent();
	DECLARE_MESSAGE_MAP()

private:
	void LayoutPicker();
	void BeginLoad(BOOL refresh);
	BOOL FinishLoad();
	void SetEmptyState(const CString& text);
	void FilterApplications(const CString& selection = CString());
	void RebuildApplications();
	void UpdateSelectionActions();
	CString SelectionKey() const;
	CString RowKey(size_t index) const;
	void ChangeRecent(size_t index, BOOL remove);
	BOOL RefreshProfileContext();
	CString SourceSummary(const InstalledApplications::Application& application) const;
	CString LaunchText(const InstalledApplications::Application& application) const;
	CString ItemDetails(const InstalledApplications::Application& application) const;
	CEdit m_search;
	CListCtrl m_list;
	CStatic m_emptyState;
	CModernButton m_launch;
	CModernButton m_cancel;
	CModernButton m_refresh;
	CModernButton m_removeRecent;
	CImageList m_icons;
	CToolTipCtrl m_listTooltip;
	CString m_hoverText;
	int m_hoverRow;
	std::vector<InstalledApplications::Application> m_applications;
	std::vector<InstalledApplications::Application> m_catalog;
	std::vector<int> m_iconIndices;
	ApplicationCatalogLoad* m_load;
	BOOL m_loading;
	BOOL m_loadFailed;
	BOOL m_recentReadFailed;
	BOOL m_rebuilding;
	RecentApplications::Load* m_recentLoad;
	CString m_profile;
	CString m_profileId;
	std::vector<RecentApplications::Entry> m_recentEntries;
};
