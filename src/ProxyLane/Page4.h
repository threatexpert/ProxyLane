#pragma once
#include "../ProxyLaneHook/ProxyModule.h"
#include "ModernUI.h"
#include "ByteHexView.h"
#include "ProtocolRawView.h"
#include "../ProxyLaneHook/PlatformSupport.h"
#include <memory>
#include <vector>
#include <string>
#include <functional>

struct MitmJob;
struct ProtocolPageData;
namespace ProtocolView { struct Row; }
class CPage4 : public CModernDialog
{
    friend class ProtocolPageHarness; // Native-control regression harness.
    DECLARE_DYNAMIC(CPage4)
public:
    CPage4(CWnd* parent = NULL);
    virtual ~CPage4();
    enum { IDD = IDD_Page4 };
    void UpdateMonitorStatus(bool offerRecordingDirectory = false);
    bool IsMonitoring() const { return m_recording; }
    bool IsBusyForConfigImport() const { return m_recording || m_job || m_stopJob || m_reconnectPrepared; }
    void SetQuicUdpWarningProvider(std::function<CString()> provider) { m_quicUdpWarning = provider; }
protected:
    std::function<CString()> m_quicUdpWarning;
    virtual void DoDataExchange(CDataExchange* dx);
    virtual BOOL OnInitDialog();
    virtual BOOL PreTranslateMessage(MSG* message);
    afx_msg void OnSize(UINT type, int cx, int cy);
    afx_msg void OnShowWindow(BOOL show, UINT status);
    afx_msg void OnTimer(UINT_PTR id);
    afx_msg void OnMonitor();
    afx_msg void OnView(NMHDR*, LRESULT*);
    afx_msg void OnFilter();
    afx_msg void OnFollowLatest();
    afx_msg void OnListScrolled(NMHDR*, LRESULT*);
    afx_msg void OnHexSelection(NMHDR*, LRESULT*);
    afx_msg void OnRawSelection(NMHDR*, LRESULT*);
    afx_msg void OnLButtonDown(UINT, CPoint);
    afx_msg void OnLButtonUp(UINT, CPoint);
    afx_msg void OnMouseMove(UINT, CPoint);
    afx_msg BOOL OnSetCursor(CWnd*, UINT, UINT);
    afx_msg void OnCaptureChanged(CWnd*);
    afx_msg void OnClear();
    afx_msg void OnCA();
    afx_msg void OnOptions();
    afx_msg void OnRecordingOptions();
    afx_msg void OnRequestSelected(NMHDR*, LRESULT*);
    afx_msg void OnRequestInfoTip(NMHDR*, LRESULT*);
    afx_msg void OnDetailTab(NMHDR*, LRESULT*);
    DECLARE_MESSAGE_MAP()
private:
    void LayoutControls(int cx, int cy);
    void SetMonitorControls(bool busy);
    void UpdateStopStatus();
    DWORD m_stopStarted=0, m_stopStatusPoll=0;
    void OpenCA(bool enableAfterClose);
    void StartMonitoring();
    bool PrepareReconnect(bool decrypt);
    void CompleteReconnect(bool commit);
    bool m_reconnectPrepared = false, m_reconnectAccepted = false;
    void InitProtocolView();
    void ApplyMonitorSettings();
    afx_msg LRESULT OnMonitorSettings(WPARAM,LPARAM);
    void InitProtocolColumns();
    void LayoutProtocolView(int x, int y, int width, int height);
    void TickProtocolView();
    bool IsViewingRecording() const;
    void UpdateRecordingControls();
    void QueueRecordingPage(int action, const std::string& path = "");
    afx_msg void OnOpenRecording();
    void SetRecordingListMode(bool offline);
    const ProtocolView::Row* RequestRow(int item) const;
    afx_msg void OnRequestDisplay(NMHDR*, LRESULT*);
    CModernButton m_openRecording;
    CStatic m_recordingViewStatus;
    void ClearProtocolView();
    void ShowProtocolDetail();
    void UpdateDetailTooltip();
    void RebuildRequests();
    bool CanFollowLatest();
    CSoftTab m_detailTabs, m_viewTabs;
    CSoftEdit m_filter;
    CToggleButton m_follow;
    CSoftCombo m_protocolFilter;
    CByteHexView m_hexView;
    double m_splitRatio = 0.42;
    bool m_dragging = false;
    CRect m_splitRect, m_protocolRect;
    CListCtrl m_requests;
    CImageList m_processIcons;
    CProtocolRawView m_detail;
    CStatic m_detailStatus;
    CToolTipCtrl m_detailTooltip;
    CString m_detailStatusText;
    std::shared_ptr<ProtocolPageData> m_protocol;
    CToggleButton m_monitor;
    CModernButton m_clear, m_options;
    CStatic m_recordStatus;
    CFont m_font;
    IProxyTlsControl* m_tls;
    bool m_recording;
    bool m_keepRecordingRequested=false;
    bool m_retainedRecording=false;
    bool m_recordingGapNotified=false;
    bool m_mitmSupported = ProxySupportsOptionalModules();
    std::shared_ptr<MitmJob> m_job, m_stopJob;
};
