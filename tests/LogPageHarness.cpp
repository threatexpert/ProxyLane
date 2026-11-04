// Actual MFC log page, owned test window; no proxy service or user input.
#include "../src/ProxyLane/stdafx.h"
#include "../src/ProxyLane/ProxyLane.h"
#ifndef LOG_PAGE_SOURCE
#define LOG_PAGE_SOURCE "../src/ProxyLane/Page2.cpp"
#endif
#include LOG_PAGE_SOURCE
#include <atomic>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <thread>

IGlobalProxy* g_GlobalProxy = nullptr;
static void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
static double CpuSeconds() {
    FILETIME created, exited, kernel, user;
    Require(GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user) != FALSE, "process times");
    ULARGE_INTEGER k, u; k.LowPart=kernel.dwLowDateTime;k.HighPart=kernel.dwHighDateTime;
    u.LowPart=user.dwLowDateTime;u.HighPart=user.dwHighDateTime;
    return (k.QuadPart+u.QuadPart)/1e7;
}
class MeasuredPage : public CPage2 {
public:
    double maxDispatchMs=0;
    DWORD maxHeartbeatMs=0;
    unsigned heartbeats=0, flushes=0;
    LRESULT WindowProc(UINT message, WPARAM wp, LPARAM lp) override {
        if (message==WM_APP+79) {
            maxHeartbeatMs=max(maxHeartbeatMs, GetTickCount()-static_cast<DWORD>(wp));
            ++heartbeats; return 0;
        }
        const auto start=std::chrono::steady_clock::now();
        const LRESULT result=CPage2::WindowProc(message,wp,lp);
        if (message==WM_TIMER || message==WM_PRINTLOGTEXT) {
            double ms=std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-start).count();
            maxDispatchMs=max(maxDispatchMs,ms);++flushes;
        }
        return result;
    }
};
static void Pump(DWORD duration) {
    DWORD start=GetTickCount();
    while(GetTickCount()-start<duration) {
        MSG msg;
        if(PeekMessage(&msg,nullptr,0,0,PM_REMOVE)) {TranslateMessage(&msg);DispatchMessage(&msg);}
        else Sleep(1);
    }
}
static CString Contents(CPage2& page) {CString value;page.m_Edit.GetWindowText(value);return value;}
static void Drain(CPage2& page) {
    DWORD start=GetTickCount();
    do {Pump(120);Require(GetTickCount()-start<20000,"log queue drain timeout");} while(page.m_logQueue.Size());
    Pump(150);
}
CWinApp testApplication;
int main(int argc, char** argv) {
    try {
        const bool baseline=argc>1;
        Require(AfxWinInit(GetModuleHandle(nullptr),nullptr,GetCommandLine(),0)!=FALSE,"MFC init");
        INITCOMMONCONTROLSEX controls={sizeof(controls),ICC_WIN95_CLASSES};InitCommonControlsEx(&controls);
        Require(Localization::Initialize()!=FALSE,"locale init");
        CWnd parent;
        Require(parent.CreateEx(0,AfxRegisterWndClass(0),L"ProxyLane log regression",WS_OVERLAPPEDWINDOW,
            CRect(20,20,1000,740),nullptr,0)!=FALSE,"parent");
        MeasuredPage page;Require(page.Create(IDD_Page2,&parent)!=FALSE,"log page");
        page.MoveWindow(0,0,960,660);page.ShowWindow(SW_SHOW);parent.ShowWindow(SW_SHOWNOACTIVATE);
        if (argc > 1 && !strcmp(argv[1], "--preview")) {
            page.CheckDlgButton(IDC_CHECK_LOADER_CAPTURE,BST_CHECKED);
            page.OnBnClickedLoaderCapture();
            OutputDebugStringA("[ProxyLane.Loader.v1] stage=LoadLibraryW error=0000007E\n");
            OutputDebugStringW(L"[ProxyLane.Hook.v1] fixture.exe (1) | stage=connect-control-pipe | module=kernel32.dll | API=CreateFile/WaitNamedPipe | error=5 (0x00000005) | Access denied");
            Pump(45000);
            page.DestroyWindow();parent.DestroyWindow();return 0;
        }
        if (!baseline) {
            PRCClient timeoutClient = {};
            timeoutClient.dwPid = 32012; timeoutClient.sType = SOCK_STREAM;
            WCHAR timeoutTarget[] = L"example.test:22";
            page.OnProxyFailure(&timeoutClient, L"curl.exe", timeoutTarget,
                TRUE, WSAETIMEDOUT, NULL);
            timeoutTarget[0] = L'X'; timeoutClient.dwPid = 0;
            Drain(page);
            CString timeoutLog = Contents(page);
            Require(timeoutLog.Find(L"curl.exe (32012)") >= 0 &&
                timeoutLog.Find(L"example.test:22") >= 0 && timeoutLog.Find(L"10060") >= 0 &&
                timeoutLog.Find(Localization::Get(L"log.connection_timeout")) >= 0,
                "localized timeout preserves borrowed PID and target in queued log");
            page.ClearAll();
            Require(page.IsDlgButtonChecked(IDC_CHECK_LOADER_CAPTURE)==BST_UNCHECKED,"diagnostic capture defaults off");
            page.CheckDlgButton(IDC_CHECK_LOADER_CAPTURE,BST_CHECKED);
            page.OnBnClickedLoaderCapture();
            Require(page.IsDlgButtonChecked(IDC_CHECK_LOADER_CAPTURE)==BST_CHECKED,"diagnostic capture starts");
            OutputDebugStringA("[ProxyLane.Loader.v1] stage=LoadLibraryW error=0000007E\n");
            Pump(400);Drain(page);
            Require(Contents(page).Find(L"126")>=0 && Contents(page).Find(L"LoadLibraryW")>=0,"diagnostic reaches real log edit");
            OutputDebugStringW(L"[ProxyLane.Hook.v1] fixture.exe (1) | stage=connect-control-pipe | module=kernel32.dll | API=CreateFile/WaitNamedPipe | error=5 (0x00000005) | Access denied");
            Pump(400);Drain(page);
            Require(Contents(page).Find(L"connect-control-pipe")>=0 && Contents(page).Find(L"CreateFile/WaitNamedPipe")>=0,"Hook initialization failure reaches real log edit");
            CRect checkbox,edit,copy;
            page.GetDlgItem(IDC_CHECK_LOADER_CAPTURE)->GetWindowRect(&checkbox);
            page.m_Edit.GetWindowRect(&edit);
            page.GetDlgItem(IDC_BTN_COPY_LOG)->GetWindowRect(&copy);
            Require(checkbox.bottom<=edit.top,"capture control does not overlap log");
            Require(checkbox.right<copy.left && checkbox.top==copy.top,"capture control is left of copy in toolbar");
            page.CheckDlgButton(IDC_CHECK_LOADER_CAPTURE,BST_UNCHECKED);
            page.OnBnClickedLoaderCapture();Drain(page);page.ClearAll();
            LoaderDiagnosticCapture occupied;
            Require(occupied.Start()==ERROR_SUCCESS,"test owns diagnostic channel");
            page.CheckDlgButton(IDC_CHECK_LOADER_CAPTURE,BST_CHECKED);
            page.OnBnClickedLoaderCapture();
            Require(page.IsDlgButtonChecked(IDC_CHECK_LOADER_CAPTURE)==BST_UNCHECKED,"occupied capture reverts checkbox");
            occupied.Stop();Drain(page);page.ClearAll();
        }
        // Seed near the old line cap; actual producer/notification/control path below.
        CString seed;
        for(int i=0;i<9990;++i) seed+=L"old log line\r\n";
        page.m_Edit.SetWindowText(seed);page.m_Edit.SetSel(seed.GetLength(),seed.GetLength());
        page.m_Edit.LineScroll(9990);
        std::atomic<bool> stop{false};
        std::thread producer([&] {
            unsigned id=0;
            while(!stop.load()) {
                for(int i=0;i<100;++i) {CString line;line.Format(L"event %u: proxy connection updated",id++);page.LogText(line);}
                PostMessage(page.m_hWnd,WM_APP+79,GetTickCount(),0);
                Sleep(20);
            }
        });
        double cpu=CpuSeconds();DWORD start=GetTickCount();Pump(10000);
        stop=true;producer.join();
        double loadCpu=100*(CpuSeconds()-cpu)/((GetTickCount()-start)/1000.0);
        size_t pending=page.m_logQueue.Size();
        Require(pending<=CPage2::MAX_PENDING_LOGS,"pending logs bounded");
        // Check while the producer's overflow is still recent: draining the
        // retained queue may legitimately trim those older warnings away.
        const bool sawOverflow=Contents(page).Find(Localization::Get(L"page2.dropped_logs").Left(4))>=0;
        Drain(page);
        int chars=page.m_Edit.GetWindowTextLength(), lines=page.m_Edit.GetLineCount();
        std::cout<<"load_cpu_one_core_percent="<<loadCpu<<" max_dispatch_ms="<<page.maxDispatchMs
            <<" max_heartbeat_ms="<<page.maxHeartbeatMs<<" heartbeats="<<page.heartbeats
            <<" pending="<<pending<<" chars="<<chars<<" lines="<<lines<<" notifications="<<page.flushes<<"\n";
        if(!baseline) {
            Require(chars<=256*1024 && lines<=CPage2::MAX_LOG_LINES,"display bounds");
            Require(page.maxDispatchMs<250 && page.maxHeartbeatMs<300 && page.heartbeats>100,"UI responsiveness under flood");
            Require(sawOverflow,"overflow notice displayed during overload");
            page.m_Edit.SetSel(100,120);page.m_Edit.LineScroll(-100000);
            CString selected=Contents(page).Mid(100,20);
            page.LogText(L"selection must survive append");Drain(page);
            int begin,end;page.m_Edit.GetSel(begin,end);
            Require(Contents(page).Mid(begin,end-begin)==selected,"selection preserved");
            Require(page.m_Edit.GetFirstVisibleLine()==0,"scroll position preserved");
        }
        page.ClearAll();page.LogText(L"fresh log after clear");Drain(page);
        CString text=Contents(page);
        Require(text.Left(3)==L"-- " && text.Find(L"fresh log after clear")>=0,"date heading after clear");
        if(!baseline) {
	        page.LogText(L"queued before clear");page.ClearAll();Drain(page);
	        Require(Contents(page).IsEmpty(),"clear removes delayed entries");
	        page.LogText(L"new date after clear");Drain(page);
            // A large append must also obey character bounds, not only line count.
            CString longLine(L'x',4096);
            for(int i=0;i<100;++i) page.LogText(longLine);
            Drain(page);
            Require(page.m_Edit.GetWindowTextLength()<=256*1024,"long-line character cap");
            Require(Contents(page).Left(3)==L"-- ","date restored after trim");
            page.m_Edit.ShowWindow(SW_HIDE);page.LogText(L"hidden log update");Drain(page);
            Require(!(page.m_Edit.GetStyle()&WS_VISIBLE),"hidden edit stays hidden");
            Require(page.maxDispatchMs<250,"long-line trimming remains responsive");
        }
        cpu=CpuSeconds();start=GetTickCount();unsigned before=page.flushes;Pump(3000);
        double idleCpu=100*(CpuSeconds()-cpu)/((GetTickCount()-start)/1000.0);
        std::cout<<"idle_cpu_one_core_percent="<<idleCpu<<" idle_log_notifications="<<page.flushes-before
            <<" max_dispatch_all_cases_ms="<<page.maxDispatchMs<<"\n";
        Require(idleCpu<5,"idle UI CPU");
        Require(page.flushes==before,"no idle log timer");
        page.LogText(L"destroy with pending refresh");Pump(20);page.DestroyWindow();parent.DestroyWindow();Pump(150);
        std::cout<<"PASS log page\n";return 0;
    } catch(const std::exception& e) {std::cerr<<"FAIL "<<e.what()<<"\n";return 1;}
}
