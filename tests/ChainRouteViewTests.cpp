#include "stdafx.h"
#include "ChainRouteView.h"
#include "ChainProgressPresentation.h"
#include "ProxyTestError.h"
#include "ModernUI.h"
#include <iostream>
#include <stdexcept>
#include <oleacc.h>

namespace {
void Check(bool ok, const char* text) { if (!ok) throw std::runtime_error(text); std::cout << "PASS: " << text << '\n'; }
class View : public CChainRouteView {
public:
    using CChainRouteView::get_accName;
    using CChainRouteView::get_accDescription;
    using CChainRouteView::get_accState;
    using CChainRouteView::accSelect;
    using CChainRouteView::accDoDefaultAction;
    void Settle() { Sleep(190); SendMessage(WM_TIMER, 1); }
    void Edge() { Sleep(660); SendMessage(WM_TIMER, 2); }
};
void Point(View& v, UINT message, CPoint p) { v.SendMessage(message, message == WM_LBUTTONUP ? 0 : MK_LBUTTON, MAKELPARAM(p.x,p.y)); }
void TestProgressPresentation() {
    ProxyInfo ssh; ssh.strProxyType=L"SSH"; ssh.sshAuth=0;
    Check(ProxyTestSshErrorDescription(PROXYERROR_AUTHFAILED,ssh,PTS_AUTH)==L"test.ssh_password_auth_failed",
        "SSH rejected credentials have an explicit authentication message");
    Check(ProxyTestSshErrorDescription(PROXYERROR_NOCONN,ssh,PTS_AUTH)==L"test.ssh_password_auth_interrupted",
        "SSH authentication disconnect does not claim rejected credentials");
    Check(ProxyTestSshErrorDescription(PROXYERROR_NOCONN,ssh,PTS_AUTH,WSAETIMEDOUT)==L"test.ssh_auth_timeout",
        "SSH authentication timeout is distinct from rejection");
    for(int phase : {PTS_CONNECTING,PTS_SSH,PTS_HOSTKEY,PTS_OPENING,PTS_PASSED})
        Check(ProxyTestSshErrorDescription(PROXYERROR_NOCONN,ssh,phase).IsEmpty(),"other SSH stages never blame authentication");
    ssh.sshAuth=1;
    Check(ProxyTestSshErrorDescription(PROXYERROR_NOCONN,ssh,PTS_AUTH)==L"test.ssh_key_auth_interrupted",
        "SSH private-key interruption uses key-specific advice");
    ssh.strProxyType=L"SOCKS5";
    Check(ProxyTestSshErrorDescription(PROXYERROR_AUTHFAILED,ssh,PTS_AUTH).IsEmpty(),"SSH guidance is not applied to other proxy protocols");
    using namespace ChainProgressPresentation;
    std::vector<ProxyTestHopProgress> raw(3);
    raw[0].stage=PTS_PASSED;
    raw[1].Apply(PTS_CONNECTING,100);raw[1].Apply(PTS_AUTH,120);raw[1].Apply(PTS_OPENING,150);
    std::vector<bool> negotiated={true,true,false},links(3,false);
    auto cards=Project(raw,negotiated,links,450);
    Check(cards[1].stage==PTS_PASSED&&cards[1].elapsed==50&&cards[2].stage==PTS_CONNECTING&&cards[2].elapsed==300,
        "next-hop connection runs on destination while negotiated source time freezes");
    raw[1].Apply(PTS_FAILED,500);raw[2].Apply(PTS_SKIPPED,500);links[1]=true;
    cards=Project(raw,negotiated,links,900);
    Check(cards[1].stage==PTS_PASSED&&cards[1].elapsed==50&&cards[2].stage==PTS_FAILED&&cards[2].elapsed==350&&cards[2].errorSource==1,
        "closed third port marks third card failed with only its inbound wait");
    Check(raw[1].stage==PTS_FAILED&&raw[1].Elapsed(900)==400&&raw[2].stage==PTS_SKIPPED,
        "presentation leaves transport failure ownership and timing untouched");
    raw[1].stage=PTS_TIMED_OUT;
    cards=Project(raw,negotiated,links,900);
    Check(cards[2].stage==PTS_TIMED_OUT&&cards[1].stage==PTS_PASSED,"link timeout belongs to destination");
    raw[1].stage=PTS_CANCELLED;links[1]=false;
    cards=Project(raw,negotiated,links,900);
    Check(cards[2].stage==PTS_CANCELLED&&cards[2].elapsed==350&&cards[1].stage==PTS_PASSED,"cancelled inbound wait freezes without blaming source");
    raw[1].stage=PTS_PASSED;raw[2]=ProxyTestHopProgress();
    raw[2].Apply(PTS_AUTH,500);raw[2].Apply(PTS_OPENING,560);negotiated[2]=true;
    cards=Project(raw,negotiated,links,1000);
    Check(cards[2].stage==PTS_PASSED&&cards[2].elapsed==410,"destination includes inbound connection and its own handshake, excluding final target");
    raw[2].Apply(PTS_FAILED,1100);links[2]=true;
    cards=Project(raw,negotiated,links,1500);
    Check(cards[2].stage==PTS_PASSED&&cards[2].elapsed==410,"final target failure does not turn the last successful proxy red");
    raw[1]=ProxyTestHopProgress();raw[2]=ProxyTestHopProgress();links.assign(3,false);negotiated[1]=false;
    raw[1].Apply(PTS_CONNECTING,100);raw[1].Apply(PTS_OPENING,150);
    cards=Project(raw,negotiated,links,450);
    Check(cards[1].stage==PTS_AUTH&&cards[2].stage==PTS_CONNECTING,"pending HTTP CONNECT never claims authentication passed");
    raw[1].Apply(PTS_FAILED,500);raw[2].Apply(PTS_SKIPPED,500);
    cards=Project(raw,negotiated,links,900);
    Check(cards[1].stage==PTS_FAILED&&cards[1].lastStage==PTS_AUTH&&cards[1].elapsed==400&&!cards[2].started&&cards[2].stage==PTS_SKIPPED,
        "HTTP 407 retains failure and response wait on authenticating proxy");
    links[1]=true;cards=Project(raw,negotiated,links,900);
    Check(cards[1].connectedOnly&&cards[1].stage==PTS_WAITING&&cards[2].stage==PTS_FAILED,
        "HTTP link failure leaves unconfirmed source neutral and destination red");
}
}
void TestChainRouteView() {
    TestProgressPresentation();
    CWnd host; Check(host.CreateEx(0,AfxRegisterWndClass(0),L"Chain view tests",WS_POPUP,CRect(0,0,900,600),NULL,0)!=FALSE,"hidden chain host");
    View view; Check(view.Create(&host,901)!=FALSE,"native chain view creation");
    CFont font; UiTheme::CreateUiFont(font,view,9); view.SetFont(&font);
    Check(view.GetFont() && view.GetFont()->GetSafeHandle()==font.GetSafeHandle(),"custom view retains the page's theme font");
    auto S=[&](int n){return UiTheme::ScaleForWindow(view,n);};
    const int oldHeight=view.PreferredHeight(); view.MoveWindow(0,0,S(680),oldHeight);
    Check(view.NodeRect(0).Height()>=S(60),"card retains room for its four content rows before nodes exist");
    // Reproduce older-host fonts, then enlarge them. Height must follow the
    // actual glyphs, including an empty view, without consulting a ListCtrl.
    CFont detail; UiTheme::CreateUiFont(detail,view,8);
    for (const wchar_t* face : { L"Tahoma", L"SimSun" }) {
        int previousHeight=0;
        for (int points : { 8, 9, 14 }) {
            LOGFONT lf={}; lf.lfHeight=-MulDiv(points,UiTheme::WindowDpi(view),72); wcscpy_s(lf.lfFaceName,face);
            CFont alternate; alternate.CreateFontIndirect(&lf); view.SetFont(&alternate);
            const int height=view.PreferredHeight(); view.MoveWindow(0,0,S(680),height);
            CClientDC dc(&view); CFont* old=dc.SelectObject(&alternate);
            TEXTMETRIC nameMetrics={},detailMetrics={}; dc.GetTextMetrics(&nameMetrics);
            dc.SelectObject(&detail); dc.GetTextMetrics(&detailMetrics); dc.SelectObject(old);
            Check(view.NodeRect(0).Height()>=S(24)+nameMetrics.tmHeight+2*detailMetrics.tmHeight,
                "legacy fonts leave separate space for name, Host and result");
            Check(height>=previousHeight,"larger fonts cannot shrink the card"); previousHeight=height;
            view.SetFont(&font);
        }
    }
    view.MoveWindow(0,0,S(680),oldHeight);
    std::vector<CChainRouteView::Node> nodes(12);
    for(int i=0;i<12;++i){nodes[i].name.Format(L"Node %d",i+1);nodes[i].host=L"long-host.example.test:1080";nodes[i].protocol=L"SOCKS5";}
    int edits=0,removes=0,moves=0,from=-1,to=-1;
    view.onAction=[&](CChainRouteView::Action action,int index,int target){if(action==CChainRouteView::Edit)++edits;if(action==CChainRouteView::Remove)++removes;if(action==CChainRouteView::Move){++moves;from=index;to=target;}};
    view.SetNodes(nodes);Check(view.Capacity()==3 && view.PageCount()==4,"long rectangular cards paginate without changing height");
    Check(view.At(0).elapsed.IsEmpty() && view.At(0).state==CChainRouteView::Idle,"idle card has no result or elapsed text");
    const CPoint body=view.NodeRect(0).CenterPoint();
    Point(view,WM_LBUTTONDOWN,body);Point(view,WM_MOUSEMOVE,body+CPoint(S(80),0));
    Check(view.NodeRect(0).left==S(24)+1+S(80)/4,"first-page overscroll uses launcher quarter-distance damping");
    Point(view,WM_LBUTTONUP,body+CPoint(S(80),0));view.Settle();Check(view.CurrentPage()==0 && view.NodeRect(0).left==S(24)+1,"boundary release springs back");
    Point(view,WM_LBUTTONDOWN,body);Point(view,WM_MOUSEMOVE,body-CPoint(S(180),0));Point(view,WM_LBUTTONUP,body-CPoint(S(180),0));view.Settle();
    Check(view.CurrentPage()==1 && moves==0,"dragging card body changes page without reordering");
    view.followProgress=true;view.Follow(8);view.Settle();Check(view.CurrentPage()==2,"test progress reveals its active page");
    view.Follow(7);Check(view.CurrentPage()==2,"progress on same page does not flip");
    view.SendMessage(WM_KEYDOWN,VK_PRIOR);view.Settle();view.Follow(11);Check(view.CurrentPage()==1,"manual page browsing suspends test following");
    view.SetProgress(3,CChainRouteView::Passed,L"120 ms",L"Passed");view.SetProgress(4,CChainRouteView::Failed,L"240 ms",L"Authentication failed");
    Check(view.At(3).elapsed==L"120 ms" && view.At(4).state==CChainRouteView::Failed,"completed success and failure retain their own times");
    view.SetEditable(false);view.Select(4);view.Settle();view.SendMessage(WM_KEYDOWN,VK_RETURN);view.SendMessage(WM_KEYDOWN,VK_DELETE);
    Check(edits==0 && removes==0,"test mode blocks edit and delete but allows selection and browsing");
    view.SetEditable(true);view.SendMessage(WM_KEYDOWN,VK_RETURN);view.SendMessage(WM_KEYDOWN,VK_DELETE);Check(edits==1&&removes==1,"keyboard editing and removal use owner actions");
    VARIANT child={};child.vt=VT_I4;child.lVal=5;BSTR text=NULL;
    Check(SUCCEEDED(view.get_accName(child,&text)) && CString(text)==L"Node 5","accessible node name");SysFreeString(text);
    view.get_accDescription(child,&text);Check(CString(text).Find(L"Authentication failed")>=0,"accessible description exposes the node's full error");SysFreeString(text);
    child.lVal=12;view.accSelect(SELFLAG_TAKESELECTION,child);view.Settle();Check(view.CurrentPage()==3&&view.Selected()==11,"accessibility selection reveals off-page nodes");
    view.SetNodes(nodes,0);view.Settle();
    CRect first=view.NodeRect(0),second=view.NodeRect(1);CPoint grip(first.left+S(12),first.top+S(10));CPoint target(second.right-S(8),second.CenterPoint().y);
    Point(view,WM_LBUTTONDOWN,grip);Point(view,WM_MOUSEMOVE,target);Point(view,WM_LBUTTONUP,target);
    Check(moves==1&&from==0&&to==1,"grip drop requests the correct ordered move");
    Point(view,WM_LBUTTONDOWN,grip);Point(view,WM_MOUSEMOVE,target);view.SendMessage(WM_CANCELMODE);Point(view,WM_LBUTTONUP,target);
    Check(moves==1,"cancelled reorder never commits to the owner's model");
    Point(view,WM_LBUTTONDOWN,grip);Point(view,WM_MOUSEMOVE,CPoint(S(670),first.CenterPoint().y));view.Edge();
    Check(view.CurrentPage()==1,"held reorder at edge flips to next page");
    CRect destination=view.NodeRect(3);target=CPoint(destination.right-S(8),destination.CenterPoint().y);
    Point(view,WM_MOUSEMOVE,target);Point(view,WM_LBUTTONUP,target);
    Check(moves==2&&from==0&&to==3,"cross-page reorder commits on release");
    view.SetNodes(nodes,0);view.Settle();Point(view,WM_LBUTTONDOWN,grip);Point(view,WM_MOUSEMOVE,second.CenterPoint());
    view.SetEditable(false);Point(view,WM_LBUTTONUP,second.CenterPoint());Check(moves==2,"starting a test cancels an unfinished reorder");
    view.SetEditable(true);view.UpdateNode(0,nodes[1]);Check(view.CurrentPage()==0&&view.Selected()==0,"editing node fields preserves page and selection");
    view.MoveWindow(0,0,S(320),oldHeight);Check(view.Capacity()==1&&view.PageCount()==12,"narrow layout paginates instead of growing vertically");
    view.Select(11);view.Settle();view.SetNodes({},-1);Check(view.CurrentPage()==0&&view.Selected()==-1&&view.PageCount()==1,"removing final node clamps page and selection");
    view.SetNodes(nodes,0);view.followProgress=true;view.Follow(11);view.SetNodes(nodes,0);
    view.SendMessage(WM_TIMER,1);
    Check(view.CurrentPage()==0 && view.NodeRect(0).left==S(24)+1,"queued animation timer cannot revive a replaced route");
    view.MoveWindow(0,0,S(680),oldHeight);
    auto dropOn=[&](int source,int targetIndex,bool rightHalf,bool margin) {
        view.SetNodes(nodes,source);view.Settle();
        CRect sourceRect=view.NodeRect(source),targetRect=view.NodeRect(targetIndex),client;view.GetClientRect(client);
        CPoint start(sourceRect.left+S(12),sourceRect.top+S(10));
        CPoint end(rightHalf?targetRect.right-S(8):targetRect.left+S(8),targetRect.CenterPoint().y);
        if(margin)end.x=targetIndex<source?S(4):client.right-S(4);
        const int before=moves;
        Point(view,WM_LBUTTONDOWN,start);Point(view,WM_MOUSEMOVE,end);Point(view,WM_LBUTTONUP,end);
        Check(moves==before+1&&from==source&&to==targetIndex,
            "adjacent reorder accepts either half of first/last card and outer margins");
    };
    for(bool rightHalf : {false,true}) { dropOn(1,0,rightHalf,false);dropOn(10,11,rightHalf,false); }
    dropOn(1,0,false,true);dropOn(10,11,true,true);
    // Own a visible off-screen window so animation lifecycle is exercised
    // without placing a test window over the user's desktop.
    BOOL animations=TRUE;SystemParametersInfo(SPI_GETCLIENTAREAANIMATION,0,&animations,0);
    host.SetWindowPos(NULL,-10000,-10000,900,600,SWP_NOACTIVATE|SWP_NOZORDER);
    host.ShowWindow(SW_SHOWNOACTIVATE);view.ShowWindow(SW_SHOWNOACTIVATE);view.SetNodes(nodes,0);
    view.SetProgress(0,CChainRouteView::Running,L"",L"Connecting");
    view.ValidateRect(NULL);view.SendMessage(WM_TIMER,3);
    CRect dirty;
    if(animations) {
        Check(view.GetUpdateRect(dirty,FALSE)!=FALSE,"running spinner schedules visual updates");
        CRect card=view.NodeRect(0);
        Check(dirty.left>card.CenterPoint().x&&dirty.top>card.CenterPoint().y&&dirty.right<=card.right&&dirty.bottom<=card.bottom,
            "spinner invalidates only the bottom-right indicator area");
    }
    view.SetProgress(0,CChainRouteView::Passed,L"120 ms",L"Passed");view.ValidateRect(NULL);view.SendMessage(WM_TIMER,3);
    Check(!view.GetUpdateRect(NULL,FALSE),"success stops spinner and ignores queued timer messages");
    view.SetProgress(0,CChainRouteView::Running,L"",L"");view.SetProgress(0,CChainRouteView::Failed,L"120 ms",L"");
    view.ValidateRect(NULL);view.SendMessage(WM_TIMER,3);
    Check(!view.GetUpdateRect(NULL,FALSE),"failure stops spinner immediately");
    view.SetProgress(0,CChainRouteView::Running,L"",L"");view.SetProgress(0,CChainRouteView::Idle,L"",L"Cancelled");
    view.ValidateRect(NULL);view.SendMessage(WM_TIMER,3);
    Check(!view.GetUpdateRect(NULL,FALSE),"cancellation stops spinner immediately");
    view.SetProgress(0,CChainRouteView::Running,L"",L"");view.ClearProgress();view.ValidateRect(NULL);view.SendMessage(WM_TIMER,3);
    Check(!view.GetUpdateRect(NULL,FALSE),"clearing results stops spinner");
    view.SetProgress(0,CChainRouteView::Running,L"",L"");view.ShowWindow(SW_HIDE);view.ValidateRect(NULL);view.SendMessage(WM_TIMER,3);
    Check(!view.GetUpdateRect(NULL,FALSE),"hidden chain view stops spinner");
    view.DestroyWindow();host.DestroyWindow();
}
