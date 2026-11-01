#define NOMINMAX
#include <windows.h>
#include <commctrl.h>
#include <UIAutomation.h>
#include <atlbase.h>
#include <chrono>
#include <atomic>
#include <algorithm>
#include <cstdio>
#include <stdexcept>
#include <thread>
#include "../../../src/ProxyLane/ProcessListAccessibility.h"
#pragma comment(lib,"comctl32.lib")
#pragma comment(lib,"ole32.lib")
using namespace ProcessListAccessibility;
static Bridge* bridge;
static std::atomic<unsigned> nativeCellReads{0};
static DWORD uiThread;
static std::atomic<unsigned> uiProviderReads{0},workerProviderReads{0};
namespace ProcessListAccessibility { void RecordProviderRead(){
    if(GetCurrentThreadId()==uiThread)++uiProviderReads;else ++workerProviderReads;
} }
static void Check(bool value,const char* text) {if(!value)throw std::runtime_error(text);}
static void HR(HRESULT value,const char* text) {if(FAILED(value)){printf("HRESULT %08lx: %s\n",value,text);throw std::runtime_error(text);}}
static LRESULT CALLBACK ListProc(HWND hwnd,UINT message,WPARAM wp,LPARAM lp,UINT_PTR,DWORD_PTR) {
    if(message==LVM_GETITEMTEXTW||message==LVM_GETITEMW||message==LVM_GETITEMCOUNT||message==LVM_GETITEMSTATE)
        ++nativeCellReads;
    if(message==WM_GETOBJECT&&static_cast<LONG>(lp)==UiaRootObjectId&&bridge)return bridge->GetObject(wp,lp);
    return DefSubclassProc(hwnd,message,wp,lp);
}
int main(int argc, char**) {
    setvbuf(stdout,nullptr,_IONBF,0);
    uiThread=GetCurrentThreadId();
    HR(CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED),"UI COM initialization");
    INITCOMMONCONTROLSEX controls={sizeof(controls),ICC_LISTVIEW_CLASSES};InitCommonControlsEx(&controls);
    WNDCLASSW type={};type.lpfnWndProc=DefWindowProcW;type.hInstance=GetModuleHandleW(nullptr);type.lpszClassName=L"ProxyLaneAccessibilityFixture";
    RegisterClassW(&type);
    HWND host=CreateWindowW(type.lpszClassName,L"Accessibility regression fixture",WS_OVERLAPPEDWINDOW,0,0,640,480,nullptr,nullptr,type.hInstance,nullptr);
    HWND window=CreateWindowW(WC_LISTVIEWW,L"",WS_CHILD|WS_VISIBLE|LVS_REPORT,0,0,620,440,host,nullptr,type.hInstance,nullptr);
    SetWindowSubclass(window,ListProc,1,0);
    HWND header=ListView_GetHeader(window);
    Bridge owner(window);bridge=&owner;Check(owner.Available(),"UI Automation unavailable");
    auto snapshot=std::make_shared<Snapshot>();snapshot->name=L"Processes";snapshot->header=header;
    const bool picker=argc>1;
    if(picker){snapshot->name=L"Applications";snapshot->automationId=L"1074";snapshot->columnCount=3;
        snapshot->canSelectMultiple=false;snapshot->sortableHeaders=false;}
    snapshot->client={0,0,620,440};snapshot->headerRect={0,0,620,24};snapshot->rowTop=24;snapshot->rowHeight=20;
    snapshot->visible=snapshot->enabled=true;
    for(int c=0;c<4;++c){snapshot->headings[c]=L"Column "+std::to_wstring(c);snapshot->columns[c]={c*155,0,(c+1)*155,24};}
    for(int i=0;i<500;++i){Row row;row.pid=100+i;row.created=10000+i;
        for(int c=0;c<4;++c)row.text[c]=L"row "+std::to_wstring(i)+L" column "+std::to_wstring(c);
        if(picker)row.accessibleName=L"Application "+std::to_wstring(i);
        snapshot->rows.push_back(row);}
    owner.Publish(snapshot,true);
    HANDLE ready=CreateEventW(nullptr,TRUE,FALSE,nullptr),start=CreateEventW(nullptr,TRUE,FALSE,nullptr),done=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    bool passed=false;
    std::thread client([&] {
        HRESULT com=CoInitializeEx(nullptr,COINIT_MULTITHREADED);
        try {
            HR(com,"client COM initialization");
            CComPtr<IUIAutomation> automation;HR(automation.CoCreateInstance(__uuidof(CUIAutomation)),"create UIA client");
            CComPtr<IUIAutomationElement> root;HR(automation->ElementFromHandle(window,&root),"get fixture element");
            CComPtr<IUIAutomationGridPattern> grid;
            HR(root->GetCurrentPatternAs(UIA_GridPatternId,__uuidof(IUIAutomationGridPattern),reinterpret_cast<void**>(&grid)),"get grid pattern");
            CComPtr<IUIAutomationCacheRequest> request;HR(automation->CreateCacheRequest(&request),"cache request");
            HR(request->put_TreeScope(TreeScope_Subtree),"subtree cache");
            for(int property:{UIA_NamePropertyId,UIA_ControlTypePropertyId,UIA_BoundingRectanglePropertyId,UIA_IsOffscreenPropertyId})
                HR(request->AddProperty(property),"cache property");
            // Establish HWND fragment entry points once while the UI is available.
            CComPtr<IUIAutomationElement> warm;HR(root->BuildUpdatedCache(request,&warm),"initial fragment discovery");
            SetEvent(ready);WaitForSingleObject(start,5000);
            auto began=std::chrono::steady_clock::now();
            nativeCellReads=0;
            CComPtr<IUIAutomationElement> cached;
            for(int repeat=0;repeat<8;++repeat){
                cached.Release();HR(root->BuildUpdatedCache(request,&cached),"bulk read alongside UI message pumping");
            }
            int count=0;HR(grid->get_CurrentRowCount(&count),"row count");Check(count==500,"missing rows");
            HR(grid->get_CurrentColumnCount(&count),"column count");Check(count==snapshot->columnCount,"wrong column count");
            CComPtr<IUIAutomationElement> outside;
            Check(grid->GetItem(0,snapshot->columnCount,&outside)==E_INVALIDARG,"phantom extra column");
            CComPtr<IUIAutomationSelectionPattern> container;
            HR(root->GetCurrentPatternAs(UIA_SelectionPatternId,__uuidof(IUIAutomationSelectionPattern),reinterpret_cast<void**>(&container)),"selection container");
            BOOL multiple;HR(container->get_CurrentCanSelectMultiple(&multiple),"selection mode");Check((multiple!=FALSE)==!picker,"wrong selection mode");
            CComPtr<IUIAutomationElementArray> children;HR(cached->GetCachedChildren(&children),"cached children");
            HR(children->get_Length(&count),"children count");Check(count==501,"expected header and 500 process rows");
            CComPtr<IUIAutomationElement> cell;HR(grid->GetItem(4,2,&cell),"grid cell");
            CComBSTR name;HR(cell->get_CurrentName(&name),"cell name");Check(wcscmp(name,L"row 4 column 2")==0,"wrong cell");
            CComPtr<IUIAutomationTreeWalker> walker;HR(automation->get_RawViewWalker(&walker),"tree walker");
            CComPtr<IUIAutomationElement> row;HR(walker->GetParentElement(cell,&row),"cell parent");
            if(picker){name.Empty();HR(row->get_CurrentName(&name),"app name");Check(wcscmp(name,L"Application 4")==0,"app row exposed process identity");}
            CComPtr<IUIAutomationSelectionItemPattern> selection;
            HR(row->GetCurrentPatternAs(UIA_SelectionItemPatternId,__uuidof(IUIAutomationSelectionItemPattern),reinterpret_cast<void**>(&selection)),"selection pattern");
            HR(selection->AddToSelection(),"queue selection without waiting for UI");
            const auto commands=owner.TakeRequests();
            bool selected=false;for(const auto& command:commands){
                selected|=command.hasRow&&command.pid==104&&command.created==10004&&command.action==AddSelection;
            }Check(selected,"wrong queued identity");
            if(picker){
                auto selectedOther=std::make_shared<Snapshot>(*snapshot);selectedOther->rows[1].selected=true;owner.Publish(selectedOther,false);
                Check(selection->AddToSelection()==UIA_E_INVALIDOPERATION,"single-selection accepted a second row");
                CComPtr<IUIAutomationTablePattern> table;
                HR(root->GetCurrentPatternAs(UIA_TablePatternId,__uuidof(IUIAutomationTablePattern),reinterpret_cast<void**>(&table)),"table pattern");
                CComPtr<IUIAutomationElementArray> headers;HR(table->GetCurrentColumnHeaders(&headers),"picker headers");
                HR(headers->get_Length(&count),"header count");Check(count==3,"wrong picker headers");
                CComPtr<IUIAutomationElement> heading;HR(headers->GetElement(0,&heading),"first header");
                CComPtr<IUnknown> invoke;heading->GetCurrentPattern(UIA_InvokePatternId,&invoke);Check(!invoke,"picker header exposed sorting");
                auto filtered=std::make_shared<Snapshot>(*snapshot);filtered->rows.erase(filtered->rows.begin()+4);owner.Publish(filtered,true);
                name.Empty();Check(cell->get_CurrentName(&name)==UIA_E_ELEMENTNOTAVAILABLE,"filtered app remained available");
            }
            auto reordered=std::make_shared<Snapshot>(*snapshot);
            std::reverse(reordered->rows.begin(),reordered->rows.end());owner.Publish(reordered,true);
            CComPtr<IUIAutomationGridItemPattern> item;
            HR(cell->GetCurrentPatternAs(UIA_GridItemPatternId,__uuidof(IUIAutomationGridItemPattern),reinterpret_cast<void**>(&item)),"grid item after sorting");
            HR(item->get_CurrentRow(&count),"sorted row index");Check(count==495,"row identity lost after sorting");
            auto replaced=std::make_shared<Snapshot>(*reordered);replaced->rows[495].created+=999;
            owner.Publish(replaced,true);
            name.Empty();Check(cell->get_CurrentName(&name)==UIA_E_ELEMENTNOTAVAILABLE,"stale PID reuse object survived");
            const double ms=std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-began).count();
            Check(ms<4000,"bulk reads exceeded responsiveness budget");
            Check(nativeCellReads==0,"UIA fell back to reading native list cells");
            printf("PASS: %s, 8 bulk reads of 500 rows/%d cells, no native cell reads, queued selection, stale identity rejection; %.1f ms\n",picker?"picker":"processes",500*snapshot->columnCount,ms);
            passed=true;
        } catch(const std::exception& error){printf("FAIL: %s\n",error.what());}
        SetEvent(ready);SetEvent(done);if(SUCCEEDED(com))CoUninitialize();
    });
    DWORD limit=GetTickCount()+10000;
    while(WaitForSingleObject(ready,0)!=WAIT_OBJECT_0&&GetTickCount()<limit){
        MsgWaitForMultipleObjects(1,&ready,FALSE,100,QS_ALLINPUT);MSG message;
        while(PeekMessageW(&message,nullptr,0,0,PM_REMOVE)){TranslateMessage(&message);DispatchMessageW(&message);}
    }
    // UIA still needs the HWND's entry-point/lifetime messages. Keep those
    // available, but verify it never returns to per-cell list-view messages.
    SetEvent(start);
    limit=GetTickCount()+10000;
    double longestDispatch=0;
    while(WaitForSingleObject(done,0)!=WAIT_OBJECT_0){
        if(GetTickCount()>=limit){puts("FAIL: UIA client did not recover within 10 seconds");ExitProcess(2);}
        auto began=std::chrono::steady_clock::now();
        MSG message;while(PeekMessageW(&message,nullptr,0,0,PM_REMOVE))DispatchMessageW(&message);
        longestDispatch=(std::max)(longestDispatch,std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-began).count());
        MsgWaitForMultipleObjects(1,&done,FALSE,10,QS_ALLINPUT);
    }
    printf("Maximum UI dispatch batch: %.1f ms\n",longestDispatch);
    printf("Provider reads: UI=%u worker=%u\n",uiProviderReads.load(),workerProviderReads.load());
    client.join();bridge=nullptr;DestroyWindow(host);
    CloseHandle(ready);CloseHandle(start);CloseHandle(done);CoUninitialize();
    return passed&&longestDispatch<100&&uiProviderReads==0&&workerProviderReads>100000?0:1;
}
