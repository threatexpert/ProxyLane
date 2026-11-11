#define NOMINMAX
#include "ProcessListAccessibility.h"
#include <UIAutomation.h>
#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <future>
#include <map>
#include <mutex>
#include <new>
#include <thread>
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

namespace ProcessListAccessibility {
#ifdef PL_ACCESSIBILITY_TEST
void RecordProviderRead();
#endif
namespace {
struct Api {
    decltype(&UiaReturnRawElementProvider) returnProvider = nullptr;
    decltype(&UiaHostProviderFromHwnd) host = nullptr;
    decltype(&UiaRaiseStructureChangedEvent) structure = nullptr;
    decltype(&UiaRaiseAutomationEvent) event = nullptr;
    typedef HRESULT (WINAPI* Disconnect)(IRawElementProviderSimple*);
    Disconnect disconnect = nullptr;
    Api() {
        wchar_t path[MAX_PATH];
        UINT length = GetSystemDirectoryW(path, MAX_PATH);
        if (!length || length + 22 >= MAX_PATH) return;
        wcscat_s(path, L"\\UIAutomationCore.dll");
        HMODULE module = LoadLibraryW(path);
        if (!module) return;
        // Providers can outlive their control; keep the module loaded.
        returnProvider = reinterpret_cast<decltype(returnProvider)>(GetProcAddress(module, "UiaReturnRawElementProvider"));
        host = reinterpret_cast<decltype(host)>(GetProcAddress(module, "UiaHostProviderFromHwnd"));
        structure = reinterpret_cast<decltype(structure)>(GetProcAddress(module, "UiaRaiseStructureChangedEvent"));
        event = reinterpret_cast<decltype(event)>(GetProcAddress(module, "UiaRaiseAutomationEvent"));
        disconnect = reinterpret_cast<Disconnect>(GetProcAddress(module, "UiaDisconnectProvider"));
    }
};
Api& Functions() { static Api api; return api; }
enum Kind { Root, HeaderBar, Header, Item, Cell };
class Provider;
typedef std::pair<DWORD, ULONGLONG> Identity;
struct Published {
    std::shared_ptr<const Snapshot> view;
    std::map<Identity, size_t> indices;
};
template<class F> HRESULT Guard(F call) {
    try { return call(); } catch (const std::bad_alloc&) { return E_OUTOFMEMORY; } catch (...) { return E_FAIL; }
}
HRESULT Text(VARIANT* value, const std::wstring& text) {
    value->vt = VT_BSTR; value->bstrVal = SysAllocStringLen(text.data(), static_cast<UINT>(text.size()));
    return value->bstrVal ? S_OK : E_OUTOFMEMORY;
}
void Boolean(VARIANT* value, bool flag) { value->vt = VT_BOOL; value->boolVal = flag ? VARIANT_TRUE : VARIANT_FALSE; }
}

struct Bridge::State {
    HWND window;
    std::mutex mutex;
    std::condition_variable wake;
    bool alive = true, pending = false, structureChanged = false, selectionChanged = false, focusChanged = false;
    std::shared_ptr<const Published> current;
    std::deque<Request> requests;
    Provider* root = nullptr;
    Provider* header = nullptr;
    explicit State(HWND hwnd) : window(hwnd) {}
    std::shared_ptr<const Published> Read() {
        std::lock_guard<std::mutex> lock(mutex);
        return alive ? current : nullptr;
    }
    HRESULT Queue(Request request) {
        std::lock_guard<std::mutex> lock(mutex);
        if (!alive || !current) return UIA_E_ELEMENTNOTAVAILABLE;
        if (!current->view->enabled || !current->view->visible) return UIA_E_ELEMENTNOTENABLED;
        if (request.hasRow && current->indices.find({request.pid, request.created}) == current->indices.end())
            return UIA_E_ELEMENTNOTAVAILABLE;
        if (request.action == AddSelection && !current->view->canSelectMultiple)
            for (const auto& row : current->view->rows)
                if (row.selected && (row.pid != request.pid || row.created != request.created))
                    return UIA_E_INVALIDOPERATION;
        if (request.action == Sort && !current->view->sortableHeaders) return UIA_E_NOTSUPPORTED;
        if (requests.size() >= 64) return UIA_E_INVALIDOPERATION;
        requests.push_back(request);
        if (!PostMessageW(window, RequestMessage, 0, 0)) { requests.pop_back(); return UIA_E_ELEMENTNOTAVAILABLE; }
        return S_OK;
    }
};

namespace {
class Provider final : public IRawElementProviderSimple, public IRawElementProviderFragment,
    public IRawElementProviderFragmentRoot, public IRawElementProviderHwndOverride,
    public IGridProvider, public ITableProvider, public ISelectionProvider,
    public ISelectionItemProvider, public IScrollItemProvider, public IScrollProvider,
    public IGridItemProvider, public ITableItemProvider, public IValueProvider, public IInvokeProvider {
    std::atomic<ULONG> refs{1};
    std::shared_ptr<Bridge::State> state;
    Kind kind;
    Identity identity;
    int column;
    bool RowIndex(const Published& data, size_t& index) const {
        auto found = data.indices.find(identity);
        if (found == data.indices.end()) return false;
        index = found->second; return true;
    }
    std::shared_ptr<const Published> Data(size_t* index = nullptr) const {
#ifdef PL_ACCESSIBILITY_TEST
        RecordProviderRead();
#endif
        auto data = state->Read(); size_t row = 0;
        if (data && (kind == Header || kind == Cell) && (column < 0 || column >= data->view->columnCount)) return nullptr;
        if (data && (kind == Item || kind == Cell) && !RowIndex(*data, row)) return nullptr;
        if (index) *index = row;
        return data;
    }
    Provider* New(Kind type, Identity id = {}, int col = -1) {
        if (type == Root || type == HeaderBar) {
            std::lock_guard<std::mutex> lock(state->mutex);
            if (!state->alive) return nullptr;
            Provider* existing = type == Root ? state->root : state->header;
            existing->AddRef(); return existing;
        }
        return new (std::nothrow) Provider(state, type, id, col);
    }
    HRESULT Fragment(Kind type, Identity id, int col, IRawElementProviderFragment** value) {
        Provider* provider = New(type, id, col);
        if (!provider) return E_OUTOFMEMORY;
        *value = static_cast<IRawElementProviderFragment*>(provider); return S_OK;
    }
    HRESULT Simple(Kind type, Identity id, int col, IRawElementProviderSimple** value) {
        Provider* provider = New(type, id, col);
        if (!provider) return E_OUTOFMEMORY;
        *value = static_cast<IRawElementProviderSimple*>(provider); return S_OK;
    }
    HRESULT Queue(Action action, double x = 0, double y = 0) {
        Request request; request.action = action; request.pid = identity.first; request.created = identity.second;
        request.hasRow = kind == Item || kind == Cell;
        request.column = column; request.x = x; request.y = y;
        return Guard([&] { return state->Queue(request); });
    }
    RECT Bounds(const Snapshot& view, size_t row) const {
        RECT rect = view.client;
        if (kind == HeaderBar) rect = view.headerRect;
        else if (kind == Header) rect = view.columns[column];
        else if (kind == Item || kind == Cell) {
            rect.top = view.rowTop + (static_cast<int>(row) - view.top) * view.rowHeight;
            rect.bottom = rect.top + view.rowHeight;
            if (kind == Cell) { rect.left = view.columns[column].left; rect.right = view.columns[column].right; }
            RECT viewport = view.client; viewport.top = view.headerRect.bottom;
            RECT clipped = {}; IntersectRect(&clipped, &rect, &viewport); rect = clipped;
        }
        if (!view.visible) SetRectEmpty(&rect);
        return rect;
    }
    HRESULT Array(const std::vector<Provider*>& providers, SAFEARRAY** result) {
        *result = SafeArrayCreateVector(VT_UNKNOWN, 0, static_cast<ULONG>(providers.size()));
        HRESULT hr = *result ? S_OK : E_OUTOFMEMORY;
        for (LONG i = 0; i < static_cast<LONG>(providers.size()); ++i) {
            if (!providers[i]) hr = E_OUTOFMEMORY;
            if (SUCCEEDED(hr)) hr = SafeArrayPutElement(*result, &i, static_cast<IRawElementProviderSimple*>(providers[i]));
            if (providers[i]) providers[i]->Release();
        }
        if (FAILED(hr) && *result) { SafeArrayDestroy(*result); *result = nullptr; }
        return hr;
    }
public:
    Provider(std::shared_ptr<Bridge::State> shared, Kind type, Identity id = {}, int col = -1)
        : state(std::move(shared)), kind(type), identity(id), column(col) {}
    // Standard COM marshaling is intentional. An agile/free-threaded marshaler
    // lets UIA call directly on the UI thread, defeating UseComThreading.
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** value) override {
        if (!value) return E_POINTER; *value = nullptr;
        if (iid == __uuidof(IUnknown) || iid == __uuidof(IRawElementProviderSimple)) *value = static_cast<IRawElementProviderSimple*>(this);
#define SUPPORT(type, condition) else if (iid == __uuidof(type) && (condition)) *value = static_cast<type*>(this)
        SUPPORT(IRawElementProviderFragment, true);
        SUPPORT(IRawElementProviderFragmentRoot, kind == Root);
        SUPPORT(IRawElementProviderHwndOverride, kind == Root);
        SUPPORT(IGridProvider, kind == Root);
        SUPPORT(ITableProvider, kind == Root);
        SUPPORT(ISelectionProvider, kind == Root);
        SUPPORT(IScrollProvider, kind == Root);
        SUPPORT(ISelectionItemProvider, kind == Item);
        SUPPORT(IScrollItemProvider, kind == Item || kind == Cell);
        SUPPORT(IGridItemProvider, kind == Cell);
        SUPPORT(ITableItemProvider, kind == Cell);
        SUPPORT(IValueProvider, kind == Cell);
        SUPPORT(IInvokeProvider, kind == Header);
#undef SUPPORT
        else return E_NOINTERFACE;
        AddRef(); return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++refs; }
    ULONG STDMETHODCALLTYPE Release() override { ULONG count = --refs; if (!count) delete this; return count; }
    HRESULT STDMETHODCALLTYPE get_ProviderOptions(ProviderOptions* value) override {
        if (!value) return E_POINTER;
        *value = static_cast<ProviderOptions>(ProviderOptions_ServerSideProvider | ProviderOptions_UseComThreading |
            ProviderOptions_ProviderOwnsSetFocus | (kind == HeaderBar ? ProviderOptions_OverrideProvider : 0));
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetPatternProvider(PATTERNID pattern, IUnknown** value) override {
        if (!value) return E_POINTER; *value = nullptr;
        auto data = Data(); if (!data) return UIA_E_ELEMENTNOTAVAILABLE;
        if (pattern == UIA_GridPatternId && kind == Root) *value = static_cast<IGridProvider*>(this);
        if (pattern == UIA_TablePatternId && kind == Root) *value = static_cast<ITableProvider*>(this);
        if (pattern == UIA_SelectionPatternId && kind == Root) *value = static_cast<ISelectionProvider*>(this);
        if (pattern == UIA_ScrollPatternId && kind == Root) *value = static_cast<IScrollProvider*>(this);
        if (pattern == UIA_SelectionItemPatternId && kind == Item) *value = static_cast<ISelectionItemProvider*>(this);
        if (pattern == UIA_ScrollItemPatternId && (kind == Item || kind == Cell)) *value = static_cast<IScrollItemProvider*>(this);
        if (pattern == UIA_GridItemPatternId && kind == Cell) *value = static_cast<IGridItemProvider*>(this);
        if (pattern == UIA_TableItemPatternId && kind == Cell) *value = static_cast<ITableItemProvider*>(this);
        if (pattern == UIA_ValuePatternId && kind == Cell) *value = static_cast<IValueProvider*>(this);
        if (pattern == UIA_InvokePatternId && kind == Header && data->view->sortableHeaders) *value = static_cast<IInvokeProvider*>(this);
        if (*value) AddRef(); return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetPropertyValue(PROPERTYID property, VARIANT* value) override {
        if (!value) return E_POINTER; VariantInit(value);
        return Guard([&]() -> HRESULT {
            size_t row; auto data = Data(&row); if (!data) return UIA_E_ELEMENTNOTAVAILABLE;
            const auto& view = *data->view;
            switch (property) {
            case UIA_ControlTypePropertyId:
                value->vt = VT_I4; value->lVal = kind == Root ? UIA_DataGridControlTypeId : kind == HeaderBar ? UIA_HeaderControlTypeId :
                    kind == Header ? UIA_HeaderItemControlTypeId : kind == Item ? UIA_DataItemControlTypeId : UIA_TextControlTypeId; break;
            case UIA_NamePropertyId:
                return Text(value, kind == Root ? view.name : kind == HeaderBar ? L"" : kind == Header ? view.headings[column] :
                    kind == Cell ? view.rows[row].text[column] : !view.rows[row].accessibleName.empty() ? view.rows[row].accessibleName :
                    view.rows[row].text[1] + L" (PID " + view.rows[row].text[0] + L")");
            case UIA_AutomationIdPropertyId:
                return Text(value, kind == Root ? view.automationId : kind == Item ? std::to_wstring(identity.first) : std::to_wstring(column));
            case UIA_IsControlElementPropertyId: case UIA_IsContentElementPropertyId: Boolean(value, true); break;
            case UIA_IsEnabledPropertyId: Boolean(value, view.enabled); break;
            case UIA_IsKeyboardFocusablePropertyId: Boolean(value, kind == Root || kind == Item); break;
            case UIA_HasKeyboardFocusPropertyId: Boolean(value, view.hasFocus && (kind == Root ? view.focused < 0 : kind == Item && view.focused == static_cast<int>(row))); break;
            case UIA_IsOffscreenPropertyId: { RECT rect = Bounds(view, row); Boolean(value, IsRectEmpty(&rect) != FALSE); break; }
            case UIA_IsPasswordPropertyId: Boolean(value, false); break;
            case UIA_FrameworkIdPropertyId: return Text(value, L"Win32");
            }
            return S_OK;
        });
    }
    HRESULT STDMETHODCALLTYPE get_HostRawElementProvider(IRawElementProviderSimple** value) override {
        if (!value) return E_POINTER; *value = nullptr;
        auto data = Data(); if (!data) return UIA_E_ELEMENTNOTAVAILABLE;
        if (kind == Root || kind == HeaderBar)
            return Functions().host(kind == Root ? state->window : data->view->header, value);
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Navigate(NavigateDirection direction, IRawElementProviderFragment** value) override {
        if (!value) return E_POINTER; *value = nullptr;
        return Guard([&]() -> HRESULT {
            size_t row; auto data = Data(&row); if (!data) return UIA_E_ELEMENTNOTAVAILABLE;
            const auto& rows = data->view->rows;
            auto item = [&](size_t index) { return Fragment(Item, { rows[index].pid, rows[index].created }, -1, value); };
            if (direction == NavigateDirection_Parent && kind != Root)
                return Fragment(kind == Cell ? Item : kind == Header ? HeaderBar : Root, kind == Cell ? identity : Identity(), -1, value);
            if (kind == Root) {
                if (direction == NavigateDirection_FirstChild) return Fragment(HeaderBar, {}, -1, value);
                if (direction == NavigateDirection_LastChild) return rows.empty() ? Fragment(HeaderBar, {}, -1, value) : item(rows.size()-1);
            } else if (kind == HeaderBar) {
                if (direction == NavigateDirection_FirstChild || direction == NavigateDirection_LastChild)
                    return Fragment(Header, {}, direction == NavigateDirection_FirstChild ? 0 : data->view->columnCount - 1, value);
                if (direction == NavigateDirection_NextSibling && !rows.empty()) return item(0);
            } else if (kind == Item) {
                if (direction == NavigateDirection_FirstChild || direction == NavigateDirection_LastChild)
                    return Fragment(Cell, identity, direction == NavigateDirection_FirstChild ? 0 : data->view->columnCount - 1, value);
                if (direction == NavigateDirection_NextSibling && row+1 < rows.size()) return item(row+1);
                if (direction == NavigateDirection_PreviousSibling) return row ? item(row-1) : Fragment(HeaderBar, {}, -1, value);
            } else {
                int next = column + (direction == NavigateDirection_NextSibling ? 1 : -1);
                if ((direction == NavigateDirection_NextSibling || direction == NavigateDirection_PreviousSibling) && next >= 0 && next < data->view->columnCount)
                    return Fragment(kind, identity, next, value);
            }
            return S_OK;
        });
    }
    HRESULT STDMETHODCALLTYPE GetRuntimeId(SAFEARRAY** value) override {
        if (!value) return E_POINTER; *value = nullptr;
        if (!Data()) return UIA_E_ELEMENTNOTAVAILABLE;
        if (kind == Root || kind == HeaderBar) return S_OK;
        int id[] = { UiaAppendRuntimeId, kind, static_cast<int>(identity.first), static_cast<int>(identity.second), static_cast<int>(identity.second >> 32), column };
        *value = SafeArrayCreateVector(VT_I4, 0, _countof(id)); if (!*value) return E_OUTOFMEMORY;
        for (LONG i=0;i<_countof(id);++i) SafeArrayPutElement(*value,&i,&id[i]); return S_OK;
    }
    HRESULT STDMETHODCALLTYPE get_BoundingRectangle(UiaRect* value) override {
        if (!value) return E_POINTER; *value = {};
        size_t row; auto data = Data(&row); if (!data) return UIA_E_ELEMENTNOTAVAILABLE;
        RECT rect = Bounds(*data->view, row); if (IsRectEmpty(&rect)) return S_OK;
        POINT origin = {}; if (!ClientToScreen(state->window, &origin)) return UIA_E_ELEMENTNOTAVAILABLE;
        value->left=rect.left+origin.x; value->top=rect.top+origin.y; value->width=rect.right-rect.left; value->height=rect.bottom-rect.top; return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetEmbeddedFragmentRoots(SAFEARRAY** value) override { if (!value) return E_POINTER; *value=nullptr; return S_OK; }
    HRESULT STDMETHODCALLTYPE SetFocus() override { return Queue(Focus); }
    HRESULT STDMETHODCALLTYPE get_FragmentRoot(IRawElementProviderFragmentRoot** value) override {
        if (!value) return E_POINTER; *value=nullptr; if (!Data()) return UIA_E_ELEMENTNOTAVAILABLE;
        Provider* root=New(Root); if(!root)return E_OUTOFMEMORY; *value=static_cast<IRawElementProviderFragmentRoot*>(root);return S_OK;
    }
    HRESULT STDMETHODCALLTYPE ElementProviderFromPoint(double x,double y,IRawElementProviderFragment** value) override {
        if(!value)return E_POINTER;*value=nullptr;auto data=Data();if(!data)return UIA_E_ELEMENTNOTAVAILABLE;
        POINT origin={};if(!ClientToScreen(state->window,&origin))return UIA_E_ELEMENTNOTAVAILABLE;
        POINT point={static_cast<LONG>(x)-origin.x,static_cast<LONG>(y)-origin.y}; const auto& v=*data->view;
        if(!v.visible||!PtInRect(&v.client,point))return S_OK;
        int col=-1;for(int i=0;i<v.columnCount;++i)if(point.x>=v.columns[i].left&&point.x<v.columns[i].right)col=i;
        if(point.y<v.headerRect.bottom)return Fragment(col>=0?Header:HeaderBar,{},col,value);
        int row=v.top+(point.y-v.rowTop)/v.rowHeight;
        if(row>=0&&row<static_cast<int>(v.rows.size()))return Fragment(col>=0?Cell:Item,{v.rows[row].pid,v.rows[row].created},col,value);
        return Fragment(Root,{},-1,value);
    }
    HRESULT STDMETHODCALLTYPE GetFocus(IRawElementProviderFragment** value) override {
        if(!value)return E_POINTER;*value=nullptr;auto data=Data();if(!data)return UIA_E_ELEMENTNOTAVAILABLE;
        const auto& v=*data->view;if(!v.hasFocus)return S_OK;
        if(v.focused>=0&&v.focused<static_cast<int>(v.rows.size()))return Fragment(Item,{v.rows[v.focused].pid,v.rows[v.focused].created},-1,value);
        return Fragment(Root,{},-1,value);
    }
    HRESULT STDMETHODCALLTYPE GetOverrideProviderForHwnd(HWND hwnd,IRawElementProviderSimple** value) override {
        if(!value)return E_POINTER;*value=nullptr;auto data=Data();if(!data)return UIA_E_ELEMENTNOTAVAILABLE;
        return hwnd==data->view->header?Simple(HeaderBar,{},-1,value):S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetItem(int row,int col,IRawElementProviderSimple** value) override {
        if(!value)return E_POINTER;*value=nullptr;auto data=Data();if(!data)return UIA_E_ELEMENTNOTAVAILABLE;
        if(row<0||row>=static_cast<int>(data->view->rows.size())||col<0||col>=data->view->columnCount)return E_INVALIDARG;
        const auto& item=data->view->rows[row];return Simple(Cell,{item.pid,item.created},col,value);
    }
    HRESULT STDMETHODCALLTYPE get_RowCount(int* value) override {if(!value)return E_POINTER;auto data=Data();if(!data)return UIA_E_ELEMENTNOTAVAILABLE;*value=static_cast<int>(data->view->rows.size());return S_OK;}
    HRESULT STDMETHODCALLTYPE get_ColumnCount(int* value) override {if(!value)return E_POINTER;auto data=Data();if(!data)return UIA_E_ELEMENTNOTAVAILABLE;*value=data->view->columnCount;return S_OK;}
    HRESULT STDMETHODCALLTYPE GetRowHeaders(SAFEARRAY** value) override {if(!value)return E_POINTER;return Array({},value);}
    HRESULT STDMETHODCALLTYPE GetColumnHeaders(SAFEARRAY** value) override {
        if(!value)return E_POINTER;*value=nullptr;return Guard([&]() -> HRESULT {auto data=Data();if(!data)return UIA_E_ELEMENTNOTAVAILABLE;std::vector<Provider*> headers;headers.reserve(data->view->columnCount);for(int i=0;i<data->view->columnCount;++i)headers.push_back(New(Header,{},i));return Array(headers,value);});
    }
    HRESULT STDMETHODCALLTYPE get_RowOrColumnMajor(RowOrColumnMajor* value) override {if(!value)return E_POINTER;*value=RowOrColumnMajor_RowMajor;return S_OK;}
    HRESULT STDMETHODCALLTYPE GetSelection(SAFEARRAY** value) override {
        if(!value)return E_POINTER;*value=nullptr;return Guard([&]() -> HRESULT {auto data=Data();if(!data)return UIA_E_ELEMENTNOTAVAILABLE;
            std::vector<Provider*> items;items.reserve(data->view->rows.size());for(const auto& row:data->view->rows)if(row.selected)items.push_back(New(Item,{row.pid,row.created}));return Array(items,value);});
    }
    HRESULT STDMETHODCALLTYPE get_CanSelectMultiple(BOOL* value) override {if(!value)return E_POINTER;auto data=Data();if(!data)return UIA_E_ELEMENTNOTAVAILABLE;*value=data->view->canSelectMultiple;return S_OK;}
    HRESULT STDMETHODCALLTYPE get_IsSelectionRequired(BOOL* value) override {if(!value)return E_POINTER;*value=FALSE;return S_OK;}
    HRESULT STDMETHODCALLTYPE Select() override {return Queue(ProcessListAccessibility::Select);}
    HRESULT STDMETHODCALLTYPE AddToSelection() override {return Queue(AddSelection);}
    HRESULT STDMETHODCALLTYPE RemoveFromSelection() override {return Queue(RemoveSelection);}
    HRESULT STDMETHODCALLTYPE get_IsSelected(BOOL* value) override {if(!value)return E_POINTER;size_t row;auto data=Data(&row);if(!data)return UIA_E_ELEMENTNOTAVAILABLE;*value=data->view->rows[row].selected;return S_OK;}
    HRESULT STDMETHODCALLTYPE get_SelectionContainer(IRawElementProviderSimple** value) override {if(!value)return E_POINTER;*value=nullptr;return Simple(Root,{},-1,value);}
    HRESULT STDMETHODCALLTYPE ScrollIntoView() override {return Queue(Reveal);}
    HRESULT STDMETHODCALLTYPE get_Row(int* value) override {if(!value)return E_POINTER;size_t row;auto data=Data(&row);if(!data)return UIA_E_ELEMENTNOTAVAILABLE;*value=static_cast<int>(row);return S_OK;}
    HRESULT STDMETHODCALLTYPE get_Column(int* value) override {if(!value)return E_POINTER;*value=column;return S_OK;}
    HRESULT STDMETHODCALLTYPE get_RowSpan(int* value) override {if(!value)return E_POINTER;*value=1;return S_OK;}
    HRESULT STDMETHODCALLTYPE get_ColumnSpan(int* value) override {if(!value)return E_POINTER;*value=1;return S_OK;}
    HRESULT STDMETHODCALLTYPE get_ContainingGrid(IRawElementProviderSimple** value) override {return get_SelectionContainer(value);}
    HRESULT STDMETHODCALLTYPE GetRowHeaderItems(SAFEARRAY** value) override {return GetRowHeaders(value);}
    HRESULT STDMETHODCALLTYPE GetColumnHeaderItems(SAFEARRAY** value) override {if(!value)return E_POINTER;return Guard([&]{return Array({New(Header,{},column)},value);});}
    HRESULT STDMETHODCALLTYPE SetValue(LPCWSTR) override {return UIA_E_NOTSUPPORTED;}
    HRESULT STDMETHODCALLTYPE get_Value(BSTR* value) override {if(!value)return E_POINTER;*value=nullptr;size_t row;auto data=Data(&row);if(!data)return UIA_E_ELEMENTNOTAVAILABLE;const auto& text=data->view->rows[row].text[column];*value=SysAllocStringLen(text.data(),static_cast<UINT>(text.size()));return *value?S_OK:E_OUTOFMEMORY;}
    HRESULT STDMETHODCALLTYPE get_IsReadOnly(BOOL* value) override {if(!value)return E_POINTER;*value=TRUE;return S_OK;}
    HRESULT STDMETHODCALLTYPE Invoke() override {return Queue(Sort);}
    int VisibleRows(const Snapshot& v) const {return (std::max)(1,static_cast<int>((v.client.bottom-v.headerRect.bottom)/v.rowHeight));}
    HRESULT STDMETHODCALLTYPE Scroll(ScrollAmount x,ScrollAmount y) override {
        if(x<ScrollAmount_LargeDecrement||x>ScrollAmount_SmallIncrement||y<ScrollAmount_LargeDecrement||y>ScrollAmount_SmallIncrement)return E_INVALIDARG;
        auto data=Data();if(!data)return UIA_E_ELEMENTNOTAVAILABLE;
        const int delta[]={-10,-1,0,10,1};
        auto amount=[&](ScrollAmount a,int page){return a==ScrollAmount_LargeDecrement?-page:a==ScrollAmount_LargeIncrement?page:delta[a];};
        return Queue(ScrollBy,amount(x,(data->view->client.right-data->view->client.left)/16)*16,amount(y,VisibleRows(*data->view)));
    }
    HRESULT STDMETHODCALLTYPE SetScrollPercent(double x,double y) override {
        if(!((x==UIA_ScrollPatternNoScroll)||(x>=0&&x<=100))||!((y==UIA_ScrollPatternNoScroll)||(y>=0&&y<=100)))return E_INVALIDARG;
        return Queue(ScrollTo,x,y);
    }
    HRESULT STDMETHODCALLTYPE get_HorizontalScrollPercent(double* value) override {if(!value)return E_POINTER;auto data=Data();if(!data)return UIA_E_ELEMENTNOTAVAILABLE;const auto& v=*data->view;*value=v.horizontalMaximum>0?100.0*v.horizontalPosition/v.horizontalMaximum:UIA_ScrollPatternNoScroll;return S_OK;}
    HRESULT STDMETHODCALLTYPE get_VerticalScrollPercent(double* value) override {if(!value)return E_POINTER;auto data=Data();if(!data)return UIA_E_ELEMENTNOTAVAILABLE;const auto& v=*data->view;int maximum=static_cast<int>(v.rows.size())-VisibleRows(v);*value=maximum>0?(std::min)(100.0,100.0*v.top/maximum):UIA_ScrollPatternNoScroll;return S_OK;}
    HRESULT STDMETHODCALLTYPE get_HorizontalViewSize(double* value) override {if(!value)return E_POINTER;auto data=Data();if(!data)return UIA_E_ELEMENTNOTAVAILABLE;const auto& v=*data->view;int width=v.client.right-v.client.left;*value=width>0?100.0*width/(width+v.horizontalMaximum):100;return S_OK;}
    HRESULT STDMETHODCALLTYPE get_VerticalViewSize(double* value) override {if(!value)return E_POINTER;auto data=Data();if(!data)return UIA_E_ELEMENTNOTAVAILABLE;const auto& v=*data->view;*value=v.rows.empty()?100:(std::min)(100.0,100.0*VisibleRows(v)/v.rows.size());return S_OK;}
    HRESULT STDMETHODCALLTYPE get_HorizontallyScrollable(BOOL* value) override {if(!value)return E_POINTER;double percent;HRESULT hr=get_HorizontalScrollPercent(&percent);*value=SUCCEEDED(hr)&&percent!=UIA_ScrollPatternNoScroll;return hr;}
    HRESULT STDMETHODCALLTYPE get_VerticallyScrollable(BOOL* value) override {if(!value)return E_POINTER;double percent;HRESULT hr=get_VerticalScrollPercent(&percent);*value=SUCCEEDED(hr)&&percent!=UIA_ScrollPatternNoScroll;return hr;}
};
}

Bridge::Bridge(HWND window) {
    auto& api=Functions();if(!api.returnProvider||!api.host||!api.structure||!api.event)return;
    auto shared=std::make_shared<State>(window);
    auto initialized=std::make_shared<std::promise<bool>>();
    auto ready=initialized->get_future();
        std::thread worker([shared,initialized] {
            HRESULT com=CoInitializeEx(nullptr,COINIT_MULTITHREADED);
            try {
                if(FAILED(com)){initialized->set_value(false);return;}
                shared->root=new Provider(shared,Root);
                shared->header=new Provider(shared,HeaderBar);
                initialized->set_value(true);
            } catch (...) {
                if(shared->header)shared->header->Release();
                if(shared->root)shared->root->Release();
                initialized->set_value(false);CoUninitialize();return;
            }
            for(;;) {
                bool structure,selection,focus;
                {std::unique_lock<std::mutex> lock(shared->mutex);shared->wake.wait(lock,[&]{return !shared->alive||shared->pending;});
                    if(!shared->alive)break;structure=shared->structureChanged;selection=shared->selectionChanged;focus=shared->focusChanged;
                    shared->pending=shared->structureChanged=shared->selectionChanged=shared->focusChanged=false;}
                auto root=static_cast<IRawElementProviderSimple*>(shared->root);
                if(structure)Functions().structure(root,StructureChangeType_ChildrenInvalidated,nullptr,0);
                if(selection)Functions().event(root,UIA_Selection_InvalidatedEventId);
                if(focus) {IRawElementProviderFragment* element=nullptr;
                    if(SUCCEEDED(shared->root->GetFocus(&element))&&element){IRawElementProviderSimple* simple=nullptr;
                        if(SUCCEEDED(element->QueryInterface(__uuidof(IRawElementProviderSimple),reinterpret_cast<void**>(&simple)))){Functions().event(simple,UIA_AutomationFocusChangedEventId);simple->Release();}element->Release();}}
            }
            if(Functions().disconnect)Functions().disconnect(static_cast<IRawElementProviderSimple*>(shared->root));
            shared->header->Release(); shared->root->Release();
            if(SUCCEEDED(com))CoUninitialize();
        });worker.detach();
    if(ready.get())m_state=shared;
}
Bridge::~Bridge() {
    if(!m_state)return;
    {std::lock_guard<std::mutex> lock(m_state->mutex);m_state->alive=false;m_state->current.reset();m_state->requests.clear();}
    m_state->wake.notify_one();
}
bool Bridge::Available() const {return m_state!=nullptr;}
LRESULT Bridge::GetObject(WPARAM wParam,LPARAM lParam) {
    if(!m_state||static_cast<LONG>(lParam)!=UiaRootObjectId)return 0;
    auto shared=m_state;
    // Register the provider from the MTA as well as creating it there. Calling
    // UiaReturnRawElementProvider on the STA makes bulk traversal run in the
    // window's hook callback. Only this short HWND handshake waits here; data
    // reads and tree traversal subsequently run on COM's background threads.
    return std::async(std::launch::async,[shared,wParam,lParam]() -> LRESULT {
        HRESULT com=CoInitializeEx(nullptr,COINIT_MULTITHREADED);
        if(FAILED(com))return 0;
        LRESULT result=Functions().returnProvider(shared->window,wParam,lParam,
            static_cast<IRawElementProviderSimple*>(shared->root));
        CoUninitialize();return result;
    }).get();
}
void Bridge::Publish(std::shared_ptr<const Snapshot> snapshot,bool structureChanged) {
    if(!m_state || !snapshot || snapshot->columnCount < 1 || snapshot->columnCount > 4)return;
    auto published=std::make_shared<Published>();published->view=std::move(snapshot);
    for(size_t i=0;i<published->view->rows.size();++i){const auto& row=published->view->rows[i];published->indices[{row.pid,row.created}]=i;}
    {std::lock_guard<std::mutex> lock(m_state->mutex);if(!m_state->alive)return;
        bool selection=false,focus=false;
        const auto old=m_state->current;
        if(old){const auto& a=*old->view;const auto& b=*published->view;
            if(structureChanged) {
                structureChanged=a.rows.size()!=b.rows.size() || a.columnCount!=b.columnCount;
                for(size_t i=0;!structureChanged&&i<a.rows.size();++i) {
                    structureChanged=a.rows[i].pid!=b.rows[i].pid||a.rows[i].created!=b.rows[i].created||a.rows[i].accessibleName!=b.rows[i].accessibleName;
                    for(int c=0;!structureChanged&&c<b.columnCount;++c)structureChanged=a.rows[i].text[c]!=b.rows[i].text[c];
                }
            }
            focus=a.focused!=b.focused||a.hasFocus!=b.hasFocus;
            std::vector<Identity> left,right;
            for(const auto& row:a.rows)if(row.selected)left.push_back({row.pid,row.created});
            for(const auto& row:b.rows)if(row.selected)right.push_back({row.pid,row.created});
            selection=left!=right;
        } else structureChanged=false;
        m_state->current=published;m_state->pending=true;m_state->structureChanged|=structureChanged;
        m_state->selectionChanged|=selection;m_state->focusChanged|=focus;}
    m_state->wake.notify_one();
}
std::vector<Request> Bridge::TakeRequests() {
    std::vector<Request> result;if(!m_state)return result;
    std::lock_guard<std::mutex> lock(m_state->mutex);result.assign(m_state->requests.begin(),m_state->requests.end());m_state->requests.clear();return result;
}
}
