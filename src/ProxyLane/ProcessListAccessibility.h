#pragma once
#include <windows.h>
#include <memory>
#include <string>
#include <vector>

namespace ProcessListAccessibility {
enum { RequestMessage = WM_APP + 219, ChangedMessage = WM_APP + 220 };
struct Row {
    // Other cached lists use these as an opaque row token + rebuild generation.
    DWORD pid = 0;
    ULONGLONG created = 0;
    std::wstring text[4];
    std::wstring accessibleName;
    bool selected = false;
};
struct Snapshot {
    std::wstring name;
    std::wstring automationId = L"1007";
    int columnCount = 4; // Supported range: 1..4.
    bool canSelectMultiple = true, sortableHeaders = true;
    std::wstring headings[4];
    std::vector<Row> rows;
    HWND header = nullptr;
    RECT client = {}, headerRect = {}, columns[4] = {};
    int top = 0, rowTop = 0, rowHeight = 1, focused = -1;
    int horizontalPosition = 0, horizontalMaximum = 0;
    bool visible = false, enabled = false, hasFocus = false;
};
enum Action { Focus, Select, AddSelection, RemoveSelection, Reveal, Sort, ScrollBy, ScrollTo };
struct Request {
    Action action = Focus;
    bool hasRow = false;
    DWORD pid = 0;
    ULONGLONG created = 0;
    int column = -1;
    double x = 0, y = 0;
};
// The UI publishes immutable values. COM callbacks never query list-view cells
// or wait for the UI thread; actions are delivered through a bounded queue.
class Bridge {
public:
    struct State;
    explicit Bridge(HWND window);
    ~Bridge();
    bool Available() const;
    LRESULT GetObject(WPARAM wParam, LPARAM lParam);
    void Publish(std::shared_ptr<const Snapshot> snapshot, bool structureChanged);
    std::vector<Request> TakeRequests();
private:
    std::shared_ptr<State> m_state;
};
}
