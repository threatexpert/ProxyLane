#include "DohWakeup.h"
#include <iostream>

int DohWakeupTestsMain() {
    HWND window = CreateWindowExW(0, L"STATIC", L"DoH notification test", 0,
        0, 0, 0, 0, HWND_MESSAGE, NULL, GetModuleHandleW(NULL), NULL);
    if (!window) return 1;
    int failures = 0;
    auto check = [&](bool ok) { if (!ok) ++failures; };
    auto take = [&](MSG& message) {
        return PeekMessage(&message, window, CDohWakeup::Message, CDohWakeup::Message, PM_REMOVE) != FALSE;
    };
    MSG message = {};
    auto first = std::make_shared<CDohWakeup>(window);
    // Several shared-query completions need only one owner wakeup.
    for (int i = 0; i < 100; ++i) check(first->Notify());
    check(take(message));
    check(first->Accept(message.message, message.wParam, message.lParam));
    check(!take(message));
    check(first->Notify());
    check(take(message));
    check(first->Accept(message.message, message.wParam, message.lParam));
    // A queued message must not reach a cancelled/replaced owner on the same HWND.
    check(first->Notify());
    std::weak_ptr<CDohWakeup> weak = first;
    first->Cancel();
    check(take(message));
    check(!first->Accept(message.message, message.wParam, message.lParam));
    first.reset();
    check(weak.expired());
    CDohWakeup replacement(window);
    check(!replacement.Accept(message.message, message.wParam, message.lParam));
    check(replacement.Notify());
    check(take(message));
    check(replacement.Accept(message.message, message.wParam, message.lParam));
    check(!take(message));
    // Invalid HWND is a terminal, observable dispatch failure, not silent polling.
    int failed = 0;
    CDohWakeup invalid(NULL, [&] { ++failed; });
    check(!invalid.Notify()); check(!invalid.Notify()); check(failed == 1);
    DestroyWindow(window);
    check(!replacement.Notify());
    std::cout << "DoH wakeup tests: " << failures << " failures\n";
    return failures ? 1 : 0;
}
