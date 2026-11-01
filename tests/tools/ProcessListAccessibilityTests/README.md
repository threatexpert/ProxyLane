# Process-list UI Automation regression

Build `ProcessListAccessibilityTests.vcxproj` using VS 2019, Release x64 or
Win32, then run `tests/bin/<platform>/Release/ProcessListAccessibilityTests.exe`.
The test uses its own hidden native list-view window and an actual Windows UIA
client; it does not inspect or control user applications.

Run the executable again with argument `picker` for the application-list variant
(three columns, single selection, application names, no header sorting). This
also checks that filtered-out rows become unavailable and a second selection is
rejected. Both variants must keep provider reads off the UI thread.

It checks eight complete UIA cache traversals of 500 process rows / 2,000 cells,
all rows remaining accessible, queued selection, identity retained after sorting,
and stale element rejection after a PID is reused. It also requires:

- No native per-cell list-view reads during traversal.
- All provider data reads on background threads, with none on the UI thread.
- UI message dispatch batches below 100 ms and traversal below 4 seconds.

The UI still pumps HWND discovery and lifetime messages. The assertion concerns
bulk traversal and provider reads, not the elimination of all HWND handshakes.
Creating the provider on an MTA alone is insufficient: registration through
`UiaReturnRawElementProvider` must also run there, and the provider must retain
standard COM marshaling rather than use a free-threaded marshaler.

Also run `python tests/ProcessListE2ETests.py <x64 ProxyLane executable>` for
native row/cache agreement, sorting, refresh, collapse/reopen, inaccessible
process metadata, and removal of exited processes.

Run `python tests/ApplicationPreloadE2ETests.py <x64 ProxyLane executable>` for
application search, warm reopen, closing during refresh, and profile isolation.
It starts only its disposable fixture's proxy and does not launch an application.

Manual acceptance: with computer-use or another UIA client active, expand the
real PL list, scroll with the wheel and scrollbar, resize the window, sort each
column, select multiple processes, and collapse/reopen. Check assistive selection
and scrolling, keyboard focus, both languages, and high DPI. The synthetic test
does not establish real mouse smoothness or screen-reader compatibility by itself.
