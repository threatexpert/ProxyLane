# Recent-app persistence tests

Build `RecentApplicationsTests.vcxproj` with VS 2019, Release Win32 or x64,
then run `bin/<platform>/RecentApplicationsTests.exe`.

The test uses isolated temporary files and does not modify ProxyLane's history
or launch/inject user applications. It covers:

- Persistence of Unicode arguments, working directory, elevation and AUMID.
- Target deduplication, case-sensitive arguments, pinning, unpinning, removal
  and the 20-unpinned-entry limit.
- One tile per launch target, with the last successful ordinary/administrator
  preference; fresh drops and existing-tile launches update the same record.
- Legacy ordinary/administrator duplicates merge on read using the latest
  launch preference, retaining a stable ID, pin and display position. The next
  history write removes duplicate sections; deleting a merged tile removes both.
- Stable home-screen positions across launches/restarts, legacy-order migration,
  append/pin/unpin/remove behavior, and independent MRU eviction.
- Shared picker/Home display order on cold load, ready-cache updates, reload,
  catalog/recent launches and explicit manual moves/pins; consumers do not sort.
- Swipe thresholds, edge resistance, page counts and snap easing.
- Shortcut origin extraction and re-resolution after the shortcut changes.
- Missing targets, oversized writes and corrupt history protection.
- Two independent processes updating the same/different profiles in one INI,
  alongside a third process updating unrelated options through Windows APIs.
- Profile deletion/recreation, stale runtime identity rejection, and independent
  pin/remove operations for the same app in different profiles.
- INI section/key names over 128 characters and values/arguments over 12,000 characters.
- Recent/catalog identity matching and background validity checking without
  permanently deleting temporarily inaccessible targets.

Manual UI acceptance (window capture timed out in the implementation session):

1. Before starting the proxy, the applications page shows the selected profile's
   history. The bottom-left status shows the selected profile in smaller muted
   text; hover reveals its full name and any unsaved-edit notice. The launch card
   has no profile row or profile-settings button. While running A, selecting B
   must leave the sidebar/history on A until B is actually started/applied.
2. Click a recent app while stopped: the confirmation names both the profile and
   app, defaults to No, and explains unsaved edits when present. No/Escape must
   start neither the proxy nor the app. Yes starts the selected proxy and then the
   app; invalid targets or failed proxy startup must not launch an app. Changing
   profiles during confirmation must never silently launch using another profile.
   Right-click offers Start normally and Start as administrator, even for a
   shield tile (Store apps omit administrator). The saved default is bold.
   A successful explicit launch/drop changes the default and shield without
   adding or moving a tile; failure or UAC cancellation leaves it unchanged.
   Left-click/Enter uses that default. Normal retains AUTO elevation behavior.
3. With at least seven recent apps and a narrow window, drag horizontally across
   tiles or gaps. Check smooth snap, small-drag snap-back, boundary resistance,
   no looping, and no accidental launch after a swipe/capture loss/Escape.
   Check horizontal touch gestures, vertical/horizontal wheel or touchpad input,
   arrow/Home/End keys and Enter/Space. Resize while on a later page and while
   dragging. Only subtle page dots appear; a single page has no dots or arrows.
4. Hover each tile on every page: show full app name/target and relevant launch
   details, without a profile line. No tooltip should hang over a moving page.
   Launch a tile: its position/page remains stable, including after restarting
   ProxyLane. New apps append; pinning deliberately moves an app to the front.
5. Expand the process list for the first time: it must appear in its final place
   without a white template-sized rectangle covering recent apps. Collapse it:
   timer refresh, activation and event callbacks must not enumerate its rows.
6. In the app picker, select a recent item: More actions and the right-click menu
   offer Move up/down, Pin/unpin and Remove. Boundary moves are disabled; fixed
   and ordinary groups remain separate. Moves retain selection, survive reopening
   and launching, and sync to Home. Check recent/catalog merging and searching,
   BAT/CMD shortcuts, Store apps and unavailable targets. Restoring a target and
   refreshing makes it usable again. Removing history must not delete app files.
7. Check both languages, narrow/maximized windows, 100%/150% DPI, and Windows'
   reduced-animation preference for clipping, overlap and misplaced tooltips.

History is stored in the existing `ProxyLane.ini`, shared by both architectures.
`[proxy_<name>] RecentAppsId` identifies the profile's history generation.
The optional `DisplayOrder` field preserves home-screen placement independently
of `LastUsed`; older records inherit their previous initial order and are migrated
on the next history write. The picker shares the home-screen display order; eviction still uses recency.
`Elevated` is a saved launch preference, not part of target identity. Legacy
duplicates retain the first tile in display order (a pinned tile takes priority),
with launch data and preference taken from the record with the latest `LastUsed`.
Arguments and working directories still distinguish different launch targets;
existing shortcut-origin matching is retained. The INI schema remains version 1.
Each `[recent_app_<profile-id>_<record-id>]` section stores a complete record,
written with one `WritePrivateProfileSection` call. Text fields with the
`Utf8Base64` suffix use standard UTF-8 + Base64 (not encryption), avoiding ANSI
code-page loss and preserving quotes/newlines/leading or trailing whitespace.
Records obey the XP-compatible whole-section size limit and reject oversized
updates before changing existing records. No additional INI or lock file is created.

A path-scoped named mutex coordinates only history read/modify/write, identity
initialization and profile deletion, not ordinary independent settings writes.
Late results carry the profile identity; stopping/switching discards the old
context. A deleted/recreated profile gets a new identity and cannot receive
history from its previous runtime. Old `.apps` files are left untouched and
are not automatically assigned to a profile because they had no profile identity.
