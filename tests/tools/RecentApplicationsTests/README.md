# Recent-app persistence tests

Build `RecentApplicationsTests.vcxproj` with VS 2019, Release Win32 or x64,
then run `bin/<platform>/RecentApplicationsTests.exe`.

The test uses isolated temporary files and does not modify ProxyLane's history
or launch/inject user applications. It covers:

- Persistence of Unicode arguments, working directory, elevation and AUMID.
- Target deduplication, case-sensitive arguments, pinning, unpinning, removal
  and the 20-unpinned-entry limit.
- Shortcut origin extraction and re-resolution after the shortcut changes.
- Missing targets, oversized writes and corrupt history protection.
- Two independent processes updating the same/different profiles in one INI,
  alongside a third process updating unrelated options through Windows APIs.
- Profile deletion/recreation, stale runtime identity rejection, and independent
  pin/remove operations for the same app in different profiles.
- INI section/key names over 128 characters and values/arguments over 12,000 characters.
- Recent/catalog identity matching and background validity checking without
  permanently deleting temporarily inaccessible targets.

Manual UI acceptance (computer-use runtime unavailable in the implementation session):

1. Start a profile, drop an ordinary app or select an app to launch; verify it
   appears in the right-hand Recent Apps card. Single-click must not launch;
   double-click (or Enter on a selected item) launches it again.
2. Restart ProxyLane: before starting the proxy, no profile's history is shown.
   Start A: only A's history appears. Merely selecting B without applying it
   must not change that. Start/apply B: B's history replaces A's. Stop: history
   disappears. Repeat with two instances running A and B concurrently.
3. Open the original app picker: recent entries appear first with Recent Apps
   as their source, then the installed catalog loads behind them without duplicate
   targets. Search and recent-app launching work while the catalog loads.
   Select a recent entry: Remove from recent appears in the right-aligned button
   group, leaving the bottom-left loading/count label unobscured. Also check
   right-click pin/unpin/remove. Removal updates the sidebar and restores the
   ordinary catalog row (if installed), without deleting the application.
4. Check BAT/CMD shortcuts, Store apps, long names/arguments and hover details.
   Unavailable recent targets remain gray with source "Recent Apps (unavailable)".
   Selection enables removal but not launching (including double-click/Enter).
   Removing the record also updates the sidebar; no app files are deleted.
   Restore an unavailable target and refresh: it should become launchable again.
   An unavailable shortcut must not hide a usable installed catalog target.
5. Check both languages, narrow windows and 100%/150% DPI for overlapping controls.

History is stored in the existing `ProxyLane.ini`, shared by both architectures.
`[proxy_<name>] RecentAppsId` identifies the profile's history generation.
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
