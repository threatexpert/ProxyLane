# ApplicationCatalogProbe

Read-only checks of the installed-application catalog on the current Windows
user account. The probe enumerates desktop and Store apps, checks cancellation,
and creates then removes one temporary desktop shortcut to verify that quoted
arguments and the working directory survive resolution. It also checks Edge
deduplication and the Visual Studio launchers pictured in UI feedback. Synthetic
merge checks cover missing cwd metadata, source order, normalized directory
separators, and preserving distinct explicit directories/case-sensitive arguments.
Merged source records are retained without duplicate shortcut paths. Launch text
checks cover quoted EXE paths, activation IDs, and arguments over 1024 characters.
It resolves a real Claude Shell drag-and-drop data object when
installed, and rejects malformed Shell IDList Array offsets/counts/lengths.
The optional shortcut is checked through both .lnk and Shell-drop resolution.
Shortcut checks accept BAT/CMD targets (including upper-case extensions and
paths with spaces), preserving arguments and working directories. Text files,
missing files and directories remain rejected. Temporary script fixtures are
never executed.
It does not launch apps or simulate a mouse drag.

Build and run from the repository root (VS 2019 MSBuild):

```powershell
& 'C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\MSBuild\Current\Bin\amd64\MSBuild.exe' tests\tools\ApplicationCatalogProbe\ApplicationCatalogProbe.vcxproj /p:Configuration=Release /p:Platform=x64
& .\tests\tools\ApplicationCatalogProbe\bin\x64\ApplicationCatalogProbe.exe
```

Use `Platform=Win32` and `bin\Win32` to check the 32-bit build. An optional first
argument names an ordinary or Store-app shortcut to resolve, for example:

```powershell
& .\tests\tools\ApplicationCatalogProbe\bin\x64\ApplicationCatalogProbe.exe "$env:USERPROFILE\Desktop\Claude.lnk"
```

`probe_result=PASS` confirms the checks passed. The probe requires Windows 7 or
later because it uses the current test compiler/runtime; the application itself
continues to use the XP toolset and falls back to Start Menu shortcuts when the
AppsFolder namespace is unavailable.
