param(
    [ValidateSet('x64','x86')][string]$Architecture = 'x64',
    [string]$BuildRoot = 'build\idle-log-fix',
    [string]$VsDevCmd = 'C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvarsall.bat'
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    $work = Join-Path $root "$BuildRoot\log-page-$Architecture"
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    $platform = if ($Architecture -eq 'x64') { 'x64' } else { 'Win32' }
    $suffix = if ($Architecture -eq 'x64') { '64' } else { '32' }
    Copy-Item "$BuildRoot\bin\ProxyLaneHook$suffix.dll" "$work\ProxyLaneHook$suffix.dll"
    $command = "@echo off`r`ncall `"$VsDevCmd`" $Architecture`r`ncl /nologo /EHsc /O2 /MT /std:c++14 /utf-8 /DWINVER=0x0601 /D_WIN32_WINNT=0x0601 /DUNICODE /D_UNICODE /I src\ProxyLane tests\LogPageHarness.cpp src\ProxyLane\ModernUI.cpp src\ProxyLane\Localization.cpp /Fo:`"$work\\`" /Fe:`"$work\LogPageHarness.exe`" /link /SUBSYSTEM:CONSOLE /LIBPATH:$BuildRoot\bin\$platform\Release ProxyLaneHook.lib $BuildRoot\build\ProxyLane\$platform\Release\ProxyLane.res ws2_32.lib crypt32.lib`r`n"
    [IO.File]::WriteAllText("$work\build.cmd",$command,[Text.Encoding]::Default)
    & cmd /c "$work\build.cmd"
    if ($LASTEXITCODE -ne 0) { throw 'Log page harness build failed' }
    & "$work\LogPageHarness.exe" | Tee-Object "$work\results.txt"
    if ($LASTEXITCODE -ne 0) { throw 'Log page harness failed' }
} finally { Pop-Location }
