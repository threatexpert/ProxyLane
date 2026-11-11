param(
    [ValidateSet('x64', 'x86')][string]$Architecture = 'x64',
    [string]$VsDevCmd = 'C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvarsall.bat',
    [switch]$Page
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    $work = Join-Path $root "build\qa\protocol-view-$Architecture"
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    $platform = if ($Architecture -eq 'x64') { 'x64' } else { 'Win32' }
    $suffix = if ($Architecture -eq 'x64') { '64' } else { '32' }
    $source = 'tests\ProtocolViewModelTests.cpp src\ProxyLane\ProtocolViewModel.cpp'
    $options = '/DPROTOCOL_VIEW_TEST'
    $libraries = 'crypt32.lib'
    if ($Page) {
        $source = 'tests\ProtocolPageHarness.cpp src\ProxyLane\ProtocolViewModel.cpp src\ProxyLane\ModernUI.cpp src\ProxyLane\Localization.cpp'
        $options = '/utf-8 /DWINVER=0x0601 /D_WIN32_WINNT=0x0601 /DUNICODE /D_UNICODE /I src\ProxyLane'
        $libraries = "/SUBSYSTEM:CONSOLE /LIBPATH:bin\$platform\Release ProxyLaneHook.lib build\ProxyLane\$platform\Release\ProxyLane.res ws2_32.lib crypt32.lib"
        Copy-Item "bin\ProxyLaneHook$suffix.dll" "$work\ProxyLaneHook$suffix.dll"
    }
    $exe = Join-Path $work $(if ($Page) { 'ProtocolPageHarness.exe' } else { 'ProtocolViewModelTests.exe' })
    $command = "@echo off`r`ncall `"$VsDevCmd`" $Architecture`r`ncl /nologo /EHsc /O2 /MT /std:c++14 $options $source /Fo:`"$work\\`" /Fe:`"$exe`" /link $libraries`r`n"
    $script = Join-Path $work 'build.cmd'
    [IO.File]::WriteAllText($script, $command, [Text.Encoding]::Default)
    & cmd /c $script
    if ($LASTEXITCODE -ne 0) { throw 'Protocol view test build failed' }
    & $exe
    if ($LASTEXITCODE -ne 0) { throw 'Protocol view test failed' }
} finally { Pop-Location }
