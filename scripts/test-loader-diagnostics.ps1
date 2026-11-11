param(
    [string]$VsDevCmd = 'C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvarsall.bat',
    [string]$HookDirectory = ''
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$work = Join-Path $root 'build\loader-diagnostics'
New-Item -ItemType Directory -Force -Path $work | Out-Null
Push-Location $root
try {
    foreach ($arch in @('x86', 'x64')) {
        $command = @"
@echo off
call "$VsDevCmd" $arch -vcvars_ver=14.16 >nul
if errorlevel 1 exit /b 1
cl /nologo /EHsc /O2 /MT /utf-8 /DUNICODE /D_UNICODE tests\LoaderDiagnosticsTests.cpp /Fo"$work\test-$arch.obj" /Fe"$work\test-$arch.exe"
if errorlevel 1 exit /b 1
cl /nologo /O2 /MT /LD tests\LoaderDiagnosticFixture.cpp /Fo"$work\fixture-$arch.obj" /Fe"$work\fixture-$arch.dll"
if errorlevel 1 exit /b 1
copy /y "$work\test-$arch.exe" "$work\utf8-$arch.exe" >nul
mt -nologo -manifest tests\loader-utf8.manifest -outputresource:"$work\utf8-$arch.exe";#1
"@
        $batch = Join-Path $work "test-$arch.cmd"
        [IO.File]::WriteAllText($batch, $command, [Text.Encoding]::Default)
        & cmd /c $batch
        if ($LASTEXITCODE -ne 0) { throw "$arch test build failed" }
    }
    foreach ($arch in @('x86', 'x64')) {
        & "$work\test-$arch.exe" "$work\test-x86.exe" "$work\test-x64.exe"
        if ($LASTEXITCODE -ne 0) { throw "$arch capture tests failed" }
        $unicode = Join-Path $work ('路径 空格-' + $arch)
        New-Item -ItemType Directory -Force -Path $unicode | Out-Null
        $dll = Join-Path $unicode '加载模块.dll'
        Copy-Item "$work\fixture-$arch.dll" $dll -Force
        & "$work\test-$arch.exe" --load $dll
        if ($LASTEXITCODE -ne 0) { throw "$arch Unicode load failed" }
        & "$work\utf8-$arch.exe" --load $dll
        if ($LASTEXITCODE -ne 0) { throw "$arch UTF-8 process Unicode load failed" }
        if ($HookDirectory) {
            $bits = if ($arch -eq 'x64') { '64' } else { '32' }
            $hook = Join-Path $unicode "ProxyLaneHook$bits.dll"
            Copy-Item (Join-Path $HookDirectory "ProxyLaneHook$bits.dll") $hook -Force
            & "$work\test-$arch.exe" --inject $hook "$work\utf8-$arch.exe"
            if ($LASTEXITCODE -ne 0) { throw "$arch actual injection into UTF-8 target failed" }
            & "$work\utf8-$arch.exe" --inject $hook "$work\test-$arch.exe"
            if ($LASTEXITCODE -ne 0) { throw "$arch actual injection from UTF-8 host failed" }
            & "$work\test-$arch.exe" --inject-fail $hook "$work\utf8-$arch.exe"
            if ($LASTEXITCODE -ne 0) { throw "$arch real loader failure in UTF-8 target failed" }
            & "$work\utf8-$arch.exe" --inject-fail $hook "$work\test-$arch.exe"
            if ($LASTEXITCODE -ne 0) { throw "$arch real loader failure from UTF-8 host failed" }
        }
    }
} finally { Pop-Location }
