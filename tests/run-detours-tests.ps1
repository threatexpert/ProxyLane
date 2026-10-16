# Requires VS 2019 with v141_xp/v142, Go, Python with psutil, and Rust on PATH.
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -latest -version '[16.0,17.0)' -products * -requires Microsoft.Component.MSBuild -property installationPath | Select-Object -First 1
if (-not $vs) { throw 'Visual Studio 2019 was not found.' }
$msbuild = Join-Path $vs 'MSBuild\Current\Bin\MSBuild.exe'
$python = (Get-Command python -ErrorAction Stop).Source
$go = (Get-Command go -ErrorAction Stop).Source
Push-Location $repo
try {
    $qa = Join-Path $repo 'build\qa\detours'
    New-Item -ItemType Directory -Force -Path $qa | Out-Null
    & $go build -o "$qa\socks5_udp_server.exe" tests/e2e/socks5_udp_server.go
    if ($LASTEXITCODE) { throw 'SOCKS5 test server build failed.' }
    foreach ($platform in @('Win32', 'x64')) {
        $bits = if ($platform -eq 'Win32') { 32 } else { 64 }
        & $msbuild src/ProxyLane.sln /m /p:Configuration=Release /p:Platform=$platform /v:minimal
        if ($LASTEXITCODE) { throw "$platform solution build failed." }
        & ".\tests\bin\$platform\Release\ProxyLaneTests.exe"
        if ($LASTEXITCODE) { throw "$platform unit tests failed." }
        $vcvars = Join-Path $vs "VC\Auxiliary\Build\vcvars$bits.bat"
        $batch = Join-Path $qa "build-traffic$bits.cmd"
        @"
@echo off
call "$vcvars" >nul
if errorlevel 1 exit /b 1
cl /nologo /EHsc /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0601 /D_WINSOCK_DEPRECATED_NO_WARNINGS tests\e2e\traffic_statistics.cpp /Fo"$qa\traffic$bits.obj" /Fe"bin\traffic$bits.exe" /link "bin\$platform\Release\ProxyLaneHook.lib" ws2_32.lib
"@ | Set-Content -LiteralPath $batch -Encoding Default
        & $env:ComSpec /d /c $batch
        if ($LASTEXITCODE) { throw "$platform traffic probe build failed." }
        & $python tests/TrafficStatisticsE2ETests.py --probe "bin/traffic$bits.exe" --socks-server "$qa\socks5_udp_server.exe"
        if ($LASTEXITCODE) { throw "$platform traffic/explicit-detach tests failed." }
    }
    & $python tests/ManagedStartupE2ETests.py --bin bin --msbuild-dir (Split-Path -Parent $msbuild)
    if ($LASTEXITCODE) { throw 'Managed child process tests failed.' }
    & $python tests/ProxyLaneIPv6BlockE2ETests.py --bin bin
    if ($LASTEXITCODE) { throw 'IPv6/DNS tests failed.' }
}
finally { Pop-Location }
