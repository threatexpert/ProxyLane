param([switch]$Online, [string]$DohUrl="https://dns.google/dns-query", [string]$Bootstrap="8.8.8.8")
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
Push-Location $repo
try {
    & $PSScriptRoot/run-doh-tests.ps1
    if ($LASTEXITCODE) { throw 'DoH unit tests failed' }
    if ($Online) {
        $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
        $vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        $vcvars = Join-Path $vs 'VC\Auxiliary\Build\vcvarsall.bat'
        $output = Join-Path $repo 'build\dns-relay-tests'
        New-Item -ItemType Directory -Force -Path $output | Out-Null
        $compile = Join-Path $output 'compile.cmd'
        @"
@echo off
call "$vcvars" x64 >nul
if errorlevel 1 exit /b %errorlevel%
cl /nologo /EHsc /std:c++14 /O2 /DUNICODE /D_UNICODE tests\DnsDohRelayHost.cpp /Fo:"$output\host.obj" /Fe:"$output\host.exe" /link /LIBPATH:bin\x64\Release ProxyLaneHook.lib ws2_32.lib user32.lib
"@ | Set-Content -LiteralPath $compile -Encoding Default
        & $env:ComSpec /c $compile
        if ($LASTEXITCODE) { throw 'DNS relay host compilation failed' }
        foreach ($name in @('ProxyLaneHook64.dll','ProxyLaneMitm64.dll','ProxyLaneSecureTransport64.dll','ProxyLaneSsh64.dll')) {
            Copy-Item -LiteralPath (Join-Path 'bin' $name) -Destination $output -Force
        }
        & python tests/e2e/dns_doh_relay.py --host (Join-Path $output 'host.exe') --doh-url $DohUrl --bootstrap $Bootstrap
        if ($LASTEXITCODE) { throw 'DNS relay integration tests failed' }
    }
} finally { Pop-Location }
