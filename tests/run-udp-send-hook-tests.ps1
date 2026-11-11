param([string]$Bin = 'bin')
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
$vcvars = Join-Path $vs 'VC\Auxiliary\Build\vcvarsall.bat'
Push-Location $repo
try {
    foreach ($arch in @('x86', 'x64')) {
        $platform = if ($arch -eq 'x86') { 'Win32' } else { 'x64' }
        $bits = if ($arch -eq 'x86') { '32' } else { '64' }
        $output = Join-Path $repo "build\udp-send-hook-tests\$arch"
        New-Item -ItemType Directory -Force -Path $output | Out-Null
        $compile = Join-Path $output 'compile.cmd'
        @"
@echo off
call "$vcvars" $arch >nul
if errorlevel 1 exit /b %errorlevel%
cl /nologo /EHsc /std:c++14 /O2 /DUNICODE /D_UNICODE tests\UdpSendHookTests.cpp /Fo:"$output\test.obj" /Fe:"$output\test.exe" /link /LIBPATH:"$Bin\$platform\Release" ProxyLaneHook.lib ws2_32.lib user32.lib
"@ | Set-Content -LiteralPath $compile -Encoding Default
        & $env:ComSpec /c $compile
        if ($LASTEXITCODE) { throw "$arch compilation failed" }
        Copy-Item -LiteralPath "$Bin\ProxyLaneHook$bits.dll" -Destination $output -Force
        $arguments = @('tests/e2e/udp_send_hooks.py', '--host', (Join-Path $output 'test.exe'))
        if ($arch -eq 'x64') {
            Copy-Item -LiteralPath "$Bin\ProxyLaneMitm64.dll" -Destination $output -Force
            $arguments += '--doh'
        }
        & python @arguments
        if ($LASTEXITCODE) { throw "$arch UDP hook regression failed" }
    }
} finally { Pop-Location }
