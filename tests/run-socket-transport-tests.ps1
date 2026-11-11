$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
$vcvars = Join-Path $vs 'VC\Auxiliary\Build\vcvarsall.bat'
Push-Location $repo
try {
    foreach ($arch in @('x86', 'x64')) {
        $output = Join-Path $repo "build\socket-transport-tests\$arch"
        New-Item -ItemType Directory -Force -Path $output | Out-Null
        $compile = Join-Path $output 'compile.cmd'
        @"
@echo off
call "$vcvars" $arch >nul
if errorlevel 1 exit /b %errorlevel%
cl /nologo /EHsc /O2 /MD /DUNICODE /D_UNICODE /DWINVER=0x0600 /I src\ProxyLaneHook /I src\ProxyLaneHook\asynsocket tests\SocketTransportTests.cpp src\ProxyLaneHook\asynsocket\AsyncSocketEx.cpp src\ProxyLaneHook\asynsocket\AsyncSocketExLayer.cpp /Fo:"$output\\" /Fe:"$output\test.exe" /link ws2_32.lib user32.lib
"@ | Set-Content -LiteralPath $compile -Encoding Default
        & $env:ComSpec /c $compile
        if ($LASTEXITCODE -ne 0) { throw "$arch compilation failed" }
        & "$output\test.exe"
        if ($LASTEXITCODE -ne 0) { throw "$arch socket transport regression failed" }
    }
} finally {
    Pop-Location
}
