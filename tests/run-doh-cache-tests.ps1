$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
Push-Location $repo
try {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    $vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    $vcvars = Join-Path $vs 'VC\Auxiliary\Build\vcvarsall.bat'
    $output = Join-Path $repo 'build\doh-cache-tests'
    New-Item -ItemType Directory -Force -Path $output | Out-Null
    $compile = Join-Path $output 'compile.cmd'
    @"
@echo off
call "$vcvars" x64 >nul
if errorlevel 1 exit /b %errorlevel%
cl /nologo /EHsc /std:c++14 /O2 /DUNICODE /D_UNICODE tests\DohCacheTests.cpp /Fo:"$output\test.obj" /Fe:"$output\test.exe" /link ws2_32.lib user32.lib
"@ | Set-Content -LiteralPath $compile -Encoding Default
    & $env:ComSpec /c $compile
    if ($LASTEXITCODE) { throw 'DoH cache test compilation failed' }
    & (Join-Path $output 'test.exe')
    if ($LASTEXITCODE) { throw 'DoH cache tests failed' }
} finally { Pop-Location }
