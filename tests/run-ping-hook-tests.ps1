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
        $output = Join-Path $repo "build\ping-hook-tests\$arch"
        New-Item -ItemType Directory -Force -Path $output | Out-Null
        $compile = Join-Path $output 'compile.cmd'
        @"
@echo off
call "$vcvars" $arch >nul
if errorlevel 1 exit /b %errorlevel%
cd /d "$output"
cl /nologo /EHsc /std:c++14 /O2 /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /I"$repo\third_party\detours\src" "$repo\tests\PingHookTests.cpp" "$repo\src\ProxyLaneHook\DetourHooks.cpp" "$repo\third_party\detours\src\detours.cpp" "$repo\third_party\detours\src\disasm.cpp" "$repo\third_party\detours\src\modules.cpp" /Fe:test.exe /link /LIBPATH:"$repo\$Bin\$platform\Release" ProxyLaneHook.lib ws2_32.lib user32.lib iphlpapi.lib
"@ | Set-Content -LiteralPath $compile -Encoding Default
        & $env:ComSpec /c $compile
        if ($LASTEXITCODE) { throw "$arch compilation failed" }
        Copy-Item -LiteralPath "$Bin\ProxyLaneHook$bits.dll" -Destination $output -Force
        & (Join-Path $output 'test.exe')
        if ($LASTEXITCODE) { throw "$arch Ping hook regression failed" }
    }
} finally { Pop-Location }
