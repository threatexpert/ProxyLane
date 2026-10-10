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
        $output = Join-Path $repo "build\bypass-transport-tests\$arch"
        New-Item -ItemType Directory -Force -Path $output | Out-Null
        $compile = Join-Path $output 'compile.cmd'
        @"
@echo off
call "$vcvars" $arch >nul
if errorlevel 1 exit /b %errorlevel%
cl /nologo /EHsc /O2 /DUNICODE /D_UNICODE tests\BypassTransportE2ETests.cpp /Fo:"$output\test.obj" /Fe:"$output\test.exe" /link /LIBPATH:bin\$platform\Release ProxyLaneHook.lib ws2_32.lib user32.lib
"@ | Set-Content -LiteralPath $compile -Encoding Default
        & $env:ComSpec /c $compile
        if ($LASTEXITCODE -ne 0) { throw "$arch compilation failed" }
        Copy-Item -LiteralPath "bin\ProxyLaneHook$bits.dll" -Destination $output
        # Intentionally omit the secure-transport DLL: direct paths must not load it.
        & "$output\test.exe"
        if ($LASTEXITCODE -ne 0) { throw "$arch bypass regression failed" }
    }
} finally {
    Pop-Location
}
