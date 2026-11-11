param([string]$Bin = (Join-Path $PSScriptRoot '..\bin'))
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -latest -version '[16.0,17.0)' -products * -requires Microsoft.Component.MSBuild -property installationPath | Select-Object -First 1
if (-not $vs) { throw 'Visual Studio 2019 was not found.' }
$qa = Join-Path $repo 'build\qa\hook-failure-diagnostics'
New-Item -ItemType Directory -Force -Path $qa | Out-Null
$Bin = (Resolve-Path -LiteralPath $Bin).Path
Push-Location $repo
try {
    foreach ($bits in @(32, 64)) {
        $vcvars = Join-Path $vs "VC\Auxiliary\Build\vcvars$bits.bat"
        $batch = Join-Path $qa "build$bits.cmd"
        @"
@echo off
call "$vcvars" >nul
if errorlevel 1 exit /b 1
cl /nologo /EHsc /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0601 /D_WINSOCK_DEPRECATED_NO_WARNINGS tests\e2e\hook_failure_diagnostics.cpp /Fo"$qa\probe$bits.obj" /Fe"$qa\probe$bits.exe" /link ws2_32.lib
"@ | Set-Content -LiteralPath $batch -Encoding Default
        & $env:ComSpec /d /c $batch
        if ($LASTEXITCODE) { throw "Probe $bits build failed" }
        foreach ($case in @('settings', 'startup', 'broken-pipe')) {
            $out = Join-Path $qa "$bits-$case.out.log"
            $err = Join-Path $qa "$bits-$case.err.log"
            $probe = Start-Process -FilePath "$qa\probe$bits.exe" -ArgumentList @("`"$Bin\ProxyLaneHook$bits.dll`"", $case) -PassThru -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err
            if (-not $probe.WaitForExit(30000)) {
                $probe.Kill()
                throw "Probe $bits / $case timed out"
            }
            $probe.WaitForExit()
            Get-Content -LiteralPath $out
            Get-Content -LiteralPath $err
            if ($probe.ExitCode) { throw "Probe $bits / $case failed: $($probe.ExitCode)" }
        }
    }
} finally { Pop-Location }
