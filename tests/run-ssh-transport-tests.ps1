param([ValidateSet('x64')][string]$Platform = 'x64', [switch]$Full)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$output = Join-Path $repo "build/ssh-tests/$Platform"
New-Item -ItemType Directory -Force -Path $output | Out-Null
$python = (Get-Command python -ErrorAction Stop).Source
$config = Join-Path $output 'fixture.json'
if (Test-Path -LiteralPath $config) { Remove-Item -LiteralPath $config }
$fixture = Start-Process -FilePath $python -ArgumentList @('"' + (Join-Path $PSScriptRoot 'ssh_test_servers.py') + '"', '"' + $config + '"') -PassThru -WindowStyle Hidden -RedirectStandardError "$output/server.log"
Push-Location $repo
try {
    for ($i=0; $i -lt 100 -and -not (Test-Path -LiteralPath $config); $i++) {
        if ($fixture.HasExited) { throw "SSH fixture exited; see $output/server.log" }
        Start-Sleep -Milliseconds 100
    }
    $ports = Get-Content -LiteralPath $config -Raw | ConvertFrom-Json
    $vswhere = "${env:ProgramFiles(x86)}/Microsoft Visual Studio/Installer/vswhere.exe"
    $vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    $arch = if ($Platform -eq 'Win32') { 'x86' } else { 'x64' }
    $bits = if ($Platform -eq 'Win32') { '32' } else { '64' }
    $compile = Join-Path $output 'compile.cmd'
    @"
@echo off
call "$vs\VC\Auxiliary\Build\vcvarsall.bat" $arch >nul
if errorlevel 1 exit /b %errorlevel%
cl /nologo /EHsc /O2 /DUNICODE /D_UNICODE tests\SshTransportTests.cpp /Fo:"$output\test.obj" /Fe:"$output\test.exe" /link /LIBPATH:"bin\$Platform\Release" ProxyLaneHook.lib ws2_32.lib user32.lib
"@ | Set-Content -LiteralPath $compile -Encoding Default
    & $env:ComSpec /c $compile
    if ($LASTEXITCODE) { throw 'SSH test compilation failed' }
    Copy-Item -LiteralPath "bin/ProxyLaneHook$bits.dll", "bin/ProxyLaneSsh$bits.dll" -Destination $output
    $arguments = @($ports.a, $ports.b, $ports.socks, $ports.http, $ports.echo, $ports.control, $ports.fingerprint)
    if ($Full) { $arguments += 'full' }
    & "$output/test.exe" @arguments
    if ($LASTEXITCODE) { throw 'SSH tests failed' }
} finally {
    Pop-Location
    if (-not $fixture.HasExited) { Stop-Process -Id $fixture.Id }
}
