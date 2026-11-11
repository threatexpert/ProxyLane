param([string]$Bin = 'bin', [switch]$Online,
    [string]$DohUrl = 'https://dns.alidns.com/dns-query', [string]$Bootstrap = '223.5.5.5')
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$output = Join-Path $repo 'build/doh-connectivity-tests'
New-Item -ItemType Directory -Force -Path $output | Out-Null
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
$fixture = $null
Push-Location $repo
try {
    $compile = Join-Path $output 'compile.cmd'
    @"
@echo off
call "$vs\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul
if errorlevel 1 exit /b %errorlevel%
cl /nologo /EHsc /std:c++14 /O2 /DUNICODE /D_UNICODE tests\DohConnectivityHost.cpp /Fo:"$output\host.obj" /Fe:"$output\host.exe" /link /LIBPATH:bin\x64\Release ProxyLaneHook.lib ws2_32.lib user32.lib
"@ | Set-Content -LiteralPath $compile -Encoding Default
    & $env:ComSpec /c $compile
    if ($LASTEXITCODE) { throw 'Connectivity host compilation failed' }
    foreach ($name in @('ProxyLaneHook64.dll','ProxyLaneMitm64.dll','ProxyLaneSsh64.dll','ProxyLaneSecureTransport64.dll')) {
        Copy-Item -LiteralPath (Join-Path $Bin $name) -Destination $output -Force
    }
    $config = Join-Path $output ('ssh-' + [guid]::NewGuid().ToString('N') + '.json')
    $fixture = Start-Process -FilePath (Get-Command python).Source -ArgumentList @('"' + (Join-Path $PSScriptRoot 'e2e/doh_ssh_fixture.py') + '"', '"' + $config + '"') -WindowStyle Hidden -PassThru -RedirectStandardError "$output/ssh.log"
    for ($i=0; $i -lt 100 -and -not (Test-Path -LiteralPath $config); ++$i) {
        if ($fixture.HasExited) { throw 'SSH fixture failed' }
        Start-Sleep -Milliseconds 100
    }
    if (-not (Test-Path -LiteralPath $config)) { throw 'SSH fixture not ready' }
    $arguments = @('tests/e2e/doh_connectivity.py', '--host', "$output/host.exe", '--url', $DohUrl, '--bootstrap', $Bootstrap, '--ssh-config', $config)
    if ($Online) { $arguments += '--online' }
    & python @arguments
    if ($LASTEXITCODE) { throw 'DoH connectivity tests failed' }
} finally {
    if ($fixture -and -not $fixture.HasExited) { Stop-Process -Id $fixture.Id }
    Pop-Location
}
