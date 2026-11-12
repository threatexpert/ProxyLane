param([ValidateSet('x64', 'ARM64')][string]$Platform = 'x64', [switch]$Full, [string]$BinaryDirectory, [string]$PythonExecutable = 'python')
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
if (-not $BinaryDirectory) { $BinaryDirectory = if ($Platform -eq 'ARM64') { 'bin/ARM64/Release' } else { 'bin' } }
if (-not [IO.Path]::IsPathRooted($BinaryDirectory)) { $BinaryDirectory = Join-Path $repo $BinaryDirectory }
if ($Platform -eq 'ARM64' -and $env:PROCESSOR_ARCHITECTURE -ne 'ARM64' -and $env:PROCESSOR_ARCHITEW6432 -ne 'ARM64') {
    throw 'ARM64 runtime tests require Windows ARM64; use scripts/build-arm64.ps1 for cross-build verification.'
}
$output = Join-Path $repo "build/ssh-tests/$Platform"
New-Item -ItemType Directory -Force -Path $output | Out-Null
$python = (Get-Command $PythonExecutable -ErrorAction Stop).Source
& $python -c "import paramiko; assert tuple(map(int, paramiko.__version__.split('.')[:2])) >= (3, 5), 'SSH fixtures require Paramiko >= 3.5 for AES-GCM'"
if ($LASTEXITCODE) { throw 'SSH test Python dependencies are missing or too old.' }
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
    if ($Platform -eq 'ARM64') {
        Copy-Item -LiteralPath (Join-Path $BinaryDirectory 'SshTransportTestsARM64.exe') -Destination (Join-Path $output 'test.exe')
        $bits = 'ARM64'
    } else {
        $vswhere = "${env:ProgramFiles(x86)}/Microsoft Visual Studio/Installer/vswhere.exe"
        $vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        $arch = 'x64'
        $bits = '64'
        $compile = Join-Path $output 'compile.cmd'
        @"
@echo off
call "$vs\VC\Auxiliary\Build\vcvarsall.bat" $arch >nul
if errorlevel 1 exit /b %errorlevel%
cl /nologo /EHsc /O2 /DUNICODE /D_UNICODE tests\SshTransportTests.cpp /Fo:"$output\test.obj" /Fe:"$output\test.exe" /link /LIBPATH:"bin\$Platform\Release" ProxyLaneHook.lib ws2_32.lib user32.lib
"@ | Set-Content -LiteralPath $compile -Encoding Default
        & $env:ComSpec /c $compile
        if ($LASTEXITCODE) { throw 'SSH test compilation failed' }
    }
    Copy-Item -LiteralPath (Join-Path $BinaryDirectory "ProxyLaneHook$bits.dll"), (Join-Path $BinaryDirectory "ProxyLaneSsh$bits.dll") -Destination $output
    $env:PROXYLANE_TEST_MODERN_PORT = $ports.modern
    $env:PROXYLANE_TEST_MODERN_FINGERPRINT = $ports.modern_fingerprint
    $arguments = @($ports.a, $ports.b, $ports.socks, $ports.http, $ports.echo, $ports.control, $ports.fingerprint)
    if ($Full) { $arguments += 'full' }
    & "$output/test.exe" @arguments
    if ($LASTEXITCODE) { throw 'SSH tests failed' }
} finally {
    Remove-Item Env:PROXYLANE_TEST_MODERN_PORT, Env:PROXYLANE_TEST_MODERN_FINGERPRINT -ErrorAction SilentlyContinue
    Pop-Location
    if (-not $fixture.HasExited) { Stop-Process -Id $fixture.Id }
}
