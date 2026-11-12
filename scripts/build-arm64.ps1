[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',
    [string]$ClangBinDirectory,
    [switch]$Rebuild
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -latest -version '[16.0,17.0)' -products * -requires Microsoft.Component.MSBuild -property installationPath | Select-Object -First 1
if (-not $vs) { throw 'Visual Studio 2019 with v142 ARM64 tools and ATL/MFC is required.' }
$vcvars = Join-Path $vs 'VC\Auxiliary\Build\vcvarsall.bat'
$msbuild = Join-Path $vs 'MSBuild\Current\Bin\MSBuild.exe'
$output = Join-Path $repositoryRoot "bin\ARM64\$Configuration"
$qa = Join-Path $repositoryRoot "build\qa\arm64-build\$Configuration"
New-Item -ItemType Directory -Force -Path $qa | Out-Null

# Import the developer environment into this invocation only. Clang needs the
# ARM64 CRT/SDK headers as well as the native libraries used by Rust's linker.
$previousEnvironment = @{}
Get-ChildItem Env: | ForEach-Object { $previousEnvironment[$_.Name] = $_.Value }
Push-Location $repositoryRoot
try {
    $compilerEnvironment = & $env:ComSpec /d /s /c ('call "{0}" amd64_arm64 >nul && set' -f $vcvars)
    if ($LASTEXITCODE) { throw 'Cannot initialize the x64-to-ARM64 compiler environment.' }
    foreach ($line in $compilerEnvironment) {
        if ($line -match '^([^=]+)=(.*)$') {
            if ([Environment]::GetEnvironmentVariable($Matches[1], 'Process') -ne $Matches[2]) {
                Set-Item -LiteralPath ('Env:' + $Matches[1]) -Value $Matches[2]
            }
        }
    }
    if ($ClangBinDirectory) {
        $clangDirectory = (Resolve-Path -LiteralPath $ClangBinDirectory).Path
        if (-not (Test-Path -LiteralPath (Join-Path $clangDirectory 'clang.exe'))) {
            throw 'ClangBinDirectory must contain clang.exe.'
        }
        $env:PATH = "$clangDirectory;$env:PATH"
    }
    $clang = Get-Command clang.exe -ErrorAction SilentlyContinue
    if (-not $clang) { throw 'ring on Windows ARM64 requires Clang. Supply -ClangBinDirectory or add clang.exe to PATH.' }
    & $clang.Source --version
    if ($LASTEXITCODE) { throw 'Clang could not be started.' }
    & python scripts/generate-arm64-bootstrap.py --clang $clang.Source --check
    if ($LASTEXITCODE) { throw 'ARM64 bootstrap source/bytes verification failed.' }

    $target = if ($Rebuild) { 'Rebuild' } else { 'Build' }
    & $msbuild src/ProxyLane.sln /m "/t:$target" "/p:Configuration=$Configuration" /p:Platform=ARM64 /v:minimal "/flp:logfile=$qa\solution.log;verbosity=normal"
    if ($LASTEXITCODE) { throw 'ARM64 product build failed.' }
    & $msbuild tests/arm64/TrafficBuildProbe.vcxproj /m "/t:$target" "/p:Configuration=$Configuration" /p:Platform=ARM64 /v:minimal "/flp:logfile=$qa\traffic.log;verbosity=normal"
    if ($LASTEXITCODE) { throw 'ARM64 traffic probe build failed.' }
    & $msbuild tests/arm64/DetoursBuildProbe.vcxproj /m "/t:$target" /p:Configuration=Release /p:Platform=ARM64 /v:minimal "/flp:logfile=$qa\detours.log;verbosity=normal"
    if ($LASTEXITCODE) { throw 'ARM64 Detours/architecture probe build failed.' }
    & $msbuild tests/arm64/InjectionTests.vcxproj /m "/t:$target" "/p:Configuration=$Configuration" /p:Platform=ARM64 /v:minimal "/flp:logfile=$qa\injection.log;verbosity=normal"
    if ($LASTEXITCODE) { throw 'ARM64 injection test build failed.' }
    & $msbuild tests/arm64/SshTransportTests.vcxproj /m "/t:$target" "/p:Configuration=$Configuration" /p:Platform=ARM64 /v:minimal "/flp:logfile=$qa\ssh.log;verbosity=normal"
    if ($LASTEXITCODE) { throw 'ARM64 SSH test build failed.' }
    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'build\qa\arm64-assessment\bin\DetoursBuildProbe.exe') -Destination $output -Force

    $files = @('ProxyLaneARM64.exe', 'ProxyLaneHookARM64.dll', 'ProxyLaneSecureTransportARM64.dll',
        'ProxyLaneTrafficARM64.exe', 'DetoursBuildProbe.exe', 'InjectionTestsARM64.exe', 'InjectionFixtureARM64.dll', 'ProxyLaneMitmARM64.dll', 'ProxyLaneMitmARM64.exe',
        'ProxyLaneSshARM64.dll', 'SshTransportTestsARM64.exe')
    $verified = foreach ($name in $files) {
        $path = Join-Path $output $name
        $bytes = [IO.File]::ReadAllBytes($path)
        if ($bytes.Length -lt 64 -or [BitConverter]::ToUInt16($bytes, 0) -ne 0x5a4d) { throw "Invalid DOS header: $name" }
        $offset = [BitConverter]::ToInt32($bytes, 0x3c)
        if ($offset -lt 0 -or $offset -gt $bytes.Length - 26 -or
            [BitConverter]::ToUInt32($bytes, $offset) -ne 0x4550 -or
            [BitConverter]::ToUInt16($bytes, $offset + 4) -ne 0xaa64 -or
            [BitConverter]::ToUInt16($bytes, $offset + 24) -ne 0x20b) {
            throw "Expected native ARM64 PE32+: $name"
        }
        [pscustomobject]@{ File = $name; Machine = '0xAA64'; SHA256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash }
    }
    [pscustomobject]@{
        Configuration = $Configuration
        Clang = $clang.Source
        RuntimeTested = $false
        InjectionImplemented = 'ARM64-to-ARM64 only; runtime validation pending'
        Files = @($verified)
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $qa 'verification.json') -Encoding UTF8
    Write-Host "ARM64 cross-build verified: $output"
    Write-Host 'ARM64-to-ARM64 injection is implemented. Runtime tests were not executed.'
}
finally {
    # Do not leave the caller's shell configured for ARM64 compilation.
    foreach ($entry in @(Get-ChildItem Env:)) {
        if (-not $previousEnvironment.ContainsKey($entry.Name)) {
            Remove-Item -LiteralPath ('Env:' + $entry.Name)
        }
    }
    foreach ($name in $previousEnvironment.Keys) {
        if ([Environment]::GetEnvironmentVariable($name, 'Process') -ne $previousEnvironment[$name]) {
            Set-Item -LiteralPath ('Env:' + $name) -Value $previousEnvironment[$name]
        }
    }
    Pop-Location
}
