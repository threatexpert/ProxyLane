param([switch]$BuildOnly)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -latest -version '[16.0,17.0)' -products * -requires Microsoft.Component.MSBuild -property installationPath | Select-Object -First 1
if (-not $vs) { throw 'Visual Studio 2019 with x86/x64/ARM64 tools is required.' }
$msbuild = Join-Path $vs 'MSBuild\Current\Bin\MSBuild.exe'
Push-Location $repo
try {
    foreach ($platform in @('Win32', 'x64', 'ARM64')) {
        & $msbuild tests/CrossArchitectureProbe.vcxproj /m /p:Configuration=Release "/p:Platform=$platform" /v:minimal
        if ($LASTEXITCODE) { throw "$platform cross-architecture probe build failed." }
    }
    if (-not $BuildOnly) {
        & python tests/CrossArchitectureE2ETests.py --bin bin
        if ($LASTEXITCODE) { throw 'Cross-architecture runtime tests failed.' }
    }
}
finally { Pop-Location }
