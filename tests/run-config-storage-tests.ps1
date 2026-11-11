$ErrorActionPreference = 'Stop'
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$msbuild = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe | Select-Object -First 1
if (-not $msbuild) { throw 'MSBuild was not found.' }
foreach ($platform in @('Win32', 'x64')) {
    & $msbuild (Join-Path $PSScriptRoot 'ConfigStorageTests.vcxproj') /m /p:Configuration=Release "/p:Platform=$platform" /v:minimal
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $testExe = Join-Path $PSScriptRoot "bin\$platform\Release\ConfigStorageTests.exe"
    & $testExe
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    python (Join-Path $PSScriptRoot 'ConfigStoragePolicyTests.py') $testExe
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
