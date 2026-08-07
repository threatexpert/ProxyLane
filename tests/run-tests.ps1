$ErrorActionPreference = 'Stop'

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path -LiteralPath $vswhere)) {
    throw 'vswhere.exe was not found.'
}
$msbuild = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe | Select-Object -First 1
if (-not $msbuild) {
    throw 'MSBuild was not found.'
}

$project = Join-Path $PSScriptRoot 'ProxyLaneTests.vcxproj'
foreach ($platform in @('Win32', 'x64')) {
    & $msbuild $project /m /p:Configuration=Release /p:Platform=$platform /v:minimal
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $executable = Join-Path $PSScriptRoot "bin\$platform\Release\ProxyLaneTests.exe"
    & $executable
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
