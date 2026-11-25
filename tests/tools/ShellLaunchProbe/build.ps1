param([switch]$XP)
$ErrorActionPreference = 'Stop'
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$msbuild = & $vswhere -latest -version '[16.0,17.0)' -products * -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe | Select-Object -First 1
if (-not $msbuild) { throw 'Visual Studio 2019 MSBuild was not found.' }
$platforms = if ($XP) { @('Win32') } else { @('Win32', 'x64') }
$configuration = if ($XP) { 'ReleaseXP' } else { 'Release' }
foreach ($platform in $platforms) {
    & $msbuild "$PSScriptRoot\ShellLaunchProbe.vcxproj" /m /nologo /v:minimal "/p:Configuration=$configuration" "/p:Platform=$platform"
    if ($LASTEXITCODE) { throw "$platform probe build failed." }
}
