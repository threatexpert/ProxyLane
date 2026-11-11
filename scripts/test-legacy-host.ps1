param([string]$Python = 'python')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$work = Join-Path $root 'build\qa\legacy-host32'
New-Item -ItemType Directory -Path $work -Force | Out-Null
$objects = Get-ChildItem (Join-Path $root 'build\ProxyLane\Win32\Release') -Filter '*.obj' |
    Where-Object Name -ne 'ProxyLane.obj'
if (-not $objects -or -not (Test-Path (Join-Path $root 'bin\ProxyLaneHook32.dll'))) {
    throw 'Build Release/Win32 before running this test.'
}
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -latest -version '[16.0,17.0)' -products * -requires Microsoft.Component.MSBuild -property installationPath | Select-Object -First 1
if (-not $vs) { throw 'Visual Studio 2019 with v141 is required.' }
$vcvars = Join-Path $vs 'VC\Auxiliary\Build\vcvarsall.bat'
$linkInputs = ($objects | ForEach-Object { '"' + $_.FullName + '"' }) -join ' '
$response = @"
/NOLOGO /LTCG /SUBSYSTEM:WINDOWS,5.01 /ENTRY:wWinMainCRTStartup /MACHINE:X86 /SAFESEH /MANIFEST:EMBED /MANIFESTUAC:"level='asInvoker' uiAccess='false'"
/OUT:"$work\ProxyLane.exe" /PDB:"$work\ProxyLane.pdb" /IMPLIB:"$work\ProxyLane.lib"
"$work\bootstrap.obj" $linkInputs "$root\build\ProxyLane\Win32\Release\ProxyLane.res" "$root\bin\Win32\Release\ProxyLaneHook.lib"
"@
Set-Content -LiteralPath "$work\link.rsp" -Value $response -Encoding Default
$batch = @"
@echo off
call "$vcvars" x86 -vcvars_ver=14.16 >nul
if errorlevel 1 exit /b 1
cl /nologo /c /O2 /GL /MT /EHsc /DWIN32 /D_WINDOWS /DNDEBUG /D_UNICODE /DUNICODE /DWINVER=0x0601 /D_WIN32_WINNT=0x0601 /source-charset:utf-8 /Fo"$work\bootstrap.obj" /Fd"$work\bootstrap.pdb" "$root\tests\LegacyHostBootstrap.cpp"
if errorlevel 1 exit /b 1
link @"$work\link.rsp"
"@
Set-Content -LiteralPath "$work\build.cmd" -Value $batch -Encoding Default
& $env:ComSpec /d /c "$work\build.cmd"
if ($LASTEXITCODE) { throw 'Legacy host test build failed.' }
Copy-Item -LiteralPath "$root\bin\ProxyLaneHook32.dll" -Destination $work -Force
& $Python -X utf8 "$root\tests\LegacyHostE2ETests.py" --binary-directory $work
if ($LASTEXITCODE) { throw 'Legacy host regression failed.' }
