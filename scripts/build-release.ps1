[CmdletBinding()]
param(
    [ValidateSet('x86-x64', 'ARM64', 'All')]
    [string]$Architecture = 'x86-x64',
    [switch]$Package,
    [switch]$CheckEnvironmentOnly,
    [string]$ClangBinDirectory,
    [string]$OutputDirectory = 'dist'
)

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$needsArm = $Architecture -in @('ARM64', 'All')
$missing = New-Object 'System.Collections.Generic.List[string]'
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = $null
if (Test-Path -LiteralPath $vswhere) {
    $vs = & $vswhere -latest -version '[16.0,17.0)' -products * -requires Microsoft.Component.MSBuild -property installationPath | Select-Object -First 1
}
if (-not $vs) { $missing.Add('Install Visual Studio 2019 / Build Tools 2019 with the repository .vsconfig components.') }

function Require-Path([string]$Path, [string]$Message) {
    if (-not (Test-Path -Path $Path)) { $missing.Add($Message) }
}
if ($vs) {
    $msbuild = Join-Path $vs 'MSBuild\Current\Bin\MSBuild.exe'
    Require-Path $msbuild 'Install MSBuild in Visual Studio 2019.'
    $vc = Join-Path $vs 'VC\Tools\MSVC'
    foreach ($arch in @('x86', 'x64')) {
        Require-Path "$vc\14.16.*\bin\Hostx64\$arch\cl.exe" "Install v141 x86/x64 build tools ($arch)."
        Require-Path "$vc\14.16.*\atlmfc\lib\$arch\nafxcw.lib" "Install v141 ATL/MFC ($arch)."
        Require-Path "$vc\14.2*\bin\Hostx64\$arch\cl.exe" "Install v142 x86/x64 build tools ($arch)."
    }
    Require-Path "$vs\MSBuild\Microsoft\VC\v150\Platforms\Win32\PlatformToolsets\v141_xp\Toolset.props" 'Install C++ Windows XP support (v141_xp).'
    if ($needsArm) {
        Require-Path "$vc\14.2*\bin\Hostx64\arm64\cl.exe" 'Install v142 ARM64 build tools.'
        Require-Path "$vc\14.2*\atlmfc\lib\arm64\mfc140u.lib" 'Install v142 ARM64 ATL/MFC.'
    }
}
$sdk71 = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SDKs\Windows\v7.1A' -ErrorAction SilentlyContinue).InstallationFolder
if (-not $sdk71) { $sdk71 = "${env:ProgramFiles(x86)}\Microsoft SDKs\Windows\v7.1A" }
Require-Path "$sdk71\Include\Windows.h" 'Install Windows 7.1A SDK via the Visual Studio XP support component.'
$sdk10 = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots' -ErrorAction SilentlyContinue).KitsRoot10
if (-not $sdk10) { $sdk10 = "${env:ProgramFiles(x86)}\Windows Kits\10" }
Require-Path "$sdk10\Include\10.*\um\Windows.h" 'Install Windows 10 SDK (19041 is the documented baseline).'
if ($needsArm) { Require-Path "$sdk10\Lib\10.*\um\arm64\kernel32.lib" 'Install Windows 10 SDK ARM64 libraries.' }

foreach ($tool in @('git', 'python', 'tar', 'rustup', 'cargo', 'powershell.exe')) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) { $missing.Add("Install $tool and add it to PATH; see docs/BUILDING.md.") }
}
$cmake = Get-Command cmake.exe -ErrorAction SilentlyContinue
$cmakeDirectory = $null
if (-not $cmake -and $vs) {
    $cmakeDirectory = Join-Path $vs 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin'
    if (-not (Test-Path "$cmakeDirectory\cmake.exe")) { $cmakeDirectory = $null }
}
if (-not $cmake -and -not $cmakeDirectory) { $missing.Add('Install CMake 3.15+ on PATH or the Visual Studio CMake component.') }
else {
    $cmakeExecutable = if ($cmake) { $cmake.Source } else { Join-Path $cmakeDirectory 'cmake.exe' }
    $cmakeVersion = & $cmakeExecutable --version
    if ($LASTEXITCODE -or -not ($cmakeVersion[0] -match 'cmake version (\d+\.\d+\.\d+)') -or [version]$Matches[1] -lt [version]'3.15.0') {
        $missing.Add('CMake 3.15+ is required.')
    }
}
if (Get-Command python -ErrorAction SilentlyContinue) {
    & python -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)'
    if ($LASTEXITCODE) { $missing.Add('python must run Python 3.8+; disable the Windows Store alias if necessary.') }
}
if (Get-Command rustup -ErrorAction SilentlyContinue) {
    $installed = & rustup toolchain list
    if ($LASTEXITCODE -or -not ($installed -match '^1\.88\.0-x86_64-pc-windows-msvc')) {
        $missing.Add('Run: rustup toolchain install 1.88.0-x86_64-pc-windows-msvc --profile minimal')
    } else {
        # ARM packages also build Intel companions and run x64 tests.
        $requiredTargets = @('x86_64-pc-windows-msvc')
        if ($needsArm) { $requiredTargets += 'aarch64-pc-windows-msvc' }
        $installedTargets = @(& rustup target list --installed --toolchain 1.88.0-x86_64-pc-windows-msvc)
        if ($LASTEXITCODE) {
            $missing.Add('Cannot query Rust targets. Run: rustup target list --installed --toolchain 1.88.0-x86_64-pc-windows-msvc')
        } else {
            foreach ($target in $requiredTargets) {
                if ($installedTargets -notcontains $target) {
                    $missing.Add("Run: rustup target add $target --toolchain 1.88.0-x86_64-pc-windows-msvc")
                }
            }
        }
    }
}
if ($needsArm) {
    $clang = $null
    if ($ClangBinDirectory) {
        $candidate = Join-Path ([IO.Path]::GetFullPath($ClangBinDirectory)) 'clang.exe'
        if (Test-Path -LiteralPath $candidate) { $clang = $candidate }
    } else {
        $command = Get-Command clang.exe -ErrorAction SilentlyContinue
        if ($command) { $clang = $command.Source }
        elseif (Test-Path "$env:ProgramFiles\LLVM\bin\clang.exe") { $clang = "$env:ProgramFiles\LLVM\bin\clang.exe" }
    }
    if (-not $clang) { $missing.Add('Install LLVM/Clang for ARM64 or pass -ClangBinDirectory <directory containing clang.exe>.') }
    else { $ClangBinDirectory = Split-Path -Parent $clang }
}
if ($missing.Count) { throw ("Build prerequisites are missing:`n - " + ($missing -join "`n - ") + "`nSee docs/BUILDING.md or docs/BUILDING_EN.md.") }
Write-Host "Environment checks passed: VS=$vs; Architecture=$Architecture"
if ($CheckEnvironmentOnly) { return }

if (-not [IO.Path]::IsPathRooted($OutputDirectory)) { $OutputDirectory = Join-Path $root $OutputDirectory }
$logDirectory = Join-Path $root ('build\release\' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 6))
New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
$originalPath = $env:PATH
$transcribing = $false
Push-Location $root
try {
    if ($cmakeDirectory) { $env:PATH = "$cmakeDirectory;$env:PATH" }
    Start-Transcript -Path (Join-Path $logDirectory 'build.log') | Out-Null
    $transcribing = $true
    # Intel Release is also needed for the ARM package's companion Hooks and
    # for runnable regression tests on this x64 Windows build host.
    foreach ($platform in @('Win32', 'x64')) {
        & $msbuild src/ProxyLane.sln /m /t:Build /p:Configuration=Release "/p:Platform=$platform" /v:minimal "/flp:logfile=$logDirectory\$platform.log;verbosity=normal"
        if ($LASTEXITCODE) { throw "$platform build failed; see $logDirectory" }
        & ".\tests\bin\$platform\Release\ProxyLaneTests.exe"
        if ($LASTEXITCODE) { throw "$platform unit tests failed." }
    }
    if ($needsArm) {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/build-arm64.ps1 -ClangBinDirectory $ClangBinDirectory
        if ($LASTEXITCODE) { throw 'ARM64 build failed.' }
    }
    & python tests/HookStaticTlsTests.py
    if ($LASTEXITCODE) { throw 'Hook static TLS verification failed.' }
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/check-locales.ps1
    if ($LASTEXITCODE) { throw 'Locale checks failed.' }
    $packages = @()
    if ($Package) {
        $architectures = if ($Architecture -eq 'All') { @('x86-x64', 'ARM64') } else { @($Architecture) }
        foreach ($item in $architectures) {
            $release = & "$PSScriptRoot\package-release.ps1" -Architecture $item -OutputDirectory $OutputDirectory
            $packages += $release
            $release | Format-List | Out-Host
        }
    }
    [pscustomobject]@{
        Commit = (& git rev-parse HEAD)
        WorkingTree = @(& git status --porcelain)
        Architecture = $Architecture
        VisualStudio = $vs
        Rust = (& rustup run 1.88.0-x86_64-pc-windows-msvc rustc --version)
        Packages = $packages
        Checks = @('Win32/x64 unit tests', 'Hook static TLS', 'locale catalogs')
        ARM64RuntimeTested = $false
        XPRuntimeTested = $false
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $logDirectory 'build-info.json') -Encoding UTF8
    Write-Host "Build complete. Logs: $logDirectory"
    Write-Host 'ARM64 and XP runtime tests are separate device checks; they were not executed here.'
} finally {
    if ($transcribing) { Stop-Transcript | Out-Null }
    $env:PATH = $originalPath
    Pop-Location
}
