[CmdletBinding()]
param(
    [ValidateSet('x64', 'ARM64')][string]$Platform = 'x64',
    [string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$project = Join-Path $repositoryRoot 'src\ProxyLaneMitm'
$output = if ($OutputDirectory) { [IO.Path]::GetFullPath($OutputDirectory) } else { Join-Path $repositoryRoot 'bin' }
$toolOutput = if ($OutputDirectory) { $output } else { Join-Path $repositoryRoot 'build\tools' }
New-Item -ItemType Directory -Path $output -Force | Out-Null
New-Item -ItemType Directory -Path $toolOutput -Force | Out-Null
$target = if ($Platform -eq 'ARM64') { 'aarch64-pc-windows-msvc' } else { 'x86_64-pc-windows-msvc' }
$suffix = if ($Platform -eq 'ARM64') { 'ARM64' } else { '64' }
& rustup target add $target --toolchain '1.88.0-x86_64-pc-windows-msvc'
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& cargo +1.88.0-x86_64-pc-windows-msvc build --manifest-path (Join-Path $project 'Cargo.toml') --release --locked --target $target
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$release = Join-Path $project ('target\' + $target + '\release')
Copy-Item -LiteralPath (Join-Path $release 'proxylane_mitm.dll') -Destination (Join-Path $output ("ProxyLaneMitm$suffix.dll")) -Force
Copy-Item -LiteralPath (Join-Path $release 'proxylane-mitm-ca.exe') -Destination (Join-Path $toolOutput ("ProxyLaneMitm$suffix.exe")) -Force
