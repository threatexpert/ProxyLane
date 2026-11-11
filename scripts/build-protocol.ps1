[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$project = Join-Path $repositoryRoot 'src\ProxyLaneProtocol'
$output = Join-Path $repositoryRoot 'build\tools'
New-Item -ItemType Directory -Path $output -Force | Out-Null
foreach ($arch in @(@('i686-pc-windows-msvc', '32'), @('x86_64-pc-windows-msvc', '64'))) {
    & cargo build --manifest-path (Join-Path $project 'Cargo.toml') --release --locked --target $arch[0]
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $release = Join-Path $project ('target\' + $arch[0] + '\release')
    Copy-Item -LiteralPath (Join-Path $release 'proxylane-protocol.exe') -Destination (Join-Path $output ('ProxyLaneProtocol' + $arch[1] + '.exe')) -Force
}
