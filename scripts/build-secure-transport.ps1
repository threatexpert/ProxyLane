[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$project = Join-Path $repositoryRoot 'src\ProxyLaneSecureTransport'
$binaryDirectory = Join-Path $repositoryRoot 'bin'

foreach ($target in @('i686-pc-windows-msvc', 'x86_64-pc-windows-msvc')) {
    & rustup target add $target
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    & cargo build --manifest-path (Join-Path $project 'Cargo.toml') --release --locked --target $target
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

New-Item -ItemType Directory -Path $binaryDirectory -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $project 'target\i686-pc-windows-msvc\release\proxylane_secure_transport.dll') `
    -Destination (Join-Path $binaryDirectory 'ProxyLaneSecureTransport32.dll') -Force
Copy-Item -LiteralPath (Join-Path $project 'target\x86_64-pc-windows-msvc\release\proxylane_secure_transport.dll') `
    -Destination (Join-Path $binaryDirectory 'ProxyLaneSecureTransport64.dll') -Force
