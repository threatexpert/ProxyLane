[CmdletBinding()]
param(
    [ValidateSet('x64', 'ARM64')]
    [string[]]$Platforms = @('x64'),
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$project = Join-Path $repositoryRoot 'src\ProxyLaneSecureTransport'
$binaryDirectory = if ($OutputDirectory) {
    [System.IO.Path]::GetFullPath($OutputDirectory)
} else {
    Join-Path $repositoryRoot 'bin'
}
$targets = @{
    x64 = @{ Triple = 'x86_64-pc-windows-msvc'; File = 'ProxyLaneSecureTransport64.dll' }
    ARM64 = @{ Triple = 'aarch64-pc-windows-msvc'; File = 'ProxyLaneSecureTransportARM64.dll' }
}

New-Item -ItemType Directory -Path $binaryDirectory -Force | Out-Null
foreach ($platform in ($Platforms | Select-Object -Unique)) {
    $target = $targets[$platform].Triple
    & rustup target add $target --toolchain '1.88.0-x86_64-pc-windows-msvc'
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    & cargo +1.88.0-x86_64-pc-windows-msvc build --manifest-path (Join-Path $project 'Cargo.toml') --release --locked --target $target
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    Copy-Item -LiteralPath (Join-Path $project "target\$target\release\proxylane_secure_transport.dll") `
        -Destination (Join-Path $binaryDirectory $targets[$platform].File) -Force
}
