[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [string]$BinaryDirectory = 'bin/ARM64/Release'
)

$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'package-release.ps1') -Architecture ARM64 `
    -BinaryDirectory $BinaryDirectory -OutputDirectory $OutputDirectory
