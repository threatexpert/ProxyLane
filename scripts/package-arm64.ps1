[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [string]$BinaryDirectory = 'bin/ARM64/Release',
    [string]$IntelBinaryDirectory = 'bin'
)

$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'package-release.ps1') -Architecture ARM64 `
    -BinaryDirectory $BinaryDirectory -IntelBinaryDirectory $IntelBinaryDirectory -OutputDirectory $OutputDirectory
