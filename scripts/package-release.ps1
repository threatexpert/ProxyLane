[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [string]$BinaryDirectory,
    [string]$IntelBinaryDirectory = 'bin',
    [ValidateSet('x86-x64', 'ARM64')]
    [string]$Architecture = 'x86-x64'
)

$ErrorActionPreference = 'Stop'

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if ([string]::IsNullOrWhiteSpace($BinaryDirectory)) {
    $BinaryDirectory = if ($Architecture -eq 'ARM64') { 'bin/ARM64/Release' } else { 'bin' }
}
if (-not [System.IO.Path]::IsPathRooted($BinaryDirectory)) {
    $BinaryDirectory = Join-Path $repositoryRoot $BinaryDirectory
}
$binaryDirectory = [System.IO.Path]::GetFullPath($BinaryDirectory)

if (-not [IO.Path]::IsPathRooted($IntelBinaryDirectory)) {
    $IntelBinaryDirectory = Join-Path $repositoryRoot $IntelBinaryDirectory
}
$IntelBinaryDirectory = [IO.Path]::GetFullPath($IntelBinaryDirectory)

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $repositoryRoot 'dist'
}
elseif (-not [System.IO.Path]::IsPathRooted($OutputDirectory)) {
    $OutputDirectory = Join-Path $repositoryRoot $OutputDirectory
}
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)

# Explicit manifests keep the x86/x64 archive independent of ARM64 build output.
if ($Architecture -eq 'ARM64') {
    $packageFiles = @(
        @{ Source = (Join-Path $binaryDirectory 'ProxyLaneARM64.exe'); Entry = 'ProxyLaneARM64.exe'; Versioned = $true; Machine = 0xaa64 },
        @{ Source = (Join-Path $binaryDirectory 'ProxyLaneHookARM64.dll'); Entry = 'ProxyLaneHookARM64.dll'; Versioned = $true; Machine = 0xaa64 },
        @{ Source = (Join-Path $IntelBinaryDirectory 'ProxyLaneHook32.dll'); Entry = 'ProxyLaneHook32.dll'; Versioned = $true; Machine = 0x14c },
        @{ Source = (Join-Path $IntelBinaryDirectory 'ProxyLaneHook64.dll'); Entry = 'ProxyLaneHook64.dll'; Versioned = $true; Machine = 0x8664 },
        @{ Source = (Join-Path $binaryDirectory 'ProxyLaneSecureTransportARM64.dll'); Entry = 'ProxyLaneSecureTransportARM64.dll'; Versioned = $false; Machine = 0xaa64 },
        @{ Source = (Join-Path $binaryDirectory 'ProxyLaneMitmARM64.dll'); Entry = 'ProxyLaneMitmARM64.dll'; Versioned = $false; Machine = 0xaa64 },
        @{ Source = (Join-Path $binaryDirectory 'ProxyLaneSshARM64.dll'); Entry = 'ProxyLaneSshARM64.dll'; Versioned = $false; Machine = 0xaa64 },
        @{ Source = (Join-Path $repositoryRoot 'README.md'); Entry = 'README.md'; Versioned = $false },
        @{ Source = (Join-Path $repositoryRoot 'README_EN.md'); Entry = 'README_EN.md'; Versioned = $false }
    )
    $archivePlatform = 'Windows-ARM64'
} else {
    $packageFiles = @(
        @{ Source = (Join-Path $binaryDirectory 'ProxyLane.exe'); Entry = 'ProxyLane.exe'; Versioned = $true; Machine = 0x14c },
        @{ Source = (Join-Path $binaryDirectory 'ProxyLane64.exe'); Entry = 'ProxyLane64.exe'; Versioned = $true; Machine = 0x8664 },
        @{ Source = (Join-Path $binaryDirectory 'ProxyLaneHook32.dll'); Entry = 'ProxyLaneHook32.dll'; Versioned = $true; Machine = 0x14c },
        @{ Source = (Join-Path $binaryDirectory 'ProxyLaneHook64.dll'); Entry = 'ProxyLaneHook64.dll'; Versioned = $true; Machine = 0x8664 },
        @{ Source = (Join-Path $binaryDirectory 'ProxyLaneSecureTransport64.dll'); Entry = 'ProxyLaneSecureTransport64.dll'; Versioned = $false; Machine = 0x8664 },
        @{ Source = (Join-Path $binaryDirectory 'ProxyLaneMitm64.dll'); Entry = 'ProxyLaneMitm64.dll'; Versioned = $false; Machine = 0x8664 },
        @{ Source = (Join-Path $binaryDirectory 'ProxyLaneSsh64.dll'); Entry = 'ProxyLaneSsh64.dll'; Versioned = $false; Machine = 0x8664 },
        @{ Source = (Join-Path $repositoryRoot 'README.md'); Entry = 'README.md'; Versioned = $false },
        @{ Source = (Join-Path $repositoryRoot 'README_EN.md'); Entry = 'README_EN.md'; Versioned = $false }
    )
    # Retain the existing release filename for current download integrations.
    $archivePlatform = 'Windows'
}

$projectLicense = Join-Path $repositoryRoot 'LICENSE'
$thirdPartyLicenses = @(
    @{ Name = 'OpenSSL'; Source = (Join-Path $repositoryRoot 'third_party\openssl\LICENSE.txt') },
    @{ Name = 'libssh2'; Source = (Join-Path $repositoryRoot 'third_party\libssh2\COPYING') },
    @{ Name = 'Microsoft Detours'; Source = (Join-Path $repositoryRoot 'third_party\detours\LICENSE.md') },
    @{ Name = 'nlohmann/json'; Source = (Join-Path $repositoryRoot 'third_party\nlohmann\LICENSE.MIT') },
    @{ Name = 'TLS trust notices'; Source = (Join-Path $repositoryRoot 'third_party\tls-trust\NOTICE.txt') },
    @{ Name = 'webpki-root-certs'; Source = (Join-Path $repositoryRoot 'third_party\tls-trust\LICENSE-webpki-root-certs.txt') },
    @{ Name = 'rustls-platform-verifier'; Source = (Join-Path $repositoryRoot 'third_party\tls-trust\LICENSE-rustls-platform-verifier.txt') },
    @{ Name = 'h3-quinn'; Source = (Join-Path $repositoryRoot 'third_party\h3-quinn\LICENSE') }
)
foreach ($packageFile in @($packageFiles) + @(@{ Source = $projectLicense }) + @($thirdPartyLicenses)) {
    if (-not (Test-Path -LiteralPath $packageFile.Source -PathType Leaf)) {
        throw "Required release file is missing: $($packageFile.Source)"
    }
}

# Check file contents, not only architecture suffixes, before replacing any ZIP.
foreach ($packageFile in $packageFiles) {
    if (-not $packageFile.ContainsKey('Machine')) { continue }
    $bytes = [IO.File]::ReadAllBytes($packageFile.Source)
    if ($bytes.Length -lt 64 -or [BitConverter]::ToUInt16($bytes, 0) -ne 0x5a4d) {
        throw "Invalid DOS header: $($packageFile.Source)"
    }
    $pe = [BitConverter]::ToInt32($bytes, 0x3c)
    if ($pe -lt 64 -or $pe -gt $bytes.Length - 26 -or [BitConverter]::ToUInt32($bytes, $pe) -ne 0x4550) {
        throw "Invalid PE header: $($packageFile.Source)"
    }
    $machine = [BitConverter]::ToUInt16($bytes, $pe + 4)
    $magic = [BitConverter]::ToUInt16($bytes, $pe + 24)
    $expectedMagic = if ($packageFile.Machine -eq 0x14c) { 0x10b } else { 0x20b }
    if ($machine -ne $packageFile.Machine -or $magic -ne $expectedMagic) {
        throw ('Wrong PE architecture in {0}: expected 0x{1:X4}, found 0x{2:X4}' -f $packageFile.Entry, $packageFile.Machine, $machine)
    }
}
$tlsDirectory = if ($Architecture -eq 'ARM64') { $IntelBinaryDirectory } else { $binaryDirectory }
& python (Join-Path $repositoryRoot 'tests/HookStaticTlsTests.py') --bin $tlsDirectory | Out-Host
if ($LASTEXITCODE) { throw 'Hook static TLS verification failed; package was not created.' }

# Generate only the archive's LICENSE; keep upstream license files unchanged.
$separator = '=' * 72
$combinedLicense = New-Object System.Text.StringBuilder
[void]$combinedLicense.Append([System.IO.File]::ReadAllText($projectLicense))
[void]$combinedLicense.Append("`r`n`r`n$separator`r`nThird-Party Software Licenses`r`n$separator`r`n")
foreach ($license in $thirdPartyLicenses) {
    $sourceName = [System.IO.Path]::GetFileName($license.Source)
    [void]$combinedLicense.Append("`r`n$($license.Name) ($sourceName)`r`n$separator`r`n`r`n")
    [void]$combinedLicense.Append([System.IO.File]::ReadAllText($license.Source))
    [void]$combinedLicense.Append("`r`n")
}

$versions = @(
    foreach ($packageFile in $packageFiles) {
        if (-not $packageFile.Versioned) {
            continue
        }

        $rawVersion = (Get-Item -LiteralPath $packageFile.Source).VersionInfo.FileVersion
        $versionMatch = [regex]::Match($rawVersion, '\d+\.\d+\.\d+\.\d+')
        if (-not $versionMatch.Success) {
            throw "Cannot read a four-part file version from: $($packageFile.Source)"
        }
        $versionMatch.Value
    }
)
$versions = @($versions | Select-Object -Unique)

if ($versions.Count -ne 1) {
    throw "Release binaries have different file versions: $($versions -join ', ')"
}
$fileVersion = $versions[0]
$version = ([Version]$fileVersion).ToString(3)

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$archivePath = Join-Path $OutputDirectory "ProxyLane-$version-$archivePlatform.zip"
if (Test-Path -LiteralPath $archivePath) {
    Remove-Item -LiteralPath $archivePath -Force
}

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$archive = [System.IO.Compression.ZipFile]::Open(
    $archivePath,
    [System.IO.Compression.ZipArchiveMode]::Create)
try {
    foreach ($packageFile in $packageFiles) {
        [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
            $archive,
            $packageFile.Source,
            $packageFile.Entry,
            [System.IO.Compression.CompressionLevel]::Optimal) | Out-Null
    }
    $licenseEntry = $archive.CreateEntry('LICENSE', [System.IO.Compression.CompressionLevel]::Optimal)
    $licenseStream = $licenseEntry.Open()
    try {
        $encoding = New-Object System.Text.UTF8Encoding($false)
        $licenseBytes = $encoding.GetBytes($combinedLicense.ToString())
        $licenseStream.Write($licenseBytes, 0, $licenseBytes.Length)
    }
    finally {
        $licenseStream.Dispose()
    }
}
finally {
    $archive.Dispose()
}

$sha256 = [System.Security.Cryptography.SHA256]::Create()
try {
    $stream = [System.IO.File]::OpenRead($archivePath)
    try {
        $hash = ([System.BitConverter]::ToString($sha256.ComputeHash($stream))).Replace('-', '')
    }
    finally {
        $stream.Dispose()
    }
}
finally {
    $sha256.Dispose()
}

$archiveInfo = Get-Item -LiteralPath $archivePath
$checksumPath = $archivePath + '.sha256'
($hash.ToLowerInvariant() + '  ' + $archiveInfo.Name) | Set-Content -LiteralPath $checksumPath -Encoding ASCII
[PSCustomObject]@{
    Version = $version
    Architecture = $Architecture
    Archive = $archiveInfo.FullName
    SizeBytes = $archiveInfo.Length
    SHA256 = $hash
    ChecksumFile = $checksumPath
}
