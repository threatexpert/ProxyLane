[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [string]$BinaryDirectory = 'bin'
)

$ErrorActionPreference = 'Stop'

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if (-not [System.IO.Path]::IsPathRooted($BinaryDirectory)) {
    $BinaryDirectory = Join-Path $repositoryRoot $BinaryDirectory
}
$binaryDirectory = [System.IO.Path]::GetFullPath($BinaryDirectory)

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $repositoryRoot 'dist'
}
elseif (-not [System.IO.Path]::IsPathRooted($OutputDirectory)) {
    $OutputDirectory = Join-Path $repositoryRoot $OutputDirectory
}
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)

$packageFiles = @(
    @{ Source = (Join-Path $binaryDirectory 'ProxyLane.exe');       Entry = 'ProxyLane.exe';       Versioned = $true },
    @{ Source = (Join-Path $binaryDirectory 'ProxyLane64.exe');     Entry = 'ProxyLane64.exe';     Versioned = $true },
    @{ Source = (Join-Path $binaryDirectory 'ProxyLaneHook32.dll'); Entry = 'ProxyLaneHook32.dll'; Versioned = $true },
    @{ Source = (Join-Path $binaryDirectory 'ProxyLaneHook64.dll'); Entry = 'ProxyLaneHook64.dll'; Versioned = $true },
    @{ Source = (Join-Path $binaryDirectory 'ProxyLaneSecureTransport64.dll'); Entry = 'ProxyLaneSecureTransport64.dll'; Versioned = $false },
    @{ Source = (Join-Path $binaryDirectory 'ProxyLaneMitm64.dll'); Entry = 'ProxyLaneMitm64.dll'; Versioned = $false },
    @{ Source = (Join-Path $repositoryRoot 'README.md');            Entry = 'README.md';           Versioned = $false },
    @{ Source = (Join-Path $repositoryRoot 'README_EN.md');         Entry = 'README_EN.md';        Versioned = $false }
)

$projectLicense = Join-Path $repositoryRoot 'LICENSE'
$thirdPartyLicenses = @(
    @{ Name = 'Microsoft Detours'; Source = (Join-Path $repositoryRoot 'third_party\detours\LICENSE.md') },
    @{ Name = 'nlohmann/json'; Source = (Join-Path $repositoryRoot 'third_party\nlohmann\LICENSE.MIT') },
    @{ Name = 'TLS trust notices'; Source = (Join-Path $repositoryRoot 'third_party\tls-trust\NOTICE.txt') },
    @{ Name = 'webpki-root-certs'; Source = (Join-Path $repositoryRoot 'third_party\tls-trust\LICENSE-webpki-root-certs.txt') },
    @{ Name = 'rustls-platform-verifier'; Source = (Join-Path $repositoryRoot 'third_party\tls-trust\LICENSE-rustls-platform-verifier.txt') },
    @{ Name = 'h3-quinn'; Source = (Join-Path $repositoryRoot 'third_party\h3-quinn\LICENSE') },
    @{ Name = 'Noto Sans SC'; Source = (Join-Path $repositoryRoot 'third_party\noto-sans-sc\OFL.txt') }
)
foreach ($packageFile in @($packageFiles) + @(@{ Source = $projectLicense }) + @($thirdPartyLicenses)) {
    if (-not (Test-Path -LiteralPath $packageFile.Source -PathType Leaf)) {
        throw "Required release file is missing: $($packageFile.Source)"
    }
}

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
$archivePath = Join-Path $OutputDirectory "ProxyLane-$version-Windows.zip"
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
[PSCustomObject]@{
    Version = $version
    Archive = $archiveInfo.FullName
    SizeBytes = $archiveInfo.Length
    SHA256 = $hash
}
