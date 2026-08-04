[CmdletBinding()]
param(
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$binaryDirectory = Join-Path $repositoryRoot 'bin'
$exampleConfig = Join-Path $repositoryRoot 'examples\ProxyLane.ini'

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
    @{ Source = $exampleConfig;                                     Entry = 'ProxyLane.ini';       Versioned = $false },
    @{ Source = (Join-Path $repositoryRoot 'README.md');            Entry = 'README.md';           Versioned = $false },
    @{ Source = (Join-Path $repositoryRoot 'README_EN.md');         Entry = 'README_EN.md';        Versioned = $false }
)

foreach ($packageFile in $packageFiles) {
    if (-not (Test-Path -LiteralPath $packageFile.Source -PathType Leaf)) {
        throw "Required release file is missing: $($packageFile.Source)"
    }
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
