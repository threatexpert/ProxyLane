param([ValidateSet('x64', 'ARM64')][string]$Platform = 'x64')
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$repo = Split-Path $PSScriptRoot -Parent
$spec = Get-Content -LiteralPath (Join-Path $repo 'third_party/openssl/dependency.json') -Raw | ConvertFrom-Json
$deps = Join-Path $repo 'build/deps'
$library = if ($Platform -eq 'ARM64') { $spec.arm64_library } else { $spec.library }
$identity = "$($spec.package)-$($spec.version)-$($spec.sha256.Substring(0,16))-$($Platform.ToLowerInvariant())-v142-mt"
$destination = Join-Path $deps $identity
$archive = Join-Path $deps "$($spec.package).$($spec.version).nupkg"
New-Item -ItemType Directory -Force -Path $deps | Out-Null
# Separate instances may build different checkouts; serialize only this cache.
$sha = [Security.Cryptography.SHA256]::Create()
try { $lockId = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($archive.ToLowerInvariant()))).Replace('-', '') }
finally { $sha.Dispose() }
$mutex = New-Object Threading.Mutex($false, "Local\ProxyLane-OpenSSL-$lockId")
$locked = $false
$staging = $null
$download = $null
try {
    try { $locked = $mutex.WaitOne(300000) } catch [Threading.AbandonedMutexException] { $locked = $true }
    if (-not $locked) { throw 'Timed out waiting for the OpenSSL dependency cache.' }
    if (-not (Test-Path -LiteralPath $archive)) {
        $download = "$archive.$([Guid]::NewGuid().ToString('N')).download"
        Write-Host "Downloading $($spec.package) $($spec.version) (precompiled $Platform / v142 / MT library)..."
        try {
            if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
                & curl.exe --fail --silent --show-error --location --retry 2 --connect-timeout 30 --max-time 300 --output $download $spec.url
                if ($LASTEXITCODE) { throw "curl exited with code $LASTEXITCODE" }
            } else {
                Invoke-WebRequest -UseBasicParsing -Uri $spec.url -OutFile $download
            }
        }
        catch { throw "OpenSSL download failed. For offline builds, place the package at '$archive'. Source: $($spec.url). $($_.Exception.Message)" }
        if ((Get-FileHash -LiteralPath $download -Algorithm SHA256).Hash -ne $spec.sha256) { throw 'OpenSSL package checksum mismatch.' }
        Move-Item -LiteralPath $download -Destination $archive
        $download = $null
    }
    # The pinned hash identifies the exact package whose NuGet.org repository
    # signature was verified when updating dependency.json. No .NET SDK needed.
    if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $spec.sha256) {
        throw "OpenSSL package checksum mismatch. Replace '$archive' with the pinned package."
    }
    $marker = Join-Path $destination '.complete'
    if (-not (Test-Path -LiteralPath $marker)) {
        if (Test-Path -LiteralPath $destination) { throw "Incomplete OpenSSL cache at '$destination'; move it aside and retry." }
        $staging = "$destination.$([Guid]::NewGuid().ToString('N')).tmp"
        New-Item -ItemType Directory -Path $staging | Out-Null
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [IO.Compression.ZipFile]::OpenRead($archive)
        try {
            foreach ($entry in $zip.Entries) {
                if ($entry.FullName.StartsWith('include/openssl/') -or $entry.FullName -eq $library -or $entry.FullName -eq 'docs/license.txt') {
                    if (-not $entry.Name) { continue }
                    $target = [IO.Path]::GetFullPath((Join-Path $staging $entry.FullName))
                    if (-not $target.StartsWith([IO.Path]::GetFullPath($staging) + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid package entry path.' }
                    New-Item -ItemType Directory -Force -Path (Split-Path $target -Parent) | Out-Null
                    [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $target)
                }
            }
            foreach ($required in @($library, 'include/openssl/opensslv.h', 'docs/license.txt')) {
                if (-not (Test-Path -LiteralPath (Join-Path $staging $required))) { throw "OpenSSL package is missing $required" }
            }
            Set-Content -LiteralPath (Join-Path $staging '.complete') -Value $spec.sha256 -Encoding ASCII
        } finally { $zip.Dispose() }
        $cacheRoot = [IO.Path]::GetFullPath($deps) + [IO.Path]::DirectorySeparatorChar
        foreach ($path in @($staging, $destination)) {
            if (-not [IO.Path]::GetFullPath($path).StartsWith($cacheRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid OpenSSL cache path.' }
        }
        Move-Item -LiteralPath $staging -Destination $destination
        $staging = $null
    }
    if ((Get-Content -LiteralPath $marker -Raw).Trim() -ne $spec.sha256) { throw 'Unexpected OpenSSL cache identity.' }
    Write-Output $destination
} finally {
    if ($download -and (Test-Path -LiteralPath $download)) { Remove-Item -LiteralPath $download }
    # Failed extraction is left under its unique name for diagnosis; never
    # publish it as a complete cache or recursively delete a computed path.
    if ($locked) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}
