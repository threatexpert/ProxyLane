param([ValidateSet('x64')][string]$Platform = 'x64')
$ErrorActionPreference = 'Stop'
# MSBuild can inherit PowerShell 7's module path while launching Windows
# PowerShell. Prefer this host's own modules for Get-FileHash/Invoke-WebRequest.
$env:PSModulePath = (Join-Path $PSHOME 'Modules') + [IO.Path]::PathSeparator + $env:PSModulePath
$repo = Split-Path $PSScriptRoot -Parent
$deps = Join-Path $repo 'build/deps'
$patch = Join-Path $repo 'third_party/libssh2/concurrent-channel-open.patch'
$patchHash = (Get-FileHash -LiteralPath $patch -Algorithm SHA256).Hash.ToLowerInvariant()
$source = Join-Path $deps "libssh2-1.11.1-$($patchHash.Substring(0,16))"
$archive = Join-Path $deps 'libssh2-1.11.1.tar.gz'
$opensslSpec = Get-Content -LiteralPath (Join-Path $repo 'third_party/openssl/dependency.json') -Raw | ConvertFrom-Json
$openssl = & (Join-Path $PSScriptRoot 'prepare-openssl.ps1')
$build = Join-Path $deps "libssh2-$Platform-$($patchHash.Substring(0,16))-openssl-$($opensslSpec.version)-$($opensslSpec.sha256.Substring(0,16))"
New-Item -ItemType Directory -Force -Path $deps | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $repo 'bin') | Out-Null
if (-not (Test-Path -LiteralPath "$source/.proxylane-patched")) {
    if (-not (Test-Path -LiteralPath $archive)) {
        Invoke-WebRequest 'https://libssh2.org/download/libssh2-1.11.1.tar.gz' -OutFile $archive
    }
    if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne 'D9EC76CBE34DB98EEC3539FE2C899D26B0C837CB3EB466A56B0F109CABF658F7') {
        throw 'libssh2 archive checksum mismatch'
    }
    New-Item -ItemType Directory -Force -Path $source | Out-Null
    & tar -xzf $archive -C $source --strip-components=1
    if ($LASTEXITCODE) { throw 'libssh2 extraction failed' }
    # Isolate patch path resolution from the surrounding ProxyLane checkout.
    # No remote is configured and this does not access the network.
    & git -C $source init -q
    if ($LASTEXITCODE) { throw 'libssh2 patch workspace initialization failed' }
    & git -C $source apply --check --whitespace=error $patch
    if ($LASTEXITCODE) { throw 'libssh2 patch verification failed' }
    & git -C $source apply --whitespace=error $patch
    if ($LASTEXITCODE) { throw 'libssh2 patch application failed' }
    Set-Content -LiteralPath "$source/.proxylane-patched" -Value $patchHash -Encoding ASCII
}
& cmake -S (Join-Path $repo 'src/ProxyLaneSsh') -B "$build-wrapper" -G 'Visual Studio 16 2019' -A $Platform "-DLIBSSH2_SOURCE=$source" "-DPROXYLANE_OPENSSL_ROOT=$openssl" "-DPROXYLANE_OPENSSL_VERSION=$($opensslSpec.version)"
if ($LASTEXITCODE) { throw 'libssh2 configuration failed' }
& cmake --build "$build-wrapper" --config Release --parallel
if ($LASTEXITCODE) { throw 'libssh2 build failed' }
$bits = '64'
$dll = Get-ChildItem -LiteralPath "$build-wrapper" -Filter libssh2.dll -Recurse | Where-Object FullName -Match '[\\/]Release[\\/]' | Select-Object -First 1
if (-not $dll) { throw 'libssh2 DLL missing' }
Copy-Item -LiteralPath $dll.FullName -Destination (Join-Path $repo "bin/ProxyLaneSsh$bits.dll")
# Inputs can change without changing the linked bytes (e.g. documentation).
# Mark the successful build outputs current so MSBuild does not run us again.
$now = Get-Date
(Get-Item -LiteralPath (Join-Path $repo "bin/ProxyLaneSsh$bits.dll")).LastWriteTime = $now
Set-Content -LiteralPath (Join-Path $deps 'ssh-backend.stamp') -Value "libssh2 1.11.1 + $patchHash, x64, OpenSSL $($opensslSpec.version) static v142 MT, $($opensslSpec.sha256)" -Encoding ASCII
