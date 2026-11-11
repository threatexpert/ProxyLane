param([string]$Toolchain = '1.88.0-x86_64-pc-windows-msvc')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    $work = Join-Path $root 'build\quic-probe'
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    & cargo "+$Toolchain" build --manifest-path tests/quic-mitm/Cargo.toml --target-dir "$work\cargo" --locked
    if ($LASTEXITCODE -ne 0) { throw 'Rust QUIC probe build failed' }
    Copy-Item "$work\cargo\debug\proxylane-quic-mitm-probe.exe" "$work\quic-probe.exe"
    $vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvarsall.bat'
    $command = "@echo off`r`ncall `"$vcvars`" x64`r`ncl /nologo /EHsc /O2 /MT /DUNICODE /D_UNICODE tests\e2e\quic_route_host.cpp /Fo:`"$work\route-host.obj`" /Fe:`"$work\route-host.exe`" /link /LIBPATH:bin\x64\Release ProxyLaneHook.lib ws2_32.lib user32.lib`r`n"
    $batch = Join-Path $work 'build-host.cmd'
    [IO.File]::WriteAllText($batch,$command,[Text.Encoding]::Default)
    & cmd /c $batch
    if ($LASTEXITCODE -ne 0) { throw 'Native QUIC route host build failed' }
    Copy-Item bin/ProxyLaneHook64.dll "$work\ProxyLaneHook64.dll"
} finally { Pop-Location }
