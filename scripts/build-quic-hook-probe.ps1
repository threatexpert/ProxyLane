$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$work = Join-Path $root 'build\quic-probe'
New-Item -ItemType Directory -Force -Path $work | Out-Null
$vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvarsall.bat'
$command = "@echo off`r`ncall `"$vcvars`" x64`r`ncd /d `"$work`"`r`ncl /nologo /std:c++17 /EHsc /O2 /MT /LD /I`"$root\third_party\detours\src`" `"$root\tests\quic-mitm\browser_trust_probe.cpp`" `"$root\third_party\detours\src\detours.cpp`" `"$root\third_party\detours\src\disasm.cpp`" `"$root\third_party\detours\src\modules.cpp`" /Fe:browser-trust-probe.dll /link /DYNAMICBASE /NXCOMPAT`r`n"
$batch = Join-Path $work 'build-trust-hook.cmd'
[IO.File]::WriteAllText($batch, $command, [Text.Encoding]::Default)
& cmd /c $batch
if ($LASTEXITCODE -ne 0) { throw 'QUIC trust hook probe build failed' }
