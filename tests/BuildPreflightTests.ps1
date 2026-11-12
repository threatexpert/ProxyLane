# Exercise the real preflight without installing/removing Rust components.
# Other missing host prerequisites are allowed: these tests isolate Rust diagnostics.
$ErrorActionPreference = 'Stop'
$entry = Join-Path $PSScriptRoot '..\scripts\build-release.ps1'
$toolchain = '1.88.0-x86_64-pc-windows-msvc'
$x64 = 'x86_64-pc-windows-msvc'
$arm = 'aarch64-pc-windows-msvc'
function rustup {
    $calls.Add(($args -join ' '))
    $global:LASTEXITCODE = 0
    switch ($args -join ' ') {
        'toolchain list' { if ($hasToolchain) { "$toolchain (default)" }; return }
        "target list --installed --toolchain $toolchain" {
            $global:LASTEXITCODE = $queryExitCode
            $targets
            return
        }
        default { throw "Unexpected rustup command (preflight must not install): $args" }
    }
}
$cases = @(
    @{ Name='Intel needs only x64'; Arch='x86-x64'; Targets=@($x64); Missing=@() },
    @{ Name='Intel missing x64'; Arch='x86-x64'; Targets=@($arm); Missing=@($x64) },
    @{ Name='ARM missing ARM target'; Arch='ARM64'; Targets=@($x64); Missing=@($arm) },
    @{ Name='All missing ARM target'; Arch='All'; Targets=@($x64); Missing=@($arm) },
    @{ Name='ARM still needs x64'; Arch='ARM64'; Targets=@($arm); Missing=@($x64) },
    @{ Name='All targets installed'; Arch='All'; Targets=@($x64,$arm); Missing=@() },
    @{ Name='Both targets missing'; Arch='All'; Targets=@(); Missing=@($x64,$arm) },
    @{ Name='Target query fails'; Arch='All'; Targets=@(); Missing=@(); QueryError=$true },
    @{ Name='Toolchain missing'; Arch='All'; Targets=@(); Missing=@(); NoToolchain=$true }
)
foreach ($case in $cases) {
    $hasToolchain = -not $case.NoToolchain
    $targets = $case.Targets
    $queryExitCode = if ($case.QueryError) { 1 } else { 0 }
    $calls = New-Object 'System.Collections.Generic.List[string]'
    $diagnostic = ''
    try { & $entry -Architecture $case.Arch -CheckEnvironmentOnly 6>$null }
    catch { $diagnostic = $_.Exception.Message }
    $expected = @()
    if ($case.NoToolchain) { $expected += "Run: rustup toolchain install $toolchain --profile minimal" }
    elseif ($case.QueryError) { $expected += "Cannot query Rust targets. Run: rustup target list --installed --toolchain $toolchain" }
    else { foreach ($target in $case.Missing) { $expected += "Run: rustup target add $target --toolchain $toolchain" } }
    $actual = @($diagnostic -split "`n" | Where-Object { $_ -match 'rustup|Rust targets' } | ForEach-Object { $_ -replace '^ - ', '' })
    if (($actual -join "`n") -cne ($expected -join "`n")) {
        throw "$($case.Name): unexpected diagnostics:`n$diagnostic"
    }
    $expectedCalls = @('toolchain list')
    if (-not $case.NoToolchain) { $expectedCalls += "target list --installed --toolchain $toolchain" }
    if (($calls -join ';') -cne ($expectedCalls -join ';')) {
        throw "$($case.Name): unexpected rustup calls: $calls; preflight: $diagnostic"
    }
    Write-Host "PASS: $($case.Name)"
}
Write-Host "$($cases.Count) build preflight checks passed."
