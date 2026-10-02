param(
    [ValidateSet('Win32', 'x64')]
    [string[]]$Platforms = @('Win32', 'x64'),
    [ValidateRange(1, 60)]
    [int]$ObserveSeconds = 10,
    [ValidateRange(1, 10)]
    [int]$Repetitions = 2
)

$ErrorActionPreference = 'Stop'
$binaryDirectory = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\bin'))

# Run on an unlocked Windows desktop, after building Release binaries to bin.
# This tests real dialog initialization and the message loop, not just /? or
# command-line parsing. It never selects a profile, starts a proxy, or targets
# an existing process. On 64-bit Windows the Win32 launcher forwards to an x64
# child; verify that exact child and clean up both owned processes.
foreach ($platform in $Platforms) {
    $name = if ($platform -eq 'x64') { 'ProxyLane64.exe' } else { 'ProxyLane.exe' }
    $executable = Join-Path $binaryDirectory $name
    if (-not (Test-Path -LiteralPath $executable)) { throw "Missing binary: $executable" }
    for ($iteration = 1; $iteration -le $Repetitions; $iteration++) {
        $ownedProcess = $null
        $forwardedProcess = $null
        try {
            $ownedProcess = Start-Process -FilePath $executable -WorkingDirectory $binaryDirectory -WindowStyle Hidden -PassThru
            $timer = [Diagnostics.Stopwatch]::StartNew()
            $readyAt = -1
            while ($true) {
                $ownedProcess.Refresh()
                if ($ownedProcess.HasExited) { throw "$name exited during startup: $($ownedProcess.ExitCode)" }
                if ($platform -eq 'Win32' -and [Environment]::Is64BitOperatingSystem -and -not $forwardedProcess) {
                    $children = Get-CimInstance Win32_Process -Filter "ParentProcessId=$($ownedProcess.Id)" |
                        Where-Object { $_.ExecutablePath -eq (Join-Path $binaryDirectory 'ProxyLane64.exe') -and
                            $_.CreationDate -ge $ownedProcess.StartTime }
                    if (@($children).Count -gt 1) { throw 'Unexpected multiple forwarding children' }
                    if (@($children).Count -eq 1) {
                        $candidate = [Diagnostics.Process]::GetProcessById($children.ProcessId)
                        try {
                            $null = $candidate.Handle # Hold the exact process through cleanup.
                            $creationDifference = $candidate.StartTime.ToUniversalTime().Ticks -
                                $children.CreationDate.ToUniversalTime().Ticks
                            # CIM reports microseconds; GetProcessTimes has 100ns precision.
                            if ($creationDifference -lt 0 -or $creationDifference -ge 10 -or
                                $candidate.Path -ne $children.ExecutablePath) { throw 'Forwarded PID identity changed' }
                            $forwardedProcess = $candidate
                        } finally {
                            if (-not $forwardedProcess) { $candidate.Dispose() }
                        }
                    }
                }
                $dialogProcess = if ($forwardedProcess) { $forwardedProcess } else { $ownedProcess }
                $dialogProcess.Refresh()
                if ($dialogProcess.HasExited) { throw "$name dialog process exited during startup" }
                $hasMainDialog = $dialogProcess.MainWindowHandle -ne [IntPtr]::Zero -and
                    $dialogProcess.MainWindowTitle -match '^ProxyLane \d+\.\d+\.\d+(?: |$)'
                if ($hasMainDialog -and $dialogProcess.Responding) {
                    if ($readyAt -lt 0) { $readyAt = $timer.Elapsed.TotalSeconds }
                    if ($timer.Elapsed.TotalSeconds - $readyAt -ge $ObserveSeconds) { break }
                } elseif ($readyAt -ge 0) {
                    throw "$name lost its main dialog or stopped responding"
                }
                if ($timer.Elapsed.TotalSeconds -gt $ObserveSeconds + 30) {
                    throw "$name failed to initialize a responsive main dialog"
                }
                Start-Sleep -Milliseconds 200
            }
            Write-Host "$platform startup smoke $iteration/$Repetitions passed: main dialog responsive for ${ObserveSeconds}s"
        } finally {
            foreach ($testProcess in @($forwardedProcess, $ownedProcess)) {
                if ($testProcess) {
                    if (-not $testProcess.HasExited) {
                        $testProcess.Kill()
                        if (-not $testProcess.WaitForExit(5000)) { throw "Test process did not exit: $($testProcess.Id)" }
                    }
                    $testProcess.Dispose()
                }
            }
        }
    }
}
