param([string]$BinaryDirectory = (Join-Path $PSScriptRoot '..\bin'))
$ErrorActionPreference = 'Stop'
# Exercise the real page in an isolated portable copy. The local listener never
# forwards traffic; it holds the handshake until cancellation or forced failure.
Add-Type @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class ChainUiProbe {
    public delegate bool EnumProc(IntPtr window, IntPtr data);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc callback, IntPtr data);
    [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr parent, EnumProc callback, IntPtr data);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr window, out uint process);
    [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr window);
    [DllImport("user32.dll")] public static extern IntPtr GetParent(IntPtr window);
    [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr window, int id);
    [DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr window);
    [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr window, uint message, IntPtr wp, IntPtr lp);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr window, StringBuilder text, int count);
    public static IntPtr FindPage(int process) {
        IntPtr page = IntPtr.Zero;
        EnumWindows((top, data) => {
            uint pid; GetWindowThreadProcessId(top, out pid);
            if (pid == process) EnumChildWindows(top, (child, unused) => {
                if (GetDlgCtrlID(child) == 0x2406) page = GetParent(child);
                return true;
            }, IntPtr.Zero);
            return true;
        }, IntPtr.Zero);
        return page;
    }
    public static string Text(IntPtr window) {
        var text = new StringBuilder(256); GetWindowText(window, text, text.Capacity); return text.ToString();
    }
    public static void Command(IntPtr page, int id) { PostMessage(page, 0x111, (IntPtr)id, IntPtr.Zero); }
    public static void DismissOwnedError(int process) {
        EnumWindows((window, unused) => {
            uint pid; GetWindowThreadProcessId(window, out pid);
            // The single OK button can use IDCANCEL. Require the message
            // static as well, and only inspect our exact test process.
            if (pid == process && GetDlgItem(window, 65535) != IntPtr.Zero) {
                int button = GetDlgItem(window, 1) != IntPtr.Zero ? 1 : 2;
                if (GetDlgItem(window, button) != IntPtr.Zero) Command(window, button);
            }
            return true;
        }, IntPtr.Zero);
    }
    public static string Describe(int process) {
        var result = new StringBuilder();
        EnumWindows((window, unused) => {
            uint pid; GetWindowThreadProcessId(window, out pid);
            if (pid == process) {
                result.AppendLine("Window: " + Text(window));
                EnumChildWindows(window, (child, data) => {
                    result.AppendLine(GetDlgCtrlID(child) + ": " + Text(child)); return true;
                }, IntPtr.Zero);
            }
            return true;
        }, IntPtr.Zero);
        return result.ToString();
    }
}
'@

function Wait-Check([scriptblock]$Condition, [string]$Description) {
    $timer = [Diagnostics.Stopwatch]::StartNew()
    while (-not (& $Condition)) {
        if ($timer.Elapsed.TotalSeconds -gt 20) {
            if ($owned) { Write-Host ([ChainUiProbe]::Describe($owned.Id)) }
            throw $Description
        }
        Start-Sleep -Milliseconds 50
    }
    Write-Output "PASS: $Description"
}

$repo = Split-Path $PSScriptRoot -Parent
$fixture = Join-Path $repo ('build\chain-ui-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture | Out-Null
Get-ChildItem -LiteralPath ([IO.Path]::GetFullPath($BinaryDirectory)) -File |
    Where-Object { $_.Extension -in @('.exe', '.dll') } | Copy-Item -Destination $fixture
New-Item -ItemType File -Path (Join-Path $fixture 'portable.flag') | Out-Null
$listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
$listener.Start()
$port = $listener.LocalEndpoint.Port
@"
[options]
language=en-US
lastselected=Chain
testhost=example.invalid:80
[proxy_First]
Type=SOCKS5
Host=127.0.0.1
Port=$port
[proxy_Last]
Type=SOCKS5
Host=127.0.0.1
Port=$port
[proxy_Chain]
Type=CHAIN
Hop1=First
Hop2=Last
HookUDP=0
BlockUDP=1
"@ | Set-Content -LiteralPath (Join-Path $fixture 'ProxyLane.ini') -Encoding Unicode
$owned = $null
$peer = $null
try {
    $owned = Start-Process -FilePath (Join-Path $fixture 'ProxyLane64.exe') -WorkingDirectory $fixture -WindowStyle Hidden -PassThru
    Wait-Check { [ChainUiProbe]::FindPage($owned.Id) -ne [IntPtr]::Zero } 'chain page initializes'
    $page = [ChainUiProbe]::FindPage($owned.Id)
    $add = [ChainUiProbe]::GetDlgItem($page, 0x2406)
    $test = [ChainUiProbe]::GetDlgItem($page, 1008)
    $idleCaption = [ChainUiProbe]::Text($test)
    if (-not [ChainUiProbe]::IsWindowEnabled($add)) { throw 'Add must start enabled' }
    [ChainUiProbe]::Command($page, 1008)
    Wait-Check { [ChainUiProbe]::Text($test) -ne $idleCaption } 'chain test starts'
    Wait-Check { $listener.Pending() } 'first local handshake connects'
    $peer = $listener.AcceptTcpClient()
    foreach ($id in @(0x2406, 0x2407, 0x2408, 0x2409, 0x240a)) {
        if ([ChainUiProbe]::IsWindowEnabled([ChainUiProbe]::GetDlgItem($page, $id))) {
            throw "Chain editing control $id remains enabled during testing"
        }
    }
    Write-Output 'PASS: all chain editing actions are disabled during testing'
    [ChainUiProbe]::Command($page, 1008)
    Wait-Check { [ChainUiProbe]::Text($test) -eq $idleCaption -and [ChainUiProbe]::IsWindowEnabled($add) } 'cancellation restores chain editing'
    $peer.Close(); $peer = $null
    [ChainUiProbe]::Command($page, 1008)
    Wait-Check { [ChainUiProbe]::Text($test) -ne $idleCaption } 'second chain test starts'
    Wait-Check { $listener.Pending() } 'second local handshake connects'
    $peer = $listener.AcceptTcpClient()
    # Reject SOCKS5 authentication explicitly; keep the socket open so the
    # protocol error, rather than TCP reset/timeout timing, finishes the test.
    $peer.GetStream().Write([byte[]]@(5, 255), 0, 2)
    Wait-Check {
        [ChainUiProbe]::DismissOwnedError($owned.Id)
        [ChainUiProbe]::Text($test) -eq $idleCaption -and [ChainUiProbe]::IsWindowEnabled($add)
    } 'failed test restores chain editing'
} finally {
    if ($peer) { $peer.Close() }
    $listener.Stop()
    if ($owned) {
        if (-not $owned.HasExited) { $owned.Kill(); $owned.WaitForExit() }
        $owned.Dispose()
    }
}
Write-Output "Chain UI regression passed; isolated fixture: $fixture"
