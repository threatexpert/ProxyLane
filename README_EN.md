<h1 align="center">ProxyLane</h1>

<p align="center">
  <strong>Transparent per-process proxy for Windows · HTTPS / QUIC traffic decryption</strong><br>
  No TUN required · Separate proxy settings · Automatic child-process inheritance · Traffic recording and offline playback
</p>

<p align="center">
  Join the community discussion on <a href="https://linux.do/t/topic/2980923">Linux.do</a> and <a href="https://v2ex.com/t/1242151">V2EX</a>
</p>

<p align="center"><a href="README.md">简体中文</a> | English</p>

---

ProxyLane gives selected Windows applications their own proxy settings without changing the system-wide proxy or installing a kernel driver. It uses user-mode process injection and network API hooks, and can pass proxy settings to child processes.

Core proxy features support **Windows XP through Windows 11**, with Win32 and x64 components.

It also helps inspect application traffic: view HTTP/1.1, HTTP/2 and HTTP/3 requests and responses, DNS and Raw/Hex data, decrypt HTTPS and QUIC v1, and save recordings for offline viewing. Select `NOPROXY` to monitor traffic without an external proxy.

## Usage Demo

![ProxyLane usage demo](demo.gif)

## Quick Start

1. Extract the entire release package, keeping the executables and DLLs together. On 64-bit Windows, use `ProxyLane64.exe`.
2. Under **Proxy Settings**, select or create a profile and enter the proxy type, server address, port and credentials.
3. Enable TCP proxying, UDP proxying and **Proxy child processes** as needed. Click **Test Current** to check the connection, then **Start Proxy**.
4. Under **Apps and Processes**, choose an app to launch, or drop an executable or shortcut into ProxyLane. To attach to a running app, select its process and click **Proxy Selected Processes**.
5. Check the runtime log for the result. Open **Traffic Monitor** to inspect connections and data.

Prefer launching applications through ProxyLane. Attaching to a running process may leave existing connections outside the proxy. For complete coverage, save your work, exit the application and launch it through ProxyLane again.

### Proxy Types and Rules

- **SOCKS5**: TCP and UDP; UDP requires server support.
- **HTTP10 / HTTP11**: TCP through HTTP CONNECT, without UDP proxying.
- **NOPROXY**: direct connections for monitoring and decryption without an external proxy. No server address or port is needed.
- **Child-process / target rules**: by default, all child processes (with **Proxy child processes** enabled) and all network destinations are proxied. To limit the scope, follow the matching examples in the interface.
- **Block UDP / Block IPv6**: restrict the corresponding traffic as needed. Blocking UDP takes priority over UDP proxying or capture.

### Proxy a Command-Line Workspace

Start the proxy with **Proxy child processes** enabled, then launch `cmd.exe` through ProxyLane. Alternatively, open a new Command Prompt, select its process and click **Proxy Selected Processes**.

Programs launched from that window, such as Git, Python, `pip` and `curl`, can inherit the proxy settings according to your child-process rules:

```bat
curl https://example.com
git clone https://github.com/example/project.git
pip install requests
python script.py
```

### Browsers Running in the Background

Edge and Chrome may keep running after their windows close. Launching them through ProxyLane can reuse an existing process, leaving traffic outside the proxy. When ProxyLane detects a possible case, it sends a tray notification. Click it to inspect the related processes and choose **End processes**, **Proxy processes** or **View related processes**.

Save your browser work and check the listed processes before ending them, then restart the browser through ProxyLane. Using **Proxy processes** directly may leave existing connections outside the proxy. Windows notification settings can affect whether the notification appears.

## Traffic Monitoring and Decryption

Monitoring and decryption require a supported **64-bit host**, which can handle both 32-bit and 64-bit target applications.

### Inspect Traffic

1. Start the proxy and hook the target application. For monitoring without an external proxy, select `NOPROXY` and enable TCP/UDP capture as needed. Disable **Block UDP** if you need UDP traffic.
2. Open **Traffic Monitor**, start monitoring, then make requests in the application.
3. Filter sessions by process and inspect requests, responses, bodies and DNS queries, or use Raw/HexView for raw data.

Ordinary traffic monitoring does not require a CA. Stopping monitoring stops new capture while existing connections keep forwarding.

### Decrypt HTTPS and QUIC

1. Open **Traffic Monitor → Decryption options** and enable HTTPS or QUIC decryption as needed.
2. Install the current-user CA when prompted, save the options and start monitoring.
3. Make the target application establish new connections. After changing QUIC decryption options, fully exit and restart the application.

HTTPS decryption is not limited to port 443. QUIC v1 support includes HTTP/3 and stream or datagram data from other supported protocols. Private trust stores, certificate pinning and unsupported protocols may prevent decryption; compatibility also varies by application version. QUIC 0-RTT forwarding, connection migration, WebTransport and CONNECT-UDP are not currently supported.

### Record and View Offline

Enable **Keep recording files** under **Traffic Monitor → Options → Recording options**, choose a directory, capacity and disk reserve, then start monitoring. The directory and limits are remembered, but recording must be enabled again after restarting ProxyLane. Capture stops when its capacity or disk-space limit is reached without deleting old data.

After stopping monitoring, choose **Options → View saved recording…** and open a recording directory. You can filter sessions and inspect requests, responses and Raw/Hex data without starting the proxy. Each directory includes a format guide for use with other tools or AI agents.

## Profile Management and Sharing

### Share One Proxy Profile

Choose **Actions ▾ → Copy full profile** on the settings page and send the complete `proxylane://profile/v1/…` line. The recipient copies it and selects **Actions ▾ → Paste profile** to fill the settings, then saves or starts the proxy. If the proxy is already running, click **Save & Apply** for the new settings to take effect.

The code includes current unsaved edits, username, **password and PSK**, network options and filtering rules. It is not encrypted, so share it only with trusted recipients. Global options, decryption settings, CA material, recordings and recent applications are not included.

### Import All Settings

Choose **Actions ▾ → Import all settings from file…** to import a `ProxyLane.ini` from another directory or version, including all profiles and recent application records stored in it.

First stop the proxy, tests and monitoring, and close applications hooked by this instance. After confirmation, ProxyLane backs up the current configuration, replaces the entire INI and restarts. Unsaved edits are lost. External files such as certificates and recordings must be moved separately.

The profile dropdown refreshes when opened to reflect changes made by other instances sharing the file. Refreshing preserves current edits.

## gonc TLS-PSK Secure Transport

For SOCKS5, HTTP10 or HTTP11, select `gonc TLS-PSK` under **Transport** and enter the remote gonc server address, port and matching PSK. No separate local gonc client is needed.

SOCKS5 supports encrypted TCP and UDP; HTTP10/HTTP11 support TCP only. To accept both SOCKS5 and HTTP on the same server port, enable `-http`, for example:

```bat
gonc -e ":s5s -u -http" -l -k -psk YOUR_PSK -tls 1083
```

Replace `YOUR_PSK` with your own key. TLS 1.3 is supported with TLS 1.2 server compatibility. The PSK is stored as plaintext in `ProxyLane.ini`, so keep the configuration file secure.

Settings live in `%APPDATA%\ProxyLane\ProxyLane.ini` by default, so upgrading or moving the program folder keeps them, and the latest 3 automatic backups sit in the `backups` folder next to it. If the program folder already contains `ProxyLane.ini` or `portable.flag`, settings stay in the program folder (portable mode).

## Compatibility and Interface Languages

- Core proxy features support Windows XP through Windows 11, with Win32 and x64 components.
- The 32-bit host and Windows XP / Server 2003 do not support traffic monitoring, decryption or gonc secure transport.
- A supported 64-bit host provides these features for 32-bit and 64-bit applications; hooking and decryption depend on application compatibility.
- Simplified Chinese and English are included. The default follows the system language; changes under **About & Language** take effect after restarting ProxyLane.

## Building

### Requirements

- Visual Studio 2019 with Desktop development with C++ and MFC components.
- Visual C++ `v141_xp` toolset and Windows 7.1A SDK for the application and Hook DLLs.
- `v142` toolset and Windows 10 SDK for the test project.
- Rust MSVC toolchain, with `rustup` and `cargo` on PATH. The MITM build uses pinned version `1.88.0`.

Prepare the Rust toolchain from the repository root:

```powershell
rustup toolchain install 1.88.0-x86_64-pc-windows-msvc
rustup target add x86_64-pc-windows-msvc
```

### Build the Application

Open `src/ProxyLane.sln`, select `Release`, and build both `Win32` and `x64`. Alternatively, run these commands from the repository root in a Visual Studio Developer PowerShell:

```powershell
msbuild .\src\ProxyLane.sln /m /p:Configuration=Release /p:Platform=Win32
msbuild .\src\ProxyLane.sln /m /p:Configuration=Release /p:Platform=x64
```

The application and runtime DLLs are written to `bin/`. The x64 Release post-build step invokes the Rust scripts to build secure transport and MITM components. The first build downloads dependencies and takes longer.

### Build Rust Components Separately

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build-secure-transport.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\build-mitm.ps1
```

These produce `bin/ProxyLaneSecureTransport64.dll` and `bin/ProxyLaneMitm64.dll`. The MITM script also writes a command-line helper to `build/tools/`. `src\build-secure-transport.bat` is a shortcut for the secure-transport script and builds only the 64-bit secure-transport DLL.

### Tests and Translation Checks

```powershell
powershell -ExecutionPolicy Bypass -File .\tests\run-tests.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\check-locales.ps1
```

The test script builds and runs Win32/x64 unit tests. Translations are in `src/ProxyLane/locales/zh-CN.json` and `en-US.json`; both must contain the same keys. Rebuild the application after editing them. Language resources are embedded in the EXE and need no separate distribution.

## Packaging a Release

After building both Win32/x64 Release configurations and the two Rust DLLs, run from the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\package-release.ps1
```

The script checks that the application and Hook DLL versions match, creates `dist/ProxyLane-version-Windows.zip`, and reports its SHA-256. Use `-OutputDirectory D:\releases` to choose another output directory.

The package includes both application architectures and Hook DLLs, the 64-bit secure-transport and MITM DLLs, both README files, and a `LICENSE` containing third-party notices. The package contains no configuration file, so extracting an upgrade over an existing install leaves your settings untouched. Test executables and command-line helpers are excluded.

## Project Structure

| Directory | Contents |
| --- | --- |
| `src/ProxyLane` | MFC desktop UI and application logic |
| `src/ProxyLaneHook`, `src/remotecode` | Process injection and network hooks |
| `src/ProxyLaneSecureTransport` | Encrypted proxy transport |
| `src/ProxyLaneMitm`, `src/ProxyLaneProtocol` | Traffic decryption and protocol parsing |
| `tests` | Automated tests and test tools |
| `examples` | Sample configuration |
| `scripts` | Build, validation and packaging scripts |
