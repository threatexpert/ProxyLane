# Building a fork and producing release packages

[简体中文](BUILDING.md)

Use `scripts/build-release.ps1` as the standard entry point. It discovers VS 2019, checks prerequisites, builds incrementally, runs Win32/x64 unit tests, checks Hook static TLS and locale catalogs, and optionally packages releases.

## 1. Install prerequisites once

The build environment is **Windows 10/11 x64 with Visual Studio 2019 16.11**. ARM64 binaries are also cross-compiled on this host.

1. Install VS 2019 or Build Tools 2019 with the Desktop development with C++ workload (C++ build tools in Build Tools). In Visual Studio Installer, select **More → Import configuration** for the 2019 instance. Import [`vs2019-intel.vsconfig`](../vs2019-intel.vsconfig) for Intel-only builds, or [`.vsconfig`](../.vsconfig) for builds including ARM64. Both files are in the repository root.
2. Install Git for Windows, Python 3.8+ and Rustup. Ensure `git`, `python`, `rustup`, `cargo` and Windows `tar.exe` work in a new PowerShell.
3. Install CMake 3.15+ on PATH, or use the VS CMake component; the standard entry point discovers the bundled CMake automatically. Versions 4.0.1 and 4.4.4 have passed builds.
4. For ARM64, install LLVM/Clang using the instructions below. Intel-only builds do not require it.

| VS components | Purpose |
| --- | --- |
| v141 x86/x64 tools, v141 ATL/MFC, C++ Windows XP support | Intel application and Hooks; XP support supplies v141_xp and Windows 7.1A SDK |
| v142 x86/x64 tools, Windows 10 SDK (baseline 10.0.19041) | Tests, SSH backend and Rust linking |
| v142 ARM64 tools, ARM64 ATL/MFC, Windows 10 SDK ARM64 libraries | Native ARM64 products and probes |

ARM packages also need Intel tools for the companion Hooks. Do not retarget projects or remove XP compatibility options to work around missing components.

### Developing and releasing only Intel products on x64 Windows

If you target ordinary x64 Windows without ARM64, select **`-Architecture x86-x64` (the default)** and import `vs2019-intel.vsconfig`. You do not need the full `.vsconfig` containing ARM64 components.

| Dependency | Intel-only package | Additional ARM64 package |
| --- | --- | --- |
| VS 2019, MSBuild, v141 x86/x64, v141 ATL/MFC, XP support / Windows 7.1A SDK | Required | Also required |
| v142 x86/x64, Windows 10 SDK, CMake, Git, Python, tar | Required | Also required |
| Rust 1.88.0 MSVC toolchain and `x86_64-pc-windows-msvc` target | Required | Also required |
| v142 ARM64, ARM64 ATL/MFC, SDK ARM64 libraries | No separate installation needed | Required |
| Rust `aarch64-pc-windows-msvc` target | Not needed | Required |
| LLVM/Clang, `-ClangBinDirectory`, ARM64 bootstrap check | Not needed | Required |

**The standard Intel release contains both x86 and x64 products**, so its full build/package still requires x86 tools even when users only run x64 Windows. It is not a pure x64 package. Projects still use `v141_xp`, so targeting only Windows 10/11 does not make the XP tool components optional. Neither an XP operating system nor an ARM64 runtime environment is required to compile.

After installing the Intel dependencies above and the x64 Rust target, run in ordinary PowerShell:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Architecture x86-x64 -CheckEnvironmentOnly
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Architecture x86-x64 -Package
```

This mode does not invoke the ARM64 build script, check Clang/ARM64 tools or download the ARM64 Rust target. Products go to `bin/`; only `dist/ProxyLane-version-Windows.zip` and its checksum are produced. Omit `-Package` to build and run basic checks without packaging.

Official downloads: [older Visual Studio versions](https://visualstudio.microsoft.com/vs/older-downloads/), [Git](https://git-scm.com/downloads/win), [Python](https://www.python.org/downloads/windows/), [Rustup](https://rustup.rs/), [CMake](https://cmake.org/download/), [LLVM](https://github.com/llvm/llvm-project/releases). Component IDs are listed in [Microsoft's VS 2019 catalog](https://github.com/MicrosoftDocs/visualstudio-docs/blob/main/docs/install/includes/vs-2019/workload-component-id-vs-community.md).

Install the pinned Rust toolchain without changing your global default:

```powershell
rustup toolchain install 1.88.0-x86_64-pc-windows-msvc --profile minimal
rustup target add x86_64-pc-windows-msvc --toolchain 1.88.0-x86_64-pc-windows-msvc
# Also needed for ARM64
rustup target add aarch64-pc-windows-msvc --toolchain 1.88.0-x86_64-pc-windows-msvc
```

Both secure transport and MITM use this version and the repository's Cargo.lock files (`--locked`).

### Installing Clang for ARM64 builds

On the **x64 Windows build host** described above, install Windows **x64** LLVM/Clang. This compiler can generate ARM64 target code; you do not need a compiler executable for an ARM64 host. Clang handles the ARM64 bootstrap assembly and `ring` C/assembly dependencies. MSVC still builds the application's and Hook's C++ code, so Clang does not replace the VS ARM64 tools or SDK.

1. Open the [official LLVM 18.1.8 release](https://github.com/llvm/llvm-project/releases/tag/llvmorg-18.1.8) and download **`LLVM-18.1.8-win64.exe`** from Assets ([direct download](https://github.com/llvm/llvm-project/releases/download/llvmorg-18.1.8/LLVM-18.1.8-win64.exe)). This version has passed all-architecture builds, bootstrap byte verification and packaging checks.
2. Run the installer and retain the default `C:\Program Files\LLVM` directory. Optionally enable its PATH setting to invoke `clang` directly, then open a new PowerShell. **The standard build entry also discovers the default directory without a PATH change.**
3. Run these checks from the repository root. The bootstrap check compiles a small ARM64 assembly file in a temporary directory and compares the result with committed bytes; `--check` does not edit sources:

```powershell
& 'C:\Program Files\LLVM\bin\clang.exe' --version
python scripts/generate-arm64-bootstrap.py --clang 'C:\Program Files\LLVM\bin\clang.exe' --check
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Architecture All -CheckEnvironmentOnly -ClangBinDirectory 'C:\Program Files\LLVM\bin'
```

After these checks pass, run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Architecture All -Package -ClangBinDirectory 'C:\Program Files\LLVM\bin'
```

For custom paths or multiple Clang installations, use `-ClangBinDirectory` to select the **bin directory containing clang.exe**, for example:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Architecture All -Package -ClangBinDirectory 'C:\tools\llvm\bin'
```

Android NDK also includes Clang and can be used as an alternative. Clang 18.0.3 from NDK 27.2 has passed builds; pass the NDK's `toolchains\llvm\prebuilt\windows-x86_64\bin` directory to `-ClangBinDirectory`.

## 2. Clone and check the environment

Use `git clone` to clone your fork to a short path such as `C:\src\ProxyLane` to avoid long VS/CMake output paths. Run the following from the repository root in ordinary PowerShell, without administrator privileges:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1 -CheckEnvironmentOnly
# Discover LLVM on PATH or in its default installation directory
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Architecture All -CheckEnvironmentOnly
```

Preflight only checks the environment and reports missing prerequisites together. It checks targets in the pinned Rust toolchain: Intel needs `x86_64-pc-windows-msvc`; ARM64/All also need `aarch64-pc-windows-msvc`. Missing targets produce the corresponding `rustup target add ... --toolchain ...` commands.

## 3. Build, check and package

```powershell
# Intel Release to bin, including basic checks
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1
# Intel package to dist
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Package
# All architectures, two packages
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Architecture All -Package
# ARM package only; still builds Intel components and runs Intel unit tests
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Architecture ARM64 -Package
```

Use `-OutputDirectory C:\releases` for another ZIP destination. Builds preserve caches and do not run Clean/Rebuild. Packaging replaces same-version ZIP/checksum files in that destination; use another directory to retain old packages. Do not run concurrent builds in one checkout. A failed build/check stops packaging. Without `-Package`, no ZIP is created.

| Output | Location |
| --- | --- |
| Intel products | `bin/`: both hosts, Hook32/64 and x64 backends |
| ARM64 products | `bin/ARM64/Release/`: native host, Hook, secure transport, MITM and SSH |
| Intel package | `dist/ProxyLane-version-Windows.zip` |
| ARM64 package | `dist/ProxyLane-version-Windows-ARM64.zip` |
| Checksums | `.zip.sha256` beside each ZIP |
| Build logs and record | `build/release/timestamp-id/`: `build.log`, platform logs, `build-info.json` |
| ARM build details and architecture/hash manifest | `build/qa/arm64-build/Release/` |

Both packages contain the root `README.md`, `README_EN.md` and combined `LICENSE`. The ARM package also includes matching Hook32/64, without Intel hosts/backends. Packaging checks PE machine types, consistent product versions and Intel Hook static TLS. Configuration, keys, probes, symbols and CA command-line tools are excluded.

Basic checks are not full feature acceptance. The standard entry runs Intel unit tests; ARM builds compile probes and check PE/bootstrap bytes without running ARM programs on x64. For a separate Intel desktop smoke test, extract a package, create an empty `portable.flag` there to isolate it from daily settings, then run `tests/run-startup-smoke.ps1 -BinaryDirectory <directory>`. ARM device cross-architecture, SSH, MITM and UAC checks, and XP dynamic loading need separate validation; see [ARM64 acceptance notes](README_ARM64.md).

## 4. Downloads and caches

First builds need access to Rust toolchain/crate servers, nuget.org and libssh2.org. OpenSSL 3.5.9's precompiled package (about 128 MiB) and libssh2 1.11.1 sources are checked against pinned SHA-256 hashes; patches are in the repository. No separate OpenSSL, Perl, NASM, NuGet or .NET SDK installation is needed.

You can preseed `build/deps/openssl-native.3.5.9.nupkg` and `build/deps/libssh2-1.11.1.tar.gz`. Fully offline builds also need Rust toolchains, target standard libraries and Cargo dependency caches. Normal reruns reuse `build/deps`, Rust `target` directories and C++ object caches.

### Cache locations and cleanup effects

Caches are retained by default. The following is a reference for deliberate space recovery. Stop builds and processes using products first, and preserve any logs, configuration or test evidence you need.

| Location | Contents and effect of deletion |
| --- | --- |
| `src/ProxyLaneMitm/target/`, `src/ProxyLaneSecureTransport/target/` | Rebuildable Rust outputs. Keeping user Cargo caches normally avoids downloading crates again |
| `src/ProxyLaneProtocol/target/` | Created by standalone protocol builds or DoH Rust tests; rebuildable |
| `build/ProxyLane/`, `build/ProxyLaneHook/`, `tests/obj/` | Rebuildable C++ intermediate files; deleting them does not trigger Rust crate downloads |
| `build/deps/` | SSH archives, extracted sources and CMake caches. Deleting everything downloads OpenSSL/libssh2 again and rebuilds; retaining the two archives while removing generated directories avoids those downloads |
| `build/release/`, `build/qa/`, other test output directories | Logs, acceptance records, probes or test fixtures. Delete only when no longer needed; subsequent builds do not restore historical logs |
| `build/test-venv/` | Python test environment created below; deletion requires recreating it and reinstalling test dependencies |
| `bin/`, `dist/` | Products and release packages, not just caches. Rebuilding/repackaging restores products, but preserve any user-created configuration, certificates or keys in `bin` first |
| `%USERPROFILE%\.cargo/registry/`, `.cargo/git/` | User Cargo download caches, overridden by `CARGO_HOME`. Deletion affects other Rust projects and triggers downloads; not routine project cleanup |

Rust toolchains and target standard libraries normally live in `%USERPROFILE%\.rustup/` (overridden by `RUSTUP_HOME`). Keep them and manage components with `rustup`; they are not project build caches.

## 5. Full regression entry points

Standard builds run basic checks; release acceptance requires selecting additional feature tests below. First finish a Release build, then run from the repository root on an interactive Windows desktop. Most scripts compile probes and use DLLs/import libraries under `bin`, so an extracted release ZIP alone cannot replace the source build tree. Run desktop/UI tests in an unlocked desktop session. Avoid parallel tests or a daily ProxyLane instance intercepting test processes.

SSH and DoH connectivity fixtures require **Paramiko >= 3.5** and `cryptography`; Detours/cross-architecture tests also use `psutil`. These are listed in [`tests/requirements-regression.txt`](../tests/requirements-regression.txt). They are test dependencies, not product build dependencies. Use an isolated environment; this PATH change affects only the current terminal and its children:

```powershell
python -m venv build/test-venv
& .\build\test-venv\Scripts\python.exe -m pip install -r tests/requirements-regression.txt
$env:PATH = "$PWD\build\test-venv\Scripts;$env:PATH"
powershell -NoProfile -ExecutionPolicy Bypass -File tests/run-ssh-transport-tests.ps1 -Full
powershell -NoProfile -ExecutionPolicy Bypass -File tests/run-doh-connectivity-tests.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File tests/run-chain-ui-tests.ps1
```

All scripts below are under `tests/`; invoke with `powershell -NoProfile -ExecutionPolicy Bypass -File tests/<script>`. Suggested time allowances exclude initial product compilation and downloads. Unless specified, only the standard build tools and local loopback networking are needed.

| Script/arguments | Coverage and additional prerequisites | Allow |
| --- | --- | --- |
| `run-tests.ps1` | Win32/x64 unit tests; already run by standard builds | 1–5 min |
| `run-startup-smoke.ps1 -BinaryDirectory <extracted directory>` | Desktop startup; create an empty `portable.flag` there first. Defaults to 2 architectures × 2 runs × 10 seconds of observation | 1–2 min |
| `run-ssh-transport-tests.ps1 -Full` | SSH, chains, keys and session timeouts; Python requirements. Full includes minute-long real waits | 5–10 min |
| `run-doh-tests.ps1` | DNS codec and DoH Rust unit tests; first run also compiles Rust test outputs | 1–5 min, extra for cold caches |
| `run-doh-tests.ps1 -Online` | Adds real DoH/TLS and proxy chains; access to the selected DoH service required | 2–10 min |
| `run-doh-cache-tests.ps1`, `run-doh-deadline-tests.ps1` | Local cache and deadline/cancellation tests | 1–5 min each |
| `run-doh-connectivity-tests.ps1` | Local failure/connectivity cases with SSH fixtures; Python requirements. Add `-Online` for remote-service cases | 2–10 min |
| `run-dns-relay-tests.ps1 -Online` | Rust tests and application DNS → DoH relay; internet required, replies retain the actual local relay source address | 2–10 min |
| `run-proxy-chain-tests.ps1`, `run-socket-transport-tests.ps1`, `run-bypass-transport-tests.ps1` | Chains, asynchronous sockets and direct transport | 1–5 min each |
| `run-chain-ui-tests.ps1` | Real chain page start/cancel/failure recovery; creates an isolated portable copy, no extra Python packages | 1–2 min |
| `run-config-storage-tests.ps1`, `run-hook-failure-diagnostics.ps1` | Configuration storage and Hook failure diagnostics | 1–5 min each |
| `run-ipv6-proxy-tester-tests.ps1`, `run-udp-send-hook-tests.ps1` | IPv6 proxy testing and UDP send paths; local protocol-stack support required for relevant cases | 1–5 min each |
| `run-detours-tests.ps1` | Injection, statistics, child processes, rebind and IPv6/DNS; also needs Go on PATH and Python requirements; incrementally builds products | 5–15 min |
| `run-cross-architecture-tests.ps1` | Builds three probe architectures and runs the injection matrix supported by the current host; needs ARM64 build tools and Python requirements. `-BuildOnly` compiles only | 5–15 min |

Online scripts accept `-DohUrl <HTTPS URL> -Bootstrap <IP>` to change services; the values must match. ARM64 SSH uses `run-ssh-transport-tests.ps1 -Platform ARM64 -Full` and requires Windows ARM64 hardware plus probes from the ARM build output (not included in release ZIPs). For the complete ARM matrix and UAC/privilege cases see [ARM64 acceptance notes](README_ARM64.md) and the [assessment/test record](windows-arm64-assessment.md). MITM, protocol and other E2E dependencies are documented in the [E2E guide](../tests/e2e/README.md). XP Hook dynamic loading still needs separate device testing.

The preflight's own regression entry is `powershell -NoProfile -ExecutionPolicy Bypass -File tests/BuildPreflightTests.ps1`; it simulates missing Rust components without installing or removing real toolchains.

## 6. Troubleshooting and individual scripts

### Known build warnings

| Warning | Meaning and handling |
| --- | --- |
| MSB8051 | XP support in `v141_xp` is deprecated. The project retains it for XP compatibility; do not retarget because of this warning |
| MSB8012 | Some Intel projects have mismatched `TargetPath` and linker `OutputFile` settings; check output paths and packaged products |
| C4244 | A conversion may lose data; check value ranges and truncation at the reported code location |

Build logs are under `build/release/`.

| Problem | Action |
| --- | --- |
| Missing v141_xp, afxwin.h or MFC libraries | Add XP support and v141 ATL/MFC in VS 2019 Installer; ARM64 needs its own v142 ATL/MFC |
| Missing Clang or bootstrap byte mismatch | Specify the correct Clang directory; use the validated version, without bypassing checks |
| Missing Rust toolchain | Run the installation command above and reopen the terminal |
| Missing Rust target | Run the reported `rustup target add ... --toolchain 1.88.0-x86_64-pc-windows-msvc`; Intel does not need the ARM64 target |
| CMake/compiler path too long | Use a shorter checkout path; do not transplant build directories from another location |
| Download/checksum failure | Check network/proxy/cache files and replace corrupt downloads at the reported path; retain hash checks |
| DLL/EXE locked | Exit applications and test processes loading products from that bin directory, then retry |

Individual entry points remain: Win32/x64 Release in `src/ProxyLane.sln`, Release/Debug in `scripts/build-arm64.ps1`, and `build-ssh.ps1`, `build-secure-transport.ps1`, `build-mitm.ps1`. For packaging only, use `scripts/package-release.ps1`, adding `-Architecture ARM64` (or use `package-arm64.ps1`). Packaging alone does not compile; the caller must ensure binaries match current sources.
