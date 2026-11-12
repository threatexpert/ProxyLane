# Building a fork and producing release packages

[简体中文](BUILDING.md)

Use `scripts/build-release.ps1` as the standard entry point. It discovers VS 2019, checks prerequisites, builds incrementally, runs Win32/x64 unit tests, checks Hook static TLS and locale catalogs, and optionally packages releases. It does not depend on maintainer-specific paths, prebuilt `bin`/`build` directories or sibling repositories.

## 1. Install prerequisites once

The validated build host is **Windows 10/11 x64 with Visual Studio 2019 16.11**. ARM64 binaries are cross-compiled on this host; building on an ARM64 host or with VS 2022 has not been validated.

1. Install VS 2019 or Build Tools 2019 with the Desktop development with C++ workload (C++ build tools in Build Tools). In Visual Studio Installer, select **More → Import configuration** for the 2019 instance and import the repository [`.vsconfig`](../.vsconfig) to add the individual components for all architectures.
2. Install Git for Windows, Python 3.8+ and Rustup. Ensure `git`, `python`, `rustup`, `cargo` and Windows `tar.exe` work in a new PowerShell. The Python Microsoft Store placeholder is not an interpreter.
3. Install CMake 3.15+ on PATH, or use the VS CMake component; the standard entry point discovers the bundled CMake automatically.
4. For ARM64, install LLVM/Clang using the instructions below. Intel-only builds do not require it. Android NDK is not a project build dependency.

| VS components | Purpose |
| --- | --- |
| v141 x86/x64 tools, v141 ATL/MFC, C++ Windows XP support | Intel application and Hooks; XP support supplies v141_xp and Windows 7.1A SDK |
| v142 x86/x64 tools, Windows 10 SDK (baseline 10.0.19041) | Tests, SSH backend and Rust linking |
| v142 ARM64 tools, ARM64 ATL/MFC, Windows 10 SDK ARM64 libraries | Native ARM64 products and probes |

ARM packages also need Intel tools for the companion Hooks. Do not retarget projects or remove XP compatibility options to work around missing components.

Official downloads: [older Visual Studio versions](https://visualstudio.microsoft.com/vs/older-downloads/), [Git](https://git-scm.com/downloads/win), [Python](https://www.python.org/downloads/windows/), [Rustup](https://rustup.rs/), [CMake](https://cmake.org/download/), [LLVM](https://github.com/llvm/llvm-project/releases). Component IDs follow [Microsoft's VS 2019 catalog](https://github.com/MicrosoftDocs/visualstudio-docs/blob/main/docs/install/includes/vs-2019/workload-component-id-vs-community.md). Historical installer availability and access requirements are controlled by the providers.

Install the pinned Rust toolchain without changing your global default:

```powershell
rustup toolchain install 1.88.0-x86_64-pc-windows-msvc --profile minimal
rustup target add x86_64-pc-windows-msvc --toolchain 1.88.0-x86_64-pc-windows-msvc
# Also needed for ARM64
rustup target add aarch64-pc-windows-msvc --toolchain 1.88.0-x86_64-pc-windows-msvc
```

Both secure transport and MITM explicitly use this version and committed Cargo.lock files (`--locked`). MSVC, SDK and Clang versions are not fully pinned, so byte-identical builds across machines are not promised.

### Installing Clang for ARM64 builds

On the **x64 Windows build host** described above, install Windows **x64** LLVM/Clang. This compiler can generate ARM64 target code; you do not need a compiler executable for an ARM64 host. Clang handles the ARM64 bootstrap assembly and `ring` C/assembly dependencies. MSVC still builds the application's and Hook's C++ code, so Clang does not replace the VS ARM64 tools or SDK.

1. Open the [official LLVM 18.1.8 release](https://github.com/llvm/llvm-project/releases/tag/llvmorg-18.1.8) and download **`LLVM-18.1.8-win64.exe`** from Assets ([direct download](https://github.com/llvm/llvm-project/releases/download/llvmorg-18.1.8/LLVM-18.1.8-win64.exe)). This is a concrete standalone installation example; Android Studio and NDK are not required.
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

For a custom installation, pass the **bin directory containing clang.exe**, not the EXE path. An explicit directory also avoids selecting a different Clang earlier on PATH when several versions are installed.

Validation scope: the complete project build has been exercised with **Clang 18.0.3 from Android NDK 27.2**, targeting `aarch64-pc-windows-msvc` to produce Windows binaries. The official **18.1.8 standalone installer URL has been verified, but that distribution has not yet completed the project's full build acceptance run**. It must not be described as the same validated toolchain. Retain the bootstrap check and complete the full architecture build with standalone versions; do not bypass failures. If NDK is already installed, pass its `toolchains\llvm\prebuilt\windows-x86_64\bin` directory instead; no second installation is necessary.

## 2. Clone and check the environment

Clone your fork to a short path such as `C:\src\ProxyLane` to avoid legacy VS/CMake nested-path limits. A normal clone is sufficient; product builds need no submodules or uncommitted maintainer files. Run the following from the repository root in ordinary PowerShell, without administrator privileges or a Developer PowerShell:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1 -CheckEnvironmentOnly
# Omit the Clang path if it is on PATH or installed in the default location
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Architecture All -CheckEnvironmentOnly -ClangBinDirectory 'C:\tools\llvm\bin'
```

Preflight performs no builds, downloads or system installations. Missing prerequisites are reported together with a nonzero exit code. It checks basic local prerequisites, not network reachability or compatibility of every third-party version.

## 3. Build, check and package

```powershell
# Intel Release to bin, including basic checks
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1
# Intel package to dist
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Package
# All architectures, two packages
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Architecture All -Package -ClangBinDirectory 'C:\tools\llvm\bin'
# ARM package only; still builds Intel components and runs Intel unit tests
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Architecture ARM64 -Package -ClangBinDirectory 'C:\tools\llvm\bin'
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

First builds need access to Rust toolchain/crate servers, nuget.org and libssh2.org. OpenSSL 3.5.9's precompiled package (about 128 MiB) and libssh2 1.11.1 sources are checked against pinned SHA-256 hashes; patches are in the repository. No separate OpenSSL, Perl, NASM, NuGet or .NET SDK installation is needed. Dependency/toolchain/lockfile updates should be explicit reviewed changes.

You can preseed `build/deps/openssl-native.3.5.9.nupkg` and `build/deps/libssh2-1.11.1.tar.gz`. Fully offline builds also need Rust toolchains, target standard libraries and Cargo dependency caches. Normal reruns reuse `build/deps`, Rust `target` directories and C++ object caches.

## 5. Troubleshooting and individual scripts

| Problem | Action |
| --- | --- |
| Missing v141_xp, afxwin.h or MFC libraries | Add XP support and v141 ATL/MFC in VS 2019 Installer; ARM64 needs its own v142 ATL/MFC |
| Missing Clang or bootstrap byte mismatch | Specify the correct Clang directory; use the validated version, without bypassing checks |
| Missing Rust toolchain | Run the installation command above and reopen the terminal |
| CMake/compiler path too long | Use a shorter checkout path; do not transplant build directories from another location |
| Download/checksum failure | Check network/proxy/cache files and replace corrupt downloads at the reported path; retain hash checks |
| DLL/EXE locked | Exit applications and test processes loading products from that bin directory, then retry |

Individual entry points remain: Win32/x64 Release in `src/ProxyLane.sln`, Release/Debug in `scripts/build-arm64.ps1`, and `build-ssh.ps1`, `build-secure-transport.ps1`, `build-mitm.ps1`. For packaging only, use `scripts/package-release.ps1`, adding `-Architecture ARM64` (or use `package-arm64.ps1`). Packaging alone does not compile; the caller must ensure binaries match current sources.

The automated path covers a configured build host. A clean Windows VM/CI installation-and-build acceptance run has not yet been established; local incremental checks must not be reported as clean-machine validation.
