# 从 fork 到发布包

[English](BUILDING_EN.md)

标准构建入口是 `scripts/build-release.ps1`。它自动定位 VS 2019、检查依赖、增量编译、运行 Win32/x64 单元测试、检查 Hook 静态 TLS 和语言资源，可选生成发布包。

## 1. 准备构建机（一次）

构建环境为 **Windows 10/11 x64 + Visual Studio 2019 16.11**，ARM64 版本也在此环境交叉编译。

1. 安装 VS 2019 或 Build Tools 2019，选择“使用 C++ 的桌面开发”（Build Tools 中为 C++ 生成工具）。在 Visual Studio Installer 中对 2019 实例选择“更多 → 导入配置”：只构建 Intel 版本导入 [`vs2019-intel.vsconfig`](../vs2019-intel.vsconfig)；包含 ARM64 的构建导入 [`.vsconfig`](../.vsconfig)。两份清单均位于仓库根目录。
2. 安装 Git for Windows、Python 3.8+、Rustup，确保 `git`、`python`、`rustup`、`cargo` 能从新开的 PowerShell 运行，Windows 自带的 `tar.exe` 也需可用。
3. 安装 CMake 3.15+ 并加入 PATH；也可使用上述 VS 配置提供的 CMake，统一入口会自动定位它。已通过构建的版本包括 4.0.1、4.4.4。
4. 构建 ARM64 时安装 LLVM/Clang，具体操作见下面的“安装 Clang”。只构建 Intel 包不需要安装它。

| VS 组件 | 用途 |
| --- | --- |
| v141 x86/x64 工具、v141 ATL/MFC、C++ Windows XP 支持 | Intel 主程序和 Hook；XP 支持组件提供 v141_xp / Windows 7.1A SDK |
| v142 x86/x64 工具、Windows 10 SDK（基线 10.0.19041） | 单元测试、SSH 后端和 Rust 链接 |
| v142 ARM64 工具、ARM64 ATL/MFC、Windows 10 SDK ARM64 库 | ARM64 原生主程序、Hook、后端和探针 |

ARM 包也需要 Intel 工具：它包含 Hook32/64 以支持仿真进程。不要为解决缺依赖而把项目重定向到其他工具集，或移除 XP 兼容选项。

### 只在 x64 Windows 上开发和发布 Intel 版本

如果目标是普通 x64 Windows，不考虑 ARM64，请选择 **`-Architecture x86-x64`（默认值）**，使用 `vs2019-intel.vsconfig`，无需导入包含 ARM64 组件的全量 `.vsconfig`。

| 依赖 | 只构建 Intel 包 | 额外构建 ARM64 包 |
| --- | --- | --- |
| VS 2019、MSBuild、v141 x86/x64、v141 ATL/MFC、XP 支持 / Windows 7.1A SDK | 需要 | 同样需要 |
| v142 x86/x64、Windows 10 SDK、CMake、Git、Python、tar | 需要 | 同样需要 |
| Rust 1.88.0 MSVC 工具链及 `x86_64-pc-windows-msvc` 目标 | 需要 | 同样需要 |
| v142 ARM64、ARM64 ATL/MFC、SDK ARM64 库 | 不需要单独安装 | 需要 |
| Rust `aarch64-pc-windows-msvc` 目标 | 不需要 | 需要 |
| LLVM/Clang、`-ClangBinDirectory` 参数、ARM64 引导代码检查 | 不需要 | 需要 |

**当前标准 Intel 发布包同时包含 x86 和 x64 产品**，所以即使使用者只运行 x64 Windows，完整构建打包仍需 x86 工具。它不是纯 x64 单架构包。项目仍使用 `v141_xp`，因此仅面向 Windows 10/11 也不能直接省略 XP 工具组件；无需安装 XP 操作系统或 ARM64 运行环境来编译。

只安装上表 Intel 所需依赖和 x64 Rust 目标后，在普通 PowerShell 执行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Architecture x86-x64 -CheckEnvironmentOnly
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Architecture x86-x64 -Package
```

该模式不会调用 ARM64 构建脚本，不检查 Clang 或 ARM64 工具，不下载 ARM64 Rust 目标。产物写入 `bin/`，只生成 `dist/ProxyLane-版本-Windows.zip` 和对应校验文件。省略 `-Package` 可只编译并运行基础检查。

依赖安装入口：[VS 历史版本](https://visualstudio.microsoft.com/vs/older-downloads/)、[Git](https://git-scm.com/downloads/win)、[Python](https://www.python.org/downloads/windows/)、[Rustup](https://rustup.rs/)、[CMake](https://cmake.org/download/)、[LLVM](https://github.com/llvm/llvm-project/releases)。VS 组件 ID 见 [Microsoft 的 VS 2019 清单](https://github.com/MicrosoftDocs/visualstudio-docs/blob/main/docs/install/includes/vs-2019/workload-component-id-vs-community.md)。

在普通 PowerShell 中安装固定 Rust 工具链，无需更改全局默认版本：

```powershell
rustup toolchain install 1.88.0-x86_64-pc-windows-msvc --profile minimal
rustup target add x86_64-pc-windows-msvc --toolchain 1.88.0-x86_64-pc-windows-msvc
# 构建 ARM64 时另外执行
rustup target add aarch64-pc-windows-msvc --toolchain 1.88.0-x86_64-pc-windows-msvc
```

安全传输和 MITM 后端都使用该版本及仓库中的 Cargo.lock（`--locked`）。

### 安装 Clang（构建 ARM64 时需要）

在上述 **x64 Windows 构建机**上，安装的是 Windows **x64 版** LLVM/Clang。同一个编译器可以生成 ARM64 目标代码；无需下载运行在 ARM64 主机上的编译器。Clang 用于 ARM64 引导汇编和 `ring` 的 C/汇编依赖，主程序和 Hook 的 C++ 部分仍使用 MSVC，因此它不能替代前面的 VS ARM64 工具和 SDK。

1. 打开 [LLVM 18.1.8 官方发布页](https://github.com/llvm/llvm-project/releases/tag/llvmorg-18.1.8)，在 Assets 中下载 **`LLVM-18.1.8-win64.exe`**（[直接下载](https://github.com/llvm/llvm-project/releases/download/llvmorg-18.1.8/LLVM-18.1.8-win64.exe)）。该版本已通过全架构构建、引导字节校验和打包检查。
2. 运行安装器，保留默认安装目录 `C:\Program Files\LLVM`。如需从命令行直接运行 `clang`，可以选择安装器的加入 PATH 选项，完成后重开 PowerShell。**统一构建入口也能自动找到默认目录，不加 PATH 同样可用。**
3. 从仓库根目录执行以下验证。引导检查会在临时目录编译一小段 ARM64 汇编，并与提交的字节比较；`--check` 不修改源码：

```powershell
& 'C:\Program Files\LLVM\bin\clang.exe' --version
python scripts/generate-arm64-bootstrap.py --clang 'C:\Program Files\LLVM\bin\clang.exe' --check
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Architecture All -CheckEnvironmentOnly -ClangBinDirectory 'C:\Program Files\LLVM\bin'
```

确认检查通过后，运行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Architecture All -Package -ClangBinDirectory 'C:\Program Files\LLVM\bin'
```

自定义安装路径或安装了多个 Clang 时，用 `-ClangBinDirectory` 指定包含 `clang.exe` 的 **bin 目录**，例如：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Architecture All -Package -ClangBinDirectory 'C:\tools\llvm\bin'
```

Android NDK 也附带 Clang，可作为备选。NDK 27.2 中的 Clang 18.0.3 已通过构建；使用时将 NDK 下的 `toolchains\llvm\prebuilt\windows-x86_64\bin` 目录传给 `-ClangBinDirectory`。

## 2. 克隆并检查环境

用 `git clone` 将自己的 fork 克隆到较短路径，例如 `C:\src\ProxyLane`，避免 VS/CMake 的嵌套输出路径过长。以下命令在仓库根目录的普通 PowerShell 中执行，无需管理员权限：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1 -CheckEnvironmentOnly
# 全架构预检；自动发现 PATH 或默认目录中的 LLVM
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Architecture All -CheckEnvironmentOnly
```

预检只检查环境，缺少依赖时汇总报错。Rust target 按固定工具链检查：Intel 需要 `x86_64-pc-windows-msvc`，ARM64/All 还需要 `aarch64-pc-windows-msvc`；缺失时给出对应的 `rustup target add ... --toolchain ...` 命令。

## 3. 编译、验证、打包

```powershell
# Intel Release：编译到 bin 并运行基础检查
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1
# Intel Release 并打包到 dist
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Package
# 全架构 Release，并生成两份包
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Architecture All -Package
# 只生成 ARM 包（仍构建 Intel 组件并运行 Intel 单元测试）
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Architecture ARM64 -Package
```

`-OutputDirectory C:\releases` 可更改 ZIP 输出目录。默认保留编译缓存，不运行 Clean/Rebuild。重复打包会替换输出目录中同版本的 ZIP 和 `.sha256`；要保留旧包请指定另一个目录。不要在同一 checkout 同时启动多个构建。构建错误或检查失败会停止流程，不继续打包；未启用 `-Package` 时不创建 ZIP。

| 产物 | 路径 |
| --- | --- |
| Intel 产品 | `bin/ProxyLane.exe`、`ProxyLane64.exe`、Hook32/64 及 x64 后端 |
| ARM64 产品 | `bin/ARM64/Release/`，包含 ARM64 宿主、Hook、安全传输、MITM、SSH |
| Intel ZIP | `dist/ProxyLane-版本-Windows.zip` |
| ARM64 ZIP | `dist/ProxyLane-版本-Windows-ARM64.zip` |
| 校验文件 | 每个 ZIP 旁的 `.zip.sha256` |
| 构建日志与记录 | `build/release/时间-标识/build.log`、平台日志、`build-info.json` |
| ARM64 详细日志、架构和哈希记录 | `build/qa/arm64-build/Release/` |

两种包都包含根目录的 `README.md`、`README_EN.md` 和合并后的 `LICENSE`。ARM 包另外包含同版本的 Hook32/64；不包含 Intel 主程序或 Intel 后端。打包脚本检查实际 PE 架构、文件版本一致性及 Intel Hook 的静态 TLS。配置、密钥、测试探针、调试符号和 CA 命令行工具均不进入 ZIP。

基础检查不等于所有功能验收。统一入口运行 Intel 单元测试；ARM 构建包含探针编译和 PE/引导字节检查，不在 x64 主机运行 ARM 程序。桌面启动检查可对解压后的 Intel 包单独执行 `tests/run-startup-smoke.ps1 -BinaryDirectory <目录>`；测试目录应先创建空的 `portable.flag`，避免使用日常用户配置。ARM 真机跨架构矩阵、SSH、MITM、UAC，以及 XP 动态加载均需独立验证，参见 [ARM64 验收说明](README_ARM64.md)。

## 4. 依赖下载与缓存

首次构建需要访问 Rust 工具链/包源、nuget.org 和 libssh2.org。OpenSSL 3.5.9 预编译包（约 128 MiB）和 libssh2 1.11.1 源码按固定 SHA-256 校验，补丁来自仓库；不需要单独安装 OpenSSL、Perl、NASM、NuGet 或 .NET SDK。

可提前放置 `build/deps/openssl-native.3.5.9.nupkg` 和 `build/deps/libssh2-1.11.1.tar.gz`。完整离线构建还需要 Rust 工具链、目标标准库和 Cargo 依赖缓存；仅复制两个压缩包不够。常规重跑会复用 `build/deps`、Rust `target` 和 C++ 对象缓存。

### 缓存位置与清理影响

默认不清理缓存。以下仅供主动释放空间时参考；先结束构建及使用产物的进程，确认不需要保留日志、配置或测试证据。

| 路径 | 内容与删除后的影响 |
| --- | --- |
| `src/ProxyLaneMitm/target/`、`src/ProxyLaneSecureTransport/target/` | Rust 编译缓存；可重建。保留用户级 Cargo 缓存时通常只重新编译，无需重下 crates |
| `src/ProxyLaneProtocol/target/` | 单独构建协议库或运行 DoH Rust 测试时产生；可重建 |
| `build/ProxyLane/`、`build/ProxyLaneHook/`、`tests/obj/` | C++ 中间文件；可重建，不会因此重新下载 Rust crates |
| `build/deps/` | SSH 下载包、解压源码和 CMake 缓存；整体删除后会重新下载 OpenSSL/libssh2 并构建。保留两个下载包，只删除生成目录可避免重复下载 |
| `build/release/`、`build/qa/`、其他测试输出目录 | 构建日志、验收记录、探针或测试现场；确认无需追溯后可删，日志不会被下一次构建还原 |
| `build/test-venv/` | 按下一节创建的 Python 测试环境；删除后需重新创建并安装测试依赖 |
| `bin/`、`dist/` | 产品和发布包，不只是缓存。产品可重新编译/打包，但 `bin` 中自行创建的配置、证书或密钥须先保留 |
| `%USERPROFILE%\.cargo/registry/`、`.cargo/git/` | 用户级 Cargo 下载缓存，受 `CARGO_HOME` 覆盖；删除会影响其他 Rust 项目并导致重新下载，不属于日常项目清理 |

Rust 工具链和目标标准库一般位于 `%USERPROFILE%\.rustup/`（可由 `RUSTUP_HOME` 覆盖）；保留它们，使用 `rustup` 管理组件，不当作项目编译缓存清除。

## 5. 完整回归入口

标准构建只执行基础检查，发布验收需按功能继续选择下列入口。先完成 Release 构建，从仓库根目录在可交互的 Windows 桌面上运行；多数脚本会编译测试探针并使用 `bin` 中的 DLL/导入库，不能只拿发布 ZIP 代替源码构建树。桌面/UI 测试不要在锁屏或无桌面会话执行，测试期间避免并行运行其他测试或让日常 ProxyLane 接管测试进程。

SSH 与 DoH 连通性 fixture 需要 **Paramiko ≥ 3.5** 和 `cryptography`，Detours/跨架构测试另用 `psutil`，统一列在 [`tests/requirements-regression.txt`](../tests/requirements-regression.txt)。它们是测试依赖，不是产品构建依赖。推荐隔离安装（PATH 修改仅影响当前终端及其子进程）：

```powershell
python -m venv build/test-venv
& .\build\test-venv\Scripts\python.exe -m pip install -r tests/requirements-regression.txt
$env:PATH = "$PWD\build\test-venv\Scripts;$env:PATH"
powershell -NoProfile -ExecutionPolicy Bypass -File tests/run-ssh-transport-tests.ps1 -Full
powershell -NoProfile -ExecutionPolicy Bypass -File tests/run-doh-connectivity-tests.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File tests/run-chain-ui-tests.ps1
```

下表脚本均在 `tests/`，用 `powershell -NoProfile -ExecutionPolicy Bypass -File tests/<脚本>` 执行。建议预留时间不含首次产品编译和依赖下载。无额外说明时，仅需标准构建工具和本地回环网络。

| 脚本/参数 | 覆盖范围与额外条件 | 建议预留 |
| --- | --- | --- |
| `run-tests.ps1` | Win32/x64 单元测试，标准构建已执行 | 1–5 分钟 |
| `run-startup-smoke.ps1 -BinaryDirectory <解压目录>` | 桌面启动；目录先放空 `portable.flag`。默认 2 架构 × 2 次 × 10 秒观察 | 1–2 分钟 |
| `run-ssh-transport-tests.ps1 -Full` | SSH、链、密钥、会话超时；Python requirements。Full 含分钟级真实等待 | 5–10 分钟 |
| `run-doh-tests.ps1` | DNS 编解码和 DoH Rust 单元测试；首次另编译 Rust 测试产物 | 1–5 分钟，冷缓存另计 |
| `run-doh-tests.ps1 -Online` | 追加真实 DoH/TLS 与代理链；需能连接所选 DoH 服务 | 2–10 分钟 |
| `run-doh-cache-tests.ps1`、`run-doh-deadline-tests.ps1` | 缓存与期限/取消，本地测试 | 每项 1–5 分钟 |
| `run-doh-connectivity-tests.ps1` | 本地失败/连通性、SSH fixture；Python requirements。加 `-Online` 才运行远程服务用例 | 2–10 分钟 |
| `run-dns-relay-tests.ps1 -Online` | Rust 测试及应用 DNS → DoH 中继；需外网，回包保留实际本地中继来源地址 | 2–10 分钟 |
| `run-proxy-chain-tests.ps1`、`run-socket-transport-tests.ps1`、`run-bypass-transport-tests.ps1` | 链、异步套接字、直连传输 | 每项 1–5 分钟 |
| `run-chain-ui-tests.ps1` | 真实代理链页面的开始、取消、失败恢复；自动创建隔离 portable 副本，无额外 Python 依赖 | 1–2 分钟 |
| `run-config-storage-tests.ps1`、`run-hook-failure-diagnostics.ps1` | 配置存储、Hook 失败诊断 | 每项 1–5 分钟 |
| `run-ipv6-proxy-tester-tests.ps1`、`run-udp-send-hook-tests.ps1` | IPv6 代理测试、UDP 发送路径；需本地协议栈支持相应用例 | 每项 1–5 分钟 |
| `run-detours-tests.ps1` | 注入、统计、子进程、重绑和 IPv6/DNS；另需 Go 在 PATH、Python requirements；会增量编译产品 | 5–15 分钟 |
| `run-cross-architecture-tests.ps1` | 编译三架构探针，运行当前主机支持的注入矩阵；需 ARM64 构建工具和 Python requirements。`-BuildOnly` 只编译 | 5–15 分钟 |

在线脚本可用 `-DohUrl <HTTPS地址> -Bootstrap <IP>` 更换服务，地址需相互匹配。ARM64 SSH 使用 `run-ssh-transport-tests.ps1 -Platform ARM64 -Full`，需 Windows ARM64 真机和 ARM 构建输出中的探针（发布 ZIP 不含探针）。完整 ARM 矩阵、UAC/权限场景见 [ARM64 验收说明](README_ARM64.md) 和 [评估与测试记录](windows-arm64-assessment.md)；MITM、协议及其他 E2E 的专用依赖见 [E2E 指南](../tests/e2e/README.md)。XP 上的 Hook 动态加载仍需单独实测。

构建预检自身的回归入口为 `powershell -NoProfile -ExecutionPolicy Bypass -File tests/BuildPreflightTests.ps1`，模拟 Rust 组件缺失，不安装或移除真实工具链。

## 6. 排错与高级入口

### 已知构建警告

| 警告 | 含义与处理 |
| --- | --- |
| MSB8051 | `v141_xp` 的 XP 支持已弃用提示；本项目为兼容 XP 保留该工具集，不因该提示重定向工具集 |
| MSB8012 | 部分 Intel 项目的 `TargetPath` 与链接器 `OutputFile` 不一致；检查输出路径和打包产物 |
| C4244 | 类型转换可能丢失数据；检查对应代码的取值范围和截断行为 |

构建日志位于 `build/release/`。

| 问题 | 处理 |
| --- | --- |
| 找不到 v141_xp / afxwin.h / MFC 库 | 在 VS 2019 Installer 补装 XP、v141 ATL/MFC；ARM64 还需自己的 v142 ATL/MFC |
| Clang 找不到或引导字节检查失败 | 显式指定正确的 Clang 目录；使用已验证版本，不跳过检查 |
| Rust 工具链缺失 | 执行上面的 `rustup toolchain install`，安装后重开终端 |
| Rust target 缺失 | 执行预检给出的 `rustup target add ... --toolchain 1.88.0-x86_64-pc-windows-msvc`；Intel 无需 ARM64 target |
| CMake/编译路径过长 | 将 checkout 放在更短路径，构建目录不应从其他路径直接搬入 |
| 下载或校验失败 | 检查网络、代理和缓存文件，按报错路径替换损坏下载；不要取消哈希校验 |
| DLL/EXE 被占用 | 退出从该 bin 目录启动的应用及已加载 Hook 的测试进程后重试 |

高级入口仍保留：`src/ProxyLane.sln` 的 Win32/x64 Release、`scripts/build-arm64.ps1` 的 Release/Debug、`scripts/build-ssh.ps1`、`scripts/build-secure-transport.ps1`、`scripts/build-mitm.ps1`。手工打包用 `scripts/package-release.ps1`，ARM64 加 `-Architecture ARM64`（或使用 `scripts/package-arm64.ps1`）；单独打包不会重新编译，调用者须确保产物来自当前源码。
