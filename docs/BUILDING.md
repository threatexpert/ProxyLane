# 从 fork 到发布包

[English](BUILDING_EN.md)

标准构建入口是 `scripts/build-release.ps1`。它定位 VS 2019、检查依赖、增量编译、运行 Win32/x64 单元测试、检查 Hook 静态 TLS 和语言资源，可选生成发布包。无需修改脚本中的本机路径，不依赖维护者的 `bin`、`build` 或相邻仓库。

## 1. 准备构建机（一次）

当前验证基线为 **Windows 10/11 x64 + Visual Studio 2019 16.11**。ARM64 是在该主机上交叉编译；这不代表已验证在 ARM64 主机或 VS 2022 上构建。

1. 安装 VS 2019 或 Build Tools 2019，选择“使用 C++ 的桌面开发”（Build Tools 中为 C++ 生成工具）。在 Visual Studio Installer 中对 2019 实例选择“更多 → 导入配置”：只构建 Intel 版本导入 [`vs2019-intel.vsconfig`](../vs2019-intel.vsconfig)；包含 ARM64 的构建导入 [`.vsconfig`](../.vsconfig)。两份清单均位于仓库根目录。
2. 安装 Git for Windows、Python 3.8+、Rustup，确保 `git`、`python`、`rustup`、`cargo` 能从新开的 PowerShell 运行。Windows 自带的 `tar.exe` 也必须可用。Python 的 Microsoft Store 占位别名不能代替实际解释器。
3. 安装 CMake 3.15+ 并加入 PATH；也可使用上述 VS 配置提供的 CMake，统一入口会自动定位它。
4. 构建 ARM64 时安装 LLVM/Clang，具体操作见下面的“安装 Clang”。只构建 Intel 包不需要安装它。Android NDK 不是项目的构建依赖。

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
| Android Studio / Android NDK | 不需要 | 不需要；已有 NDK 时可复用其 Clang |

**当前标准 Intel 发布包同时包含 x86 和 x64 产品**，所以即使使用者只运行 x64 Windows，完整构建打包仍需 x86 工具。它不是纯 x64 单架构包。项目仍使用 `v141_xp`，因此仅面向 Windows 10/11 也不能直接省略 XP 工具组件；无需安装 XP 操作系统或 ARM64 运行环境来编译。

只安装上表 Intel 所需依赖和 x64 Rust 目标后，在普通 PowerShell 执行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Architecture x86-x64 -CheckEnvironmentOnly
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Architecture x86-x64 -Package
```

该模式不会调用 ARM64 构建脚本，不检查 Clang 或 ARM64 工具，不下载 ARM64 Rust 目标。产物写入 `bin/`，只生成 `dist/ProxyLane-版本-Windows.zip` 和对应校验文件。省略 `-Package` 可只编译并运行基础检查。

依赖安装入口：[VS 历史版本](https://visualstudio.microsoft.com/vs/older-downloads/)、[Git](https://git-scm.com/downloads/win)、[Python](https://www.python.org/downloads/windows/)、[Rustup](https://rustup.rs/)、[CMake](https://cmake.org/download/)、[LLVM](https://github.com/llvm/llvm-project/releases)。VS 组件 ID 依据 [Microsoft 的 VS 2019 清单](https://github.com/MicrosoftDocs/visualstudio-docs/blob/main/docs/install/includes/vs-2019/workload-component-id-vs-community.md)。安装器可用性和历史版本访问要求以各官网为准。

在普通 PowerShell 中安装固定 Rust 工具链，无需更改全局默认版本：

```powershell
rustup toolchain install 1.88.0-x86_64-pc-windows-msvc --profile minimal
rustup target add x86_64-pc-windows-msvc --toolchain 1.88.0-x86_64-pc-windows-msvc
# 构建 ARM64 时另外执行
rustup target add aarch64-pc-windows-msvc --toolchain 1.88.0-x86_64-pc-windows-msvc
```

安全传输和 MITM 后端都显式使用该版本及提交的 Cargo.lock（`--locked`）。Clang、MSVC、SDK 并非完全锁定，因此不承诺跨机器逐字节相同的二进制。

### 安装 Clang（构建 ARM64 时需要）

在上述 **x64 Windows 构建机**上，安装的是 Windows **x64 版** LLVM/Clang。同一个编译器可以生成 ARM64 目标代码；无需下载运行在 ARM64 主机上的编译器。Clang 用于 ARM64 引导汇编和 `ring` 的 C/汇编依赖，主程序和 Hook 的 C++ 部分仍使用 MSVC，因此它不能替代前面的 VS ARM64 工具和 SDK。

1. 打开 [LLVM 18.1.8 官方发布页](https://github.com/llvm/llvm-project/releases/tag/llvmorg-18.1.8)，在 Assets 中下载 **`LLVM-18.1.8-win64.exe`**（[直接下载](https://github.com/llvm/llvm-project/releases/download/llvmorg-18.1.8/LLVM-18.1.8-win64.exe)）。这是一个明确的独立安装示例，不要求安装 Android Studio 或 NDK。
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

若使用自定义安装目录，将参数改为包含 `clang.exe` 的 **bin 目录**，而不是 EXE 文件路径。已安装多个 Clang 时也建议显式指定，避免 PATH 中另一个版本被优先选中。

验证范围：本项目目前完整实跑过的是 Android NDK 27.2 随附的 **Clang 18.0.3**，以 `aarch64-pc-windows-msvc` 为目标生成 Windows 二进制。上述官方 **18.1.8 独立安装包的下载地址已核实，但尚未在本项目完成整套构建验收**；它与 NDK 版不能标记为同一份已验证工具链。使用独立版本时应保留引导检查并完成全架构构建，不跳过失败。若已有 NDK，可直接将其 `toolchains\llvm\prebuilt\windows-x86_64\bin` 传给 `-ClangBinDirectory`，无需再安装另一份。

## 2. 克隆并检查环境

克隆自己的 fork 到较短路径，例如 `C:\src\ProxyLane`，避免 VS/CMake 的嵌套输出路径超过旧工具链限制。普通 `git clone` 即可，生产构建无需子模块或维护者的未提交文件。以下命令在仓库根目录执行，使用普通 PowerShell，不要求 Developer PowerShell 或管理员权限：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1 -CheckEnvironmentOnly
# 全架构预检；LLVM 在 PATH 或默认安装位置时可省略路径参数
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Architecture All -CheckEnvironmentOnly -ClangBinDirectory 'C:\tools\llvm\bin'
```

预检不编译、不下载依赖，也不安装系统组件。缺少工具时汇总报告并返回非零退出码。它检查本地基本条件，不能保证网络可达或第三方工具所有版本均兼容。

## 3. 编译、验证、打包

```powershell
# Intel Release：编译到 bin 并运行基础检查
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1
# Intel Release 并打包到 dist
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Package
# 全架构 Release，并生成两份包
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Architecture All -Package -ClangBinDirectory 'C:\tools\llvm\bin'
# 只生成 ARM 包（仍构建 Intel 组件并运行 Intel 单元测试）
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1 -Architecture ARM64 -Package -ClangBinDirectory 'C:\tools\llvm\bin'
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

首次构建需要访问 Rust 工具链/包源、nuget.org 和 libssh2.org。OpenSSL 3.5.9 预编译包（约 128 MiB）和 libssh2 1.11.1 源码按固定 SHA-256 校验，补丁来自仓库；不需要单独安装 OpenSSL、Perl、NASM、NuGet 或 .NET SDK。Rust 版本、源码依赖版本和锁文件更改应作为显式代码变更审查。

可提前放置 `build/deps/openssl-native.3.5.9.nupkg` 和 `build/deps/libssh2-1.11.1.tar.gz`。完整离线构建还需要 Rust 工具链、目标标准库和 Cargo 依赖缓存；仅复制两个压缩包不够。常规重跑会复用 `build/deps`、Rust `target` 和 C++ 对象缓存。

## 5. 排错与高级入口

| 问题 | 处理 |
| --- | --- |
| 找不到 v141_xp / afxwin.h / MFC 库 | 在 VS 2019 Installer 补装 XP、v141 ATL/MFC；ARM64 还需自己的 v142 ATL/MFC |
| Clang 找不到或引导字节检查失败 | 显式指定正确的 Clang 目录；使用已验证版本，不跳过检查 |
| Rust 工具链缺失 | 执行上面的 `rustup toolchain install`，安装后重开终端 |
| CMake/编译路径过长 | 将 checkout 放在更短路径，构建目录不应从其他路径直接搬入 |
| 下载或校验失败 | 检查网络、代理和缓存文件，按报错路径替换损坏下载；不要取消哈希校验 |
| DLL/EXE 被占用 | 退出从该 bin 目录启动的应用及已加载 Hook 的测试进程后重试 |

高级入口仍保留：`src/ProxyLane.sln` 的 Win32/x64 Release、`scripts/build-arm64.ps1` 的 Release/Debug、`scripts/build-ssh.ps1`、`scripts/build-secure-transport.ps1`、`scripts/build-mitm.ps1`。手工打包用 `scripts/package-release.ps1`，ARM64 加 `-Architecture ARM64`（或使用 `scripts/package-arm64.ps1`）；单独打包不会重新编译，调用者须确保产物来自当前源码。

当前自动化覆盖的是已配置构建机上的流程；尚未建立干净 Windows 虚拟机/CI 的完整安装与构建验收。不要将本地增量验证描述成全新机器验收。
