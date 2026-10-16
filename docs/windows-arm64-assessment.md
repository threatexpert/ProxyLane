# Windows ARM64 原生支持评估

初始评估日期：2026-10-15；初始基线：`main` 的 `26386d2`。
开发分支：`codex/windows-arm64-assessment`。2026-10-16 已合入 `main` 的 `a14a721`，
保留当前显式卸载约定：无 HookCallGate，不暂停其他线程，调用者保证卸载时机。
本分支正在分阶段适配，尚不能发布为支持 ARM64 的完整产品。

## 2026-10-16 第二阶段：原生交叉编译

已新增产品的 `Debug|ARM64` 和 `Release|ARM64` 配置，使用 VS 2019 v142、
Windows 10 SDK，现有 Win32/x64 的 v141_xp 配置保持不变。
C++ GUI 与 Hook DLL 均已完整编译、链接；Rust 的 `aarch64-pc-windows-msvc`
目标及锁定版本的 `ring/rustls` 也已实际编译通过，未修改 Cargo.lock 或上游源码。

推荐从 x64 Windows 开发主机运行：

```powershell
.\scripts\build-arm64.ps1 -ClangBinDirectory 'C:\path\to\llvm\bin'
.\scripts\build-arm64.ps1 -Configuration Debug -ClangBinDirectory 'C:\path\to\llvm\bin'
```

若 `clang.exe` 已在 PATH 中，可省略 `-ClangBinDirectory`。脚本会加载
`vcvarsall amd64_arm64` 的头文件/库环境，并在结束时恢复调用者的环境变量。
需要 VS 2019 的 ARM64 编译器、ATL/MFC、Windows 10 SDK、Rust 与 Clang；
不能只把 Clang 放进 PATH 而遗漏 MSVC/SDK 头文件。`ring 0.17.14` 的 Windows ARM64
C 代码要求 Clang。本机实际使用现有 Android NDK 27.2 附带的 Clang 18.0.3，
以 `--target=aarch64-pc-windows-msvc` 编译并链接 Windows SDK/CRT；产物不是 Android ELF。
Rust 的官方平台说明也支持在 Windows 上进行架构交叉编译：
[Windows MSVC targets](https://doc.rust-lang.org/rustc/platform-support/windows-msvc.html)。

产物放在 `bin/ARM64/Release/` 或 `bin/ARM64/Debug/`，与既有发行产物隔离：

| 文件 | 用途 |
|---|---|
| `ProxyLaneARM64.exe` | 原生 GUI |
| `ProxyLaneHookARM64.dll` | 原生 Hook/本地代理模块，保留显式卸载接口 |
| `ProxyLaneSecureTransportARM64.dll` | 原生 Rust 安全传输模块 |
| `ProxyLaneTrafficARM64.exe` | 复用现有 TCP/UDP、启停及显式卸载测试的原生测试程序 |
| `DetoursBuildProbe.exe` | 架构识别与 Detours 事务探针（始终为 Release 探针） |

脚本验证所有上述文件均为 PE32+、Machine `0xAA64`，写入 SHA256 清单。
Debug 的安全传输模块与既有构建习惯一致，使用 Rust Release 版本。
`ProxyLaneTests` 中的指令字节用例仍为 x86/x64，解决方案 ARM64 配置不构建它；
两个原生探针由 `build-arm64.ps1` 单独构建，不能把它们当作完整 ARM64 重定位测试覆盖。
流量探针仍需要现有 `TrafficStatisticsE2ETests.py` 和 SOCKS5 测试服务配合；此阶段未运行。

`InjectDll.cpp` 按实际指令集分支，ARM64 分支明确返回不支持；`AttachToI` 在 ARM64
也直接返回 `ERROR_NOT_SUPPORTED`，不会分配或执行 x86/x64 的远程线程机器码。
所有 Windows ARM64 宿主的自动注入路由仍被第一阶段策略禁用；允许在受控测试进程内
直接调用 `gp_HookWinsock/gp_UnhookWinsock`，用于后续验证原生 inline hook。
构建成功不代表远程注入、网络代理或安全传输已经在 ARM64 上验证通过。

本阶段验证：

- Release、Debug 完整交叉构建和五个产物的 PE 架构检查通过。
- 导出表：Hook DLL 的 7 个导出、Rust DLL 的 13 个 C ABI 导出存在。
- GUI 和流量探针均依赖 `ProxyLaneHookARM64.dll`，没有错误链接 x64 Hook DLL。
- 安全传输 DLL 依赖 `VCRUNTIME140.dll`；虚拟机运行时需具备相应 ARM64 VC 运行库。
- Win32/x64 Release 解决方案重新编译、两架构单元测试通过；本阶段未重复上一阶段
  已通过的完整网络 E2E，也未执行任何 ARM64 程序。

构建日志、导入/导出表和 SHA256 清单位于 `build/qa/arm64-build/`，
配置分别使用 `Release/verification.json` 与 `Debug/verification.json`。
尚未合并 main、未修改发行打包脚本，也未打 ARM64 发行包。
下一步是原生进程内运行测试和 ARM64 bootstrap/helper 的实现。

## 2026-10-16 第一阶段：架构识别与路由

已将 GUI、提权/子进程辅助注入、底层注入入口统一接入
`src/ProxyLaneHook/ProcessArchitecture.h`，区分 `Unknown/X86/X64/Arm64`。
动态调用 `IsWow64Process2`，失败保留错误并拒绝注入；只有 API 不存在且操作系统早于
Windows 10 1709 时，才允许用旧接口识别 x86/x64。使用 `RtlGetVersion` 读取真实系统版本，
避免应用 manifest 影响判断。ARM 仿真环境中 `GetNativeSystemInfo` 也可能返回仿真架构，
不能把这个 API 单独当作真实宿主架构的证据。参见
[GetNativeSystemInfo 文档](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getnativesysteminfo)。

产物名称集中定义为既有 x86/x64 名称及 `ProxyLaneARM64.exe`、
`ProxyLaneHookARM64.dll`、`ProxyLaneSecureTransportARM64.dll`。
启动器根据宿主架构选择原生程序；安全传输根据当前模块架构选择 DLL。
辅助进程不再根据 DLL 文件名是否以 `64.dll` 结尾来推断架构。
远程子进程标记读取也先确认架构；获取 WOW64 PEB 失败时不再继续解析另一种 PEB 布局。

**阶段性限制：** ARM64 宿主上的注入路由暂时全部返回不支持，包括仿真进程；
原生 ARM64 bootstrap、对应 helper 和混合模块边界尚待实现。第一阶段新增文件名只是明确映射；
第二阶段已补充原生交叉构建，尚未开放注入。x86/x64 Windows 的同架构直连与跨架构辅助流程保留。
ARM64EC/ARM64X 不在本阶段支持范围；进程架构识别也不能证明混合模块 ABI 兼容。

新增 `tests/ProcessArchitectureTests.cpp`，覆盖三种架构、ARM 宿主仿真进程、未知 machine、
API 失败不回退、旧系统回退边界、路由及真实当前进程查询。
ARM64 探针已更新为当前 `InstallDetourHooks/RemoveDetourHooks` API 并包含上述测试，
不再引用已删除的 HookCallGate。x64 主机仅验证该探针交叉编译和 PE Machine，未运行它。

验证已通过，记录见 `build/qa/arm64-foundation/`：

- Release Win32/x64 完整解决方案编译、两架构单元测试。
- `tests/run-detours-tests.ps1`：TCP/UDP 统计和重启、显式卸载、四种 x86/x64
  父子/孙进程组合（8 次代理连接）、MSBuild 启动、IPv6/DNS 回归。
- `tests/run-startup-smoke.ps1 -ObserveSeconds 5 -Repetitions 1`：x86 转交 x64
  和直接 x64 启动均通过，主窗口保持响应。
- ARM64 探针交叉编译、PE Machine `0xAA64` 验证通过；未在 ARM 设备运行。
- 检查四个 x86/x64 EXE/DLL 的 PE 架构与导入表，没有新增对 `IsWow64Process2`
  或 `RtlGetVersion` 的静态导入。旧系统回退经过模拟测试，尚未在 XP 实机重测。

本阶段不修改 main、不发布发行包。
第一阶段后续的原生交叉构建已在第二阶段完成；进程内运行验收、原生注入和匹配架构的 helper 仍待完成。


## 初始评估结论与证据（2026-10-15）

原生 ARM64 支持可行，Detours 后端已有可用的构建基础；主要工作是将整个工程从
“32 位 / 64 位”的二选一模型改为明确区分 x86、x64、ARM64，并适配注入与子进程流程。
目前不能仅复制 x64 项目配置就发布 ARM64 版本。

已在 Windows 10 x64（10.0.19045）上完成以下检查：

| 项目 | 结果 | 证据范围 |
|---|---|---|
| VS 2019 v142 ARM64 编译器、ATL/MFC 库目录 | 已安装 | 本机 `14.29.30133` 的 `bin/Hostx64/arm64`、`atlmfc/lib/arm64` 存在；未编译完整 MFC 应用 |
| Detours 核心及本项目事务/入口保护封装 | ARM64 编译、链接通过 | `detours.cpp`、`disasm.cpp`、`modules.cpp`、`DetourHooks.cpp`、`HookCallGate.cpp` |
| 输出架构 | 已验证为原生 ARM64 | 读取构建探针的 PE 文件头，Machine 为 `0xAA64`；编译时检查 `_M_ARM64` 且排除 `_M_ARM64EC` |
| ARM64 执行、hook 和 DLL 注入 | 未验证 | 当前执行主机是 x64，没有在此运行 ARM64 探针 |
| Rust 安全传输 ARM64 | 未构建 | 本机尚未安装 `aarch64-pc-windows-msvc` 标准库目标；现有脚本仅构建 x86/x64 |

复现构建：在 VS 2019 开发者命令行中运行：

```powershell
msbuild tests/arm64/DetoursBuildProbe.vcxproj /m /p:Configuration=Release /p:Platform=ARM64
dumpbin /headers build/qa/arm64-assessment/bin/DetoursBuildProbe.exe
```

本次日志为 `build/qa/arm64-assessment/build.log`，PE 检查结果为同目录
`verification.json`。该探针只用于编译、链接检查，没有实际安装 hook；
不能将其构建成功等同于原生运行测试通过。探针未加入现有 x86/x64 解决方案。

## 必须处理的工程位置

下列行号按评估基线记录，后续修改时应按函数名定位。

| 优先级 | 位置 | 当前行为与适配要求 |
|---|---|---|
| P0 | `src/ProxyLane/Page3.cpp:699`，`is64Process`、`ChooseProxyLaneHookModule`、`ChooseRundll32` | 只用 `IsWow64Process` 和文件名 `64.dll` 选择模块，无法正确表达 x64 与 ARM64 的区别；需要共享的架构检测与明确的产物映射 |
| P0 | `src/ProxyLaneHook/ElevatedLauncher.cpp:92,276`，`Is64BitProcess`、`ProxyLaneInjectSuspendedProcess` | 只比较双方是否 64 位就决定能否直接注入；x64 与 ARM64 同为 64 位却不是同一指令集，必须改成目标执行架构匹配，并更新提权/辅助进程路径 |
| P0 | `src/ProxyLaneHook/InjectDll.cpp:38` | `_WIN64` 分支内是 x64 机器码与 `CONTEXT.Rip/Rax`，ARM64 同样定义 `_WIN64`，会错误进入此分支；必须按 `_M_IX86`、`_M_X64`、`_M_ARM64` 分开，提供原生注入实现 |
| P0 | `src/ProxyLaneHook/ProxyModule.cpp:283`，`AttachToI` | 远程线程占位代码为 x86/x64 的 NOP/RET，不能在 ARM64 上执行；无主线程 ID 的附加路径也需适配 |
| P0 | `src/remotecode/remoteCode.h:18` 和 `remoteCode.cpp` | 引导参数含指针、句柄和布局依赖；新的 ARM64 引导代码需有可复现生成流程与偏移检查，不能直接复用现有字节数组 |
| P1 | `src/ProxyLaneHook/HookWinsock.cpp:2278`，`FinishChildCreation` | 子进程创建、暂停、PRC 决策、注入、恢复是完整链路，架构切换后必须保持父进程返回前注入与失败恢复语义 |
| P1 | `src/ProxyLaneHook/ProxyReceptionCentre.cpp:279`，`RemoteProcessHasChildGuard` | 通过 WOW64 状态、PEB/环境偏移读取远程标记；需要分别验证 ARM64、x64 仿真和 x86 仿真的布局及失败处理，不能仅按位宽推断 |
| P1 | `src/ProxyLaneHook/DeferredMitigationPolicy.h:100` | 使用未公开的属性列表内存布局，`_WIN64` 下固定头部大小；需在 ARM64 的实际创建流程中验证，不能由 x64 测试推导 |
| P1 | `src/ProxyLane/ProxyLane.cpp:188` | x86 启动器在 WOW64 下转交给 `ProxyLane64.exe`；需增加原生宿主架构选择，避免 ARM64 主机仍固定转交 x64 |
| P1 | `src/ProxyLaneHook/asynsocket/AsyncSecureSocketLayer.cpp:96` | `_WIN64` 一律加载 `ProxyLaneSecureTransport64.dll`；需要独立 ARM64 DLL 名称和加载映射 |
| P1 | `src/ProxyLane/*.vcxproj`、`src/ProxyLaneHook/*.vcxproj`、`src/ProxyLane.sln` | 产品只有 Win32/x64、v141_xp 配置；建议 ARM64 单独使用 v142 + Windows 10 SDK，现有 XP 配置保留给 x86/x64 |
| P1 | `scripts/build-secure-transport.ps1`、`scripts/package-release.ps1` | 需要 ARM64 Rust 目标、依赖构建验证，以及明确的三架构输出/打包清单 |
| P2 | `tests/DetourHooksTests.cpp`、托管启动/流量测试 | 指令重定位单测使用 x86/x64 字节序列，ARM64 不能直接执行；新增 ARM64 指令用例和父子进程架构矩阵 |

`HookNewProcessInfo` 等现有消息主要使用固定宽度字段，可以优先保持协议兼容；
但仍需逐个检查实际传输结构的 `sizeof/offsetof`，不能因存在 `#pragma pack(1)` 就认定
所有结构都可跨架构传输。`myapi` 是远程执行参数，与 PRC 的消息协议应分别处理。

## 建议实施顺序

1. **统一架构识别和模块选择。** 引入 `Unknown/X86/X64/Arm64`，动态调用
   `IsWow64Process2`；成功且 `processMachine == IMAGE_FILE_MACHINE_UNKNOWN` 时使用
   `nativeMachine`。失败保持 Unknown，不把它当成 x64。旧系统仅在确认是传统
   x86/x64 环境后使用兼容分支。同步替换 GUI、提权和子进程注入中的二选一逻辑。
   此规则依据 [Microsoft 的接口定义](https://learn.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-iswow64process2)。
2. **建立 ARM64 原生构建和进程内验证。** 先补足架构编译分支，构建原生 Hook DLL；
   在受控 ARM64 测试程序中直接加载并启停 hook，验证网络代理和指令重定位，先不依赖远程注入。
   建议产物显式命名为 `ProxyLaneARM64.exe`、`ProxyLaneHookARM64.dll`、
   `ProxyLaneSecureTransportARM64.dll`，避免与已有 x64 的 `64` 命名冲突。
3. **适配 ARM64→ARM64 注入。** 覆盖启动时的挂起主线程和附加到运行中进程两条路径；
   验证寄存器/栈恢复、加载器时序、实际函数地址解析和失败时的线程恢复。
   Detours 的注入 API 可以作为单独方案评估，但本次只引入了其 inline hook 核心，
   不能认为现有私有注入流程已被 Detours 接管。
4. **再扩展跨架构路由。** 优先使用与目标架构匹配的辅助程序；若继续使用系统
   `rundll32`，必须在 Windows on ARM 上验证其实际架构、重定向与模块加载兼容性。
   不继续把 `System32 == x64` 写进业务规则。
5. **补齐安全传输和发布。** 构建 `aarch64-pc-windows-msvc`，检查锁定版本的
   rustls/ring 及 C ABI。Rust 官方列出了该目标及 Windows 交叉编译路径，
   但这不代替本项目依赖的实际构建测试：[Rust MSVC 平台说明](https://doc.rust-lang.org/stable/rustc/platform-support/windows-msvc.html)。

上述工作分成可独立审查的提交；第一阶段架构识别已实施，后续再引入 ARM64 特有的执行代码。

## 验收边界

建议首期以 Windows 11 on ARM 的纯 ARM64 进程为目标，ARM64EC/ARM64X 混合模块单独评估；
仅靠一个进程位宽或架构枚举不能保证混合模块 ABI 兼容。现有 x86/x64 程序在 ARM 主机
上的仿真运行也应单独测试，不能把“系统能运行它”当成“注入和 inline hook 已兼容”。
微软区分了 Windows 10 on ARM 的 x86 仿真与 Windows 11 的 x64 仿真，并要求在 ARM
设备或相应虚拟机上进行运行测试：[添加 Arm 支持](https://learn.microsoft.com/en-us/windows/arm/add-arm-support)。

最低验收集：

- ARM64 单进程启停、TCP/UDP、DNS、ConnectEx/WSASendMsg 缓存回调、阻断与绕过策略。
- ARM64 原生重定位：分支、条件分支、PC 相对寻址和字面量加载；调用者保证静默时的启停、安装后的并发调用、失败回滚。
- ARM64→ARM64 子进程/孙进程、提权、附加、失败后的挂起线程恢复。
- 在同一 ARM 主机上逐项测试 x86/x64/ARM64 父子进程的九种组合；未支持的组合应明确拒绝，
  不能错误选择另一架构的 DLL。
- ARM64 安全传输 DLL 的实际 TLS/PSK 连接，并保持现有 x86/x64 回归通过。

已完成共享架构识别改造和原生 ARM64 交叉构建；尚未完成 ARM64 远程注入及 ARM 设备运行验收。
