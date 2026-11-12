# ProxyLane Windows ARM64 开发测试包

本包面向 Windows 11 ARM64，尚未完成 Windows ARM64 实机验收，不代表正式 ARM64 支持已经发布。

## 文件与启动

完整解压后直接运行 `ProxyLaneARM64.exe`，保持以下文件在同一目录：

- `ProxyLaneARM64.exe`：原生界面与代理宿主。
- `ProxyLaneHookARM64.dll`：原生注入、Hook 和本地代理组件。
- `ProxyLaneSecureTransportARM64.dll`：安全传输后端。
- `ProxyLaneMitmARM64.dll`：MITM、协议分析与 DoH 后端。
- `ProxyLaneSshARM64.dll`：按需加载的原生 SSH 后端，使用同一版本 libssh2 / OpenSSL。

这些文件均已通过 Release 交叉构建和 PE ARM64 架构检查。运行时需要 ARM64 的 Microsoft Visual C++ 运行库。
本包仅包含上述 5 个产品二进制，不含 x86/x64 程序、CA 命令行工具、调试符号或测试探针。

## 当前代理范围

| Windows ARM 上的目标 | 当前状态 |
| --- | --- |
| 纯 ARM64 进程：启动时注入、附加运行中进程 | 已实现，待 ARM64 实机验收 |
| 已代理的 ARM64 父进程创建 ARM64 子进程/孙进程 | 已接入现有子进程流程，待 ARM64 实机验收 |
| x86 / x64 仿真进程及跨架构子进程 | 当前不支持注入 |
| ARM64EC / ARM64X 混合目标 | 不在当前支持范围 |

Windows 11 ARM 能仿真运行 x86/x64 应用，但这不等于本包能够代理它们。
当前普通子进程创建流程在注入失败后会释放 ProxyLane 自己增加的挂起；
因此 ARM64 父进程启动 x86/x64 子进程时，子进程可能继续运行而未被代理，不能依赖父进程代理设置保护其流量。
调用者原本要求的挂起不由 ProxyLane 取消。

SSH 后端和 GUI 提权启动已接入并完成交叉构建；“以管理员身份启动”与 x64 一样使用系统 `rundll32.exe`，不再需要单独的 helper 文件。
SSH 实际通信、UAC 确认/取消、系统宿主加载 ARM64 Hook、提权目标的代理与子进程仍待 ARM64 实机验收。
提权启动只支持纯 ARM64 目标；注入失败时终止本次创建的目标，不让它绕过代理继续运行。
浏览器 QUIC 策略 Hook 尚未适配。
不要把其他发行包中的 x86/x64 DLL 改名后放入本目录。

DoH 的本地 UDP 回包保留实际中继来源地址，不提供原 DNS 服务器来源地址透明性。

## 初次测试

先使用纯 ARM64 的自有测试程序验证普通 TCP/UDP 代理，再检查原生子进程继承。
主程序能启动、或 ARM64 文件编译成功，都不能代替 Hook、注入和网络流量的实际验收。

## English

This is an experimental native Windows 11 ARM64 package, cross-built but not yet runtime-tested on Windows ARM64.
Run `ProxyLaneARM64.exe` with the bundled DLLs in the same directory. An ARM64 Visual C++ runtime is required.
Native ARM64 injection and native child-process routing are implemented but await device validation.
Native SSH is included. Elevated launch uses system `rundll32.exe`, as on x64, with no separate helper executable.
SSH, UAC and loading the ARM64 Hook into the system host still require ARM64 device validation.
Elevated launch only supports pure ARM64 targets and terminates its newly created target if injection fails.
x86/x64 emulated targets, mixed-architecture children, ARM64EC/ARM64X targets and the browser QUIC policy hook
are not supported. An unsupported child created by an ordinary proxied parent can continue without proxy interception.
This package contains five ARM64 product binaries; the CA command-line tool, test probes and x86/x64 binaries are excluded.

[Windows on Arm emulation reference](https://learn.microsoft.com/en-us/windows/arm/apps-on-arm-x86-emulation)
