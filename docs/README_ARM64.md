# ProxyLane Windows ARM64 开发测试包

本包面向 Windows 11 ARM64，尚未完成 Windows ARM64 实机验收，不代表正式 ARM64 支持已经发布。

## 文件与启动

完整解压后直接运行 `ProxyLaneARM64.exe`，保持以下文件在同一目录：

- `ProxyLaneARM64.exe`：原生界面与代理宿主。
- `ProxyLaneHookARM64.dll`：原生注入、Hook 和本地代理组件。
- `ProxyLaneSecureTransportARM64.dll`：安全传输后端。
- `ProxyLaneMitmARM64.dll`：MITM、协议分析与 DoH 后端。
- `ProxyLaneMitmARM64.exe`：CA 管理命令行工具；启动普通代理或使用 DoH 不需要安装 CA。

这些文件均已通过 Release 交叉构建和 PE ARM64 架构检查。运行时需要 ARM64 的 Microsoft Visual C++ 运行库。
本包不含 x86/x64 程序、不含 SSH 后端、不含调试符号或测试探针。

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

SSH 后端、浏览器 QUIC 策略 Hook、GUI 的 ARM64 提权 helper 仍未适配。
需要管理员权限时先以管理员身份启动 `ProxyLaneARM64.exe`，再测试原生目标的直接注入。
不要把其他发行包中的 x86/x64 DLL 改名后放入本目录。

DoH 的本地 UDP 回包保留实际中继来源地址，不提供原 DNS 服务器来源地址透明性。

## 初次测试

先使用纯 ARM64 的自有测试程序验证普通 TCP/UDP 代理，再检查原生子进程继承。
主程序能启动、或 ARM64 文件编译成功，都不能代替 Hook、注入和网络流量的实际验收。

## English

This is an experimental native Windows 11 ARM64 package, cross-built but not yet runtime-tested on Windows ARM64.
Run `ProxyLaneARM64.exe` with the bundled DLLs in the same directory. An ARM64 Visual C++ runtime is required.
Native ARM64 injection and native child-process routing are implemented but await device validation.
x86/x64 emulated targets, mixed-architecture children, ARM64EC/ARM64X targets, SSH, the browser QUIC policy hook,
and the elevated helper are not supported. An unsupported child can continue running without proxy interception.
This package contains only ARM64 product binaries; test probes and x86/x64 binaries are excluded.

[Windows on Arm emulation reference](https://learn.microsoft.com/en-us/windows/arm/apps-on-arm-x86-emulation)
