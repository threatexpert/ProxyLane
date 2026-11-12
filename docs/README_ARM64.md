# ProxyLane Windows ARM64 开发测试包

本包面向 Windows 11 ARM64。注入与子进程代理、SSH、MITM/TLS、UAC 已获用户 ARM 真机测试通过反馈；完整自动化跨架构矩阵尚未确认全部跑完。

## 实现状态与验证状态

以下“待验收”表示代码已实现，但尚未在 Windows 11 ARM 真机上完成全部运行测试，不表示功能尚未开发。

| 功能 | 实现状态 | Windows 11 ARM 验证状态 |
| --- | --- | --- |
| ARM64/x64/x86 目标注入、附加及跨架构子进程代理 | 已实现，三种 Hook 已构建并打包 | 用户所测场景通过，具体组合见下；完整自动化矩阵尚未确认全部跑完 |
| SSH 后端 | 已实现，原生 ARM64 DLL 已构建并打包 | 用户 ARM 真机测试通过 |
| MITM/TLS 后端 | 已实现，原生 ARM64 DLL 已构建并打包 | 用户 ARM 真机测试通过 |
| UAC / 管理员启动 | 已实现，使用系统 rundll32，无独立提权 helper | 用户 ARM 真机测试通过 |
| 浏览器专用 QUIC 策略干预 | ARM64 适配未实现；按用户决定暂缓 | 不纳入本轮验收范围 |

完整跨架构“矩阵”是一组测试用例，不是一项尚未实现的功能。编译通过及 Intel 回归通过不能替代 ARM 真机验收，也不代表任意 ARM64EC 混合模块都兼容。

2026-11-12 用户补充 ARM 真机反馈：子进程代理、SSH、MITM/TLS、UAC 均测试可用。以下父子进程场景均可代理子进程：

| 父进程 | 子进程 | 结果 |
| --- | --- | --- |
| 用户描述为 `syswow32` 目录中的 cmd | amd64 gonc | 通过 |
| 同上 | i386 gonc | 通过 |
| 原生 ARM64 cmd | amd64 gonc | 通过 |
| 原生 ARM64 cmd | i386 gonc | 通过 |

目录名 `syswow32` 按用户原话记录，尚未核实是否指 SysWOW64，不据此认定该 cmd 的实际运行架构。此前原生 ARM64X 命令行注入及 x64 PowerShell 附加后的子进程接管也已有用户成功反馈。以上为用户实测记录，不冒充自动化矩阵报告。

2026-11-12 决定：暂缓 ARM64 浏览器专用 QUIC 策略干预。ARM64 宿主目前不启用这项策略，包括其代理的 x64 仿真浏览器；不宣称已与 amd64 的此项功能对齐。这里指浏览器内部策略 Hook，不表示常规 UDP 代理未实现。

## 文件与启动

完整解压后运行 `ProxyLaneARM64.exe`，保持以下 7 个产品二进制在同一目录：

- `ProxyLaneARM64.exe`：原生界面与代理宿主。
- `ProxyLaneHookARM64.dll`：原生注入、Hook 和代理组件。
- `ProxyLaneHook32.dll`：x86 仿真目标的注入和 Hook。
- `ProxyLaneHook64.dll`：x64 仿真目标的注入和 Hook。
- `ProxyLaneSecureTransportARM64.dll`：安全传输后端。
- `ProxyLaneMitmARM64.dll`：MITM、协议分析与 DoH 后端。
- `ProxyLaneSshARM64.dll`：按需加载的原生 SSH 后端。

Hook32/64 与 Intel 包来自同一版本构建，不能用旧版本 DLL 替换。后端在 ARM64 代理宿主内运行，不需要为了仿真目标再打包 Intel 后端或 Intel 主程序。运行时需要 ARM64 的 Microsoft Visual C++ 运行库。
本包不含独立提权 helper、MITM CA 命令行工具、调试符号或测试探针。Intel 包继续不包含 ARM64 模块。

## 注入与子进程

- 以 Windows 11 报告的实际进程架构选择 Hook，不以文件名、父进程架构或 ARM64X 的磁盘 PE 头猜测。
- 原生 ARM64 目标使用 HookARM64；x64 兼容模式目标使用 Hook64；x86 目标使用 Hook32。
- 同架构直接执行注入；跨架构使用系统 `rundll32.exe`。x86 使用 SysWOW64，ARM64/x64 使用 System32 并显式选择运行模式。启动后核对宿主架构，再允许它执行注入。
- GUI 启动/附加、提权启动以及已代理父进程创建的子进程均接入上述路由。三种架构之间的九种父子组合已实现路由，已获上述 ARM 真机成功反馈；完整自动化矩阵尚未确认全部跑完。
- ARM64EC/x64 兼容模式使用已有 x64 Hook 路径，未单独承诺任意混合模块或非导出函数 Hook 都兼容。
- Hook32/64 按既有模块映射接管一次公开 CreateProcessW（Windows 7 选择 Kernel32，Windows 8+ 选择 KernelBase），并保留内部入口；不要求 Windows 7 的 KernelBase 导出该函数。动态 TLS 保证一次创建只处理一次子进程。x64 PowerShell 附加后创建子进程的个案已有用户实测通过，完整 ARM 矩阵仍待验收。
- 注入排队成功不等于 Hook 初始化成功；应检查 PL 中的初始化结果和实际代理流量。

普通子进程流程在注入失败后会释放 PL 自己增加的挂起，子进程可能继续运行而未被代理；调用者原本要求的挂起不由 PL 取消。严格“启动并代理”以及提权启动失败时终止本次创建的目标。
SSH、MITM/TLS、UAC 及上述跨架构子进程场景均已有实现，并获用户 ARM 真机测试通过反馈。浏览器专用 QUIC 策略干预的 ARM64 适配未实现，已明确暂缓。
DoH 的本地 UDP 回包保留实际中继来源地址，不提供原 DNS 服务器来源地址透明性。

## ARM 真机矩阵验收

开发机运行 `tests/run-cross-architecture-tests.ps1 -BuildOnly` 生成三种架构的测试探针。
在 Windows 11 ARM 上，以原生 64 位 Python（安装 psutil）运行：

```powershell
python tests/CrossArchitectureE2ETests.py --bin <完整解压的ARM64包目录> --probes <三个CrossArchitectureProbe程序所在目录>
```

测试分别通过 Kernel32 和 KernelBase 的 CreateProcessW 覆盖 9 种父子组合及孙进程（共 18 个启动用例），以及 9 种运行中附加后再创建子进程/孙进程的组合；验证实际加载的 Hook 和 SOCKS5 数据收发，预期 82 次成功代理连接。同时检查创建失败后的错误码与再次创建，以及调用者自己的 CREATE_SUSPENDED 是否保留。测试只管理自己创建的进程并使用临时便携配置，不改动现有 PL 配置。它不代替 UAC、不同用户、浏览器、UDP 和混合模块的专项验证。

## English

Experimental Windows 11 ARM64 package. Injection/child handling, SSH, MITM/TLS and elevated launch are implemented and built, with user-reported ARM device test success. Completion of the full automated cross-architecture matrix has not been confirmed.
On 2026-11-12 the user reported successful proxying of both amd64 and i386 gonc children launched from a native ARM64 cmd, and from another cmd described as residing in `syswow32`. The latter directory name is recorded verbatim; whether it means SysWOW64 and that parent's active ABI have not been verified. Native ARM64X shell injection and the x64 PowerShell child-process fix also have user-reported device success.
As decided on 2026-11-12, ARM64 adaptation of the browser-specific QUIC policy intervention is not implemented and is deferred, outside the current acceptance scope. The ARM64 host does not enable this policy, including for emulated x64 browsers. This limitation concerns browser-internal policy hooks, not the implementation of ordinary UDP proxying.
Run `ProxyLaneARM64.exe` with all seven bundled binaries. The ARM64 host uses native transport/MITM/SSH backends. Matching-version Hook32 and Hook64 support the x86/x64 target paths; no Intel GUI or backend binaries are needed for these targets.
Injection selects the target's active ABI. Cross-architecture routes use system rundll32 with explicit machine selection and verify the helper before execution. Startup, running-process attachment, elevated launch and child injection share this routing. ARM64EC/x64 mode uses Hook64; arbitrary mixed-module hooks are not separately certified.
An injection scheduling result is not a Hook initialization acknowledgment. On ordinary child injection failure, PL releases only its own suspension, so that child may continue without interception. Strict and elevated launch terminate the newly created target on injection failure.
The package contains no standalone elevation helper, CA executable, debug symbols or test probes. Intel releases remain free of ARM64 binaries. Hook32 retains its XP static-TLS check; XP runtime validation has not been performed here.
For device tests, run the Python command above using native 64-bit Python with psutil and all three probes. Expected results: 18 startup cases through Kernel32/KernelBase, 9 attachment-then-child cases, 82 proxied connections. KernelBase cases also check failed creation and caller-owned suspension. The user's successful UAC, SSH and MITM/TLS tests are separate from this automated matrix.

[Windows on Arm emulation reference](https://learn.microsoft.com/en-us/windows/arm/apps-on-arm-x86-emulation)
