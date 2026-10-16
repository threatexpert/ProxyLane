# Detours 迁移：x86 / x64

## 分支与依赖

迁移已通过 `e45f579` 合并到 `main`，保留依赖引入 `fb535c6`、后端替换
`8f80a84`、回归测试 `8d3ab7f` 三个提交。旧后端最后一个提交为 `4461854`，
使用附注标签 `pre-detours-migration` 保存，便于检出对照版本。
后续 Windows ARM64 原生适配单独评估，不改变此 x86/x64 基线。

Detours 源码位于 `third_party/detours`，固定到 Microsoft 上游提交
`1dbd4ea281d73d478aa8d09a8b83fbd265f715f7`，使用 MIT 许可证。
上游源文件未修改，来源和许可证见该目录的 `UPSTREAM.txt`、`LICENSE.md`。
`Detours.props` 将 `detours.cpp`、`disasm.cpp`、`modules.cpp` 随调用项目编译，
沿用项目的架构、工具集和 CRT。旧的四个 `inlineHook_*.lib` 与 `inlinehook.h` 已删除。

本次仅迁移 Win32/x64 inline hook。DLL 注入、跨位数启动和现有代理策略沿用原实现；
没有添加 ARM64 或 ARM64EC 构建配置。

旧 x64 后端使用入口前 5 字节填充区和入口处的 `EB F9` 短跳转。
当前 Detours 没有主动创建这种 patch-above 布局的接口；其 x86/x64 入口补丁
需要至少 5 字节完整指令或可用的函数尾填充。过短目标会导致本项目中止整批安装。
识别已有 OS hotpatch 的能力不等于支持创建该布局，这是已知的兼容性差异。

## 实现与生命周期

- `HookDispatch.h` 保存带调用约定的原函数指针。Detours 安装时将其更新为 trampoline；
  不再修改占位 C++ 函数，也不再使用 `myAlloc4Bakcode`。
- `HookWinsock.cpp` 在提交入口补丁之前准备配置、回调对象并解析全部导出，
  再通过 `InstallDetourHooks` 执行单次安装事务。准备失败中止事务；未安装成功的
  对象可以清理后重试，成功安装的对象、配置和跳板保持到显式卸载或进程结束。
- 安装／卸载流程仍有串行化锁，防止生命周期请求互相交错。此锁不进入网络调用热路径，
  也不阻止普通回调执行。已有 hook 时再次调用 `gp_HookWinsock` 验证并重新绑定 PRC，
  成功返回 `TRUE`，不重装补丁；参见下文重绑定回归修复。
- 安装和卸载均不枚举、不打开、不挂起宿主线程，也不调用 `DetourUpdateThread`。
  这样避免挂起持锁线程后，安装事务申请同一把锁造成的死锁。
  **事务不保证并发发布原子性**：首次安装时仍有入口指令改写、其他线程指令位置，
  以及入口已改写而 `Original_*` 指针尚未更新的窗口。优先在启动阶段安装；
  这些是明确接受的并发安装风险，功能回归通过不代表消除了风险。
- 移除 `HookCallGate` / `HookCallScope`，不再排空网络调用，也不在每次调用中维护
  全局活动计数、嵌套 TLS 或排空事件。请求管道、socket 表等业务锁及子进程创建 TLS 保留。
- 异步 socket 层保留轻量 `Bypass_*` 包装：已安装时调用稳定 trampoline，未安装时调用
  系统函数；显式卸载后 Detours 会将原函数指针恢复为系统入口。包装本身不创建保护域、
  不等待全局调用门。
- 安装前固定 DLL。`gp_UnhookWinsock` 可以恢复入口补丁、释放 trampoline 和 hook 对象，
  但不会卸载 DLL。`DllMain` 退出路径不自动卸载、不等待、不执行 Detours 事务。
- **显式卸载由调用者保证时机**：调用者必须阻止新的相关调用，并确保没有线程正在执行
  受影响的函数入口、trampoline、hook 回调、`Bypass_*` 或缓存的扩展回调，直到卸载返回。
  仅拿到生命周期锁、等待一定时长或看到线程暂时空闲，都不等于满足这个条件。
  不支持在活动 hook 回调内部调用卸载；待完成的异步活动也须由调用者确认不再使用相关状态。
- 卸载准备失败中止整批事务，保留对象、配置和原函数指针；成功后删除对象、清理子进程
  guard 并允许再次安装。没有 hook 对象时返回 `FALSE` / `ERROR_NOT_FOUND`（1168）。
- 应用可能长期缓存 `ConnectEx` / `WSASendMsg` 回调。两个包装函数在无启用对象时直接
  调用保留的 provider 原函数，避免卸载后解引用已删除对象；再次安装成功后重新使用代理逻辑。
  这个状态判断没有活动计数、TLS 或全局锁，也不提供与卸载并发执行的安全保证。
- GUI 开始／停止沿用本地代理服务的启停流程，不新增宿主 hook 的逻辑开关。

## 验证

当前 Release 回归覆盖：

- Win32/x64 完整解决方案编译与现有单元测试。
- 相对 CALL、短/近条件跳转、x64 RIP 相对 LEA/MOV 的 trampoline 执行结果。
- 无效参数、重复绑定、安装和卸载的批量准备失败中止与重试，以及原指针／入口／页面保护恢复。
- 每个 Detours 用例在独立进程运行；单线程下反复安装／卸载，或安装后四线程调用，
  等待全部工作线程退出后再卸载。不把并发改写竞态包装成已保证安全的测试。
- Win32/x64 TCP/UDP 真实流量与精确统计、安装失败重试、同一服务重绑定与无效服务拒绝、
  三轮显式卸载／再次安装，卸载后入口字节恢复，缓存扩展回调在卸载、重装失败及重装成功后均可用。
- 本地代理服务关闭、重启后，由新的客户端进程继续发送并验证统计。
- 同一个真实 cmd 跨两个 ProxyLane GUI 进程存活：curl 首次代理、GUI 退出后直连、
  新 GUI 启动但未重绑定时直连、重绑定后恢复代理；x86/x64 两组均检查 PID/创建时间不变。
- 32→32、32→64、64→32、64→64 托管子进程/孙进程启动、SOCKS5 连接和 MSBuild 启动。
- IPv6 阻断、loopback 例外与仅 IPv4 的远程 DNS。

从仓库运行 `tests/run-detours-tests.ps1` 可执行以上 Release 回归。需要 VS 2019 的
v141_xp/v142、Windows SDK、项目所用 ATL/MFC，以及 PATH 中的 Go、64 位 Python
（含 psutil）、Rust/cargo/rustup；解决方案会构建已有的安全传输组件。
重绑定 E2E 还需要系统的 x86/x64 curl，以及一个本机非 loopback IPv4 接口。
仅运行单元测试可使用 `tests/run-tests.ps1`。

完整 E2E 最好从未被其他 ProxyLane 代理的进程启动。Python 测试运行器仅在启动工作线程和
网络 I/O 之前，尝试解除自身继承的 Hook，由运行器保证这一时机。若解除失败，测试会明确
报错，不能忽略失败后混用两套 Hook，也不会修改用户正在运行的代理进程。

2026-10-16 恢复由调用者保证时机的显式卸载后，Win32/x64 Release 完整回归通过，
包括安装／卸载失败回滚、工作线程结束后卸载、三轮重新安装及缓存扩展回调。日志位于
`build/qa/explicit-detach/regression.log`。没有恢复调用门、线程挂起或 GUI 自动卸载。

2026-10-16 首次常驻 hook 调整已在 Windows 10 x64 / VS 2019 通过当时的 Win32/x64
Release 回归，日志位于 `build/qa/hook-lifecycle/regression.log`。未进行吞吐量基准测试，
不把移除同步操作表述为已测得的性能提升。

2026-10-15 合并后，已在原工程目录重新构建 Win32/x64 Release 并通过完整回归。
日志保存在 `build/qa/detours-merge`。运行中的另一套 ProxyLane 曾向测试服务和探针
注入第二份 Hook DLL，导致 UDP 超时；流量测试现与托管启动测试一样，仅解除一次性
Python 测试进程继承的 hook，再创建受控子进程，不修改用户正在运行的代理。
上述为原迁移时的验证记录。当前发行包只在根目录携带 `LICENSE-Detours.txt`，
不附带来源说明，也不创建 `third_party` 目录。
迁移 worktree 的构建产物及日志另存于 `build/detours-migration-archive`。

## 2026-10-16：同一宿主跨服务退出重开的重绑定修复

修复基线为 `main a14a721`，分支 `codex/hook-rebind-fix`，在独立 worktree 开发，
没有包含主目录的未提交功能。ARM64 分支另行维护，本次不合并其代码。

`v1.2.16` 的 `gp_HookWinsock` 在对象存在时先调用 `SetPRCPipeName` 再返回 FALSE。
迁移提交 `8f80a84` 将该分支改成直接返回，丢失了更新服务地址的副作用。
退出 GUI 不会让存活宿主中的 Hook 失效；新 GUI 的 PRC 管道 GUID 改变，因此重复注入
必须允许已安装对象更换服务地址。原测试中的“重复安装应拒绝”断言错误地固化了这个回归。

现在重复调用走 `RebindPRC`：先用独立连接验证新服务、登记当前进程身份，成功后在现有
请求管道锁内断开缓存控制连接并发布新管道名，然后发送 Hook 成功通知。新服务不可用时
保留原绑定。通知发送失败发生在绑定发布之后，不回滚已生效的绑定，可以再次调用重试。
此路径不执行 Detours 安装/卸载，不创建新 Hook 对象，不等待所有网络回调排空。
临时 DNS/关闭 socket 请求使用加锁复制的管道名；子进程查询和注入使用同一份快照。
名字锁与请求 I/O 锁分开，读取管道名不必等待另一个线程完成阻塞式管道请求；名字锁内不做 I/O。
切换时已经开始的临时请求可以完成于旧服务，不承诺迁移既有 TCP/UDP 连接。

测试 `tests/HookRebindE2ETests.py` 使用两个真实 GUI 进程，按管道服务器 PID 找到各自的
管道，通过生产 `rundll32/AttachTo` 路径代理同一 cmd，再让它执行系统 curl。测试只连接
本机 HTTP/SOCKS5 服务：直连返回 DIRECT，经过 SOCKS5 返回 PROXY，避免把 curl 成功
误判为代理成功。GUI 使用 WM_CLOSE 正常退出；清理只处理测试拥有的 PID。

复现：

```powershell
python tests/HookRebindE2ETests.py --bin bin
# 单独验证 x64（完整回归默认验证两架构）：
python tests/HookRebindE2ETests.py --bin bin --bits 64
```

未修复基线已在 `build/qa/rebind/baseline-test.log` 留下预期失败：第一次代理、退出后
直连均完成，第二次重绑定后仍为 DIRECT。每次测试的 `results.json` 保存宿主 PID、
创建时间、两次 GUI PID、不同的管道名和逐请求路由证据。完整回归日志在
`build/qa/rebind/regression.log`。

最终验证通过：Win32/x64 Release 构建与单元测试、TCP/UDP 统计及显式卸载、四种父子/
孙进程组合、MSBuild 启动、IPv6/DNS，以及新的两架构重绑定 E2E。
最终重绑定证据位于 `build/qa/hook-rebind-1ae8f2ff/results.json`，x86 cmd PID 111452、
x64 cmd PID 109712 均跨服务进程重启存活并恢复代理。主目录原有 49 个未提交/未跟踪
文件已与操作前 SHA256 快照比较，内容未变；修复产物仅生成于独立 worktree 的 `bin/`。

## 对 v1.2.16 → a14a721 的行为差异复核

复核涵盖全部产品代码差异，并区分原迁移、后续明确约定的生命周期调整和旧有局限。
没有把当前主目录的其他未提交修改算入 Detours 迁移。

| 变化 | 影响与处理 |
|---|---|
| 已安装对象拒绝重复调用 | 确认的非预期回归，本次修复。新返回值为实际重绑定/通知结果，不保留旧版“改了地址却返回 FALSE”的不一致行为。 |
| 单个 Hook 顺序安装改为整批事务 | 某个目标解析或准备失败时不再保留部分 Hook；成功提交才设置启用状态。属于安装失败语义的有意变化，已有回滚/重试测试。 |
| 入口前填充区短跳方案改为 Detours 重定位 | 太短或 Detours 无法重定位的目标可能导致整批失败；这是明确的后端兼容性差异，尚未实现旧库的两字节入口方案。 |
| DLL pin，退出不自动卸载 | 正常 FreeLibrary 不再卸载 DLL；进程退出不执行 detach 事务。显式卸载仍恢复补丁并释放对象，DLL 留存。属于此前确认的生命周期约定。 |
| 安装失败清理对象，卸载失败保留对象 | 改善失败后重试与回调有效性；不再沿用旧版部分失败状态。无对象卸载增加 ERROR_NOT_FOUND。 |
| `Bypass_*` 改为每次读取当前原函数指针 | 内部 socket 对象不再保存可能已释放的 Detours trampoline；即使对象早于安装创建，也会选择当前旁路函数。是明确的调用路径变化，未做吞吐量定量承诺。 |
| 扩展函数原地址跨对象保存 | `ConnectEx`/`WSASendMsg` 缓存回调在显式卸载后仍能转发原函数；原先对象删除后的访问不再受支持。单槽缓存可能被不同 provider 覆盖的问题在旧版成员指针中也存在。 |
| 目标模块加载 | 从每次 LoadLibrary 改为已加载时复用，减少额外引用。当前目标为 ws2_32、advapi32、kernel32/KernelBase；前两者是 Hook DLL 的静态依赖，后两者属于进程系统模块。本次没有改为支持可卸载的任意插件模块。 |
| HookCallGate、线程枚举/挂起 | 中间迁移版本引入，随后已按约定删除；当前只有生命周期串行化锁，未新增并发安装/卸载安全保证。 |

比对确认 `InjectDll.cpp`、`ElevatedLauncher.cpp`、`PRCPipeClient.cpp`、
`ProxyReceptionCentre.cpp`、`GlobalProxy.cpp` 和 GUI `Page3.cpp` 在该迁移范围内没有差异。
Hook API 选择、TCP/UDP/DNS 策略分支及 GUI 开始/停止业务没有被替换；函数转发存储方式改变。
除重绑定外，本轮未确认第二个非预期的用户行为回归；代码审查与现有测试不能证明所有
宿主、系统版本和网络 provider 都等价。

另外发现两个与重绑定相关、但 **v1.2.16 已存在** 的局限，本次保持边界不扩大改动：

- 已安装宿主的 `m_psi` 和 Hook 选择保留首次安装配置，重绑定不做热更新。新子进程初次
  安装时从新服务读取配置。不能直接对运行中的对象重跑 EnableHook 并改写配置字段。
- 子进程 watchdog 环境标记沿用首次服务生成的名字，新 GUI 不能凭该旧标记识别重绑定
  宿主遗留的孤儿挂起子进程。普通子进程创建由父进程自身恢复，本次 cmd/curl 场景不依赖
  watchdog；跨服务刷新该标记需要单独处理与进程创建/环境继承的并发一致性。

尚未验证 XP/Windows 7、Windows 11 或 Windows on ARM 的运行环境。保留 v141_xp
编译配置不等于已经完成旧系统运行认证。此次没有扩展原有的 Winsock 多 provider
处理方式，扩展函数仍各保存一个原函数指针；第三方 provider 组合需要单独测试。
