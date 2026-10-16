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
  也不阻止普通回调执行。已有 hook 时再次调用 `gp_HookWinsock` 返回 `FALSE` / `ERROR_ALREADY_EXISTS`，不重装补丁。
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
- Win32/x64 TCP/UDP 真实流量与精确统计、安装失败重试、重复安装拒绝、
  三轮显式卸载／再次安装，卸载后入口字节恢复，缓存扩展回调在卸载、重装失败及重装成功后均可用。
- 本地代理服务关闭、重启后，由新的客户端进程继续发送并验证统计。
- 32→32、32→64、64→32、64→64 托管子进程/孙进程启动、SOCKS5 连接和 MSBuild 启动。
- IPv6 阻断、loopback 例外与仅 IPv4 的远程 DNS。

从仓库运行 `tests/run-detours-tests.ps1` 可执行以上 Release 回归。需要 VS 2019 的
v141_xp/v142、Windows SDK、项目所用 ATL/MFC，以及 PATH 中的 Go、64 位 Python
（含 psutil）、Rust/cargo/rustup；解决方案会构建已有的安全传输组件。
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

尚未验证 XP/Windows 7、Windows 11 或 Windows on ARM 的运行环境。保留 v141_xp
编译配置不等于已经完成旧系统运行认证。此次没有扩展原有的 Winsock 多 provider
处理方式，扩展函数仍各保存一个原函数指针；第三方 provider 组合需要单独测试。
