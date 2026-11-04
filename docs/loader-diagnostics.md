# 加载诊断捕获

运行日志右上角、复制按钮左侧的“加载诊断捕获”每次启动默认关闭，不写入配置。
开启后，PL 监听当前会话的经典 DBWIN 通道，记录
`[ProxyLane.Loader.v1] stage=LoadLibraryW error=XXXXXXXX` 格式的加载失败报告，
以及 `[ProxyLane.Hook.v1]` 格式的 Hook 初始化失败报告。仅接收这两个
ProxyLane 命名空间下的格式，不兼容旧前缀。
错误码是八位大写十六进制；接受 LF / CRLF 行尾。PID 来自 DBWIN 数据块。
PL 将错误码转换为系统错误说明，并写入现有有界运行日志队列。
Hook 初始化报告保留阶段、模块和 API 字段；不依赖发送方本地化描述的编码。
原有 PRC 管道日志继续保留，因此开启捕获时，同一初始化失败也可能通过管道
再次显示。调试捕获标记为“Hook 初始化诊断”，不影响原有失败处理。

这是辅助诊断，不修改进程列表的注入状态、子进程放行逻辑或成功判定。
未收到报告不代表加载成功。报告也不是经过身份认证的控制消息，不能用于
自动终止、重试注入或修改安全策略。

## 兼容范围

- 支持同一会话的 x86/x64 输出，接收器位数不必与发送进程一致。
- 不捕获其他登录会话或 Session 0；AppContainer、沙箱和调试器附加状态
  可能导致输出不可见。未承诺这些场景的覆盖率。
- 通道被 DebugView、其他 PL 实例或其他监听器占用时，开启失败并写日志。
  已存在的命名对象不会被接管或触发。关闭捕获后可使用外部诊断工具。
- 接收线程先复制有限数据并释放共享缓冲区，再过滤、入队。待显示队列最多
  128 条，过载时计数并提示丢弃。显示由 UI 定时器处理，不在接收线程中写日志。
- 关闭会停止线程并释放本地对象。发送端暂时持有旧对象时，立即重开可能提示
  占用，稍后重试即可。DBWIN 本身不是可靠广播或保证不等待的传输。
- 实现保留 XP 工具链；低完整性标签仅在支持该功能的系统使用。实际运行验证
  以开发机 Windows 为准，没有据此声称旧系统或全部沙箱已验证。

## 远端代码

DLL 路径全程使用 `GetModuleFileNameW` / `WCHAR` / `LoadLibraryW`，仍保留
现有 `MAX_PATH` 限制，检测截断后拒绝注入。入口名称和 PRC 管道参数保持原格式。
远端加载失败时立即保存 `GetLastError`，通过参数块中的 `FormatMessageA`
函数指针及 ASCII 模板格式化数字错误码，再调用 `OutputDebugStringA`。
无远端管道连接、重试、结果回读或新增事件交接。该输出与 PL 捕获开关无关，
因此关闭内置捕获时仍可使用 DebugView 等工具。只输出失败，成功不输出。

`remoteCode.cpp` 不使用 CRT 格式化、外部字符串常量或额外模块依赖。
系统错误说明在 PL 端使用 `FormatMessageW` 生成，避免调试通道中的 ANSI
转换损坏中文诊断文字。输出 API 本身仍可能受调试器/接收设施影响。

生成并验证两种架构的数组：

```powershell
python scripts/generate-remote-code.py
python scripts/generate-remote-code.py --check
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/test-loader-diagnostics.ps1
# 已编译 bin 下的 Hook DLL 时，额外测试真实注入跳板：
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/test-loader-diagnostics.ps1 -HookDirectory bin
```

生成脚本使用 VS 2019 的 14.16 编译器，提取单独代码段，拒绝包含重定位的
对象文件。机器码写入 `src/remotecode/remoteCode.x86.inc` 和 `.x64.inc`。
测试在新地址执行复制后的机器码，并验证真实跨进程调试输出、两种位数互收、
非匹配消息过滤、通道冲突、队列上限、关闭/重开，以及 CP936/UTF-8 进程中的
非 ASCII 路径加载（实际系统传统代码页由测试打印）。
