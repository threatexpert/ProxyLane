# 项目实现约束

## 注入 DLL 的 Windows XP 兼容约束

- `ProxyLaneHook32.dll` 需要在 Windows XP 上通过 `LoadLibrary` 动态加载到目标进程。注入 DLL 及其链接对象、静态库不得引入编译器静态 TLS，包括 `thread_local`、`__declspec(thread)`，以及依赖这些机制的隐式初始化。保持现有 `/Zc:threadSafeInit-` 构建约束。
- 每线程状态沿用项目现有的 `TlsAlloc`、`TlsGetValue`、`TlsSetValue` 按需初始化方式；处理分配失败，并在所属线程的既有关闭路径释放对象。不得为此在 DLL 加载/卸载回调中执行窗口、网络或复杂对象的创建和销毁。
- 此约束针对可注入的 Hook DLL，不扩展为对独立宿主、可选 64 位模块或所有 TLS API 的禁用；修复兼容性问题无需更换现有注入和 Hook 架构。
- 发布前运行 `python tests/HookStaticTlsTests.py`，检查最终 Hook DLL 的 PE TLS 目录，防止链接依赖重新引入静态 TLS。主程序启动、静态导入 DLL 或新版 Windows 上注入成功，都不能代替 XP 动态加载兼容验证；尚未在 XP 实测时须明确说明。
- 回归背景：1.3.10 的 DoH 查询状态曾使用 `thread_local Queries queries`，导致 XP 注入时在 `__dyn_tls_init` / `DohResolver.cpp` 初始化阶段崩溃，即使没有启用 DoH 也会触发。微软限制说明：https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-data

## UDP 来源地址恢复：不采用

决定：UDP 回包来源地址恢复技术当前不认为可靠和稳定，本工程不采用。此约束适用于后续维护和新增功能。

- DoH 接管应用 DNS 请求后，可以通过现有本地 UDP 中继回包，但必须保留实际来源地址和端口，不改写为应用最初请求的 DNS 服务器。
- 客户端如果校验原 DNS 服务器的来源地址而拒绝本地中继回包，按不支持处理，不为其增加来源地址伪装或恢复。
- 不得为了恢复 UDP 来源地址新增或扩展 `recvfrom`、`WSARecvFrom`、`WSARecvMsg` Hook；不得通过 `WSAIoctl` 替换接收扩展函数实现此目的。
- 不得为此跟踪或改写应用的 OVERLAPPED、完成回调、事件或 IOCP 完成结果，包括 Hook `WSAGetOverlappedResult`、`GetQueuedCompletionStatus`、`GetQueuedCompletionStatusEx`。
- UDP `getpeername` 同样不得改写为原 DNS 服务器地址。既有 TCP 对端地址处理不属于本次撤销范围。
- 不得以其他机制绕过这一决定，也不得以兼容性修复、测试通过或功能完善为由自行重新引入。若未来需要重新评估，必须先提交具体方案并取得用户明确批准，再实施。
- 测试和文档不得承诺来源地址透明；测试应验证实际本地中继地址未被改写。

## DoH 事件驱动约束

- DoH 完成、回包、TCP/TLS 推进和地址重试使用现有消息循环/套接字事件，不使用高频定时器轮询或推进。
- 定时器可用于超时、空闲回收和延迟清理；不得在维护定时器中检查 DoH 完成状态或调用 DoH Pump。
- 通知必须处理取消、对象销毁后的过期消息、共享查询和消息投递失败，不能恢复为定时轮询兜底。

## 运行日志语言

- 运行日志的信息使用英文即可，不要求中英文切换或双语文案。
- 此约定针对运行日志，不改变界面文案的语言要求。
- DoH 查询日志默认记录开始和结果（包括失败原因），避免等待数据报等冗余过程日志；必要时可以补充有价值的 CNAME 跳转等事件，不硬性限制每次查询只能两条日志。开始文案不得将缓存命中、共享查询或本地拒绝误述为新发起远程查询。
- DoH 结果日志保持简短：显示状态、A/AAAA 的 IP、耗时及适用的缓存/共享标记；非缓存命中的成功结果另外显示 PL 实际采用的缓存有效期 `cache_ttl=Ns`，零表示不缓存，缓存命中和失败结果不显示此字段。不展开各记录的 TTL、CNAME 或其他记录详情，不为日志累计跨响应 CNAME 记录。实际 DNS 解析和 TTL 缓存逻辑不受此限制影响。
