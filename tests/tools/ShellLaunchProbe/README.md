# Shell 启动接管验证

`ShellLaunchProbe` 是测试工具，不进入发行包。默认通过桌面 Explorer 的 `IShellDispatch2::ShellExecute` 启动 `D:\tools\test.exe`。不向 Explorer 注入 DLL。

## 正式 Hook

`src/ProxyLaneHook/ShellLaunchHooks.cpp` 拦截 4 类 API：ShellExecuteExW、CoCreateInstance、CoCreateInstanceEx、CoGetClassObject，以及 3 种接口方法：IClassFactory::CreateInstance、IShellDispatch2::ShellExecute、IDispatch::Invoke。

ShellExecuteExW 同时覆盖 shell32 和系统 Windows.Storage 中可用的实现。新版 Windows 的 ShellExecuteA/W 可以在 Windows.Storage 内部直接调用 ExW，绕过 shell32 的延迟导入入口。两个入口按 Detours 实际补丁地址去重，共用改写逻辑和 TLS 重入保护；XP 没有 Windows.Storage 时沿用 shell32 路径。Windows.Storage 只从系统目录动态加载，不新增静态导入。

`--api storage` 可直接验证 Windows.Storage 的 ShellExecuteExW 入口；系统没有该导出时返回 77。正式 E2E 在入口可用时验证 32/64 位改写、目标及跨位数子进程的 SOCKS 流量、过滤策略和卸载后的恢复。

应用创建 Shell 对象成功后，直接取得最终接口。ShellWindows 路径主动调用 FindWindowSW → QueryService → QueryActiveShellView → GetItemObject → get_Application；这些 getter 及 QueryInterface 都不再被 Hook。类工厂入口只修改 CreateInstance，等应用真正创建对象后才发现最终接口，不预先创建实例。Invoke 也不再跟踪返回对象。

不拦截 CoUnmarshalInterface；仅通过解封送取得且未命中已覆盖虚表的对象不保证接管。相关对象创建后若主动发现或安装最终槽失败，记录错误、释放返回对象并向调用者返回失败，不静默交付未覆盖的对象。没有可用桌面 Explorer 的环境可能因此无法创建 ShellWindows，即使调用者只打算枚举窗口。


COM 按 SDK 虚表槽原位交换指针，保留表前的 RPC 元数据，不修改共享 Ndr 方法入口，不保留跨 apartment 的 COM 引用。读写、恢复处理虚表释放和地址重用；显式卸载沿用项目既有的调用方静止要求。

open/runas 文件请求改写为本套 PL 的 `--auto --profile … --wait-exit --literal-arguments --show-window … --run 原目标 -- 原参数`，不按扩展名筛选。目标交给 PL 现有启动入口，快捷方式沿用 PL 的解析和参数合并逻辑；直接 AppsFolder 地址使用现有 packaged 模式。保留工作目录、显示方式和原参数文本。普通 CLI 继续默认展开环境变量，Shell 请求不二次展开。PRC 初次连接和 rebind 缓存主 PL 路径、身份、配置名；改写遵守子进程开关和过滤策略。助手自身不再被递归注入。

runas 保留原 verb。已提权助手通过内部 `--shell-pipe` 接入原 PRC，用已经取得的 token 显式挂起创建目标，调用 `gp_InjectAndResumeShellChild` 检查策略和注入准备结果后恢复并等待。助手不再调用 `gp_HookWinsock` 给自身安装整套 Hook。管道、策略或注入准备失败时终止尚未恢复的目标；返回成功表示 bootstrap 准备成功，不是同步确认目标 DLL/Hook 初始化完成。

已有 `explorer.exe shell:AppsFolder\AUMID` 特例继续使用 `--internal-launch-app`，激活完成即退出，不等待商店应用最终退出，保留安装器等待 Explorer 的原有流程。

PL 不支持的目标、缺失文件也交给助手，失败写入主 PL 日志，不回退 Explorer/Shell 直接启动。无法转交的 PIDL、显式 class、SEE_MASK_DOENVSUBST 等 open/runas 请求直接失败并记录日志；PRC 通信失败同样不能当作过滤规则放行。非启动 verb 保持原行为。Hook 前已取得且之后未共享已覆盖虚表的 COM 对象不保证被发现。

## 等待与兼容

Shell 返回的 hProcess 是 PL 助手。普通 EXE 模式等待启动结果中的进程，不等待整棵子进程树。主 PL 回复 PID/创建时间，助手核实后等待并返回 DWORD 退出码；打不开、目标消失或身份不匹配时返回 0。启动失败返回 PL 的自动化错误码（如无效目标 5、创建失败 6），不伪装为目标退出码。无主 PL 时，该实例保持消息循环服务目标并在目标结束后退出。普通 CLI 不加 `--wait-exit` 保持原行为。

普通命令保持 v1/v3，等待请求用 v4，Shell 参数扩展用 v5。PRC startup flag 3 保留旧的 536 字节 host 信息，flag 4 增加配置名。新客户端接受旧回复；已启用子进程接管但缺少新版 host 能力时，Shell 启动失败，不直接放行。

## 自动验证

```powershell
./tests/tools/ShellLaunchProbe/build.ps1
python tests/ShellLaunchE2ETests.py --bin build/shell-active/bin --production
python tests/AutomationWaitE2ETests.py --bin build/shell-active/bin --production
python tests/AppLauncherE2ETests.py --bin build/shell-active/bin
python tests/HookStaticTlsTests.py --bin build/shell-active/bin
```

`--production` 让主 PL 注入调用程序，探针自己不安装实验 detour。覆盖 32/64 位、COM/Invoke/命名/BYREF、Shell 句柄等待、原始参数、工作目录，以及目标和跨位数子进程的实际 SOCKS PING/PONG。另测并发 STA/MTA、COM 重新初始化、显式卸载和子进程策略。覆盖本地/Explorer 的直接创建、类工厂和 CoCreateInstanceEx，以及 IDispatch 返回视图。

快捷方式回归使用 pywin32 创建临时 .lnk，对比未 Hook 的 Windows 启动参数、工作目录和显示方式；覆盖 32/64 位、COM/Invoke/Shell、目标及子进程实际 SOCKS 通信、非 .exe PE 文件，以及不支持/缺失目标的失败日志。可用 `--production --shortcuts-only` 单独运行。

测试使用隔离的 portable 目录和自有进程。AppsFolder 测试只注册并清理自己的临时测试包，不更改开发者模式或安装证书。不自动确认 UAC。XP 实机、实际 UAC 交互和真实安装器仍须人工验证。

## 独立实验

探针可用 `--api com|com-factory|com-extended|com-dispatch|local|factory|extended|shell --invoke --named --byref --target 路径 --args 原参数 --cwd 目录`。加 `--redirect ProxyLane64.exe --profile 名称` 会启用探针自己的实验 Detours，不属于正式 Hook 验证。`--wait-exit` 让 Shell 探针等待返回句柄并转发退出码。


## 按需发现与共享虚表实验

正式 Hook 在子进程初始化时不创建 Shell 实例、不初始化 COM，也不添加发现线程。无关 CLSID 直接调用原函数；相关对象创建后按需取得最终接口，并在每次创建时重新检查当前槽，不使用进程级“已经初始化”标记跳过检查。`IShellDispatch2` 继承的 Invoke 与 QueryInterface 返回的 IDispatch 都检查实际槽；按槽去重，不按虚表缓存对象能力。 ShellWindows 每次相关创建都重新查询最终接口，因此会增加这条 COM 路径的查询开销；不把已知表仍有补丁等同于新对象一定使用该表，也不承诺新方案比接口链观察更快。

`ShellLaunchProbe.exe --shared-tables` 是独立实验：第一次实际取得本地 Shell 和 Explorer 对象后，修改 ShellExecute、继承 Invoke 和 QI(IDispatch) 的 Invoke 槽；后续创建对象时不再修补，检查 STA/MTA、释放和重新初始化后的实际回调。标记调用不启动应用，不注入 Explorer。正式方案已使用按需取得共享虚表；单台系统成功不证明 XP/其他系统或所有代理生命周期都共享同一虚表。实际启动及网络通信另由生产回归覆盖。

`python tests/ShellLaunchE2ETests.py --bin build/shell-active/bin --benchmark-only` 输出未 Hook/被 Hook 的无关 ShellLink、本地 Shell 和 Explorer 完整接口链耗时中位数和 P95。它只衡量 COM 创建/发现开销，不代表整个进程启动时间。

生产回归还直接调用提权助手使用的注入接口，覆盖 32/64 位双向注入、子进程实际 SOCKS 通信、管道不存在和目标句柄不可写时保留挂起。该测试不触发 UAC，不能替代真实提权交互验证。

`--audit-active HookDLL PRC管道` 在独立进程中启用正式 Hook，检查初始化没有主动修补现存 Shell 对象；应用创建对象后最终槽被修补，但六种中间方法未改；模拟桌面发现失败时返回错误，模拟最终槽被恢复后能在下一次创建时重新安装，最后显式卸载恢复原槽。测试只修改自身进程的虚表。
