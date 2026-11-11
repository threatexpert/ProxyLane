# 实时协议还原接入（开发验证版）

“开始监视”是采集的统一入口；HTTPS 和 QUIC 解密均是默认关闭的选项，保存后在开始监视时校验 CA 和模块依赖。停止监视同时停止新连接解密、明文采集、协议分析和缓存写入，但已经接管的 TLS/QUIC 连接继续转发，旧连接不会在重新开始监视时恢复采集。流量监视页提供简单的会话列表和详情视图，没有 Web 服务。

## 数据链路

`CMitmBridge` 将连接编号、PID、进程创建时间、socket、socket 代次和目标地址传给 MITM。Rust 的 `Session` 在上游握手完成后读取实际协商的 ALPN，创建分析流；每次从 rustls reader 取出的完整明文同时交给原监视回调和独立分析队列。

队列按连接保留双向事件的因果顺序，并记录每个方向从 0 开始的绝对明文字节偏移。独立 worker 调用 `ProxyLaneProtocol::Analyzer`，完成 HTTP/1.1、HTTP/2 请求响应配对、正文解压与载荷缓存。进程信息来自 PRC，不从 HTTP 内容推测；连接编号与简单数据监视日志一致。

- ALPN `h2` → HTTP/2；`http/1.1` → HTTP/1.1。
- 没有 ALPN 时，有限缓存首个客户端请求行或 HTTP/2 preface，确认协议后从偏移 0 重放。
- 其他 ALPN、无法识别的应用协议、server-first 非 HTTP 流转为双向字节流缓存。检测中的客户端前缀完整重放，检测最多等待 2 秒；不把 TCP read 当作消息边界。未解密的 TLS ClientHello 特征标为 encrypted，解密后的流标为 decrypted。
- 不按 443 端口判断；非标准端口同样生效。
- `close_notify` 只有在 rustls reader 的缓冲明文读完后才传为 clean EOF。裸 TCP EOF 传为不完整关闭；释放连接传为 capture close，不伪造协议正常结束。
- 解析、解压和磁盘写入均在后台线程。首次创建 MITM 会话会初始化分析服务和缓存目录；后续明文回调只执行有上限的复制和 `try_send`，不等待分析或磁盘。

## 限制与异常处理

| 项目 | 当前默认值 |
| --- | --- |
| 同时分析的 TLS 连接 | 32 |
| 每连接未完成 HTTP 请求 / H2 stream | 8 |
| 明文输入队列 | 512 个事件，数据片段最大 16 KiB（约 8 MiB） |
| 每个消息正文预览 | 编码前后各最多 64 KiB |
| 还原结果保留 | 最多 256 条且序列化后最多 16 MiB |
| 每次 poll | 最多 64 条且内容合计最多 2 MiB |
| 单个请求+响应的缓存载荷 | 合计 32 MiB |
| 本实例总缓存载荷 | 512 MiB |
| 缓存读取 | 每次最多 64 KiB |
| 按需解压 | 完整编码载荷最多 32 MiB，输出最多 4 MiB |

队列满时，当前连接设置独立于队列的丢失标记，停止接收后续分析数据；worker 消费完已接受的前缀后输出溢出诊断和未完成的请求。绝不跨越缺口继续解 HPACK。超过连接数或新连接入队失败通过 `rejected_connections` 计数报告；不影响正常网络转发。缓存队列满或达到容量限制只影响载荷保留，HTTP 边界解析仍继续。

结果环形缓冲淘汰旧结果，并在 poll 返回 `lost_before`；载荷缓存按先完成的请求淘汰旧载荷。两者独立管理，不能以旧结果里的缓存快照推断载荷仍在，需查询 `cache_status`。没有落盘历史记录或默认抓包 JSONL。

缓存不可写时仍进行有限的内存还原，`stats.cache_error` 报告原因。单个协议错误不终止 TLS；原有 TLS 验证失败与网络错误的处理不变。

临时目录为 `%TEMP%\ProxyLane\protocol-cache-v1\run-<128-bit random>\`，每个 ProxyLane 实例拥有单独目录、配额与持有的 owner 锁；启动跳过活跃实例，只清理能获得锁的崩溃残留。停止代理（PRC 会话释放后）或释放代理宿主时，join 后台线程、关闭文件并清理本次运行目录。根目录里的空 `manager.lock` 可以保留。

## 多实例 CA 与 CRL

多个实例共用磁盘上的同一个 CA；`ca.json` 中的 `crl_port` 只是首选端口（默认 18767）。每个进程创建 TLS Context 时先尝试绑定该端口；已占用或不可用时直接绑定 `127.0.0.1:0`，由系统分配空闲端口，避免先查空闲端口再绑定的竞争。运行时端口不写回共享 CA 文件，不需要重新安装 CA。

网站证书的 CRL Distribution Point 使用本实例实际绑定的端口，证书缓存按域名与端口区分。CA 管理显示本实例的运行地址；尚未启动时显示 `not started in this instance`，查询状态不会启动监听。独立 CA 命令行工具输出的 `crl_port` 仍指磁盘首选值，不代表其他进程的实际监听地址。

CRL 服务由进程 TLS Context 持有，不随“开始监视”或“解密 HTTPS”开关停止，以便已有连接继续进行证书校验。实例退出时释放其端口，其他实例继续服务自己的 CRL。CRL 只监听 loopback；保留正常的证书信任与吊销检查。旧版本占用首选端口也不会阻止新版启动。

## 后台查询接口

使用现有 `IGlobalProxy::GetTlsControl()->QueryProtocol(request, output, capacity)`，无新增 Hook DLL 的 `gp_Mitm` 导出。MITM DLL 内部 ABI 升为 6，增加内部 `plm_protocol`；Hook 和 MITM DLL 必须配套更新。

请求/响应为 UTF-8 JSON。接口在消费者后台线程调用，不能从 PRC 回调调用，可能等待分析或磁盘查询。返回正数是包含末尾 NUL 的所需缓冲区大小；缓冲区不足时不写入，可增大重试；返回 -1 时缓冲区中是错误文本。poll 非破坏性，消费者维护序号，重试不会吃掉事件。

```json
{"type":"stats"}
{"type":"poll","after":0,"limit":16}
{"type":"cache_status","run_id":"<stats/poll 返回值>","cache_id":1}
{"type":"cache_read","run_id":"<同上>","cache_id":1,"direction":"server","offset":0,"length":65536}
{"type":"cache_decode","run_id":"<同上>","cache_id":1,"direction":"server"}
```

每次启动分析服务生成新的 `run_id`。消费者发现 run_id 改变需重置 poll 序号；读取旧 run_id 的缓存会失败，防止代理重启后 cache_id 重用造成串数据。`direction` 为 `client`（应用发出）或 `server`（目标返回）。`exchange.id` 为 HTTP/1 顺序号或 H2 Stream ID；缓存 ID 在本次后台运行内全局分配。

`stats` 包括活跃/拒绝连接数、结果保留/淘汰量、缓存用量/峰值/淘汰数/残留清理数/警告。`poll` 返回 `records`、`next`、`last_sequence`、`lost_before`；记录可能是 `exchange`、连接级 `stream`、解析 `diagnostic` 或接入层 `analysis_diagnostic`。未启用后台或停止后查询返回 `{"type":"inactive"}`，查询不会启动服务。

内部 `{"type":"shutdown"}` 用于宿主在释放会话后停止后台；普通消费者不应调用。缓存读取无路径参数，只能读本实例管理的载荷。

## 构建和测试

`scripts/build-mitm.ps1` 已自动编译链接协议 library，仅输出 64 位 MITM DLL；无需启动 `ProxyLaneProtocol*.exe`，也不增加额外协议 DLL。主程序和 Hook 按现有 solution 的 Release/Win32、Release/x64 编译到 `bin`。

`bin` 仅存放运行组件。CA 命令行工具 `ProxyLaneMitm64.exe` 和独立协议验证工具 `ProxyLaneProtocol32/64.exe` 输出到 `build/tools`，不进入发行包；测试探针和每次测试的隔离运行目录放在 `build/qa`。

```powershell
cargo test --manifest-path src/ProxyLaneMitm/Cargo.toml --locked
cargo test --manifest-path src/ProxyLaneMitm/Cargo.toml --locked --release --target i686-pc-windows-msvc
cargo clippy --manifest-path src/ProxyLaneMitm/Cargo.toml --locked --all-targets -- -D warnings
python tests/e2e/mitm_e2e.py --arch 64 --protocol
python tests/e2e/mitm_e2e.py --arch 64 --protocol --multi-instance
```

端到端测试需要先编译 `mitm_host64.exe`（命令见 tests/e2e/README.md），以及 Python cryptography、h2、brotli、zstandard。创建专用 CA 并在 finally 移除，系统可能弹出一次安装确认；使用注入的 curl/Python、真实 Hook/PRC、SOCKS5/CONNECT 和本地 TLS origin。覆盖 32 位 curl、关闭监视、非 443 端口、无 ALPN、chunked+gzip、H2 多路乱序+动态 HPACK+Brotli/zstd、双连接复用 Stream ID、大载荷限额/淘汰及退出清理。Rust 测试另外确定性验证队列溢出、关闭通知、不可写缓存、连接与结果上限。

测试可通过 `PROXYLANE_PROTOCOL_CACHE_ROOT` 隔离缓存目录，通过 `PROXYLANE_PROTOCOL_ENTRY_BYTES` / `PROXYLANE_PROTOCOL_TOTAL_BYTES` 设置字节限额。正式默认值保持上表；这些是宿主启动环境配置，界面尚未暴露。

`--multi-instance` 同时启动两个真实 PRC 宿主，分别注入 Schannel curl，两个宿主均为 64 位，覆盖目标 curl 的 64/64 位与 32/64 位组合、首选端口被其他程序占用、关闭监视和解密开关后 CRL 仍可用、退出一个实例后另一个继续建立 HTTPS 连接。检查客户端实际拿到的证书 CRL 地址及签名，直接读取并验签两个实例的 CRL；curl 不使用跳过证书或吊销检查的参数。仅清理测试 CA 的指定 CRL URL 缓存，不清空用户系统缓存。

主要代码：`src/ProxyLaneHook/MitmBridge.cpp`（身份与接口桥接），`GlobalProxy.cpp`（停止清理），`src/ProxyLaneMitm/src/session.rs`（明文/EOF 接入），`protocol.rs`（分析 worker、配额、结果查询），`src/ProxyLaneProtocol/src`（协议解析与载荷缓存）。

## 最小会话视图

数据监视页勾选“开始监视”，会话列表按加入顺序显示，不分组；序号、进程名、PID 各自独立成列。支持进程名或地址的子串搜索、纯数字 PID 精确过滤，以及 HTTP/TCP/UDP/TLS 类型过滤。过滤只影响展示，不改变采集或缓存。在 MITM 会话创建时按 PID + 创建时间校验并保存进程名，进程退出后仍能显示；权限不足等导致无法取得时才保留 PID。“请求”/“响应”页签显示各自的头、trailer 和正文；简单页面不再提供原始网络日志，也不启用原始监视队列；详情右侧为 Raw / HexView，默认 Raw，每条会话独立记住设置。两种视图均包含还原后的 HTTP 头和解压正文；HTTP/2 的 HexView 是还原内容的字节表示，不是原始 HPACK 帧。普通 TCP/UDP 只显示实际载荷。描述、截断、淘汰提示在内容框上方，空正文不追加文字。独立原生 HexView 按字节绘制可见行，支持偏移、字符栏、字节选择、键盘滚动和复制；二进制和空正文不锁定视图。上下区域可拖动分隔条调整。

HTTP 结果在请求/响应完成或连接分析结束时加入列表；HTTP 大文件传输期间尚不显示下载进度。TCP/非 HTTP TLS 则按连接显示，活动字节数最多每 500 ms 发布一次，UI 以 run_id + connection.id 更新原行，保留选择及 HEX 设置。流详情使用发送/接收页签，直接读缓存前 64 KiB，不执行 HTTP 解压；关闭、停止、缓存截断、淘汰均有标记。UDP 按进程/socket/目标分为会话，保存各方向的数据报偏移和长度，通过详情下拉选择单个数据报（包括零长度数据报），每方向最多索引 256 个包，超出时提示；UDP 不进入 HTTP 猜测。STARTTLS 升级和 WebSocket 消息还原尚未提供。

- UI 每 500 ms 在工作线程查询最多 32 条结果，列表最多 512 条且元数据最多 8 MiB；不保留每条结果携带的正文预览副本。
- 选中记录后，后台通过当前 run_id + cache_id 查询状态、读取和解压。缓存已淘汰或已失效时保留头部，正文区明确提示不可用；截断、未完成和解码错误单独显示原因。
- 完整正文解压仍受后台 4 MiB 上限约束，界面最多展示前 64 KiB，不改变缓存大小。无法完整解压时仅显示标注的可用前缀，压缩前缀强制 HEX；非 UTF-8/二进制也使用 HEX，不猜测字符编码。
- 当前选择每 2 秒复核缓存状态；状态不变不重复解压。淘汰后清除正在显示的正文。
- 切换选择、清空或监视状态变化通过 epoch/key 忽略旧工作结果；工作线程不持有窗口指针。“清空”清除本地视图并把查询游标移动到当前末尾，不清除其他消费者的后台结果或载荷缓存。

代码：`Page4Protocol.cpp` 管理控件和异步查询；`ProtocolViewModel.cpp` 管理结果投影、按需读取及限制。JSON 使用固定版本 nlohmann/json 3.11.3（MIT，`third_party/nlohmann`）。

`tests/ProtocolViewModelTests.cpp` 覆盖缓存状态、运行代次、正文和元数据限制，支持回放真实 MITM 查询日志；`tests/ProtocolPageHarness.cpp` 创建真实页面控件并使用测试查询服务，覆盖分组、选择、正文、HEX、淘汰刷新、缩放、列表上限、清空、进程名快照、地址简化和每请求 HEX，不安装证书、不启动代理。

页面回归测试（先构建对应 Release 主程序和资源）：

```powershell
.\scripts\test-protocol-view.ps1 -Architecture x64
.\scripts\test-protocol-view.ps1 -Architecture x86
.\scripts\test-protocol-view.ps1 -Architecture x64 -Page
.\scripts\test-protocol-view.ps1 -Architecture x86 -Page
python tests/MonitorLayoutE2ETests.py --language zh-CN
python tests/MonitorLayoutE2ETests.py --language en-US
python tests/MonitorTrafficE2ETests.py
```

协议结果的 connection 增加 process_name、server_name、server_port（缺失时按默认值兼容旧输入）。destination 继续保留原始域名/IP/端口供底层分析，界面使用 server_name:server_port；IPv6 字面量保留方括号，不在域名后重复显示内部映射 IP。

### 被动 TCP 通路

`CProtocolTap` 在已协商代理隧道的 `CPRCTcpPeer::Receive` 路径观察实际收到的数据；不观察 SOCKS/CONNECT 握手，不拥有或改变套接字。无 MITM 时才创建，避免密文和明文重复记录。`monitor_start`/`monitor_stop` 经现有 `QueryProtocol` 控制本实例的新 TCP 采集；关闭后已有 tap 在下次数据到达时停止，不从中途重新拼接。开启监视前已建立的普通 TCP 连接需重新连接。内部 DLL ABI 6 增加 `plm_stream_open`/`plm_stream_io`，Hook 对外仍保持原来的导出集合。

`stream` 记录包含连接身份、sent_bytes/received_bytes、finished/complete、problem 和 cache。它与 HTTP 共享单条/总量限制、后台写盘队列、完成载荷淘汰、退出和崩溃残留清理。队列丢失后只保留连续前缀并终止采集，网络转发继续。


## 会话视图补充

### DNS 与 QUIC

- 普通 DNS：UDP/TCP 53；UDP 非标准端口仅在首包通过 DNS 解析时启用。TCP 使用 2 字节长度前缀处理拆包/粘包。mDNS、DoH、DoT 的专门解析不在本阶段范围内。
- 使用 hickory-proto 0.24.4（关闭默认功能），DNS 名称压缩和资源记录交给库处理。锁文件保留兼容 Rust 1.82 的 idna_adapter 1.1.0；协议独立构建还固定兼容的 jobserver 0.1.32。
- 每次查询生成稳定 `run_id + connection.id + exchange.id`，请求/响应更新同一行，保留序号和 HexView 选择。配对键包含事务 ID 与规范化问题列表，进程身份沿用连接快照。相同待处理查询按重传计数，最近完成响应去重；ID 重用产生新事务。不声称能区分完全相同 ID/问题重用后的迟到响应。
- 每连接最多 64 条待响应查询，10 秒超时；最多保留 64 个完成去重键。TCP 缓冲最多一条 65535 字节消息加一个输入块；DNS 问题最多 16、资源记录最多 256。未配对、畸形、超时、关闭及队列丢失均保留明确状态。
- 每条 DNS 请求/响应使用独立的现有载荷缓存；Raw 按需从缓存解析，HexView 为 DNS 原报文字节（TCP 的长度前缀不计入消息）。淘汰或截断后不使用另一份常驻正文绕过缓存。列表字节数是首条查询及配对响应的报文长度，不累计重传。
- QUIC 使用现有 rustls 的 Initial 密钥和 AEAD/包头保护 API，支持 RFC 9001 v1 与 RFC 9369 v2；仅认证成功才改标 QUIC，443 端口不是识别依据。支持合并长包、Initial 包号重建、CRYPTO 乱序片段及一致重叠；每连接最多 4 个 Initial 上下文、128 次 Initial 检查，每上下文 CRYPTO 上限 64 KiB。
- Raw 为连接握手摘要：可见 SNI、客户端提供的 ALPN、ECH 是否出现、Initial DCID；ALPN 不是服务器已协商协议。ECH 时 SNI 可能只是外层域名。HexView 为选中方向和数据报的捕获原始字节。无 Initial、未知版本或未通过认证时仍显示 UDP，不伪造 HTTP/3 明文；连接迁移后的跨路由合并尚未提供。
- `testdata/rfc9001-client-initial.hex`、`rfc9369-client-initial.hex` 来自相应 RFC 附录 A.2。验证命令：`cargo test --manifest-path src/ProxyLaneMitm/Cargo.toml --locked --lib`；实际注入与界面：`python -X utf8 tests/MonitorUdpE2ETests.py --dns-quic`，隔离配置/本地中继，不安装 CA。

- HTTP 连接由 Rust 携带真实 `decrypted` 标记，显示为 `TLS/HTTP/1.1` 或 `TLS/HTTP/2`；不依据端口、`:scheme` 或请求 URL 猜测是否经过 MITM。非 HTTP 明文 TLS 显示 `TLS`，未解密记录仍明确标记 encrypted。
- HTTP 目标优先读取 `:authority`，其次 `Host`，最后回退连接目标；PID/进程身份仍仅来自连接元数据。列表“载荷 (B)”对 HTTP 指请求/响应正文，对 TCP/UDP 指双向载荷，均不包括网络封装开销。
- 叶证书截止时间为生成时间后 14 天，不超过 CA 的截止时间。已有进程的内存证书缓存需重启后更新，不重新生成 CA。
- `CUdpProxyTask` 在路由匹配后采集应用及远端数据报，socket/目标路由各自持有一个 passive tap；无 SOCKS5 封装，不改变转发。内部 ABI 6 支持 datagram 操作，Hook 对外导出不变。
- `tests/MonitorUdpE2ETests.py` 用隔离配置、真实注入、SOCKS5 UDP relay 和两个 UDP echo 端点验证多路由、多 socket、包边界、零长度数据报及 Raw/HexView；不安装 CA。


### MITM 选项与连接生命周期

- 界面中的 MITM 选项集中提供当前用户 CA 信任管理和目标服务器证书校验开关。默认严格校验；跳过选项保存在程序旁 `ProxyLane.ini` 的 `[options] MitmSkipUpstreamVerify=0/1`，启动时恢复，由新 TLS 会话快照，仍验证 TLS 握手签名和记录完整性。它不改变客户端对 ProxyLane CA 的信任要求。
- 开启解密或监视时，对本实例尚未接入相应采集的 TCP 连接提供断开、仅新连接、取消。任务管理器先标记快照，CA/监视准备成功后才提交；网络线程的任务定时器负责断开。新任务不继承标记，失败或取消清除快照。
- 无载荷的 TCP/TLS 连接也发布连接状态。列表以首个实际请求/流替换连接占位记录并保留序号，不为后续关闭事件增加重复行。握手失败保留错误信息，载荷区留空。
- DNS 列表显示查询域名，详情上方保留 DNS 服务器地址和端口。DoH GET 的 dns 参数与 POST/响应的 application/dns-message 正文使用现有 DNS 解析器；正文先通过原有缓存解压，再解析 DNS。DoH 保留 HTTP 状态、头与请求归属，HexView 仍显示头和实际载荷字节。HTTP/3 通过下述 QUIC 入口接入相同的缓存和 DoH 还原。
- 内部 MITM DLL ABI 升为 8，补充 TCP 建立结果通知；Hook 对外导出不变。选项通过已有 QueryProtocol 接口传递。

同目录程序共用 ini；32 位程序保留但不应用这一配置项。修改立即保存，其他已运行实例不自动同步；写入失败会恢复当前实例原值并提示错误。


### MITM 选项与持久化

GUI 的 MITM 选项新增九项参数，保存到程序旁 `ProxyLane.ini` 的 `[mitm]` 段。
同目录程序共用 ini，32 位 GUI 不应用 MITM 设置；每个已运行的 64 位实例保留自己的配置快照，不热重载其他实例的修改。

| INI 键 | 默认值 | 范围 | 单位/含义 |
|---|---:|---:|---|
| EntryMiB | 32 | 1–1024 | 单条载荷双向合计 MiB |
| TotalMiB | 512 | 16–8192 | 本实例缓存总 MiB，必须不小于 EntryMiB |
| HistoryRows | 512 | 128–10000 | GUI 历史行数；元数据预算同步按每行 16 KiB 扩展 |
| PreviewKiB | 64 | 16–1024 | 每方向正文显示 KiB |
| DecodeMiB | 4 | 1–64 | 按需完整解压的输出 MiB |
| Connections | 32 | 1–256 | 同时参与协议还原的连接数，不限制转发连接数 |
| PendingRequests | 8 | 1–256 | 每连接未完成 HTTP 请求/HTTP2 Stream 数 |
| UdpPackets | 256 | 16–4096 | 每方向保存的 UDP 报文索引数 |
| HandshakeSeconds | 15 | 5–120 | TLS 检测/握手超时秒数，新连接使用保存值 |

显示设置保存后立即生效。缓存和还原配置在下一次开始监视时应用：只有配置确实变化才关闭旧分析运行、清理旧载荷并在新连接到来时创建新运行；旧连接的转发不受影响，完整采集仍需新连接。
GUI 的配置保存先校验整个配置，再一次写入专用 ini 段，最后提交后台；关闭窗口不提交尚未保存的数值。
证书校验复选框在“保存并关闭”时保存到 `[options] MitmSkipUpstreamVerify`，取消不保存本次选项修改。

按需解压的输入另受 `min(EntryMiB, 64 MiB)` 保护；解压完整性和输出上限检查成功后只向 GUI 返回显示前缀及实际解码字节数，避免把最多 64 MiB 的正文转换成巨大的 JSON 回包。
原始缓存读取单次最多 1 MiB；后台常驻的编码/解码预览仍各限 64 KiB。
缓存大小不是整个进程的内存预算。缓存索引容量随列表配置扩展，内部事件队列与解析器防护限制仍由程序管理。

32 位主程序不加载 MITM 或 SecureTransport 模块，保留普通代理功能；已有 MITM 设置保留但不应用，加密代理配置拒绝启动而不降级为明文。64 位主程序使用两种位数的 Hook 处理 32/64 位目标进程。


## QUIC / HTTP/3 实验接入

QUIC 数据入口位于 `CUdpProxyTask` / `CQuicBridge`，不按进程名或端口筛选。检查经过认证的 QUIC Initial，本实例最多保留 256 个候选/活动桥，每个候选最多保留 64 KiB / 64 个报文并等待 5 秒，重组 ClientHello 后仅接管当前支持的 QUIC v1、ALPN h3。其他协议及无法确认的握手保留原始数据按原路转发，不将 UDP 443 当作充分依据。无 SNI 时仅允许以明确的 IP 目标签发 IP SAN 证书。

Rust `quic_live` 使用 quinn / rustls 和 h3 / h3-quinn 终止两端连接。抽象 UDP socket 的所有报文回到原有 NOPROXY / SOCKS5 路由，不另外发起系统 DNS 或直连绕过代理。每方向收、发队列各限 512 KiB，单连接收/发窗口各限 1 MiB；当前 QUIC 桥数量受 Connections 限制，单连接并行请求受 PendingRequests 限制。HTTP/3 头和 DATA 送入既有带代次的观察队列，经 `ProxyLaneProtocol::http3::Capture` 使用原缓存、解压和 DoH 逻辑。列表显示 QUIC/HTTP/3，保留 PID、进程创建时间、socket 代次、连接及 stream ID。

`[options] DecryptQUIC=0/1` 默认关闭。首次注入时通过既有 PRC 启动消息的可选扩展读取，禁止 UDP 或未接管 UDP 时兼容逻辑不启用。重复注入、重新绑定 PRC、停止监视与修改选项不改变首次决定；必须重新运行目标应用。普通系统证书校验仍保留，不限定只信任 ProxyLane CA。

兼容层不按 EXE 名称或 NetworkService 角色筛选。KernelBase 的 LoadLibraryExW 入口仅记录 chrome.dll / msedge.dll 模块提示；数据文件加载不触发，加载回调不定位、不通信、不装 Hook。首次及后续允许接管的 UDP 发送会补查模块，覆盖已加载模块和绕过 LoadLibraryExW 的加载方式。TCP、单纯 UDP connect、被禁止或绕过代理的 UDP 不启动安装。普通应用没有候选模块便直接继续。

目标进程自己的后台任务加载同目录 ProxyLaneMitm64.dll，读取自身已加载映像的有界快照并调用 Rust 内存定位器。使用字符串交叉引用、指令结构和异常展开边界唯一定位 ShouldAllowUnknownRootForHost；无固定版本、偏移、厂商签名或整文件 SHA。安装前仍核对两段小函数的快照摘要及调用位置，避免代码变化后错误写入。仅从识别的证书完成分支放行；找不到或存在歧义时保守放弃。该过程不初始化 CA、采集缓存或网络运行时。安装后保留模块和 Hook 至目标退出。

第一次 UDP 注册携带 None/Pending/Ready/Unavailable 状态，已注册的 connected UDP 在发送前通过原管道报告状态，后台任务再报告完成结果。PRC 只维护有界、按实例及 PID/创建时间隔离的状态表，无浏览器轮询、远程定位或额外远程初始化线程。仅明确 Pending 的新 QUIC 在发出 MITM 握手前异步等待，截止时间从首包计时，最多 2 秒；没有报告不是 Pending，普通应用不等待。超时、失败或队列超限恢复普通代理转发，该路由不再切换 MITM。非 QUIC UDP 不等待。最多 128 个待接管队列，每队列常规上限 64 KiB / 64 包，所有暂存 Initial 数据合计硬上限 8 MiB；超出预算的新报文直接普通转发，不继续等待。总桥数上限仍为 256。

停止监视停止新增解密和采集，已接管连接继续转发，兼容 Hook 不撤回。新的目标进程经过普通注入后按当时配置重新初始化。不能保证所有机器、所有新版本在等待期限内完成定位；超时优先保持通信。

### 当前边界

- 通用入口不等于所有 QUIC 应用协议均已实现：目前还原 HTTP/3，其他 ALPN 保持原路转发；不提供通用自定义 QUIC stream、WebTransport、QUIC DATAGRAM 或连接迁移的语义代理。
- 当前一个 UDP 路由只接管一条 QUIC 连接，不支持同一 socket 同时承载多条独立连接。
- 不接受 0-RTT，不复用目标服务器票据；真实 ECH、客户端证书认证、证书固定和独立信任库仍可能无法解密。未知版本浏览器的兼容 Hook 也可能不可用。
- 既有 UDP 透明路由对部分未连接 socket 的异步 recvfrom 会暴露本地回包源端口。严格检查对端地址的 aioquic 默认客户端已复现丢弃回包；正常 connected UDP 客户端已验证。此问题属于原 UDP Hook 的收包地址兼容性缺口，不能用通过浏览器测试来掩盖。
- 自动化测试在 `tests/e2e/quic_live_*`，测试宿主和结果位于 `build/quic-live`，不进入 bin。测试不修改证书信任、浏览器策略或用户配置文件。
