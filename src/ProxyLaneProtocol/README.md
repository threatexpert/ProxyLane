# Rust 协议还原验证版

Rust library + 命令行程序，用来验证“TLS 明文 → HTTP 请求/响应 → 解压正文”的链路。library 已作为依赖接入 ProxyLane 的实时 MITM，数据监视页已有简单的请求列表和详情视图；实时接入说明见 [realtime-protocol.md](../../docs/realtime-protocol.md)。独立命令行不监听端口、不安装证书，默认启用有上限的临时载荷缓存，退出删除；可用 `--no-cache` 保持纯内存验证。

## 运行

在仓库根目录运行（已构建到 `bin`）：

```powershell
.\build\tools\ProxyLaneProtocol64.exe .\src\ProxyLaneProtocol\fixtures\demo.jsonl
```

默认向 stdout 输出 JSONL。示例是合成流量，包含一个 HTTP/1.1 gzip 请求/响应，以及两个交错传输的 HTTP/2 zstd 请求/响应。HTTP/2 Stream 3 先于 Stream 1 完成，输出仍能正确对应请求。没有使用用户的浏览记录。

只看配对结果：

```powershell
.\build\tools\ProxyLaneProtocol64.exe .\src\ProxyLaneProtocol\fixtures\demo.jsonl |
  ForEach-Object { $_ | ConvertFrom-Json } |
  Where-Object type -eq exchange |
  ForEach-Object {
    [pscustomobject]@{
      PID = $_.connection.pid
      Protocol = $_.protocol
      Stream = $_.exchange.id
      Method = $_.exchange.request.method
      Path = $_.exchange.request.target
      Status = $_.exchange.response.status
      Decode = $_.exchange.response.decoding
    }
  } | Format-Table
```

预期三条结果：HTTP/1.1 `POST /echo → 200`；HTTP/2 Stream 3 `GET /second → 200`；HTTP/2 Stream 1 `POST /echo → 200`。三条正文解码状态均为 `ok`。

32 位程序为 `build/tools/ProxyLaneProtocol32.exe`。不指定文件时从 stdin 读取，可由上游实时写入事件；JSONL 是验证用交换格式，未来不要求 C++ 把每块流量转换为 JSON。

## 选用的库

| 工作 | 库 | 本项目补充的部分 |
|---|---|---|
| HTTP/1 头、chunk size、trailer 语法 | [httparse 1.10.1](https://docs.rs/httparse/1.10.1/httparse/) | 双向状态、消息边界、持久连接和请求响应配对 |
| HTTP/2 HPACK / Huffman | [httlib-hpack 0.1.3](https://docs.rs/httlib-hpack/0.1.3/httlib_hpack/) | 帧、CONTINUATION、Stream ID、双向头表和 SETTINGS ACK |
| gzip / deflate | [flate2 1.1.5](https://docs.rs/flate2/1.1.5/flate2/) | 有限解压、完整性判断、原始 deflate 兼容 |
| Brotli | [brotli 8.0.2](https://docs.rs/brotli/8.0.2/brotli/) | 有限输出、完整结束及多余字节判断 |
| zstd | [zstd 0.13.3](https://docs.rs/zstd/0.13.3/zstd/) | 输出和解压窗口限制 |

没有直接使用 `h2` 作为被动解析器：它面向 HTTP/2 端点，会维护发送、接收和流控行为；这里读取的是已经被 MITM 收发的字节，不应再次参与协议交互。验证测试使用 Python `h2` 生成端点流量，避免完全用同一套实现自证。

`httlib-hpack 0.1.3` 的截断整数/字符串输入在本次变异测试中触发了越界 panic。因此 `hpack_guard.rs` 在进入库之前检查每个表示的整数、字符串长度和边界；Huffman 和动态表仍由库处理，不通过捕获 panic 掩盖错误。回归测试保留这些畸形输入。正式集成前仍需要更广泛的 fuzz/audit，不能仅凭正常样例选库。

依赖版本与 `Cargo.lock` 一起固定，兼容本机 Rust 1.82。锁文件中的 `jobserver` 固定为 0.1.32，以避开新版本的 Rust 2024 依赖。zstd 包含本地 C 编译部分，需要 MSVC 构建环境；可执行程序无需 Python。Python 仅用于独立验证。

## 当前实现范围

- HTTP/1.1：任意输入分片，Content-Length、chunked、trailer、连接关闭定界；keep-alive、流水线、HEAD、100/103 等临时响应。
- HTTP/2：客户端 preface、SETTINGS/ACK、HEADERS/CONTINUATION、DATA/padding、trailer、RST_STREAM、GOAWAY；按连接和方向保持 HPACK 状态，按 Stream ID 配对并发请求。
- 请求正文和响应正文都支持 gzip（含多 member）、zlib deflate、旧式 raw deflate、Brotli、zstd；按反序处理多层 Content-Encoding，最多四层。
- `body_base64` 是去除传输分块/帧后的编码正文预览；解压后的预览为 `decoded_base64`，有效 UTF-8 另附 `text`。缓存模式下编码和解码预览各限 64 KiB；较大的正文通过缓存接口按需读取/解压。没有猜测字符集、格式化 JSON 或解析业务协议。
- HTTP 消息完整性 `complete`、配对/传输问题 `problem` 和正文解码状态 `decoding` 分开报告。HTTP 完整但压缩正文损坏时，`complete=true`、`decoding=failed: ...`，不会伪造解压结果。
- HTTP/1.1 的定长/chunked 消息或 HTTP/2 的 END_STREAM 已完整到达后，缺少 TLS close_notify 不会把已完成请求改判成失败。靠 EOF 定界的 HTTP/1 响应需要可信关闭才能认定完整。

本版是有边界检查的被动还原原型，**不是完整 HTTP 协议合规校验器，也未进行长期模糊测试或性能验收**。暂不处理 HTTP/2 server push、CONNECT 隧道、WebSocket、h2c upgrade、HTTP/3、gRPC 消息和压缩字典。遇到会影响后续还原的未支持特性或畸形数据时，输出 diagnostic 并停止该连接的解析。

协议由调用方明确指定为 `http1` 或 `h2`（以后由 MITM 的 ALPN/嗅探结果提供）。必须从连接开始取数据；不支持直接导入 PCAP、从连接中段恢复 HPACK，或把已有的截断 GUI 日志补成完整响应。

## 输入约定

每行一个事件，UTF-8，无 BOM：

```json
{"type":"open","protocol":"http1","connection":{"id":"run-1/connection-7","pid":1234,"process_start":987654321,"socket":1680,"generation":18,"destination":"example.test:8443"}}
{"type":"data","connection_id":"run-1/connection-7","direction":"client","offset":0,"data_base64":"R0VUIC8gSFRUUC8xLjENCg0K"}
{"type":"data","connection_id":"run-1/connection-7","direction":"server","offset":0,"data_base64":"SFRUUC8xLjEgMjAwIE9LDQpDb250ZW50LUxlbmd0aDogMg0KDQpvaw=="}
{"type":"eof","connection_id":"run-1/connection-7","direction":"server","clean":true}
{"type":"eof","connection_id":"run-1/connection-7","direction":"client","clean":true}
{"type":"close","connection_id":"run-1/connection-7"}
```

- `id` 应唯一标识本次运行中的一个连接，不得用裸 socket 或 PID 代替。进程创建时间、socket generation 原样传回输出，供之后关联 UI。
- `client` 指应用 → 服务器，`server` 指服务器 → 应用。
- 两个方向的 `offset` 各自从 0 开始；每块必须与上一块连续。重复、缺口、乱序立即报告并终止解析，尤其不能在 HPACK 丢块后继续猜测。
- 也要保留跨方向的因果顺序：请求头必须先于对应响应到达解析器；SETTINGS 必须先于其 ACK。现有 GUI 单消费者队列及 2048 字节预览不能直接用作数据源。
- TLS 场景的 `clean=true` 表示收到 close_notify；普通未加密 TCP 可用正常 EOF。`close` 或输入文件结束仅表示停止采集，不会伪造 clean EOF。
- `exchange` 事件在请求和最终响应都完成时输出；关闭、错误、RST_STREAM、GOAWAY 也会输出已知的部分消息。没有完整头部可展示时只有 diagnostic。已经发生致命错误的连接会忽略后续 data，直到 close。
- 正常事件处理（包含报告协议/解压/载荷缓存问题）退出码为 0；无效 JSON、错误事件引用、输入限制、输入输出 IO 失败、缓存初始化/退出清理失败退出码为 2。自动化应检查 JSON 中的 diagnostic、problem、complete、decoding，以及 cache 状态。

## 临时载荷缓存

缓存以一次请求及其响应为单位：HTTP/1.1 对应请求序号，HTTP/2 对应 Stream ID。所有连接共享一个 `PayloadCache`，缓存 ID 在本次运行中唯一，不依赖 PID/socket/Stream ID 单独标识。请求和响应分别存放，但共用单条额度。

| 项目 | 默认值/行为 |
|---|---|
| 单条编码载荷 | 请求＋响应共 32 MiB |
| 全局编码载荷 | 本实例所有连接共 512 MiB，写入前检查额度 |
| 内存预览 | 每方向编码、解码预览各最多 64 KiB |
| 写盘队列 | 128 个命令，每个载荷块最多 16 KiB，另有一个在处理的块 |
| 活跃缓存索引 | 最多 4096 条，另保留最多 4096 条已淘汰状态 |
| 按需解压 | 只解压完整缓存的正文，输入最多 32 MiB，输出最多 4 MiB，不额外落盘 |

目录为 `%TEMP%\ProxyLane\protocol-cache-v1\run-<随机标识>\`。只保存去掉 HTTP 分块/帧的 Content-Encoding 正文；请求头、响应头和会话摘要保留在解析结果中，不写入载荷文件。全局额度统计载荷文件字节，不包含文件系统分配单元、目录、锁文件和输出到 stdout 的 JSON。

写盘异步进行。达到总量限制时，优先删除**最早完成**且已处理完排队写入的请求载荷，已输出的请求摘要和头部不因此丢失。没有可淘汰的已完成条目时，保存当前可用额度内的前缀，停止该条请求的进一步缓存；不删除正在传输的其他请求载荷。达到单条上限同样只保留前缀。无论缓存是否完整，HTTP 字节计数、chunked、帧、HPACK 和请求响应配对继续工作。

队列满或写盘失败时，停止该条缓存，并保留明确原因。不会丢掉中间一块后继续拼接后面的正文，也不会等待磁盘完成而卡住解析入口。若正文超出预览大小，`decoding` 显示 `deferred`；是否能读到完整内容要再查询缓存，不能仅凭 HTTP 的 `complete=true` 判断。

正常退出（包括输入解析错误）会先停止接收缓存写入、处理已排队的数据、关闭文件，再删除本次 run 目录。强制终止/崩溃后，在下一次缓存初始化时清理旧 run；活动实例持有 `owner.lock` 的系统文件锁，不会被清理。创建及清理用根目录的 `manager.lock` 串行化。根目录和零长度管理锁会保留，载荷和每次运行目录会删除。

清理只处理本组件的目录格式和文件名，遇到未知文件、错误标记、符号链接/junction/reparse point 会跳过并报告。采用平面逐文件清理，不递归跟随目录；不能删除的残留不会被当成清理成功。临时缓存不承诺崩溃恢复浏览历史，不对每块数据执行 fsync；残留用于删除，不用于恢复。

可配置额度（单位为字节），例如：

```powershell
.\build\tools\ProxyLaneProtocol64.exe --cache-entry-bytes 33554432 --cache-total-bytes 536870912 .\src\ProxyLaneProtocol\fixtures\demo.jsonl
```

另有 `--cache-root PATH`、`--cache-queue-chunks N`、`--cache-max-entries N`。`--cache-root` 应指向独立缓存目录。多个独立运行实例各自拥有额度；同一个实例内所有连接共享额度。

`exchange.cache` 给出缓存 ID、两个方向的已写字节数、待写块数、完成状态、是否已淘汰和原因。这是事件产生时的快照，异步写入和后续淘汰可能改变状态。库调用方保留的 `CacheRef` 可读取最新状态；JSONL 调用方可在同一进程内发送以下查询：

```json
{"type":"cache_stats"}
{"type":"cache_status","cache_id":1}
{"type":"cache_read","cache_id":1,"direction":"server","offset":0,"length":65536}
{"type":"cache_decode","cache_id":1,"direction":"server"}
```

查询会等待之前排队的写入处理完毕，分别返回 `cache_stats`、`cache_status` 或 `cache_payload`；读取/解码失败返回 `cache_error`，不会中止协议解析。原始读取每次最多 1 MiB，可按偏移连续读取；当前按需解码在请求响应配对结束后执行，要求该方向 HTTP 完整且缓存字节数与实际正文长度一致。已淘汰的缓存无法读取，较老的淘汰状态也可能因索引上限返回 `null`。缓存 ID 不接受路径，不能通过接口读取任意本地文件。

**文件输入处理结束后程序立即退出，缓存也立即清除。** 要验证读取功能，把查询追加在输入文件末尾，或者通过 stdin 在进程存活期间交互；示例 `fixtures/cache-demo.jsonl` 已附读取和解压查询。用户主动保存 stdout/导出的文件不属于本组件临时目录，不会被自动删除。

## 资源边界

默认每连接最多 16 个未完成请求。启用缓存时正文预览及载荷按上表限制；`--no-cache` 或库的 `Analyzer::new` 保留原先每消息 1 MiB 编码正文、4 MiB 解压正文的验证行为。`Analyzer::with_cache` 接入共享缓存。超限后仍继续计数、识别消息边界和处理下一条请求，不对被截断的正文假装完成解压。

头部/HPACK block 上限 64 KiB、头数 256、HPACK 表上限 64 KiB、单帧 1 MiB、临时响应 16 个、未 ACK 的 SETTINGS 16 个。zstd 解压窗口上限 8 MiB；Brotli 禁用非标准大窗口。CLI 同时最多 8 个连接，每行输入最多 2 MiB。输出包含编码正文、解码正文和 UTF-8 文本时有多份内存开销，这些是各项限制，**不是进程总内存预算**。

解析器返回的结果由调用方及时消费，不能在调用方无限积累预览。载荷写盘队列、磁盘额度及索引条数已有限制；未来接入实时 MITM 时仍需为传输输入和 UI 历史增加全局内存预算、连接超时及背压策略。按需解压/读取属于显式同步查询，不能在网络转发线程中调用。

## 构建和验证

```powershell
cargo test --manifest-path src/ProxyLaneProtocol/Cargo.toml --locked
cargo clippy --manifest-path src/ProxyLaneProtocol/Cargo.toml --all-targets --locked -- -D warnings
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-protocol.ps1
python tests/e2e/protocol_reconstruction.py --binary build/tools/ProxyLaneProtocol64.exe
python tests/e2e/protocol_reconstruction.py --binary build/tools/ProxyLaneProtocol32.exe
python tests/e2e/protocol_cache.py --binary build/tools/ProxyLaneProtocol64.exe
python tests/e2e/protocol_cache.py --binary build/tools/ProxyLaneProtocol32.exe
```

构建需要已安装 `i686-pc-windows-msvc`、`x86_64-pc-windows-msvc` 目标及 MSVC。验证脚本的 Python 依赖见 `tests/e2e/protocol-requirements.txt`。

Rust 测试覆盖状态机和资源上限；Python 验证用独立编码器产生七种编码组合、1/7/65536 字节分片、双向压缩正文、HTTP/2 多路复用、动态头表/Huffman/表容量变化、临时响应和 trailers；还校验压缩损坏、截断、尾部多余字节和解压膨胀上限。

缓存测试覆盖请求/响应合计限额、全局限额、旧载荷淘汰、活跃条目保护、34 MiB 下载仅缓存 32 MiB、HTTP/2 独立 Stream、chunked 去帧、按需解压、写入失败、队列饱和和索引限制。`protocol_cache.py` 用自己启动的子进程验证正常退出、错误退出、强制终止后的残留清理、初始化中断、活动实例保护及 junction/未知文件保护，不操作用户的实际缓存。

主要代码：`src/cache.rs`（额度、异步写入、淘汰及读取）、`src/cache_directory.rs`（目录与锁、退出及残留清理）、`src/lib.rs`（连接 API、偏移检查）、`src/http1.rs`、`src/http2.rs`、`src/decode.rs`、`src/model.rs`、`src/main.rs`（JSONL CLI）。下一步是从 MITM 的完整明文回调异步送入这个 API，并传递 ALPN、连接身份、方向和连续字节偏移；不从日志文本反推协议。
