# 安装包与程序内更新

ProxyLane 同时提供 zip 便携包和 Inno Setup 安装包。安装版装到 `Program Files\ProxyLane`，
配置仍保存在 `%LOCALAPPDATA%\ProxyLane\ProxyLane.ini`，升级和卸载都不会删除配置。
安装版可以在“设置与关于 → 检查更新”中直接下载并安装新版本；zip 版仍打开下载站，由用户手动替换。

## 构建安装包

需要 Inno Setup 6（`ISCC.exe` 位于 PATH 或默认安装目录）。在完成 Win32/x64 Release 构建后执行：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\package-release.ps1 -Installer
```

脚本先生成 zip，再把相同文件暂存到 `dist/installer-staging-版本/`，然后编译
`installer/ProxyLane.iss`，输出 `dist/ProxyLane-版本-Setup.exe` 及其 SHA-256。
可用 `-InnoSetupCompiler` 指定 `ISCC.exe` 路径。

安装包行为：

- 需要管理员权限。64 位 Windows 安装 x86 与 x64 全部组件，开始菜单快捷方式指向 `ProxyLane64.exe`；32 位 Windows 只安装 x86 组件。
- 最低支持 Windows 7 SP1（Inno Setup 6 的要求）。Windows XP 用户继续使用 zip 包。
- 不使用 Restart Manager：已代理的应用会继续加载 `ProxyLaneHook*.dll`，关闭它们会丢失用户工作。
  被占用的文件会先改名为 `*.pl-old`，再写入新文件；旧映像对仍在运行的进程保持有效，
  下次安装或卸载时清理。
- 安装和卸载前等待所有 ProxyLane 进程退出（每个进程都持有互斥体 `ProxyLaneRunning`）。

## 程序内更新流程

1. 用户点击“检查更新”。ProxyLane 启动一个无窗口的自身副本（`--update-helper release`）
   请求 `https://10000.download/api/tools/proxylane/release`。
2. **如果代理正在运行**，主程序会在辅助进程恢复运行前注入 ProxyLaneHook。辅助进程的流量因此走当前代理配置，
   包括 SOCKS5/HTTP、认证、加密传输和目标规则，不需要另外实现一套代理协议。
   这一步跳过子进程筛选规则；注入失败时直接报错，不会悄悄改成直连。
   代理未运行时按系统网络设置访问，与之前的检查更新行为一致。
3. 发现新版本后，如果当前是安装版，并且接口为该版本提供了符合约定的安装包（见下文），
   状态链接显示“点击下载并安装”；否则仍然打开下载站。
4. 用户确认后，辅助进程以同样的方式下载安装包到 `%TEMP%\ProxyLane-Update\`。
   主程序校验文件大小和 SHA-256，不一致就删除文件。
5. 用户再次确认后，ProxyLane 依次执行常规退出检查（未保存的修改、仍在代理的进程），
   安装前再校验一次文件，然后以 `/SILENT /SUPPRESSMSGBOXES /NORESTART /SP- /AUTOUPDATE`
   启动安装程序。
6. 安装程序完成提权后创建互斥体 `ProxyLaneSetupWaiting`。ProxyLane 看到它才退出；如果用户拒绝 UAC，
   安装程序会先结束，ProxyLane 保持运行。安装程序最多等待 60 秒，等 ProxyLane 释放文件后
   安装到原目录，最后以原用户身份重新启动 ProxyLane。

辅助进程只会从固定站点 `https://10000.download` 下载，路径必须匹配 `/d/proxylane/[A-Za-z0-9_-]{1,64}`；
不跟随重定向，不发送 Cookie 或认证信息。接口元数据里的 URL 不会被打开。

## 本地测试更新流程

服务端还没提供安装包 asset 时，可以用测试构建加本地服务器把整条流程走一遍：

1. 编译时定义 `PROXYLANE_UPDATE_LOCAL_TEST`（例如在 Developer PowerShell 中设置
   `$env:CL='/DPROXYLANE_UPDATE_LOCAL_TEST'` 后再 msbuild），更新源会改为 `http://127.0.0.1:8765`。
   正式构建不要定义这个宏。
2. 用这个构建运行 `package-release.ps1 -Installer`，然后安装生成的安装包。
3. 运行 `python scripts/serve-update-test.py dist\ProxyLane-版本-Setup.exe`。它会把该安装包发布为 v9.9.9，
   并附上大小和 SHA-256；加 `--corrupt` 可以测试哈希不一致时的拒绝逻辑。
4. 在 ProxyLane 中启动任意配置（例如 Direct），然后在“设置与关于”中检查更新、下载并安装。
   代理运行时，服务器日志里的请求来自被注入的辅助进程。

## 发布接口约定

现有接口已经返回 `assets` 数组。客户端只接受满足以下全部条件的 asset 作为安装包：

| 字段 | 要求 |
| --- | --- |
| `name` | 精确等于 `ProxyLane-<版本>-Setup.exe`，版本为 `version` 去掉前缀 `v` |
| `path` | `/d/proxylane/<id>`，`id` 只含字母、数字、`-`、`_`，最长 64 字符 |
| `size` | 正整数，不超过 256 MiB，与下载结果一致 |
| `sha256` 或 `digest` | 64 位十六进制；`digest` 使用 GitHub Release asset 的 `sha256:<hex>` 格式 |

示例（只比当前接口多了安装包 asset 及其 `digest`）：

```json
{
  "version": "v1.4.0",
  "assets": [
    { "id": "1", "name": "ProxyLane-1.4.0-Windows.zip", "size": 8906430, "platform": "Windows", "path": "/d/proxylane/1" },
    { "id": "2", "name": "ProxyLane-1.4.0-Setup.exe", "size": 9123456, "platform": "Windows", "path": "/d/proxylane/2",
      "digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }
  ]
}
```

缺少安装包 asset 或字段不合规时，客户端退回原有行为（打开下载站），
所以服务端可以先上线，旧客户端也不受影响。GitHub Release API 已为每个 asset 提供 `digest`，
下载站直接透传即可。

SHA-256 能保证下载结果与接口公布的内容一致，但信任根仍然是 `10000.download` 的 HTTPS 证书。
如果以后对安装包做 Authenticode 签名，可以在运行前再加一道签名校验。
