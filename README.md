# ProxyLane

ProxyLane 是一款面向 Windows 的应用级代理工具。它通过进程注入和网络 API Hook，让指定程序的网络连接使用单独配置的代理，而不需要修改系统全局代理。

## 界面预览

![ProxyLane 界面预览](UI.png)

## 功能

- 为指定应用或进程启用代理
- 支持代理配置管理和连接测试
- 支持 SOCKS5 TCP 与 UDP 代理
- 支持进程规则和目标规则
- 支持直接拖入程序或快捷方式启动
- 提供运行日志和连接数据监视
- 提供 Win32 与 x64 版本
- 兼容 Windows XP 及更高版本

## 构建环境

- Visual Studio 2019
- Visual C++ v141_xp 工具集
- Windows 7.1A SDK

打开 `src/ProxyLane.sln`，选择 `Win32` 或 `x64` 平台后构建即可。Release 输出位于 `bin/` 目录。

## 打包发行版

先构建 Win32 与 x64 的 Release 版本，然后在项目根目录运行：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\package-release.ps1
```

脚本会从程序文件属性读取版本号，检查四个发行二进制文件的版本是否一致，并生成 `dist/ProxyLane-版本-Windows.zip`。压缩包包含 Win32/x64 主程序、对应的 Hook DLL、样例配置和 README。

样例配置保存在 `examples/ProxyLane.ini`，打包后会以 `ProxyLane.ini` 放在压缩包根目录。

如需指定输出目录，可增加参数 `-OutputDirectory D:\releases`。

## 项目结构

- `src/ProxyLane`：MFC 桌面界面与应用逻辑
- `src/ProxyLaneHook`：进程注入与网络 Hook 模块
- `src/remotecode`：远程代码执行辅助模块
- `tests`：单元测试
- `examples`：样例配置
- `scripts`：发行包生成脚本

## 版本

当前版本：1.0.0.0
