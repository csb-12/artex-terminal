# 安全政策

本仓库是授权范围内的 POS / 终端评估工具包。Skill 与 MCP **不内置 exploit 源码**。

## 请不要

- 在 Issue / PR / Discussions 里贴 exploit、PoC 源码、补丁 hex、XDL 帧、firehose 本体
- 贴完整 PAN、磁道、PIN、ARTEX 登录密码、`config/.artex-auth.json`
- 请求对未授权设备的利用协助

这类内容会被关闭，不会合并。

## 本包自身的漏洞

如果你发现 `pos-delivery`、bootstrap 或 Skill 调度有安全问题（例如写入门可绕过、proposed token 可伪造、意外执行 Bash 刷写），请不要公开 Issue，改用 GitHub 的 Private vulnerability reporting，或只描述复现条件、不附利用代码。

## 授权范围

对清单外设备使用本仓库，不属于本项目支持的范围。
