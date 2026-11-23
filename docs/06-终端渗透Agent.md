# 终端渗透 Agent

本包把现有 ARTEX **特化成专门打授权 POS / 收银 / 刷卡终端的 Agent**。不 fork Go 核心，不替换滴滴/字节那套 Web SRC 人格。

聊天页左侧选 **终端渗透**（key = `terminal`）。成功标准：可复现的内核代码执行，或重启后仍在的设备接管。

## 1. 它是什么

| 层 | 作用 |
|---|---|
| Agent `terminal` | 专用人格：USB → 指纹 → 选链 → ACE/接管。第一回合必须 `Skill pos-pentest` |
| 七个 `pos-*` Skill | 主控 + USB/PAX/Verifone/MTK/LPE/接管。`mcps: pos-delivery`，加载后才解锁工具 |
| MCP `pos-delivery` | 宿主机执行 adb/fastboot/mtkclient/UART/CVE 匹配。Agent 禁止 Bash 拼这些命令 |
| 拦截 `[POS] *` | 不可逆写入 ASK；禁止用 Bash 绕过 MCP 刷写 |
| 编排加段 | `pentest` / `planner` / `worker` / `mainagent` / `goals` 前置「终端渗透路由」。网站任务忽略该段 |

默认**不**整份替换内置 `pentest` 提示词。这台 ARTEX 同时挂着滴滴/字节工作区。只有你明确要放弃 Web 任务人格时才加 `--specialize-pentest`。

## 2. 启用顺序

1. 启动 MCP（无黑窗）：

   ```text
   pythonw.exe D:\二开artex\mcp\pos-delivery\run_http_9911.py
   ```

   或双击 `scripts\launch-http.vbs`。`GET http://127.0.0.1:9911/health` 应返回 ok。

2. 把七个 Skill 挂进容器（**逐目录 bind**）：

   ```text
   docker compose -f D:\ARTEX渗透\ARTEX\docker-compose.yml -f D:\二开artex\config\docker-compose.terminal.yml up -d
   ```

   改完 Skill 容器立刻读到（bind mount）。本机部署会执行该 compose。

3. 把 ARTEX 登录密码放到 `config/.artex-auth.json`（从 `config/artex-auth.example.json` 复制，已 gitignore）：

   ```json
   {
     "url": "http://127.0.0.1:8787",
     "username": "ARTEX",
     "password": "你的密码"
   }
   ```

4. 种 Agent（幂等，可重复跑）：

   ```text
   C:\Users\蒋蒋\.grok\agent-python\python.exe D:\二开artex\scripts\bootstrap-terminal-agent.py
   ```

   只校验文件：`--self-check`。只看计划：`--dry-run`。宿主机跑 ARTEX 不走 Docker：`--host-mcp`。

5. 打开 `http://127.0.0.1:8787` → 聊天 → 选 **终端渗透**。

## 3. 第一条指令

> 授权 POS，窗口 [起止日期]。设备已插 USB。按指纹打到内核 ACE 或接管。

Agent 应立刻：`Skill pos-pentest` → `usb_enum` → 有 adb 再 `adb_getprop` → `fingerprint_classify` → 只加载 `next_skills[0]`。

不要让它跑一键 root。不要让它用 Bash 调 adb/fastboot。

书面授权未点名具体机型时，按 **SUNMI P2 Pro T6920** 排路径（MSM8917，ADB 常被 MDM 灰掉，P1 是 EDL `05c6:9008`）。指纹是 PAX / Verifone / MTK 时改走对应 Skill。

## 4. 任务模式

从「任务」而不是聊天页进时，跑的是 `pentest`/`planner`/`worker`。bootstrap 给它们前置加段：消息里出现 POS/商米/PAX/刷机/EDL 等词，就切终端渗透流程；目标是网站/API 时忽略加段。

## 5. 闸门

- 只读探针（枚举、getprop、CVE 匹配、指纹）默认自己做。
- 解锁 bootloader、seccfg、擦写分区、SBI 覆盖、Magisk 补 boot、payload 投递：MCP 先 `proposed`，ARTEX 拦截 ASK。把 `effect` 原文给你看，你批了再带 `confirm_token`。
- Skill 不内置利用代码。`POS_EXPLOIT_SERVICE_URL` 未配时 `payload_deliver` 返回 `not_configured`，记缺口、切下一条假设。

## 6. 不要做的事

- 不要把 `D:\二开artex\skills` 整卷挂到 `/app/skills`。
- 不要改 `D:\ARTEX渗透\ARTEX` 源码来做这个 Agent。
- 不要从 VBS 自动 bootstrap（VBS 里不能放密码）。
- 不要对清单外设备动手。
