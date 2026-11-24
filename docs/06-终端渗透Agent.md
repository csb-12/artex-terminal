# 终端渗透 Agent

本包把现有 ARTEX **特化成专门打授权 POS / 收银 / 刷卡终端的独立渗透 Agent**。不 fork Go 核心，不替换你现有的 Web SRC 人格。

人格按原版 ARTEX「渗透测试」agent 简介写：一个人从头打到尾，同时是规划者、执行者、审计者。工具给事实、分类器给假设，路线自己排。领域从 Web 攻击面换成 USB / bootloader / 内核 / 接管。

聊天页左侧选 **终端渗透**（key = `terminal`）。成功标准：可复现的内核代码执行，或重启后仍在的设备接管。CVE 命中不是漏洞。内核 ACE 不是支付密钥/TEE 被打穿。

## 1. 它是什么

| 层 | 作用 |
|---|---|
| Agent `terminal` | 专用人格：原版六条心法 + 自主决策。开局 `Skill pos-pentest` + `usb_enum`，之后按回包自己排 |
| 八个 `pos-*` Skill | 主控 + USB/PAX/Verifone/MTK/LPE/接管 + 安卓/OS 代码审计。`mcps: pos-delivery`，加载后才解锁工具 |
| MCP `pos-delivery` | 宿主机执行 adb/fastboot/mtkclient/UART/CVE 匹配。Agent 禁止 Bash 拼这些命令 |
| 拦截 `[POS] *` | 不可逆写入 ASK；禁止用 Bash 绕过 MCP 刷写 |
| 编排加段 | `pentest` / `planner` / `worker` / `mainagent` / `goals` 前置「终端渗透路由」。网站任务忽略该段 |

默认**不**整份替换内置 `pentest` 提示词。这台 ARTEX 如果还跑 Web SRC，只有你明确要放弃 Web 任务人格时才加 `--specialize-pentest`。

心法（与原版一一对应）：

1. 先广后聚，别隧道视野（先摸 adb/fastboot/EDL/BROM/UART，再爱上某一个 CVE）
2. 一条路要走透再下结论（ADB 灰掉要换 fastboot/EDL，不是停）
3. 封锁路线不无理由重试
4. 对抗式自检（CVE 命中 / 补丁日期 ≠ ACE）
5. 要具体结论，不要状态报告
6. 不轻言放弃（缺口要写明，禁止说「无法利用」就收工）

## 2. 启用顺序

1. 启动 MCP（无黑窗）：

   ```text
   pythonw mcp/pos-delivery/run_http_9911.py
   ```

   或 `scripts/launch-http.ps1` / 双击 `scripts/launch-http.vbs`。`GET http://127.0.0.1:9911/health` 应返回 ok。

2. 把八个 Skill 挂进容器（**逐目录 bind**）：

   ```text
   python scripts/bootstrap-terminal-agent.py --init
   docker compose --env-file config/.compose.env -f "%ARTEX_HOME%/docker-compose.yml" -f config/docker-compose.terminal.yml up -d
   ```

   改完 Skill 后，bind mount 的环境容器立刻读到。

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
   python scripts/bootstrap-terminal-agent.py
   ```

   只校验文件：`--self-check`。只看计划：`--dry-run`。宿主机跑 ARTEX 不走 Docker：`--host-mcp`。UI token 过期且 auth 文件没有密码时：`--via-postgres`（只写人格/加段，不管 MCP）。

5. 打开 ARTEX 聊天页 → 选 **终端渗透**。

## 3. 第一条指令

> 授权 POS，窗口 [起止日期]。设备已插 USB。看清入口后打到内核 ACE 或接管。

Agent 应立刻：`Skill pos-pentest` → `usb_enum`。这是看设备，不是整场剧本。看见 USB 之后自己排探针、自己加载 1–2 条 Skill、TodoWrite 铺 2–3 条路线。`fingerprint_classify` 的 hypotheses 是建议，不必死跟 `next_skills[0]`。

不要让它跑一键 root。不要让它用 Bash 调 adb/fastboot。不要让它每轮写五段状态报告。卡住时它应自己换模式/换候选，而不是问「接下来怎么办」。

T6920（SUNMI P2 Pro，MSM8917，ADB 常被 MDM 灰掉，EDL `05c6:9008`）是实验室代表机，不是默认身份。没摸清 USB 之前不要套它的 EDL 树。指纹是 PAX / Verifone / MTK 时改走对应 Skill。

## 4. 任务模式

从「任务」而不是聊天页进时，跑的是 `pentest`/`planner`/`worker`。bootstrap 给它们前置加段：消息里出现 POS/商米/PAX/刷机/EDL 等词，就切终端渗透流程；目标是网站/API 时忽略加段。

聊天页没有探索图：不要指望 `report_finding` 能落库。路线用 TodoWrite；设备入口用 `insert_assets`（bootstrap 会绑到 `terminal`）。

## 5. 闸门

- 只读探针（枚举、getprop、CVE 匹配、指纹、adb_surface、adb_pull）默认自己做。
- 解锁 bootloader、seccfg、擦写分区、SBI 覆盖、Magisk 补 boot、payload 投递：MCP 先 `proposed`，ARTEX 拦截 ASK。把 `effect` 原文给你看，你批了再带 `confirm_token`。
- Skill 不内置利用代码。`POS_EXPLOIT_SERVICE_URL` 未配时 `payload_deliver` 返回 `not_configured`，记缺口、切下一条假设。

## 6. 不要做的事

- 不要把本仓库整个 `skills/` 挂到 `/app/skills`。
- 不要改 ARTEX 源码来做这个 Agent。
- 不要从 VBS 自动 bootstrap（VBS 里不能放密码）。
- 不要对清单外设备动手。
- 不要把完整 PAN / 磁道 / PIN 写进会话。
