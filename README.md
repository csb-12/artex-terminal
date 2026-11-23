# 终端渗透 Agent（ARTEX 二开）

把现有 ARTEX（`D:\ARTEX渗透\ARTEX`）特化成**专门针对授权 POS / 收银 / 刷卡终端**的 Agent。不改 ARTEX Go 源码，不替换 `api-recon` / `bytesrc`。

聊天页选 **终端渗透**（key = `terminal`）。成功标准：可复现的内核代码执行，或重启后仍在的设备接管。禁止一键 root 脚本。Skill **不内置利用代码**。不可逆写入走 MCP `proposed` + ARTEX `ask`。

## 包结构

```
D:\二开artex
├── agent/
│   ├── terminal.md                 专用 Agent 人格（无 Go 模板花括号）
│   ├── terminal-wrapup.md          步数/超时收尾
│   └── orchestration-addendum.md   给 pentest/planner/worker 的 POS 路由加段
├── skills/                         七个 ARTEX Skill（mcps: pos-delivery）
│   ├── pos-pentest/
│   ├── pos-usb-entry/
│   ├── pos-pax-fastboot/           CVE-2023-42134
│   ├── pos-verifone-sbi/           CVE-2019-14715
│   ├── pos-mtk-brom/               BROM + DA + seccfg
│   ├── pos-android-lpe/            受限 shell LPE 匹配
│   └── pos-takeover/               Magisk / seccfg / SBI 持久化
├── mcp/pos-delivery/               宿主机 MCP（adb/fastboot/mtkclient/UART/CVE）
├── config/
│   ├── agent-terminal.json         Agent 清单
│   ├── mcp-server.artex.json       Docker：host.docker.internal:9911
│   ├── mcp-server.host.json        宿主机：127.0.0.1:9911
│   ├── intercept-rules.json
│   ├── docker-compose.terminal.yml 逐目录挂 pos-*（不要整卷 overlay）
│   ├── docker-compose.cdrive.yml   Windows D: virtiofs 坏了时走 C: 联接
│   └── artex-auth.example.json     复制为 .artex-auth.json（已 gitignore）
├── docs/
│   ├── 01-授权设备渗透路线图.md
│   ├── 02-Skill与MCP接口.md
│   ├── 03-PAX-fastboot验证步骤模板.md
│   ├── 04-Verifone-SBI验证步骤模板.md
│   ├── 05-挂载到ARTEX.md
│   └── 06-终端渗透Agent.md
└── scripts/
    ├── launch-http.vbs             无窗启动 MCP HTTP :9911
    └── bootstrap-terminal-agent.py 幂等种 Agent / Skill / MCP / 拦截
```

## 启用（三步）

1. MCP（无黑窗）：

   ```text
   pythonw.exe D:\二开artex\mcp\pos-delivery\server.py --http 127.0.0.1:9911
   ```

   `GET http://127.0.0.1:9911/health` 应返回 `ok`。

2. Skill 挂进容器：

   ```text
   docker compose -f D:\ARTEX渗透\ARTEX\docker-compose.yml -f D:\二开artex\config\docker-compose.terminal.yml up -d
   ```

   Windows Docker Desktop 的 D: 挂载若报 `mkdir /run/desktop/mnt/host/d: file exists`，改用 `config/docker-compose.cdrive.yml`（C: NTFS 联接，说明见 `docs/05-挂载到ARTEX.md`）。

3. 种专用 Agent（密码放 `config/.artex-auth.json`）：

   ```text
   C:\Users\蒋蒋\.grok\agent-python\python.exe D:\二开artex\scripts\bootstrap-terminal-agent.py --self-check
   C:\Users\蒋蒋\.grok\agent-python\python.exe D:\二开artex\scripts\bootstrap-terminal-agent.py
   ```

聊天页选 **终端渗透**，说：

> 授权 POS，窗口 [起止日期]。设备已插 USB。按指纹打到内核 ACE 或接管。

完整说明：`docs/06-终端渗透Agent.md`。

## 文档

1. 路线图（代表机 T6920 + 指纹分支）：`docs/01-授权设备渗透路线图.md`
2. Skill / MCP 接口：`docs/02-Skill与MCP接口.md`
3. 验证模板：`docs/03-*.md`、`docs/04-*.md`
4. 挂载细节：`docs/05-挂载到ARTEX.md`
5. 专用 Agent：`docs/06-终端渗透Agent.md`

## 约束

- 仅书面授权清单内的设备；窗口占位 `[起止日期]`。
- Agent 禁止 Bash 调 adb/fastboot/mtkclient；一律 `mcp__pos-delivery__*`。
- Windows 禁止弹 cmd：MCP 用 pythonw，子进程 `CREATE_NO_WINDOW`。
- `POS_EXPLOIT_SERVICE_URL` 指向实验室编译投递服务；不配则 `payload_deliver` 返回 `not_configured`。
- 默认不替换内置 `pentest` 人格（这台 ARTEX 还跑滴滴/字节 Web SRC）。要整机变成终端专用，才加 `--specialize-pentest`。
