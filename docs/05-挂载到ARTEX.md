# 挂载到 ARTEX

本包不改 `D:\ARTEX渗透\ARTEX` 源码。把 Skill 挂进容器的 `/app/skills`，MCP 跑在宿主机，再用 bootstrap 种出专用 Agent **终端渗透**。

产品说明与聊天页用法：`docs/06-终端渗透Agent.md`。

ARTEX 安装树默认：`D:\ARTEX渗透\ARTEX`。Skill 加载顺序：`ARTEX_SKILL_DIR` > `config.json` 的 `skill_dir` > 可执行文件旁 `skills/`。Docker 已绑定 `./skills:/app/skills`。

## 1. 启动 pos-delivery（宿主机，无黑窗）

```text
pythonw.exe D:\二开artex\mcp\pos-delivery\run_http_9911.py
```

或双击/静默：`scripts\launch-http.vbs`。包装脚本绑 `0.0.0.0:9911`，让容器里的 `http://host.docker.internal:9911` 能打到宿主机。

检查：浏览器或 curl `http://127.0.0.1:9911/health` 应返回 `{"ok":true,"server":"pos-delivery"}`。

依赖：`pip install -r D:\二开artex\mcp\pos-delivery\requirements.txt`（pyserial）。adb/fastboot 在 PATH 或 Android SDK `platform-tools`。MTK 链需要本机 mtkclient。

可选环境变量见 `mcp/pos-delivery/env.example`。

## 2. Docker：覆盖挂载七个 Skill

推荐用第二份 compose，不碰 ARTEX 目录里的文件：

```text
docker compose -f D:\ARTEX渗透\ARTEX\docker-compose.yml -f D:\二开artex\config\docker-compose.terminal.yml up -d
```

也可以把 `config/docker-compose.override.example.yml` 复制为 ARTEX 目录下的 `docker-compose.override.yml`（与现有 `docker-compose.yml` 并列）。两种方式都是把各 `pos-*` 目录叠到 `/app/skills/pos-*`，**不要**把整个 `D:/二开artex/skills` 盖到 `/app/skills`，否则会盖掉 `api-recon` / `bytesrc`。不要两份同时叠（挂载重复，功能一样）。

Windows Docker Desktop 已提供 `host.docker.internal`。Linux 引擎需要 `extra_hosts`。本机部署会执行上述 compose（只追加七个 pos-* 目录，不整卷覆盖 `/app/skills`）。

本机 Docker Desktop 的 D: virtiofs 若损坏（`mkdir /run/desktop/mnt/host/d: file exists` / `I/O error`），不要叠原 `docker-compose.yml`（里面有 D: 绑定）。

NTFS 联接（`mklink /J C:\...\artex-bind D:\ARTEX渗透\ARTEX`）在这台 Docker Desktop 上**行不通**：引擎会把联接解析成 D: 真实路径，仍去建 `/run/desktop/mnt/host/d`。`config/docker-compose.cdrive.yml` 留给 virtiofs 能跟着联走的环境。

本机实际用 named volume，宿主机文件用 `docker cp` 灌进容器：

```text
docker compose -p artex --env-file D:\ARTEX渗透\ARTEX\.env -f D:\二开artex\config\docker-compose.namedvol.yml up -d
docker cp D:\ARTEX渗透\ARTEX\grok-bridge.py artex-artex-1:/app/grok-bridge.py
docker cp D:\ARTEX渗透\ARTEX\skills/. artex-artex-1:/app/skills/
docker cp D:\二开artex\skills/. artex-artex-1:/app/skills/
```

项目名必须是 `artex` 才能沿用已有 postgres 卷。不挂滴滴/字节 D: 工作区。历史 `data/tasks` 不自动灌入。改 Skill 后重新 `docker cp` 对应目录。

## 3. 不改 compose 时：复制 Skill

把 `D:\二开artex\skills\pos-*` 七个文件夹复制进 `D:\ARTEX渗透\ARTEX\skills\`。改 Skill 后容器立刻读到（bind mount）。

## 4. 在 ARTEX UI 登记 MCP

系统设置 → MCP → 新增：

- Docker 里的 ARTEX：整份粘贴 `config/mcp-server.artex.json`
- 宿主机直接跑 ARTEX：整份粘贴 `config/mcp-server.host.json`

stdio 备选（与设备同机、不走 Docker）：

- command: `pythonw.exe`
- args: `["C:\\Users\\蒋蒋\\.grok\\bin\\mcp-noconsole.py", "D:\\二开artex\\mcp\\pos-delivery\\server.py"]`

保存后刷新工具缓存。未加载 POS Skill 前，这些工具是 skill-gated，不进全局工具块。

## 5. Agent 可见性

bootstrap 会把七个 `pos-*` 合并进 `terminal` / `pentest` / `planner` / `worker` / `mainagent` / `goals`。手工做时：给要跑 POS 的 Agent 勾选七个 Skill。只勾 `pos-pentest` 时，主控仍会再加载子 Skill；子 Skill 目录也要可见，否则 `Skill` 工具报 unknown。

## 6. 拦截规则

UI 拦截规则导入或逐条新增 `config/intercept-rules.json`：

- 写入类 `mcp__pos-delivery__*` → `ask`
- Bash 文本匹配 `fastboot flash` / mtkclient 写 → `ask`

只读工具不配规则，走默认放行。

注意：ARTEX 内置规则把 Bash 里的 `reboot` 当破坏性命令。Agent 必须用 `adb_reboot`，不要 Bash `reboot`。

## 7. 开一次任务的最短指令

聊天页选 **终端渗透**，说：

> 授权 POS，窗口 [起止日期]。设备已插 USB。按指纹打到内核 ACE 或接管。

不要要求它跑一键 root。

## 8. 种专用 Agent（幂等）

复制 `config/artex-auth.example.json` → `config/.artex-auth.json`，填 ARTEX 登录密码（该文件已 gitignore）。MCP 先在 `:9911` 听着。

```text
C:\Users\蒋蒋\.grok\agent-python\python.exe D:\二开artex\scripts\bootstrap-terminal-agent.py --self-check
C:\Users\蒋蒋\.grok\agent-python\python.exe D:\二开artex\scripts\bootstrap-terminal-agent.py
```

脚本会：创建/更新 `terminal`、写入人格与 wrapup、登记 `pos-delivery`、把七个 Skill 合并进 `terminal`/`pentest`/`planner`/`worker`/`mainagent`/`goals` 的可见性、导入 `[POS]` 拦截、给编排 Agent 前置 POS 路由加段。默认不整份替换 `pentest`。宿主机 ARTEX 加 `--host-mcp`。
