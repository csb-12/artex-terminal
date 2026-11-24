# 挂载到 ARTEX

本包不改 ARTEX 源码。把 Skill 挂进容器的 `/app/skills`，MCP 跑在宿主机，再用 bootstrap 种出专用 Agent **终端渗透**。

产品说明与聊天页用法：`docs/06-终端渗透Agent.md`。

下面用两个占位：

- `ARTEX_HOME` — 你的 ARTEX 安装目录（里面有 `docker-compose.yml`）
- `ERKA_ROOT` — 本仓库根目录，由 `python scripts/bootstrap-terminal-agent.py --init` 写入 `config/.compose.env`

Skill 加载顺序（ARTEX 侧）：`ARTEX_SKILL_DIR` > `config.json` 的 `skill_dir` > 可执行文件旁 `skills/`。Docker 通常绑定 `./skills:/app/skills`。

## 1. 启动 pos-delivery（宿主机，无黑窗）

```text
pythonw mcp/pos-delivery/run_http_9911.py
```

或 `scripts/launch-http.ps1` / 双击 `scripts/launch-http.vbs`。包装脚本绑 `0.0.0.0:9911`，让容器里的 `http://host.docker.internal:9911` 能打到宿主机。

检查：`http://127.0.0.1:9911/health` 应返回 `{"ok":true,"server":"pos-delivery"}`。

依赖：`python -m pip install -r mcp/pos-delivery/requirements.txt`（pyserial）。adb/fastboot 在 PATH 或 Android SDK `platform-tools`。MTK 链需要本机 mtkclient。

可选环境变量见 `mcp/pos-delivery/env.example`。

## 2. Docker：覆盖挂载八个 Skill

先生成本机路径：

```text
python scripts/bootstrap-terminal-agent.py --init
```

推荐用第二份 compose，不碰 ARTEX 目录里的文件：

```text
docker compose --env-file config/.compose.env -f "%ARTEX_HOME%/docker-compose.yml" -f config/docker-compose.terminal.yml up -d
```

也可以把 `config/docker-compose.override.example.yml` 复制为 ARTEX 目录下的 `docker-compose.override.yml`。两种方式都是把各 `pos-*` 目录叠到 `/app/skills/pos-*`，**不要**把整个 `skills/` 盖到 `/app/skills`，否则会盖掉 `api-recon` / `bytesrc`。不要两份同时叠。

Windows Docker Desktop 已提供 `host.docker.internal`。Linux 引擎需要 `extra_hosts`（terminal.yml 已加）。

### Windows：D: virtiofs 损坏时

若 `docker compose` 报 `mkdir /run/desktop/mnt/host/d: file exists` / `I/O error`，**不要叠原 compose**（里面可能含 D: 绑定）。改用 named volume + `docker cp`：

```text
docker compose -p artex --env-file "%ARTEX_HOME%/.env" --env-file config/.compose.env -f config/docker-compose.namedvol.yml up -d
docker cp "%ARTEX_HOME%/grok-bridge.py" artex-artex-1:/app/grok-bridge.py
docker cp "%ARTEX_HOME%/skills/." artex-artex-1:/app/skills/
docker cp skills/. artex-artex-1:/app/skills/
```

项目名必须是 `artex` 才能沿用已有 postgres 卷。改 Skill 后重新 `docker cp` 对应目录。

C: NTFS 联接（`config/docker-compose.cdrive.yml`）只在 virtiofs 能跟着联接走的环境可用；有的 Docker Desktop 会把联接解析回真实盘符，那份环境请用 namedvol。

## 3. 不改 compose 时：复制 Skill

把本仓库 `skills/pos-*` 八个文件夹复制进 `$ARTEX_HOME/skills/`。若 ARTEX 的 compose 把 `./skills` bind 进容器，改完立刻读到。

## 4. 在 ARTEX UI 登记 MCP

系统设置 → MCP → 新增：

- Docker 里的 ARTEX：整份粘贴 `config/mcp-server.artex.json`
- 宿主机直接跑 ARTEX：整份粘贴 `config/mcp-server.host.json`

stdio 备选（与设备同机、不走 Docker）：

- command: `pythonw.exe`
- args: `["mcp/pos-delivery/server.py"]`（改成你克隆后的绝对路径）

子进程 `CREATE_NO_WINDOW`。禁止 `cmd /k`。保存后刷新工具缓存。未加载 POS Skill 前，这些工具是 skill-gated，不进全局工具块。

## 5. Agent 可见性

bootstrap 会把八个 `pos-*` 合并进 `terminal` / `pentest` / `planner` / `worker` / `mainagent` / `goals`。手工做时：给要跑 POS 的 Agent 勾选八个 Skill。只勾 `pos-pentest` 时，主控仍会再加载子 Skill；子 Skill 目录也要可见，否则 `Skill` 工具报 unknown。Skill 是领域知识，不是逐步念完的剧本。

## 6. 拦截规则

UI 拦截规则导入或逐条新增 `config/intercept-rules.json`：

- 写入类 `mcp__pos-delivery__*` → `ask`
- Bash 文本匹配 `fastboot flash` / mtkclient 写 → `ask`

只读工具不配规则，走默认放行。

注意：ARTEX 内置规则把 Bash 里的 `reboot` 当破坏性命令。Agent 必须用 `adb_reboot`，不要 Bash `reboot`。

## 7. 开一次任务的最短指令

聊天页选 **终端渗透**，说：

> 授权 POS，窗口 [起止日期]。设备已插 USB。看清入口后打到内核 ACE 或接管。

不要要求它跑一键 root。

## 8. 种专用 Agent（幂等）

复制 `config/artex-auth.example.json` → `config/.artex-auth.json`，填 ARTEX 登录密码（该文件已 gitignore）。MCP 先在 `:9911` 听着。

```text
python scripts/bootstrap-terminal-agent.py --self-check
python scripts/bootstrap-terminal-agent.py
```

脚本会：创建/更新 `terminal`、写入人格与 wrapup、登记 `pos-delivery`、把八个 Skill 合并进相关 Agent 的可见性、导入 `[POS]` 拦截、给编排 Agent 前置 POS 路由加段。默认不整份替换 `pentest`。宿主机 ARTEX 加 `--host-mcp`。UI token 过期加 `--via-postgres`。
