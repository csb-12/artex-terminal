# -*- coding: utf-8 -*-
"""把现有 ARTEX 特化成「终端渗透」Agent（幂等，只打 HTTP API，不改 Go 源码）。

用法（在本仓库根目录）：
  python scripts/bootstrap-terminal-agent.py --self-check
  python scripts/bootstrap-terminal-agent.py --init
  python scripts/bootstrap-terminal-agent.py
  python scripts/bootstrap-terminal-agent.py --dry-run
  python scripts/bootstrap-terminal-agent.py --password <ARTEX密码>
  python scripts/bootstrap-terminal-agent.py --host-mcp
  python scripts/bootstrap-terminal-agent.py --via-postgres

密码来源：--password > 环境变量 ARTEX_PASSWORD > config/.artex-auth.json
本脚本不打印密码，不写进任何日志。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# 本机 ARTEX / MCP 走直连。Clash TUN 会让 urllib 默认代理把 127.0.0.1:9911 吞成悬挂。
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

PACK = Path(__file__).resolve().parent.parent
MANIFEST = PACK / "config" / "agent-terminal.json"
AUTH_FILE = PACK / "config" / ".artex-auth.json"
ADD_START = "━━ 终端渗透路由（二开）━━"
ADD_END = "━━ 终端渗透路由结束 ━━"
POS_SKILLS = [
    "pos-pentest",
    "pos-usb-entry",
    "pos-pax-fastboot",
    "pos-verifone-sbi",
    "pos-mtk-brom",
    "pos-android-lpe",
    "pos-takeover",
    "pos-code-audit",
]
DEFAULT_INTERCEPT_TOOLS = [
    "Bash",
    "WebFetch",
    "web_search",
    "shell_open",
    "shell_send",
    "Write",
    "Edit",
    "MultiEdit",
]
POS_WRITE_TOOLS = [
    "fastboot_flashing_unlock",
    "fastboot_oem_unlock",
    "fastboot_flash",
    "fastboot_erase",
    "fastboot_boot_image",
    "mtk_seccfg_unlock",
    "mtk_partition_write",
    "mtk_partition_erase",
    "sbi_overlay",
    "xdl_upload",
    "magisk_patch_boot",
    "payload_deliver",
]
POS_INTERCEPT_TOOLS = [f"mcp__pos-delivery__{n}" for n in POS_WRITE_TOOLS] + [
    "mcp__pos-delivery__adb_shell",
]
REQUIRED_FILES = [
    "agent/terminal.md",
    "agent/terminal-wrapup.md",
    "agent/orchestration-addendum.md",
    "config/agent-terminal.json",
    "config/artex-auth.example.json",
    "config/intercept-rules.json",
    "config/mcp-server.artex.json",
    "config/mcp-server.host.json",
    "config/docker-compose.terminal.yml",
    "config/docker-compose.cdrive.yml",
    "config/docker-compose.namedvol.yml",
    "config/docker-compose.override.example.yml",
    "config/compose.env.example",
    "scripts/launch-http.vbs",
    "scripts/launch-http.ps1",
    "LICENSE",
    "SECURITY.md",
    "mcp/pos-delivery/server.py",
    "mcp/pos-delivery/data/qcom_edl_index.json",
    "mcp/pos-delivery/data/kernel_cve_index.json",
    "docs/06-终端渗透Agent.md",
]
GRAPH_TOOLS = ["insert_assets", "list_assets", "list_companies"]


class APIError(RuntimeError):
    def __init__(self, status: int, url: str, body: str):
        self.status = status
        self.url = url
        snippet = body.replace("\r", " ").replace("\n", " ")[:400]
        super().__init__(f"HTTP {status} {url} {snippet}")


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_text(path: Path) -> str:
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


def skill_frontmatter(path: Path) -> dict[str, str]:
    text = load_text(path)
    if not text.startswith("---"):
        raise ValueError(f"{path} 缺少 YAML frontmatter")
    parts = text.split("---", 2)
    if len(parts) < 3:
        raise ValueError(f"{path} frontmatter 未闭合")
    fm: dict[str, str] = {}
    for line in parts[1].splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        fm[k.strip()] = v.strip()
    return fm


def upsert_addendum(current: str, addendum: str) -> str:
    block = addendum.strip() + "\n\n"
    if ADD_START in current and ADD_END in current:
        i = current.find(ADD_START)
        j = current.find(ADD_END, i)
        if i >= 0 and j > i:
            j += len(ADD_END)
            while j < len(current) and current[j] == "\n":
                j += 1
            return current[:i] + block + current[j:]
    return block + current.lstrip()


def union_keep(existing: list, extra: list) -> list:
    out: list = []
    seen: set = set()
    for x in list(existing) + list(extra):
        if x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out


def self_check() -> list[str]:
    errors: list[str] = []
    for rel in REQUIRED_FILES:
        if not (PACK / rel).is_file():
            errors.append(f"缺文件 {rel}")

    for name in POS_SKILLS:
        p = PACK / "skills" / name / "SKILL.md"
        if not p.is_file():
            errors.append(f"缺 Skill {name}")
            continue
        try:
            fm = skill_frontmatter(p)
        except ValueError as e:
            errors.append(str(e))
            continue
        if fm.get("name") != name:
            errors.append(f"{name} frontmatter name={fm.get('name')!r}")
        if fm.get("mcps") != "pos-delivery":
            errors.append(f"{name} mcps={fm.get('mcps')!r} 必须是 pos-delivery")
        desc = fm.get("description", "")
        n = len(desc.encode("utf-8"))
        if n > 500:
            errors.append(f"{name} description {n}B > 500")
        if not desc:
            errors.append(f"{name} description 空")

    try:
        man = load_json(MANIFEST)
    except Exception as e:
        errors.append(f"agent-terminal.json {e}")
        man = {}
    if man.get("key") != "terminal" or man.get("name") != "终端渗透":
        errors.append(f"manifest key/name {man.get('key')}/{man.get('name')}")
    if man.get("mcp_name") != "pos-delivery":
        errors.append("manifest mcp_name 必须是 pos-delivery")
    if man.get("skills") != POS_SKILLS:
        errors.append(f"manifest skills 与八目录不一致: {man.get('skills')}")
    if "terminal" not in (man.get("wire_agents") or []):
        errors.append("wire_agents 必须含 terminal")
    if "terminal" in (man.get("addendum_agents") or []):
        errors.append("addendum_agents 不应含 terminal（terminal 用整份人格）")

    term = load_text(PACK / "agent" / "terminal.md") if (PACK / "agent" / "terminal.md").is_file() else ""
    if "{{" in term:
        errors.append("agent/terminal.md 含 {{ ，自定义 Agent 渲染会失败")
    if "pos-pentest" not in term or "usb_enum" not in term:
        errors.append("terminal.md 缺少开局 Skill pos-pentest / usb_enum")
    if "一键 root" not in term:
        errors.append("terminal.md 未禁止一键 root")
    if "核心心法" not in term:
        errors.append("terminal.md 缺少原版 ARTEX 核心心法结构")
    if "自主决策" not in term:
        errors.append("terminal.md 缺少自主决策段")
    if "每轮必须交代" in term:
        errors.append("terminal.md 不应再强制每轮状态报告")
    if "TodoWrite" not in term:
        errors.append("terminal.md 缺少 TodoWrite 路线组合")
    if "fingerprint_classify" not in term:
        errors.append("terminal.md 缺少 fingerprint_classify")
    if "只加载 next_skills[0]" in term:
        errors.append("terminal.md 把分类器当指挥官了")
    if "必须按这个顺序" in term:
        errors.append("terminal.md 不应再写死板第一回合顺序")

    add = load_text(PACK / "agent" / "orchestration-addendum.md") if (PACK / "agent" / "orchestration-addendum.md").is_file() else ""
    if ADD_START not in add or ADD_END not in add:
        errors.append("orchestration-addendum.md 缺幂等标记")
    if "建议不是命令" not in add:
        errors.append("orchestration-addendum.md 缺少自主决策口径")
    if "只加载 next_skills[0]" in add:
        errors.append("orchestration-addendum.md 把分类器当指挥官了")
    if "{{" in add:
        errors.append("orchestration-addendum.md 含 {{")

    wrap = load_text(PACK / "agent" / "terminal-wrapup.md") if (PACK / "agent" / "terminal-wrapup.md").is_file() else ""
    if "{{" in wrap:
        errors.append("terminal-wrapup.md 含 {{")

    try:
        ir = load_json(PACK / "config" / "intercept-rules.json")
        rules = ir.get("rules") or []
        if len(rules) < 3:
            errors.append(f"intercept-rules 只有 {len(rules)} 条")
        names = []
        for r in rules:
            names.append(r.get("name", ""))
            if not str(r.get("name", "")).startswith("[POS]"):
                errors.append(f"拦截规则名未以 [POS] 开头: {r.get('name')}")
            if r.get("action") != "ask":
                errors.append(f"{r.get('name')} action={r.get('action')}")
            try:
                re.compile(r.get("pattern") or "")
            except re.error as e:
                errors.append(f"{r.get('name')} 正则无效: {e}")
        if len(names) != len(set(names)):
            errors.append("拦截规则重名")
    except Exception as e:
        errors.append(f"intercept-rules.json {e}")

    for rel, expect_host in (
        ("config/mcp-server.artex.json", "host.docker.internal"),
        ("config/mcp-server.host.json", "127.0.0.1"),
    ):
        p = PACK / rel
        if not p.is_file():
            continue
        try:
            m = load_json(p)
        except Exception as e:
            errors.append(f"{rel} {e}")
            continue
        if m.get("name") != "pos-delivery":
            errors.append(f"{rel} name={m.get('name')}")
        if m.get("transport") != "http":
            errors.append(f"{rel} transport={m.get('transport')}")
        if expect_host not in (m.get("url") or ""):
            errors.append(f"{rel} url 应含 {expect_host}: {m.get('url')}")

    for rel in ("config/docker-compose.terminal.yml", "config/docker-compose.override.example.yml"):
        p = PACK / rel
        if not p.is_file():
            continue
        text = load_text(p)
        if re.search(r"二开artex/skills:/app/skills(?:\s|$)", text):
            errors.append(f"{rel} 整卷 overlay 了 /app/skills，会盖掉 api-recon/bytesrc")
        binds = re.findall(r"/app/skills/pos-[a-z0-9-]+", text)
        if len(set(binds)) != 8:
            errors.append(f"{rel} pos-* 挂载 {sorted(set(binds))} 不是 8 个")
        if "${ERKA_ROOT}" not in text:
            errors.append(f"{rel} 必须用 ${{ERKA_ROOT}} 挂载，不要写死本机路径")

    gi = load_text(PACK / ".gitignore") if (PACK / ".gitignore").is_file() else ""
    if "config/.artex-auth.json" not in gi:
        errors.append(".gitignore 未忽略 config/.artex-auth.json")
    if "config/.compose.env" not in gi:
        errors.append(".gitignore 未忽略 config/.compose.env")

    for rel in (
        "README.md",
        "LICENSE",
        "NOTICE.md",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "scripts/launch-http.vbs",
        "scripts/launch-http.ps1",
        "scripts/bootstrap-terminal-agent.py",
        "config/docker-compose.terminal.yml",
        "config/docker-compose.override.example.yml",
        "config/docker-compose.namedvol.yml",
        "config/docker-compose.cdrive.yml",
        "config/compose.env.example",
        "docs/02-Skill与MCP接口.md",
        "docs/05-挂载到ARTEX.md",
        "docs/06-终端渗透Agent.md",
        "mcp/pos-delivery/README.md",
    ):
        p = PACK / rel
        if p.is_file() and "\u848b\u848b" in load_text(p):
            errors.append(f"{rel} 含本机用户名，不能公开")

    example = PACK / "config" / "artex-auth.example.json"
    if example.is_file():
        try:
            ex = load_json(example)
            if "password" in json.dumps(ex) and ex.get("password") and "在此填写" not in str(ex.get("password")):
                errors.append("artex-auth.example.json 不能写真实密码")
        except Exception as e:
            errors.append(f"artex-auth.example.json {e}")

    return errors


def docker_slash(p: Path) -> str:
    return str(p.resolve()).replace("\\", "/")


def write_compose_env() -> Path:
    out = PACK / "config" / ".compose.env"
    lines = [
        "# generated by bootstrap --init; do not commit",
        f"ERKA_ROOT={docker_slash(PACK)}",
    ]
    grok = Path.home() / ".grok" / "auth.json"
    if grok.is_file():
        lines.append(f"GROK_AUTH_JSON={docker_slash(grok)}")
    artex = (os.environ.get("ARTEX_HOME") or "").strip()
    if artex:
        lines.append(f"ARTEX_HOME={docker_slash(Path(artex))}")
    userprofile = Path.home()
    artex_bind = userprofile / "artex-bind"
    erka_bind = userprofile / "erka-bind"
    if artex_bind.exists():
        lines.append(f"ARTEX_BIND={docker_slash(artex_bind)}")
    if erka_bind.exists():
        lines.append(f"ERKA_BIND={docker_slash(erka_bind)}")
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out


def print_init_help(env_path: Path) -> None:
    log(f"已写入 {env_path}")
    log("")
    log("下一步：")
    log("  1. python -m pip install -r mcp/pos-delivery/requirements.txt")
    log("  2. pythonw mcp/pos-delivery/run_http_9911.py")
    log("     或 scripts/launch-http.ps1 / scripts/launch-http.vbs")
    log("  3. 设置 ARTEX_HOME 为你的 ARTEX 安装目录，挂 Skill：")
    log("     docker compose --env-file config/.compose.env -f \"%ARTEX_HOME%/docker-compose.yml\" -f config/docker-compose.terminal.yml up -d")
    log("  4. 复制 config/artex-auth.example.json → config/.artex-auth.json 并填密码")
    log("  5. python scripts/bootstrap-terminal-agent.py")
    log(f"  ERKA_ROOT={docker_slash(PACK)}")


class Artex:
    def __init__(self, base: str, token: str | None = None, timeout: float = 30.0):
        self.base = base.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _req(self, method: str, path: str, body: Any | None = None, timeout: float | None = None) -> Any:
        data = None
        headers = {"Accept": "application/json"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        if body is not None:
            raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
            data = raw
            headers["Content-Type"] = "application/json; charset=utf-8"
        req = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with _OPENER.open(req, timeout=timeout or self.timeout) as resp:
                blob = resp.read()
                if not blob:
                    return {}
                return json.loads(blob.decode("utf-8"))
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", "replace")
            raise APIError(e.code, path, err_body) from None
        except urllib.error.URLError as e:
            raise RuntimeError(f"连不上 ARTEX {self.base}{path}: {e.reason}") from None

    def get(self, path: str) -> Any:
        return self._req("GET", path)

    def post(self, path: str, body: Any, timeout: float | None = None) -> Any:
        return self._req("POST", path, body, timeout=timeout)

    def put(self, path: str, body: Any) -> Any:
        return self._req("PUT", path, body)

    def patch(self, path: str, body: Any) -> Any:
        return self._req("PATCH", path, body)

    def get_allow_404(self, path: str) -> Any | None:
        try:
            return self.get(path)
        except APIError as e:
            if e.status == 404:
                return None
            raise


def ping_json(url: str, timeout: float = 2.0) -> bool:
    """本机健康检查。socket + 线程超时，避免 9911 未监听时 Clash 把 connect 挂死。"""
    parsed = urlparse(url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    box: dict[str, bool] = {"ok": False}

    def _run() -> None:
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            try:
                s.settimeout(timeout)
                req = f"GET {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                s.sendall(req.encode("ascii"))
                data = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > 65536:
                        break
            finally:
                s.close()
            status = data.split(b"\r\n", 1)[0]
            box["ok"] = b" 2" in status
        except Exception:
            box["ok"] = False

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout + 0.8)
    return bool(box["ok"])


def resolve_auth(args: argparse.Namespace) -> tuple[str, str, str, str]:
    url = (args.url or "").strip()
    user = "ARTEX"
    password = (args.password or os.environ.get("ARTEX_PASSWORD") or "").strip()
    token = (getattr(args, "token", "") or os.environ.get("ARTEX_TOKEN") or "").strip()
    if AUTH_FILE.is_file():
        try:
            cfg = load_json(AUTH_FILE)
        except Exception as e:
            raise SystemExit(f"读 {AUTH_FILE} 失败: {e}") from None
        url = url or str(cfg.get("url") or "").strip()
        user = str(cfg.get("username") or user).strip() or "ARTEX"
        if not password:
            password = str(cfg.get("password") or "").strip()
        if not token:
            token = str(cfg.get("token") or "").strip()
    url = url or "http://127.0.0.1:8787"
    return url, user, password, token


def mcp_url(args: argparse.Namespace) -> str:
    rel = "config/mcp-server.host.json" if args.host_mcp else "config/mcp-server.artex.json"
    return load_json(PACK / rel)["url"]


def log(msg: str) -> None:
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()


def seed(args: argparse.Namespace) -> int:
    man = load_json(MANIFEST)
    prompt = load_text(PACK / man["prompt_file"])
    wrapup = load_text(PACK / man["wrapup_file"])
    addendum = load_text(PACK / man["addendum_file"])
    intercept = load_json(PACK / "config" / "intercept-rules.json")["rules"]
    url, user, password, token = resolve_auth(args)
    mcp_endpoint = mcp_url(args)
    host_health = str(load_json(PACK / "config" / "mcp-server.host.json").get("url") or "").rstrip("/") + "/health"
    key = man["key"]
    skills = list(man["skills"])
    wire = list(man["wire_agents"])
    add_agents = list(man["addendum_agents"])

    log(f"ARTEX {url}")
    log(f"Agent {key} / {man['name']}")
    log(f"MCP pos-delivery {mcp_endpoint}")
    log(f"挂 Skill {', '.join(skills)}")
    log(f"可见性写入 {', '.join(wire)}")
    log(f"加段写入 {', '.join(add_agents)}")
    if args.specialize_pentest:
        log("警告: --specialize-pentest 会用终端人格整份替换 pentest，任务模式丢掉 {{.Goal}} / Web SRC")
    if args.dry_run:
        log("dry-run：不登录、不写库")
        return 0
    if not password and not token:
        log("没有密码或 token。复制 config/artex-auth.example.json 为 config/.artex-auth.json 并填密码，或设 ARTEX_PASSWORD / ARTEX_TOKEN / --password / --token")
        return 2

    if not ping_json(url.rstrip("/") + "/api/health"):
        log(f"ARTEX 健康检查失败: {url}/api/health  （先在 {url} 打开 UI）")
        return 3

    api = None
    if token:
        probe = Artex(url, token)
        try:
            probe.get("/api/agents")
            api = probe
            log("使用已有 token")
        except APIError as e:
            if e.status in (401, 403) and password:
                log("token 无效或已过期，改用密码登录")
            else:
                log(f"token 无效或已过期: {e}")
                log("本机 Docker 可改跑: --via-postgres  （只写提示词/加段，不管 MCP）")
                return 4
    if api is None:
        if not password:
            log("没有密码或 token。复制 config/artex-auth.example.json 为 config/.artex-auth.json 并填密码，或设 ARTEX_PASSWORD / ARTEX_TOKEN / --password / --token")
            return 2
        guest = Artex(url)
        try:
            tok = guest.post("/api/auth/login", {"username": user, "password": password}).get("token")
        except APIError as e:
            log(f"登录失败: {e}")
            return 4
        if not tok:
            log("登录成功但响应没有 token")
            return 4
        api = Artex(url, tok)

    agents = {a["key"]: a for a in (api.get("/api/agents").get("agents") or [])}
    if key in agents:
        api.patch(f"/api/agents/{key}", {"name": man["name"], "description": man["description"]})
        log(f"已有 {key}，更新名称/描述")
    else:
        api.post("/api/agents", {"key": key, "name": man["name"], "description": man["description"]})
        log(f"已创建 {key}")

    detail = api.get(f"/api/agents/{key}")
    cur = detail.get("prompt") or ""
    if cur != prompt:
        api.put(f"/api/agents/{key}/prompt", {"template": prompt, "note": "二开 terminal 人格"})
        log("已写入 terminal 提示词")
    else:
        log("terminal 提示词已是最新")

    if (detail.get("wrapup_prompt") or "") != wrapup:
        api.put(f"/api/agents/{key}/wrapup", {"prompt": wrapup})
        log("已写入 wrapup")
    else:
        log("wrapup 已是最新")

    api.put(
        f"/api/agents/{key}/config",
        {
            "max_turns": int(man.get("max_turns") or 0),
            "run_seconds": int(man.get("run_seconds") or 3600),
            "web_search": bool(man.get("web_search", True)),
            "interactive_shell": bool(man.get("interactive_shell", False)),
        },
    )
    log("已写入 terminal 运行配置")

    mcp_health = ping_json(host_health)
    if not mcp_health:
        log(f"宿主机 MCP 还没起来（{host_health}）。先 scripts/launch-http.vbs。本次仍登记 MCP。")

    servers = api.get("/api/mcp").get("servers") or []
    existing = next((s for s in servers if s.get("name") == "pos-delivery"), None)
    payload = {
        "name": "pos-delivery",
        "transport": "http",
        "url": mcp_endpoint,
        "enabled": True,
        "insecure": True,
        "command": "",
        "args": [],
        "env": {},
    }
    if existing:
        payload["id"] = int(existing["id"])
        same = (
            existing.get("transport") == "http"
            and existing.get("url") == mcp_endpoint
            and existing.get("enabled") is True
        )
        if same:
            mcp_id = int(existing["id"])
            log(f"MCP pos-delivery 已存在 id={mcp_id}")
        else:
            mcp_id = int(api.post("/api/mcp", payload).get("id") or existing["id"])
            log(f"已更新 MCP pos-delivery id={mcp_id}")
        if mcp_health:
            try:
                api.post(f"/api/mcp/{mcp_id}/refresh", {}, timeout=50)
                log("已刷新 MCP 工具缓存")
            except Exception as e:
                log(f"刷新 MCP 工具缓存失败（可在 UI 再点一次）: {e}")
    else:
        # 服务未就绪时先 disabled 插入，避免 ARTEX 为发现工具卡 45s；再立刻 enable。
        if not mcp_health:
            payload["enabled"] = False
            mcp_id = int(api.post("/api/mcp", payload).get("id"))
            payload["id"] = mcp_id
            payload["enabled"] = True
            api.post("/api/mcp", payload)
            log(f"已登记 MCP pos-delivery id={mcp_id}（工具发现待 MCP 起来后刷新）")
        else:
            mcp_id = int(api.post("/api/mcp", payload, timeout=50).get("id"))
            log(f"已新增 MCP pos-delivery id={mcp_id}")

    for ag_key in wire:
        vis = api.get_allow_404(f"/api/agents/{ag_key}/visibility")
        if vis is None:
            log(f"跳过可见性 {ag_key}（agent 不存在）")
            continue
        mcp_ids = [int(x) for x in (vis.get("mcp") or [])]
        sk = list(vis.get("skill") or [])
        new_mcp = union_keep(mcp_ids, [mcp_id])
        new_sk = union_keep(sk, skills)
        if new_mcp == mcp_ids and new_sk == sk:
            log(f"可见性 {ag_key} 已包含 POS")
            continue
        api.put(f"/api/agents/{ag_key}/visibility", {"mcp": new_mcp, "skill": new_sk})
        log(f"已合并可见性 {ag_key} skill+={len(new_sk) - len(sk)} mcp+={len(new_mcp) - len(mcp_ids)}")

    live_rules = api.get("/api/intercept/rules").get("rules") or []
    by_name = {r.get("name"): r for r in live_rules}
    for rule in intercept:
        body = {k: rule[k] for k in (
            "name", "enabled", "priority", "match_target", "match_type",
            "pattern", "action", "message", "timeout_enabled", "timeout_seconds", "timeout_action",
        ) if k in rule}
        old = by_name.get(rule["name"])
        if old:
            same = all(old.get(k) == body.get(k) for k in body if k != "name")
            if same:
                log(f"拦截已存在 {rule['name']}")
                continue
            api.put(f"/api/intercept/rules/{int(old['id'])}", body)
            log(f"已更新拦截 {rule['name']}")
        else:
            api.post("/api/intercept/rules", body)
            log(f"已创建拦截 {rule['name']}")

    try:
        cfg = api.get("/api/intercept/tool-config")
        enabled = list(cfg.get("enabled_tools") or [])
        if not enabled:
            enabled = list(DEFAULT_INTERCEPT_TOOLS)
        new_en = union_keep(enabled, POS_INTERCEPT_TOOLS)
        if new_en != enabled:
            api.put("/api/intercept/tool-config", {"enabled_tools": new_en})
            log("已合并拦截工具名单（默认工具 + POS 写入）")
        else:
            log("拦截工具名单已含 POS 写入工具")
    except Exception as e:
        log(f"拦截工具名单更新失败（规则仍在）: {e}")

    for ag_key in add_agents:
        if args.specialize_pentest and ag_key == "pentest":
            det = api.get_allow_404(f"/api/agents/{ag_key}")
            if det is None:
                log("pentest 不存在，跳过 specialize")
                continue
            if (det.get("prompt") or "") != prompt:
                api.put(f"/api/agents/{ag_key}/prompt", {"template": prompt, "note": "specialize-pentest=terminal"})
                log("已用终端人格整份替换 pentest")
            else:
                log("pentest 已是终端人格")
            continue
        det = api.get_allow_404(f"/api/agents/{ag_key}")
        if det is None:
            log(f"跳过加段 {ag_key}（agent 不存在）")
            continue
        cur_p = det.get("prompt") or ""
        new_p = upsert_addendum(cur_p, addendum)
        if new_p == cur_p:
            log(f"加段 {ag_key} 已在")
            continue
        api.put(f"/api/agents/{ag_key}/prompt", {"template": new_p, "note": "终端渗透路由加段"})
        log(f"已写入加段 {ag_key}")

    bind_graph_tools(api, key)

    log("完成。聊天页选「终端渗透」。第一条先让它加载 pos-pentest。MCP 必须先在 :9911 听着。")
    return 0


def _dollar(s: str, tag: str = "body") -> str:
    t = tag
    while f"${t}$" in s:
        t += "x"
    return f"${t}${s}${t}$"


def _psql(container: str, sql: str) -> str:
    r = subprocess.run(
        ["docker", "exec", "-i", container, "psql", "-U", "artex", "-d", "artex", "-v", "ON_ERROR_STOP=1", "-tA"],
        input=sql.encode("utf-8"),
        capture_output=True,
    )
    if r.returncode != 0:
        err = (r.stderr or b"").decode("utf-8", "replace") + (r.stdout or b"").decode("utf-8", "replace")
        raise RuntimeError(err.strip() or f"psql exit {r.returncode}")
    return (r.stdout or b"").decode("utf-8")


def plant_via_postgres(args: argparse.Namespace) -> int:
    """UI 登录不可用时，把人格/加段/wrapup 写进本机 ARTEX postgres。不管 MCP/拦截。"""
    man = load_json(MANIFEST)
    prompt = load_text(PACK / man["prompt_file"])
    wrapup = load_text(PACK / man["wrapup_file"])
    addendum = load_text(PACK / man["addendum_file"])
    desc = str(man.get("description") or "")
    name = str(man.get("name") or "终端渗透")
    key = man["key"]
    add_agents = list(man["addendum_agents"])
    container = args.postgres_container
    if args.dry_run:
        log(f"dry-run --via-postgres container={container} 将写 {key} + 加段 {', '.join(add_agents)}")
        return 0
    try:
        keys = _psql(container, "select key from agents order by key;")
    except Exception as e:
        log(f"连不上 postgres 容器 {container}: {e}")
        return 7
    have = {ln.strip() for ln in keys.splitlines() if ln.strip()}
    if key not in have:
        log(f"库里没有 agent {key}，先用 API bootstrap 创建")
        return 7

    sql: list[str] = []
    sql.append("BEGIN;")
    sql.append(
        "DO $do$\n"
        "DECLARE aid bigint; pid bigint; ver int;\n"
        "BEGIN\n"
        f"  SELECT id INTO aid FROM agents WHERE key = {_dollar(key, 'k')};\n"
        "  SELECT COALESCE(max(version),0)+1 INTO ver FROM agent_prompts WHERE agent_id = aid;\n"
        "  INSERT INTO agent_prompts(agent_id,version,template_text,note,updated_by)\n"
        f"  VALUES (aid, ver, {_dollar(prompt, 'p')}, '二开 terminal 人格', 'via-postgres')\n"
        "  RETURNING id INTO pid;\n"
        "  UPDATE agents SET current_prompt_id = pid,\n"
        f"    name = {_dollar(name, 'n')},\n"
        f"    description = {_dollar(desc, 'd')},\n"
        f"    wrapup_prompt = {_dollar(wrapup, 'w')}\n"
        "    WHERE id = aid;\n"
        "END\n"
        "$do$;"
    )

    fetch = _psql(
        container,
        "select json_build_object('key', a.key, 'template', coalesce(p.template_text,''))::text "
        "from agents a left join agent_prompts p on p.id=a.current_prompt_id "
        f"where a.key in ({','.join(_dollar(k, 'a'+str(i)) for i,k in enumerate(add_agents))});",
    )
    current: dict[str, str] = {}
    for ln in fetch.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        row = json.loads(ln)
        current[row["key"]] = row.get("template") or ""

    for i, ag_key in enumerate(add_agents):
        if ag_key not in have:
            log(f"跳过加段 {ag_key}（库里没有）")
            continue
        if args.specialize_pentest and ag_key == "pentest":
            new_p = prompt
            note = "specialize-pentest=terminal"
        else:
            new_p = upsert_addendum(current.get(ag_key, ""), addendum)
            note = "终端渗透路由加段"
        if new_p == current.get(ag_key, ""):
            log(f"加段 {ag_key} 已在")
            continue
        tag = f"t{i}"
        sql.append(
            "DO $do$\n"
            "DECLARE aid bigint; pid bigint; ver int;\n"
            "BEGIN\n"
            f"  SELECT id INTO aid FROM agents WHERE key = {_dollar(ag_key, 'k'+tag)};\n"
            "  SELECT COALESCE(max(version),0)+1 INTO ver FROM agent_prompts WHERE agent_id = aid;\n"
            "  INSERT INTO agent_prompts(agent_id,version,template_text,note,updated_by)\n"
            f"  VALUES (aid, ver, {_dollar(new_p, 'p'+tag)}, {_dollar(note, 'n'+tag)}, 'via-postgres')\n"
            "  RETURNING id INTO pid;\n"
            "  UPDATE agents SET current_prompt_id = pid WHERE id = aid;\n"
            "END\n"
            "$do$;"
        )
        log(f"将写入加段 {ag_key}")

    sql.append("COMMIT;")
    try:
        _psql(container, "\n".join(sql))
    except Exception as e:
        log(f"写入 postgres 失败: {e}")
        return 7

    check = _psql(
        container,
        "select case when p.template_text like '%自主决策%' then 'yes' else 'no' end "
        "from agents a join agent_prompts p on p.id=a.current_prompt_id where a.key='terminal';",
    ).strip()
    if check != "yes":
        log("写入后 terminal 提示词未含「自主决策」，请检查")
        return 7
    log(f"已经 docker postgres 写入 {key} 人格/wrapup，以及编排加段。MCP/拦截未改（需要 API 登录）。")
    return 0


def bind_graph_tools(api: Artex, agent_key: str) -> None:
    """聊天页没有探索图，但 insert_assets/list_assets 仍可写全局资产图。不绑 report_finding。"""
    try:
        rows = api.get("/api/tools").get("tools") or []
    except Exception as e:
        log(f"读工具目录失败，跳过资产图绑定: {e}")
        return
    by = {t.get("key"): t for t in rows if isinstance(t, dict)}
    for tool_key in GRAPH_TOOLS:
        row = by.get(tool_key)
        if not row:
            log(f"跳过绑工具 {tool_key}（目录无此工具）")
            continue
        agents = list(row.get("agents") or [])
        if agent_key in agents:
            log(f"工具 {tool_key} 已绑 {agent_key}")
            continue
        body = {
            "description": row.get("description") or "",
            "schema": row.get("schema") if row.get("schema") is not None else {},
            "agents": agents + [agent_key],
            "enabled": bool(row.get("enabled", True)),
        }
        try:
            api.put(f"/api/tools/{tool_key}", body)
            log(f"已把 {tool_key} 绑到 {agent_key}")
        except Exception as e:
            log(f"绑定 {tool_key} 失败: {e}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="把 ARTEX 特化成终端渗透 Agent")
    ap.add_argument("--self-check", action="store_true", help="只校验本包文件，不打 API")
    ap.add_argument("--dry-run", action="store_true", help="打印计划，不登录")
    ap.add_argument("--url", default="", help="ARTEX UI 地址，默认 http://127.0.0.1:8787")
    ap.add_argument("--password", default="", help="ARTEX 登录密码（不要写进仓库）")
    ap.add_argument("--token", default="", help="已有 JWT，跳过登录（不要写进仓库）")
    ap.add_argument("--host-mcp", action="store_true", help="MCP URL 用 127.0.0.1:9911（宿主机 ARTEX）")
    ap.add_argument(
        "--specialize-pentest",
        action="store_true",
        help="用 terminal.md 整份替换 pentest 提示词。默认否：只加路由段，保留滴滴/字节 Web SRC",
    )
    ap.add_argument(
        "--via-postgres",
        action="store_true",
        help="UI token 过期时，经本机 docker postgres 写 terminal 人格/wrapup/编排加段",
    )
    ap.add_argument("--postgres-container", default="artex-postgres-1", help="postgres 容器名")
    ap.add_argument(
        "--init",
        action="store_true",
        help="写入 config/.compose.env（ERKA_ROOT=本仓库），打印别人克隆后的下一步",
    )
    args = ap.parse_args(argv)

    errs = self_check()
    if errs:
        for e in errs:
            log("SELF-CHECK FAIL  " + e)
        return 1
    log("SELF-CHECK PASS  包文件齐全")
    if args.self_check:
        return 0
    if args.init:
        print_init_help(write_compose_env())
        return 0
    try:
        if args.via_postgres:
            return plant_via_postgres(args)
        return seed(args)
    except APIError as e:
        log(str(e))
        return 5
    except Exception as e:
        log(f"{type(e).__name__}: {e}")
        return 6


if __name__ == "__main__":
    sys.exit(main())
