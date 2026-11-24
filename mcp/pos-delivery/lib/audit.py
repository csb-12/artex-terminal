"""安卓 / OS 代码审计事实地图。判断归 agent，工具不输出漏洞结论。

思路对齐 Treasure Map：六层是/否/未知；未知不沉底；事实层只读；标注层可写且必须引用 evidence_ref。
Windows 上不跑 Ghidra。函数级补丁对比标缺口，指向 WSL2 的 tmap。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from pathlib import Path
from typing import Any

from . import apkscan, elfscan
from .winproc import which

LAYERS = (
    "external_source",
    "attacker_controlled",
    "writer_known",
    "reachable",
    "filtered",
    "analysis_complete",
)
IMPACT = {
    "cmd": 0,
    "fmt": 1,
    "copy": 2,
    "jni": 3,
    "exported": 4,
    "webview": 5,
    "script": 6,
    "init": 7,
    "path": 8,
    "secret": 9,
    "elf": 10,
    "apk": 11,
}
SCRIPT_HINTS = [
    (r"\bsystem\s*\(", "cmd"),
    (r"\beval\s+", "cmd"),
    (r"`[^`]+`", "cmd"),
    (r"\$\([^)]+\)", "cmd"),
    (r"chmod\s+777", "path"),
    (r"\bchmod\s+[-+]*s", "path"),
    (r"/system/xbin/su\b", "cmd"),
    (r"\bbusybox\b", "cmd"),
]
INIT_SERVICE = re.compile(r"^\s*service\s+(\S+)\s+(\S+)", re.M)
VENDOR_PKG = re.compile(
    r"(sunmi|pax|paydroid|verifone|landi|newland|nexgo|morefun|telpo|imin|wizarpos|smartpos|pos\.)",
    re.I,
)


def atlas_dir() -> Path:
    env = os.environ.get("POS_AUDIT_ATLAS")
    if env:
        p = Path(env)
    else:
        p = Path.home() / ".pos-delivery" / "atlas"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _run_path(name: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", name.strip()) or "run"
    return atlas_dir() / f"{safe}.json"


def load_run(name: str) -> dict[str, Any]:
    p = _run_path(name)
    if not p.is_file():
        return {
            "run": name,
            "facts": [],
            "annotations": [],
            "read": [],
            "created": time.time(),
            "roots": [],
            "note": "事实层只读。判断写 annotations，必须带 evidence_ref。工具不输出漏洞结论。",
        }
    return json.loads(p.read_text(encoding="utf-8"))


def save_run(doc: dict[str, Any]) -> Path:
    p = _run_path(str(doc.get("run") or "run"))
    p.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    return p


def _sha12(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", "ignore")).hexdigest()[:12]


def evidence_ref(run: str, fact: dict[str, Any]) -> str:
    key = f"{fact.get('path')}|{fact.get('kind')}|{fact.get('name')}"
    return f"{run}#{_sha12(key)}:{fact.get('kind')}@{fact.get('name')}"


def _attach_refs(run: str, facts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for f in facts:
        g = dict(f)
        g["evidence_ref"] = evidence_ref(run, g)
        g["verdict"] = None
        out.append(g)
    return out


def list_runs() -> dict[str, Any]:
    rows = []
    for p in sorted(atlas_dir().glob("*.json")):
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        facts = doc.get("facts") or []
        ann = doc.get("annotations") or []
        rows.append(
            {
                "run": doc.get("run") or p.stem,
                "facts": len(facts),
                "annotations": len(ann),
                "unread": max(0, len(facts) - len(set(doc.get("read") or []))),
                "roots": doc.get("roots") or [],
            }
        )
    return {"ok": True, "atlas": str(atlas_dir()), "runs": rows, "tmap": tmap_status()}


def tmap_status() -> dict[str, Any]:
    exe = which("tmap")
    return {
        "available": bool(exe),
        "path": exe,
        "windows_native": os.name == "nt",
        "note": "Treasure Map 原生 Windows 不能跑 Ghidra。本 MCP 的 audit_* 提供可在 Windows 落地的事实地图（APK/ELF/init/脚本）。函数级补丁对比请 WSL2 安装 https://github.com/JoeyZzZzZz/treasure-map 后用 tmap scan/diff。未知不等于安全。工具不生成 PoC。",
    }


def _is_elf(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def _scan_script(path: Path) -> list[dict[str, Any]]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    facts = []
    if path.suffix.lower() in (".rc",) or path.name.startswith("init"):
        for m in INIT_SERVICE.finditer(text):
            facts.append(
                {
                    "kind": "init",
                    "name": f"service {m.group(1)} {m.group(2)}",
                    "path": str(path),
                    "external_source": "unknown",
                    "attacker_controlled": "unknown",
                    "writer_known": "yes",
                    "reachable": "unknown",
                    "filtered": "unknown",
                    "analysis_complete": "no",
                    "unknown_reason": "init.rc 声明是事实；谁能触发、是否 root 未证实",
                }
            )
    for rx, kind in SCRIPT_HINTS:
        if re.search(rx, text):
            facts.append(
                {
                    "kind": kind if kind != "path" else "script",
                    "name": rx,
                    "path": str(path),
                    "external_source": "unknown",
                    "attacker_controlled": "unknown",
                    "writer_known": "unknown",
                    "reachable": "unknown",
                    "filtered": "unknown",
                    "analysis_complete": "unknown",
                    "unknown_reason": "脚本文本命中，未做数据流",
                }
            )
    return facts


def _scan_secret_strings(path: Path, text: str) -> list[dict[str, Any]]:
    facts = []
    for m in re.finditer(r"(AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|sk_live_[0-9a-zA-Z]+)", text):
        facts.append(
            {
                "kind": "secret",
                "name": m.group(1)[:24] + "…",
                "path": str(path),
                "external_source": "no",
                "attacker_controlled": "no",
                "writer_known": "yes",
                "reachable": "unknown",
                "filtered": "unknown",
                "analysis_complete": "no",
                "unknown_reason": "硬编码片段是事实；是否仍有效、谁能读到未知。不要把完整密钥写进会话。",
            }
        )
    return facts


def scan_tree(root: str, run: str, limit: int = 400) -> dict[str, Any]:
    base = Path(root)
    if not base.exists():
        return {"ok": False, "error": f"路径不存在: {root}"}
    facts: list[dict[str, Any]] = []
    n_apk = n_elf = n_script = 0
    skipped = []
    files = [base] if base.is_file() else list(base.rglob("*"))
    for p in files:
        if not p.is_file():
            continue
        if p.stat().st_size > 80 * 1024 * 1024:
            skipped.append({"path": str(p), "reason": "file too large"})
            continue
        low = p.suffix.lower()
        try:
            if low == ".apk" or p.name.endswith(".apk"):
                if n_apk >= 40:
                    skipped.append({"path": str(p), "reason": "apk cap"})
                    continue
                facts.extend(apkscan.scan_apk(p))
                n_apk += 1
            elif _is_elf(p):
                if n_elf >= limit:
                    skipped.append({"path": str(p), "reason": "elf cap"})
                    continue
                facts.extend(elfscan.scan_elf(p))
                n_elf += 1
            elif low in (".sh", ".rc", ".xml", ".prop", ".js") or p.name in ("ueventd.rc", "init.rc"):
                if n_script >= 200:
                    continue
                facts.extend(_scan_script(p))
                try:
                    facts.extend(_scan_secret_strings(p, p.read_text(encoding="utf-8", errors="ignore")[:200000]))
                except OSError:
                    pass
                n_script += 1
        except Exception as e:
            skipped.append({"path": str(p), "reason": str(e)})
        if len(facts) > 5000:
            skipped.append({"reason": "fact cap 5000"})
            break
    facts = _attach_refs(run, facts)
    doc = load_run(run)
    existing = {f.get("evidence_ref") for f in doc.get("facts") or []}
    added = [f for f in facts if f["evidence_ref"] not in existing]
    doc["facts"] = list(doc.get("facts") or []) + added
    roots = list(doc.get("roots") or [])
    if str(base) not in roots:
        roots.append(str(base))
    doc["roots"] = roots
    doc["run"] = run
    save_run(doc)
    return {
        "ok": True,
        "run": run,
        "added": len(added),
        "facts_total": len(doc["facts"]),
        "scanned": {"apk": n_apk, "elf": n_elf, "script": n_script},
        "skipped": skipped[:40],
        "note": "以上都是事实候选，不是漏洞。用 audit_list 看图，用 audit_annotate 写判断。",
        "tmap": tmap_status(),
    }


def _proven_safe(f: dict[str, Any]) -> bool:
    return f.get("attacker_controlled") == "no" and f.get("external_source") == "no"


def list_candidates(
    run: str,
    kind: str | None = None,
    sort: str = "default",
    limit: int = 40,
    hide_safe: bool = True,
) -> dict[str, Any]:
    doc = load_run(run)
    facts = list(doc.get("facts") or [])
    if kind:
        facts = [f for f in facts if f.get("kind") == kind]
    shown = facts
    if hide_safe:
        shown = [f for f in facts if not _proven_safe(f)]
    # 未知不沉底。只有 proven_safe 后排。
    if sort == "default":
        shown.sort(key=lambda f: (_proven_safe(f), IMPACT.get(str(f.get("kind")), 50), str(f.get("path"))))
    elif sort in LAYERS:
        order = {"yes": 0, "unknown": 1, "no": 2}

        def key(f: dict[str, Any]):
            v = str(f.get(sort) or "unknown")
            return (order.get(v, 1), IMPACT.get(str(f.get("kind")), 50))

        shown.sort(key=key)
    judged = {a.get("evidence_ref") for a in doc.get("annotations") or []}
    for f in shown:
        f["judged"] = f.get("evidence_ref") in judged
        f["read"] = f.get("evidence_ref") in set(doc.get("read") or [])
    return {
        "ok": True,
        "run": run,
        "total": len(facts),
        "shown": len(shown),
        "limit": limit,
        "candidates": shown[: max(1, min(limit, 200))],
        "note": "没有分数。换排序只换顺序。未知不等于安全。不要把本列表当漏洞清单。",
    }


def get_candidate(run: str, ref: str) -> dict[str, Any]:
    doc = load_run(run)
    read = list(doc.get("read") or [])
    if ref not in read:
        read.append(ref)
        doc["read"] = read
        save_run(doc)
    fact = next((f for f in doc.get("facts") or [] if f.get("evidence_ref") == ref), None)
    anns = [a for a in doc.get("annotations") or [] if a.get("evidence_ref") == ref]
    if not fact:
        return {"ok": False, "error": "unknown evidence_ref"}
    return {"ok": True, "fact": fact, "annotations": anns, "note": "fact 只读。判断在 annotations。"}


def annotate(run: str, ref: str, judgment: str, cites: list[str] | None, incomplete_patch: str | None = None) -> dict[str, Any]:
    if not ref or not judgment:
        return {"ok": False, "error": "需要 evidence_ref 和 judgment"}
    if re.search(r"\b(shellcode|msfvenom|meterpreter)\b", judgment, re.I):
        return {"ok": False, "error": "标注层禁止写 shellcode。只写判断与依据。"}
    doc = load_run(run)
    facts = {f.get("evidence_ref") for f in doc.get("facts") or []}
    if ref not in facts:
        return {"ok": False, "error": "evidence_ref 不在事实层。先 audit_scan / audit_list。"}
    rec = {
        "evidence_ref": ref,
        "judgment": judgment,
        "cites": cites or [ref],
        "incomplete_patch": incomplete_patch,
        "at": time.time(),
    }
    doc.setdefault("annotations", []).append(rec)
    save_run(doc)
    return {"ok": True, "annotation": rec, "note": "判断已写入标注层，未改事实。"}


def coverage(run: str) -> dict[str, Any]:
    doc = load_run(run)
    facts = doc.get("facts") or []
    refs = [f.get("evidence_ref") for f in facts]
    read = set(doc.get("read") or [])
    judged = {a.get("evidence_ref") for a in doc.get("annotations") or []}
    unread = [r for r in refs if r not in read]
    unjudged = [r for r in refs if r not in judged]
    return {
        "ok": True,
        "run": run,
        "facts": len(facts),
        "read": len(read),
        "judged": len(judged),
        "unread_count": len(unread),
        "unjudged_count": len(unjudged),
        "unread_sample": unread[:20],
        "unjudged_sample": unjudged[:20],
        "declaration": "没读过的标未读，不标没问题。必读项没判完，审查没结束。",
    }


def diff_runs(before: str, after: str) -> dict[str, Any]:
    a = load_run(before)
    b = load_run(after)
    if not (a.get("facts") or b.get("facts")):
        return {"ok": False, "error": "两个 run 都要先 audit_scan"}

    def key(f: dict[str, Any]) -> tuple:
        return (str(f.get("kind")), str(f.get("name")), Path(str(f.get("path"))).name)

    ka = {key(f): f for f in a.get("facts") or []}
    kb = {key(f): f for f in b.get("facts") or []}
    only_before = [ka[k] for k in ka.keys() - kb.keys()]
    only_after = [kb[k] for k in kb.keys() - ka.keys()]
    both = [k for k in ka.keys() & kb.keys()]
    must = []
    for k in both:
        fa, fb = ka[k], kb[k]
        changed_layers = [L for L in LAYERS if fa.get(L) != fb.get(L)]
        if changed_layers or fa.get("path") != fb.get("path"):
            must.append({"key": k, "before": fa, "after": fb, "changed_layers": changed_layers, "group": "same-call-still-there"})
    for f in only_before:
        must.append({"key": key(f), "before": f, "after": None, "group": "removed-or-unmatched", "hint": "入口没了但同名处理函数可能还在，标未定不要报删除成功"})
    for f in only_after:
        must.append({"key": key(f), "before": None, "after": f, "group": "new-attack-surface"})
    return {
        "ok": True,
        "before": before,
        "after": after,
        "must_read": must[:200],
        "must_read_count": len(must),
        "only_before": len(only_before),
        "only_after": len(only_after),
        "questions": [
            "这是不是安全修复？修的是旧版本里哪个弱点？",
            "修完整了吗？（入口断了但处理函数还在 / 缓冲区变大拷贝长度没变 / 校验只在前端）",
            "同样的调用在别处还有没有？",
            "新代码有没有带来新攻击面？",
        ],
        "note": "这是文件/符号级 diff，不是 Ghidra 函数级。函数级请 tmap diff（WSL2）。没读的改动标未读，不算没问题。",
        "tmap": tmap_status(),
    }


def collect_from_device(serial: str | None, dest: str, run: str) -> dict[str, Any]:
    from . import adb

    dest_p = Path(dest)
    dest_p.mkdir(parents=True, exist_ok=True)
    pkgs = adb.shell(serial, "pm list packages -f", timeout=40)
    text = pkgs.get("stdout") or ""
    pulled = []
    skipped = []
    for line in text.splitlines():
        # package:/data/app/foo.apk=com.sunmi.xxx
        if "=" not in line or "package:" not in line:
            continue
        path_part, _, pkg = line.partition("=")
        apk_path = path_part.replace("package:", "").strip()
        pkg = pkg.strip()
        if not VENDOR_PKG.search(pkg):
            continue
        if len(pulled) >= 20:
            skipped.append(pkg)
            continue
        local = dest_p / f"{pkg}.apk"
        r = adb.pull(serial, apk_path, str(local))
        if r.get("ok"):
            pulled.append({"pkg": pkg, "remote": apk_path, "local": str(local)})
        else:
            skipped.append({"pkg": pkg, "error": r.get("error") or r.get("stderr")})
    bins = adb.shell(serial, "ls -l /system/bin /vendor/bin /system/xbin 2>/dev/null | head -n 80", timeout=20)
    init = adb.shell(serial, "ls /init*.rc /system/etc/init 2>/dev/null | head -n 40", timeout=15)
    inventory = dest_p / "inventory.json"
    inventory.write_text(
        json.dumps({"pulled": pulled, "bin_ls": bins.get("stdout"), "init_ls": init.get("stdout")}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    scan = scan_tree(str(dest_p), run) if pulled else {"ok": True, "added": 0, "facts_total": 0}
    return {
        "ok": True,
        "run": run,
        "pulled": pulled,
        "skipped": skipped[:30],
        "inventory": str(inventory),
        "scan": scan,
        "note": "只拉厂商包前缀 APK。system 分区 ELF 需 root/可读才 pull。这是事实采集，不是漏洞列表。",
    }
