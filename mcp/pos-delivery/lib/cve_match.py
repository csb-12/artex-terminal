from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from . import data_dir


def _load(name: str) -> list[dict[str, Any]] | dict[str, Any]:
    p = data_dir.path(name)
    if not p.is_file():
        return []
    return json.loads(p.read_text(encoding="utf-8"))


def _patch_to_date(s: str) -> datetime | None:
    s = (s or "").strip()
    for fmt in ("%Y-%m-%d", "%Y-%m"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def _android_major(release: str) -> int | None:
    try:
        return int(str(release).split(".")[0])
    except (TypeError, ValueError):
        return None


def match_kernel(
    security_patch: str,
    kernel_release: str = "",
    platform: str = "",
    has_uvc: bool | None = None,
    has_kgsl: bool | None = None,
    has_mali: bool | None = None,
    android_release: str = "",
) -> dict:
    items = _load("kernel_cve_index.json")
    if not isinstance(items, list):
        items = []
    patch = _patch_to_date(security_patch)
    major = _android_major(android_release)
    hits = []
    for cve in items:
        reasons = []
        score = 0
        dropped = False
        plats = [p.lower() for p in (cve.get("platforms") or [])]
        plat = (platform or "").lower()
        if plats and plat and plat not in plats:
            continue
        if cve.get("needs_uvc") and has_uvc is False:
            continue
        if cve.get("needs_kgsl") and has_kgsl is False:
            continue
        if cve.get("needs_mali") and has_mali is False:
            continue
        min_a = cve.get("min_android")
        max_a = cve.get("max_android")
        if major is not None:
            if isinstance(min_a, int) and major < min_a:
                dropped = True
                reasons.append(f"Android {major} < min {min_a}")
            if isinstance(max_a, int) and major > max_a:
                dropped = True
                reasons.append(f"Android {major} > max {max_a}")

        fixed = _patch_to_date(cve.get("android_patch") or "")
        patch_says_fixed = bool(patch and fixed and patch >= fixed)
        if patch and fixed and patch < fixed:
            reasons.append(f"security_patch {security_patch} < {cve.get('android_patch')}")
            score += 3
        elif patch_says_fixed:
            reasons.append("月度补丁日期声称已修；POS OEM 日期常虚高，仍需用 uname/驱动节点核实")
            score -= 1

        if plats and plat and plat in plats:
            reasons.append(f"平台匹配 {platform}")
            score += 2
        if cve.get("needs_uvc") and has_uvc:
            reasons.append("设备存在 UVC/camera 节点")
            score += 2
        if cve.get("needs_kgsl") and has_kgsl:
            reasons.append("设备存在 kgsl 节点")
            score += 2
        if cve.get("needs_mali") and has_mali:
            reasons.append("设备存在 mali 节点")
            score += 2

        kr = (kernel_release or "").lower()
        kernel_hit = False
        for needle in cve.get("kernel_hints") or []:
            if needle.lower() in kr:
                reasons.append(f"kernel 提示 {needle}")
                score += 2
                kernel_hit = True

        try:
            ph = int(cve.get("priority_hint") or 3)
        except (TypeError, ValueError):
            ph = 3
        if ph <= 2:
            score += 4 - ph
            reasons.append(f"索引优先 {ph}")

        if dropped and not kernel_hit:
            continue
        # 补丁日期声称已修但内核仍落在窗口：POS 上保留为低分候选，禁止直接丢掉。
        if score <= 0 and kernel_hit:
            score = 1
            reasons.append("补丁日期与内核版本不一致，按 OEM 未合补丁候选保留")
        if score > 0:
            hits.append({**cve, "score": score, "reasons": reasons, "exploit_in_skill": False})
    hits.sort(key=lambda x: -x["score"])
    return {
        "security_patch": security_patch,
        "kernel_release": kernel_release,
        "android_release": android_release,
        "candidates": hits,
        "note": "Skill/MCP 不内置利用代码。命中后走 payload_deliver / 外部编译服务验证。CVE 命中不是 ACE。",
    }


def match_paydroid(model: str, display_id: str, fingerprint: str) -> dict:
    items = _load("paydroid_cve_index.json")
    if not isinstance(items, list):
        items = []
    blob = f"{model} {display_id} {fingerprint}".lower()
    hits = []
    for cve in items:
        ok = False
        reasons = []
        for n in cve.get("models") or []:
            if n.lower() in blob:
                ok = True
                reasons.append(f"型号命中 {n}")
        for n in cve.get("os_hints") or []:
            if n.lower() in blob:
                ok = True
                reasons.append(f"系统提示 {n}")
        if ok:
            hits.append({**cve, "reasons": reasons})
    return {"blob": blob, "candidates": hits}


def match_verifone(model: str, extra: str = "") -> dict:
    items = _load("verifone_cve_index.json")
    if not isinstance(items, list):
        items = []
    blob = f"{model} {extra}".lower()
    hits = []
    for cve in items:
        ok = any(n.lower() in blob for n in (cve.get("models") or []))
        if ok or "verifone" in blob:
            hits.append(cve)
    return {"blob": blob, "candidates": hits}


def edl_programmer_hint(soc: str = "", model: str = "", platform: str = "") -> dict:
    items = _load("qcom_edl_index.json")
    if not isinstance(items, list):
        items = []
    blob = f"{soc} {model} {platform}".lower()
    hits = []
    for row in items:
        keys = [row.get("soc") or ""] + list(row.get("aliases") or []) + list(row.get("models") or [])
        if any(k and k.lower() in blob for k in keys):
            hits.append(row)
    if not hits and ("8917" in blob or "t6920" in blob or "p2" in blob):
        hits = [r for r in items if str(r.get("soc") or "").lower() == "msm8917"]
    return {
        "query": {"soc": soc, "model": model, "platform": platform},
        "candidates": hits,
        "note": "只给公开 firehose 文件名提示，不提供程序员本体。缺文件记缺口，不要编造可写。",
    }


def magisk_feasibility(release: str, verifiedboot: str, flash_locked: str, slot_suffix: str) -> dict:
    try:
        major = int(str(release).split(".")[0])
    except (TypeError, ValueError):
        major = 0
    vbmeta_disable = verifiedboot in ("green",) and flash_locked in ("1", "yes", "true")
    return {
        "android_release": release,
        "magisk_likely": 7 <= major <= 15,
        "need_vbmeta_disable": vbmeta_disable,
        "ab_device": bool(slot_suffix),
        "slot_suffix": slot_suffix,
        "hide_stack": ["Zygisk", "DenyList", "Shamiko"],
        "notes": [
            "boot 修补前先只读 dump boot / boot_a",
            "verifiedbootstate=green 且 locked 时，持久化通常要关 AVB 或重签 vbmeta",
            "支付进程加入 DenyList，评估 Shamiko 对 POS 自研 root 检测的覆盖",
            "Android 7 商米常用 Magisk 旧分支；不要默认『有 root 就装 Magisk』",
            "内核 ACE 不等于 TEE/支付密钥被打穿",
        ],
    }
