from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

DATA = Path(__file__).resolve().parent.parent / "data"


def _load(name: str) -> list[dict[str, Any]]:
    p = DATA / name
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


def match_kernel(security_patch: str, kernel_release: str = "", platform: str = "", has_uvc: bool | None = None) -> dict:
    items = _load("kernel_cve_index.json")
    patch = _patch_to_date(security_patch)
    hits = []
    for cve in items:
        reasons = []
        score = 0
        fixed = _patch_to_date(cve.get("android_patch") or "")
        if patch and fixed and patch < fixed:
            reasons.append(f"security_patch {security_patch} < {cve.get('android_patch')}")
            score += 3
        elif patch and fixed and patch >= fixed:
            reasons.append("可能已随月度补丁修复")
            score -= 2
        plats = [p.lower() for p in (cve.get("platforms") or [])]
        plat = (platform or "").lower()
        if plats and plat and plat not in plats:
            continue
        if cve.get("needs_uvc") and has_uvc is False:
            continue
        if plats and plat and plat in plats:
            reasons.append(f"平台匹配 {platform}")
            score += 2
        if cve.get("needs_uvc") and has_uvc:
            reasons.append("设备存在 UVC/camera 节点")
            score += 2
        kr = (kernel_release or "").lower()
        for needle in cve.get("kernel_hints") or []:
            if needle.lower() in kr:
                reasons.append(f"kernel 提示 {needle}")
                score += 1
        if score > 0:
            hits.append({**cve, "score": score, "reasons": reasons, "exploit_in_skill": False})
    hits.sort(key=lambda x: -x["score"])
    return {
        "security_patch": security_patch,
        "kernel_release": kernel_release,
        "candidates": hits,
        "note": "Skill/MCP 不内置利用代码。命中后走 payload_deliver / 外部编译服务验证。",
    }


def match_paydroid(model: str, display_id: str, fingerprint: str) -> dict:
    items = _load("paydroid_cve_index.json")
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
    blob = f"{model} {extra}".lower()
    hits = []
    for cve in items:
        ok = any(n.lower() in blob for n in (cve.get("models") or []))
        if ok or "verifone" in blob:
            hits.append(cve)
    return {"blob": blob, "candidates": hits}


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
        ],
    }
