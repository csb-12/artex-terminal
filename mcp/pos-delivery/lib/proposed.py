"""Irreversible writes stay in proposed until a matching confirm_token is replayed."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any

TTL_SEC = 2 * 60 * 60
WRITE_TOOLS = {
    "fastboot_flashing_unlock",
    "fastboot_oem_unlock",
    "fastboot_flash",
    "fastboot_erase",
    "fastboot_boot_image",
    "mtk_seccfg_unlock",
    "mtk_partition_write",
    "mtk_partition_erase",
    "partition_write",
    "partition_erase",
    "sbi_overlay",
    "xdl_upload",
    "magisk_patch_boot",
    "payload_deliver",
}

_secret = os.environ.get("POS_DELIVERY_SECRET") or secrets.token_hex(32)
_store: dict[str, dict[str, Any]] = {}


def _canonical(tool: str, args: dict[str, Any]) -> bytes:
    body = {k: v for k, v in args.items() if k != "confirm_token"}
    return json.dumps({"tool": tool, "args": body}, sort_keys=True, ensure_ascii=False).encode("utf-8")


def issue(tool: str, args: dict[str, Any], effect: str) -> dict[str, Any]:
    payload = _canonical(tool, args)
    token = hmac.new(_secret.encode(), payload + str(time.time()).encode(), hashlib.sha256).hexdigest()[:32]
    _store[token] = {
        "tool": tool,
        "args_hash": hashlib.sha256(payload).hexdigest(),
        "issued_at": time.time(),
        "effect": effect,
    }
    return {
        "status": "proposed",
        "confirm_token": token,
        "tool": tool,
        "effect": effect,
        "reversible": False,
        "ttl_sec": TTL_SEC,
        "next": "人工批准后，用同一参数加上 confirm_token 再调用一次才会真正写入。",
        "args": {k: v for k, v in args.items() if k != "confirm_token"},
    }


def consume(tool: str, args: dict[str, Any]) -> dict[str, Any] | None:
    token = str(args.get("confirm_token") or "").strip()
    if not token:
        return None
    rec = _store.get(token)
    if not rec:
        return {"status": "rejected", "error": "confirm_token 无效或已消费"}
    if rec["tool"] != tool:
        return {"status": "rejected", "error": "confirm_token 与工具名不匹配"}
    if time.time() - rec["issued_at"] > TTL_SEC:
        _store.pop(token, None)
        return {"status": "rejected", "error": "confirm_token 已过期，重新 proposed"}
    payload = _canonical(tool, args)
    if hashlib.sha256(payload).hexdigest() != rec["args_hash"]:
        return {"status": "rejected", "error": "参数与 proposed 时不一致"}
    _store.pop(token, None)
    return {"status": "confirmed"}
