"""Dispatch compile/upload to an external lab service. No local exploit body."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any


def compile_and_deliver(spec: dict[str, Any]) -> dict:
    url = (os.environ.get("POS_EXPLOIT_SERVICE_URL") or "").rstrip("/")
    if not url:
        return {
            "ok": False,
            "status": "not_configured",
            "error": "未配置 POS_EXPLOIT_SERVICE_URL。把实验室 exploit 编译/投递服务的 URL 配上后再调。",
            "spec_echo": {
                "cve": spec.get("cve"),
                "target": spec.get("target"),
                "stage": spec.get("stage"),
            },
            "note": "本 MCP 只转发元数据，不生成、不内置利用代码。",
        }
    payload = json.dumps(spec, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url + "/compile-deliver",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    token = os.environ.get("POS_EXPLOIT_SERVICE_TOKEN")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            try:
                parsed = json.loads(body)
            except json.JSONDecodeError:
                parsed = {"raw": body}
            return {"ok": True, "service": url, "result": parsed}
    except urllib.error.URLError as e:
        return {"ok": False, "error": str(e), "service": url}
