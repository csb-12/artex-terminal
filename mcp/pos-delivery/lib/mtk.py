"""Wrap mtkclient CLI. Does not vendor Kamakiri source."""
from __future__ import annotations

import os
import sys

from .winproc import run, which


def _mtk_cmd() -> list[str] | None:
    exe = which("mtk")
    if exe:
        return [exe]
    # Prefer pythonw so a module invocation does not open a console.
    pyw = which("pythonw") or os.environ.get("PYTHONW")
    if pyw and which("mtkclient") is None:
        # `pythonw -m mtkclient` if the package is installed
        return [pyw, "-m", "mtkclient"]
    return None


def detect() -> dict:
    cmd = _mtk_cmd()
    if not cmd:
        return {
            "ok": False,
            "error": "未找到 mtk / mtkclient。安装 https://github.com/bkerler/mtkclient 后重试。",
            "hint": "BROM 常见 VID:PID = 0e8d:0003；Preloader 0e8d:2000 / 0e8d:20ff",
        }
    r = run(cmd + ["printgpt"], timeout=20)
    r["wrapper"] = cmd
    return r


def da_info() -> dict:
    cmd = _mtk_cmd()
    if not cmd:
        return {"ok": False, "error": "未找到 mtkclient"}
    return run(cmd + ["da", "printgpt"], timeout=60)


def seccfg_unlock() -> dict:
    cmd = _mtk_cmd()
    if not cmd:
        return {"ok": False, "error": "未找到 mtkclient"}
    return run(cmd + ["da", "seccfg", "unlock"], timeout=120)


def partition_read(part: str, dest: str) -> dict:
    cmd = _mtk_cmd()
    if not cmd:
        return {"ok": False, "error": "未找到 mtkclient"}
    return run(cmd + ["r", part, dest], timeout=180)


def partition_write(part: str, image: str) -> dict:
    cmd = _mtk_cmd()
    if not cmd:
        return {"ok": False, "error": "未找到 mtkclient"}
    return run(cmd + ["w", part, image], timeout=180)


def partition_erase(part: str) -> dict:
    cmd = _mtk_cmd()
    if not cmd:
        return {"ok": False, "error": "未找到 mtkclient"}
    return run(cmd + ["e", part], timeout=120)
