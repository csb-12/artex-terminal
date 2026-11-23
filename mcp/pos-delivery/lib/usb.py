from __future__ import annotations

import json
import sys
from pathlib import Path

from .winproc import run, which

VIDPID_DB = json.loads((Path(__file__).resolve().parent.parent / "data" / "vidpid.json").read_text(encoding="utf-8"))


def _classify_vidpid(vid: str, pid: str) -> list[str]:
    v, p = vid.lower(), pid.lower()
    tags = []
    for group, items in VIDPID_DB.items():
        for it in items:
            if it["vid"].lower() == v and it["pid"].lower() == p:
                tags.append(group)
    return tags


def enum_usb() -> dict:
    devices = []
    if sys.platform == "win32":
        ps = which("powershell") or which("pwsh")
        if not ps:
            return {"ok": False, "error": "找不到 powershell"}
        cmd = (
            "Get-PnpDevice -PresentOnly | "
            "Where-Object { $_.InstanceId -match 'VID_' } | "
            "Select-Object Status,Class,FriendlyName,InstanceId | "
            "ConvertTo-Json -Compress"
        )
        r = run(
            [ps, "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", cmd],
            timeout=25,
        )
        raw = (r.get("stdout") or "").strip()
        parsed = []
        if raw:
            try:
                data = json.loads(raw)
                parsed = data if isinstance(data, list) else [data]
            except json.JSONDecodeError:
                parsed = []
        for row in parsed:
            inst = str(row.get("InstanceId") or "")
            vid = pid = ""
            up = inst.upper()
            if "VID_" in up:
                try:
                    vid = up.split("VID_")[1][:4]
                except IndexError:
                    vid = ""
            if "PID_" in up:
                try:
                    pid = up.split("PID_")[1][:4]
                except IndexError:
                    pid = ""
            tags = _classify_vidpid(vid, pid) if vid and pid else []
            devices.append(
                {
                    "name": row.get("FriendlyName"),
                    "class": row.get("Class"),
                    "status": row.get("Status"),
                    "instance": inst,
                    "vid": vid,
                    "pid": pid,
                    "tags": tags,
                }
            )
        return {"ok": True, "devices": devices, "adb_tags": [d for d in devices if "adb" in d["tags"] or "mtk" in "".join(d["tags"])]}
    # Linux: /sys/bus/usb
    r = run(["lsusb"], timeout=10)
    return {"ok": r.get("ok"), "raw": r.get("stdout"), "stderr": r.get("stderr")}
