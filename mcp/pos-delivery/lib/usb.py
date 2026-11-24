from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from .winproc import run, which

VIDPID_DB = json.loads((Path(__file__).resolve().parent.parent / "data" / "vidpid.json").read_text(encoding="utf-8"))
_LSUSB_ID = re.compile(r"id\s+([0-9a-f]{4}):([0-9a-f]{4})", re.I)


def _classify_vidpid(vid: str, pid: str) -> list[str]:
    v, p = vid.lower(), pid.lower()
    tags = []
    for group, items in VIDPID_DB.items():
        for it in items:
            if it["vid"].lower() == v and it["pid"].lower() == p:
                tags.append(group)
    return tags


def _row(name: str, cls: str, status: str, inst: str, vid: str, pid: str) -> dict:
    tags = _classify_vidpid(vid, pid) if vid and pid else []
    return {
        "name": name,
        "class": cls,
        "status": status,
        "instance": inst,
        "vid": vid.lower() if vid else "",
        "pid": pid.lower() if pid else "",
        "vidpid": f"{vid.lower()}:{pid.lower()}" if vid and pid else "",
        "tags": tags,
    }


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
            devices.append(
                _row(
                    str(row.get("FriendlyName") or ""),
                    str(row.get("Class") or ""),
                    str(row.get("Status") or ""),
                    inst,
                    vid,
                    pid,
                )
            )
        return _pack(True, devices)

    r = run(["lsusb"], timeout=10)
    raw = r.get("stdout") or ""
    for line in raw.splitlines():
        m = _LSUSB_ID.search(line)
        if not m:
            continue
        vid, pid = m.group(1), m.group(2)
        devices.append(_row(line.strip(), "usb", "present", line.strip(), vid, pid))
    return _pack(bool(r.get("ok")), devices, raw=raw, stderr=r.get("stderr"))


def _pack(ok: bool, devices: list[dict], **extra) -> dict:
    tags = []
    vidpid = []
    for d in devices:
        tags.extend(d.get("tags") or [])
        if d.get("vidpid"):
            vidpid.append(d["vidpid"])
    interesting = [
        d
        for d in devices
        if d.get("tags")
        or (d.get("class") or "").lower() in ("androidusbdeviceclass", "androidusbdevice", "ports", "modem", "usbdevice")
    ]
    return {
        "ok": ok,
        "devices": devices,
        "vidpid": sorted(set(vidpid)),
        "tags": sorted(set(tags)),
        "interesting": interesting,
        **extra,
    }
