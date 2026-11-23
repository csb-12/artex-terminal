from __future__ import annotations

import re

from .winproc import run, which

# 分区级写入必须走 proposed 门（fastboot_* / mtk_*），禁止经 adb shell 直写。
_WRITE_SHELL = re.compile(
    r"(?is)(\bdd\b.*\bof=|\bof=/dev/block|\bflash_image\b|\bmake_ext4fs\b|"
    r"\bsimg2img\b|\bfastboot\b|\bmtkclient\b|"
    r"(?:^|\s)reboot(?:\s|$)|"
    r"\brm\s+-rf\s+/(?:system|vendor|data)\b)"
)

PROP_KEYS = [
    "ro.product.brand",
    "ro.product.manufacturer",
    "ro.product.model",
    "ro.product.device",
    "ro.product.name",
    "ro.product.board",
    "ro.hardware",
    "ro.board.platform",
    "ro.boot.hardware",
    "ro.build.display.id",
    "ro.build.version.release",
    "ro.build.version.sdk",
    "ro.build.version.security_patch",
    "ro.build.fingerprint",
    "ro.debuggable",
    "ro.secure",
    "ro.adb.secure",
    "ro.boot.verifiedbootstate",
    "ro.boot.flash.locked",
    "ro.boot.vbmeta.device_state",
    "ro.boot.slot_suffix",
    "ro.crypto.state",
    "ro.serialno",
    "sys.usb.state",
    "sys.usb.config",
]


def _adb() -> str | None:
    return which("adb")


def devices() -> dict:
    exe = _adb()
    if not exe:
        return {"ok": False, "error": "adb 不在 PATH / platform-tools"}
    r = run([exe, "devices", "-l"])
    rows = []
    for line in (r.get("stdout") or "").splitlines()[1:]:
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        rows.append({"serial": parts[0], "state": parts[1] if len(parts) > 1 else "", "raw": line})
    r["devices"] = rows
    r["adb"] = exe
    return r


def getprop(serial: str | None = None, keys: list[str] | None = None) -> dict:
    exe = _adb()
    if not exe:
        return {"ok": False, "error": "adb 不在 PATH"}
    argv = [exe]
    if serial:
        argv += ["-s", serial]
    argv += ["shell", "getprop"]
    r = run(argv, timeout=45)
    wanted = set(keys or PROP_KEYS)
    props: dict[str, str] = {}
    for line in (r.get("stdout") or "").splitlines():
        line = line.strip()
        if not line.startswith("[") or "]: [" not in line:
            continue
        k, _, rest = line[1:].partition("]: [")
        v = rest[:-1] if rest.endswith("]") else rest
        if k in wanted:
            props[k] = v
    r["props"] = props
    r["serial"] = serial
    return r


def shell(serial: str | None, command: str, timeout: int = 30) -> dict:
    if _WRITE_SHELL.search(command or ""):
        return {
            "ok": False,
            "error": "adb_shell 拒绝分区写入 / reboot / fastboot。刷写走 fastboot_* 或 mtk_*（proposed）；重启走 adb_reboot。",
            "command": command,
            "serial": serial,
        }
    exe = _adb()
    if not exe:
        return {"ok": False, "error": "adb 不在 PATH"}
    argv = [exe]
    if serial:
        argv += ["-s", serial]
    argv += ["shell", command]
    r = run(argv, timeout=timeout)
    r["serial"] = serial
    r["command"] = command
    return r


def id_selinux_mounts(serial: str | None = None) -> dict:
    cmds = {
        "id": "id",
        "getenforce": "getenforce",
        "verified_boot": "getprop ro.boot.verifiedbootstate",
        "flash_locked": "getprop ro.boot.flash.locked",
        "mounts": "cat /proc/mounts",
        "partitions": "ls -l /dev/block/by-name 2>/dev/null || ls -l /dev/block/platform/*/by-name 2>/dev/null",
        "selinux_policy": "ls -l /sys/fs/selinux/policy 2>/dev/null",
        "writable_hint": "mount | grep -E ' /system | /vendor | /odm | / | /data '",
    }
    out = {"ok": True, "serial": serial, "results": {}}
    for name, cmd in cmds.items():
        out["results"][name] = shell(serial, cmd)
    id_out = (out["results"]["id"].get("stdout") or "").lower()
    out["uid0"] = "uid=0(" in id_out
    enf = (out["results"]["getenforce"].get("stdout") or "").strip()
    out["selinux"] = enf
    return out


def reboot(serial: str | None, mode: str) -> dict:
    exe = _adb()
    if not exe:
        return {"ok": False, "error": "adb 不在 PATH"}
    argv = [exe]
    if serial:
        argv += ["-s", serial]
    if mode in ("bootloader", "fastboot"):
        argv += ["reboot", "bootloader"]
    elif mode == "edl":
        argv += ["reboot", "edl"]
    elif mode == "recovery":
        argv += ["reboot", "recovery"]
    else:
        argv += ["reboot"]
    return run(argv, timeout=20)
