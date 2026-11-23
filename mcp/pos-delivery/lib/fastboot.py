from __future__ import annotations

from .winproc import run, which

VARS = [
    "product",
    "unlocked",
    "secure",
    "variant",
    "version-bootloader",
    "version-baseband",
    "serialno",
    "hw-revision",
    "current-slot",
    "slot-count",
    "has-slot:boot",
    "partition-type:boot",
    "unlocked_critical",
    "securestate",
    "off-mode-charge",
]


def _fb() -> str | None:
    return which("fastboot")


def devices() -> dict:
    exe = _fb()
    if not exe:
        return {"ok": False, "error": "fastboot 不在 PATH / platform-tools"}
    r = run([exe, "devices", "-l"])
    rows = []
    for line in (r.get("stdout") or "").splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        rows.append({"serial": parts[0], "state": parts[1] if len(parts) > 1 else "", "raw": line})
    r["devices"] = rows
    r["fastboot"] = exe
    return r


def getvar(serial: str | None, name: str = "all") -> dict:
    exe = _fb()
    if not exe:
        return {"ok": False, "error": "fastboot 不在 PATH"}
    argv = [exe]
    if serial:
        argv += ["-s", serial]
    argv += ["getvar", name]
    # fastboot prints getvar to stderr
    r = run(argv, timeout=40)
    text = (r.get("stderr") or "") + "\n" + (r.get("stdout") or "")
    vars_: dict[str, str] = {}
    for line in text.splitlines():
        if ":" in line and not line.lower().startswith("finished"):
            k, _, v = line.partition(":")
            k, v = k.strip(), v.strip()
            if k:
                vars_[k] = v
    r["vars"] = vars_
    r["serial"] = serial
    return r


def getvar_bundle(serial: str | None = None) -> dict:
    all_r = getvar(serial, "all")
    missing = [k for k in VARS if k not in (all_r.get("vars") or {})]
    extra = {}
    for k in missing:
        extra[k] = getvar(serial, k).get("vars", {}).get(k, "")
    all_r["requested"] = extra
    return all_r


def oem_help(serial: str | None = None) -> dict:
    """Read-only probe of vendor oem surface. Does not flash."""
    exe = _fb()
    if not exe:
        return {"ok": False, "error": "fastboot 不在 PATH"}
    argv_base = [exe] + (["-s", serial] if serial else [])
    probes = []
    for extra in (["oem", "help"], ["oem", "?"], ["help"], ["getvar", "all"]):
        r = run(argv_base + extra, timeout=15)
        probes.append({"cmd": extra, "stdout": r.get("stdout"), "stderr": r.get("stderr"), "returncode": r.get("returncode")})
    return {"ok": True, "serial": serial, "probes": probes}


def flashing_unlock(serial: str | None = None) -> dict:
    exe = _fb()
    if not exe:
        return {"ok": False, "error": "fastboot 不在 PATH"}
    argv = [exe] + (["-s", serial] if serial else []) + ["flashing", "unlock"]
    return run(argv, timeout=60)


def oem_unlock(serial: str | None = None) -> dict:
    exe = _fb()
    if not exe:
        return {"ok": False, "error": "fastboot 不在 PATH"}
    argv = [exe] + (["-s", serial] if serial else []) + ["oem", "unlock"]
    return run(argv, timeout=60)


def flash(serial: str | None, partition: str, image: str) -> dict:
    exe = _fb()
    if not exe:
        return {"ok": False, "error": "fastboot 不在 PATH"}
    argv = [exe] + (["-s", serial] if serial else []) + ["flash", partition, image]
    return run(argv, timeout=180)


def erase(serial: str | None, partition: str) -> dict:
    exe = _fb()
    if not exe:
        return {"ok": False, "error": "fastboot 不在 PATH"}
    argv = [exe] + (["-s", serial] if serial else []) + ["erase", partition]
    return run(argv, timeout=60)


def boot_image(serial: str | None, image: str) -> dict:
    exe = _fb()
    if not exe:
        return {"ok": False, "error": "fastboot 不在 PATH"}
    argv = [exe] + (["-s", serial] if serial else []) + ["boot", image]
    return run(argv, timeout=60)
