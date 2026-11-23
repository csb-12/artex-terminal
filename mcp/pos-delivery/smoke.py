# -*- coding: utf-8 -*-
"""In-process smoke: tools/list, T6920 fingerprint, CVE match, write gate, adb_shell deny."""
from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
os.chdir(ROOT)
sys.path.insert(0, ROOT)

from server import handle_rpc, TOOLS  # noqa: E402
from lib import adb, cve_match, fingerprint  # noqa: E402


def call(method, params=None, id_=1):
    msg = {"jsonrpc": "2.0", "id": id_, "method": method}
    if params is not None:
        msg["params"] = params
    return handle_rpc(msg)


def tool(name, args):
    r = call("tools/call", {"name": name, "arguments": args})
    text = r["result"]["content"][0]["text"]
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"_raw": text}


errors = []

listed = call("tools/list")
names = [t["name"] for t in listed["result"]["tools"]]
if len(names) != len(TOOLS):
    errors.append(f"tools/list count {len(names)} != {len(TOOLS)}")
if "usb_enum" not in names or "payload_deliver" not in names:
    errors.append("missing core tools")

fp = fingerprint.classify(
    {
        "ro.product.brand": "SUNMI",
        "ro.product.model": "P2_PRO",
        "ro.product.device": "T6920",
        "ro.board.platform": "msm8917",
        "ro.build.version.release": "7.1.2",
        "ro.build.version.security_patch": "2018-06-01",
        "ro.debuggable": "0",
        "ro.secure": "1",
        "ro.boot.verifiedbootstate": "green",
        "ro.boot.flash.locked": "1",
    },
    vidpid=["05c6:9008", "22d9:2769"],
    fastboot_vars={"unlocked": "no"},
)
if fp["vendor"] != "sunmi" or fp["platform"] != "qcom":
    errors.append(f"T6920 classify {fp['vendor']}/{fp['platform']}")
hyp_ids = [h["id"] for h in fp["hypotheses"]]
if hyp_ids[:1] != ["qcom-edl-firehose"]:
    errors.append(f"T6920 P1 {hyp_ids}")
if fp.get("flash_locked") != "1" or fp.get("fastboot_unlocked") != "no":
    errors.append(f"lock fields {fp.get('flash_locked')}/{fp.get('fastboot_unlocked')}")

pax = fingerprint.classify(
    {"ro.product.model": "A920Pro", "ro.build.display.id": "PayDroid"},
    vidpid=["18d1:d00d"],
)
if pax["vendor"] != "pax" or pax["next_skills"][0] != "pos-pax-fastboot":
    errors.append(f"PAX classify {pax}")

kern = cve_match.match_kernel("2018-06-01", "3.18.31-perf", "qcom", has_uvc=False)
cves = [c["cve"] for c in kern["candidates"]]
if "CVE-2022-20409" not in cves:
    errors.append(f"old patch kernel match {cves}")
if "CVE-2024-53104" in cves:
    errors.append(f"UVC should drop when has_uvc=False: {cves}")
if "CVE-2023-6241" in cves:
    errors.append(f"Mali should drop on qcom: {cves}")

pay = cve_match.match_paydroid("A50", "PayDroid", "")
if not pay["candidates"]:
    errors.append("paydroid miss A50")

vf = cve_match.match_verifone("VX680")
if not vf["candidates"]:
    errors.append("verifone miss VX680")

prop = tool("fastboot_flash", {"partition": "boot", "image": r"C:\lab\boot.img"})
if prop.get("status") != "proposed" or not prop.get("confirm_token"):
    errors.append(f"write gate {prop}")

denied = adb.shell(None, "dd if=/sdcard/x of=/dev/block/boot")
if denied.get("ok") is not False:
    errors.append(f"adb_shell dd not denied {denied}")

init = call("initialize")
if init["result"]["serverInfo"]["name"] != "pos-delivery":
    errors.append("initialize name")

out = {
    "ok": not errors,
    "errors": errors,
    "tool_count": len(names),
    "t6920": {
        "vendor": fp["vendor"],
        "platform": fp["platform"],
        "hypotheses": hyp_ids,
        "next": fp["next_skills"],
    },
    "pax_next": pax["next_skills"],
    "kernel_hits": cves,
    "proposed_tool": prop.get("tool"),
}
sys.stdout.buffer.write((json.dumps(out, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
sys.exit(0 if not errors else 1)
