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
from lib import adb, audit, cve_match, fingerprint  # noqa: E402


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
tool_names = [t["name"] for t in listed["result"]["tools"]]
if len(tool_names) != len(TOOLS):
    errors.append(f"tools/list count {len(tool_names)} != {len(TOOLS)}")
for must in (
    "usb_enum",
    "payload_deliver",
    "adb_surface",
    "adb_pull",
    "edl_programmer_hint",
    "audit_scan",
    "audit_list",
    "audit_annotate",
    "audit_diff",
):
    if must not in tool_names:
        errors.append(f"missing tool {must}")

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
    adb_state="unauthorized",
    usb_tags=["qcom_edl", "sunmi"],
)
if fp["vendor"] != "sunmi" or fp["platform"] != "qcom":
    errors.append(f"T6920 classify {fp['vendor']}/{fp['platform']}")
hyp_ids = [h["id"] for h in fp["hypotheses"]]
if hyp_ids[:1] != ["qcom-edl-firehose"]:
    errors.append(f"T6920 P1 {hyp_ids}")
if fp["next_skills"][0] != "pos-usb-entry":
    errors.append(f"T6920 next {fp['next_skills']}")
if fp.get("flash_locked") != "1" or fp.get("fastboot_unlocked") != "no":
    errors.append(f"lock fields {fp.get('flash_locked')}/{fp.get('fastboot_unlocked')}")
if "adb-unauthorized" not in hyp_ids:
    errors.append(f"missing unauthorized hyp {hyp_ids}")
if "android-os-code-audit" not in hyp_ids:
    errors.append(f"missing code-audit hyp {hyp_ids}")
if fp["next_skills"][0] == "pos-code-audit":
    errors.append("code-audit must not outrank EDL on T6920")
if fp.get("advisory") is not True:
    errors.append("fingerprint hypotheses must be marked advisory")

pax = fingerprint.classify(
    {"ro.product.model": "A920Pro", "ro.build.display.id": "PayDroid"},
    vidpid=["18d1:d00d"],
    adb_state="device",
)
if pax["vendor"] != "pax" or pax["next_skills"][0] != "pos-pax-fastboot":
    errors.append(f"PAX classify {pax}")

landi = fingerprint.classify({"ro.product.brand": "landi", "ro.product.model": "N910"})
if landi["vendor"] != "landi":
    errors.append(f"landi classify {landi['vendor']}")
if any("cve-20" in h["id"] for h in landi["hypotheses"]):
    errors.append(f"landi forged cve {landi['hypotheses']}")

kern = cve_match.match_kernel(
    "2018-06-01",
    "3.18.31-perf",
    "qcom",
    has_uvc=False,
    has_kgsl=True,
    has_mali=False,
    android_release="7.1.2",
)
cves = [c["cve"] for c in kern["candidates"]]
if "CVE-2022-20409" not in cves:
    errors.append(f"old patch kernel match {cves}")
if "CVE-2016-5195" not in cves:
    errors.append(f"DirtyCOW should hit kernel 3.18: {cves}")
if cves and cves[0] != "CVE-2016-5195":
    errors.append(f"Android 7 / 3.18 应把 DirtyCOW 放首位: {cves}")
if "CVE-2024-53104" in cves:
    errors.append(f"UVC should drop when has_uvc=False: {cves}")
if "CVE-2023-6241" in cves or "CVE-2022-38181" in cves:
    errors.append(f"Mali should drop on qcom: {cves}")
if "CVE-2024-31317" in cves:
    errors.append(f"Zygote should drop on Android 7: {cves}")
if "CVE-2019-2215" in cves:
    errors.append(f"CVE-2019-2215 should drop on Android 7: {cves}")
if "CVE-2024-23380" in cves or "CVE-2022-22057" in cves:
    errors.append(f"2022/2024 GPU 不应套 Android 7: {cves}")
if "CVE-2023-20938" in cves:
    errors.append(f"CVE-2023-20938 不应套 Android 7: {cves}")

pay = cve_match.match_paydroid("A50", "PayDroid", "")
if not pay["candidates"]:
    errors.append("paydroid miss A50")
if not cve_match.match_paydroid("A35", "PayDroid", "")["candidates"]:
    errors.append("paydroid miss A35")

vf = cve_match.match_verifone("VX680")
if not vf["candidates"]:
    errors.append("verifone miss VX680")

edl = cve_match.edl_programmer_hint("msm8917", "T6920", "qcom")
programmers = [p for row in edl["candidates"] for p in (row.get("programmers") or [])]
if "prog_emmc_firehose_8917.mbn" not in programmers:
    errors.append(f"edl hint {edl}")

prop = tool("fastboot_flash", {"partition": "boot", "image": r"C:\lab\boot.img"})
if prop.get("status") != "proposed" or not prop.get("confirm_token"):
    errors.append(f"write gate {prop}")

denied = adb.shell(None, "dd if=/sdcard/x of=/dev/block/boot")
if denied.get("ok") is not False:
    errors.append(f"adb_shell dd not denied {denied}")

init = call("initialize")
if init["result"]["serverInfo"]["name"] != "pos-delivery":
    errors.append("initialize name")

hint = tool("edl_programmer_hint", {"soc": "msm8917", "model": "T6920"})
if not hint.get("candidates"):
    errors.append(f"edl tool {hint}")

# 代码审计事实地图：扫描命中不是漏洞；标注层与事实层隔离。
import tempfile
import zipfile
from pathlib import Path

atlas = tempfile.mkdtemp(prefix="pos-atlas-")
os.environ["POS_AUDIT_ATLAS"] = atlas
fw1 = Path(tempfile.mkdtemp(prefix="fw1-"))
fw2 = Path(tempfile.mkdtemp(prefix="fw2-"))
(fw1 / "init.rc").write_text("service debug /system/bin/sh\n    user root\n", encoding="utf-8")
(fw1 / "tool.sh").write_text("system($cmd)\n", encoding="utf-8")
manifest = """<?xml version="1.0"?>
<manifest package="com.sunmi.demo" xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:debuggable="true">
    <activity android:name=".Debug" android:exported="true">
      <intent-filter><action android:name="android.intent.action.MAIN"/></intent-filter>
    </activity>
  </application>
</manifest>
"""
apk = fw1 / "app.apk"
with zipfile.ZipFile(apk, "w") as z:
    z.writestr("AndroidManifest.xml", manifest)
    z.writestr("classes.dex", b"xxxx Ljava/lang/Runtime;->exec yyyy")
(fw2 / "init.rc").write_text("# debug service removed\n", encoding="utf-8")
(fw2 / "tool.sh").write_text("echo safe\n", encoding="utf-8")
s1 = audit.scan_tree(str(fw1), "fw-old")
s2 = audit.scan_tree(str(fw2), "fw-new")
if not s1.get("ok") or s1.get("added", 0) < 1:
    errors.append(f"audit scan old {s1}")
lst = audit.list_candidates("fw-old", limit=20)
kinds = {c.get("kind") for c in lst.get("candidates") or []}
if "exported" not in kinds and "cmd" not in kinds and "init" not in kinds:
    errors.append(f"audit list kinds {kinds}")
if any(c.get("verdict") for c in lst.get("candidates") or []):
    errors.append("audit must not attach vuln verdicts")
ref = (lst.get("candidates") or [{}])[0].get("evidence_ref")
if ref:
    g = audit.get_candidate("fw-old", ref)
    if not g.get("ok"):
        errors.append(f"audit get {g}")
    an = audit.annotate("fw-old", ref, "exported 是事实，可达未知，不是 RCE", [ref], "入口还在")
    if not an.get("ok"):
        errors.append(f"audit annotate {an}")
    bad = audit.annotate("fw-old", ref, "here is shellcode deadbeef", [ref])
    if bad.get("ok"):
        errors.append("annotate should reject shellcode")
cov = audit.coverage("fw-old")
if cov.get("read", 0) < 1:
    errors.append(f"coverage read {cov}")
df = audit.diff_runs("fw-old", "fw-new")
if not df.get("ok") or df.get("must_read_count", 0) < 1:
    errors.append(f"audit diff {df}")
if s2.get("ok") is False:
    errors.append(f"audit scan new {s2}")

out = {
    "ok": not errors,
    "errors": errors,
    "tool_count": len(tool_names),
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
