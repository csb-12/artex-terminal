from __future__ import annotations

from typing import Any


def classify(props: dict[str, str], vidpid: list[str] | None = None, fastboot_vars: dict[str, str] | None = None) -> dict[str, Any]:
    blob = " ".join(f"{k}={v}" for k, v in (props or {}).items()).lower()
    blob += " " + " ".join(vidpid or []).lower()
    fv = fastboot_vars or {}
    blob += " " + " ".join(f"{k}={v}" for k, v in fv.items()).lower()

    vendor = "unknown"
    if any(x in blob for x in ("sunmi", "商米", "t69", "t6920", "t6900", "p2pro", "p2_pro", "p2-pro", "22d9:")):
        vendor = "sunmi"
    elif any(x in blob for x in ("pax", "paydroid", "a920", "a50", "a77", "a920pro")):
        vendor = "pax"
    elif any(x in blob for x in ("verifone", "vx520", "vx680", "vx690", "mx900", "mx915", "e355")):
        vendor = "verifone"
    elif "ingenico" in blob:
        vendor = "ingenico"
    elif "landi" in blob or "n910" in blob:
        vendor = "landi"

    platform = "unknown"
    if any(x in blob for x in ("mtk", "mediatek", "mt67", "mt65", "mt68", "mt87", "mt816", "0e8d:")):
        platform = "mtk"
    elif any(x in blob for x in ("qcom", "qualcomm", "msm", "sdm", "sm4", "sm6", "sm8", "8917", "9008")):
        platform = "qcom"
    elif "unisoc" in blob or "spreadtrum" in blob:
        platform = "unisoc"
    elif "rk3" in blob or "rockchip" in blob:
        platform = "rockchip"

    skills: list[str] = ["pos-usb-entry", "pos-android-lpe", "pos-takeover"]
    hypotheses: list[dict[str, Any]] = []

    if vendor == "pax":
        skills = ["pos-pax-fastboot", "pos-usb-entry", "pos-android-lpe", "pos-takeover"]
        hypotheses.append(
            {
                "id": "pax-cve-2023-42134",
                "priority": 1,
                "skill": "pos-pax-fastboot",
                "why": "指纹匹配 PAX/PayDroid，优先验证 fastboot 隐藏命令覆盖未签名分区 + 内核参数注入。",
            }
        )
    elif vendor == "verifone":
        skills = ["pos-verifone-sbi", "pos-usb-entry", "pos-takeover"]
        hypotheses.append(
            {
                "id": "verifone-cve-2019-14715",
                "priority": 1,
                "skill": "pos-verifone-sbi",
                "why": "指纹匹配 Verifone VX/MX，优先验证 SBI RS232 XDL 未签名写入。",
            }
        )

    if platform == "mtk":
        if "pos-mtk-brom" not in skills:
            skills.insert(0, "pos-mtk-brom")
        hypotheses.append(
            {
                "id": "mtk-kamakiri-da-seccfg",
                "priority": 1 if vendor != "pax" else 2,
                "skill": "pos-mtk-brom",
                "why": "MTK VID/PID 或 board 指纹，候选 Kamakiri BROM + DA 任意读写 + seccfg unlock。",
            }
        )
    if platform == "qcom":
        hypotheses.append(
            {
                "id": "qcom-edl-firehose",
                "priority": 1 if vendor == "sunmi" else 2,
                "skill": "pos-usb-entry",
                "why": "高通平台可枚举 9008 EDL / firehose 作为 boot 分区读写入口。商米 P2/T6920 常见 ADB 被 MDM 关掉，EDL 优先于等 shell。",
            }
        )

    hypotheses.append(
        {
            "id": "adb-shell-to-lpe",
            "priority": 3,
            "skill": "pos-android-lpe",
            "why": "若只有受限 adb shell，按 security_patch 匹配内核/Zygote LPE。",
        }
    )
    hypotheses.append(
        {
            "id": "uart-debug-shell",
            "priority": 4,
            "skill": "pos-usb-entry",
            "why": "授权含物理接触时探测 UART 无认证 console。",
        }
    )

    hypotheses.sort(key=lambda h: h["priority"])
    flash_locked = (props.get("ro.boot.flash.locked") or "").lower()
    unlocked = (fv.get("unlocked") or "").lower()
    vb = (props.get("ro.boot.verifiedbootstate") or "").lower()
    return {
        "vendor": vendor,
        "platform": platform,
        "model": props.get("ro.product.model") or fv.get("product") or "",
        "brand": props.get("ro.product.brand") or "",
        "security_patch": props.get("ro.build.version.security_patch") or "",
        "release": props.get("ro.build.version.release") or "",
        "debuggable": props.get("ro.debuggable") or "",
        "secure": props.get("ro.secure") or "",
        "verifiedbootstate": vb,
        "flash_locked": flash_locked,
        "fastboot_unlocked": unlocked,
        "serial": props.get("ro.serialno") or fv.get("serialno") or "",
        "next_skills": skills,
        "hypotheses": hypotheses,
    }
