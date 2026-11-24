from __future__ import annotations

from typing import Any


def _blob(*parts: Any) -> str:
    chunks: list[str] = []
    for p in parts:
        if p is None:
            continue
        if isinstance(p, dict):
            chunks.append(" ".join(f"{k}={v}" for k, v in p.items()))
        elif isinstance(p, (list, tuple)):
            chunks.append(" ".join(str(x) for x in p))
        else:
            chunks.append(str(p))
    return " ".join(chunks).lower()


def _uniq(items: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for x in items:
        if x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out


def classify(
    props: dict[str, str],
    vidpid: list[str] | None = None,
    fastboot_vars: dict[str, str] | None = None,
    adb_state: str | None = None,
    usb_tags: list[str] | None = None,
) -> dict[str, Any]:
    props = props or {}
    fv = fastboot_vars or {}
    tags = [t.lower() for t in (usb_tags or [])]
    vidpid = vidpid or []
    blob = _blob(props, vidpid, fv, tags, adb_state)

    vendor = "unknown"
    if any(x in blob for x in ("sunmi", "商米", "t69", "t6920", "t6900", "p2pro", "p2_pro", "p2-pro", "22d9:")):
        vendor = "sunmi"
    elif any(x in blob for x in ("pax", "paydroid", "a920", "a50", "a77", "a80", "a35", "a920pro")):
        vendor = "pax"
    elif any(x in blob for x in ("verifone", "vx520", "vx680", "vx690", "vx820", "mx900", "mx915", "mx925", "e355")):
        vendor = "verifone"
    elif "ingenico" in blob or "telium" in blob or "tetra" in blob or "lane/" in blob:
        vendor = "ingenico"
    elif "landi" in blob or "n910" in blob or "appos" in blob:
        vendor = "landi"
    elif any(x in blob for x in ("newland", "n900", "n950", "n500")):
        vendor = "newland"
    elif "nexgo" in blob or "newgpay" in blob:
        vendor = "nexgo"
    elif "morefun" in blob:
        vendor = "morefun"
    elif "telpo" in blob:
        vendor = "telpo"
    elif "imin" in blob:
        vendor = "imin"
    elif "castles" in blob or "saturn" in blob:
        vendor = "castles"

    platform = "unknown"
    if any(x in blob for x in ("mtk", "mediatek", "mt67", "mt65", "mt68", "mt87", "mt816", "0e8d:")):
        platform = "mtk"
    elif any(x in blob for x in ("qcom", "qualcomm", "msm", "sdm", "sm4", "sm6", "sm8", "8917", "8909", "8953", "9008", "9006")):
        platform = "qcom"
    elif "unisoc" in blob or "spreadtrum" in blob or "sprd" in blob or "ums" in blob:
        platform = "unisoc"
    elif "rk3" in blob or "rockchip" in blob:
        platform = "rockchip"

    adb = (adb_state or "").lower()
    has_adb_shell = adb in ("device", "recovery")
    adb_unauthorized = adb in ("unauthorized", "offline")
    has_fastboot = any("fastboot" in str(x).lower() for x in vidpid) or bool(fv) or "d00d" in blob
    has_edl = "9008" in blob or "qcom_edl" in tags
    has_brom = "0e8d:0003" in blob or "mtk_brom" in tags
    has_preloader = "0e8d:2000" in blob or "0e8d:20ff" in blob or "mtk_preloader" in tags

    skills: list[str] = ["pos-usb-entry"]
    hypotheses: list[dict[str, Any]] = []

    def add_skill(*names: str) -> None:
        for n in names:
            if n not in skills:
                skills.append(n)

    def hyp(hid: str, priority: int, skill: str, why: str) -> None:
        hypotheses.append({"id": hid, "priority": priority, "skill": skill, "why": why})

    if vendor == "pax":
        add_skill("pos-pax-fastboot", "pos-android-lpe", "pos-takeover")
        skills = _uniq(["pos-pax-fastboot", "pos-usb-entry"] + skills)
        hyp(
            "pax-cve-2023-42134",
            1,
            "pos-pax-fastboot",
            "指纹匹配 PAX/PayDroid，优先验证 fastboot 隐藏命令覆盖未签名分区 + 内核参数注入。",
        )
    elif vendor == "verifone":
        add_skill("pos-verifone-sbi", "pos-takeover")
        skills = _uniq(["pos-verifone-sbi", "pos-usb-entry"] + skills)
        hyp(
            "verifone-cve-2019-14715",
            1,
            "pos-verifone-sbi",
            "指纹匹配 Verifone VX/MX，优先验证 SBI RS232 XDL 未签名写入。",
        )
    elif vendor in ("ingenico", "landi", "newland", "nexgo", "morefun", "telpo", "imin", "castles"):
        add_skill("pos-android-lpe", "pos-takeover")
        hyp(
            f"{vendor}-generic-usb-uart",
            2,
            "pos-usb-entry",
            f"指纹匹配 {vendor}，无专属公开链 Skill。走 USB/ADB/fastboot/UART 通用入口，缺口写明，不要伪造专用 CVE。",
        )

    if platform == "mtk" or has_brom or has_preloader:
        add_skill("pos-mtk-brom", "pos-android-lpe", "pos-takeover")
        if "pos-mtk-brom" in skills:
            skills = _uniq(["pos-mtk-brom"] + [s for s in skills if s != "pos-mtk-brom"])
        prio = 1 if vendor != "pax" else 2
        if has_brom:
            prio = 1
        hyp(
            "mtk-kamakiri-da-seccfg",
            prio,
            "pos-mtk-brom",
            "MTK VID/PID 或 board 指纹，候选 Kamakiri BROM + DA 任意读写 + seccfg unlock。",
        )

    if platform == "qcom" or has_edl:
        add_skill("pos-usb-entry", "pos-android-lpe", "pos-takeover")
        prio = 1 if vendor == "sunmi" or has_edl else 2
        if adb_unauthorized or (not has_adb_shell and vendor == "sunmi"):
            prio = 1
        hyp(
            "qcom-edl-firehose",
            prio,
            "pos-usb-entry",
            "高通平台可枚举 9008 EDL / firehose 作为 boot 分区读写入口。商米 P2/T6920 常见 ADB 被 MDM 关掉，EDL 优先于等 shell。缺程序员时用 edl_programmer_hint 记文件名。",
        )

    if platform == "unisoc":
        add_skill("pos-usb-entry", "pos-android-lpe", "pos-takeover")
        hyp(
            "unisoc-download",
            2,
            "pos-usb-entry",
            "展锐/Unisoc 下载模式，走通用 USB 入口；不要套高通 EDL 树。",
        )
    if platform == "rockchip":
        add_skill("pos-usb-entry", "pos-android-lpe", "pos-takeover")
        hyp(
            "rockchip-loader",
            2,
            "pos-usb-entry",
            "Rockchip loader 面，走通用 USB 入口。",
        )

    if has_adb_shell:
        add_skill("pos-android-lpe", "pos-takeover")
        hyp(
            "adb-shell-to-lpe",
            2 if vendor not in ("pax", "verifone") else 3,
            "pos-android-lpe",
            "adb 已是 device，按 security_patch 与驱动节点匹配内核/Zygote LPE。POS OEM 补丁日期常虚高，仍需实测。",
        )
    elif adb_unauthorized:
        add_skill("pos-android-lpe")
        hyp(
            "adb-unauthorized",
            5,
            "pos-usb-entry",
            "ADB unauthorized：LPE 前置不满足。继续 fastboot 按键 / EDL / BROM / UART，不要停。",
        )
    else:
        hyp(
            "adb-shell-to-lpe",
            4,
            "pos-android-lpe",
            "当前未见可用 adb shell。若稍后授权/解开 MDM，再按 security_patch 匹配 LPE。",
        )

    hyp(
        "uart-debug-shell",
        3 if vendor == "verifone" else 4,
        "pos-usb-entry" if vendor != "verifone" else "pos-verifone-sbi",
        "授权含物理接触时探测 UART 无认证 console。probe 会先打 CR/LF 唤醒 banner。",
    )

    if has_fastboot and vendor != "pax":
        hyp(
            "fastboot-unlock-or-boot",
            3,
            "pos-usb-entry",
            "fastboot 在线：记录 unlocked/secure；解锁是可编排步骤（proposed，通常清 userdata），不是回避项。",
        )

    add_skill("pos-android-lpe", "pos-takeover", "pos-code-audit")
    hyp(
        "android-os-code-audit",
        3 if has_adb_shell else 4,
        "pos-code-audit",
        "安卓 APK + OS/ELF/init 事实地图（Treasure Map 思路）。扫描命中不是漏洞；未知不沉底。有 dump/adb 就画地图，判断写标注层。",
    )
    hypotheses.sort(key=lambda h: (h["priority"], h["id"]))

    # next_skills 按建议优先级排：有专属 P1 链时把它放到最前。这是假设目录，不是命令。
    p1 = next((h["skill"] for h in hypotheses if h["priority"] == 1), "pos-usb-entry")
    skills = _uniq([p1, "pos-usb-entry"] + skills)

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
        "adb_state": adb,
        "usb_tags": tags,
        "entry": {
            "adb_shell": has_adb_shell,
            "adb_unauthorized": adb_unauthorized,
            "fastboot": has_fastboot,
            "edl": has_edl,
            "brom": has_brom,
            "preloader": has_preloader,
        },
        "next_skills": skills,
        "hypotheses": hypotheses,
        "advisory": True,
        "note": "hypotheses / next_skills 按 priority 排序，是建议不是命令。按现场证据自己选链、自己加载 1–2 条 Skill。不要把八条全加载。POS OEM 的 security_patch 常虚高；CVE 命中不是 ACE。",
    }
