"""APK 事实层：清单 exported / DEX 字符串 / JNI .so。不判断漏洞。"""
from __future__ import annotations

import re
import struct
import zipfile
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

from . import elfscan

DEX_HINTS = [
    ("cmd", "Ljava/lang/Runtime;->exec"),
    ("cmd", "ProcessBuilder"),
    ("cmd", "getRuntime"),
    ("jni", "loadLibrary"),
    ("jni", "System.load("),
    ("webview", "setJavaScriptEnabled"),
    ("webview", "addJavascriptInterface"),
    ("path", "openFileOutput"),
    ("path", "getExternalStorage"),
    ("exported", "exported"),
]

NS = "{http://schemas.android.com/apk/res/android}"


def _u32(data: bytes, off: int) -> int | None:
    if off + 4 > len(data):
        return None
    return struct.unpack_from("<I", data, off)[0]


def axml_strings(data: bytes) -> list[str]:
    """抽 Android binary XML 的 string pool。失败返回空。"""
    if len(data) < 12:
        return []
    # RES_XML_TYPE = 0x0003, header 8
    typ, hs = struct.unpack_from("<HH", data, 0)
    if typ not in (0x0003, 0x0001):
        return []
    # 找 string pool chunk 0x0001
    pos = 8 if typ == 0x0003 else 0
    strings: list[str] = []
    while pos + 8 <= len(data):
        ctyp, chs, csz = struct.unpack_from("<HHI", data, pos)
        if csz < 8 or pos + csz > len(data):
            break
        if ctyp == 0x0001:
            scount, _, flags, sstart, _ = struct.unpack_from("<IIIII", data, pos + 8)
            utf8 = bool(flags & 0x100)
            for i in range(min(scount, 8000)):
                offp = pos + 8 + 20 + i * 4
                if offp + 4 > len(data):
                    break
                rel = struct.unpack_from("<I", data, offp)[0]
                sp = pos + sstart + rel
                try:
                    if utf8:
                        if sp + 2 > len(data):
                            continue
                        # UTF-8 string pool: u8 char len, u8 byte len, bytes
                        slen = data[sp]
                        n = 1
                        if slen & 0x80:
                            slen = ((slen & 0x7F) << 8) | data[sp + 1]
                            n = 2
                        blen = data[sp + n]
                        m = 1
                        if blen & 0x80:
                            blen = ((blen & 0x7F) << 8) | data[sp + n + 1]
                            m = 2
                        b = data[sp + n + m : sp + n + m + blen]
                        strings.append(b.decode("utf-8", "ignore"))
                    else:
                        if sp + 2 > len(data):
                            continue
                        clen = struct.unpack_from("<H", data, sp)[0]
                        extra = 2
                        if clen & 0x8000:
                            clen = ((clen & 0x7FFF) << 16) | struct.unpack_from("<H", data, sp + 2)[0]
                            extra = 4
                        raw = data[sp + extra : sp + extra + clen * 2]
                        strings.append(raw.decode("utf-16-le", "ignore"))
                except Exception:
                    continue
            break
        pos += csz
    return strings


def _dex_strings(data: bytes) -> list[str]:
    out: list[str] = []
    # UTF-8 runs
    buf = bytearray()
    for b in data:
        if 32 <= b < 127:
            buf.append(b)
        else:
            if len(buf) >= 6:
                out.append(buf.decode("ascii"))
            buf.clear()
    if len(buf) >= 6:
        out.append(buf.decode("ascii"))
    # UTF-16LE runs
    i = 0
    while i + 4 < len(data):
        if data[i + 1] == 0 and 32 <= data[i] < 127:
            j = i
            chars = []
            while j + 1 < len(data) and data[j + 1] == 0 and 32 <= data[j] < 127:
                chars.append(chr(data[j]))
                j += 2
            if len(chars) >= 6:
                out.append("".join(chars))
            i = j
        else:
            i += 1
        if len(out) > 20000:
            break
    return out


def _manifest_facts_from_xml(root: ET.Element, apk: str) -> list[dict[str, Any]]:
    facts = []
    pkg = root.attrib.get("package") or ""
    for tag in ("activity", "service", "receiver", "provider"):
        for el in root.iter(tag):
            name = el.attrib.get(NS + "name") or el.attrib.get("name") or ""
            exported = (el.attrib.get(NS + "exported") or el.attrib.get("exported") or "").lower()
            perm = el.attrib.get(NS + "permission") or el.attrib.get("permission") or ""
            has_filter = any(c.tag.endswith("intent-filter") for c in list(el))
            if exported == "true" or (exported == "" and has_filter):
                facts.append(
                    {
                        "kind": "exported",
                        "name": f"{tag}:{name}",
                        "path": apk,
                        "package": pkg,
                        "permission": perm,
                        "has_intent_filter": has_filter,
                        "external_source": "yes" if has_filter else "unknown",
                        "attacker_controlled": "unknown",
                        "writer_known": "yes",
                        "reachable": "unknown",
                        "filtered": "yes" if perm else "unknown",
                        "analysis_complete": "no",
                        "unknown_reason": "清单 exported 是事实；跨应用/本地是否真能调到仍未知",
                    }
                )
    app_el = next((el for el in root.iter() if str(el.tag).endswith("application")), None)
    src = app_el if app_el is not None else root
    debuggable = (src.attrib.get(NS + "debuggable") or src.attrib.get("debuggable") or "").lower()
    if debuggable == "true":
        facts.append(
            {
                "kind": "exported",
                "name": "application:debuggable",
                "path": apk,
                "package": pkg,
                "external_source": "yes",
                "attacker_controlled": "unknown",
                "writer_known": "yes",
                "reachable": "unknown",
                "filtered": "unknown",
                "analysis_complete": "yes",
                "unknown_reason": "",
            }
        )
    return facts


def _layer_unknown(kind: str, name: str, path: str, why: str, **extra: Any) -> dict[str, Any]:
    rec = {
        "kind": kind,
        "name": name,
        "path": path,
        "external_source": "unknown",
        "attacker_controlled": "unknown",
        "writer_known": "unknown",
        "reachable": "unknown",
        "filtered": "unknown",
        "analysis_complete": "unknown",
        "unknown_reason": why,
    }
    rec.update(extra)
    return rec


def scan_apk(path: Path) -> list[dict[str, Any]]:
    facts: list[dict[str, Any]] = []
    apk = str(path)
    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile:
        return [_layer_unknown("apk", path.name, apk, "不是 zip/apk")]
    names = zf.namelist()
    if "AndroidManifest.xml" in names:
        raw = zf.read("AndroidManifest.xml")
        if raw.lstrip().startswith(b"<") or raw.lstrip().startswith(b"<?xml"):
            try:
                root = ET.fromstring(raw)
                facts.extend(_manifest_facts_from_xml(root, apk))
            except ET.ParseError:
                facts.append(_layer_unknown("exported", "AndroidManifest.xml", apk, "文本 XML 解析失败"))
        else:
            pool = axml_strings(raw)
            blob = " ".join(pool)
            if "android.intent.action.BOOT_COMPLETED" in blob or re.search(r"exported", blob, re.I):
                facts.append(
                    _layer_unknown(
                        "exported",
                        "AndroidManifest.xml:string-pool",
                        apk,
                        "AXML 只抽出 string pool，未还原组件树；exported 是否为 true 未证实",
                        strings=[s for s in pool if "export" in s.lower() or s.startswith("com.") or "BOOT" in s][:40],
                    )
                )
    for n in names:
        low = n.lower()
        if low.endswith("classes.dex") or re.search(r"classes\d+\.dex$", low):
            dex = zf.read(n)
            strs = _dex_strings(dex[: min(len(dex), 8_000_000)])
            joined = "\n".join(strs)
            for kind, needle in DEX_HINTS:
                if needle in joined:
                    facts.append(
                        _layer_unknown(
                            kind,
                            needle,
                            f"{apk}!{n}",
                            "DEX 字符串命中，不是调用图；可达/过滤均为未知",
                        )
                    )
        if "/lib/" in low.replace("\\", "/") and low.endswith(".so"):
            so = zf.read(n)
            for f in elfscan.scan_elf(Path(n), so):
                f["path"] = f"{apk}!{n}"
                facts.append(f)
    if not facts:
        facts.append(_layer_unknown("apk", path.name, apk, "未抽出 exported/DEX/JNI 线索，分析不完整"))
    return facts
