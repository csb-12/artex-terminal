"""ELF 事实层：导入符号 + 字符串。不判断漏洞。"""
from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

CMD = {"system", "popen", "execl", "execle", "execlp", "execv", "execvp", "execve", "dlopen"}
COPY = {"strcpy", "strcat", "gets", "sprintf", "vsprintf", "scanf"}
FMT = {"sprintf", "vsprintf", "printf", "fprintf", "syslog"}
PATH = {"open", "openat", "fopen", "unlink", "chmod", "chown"}
KIND_OF = {n: k for k, group in (("cmd", CMD), ("fmt", FMT), ("copy", COPY), ("path", PATH)) for n in group}


def _u(fmt: str, data: bytes, off: int):
    size = struct.calcsize(fmt)
    if off + size > len(data):
        return None
    return struct.unpack_from(fmt, data, off)[0]


def _strings(data: bytes, min_len: int = 4) -> list[str]:
    out: list[str] = []
    buf = bytearray()
    for b in data:
        if 32 <= b < 127:
            buf.append(b)
        else:
            if len(buf) >= min_len:
                out.append(buf.decode("ascii"))
            buf.clear()
    if len(buf) >= min_len:
        out.append(buf.decode("ascii"))
    return out


def _phdrs(data: bytes) -> tuple[bool, int, int, int] | None:
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[5] != 1:
        return None
    is64 = data[4] == 2
    if is64:
        return True, _u("<Q", data, 32) or 0, _u("<H", data, 54) or 0, _u("<H", data, 56) or 0
    return False, _u("<I", data, 28) or 0, _u("<H", data, 42) or 0, _u("<H", data, 44) or 0


def _v2f(data: bytes, is64: bool, phoff: int, phentsize: int, phnum: int, vaddr: int) -> int | None:
    for i in range(phnum):
        off = phoff + i * phentsize
        if is64:
            if off + 56 > len(data):
                continue
            p_type, _, p_offset, p_vaddr, _, p_filesz, _, _ = struct.unpack_from("<IIQQQQQQ", data, off)
        else:
            if off + 32 > len(data):
                continue
            p_type, p_offset, p_vaddr, _, p_filesz, _, _, _ = struct.unpack_from("<IIIIIIII", data, off)
        if p_type == 1 and p_vaddr <= vaddr < p_vaddr + p_filesz:
            return p_offset + (vaddr - p_vaddr)
    return None


def _dyn_imports(data: bytes) -> tuple[list[str], str]:
    hdr = _phdrs(data)
    if not hdr:
        return [], "not_elf"
    is64, phoff, phentsize, phnum = hdr
    dyn = None
    for i in range(phnum):
        off = phoff + i * phentsize
        if is64:
            if off + 56 > len(data):
                continue
            p_type, _, p_offset, _, _, p_filesz, _, _ = struct.unpack_from("<IIQQQQQQ", data, off)
        else:
            if off + 32 > len(data):
                continue
            p_type, p_offset, _, _, p_filesz, _, _, _ = struct.unpack_from("<IIIIIIII", data, off)
        if p_type == 2:
            dyn = (p_offset, p_filesz)
            break
    if not dyn:
        return [], "no_dynamic"
    doff, dsz = dyn
    dent = 16 if is64 else 8
    strtab = syment = symtab = 0
    pos = doff
    end = min(len(data), doff + dsz)
    while pos + dent <= end:
        tag, val = struct.unpack_from("<QQ" if is64 else "<II", data, pos)
        if tag == 0:
            break
        if tag == 5:
            strtab = val
        elif tag == 6:
            symtab = val
        elif tag == 11:
            syment = val
        pos += dent
    str_off = _v2f(data, is64, phoff, phentsize, phnum, strtab)
    sym_off = _v2f(data, is64, phoff, phentsize, phnum, symtab)
    if str_off is None or sym_off is None or not syment:
        return [], "dyn_unmapped"
    names = []
    for n in range(4096):
        so = sym_off + n * syment
        if so + 4 > len(data):
            break
        st_name = _u("<I", data, so)
        if not st_name:
            if n > 16:
                break
            continue
        p = str_off + st_name
        if p >= len(data):
            break
        z = data.find(b"\x00", p, p + 256)
        if z < 0:
            break
        name = data[p:z].decode("ascii", "ignore")
        if name:
            names.append(name)
    return names, "dynsym"


def scan_elf(path: Path, data: bytes | None = None) -> list[dict[str, Any]]:
    raw = data if data is not None else path.read_bytes()
    if len(raw) < 16 or raw[:4] != b"\x7fELF":
        return []
    machine = {3: "x86", 8: "mips", 40: "arm", 62: "x86_64", 183: "aarch64", 243: "riscv"}.get(
        _u("<H", raw, 18) or 0, "unknown"
    )
    imports, how = _dyn_imports(raw)
    strs = _strings(raw[: min(len(raw), 2_000_000)])
    facts: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, name: str, complete: str, why: str) -> None:
        facts.append(
            {
                "kind": kind,
                "name": name,
                "path": str(path),
                "arch": machine,
                "external_source": "unknown",
                "attacker_controlled": "unknown",
                "writer_known": "unknown",
                "reachable": "unknown",
                "filtered": "unknown",
                "analysis_complete": complete,
                "unknown_reason": why,
                "provenance": how,
            }
        )

    for n in imports:
        kind = KIND_OF.get(n)
        if kind and (kind, n) not in seen:
            seen.add((kind, n))
            add(kind, n, "yes" if how == "dynsym" else "unknown", "dynsym import" if how == "dynsym" else how)

    if how != "dynsym":
        blob = " ".join(strs[:4000])
        for n, kind in KIND_OF.items():
            if n in blob and (kind, n) not in seen:
                seen.add((kind, n))
                add(kind, n, "unknown", "仅字符串命中，未解析到 dynsym；未知不等于安全")

    if not facts:
        add("elf", path.name, "unknown", f"ELF {machine} 未命中危险导入（{how}）")
    return facts
