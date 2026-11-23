#!/usr/bin/env python3
"""pos-delivery MCP: USB/ADB/fastboot/mtkclient/UART wrappers + CVE match.

Stdio NDJSON and Streamable HTTP. Irreversible writes stay proposed until
confirm_token. No exploit source is shipped.
"""
from __future__ import annotations

import json
import sys
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import urlparse

from lib import adb, cve_match, deliver, fastboot, fingerprint, mtk, proposed, uart, usb

SERVER_NAME = "pos-delivery"
SERVER_VERSION = "1.0.0"
PROTOCOL = "2025-06-18"


def _elog(msg: str, persist: bool = False) -> None:
    # pythonw 下 sys.stderr 是 None，直接 write 会把 HTTP 服务打崩。
    line = msg if msg.endswith("\n") else msg + "\n"
    try:
        err = sys.stderr
        if err is not None:
            err.write(line)
            err.flush()
    except Exception:
        pass
    if persist:
        try:
            from pathlib import Path as _P

            with _P(__file__).with_name("http-9911.log").open("a", encoding="utf-8") as f:
                f.write(line)
        except Exception:
            pass


def _text(obj: Any, is_error: bool = False) -> dict:
    if isinstance(obj, str):
        body = obj
    else:
        body = json.dumps(obj, ensure_ascii=False, indent=2)
    return {"content": [{"type": "text", "text": body}], "isError": is_error}


def _need(args: dict, *keys: str) -> str | None:
    for k in keys:
        if args.get(k) in (None, ""):
            return f"missing {k}"
    return None


def _gate_write(name: str, args: dict, effect: str, runner: Callable[[], dict]) -> dict:
    if not args.get("confirm_token"):
        return _text(proposed.issue(name, args, effect))
    gate = proposed.consume(name, args)
    if not gate or gate.get("status") != "confirmed":
        return _text(gate or {"status": "rejected", "error": "需要 confirm_token"}, True)
    result = runner()
    result["status"] = "executed"
    result["tool"] = name
    return _text(result, not result.get("ok", True))


def t_usb_enum(_args: dict) -> dict:
    return _text({"usb": usb.enum_usb(), "adb": adb.devices(), "fastboot": fastboot.devices()})


def t_adb_devices(_args: dict) -> dict:
    return _text(adb.devices())


def t_adb_getprop(args: dict) -> dict:
    return _text(adb.getprop(args.get("serial"), args.get("keys")))


def t_adb_id_selinux_mounts(args: dict) -> dict:
    return _text(adb.id_selinux_mounts(args.get("serial")))


def t_adb_shell(args: dict) -> dict:
    err = _need(args, "command")
    if err:
        return _text({"error": err}, True)
    return _text(adb.shell(args.get("serial"), args["command"], int(args.get("timeout") or 30)))


def t_adb_reboot(args: dict) -> dict:
    mode = args.get("mode") or "bootloader"
    return _text(adb.reboot(args.get("serial"), mode))


def t_fastboot_devices(_args: dict) -> dict:
    return _text(fastboot.devices())


def t_fastboot_getvar(args: dict) -> dict:
    return _text(fastboot.getvar_bundle(args.get("serial")))


def t_fastboot_oem_help(args: dict) -> dict:
    return _text(fastboot.oem_help(args.get("serial")))


def t_uart_list_ports(_args: dict) -> dict:
    return _text(uart.list_ports())


def t_uart_probe(args: dict) -> dict:
    err = _need(args, "port")
    if err:
        return _text({"error": err}, True)
    return _text(uart.probe(args["port"], int(args.get("baud") or 115200), float(args.get("seconds") or 3)))


def t_fingerprint_classify(args: dict) -> dict:
    return _text(
        fingerprint.classify(
            args.get("props") or {},
            args.get("vidpid"),
            args.get("fastboot_vars"),
        )
    )


def t_cve_match_kernel(args: dict) -> dict:
    return _text(
        cve_match.match_kernel(
            args.get("security_patch") or "",
            args.get("kernel_release") or "",
            args.get("platform") or "",
            args.get("has_uvc"),
        )
    )


def t_cve_match_paydroid(args: dict) -> dict:
    return _text(
        cve_match.match_paydroid(
            args.get("model") or "",
            args.get("display_id") or "",
            args.get("fingerprint") or "",
        )
    )


def t_cve_match_verifone(args: dict) -> dict:
    return _text(cve_match.match_verifone(args.get("model") or "", args.get("extra") or ""))


def t_magisk_feasibility(args: dict) -> dict:
    return _text(
        cve_match.magisk_feasibility(
            args.get("release") or "",
            args.get("verifiedboot") or "",
            args.get("flash_locked") or "",
            args.get("slot_suffix") or "",
        )
    )


def t_mtk_detect(_args: dict) -> dict:
    return _text(mtk.detect())


def t_mtk_da_info(_args: dict) -> dict:
    return _text(mtk.da_info())


def t_mtk_read(args: dict) -> dict:
    err = _need(args, "partition", "dest")
    if err:
        return _text({"error": err}, True)
    return _text(mtk.partition_read(args["partition"], args["dest"]))


def t_fastboot_flashing_unlock(args: dict) -> dict:
    return _gate_write(
        "fastboot_flashing_unlock",
        args,
        "执行 fastboot flashing unlock，解锁 bootloader，通常会清 userdata。",
        lambda: fastboot.flashing_unlock(args.get("serial")),
    )


def t_fastboot_oem_unlock(args: dict) -> dict:
    return _gate_write(
        "fastboot_oem_unlock",
        args,
        "执行 fastboot oem unlock。",
        lambda: fastboot.oem_unlock(args.get("serial")),
    )


def t_fastboot_flash(args: dict) -> dict:
    err = _need(args, "partition", "image")
    if err:
        return _text({"error": err}, True)
    return _gate_write(
        "fastboot_flash",
        args,
        f"覆盖分区 {args.get('partition')} ← {args.get('image')}",
        lambda: fastboot.flash(args.get("serial"), args["partition"], args["image"]),
    )


def t_fastboot_erase(args: dict) -> dict:
    err = _need(args, "partition")
    if err:
        return _text({"error": err}, True)
    return _gate_write(
        "fastboot_erase",
        args,
        f"擦除分区 {args.get('partition')}",
        lambda: fastboot.erase(args.get("serial"), args["partition"]),
    )


def t_fastboot_boot_image(args: dict) -> dict:
    err = _need(args, "image")
    if err:
        return _text({"error": err}, True)
    return _gate_write(
        "fastboot_boot_image",
        args,
        f"fastboot boot {args.get('image')}：RAM 中启动镜像，内核级代码执行。",
        lambda: fastboot.boot_image(args.get("serial"), args["image"]),
    )


def t_mtk_seccfg_unlock(args: dict) -> dict:
    return _gate_write(
        "mtk_seccfg_unlock",
        args,
        "mtkclient da seccfg unlock：改 seccfg，改变 bootloader 锁状态。",
        mtk.seccfg_unlock,
    )


def t_mtk_partition_write(args: dict) -> dict:
    err = _need(args, "partition", "image")
    if err:
        return _text({"error": err}, True)
    return _gate_write(
        "mtk_partition_write",
        args,
        f"DA 模式写入分区 {args.get('partition')}",
        lambda: mtk.partition_write(args["partition"], args["image"]),
    )


def t_mtk_partition_erase(args: dict) -> dict:
    err = _need(args, "partition")
    if err:
        return _text({"error": err}, True)
    return _gate_write(
        "mtk_partition_erase",
        args,
        f"DA 模式擦除分区 {args.get('partition')}",
        lambda: mtk.partition_erase(args["partition"]),
    )


def t_sbi_overlay(args: dict) -> dict:
    err = _need(args, "payload_path")
    if err:
        return _text({"error": err}, True)
    return _gate_write(
        "sbi_overlay",
        args,
        "通过外部 XDL/SBI 服务覆盖 Verifone SBI 运行时代码。",
        lambda: deliver.compile_and_deliver(
            {"stage": "sbi_overlay", "payload_path": args["payload_path"], "port": args.get("port"), "cve": "CVE-2019-14715"}
        ),
    )


def t_xdl_upload(args: dict) -> dict:
    err = _need(args, "payload_path")
    if err:
        return _text({"error": err}, True)
    return _gate_write(
        "xdl_upload",
        args,
        "RS232 XDL 上传 payload（H.OUT 或内存镜像）。",
        lambda: deliver.compile_and_deliver(
            {"stage": "xdl_upload", "payload_path": args["payload_path"], "port": args.get("port"), "cve": "CVE-2019-14715"}
        ),
    )


def t_magisk_patch_boot(args: dict) -> dict:
    err = _need(args, "boot_image")
    if err:
        return _text({"error": err}, True)
    return _gate_write(
        "magisk_patch_boot",
        args,
        f"用外部服务修补 boot 镜像 {args.get('boot_image')} 并准备回写。",
        lambda: deliver.compile_and_deliver(
            {
                "stage": "magisk_patch_boot",
                "boot_image": args["boot_image"],
                "vbmeta_disable": bool(args.get("vbmeta_disable")),
                "target": args.get("serial"),
            }
        ),
    )


def t_payload_deliver(args: dict) -> dict:
    err = _need(args, "cve")
    if err:
        return _text({"error": err}, True)
    return _gate_write(
        "payload_deliver",
        args,
        f"向外部 exploit 服务投递 {args.get('cve')} 的编译/上传任务。",
        lambda: deliver.compile_and_deliver(args),
    )


def _schema(props: dict, required: list[str] | None = None) -> dict:
    s: dict[str, Any] = {"type": "object", "properties": props, "additionalProperties": True}
    if required:
        s["required"] = required
    return s


SERIAL = {"type": "string", "description": "adb/fastboot 序列号，单设备可省略"}
TOKEN = {"type": "string", "description": "proposed 返回的 confirm_token；缺省则只提案不执行"}

TOOLS: list[dict[str, Any]] = [
    {"name": "usb_enum", "description": "枚举 USB VID/PID、adb devices、fastboot devices。连接 POS 后第一步。", "inputSchema": _schema({}), "fn": t_usb_enum},
    {"name": "adb_devices", "description": "adb devices -l", "inputSchema": _schema({}), "fn": t_adb_devices},
    {"name": "adb_getprop", "description": "采集 ro.debuggable/secure/verifiedbootstate/flash.locked 等指纹。", "inputSchema": _schema({"serial": SERIAL, "keys": {"type": "array", "items": {"type": "string"}}}), "fn": t_adb_getprop},
    {"name": "adb_id_selinux_mounts", "description": "id / getenforce / mounts / by-name 分区，判断 shell 权限和可写分区。", "inputSchema": _schema({"serial": SERIAL}), "fn": t_adb_id_selinux_mounts},
    {"name": "adb_shell", "description": "adb shell 执行一条命令。侦察用；不要用来 dd/刷分区。", "inputSchema": _schema({"serial": SERIAL, "command": {"type": "string"}, "timeout": {"type": "integer"}}, ["command"]), "fn": t_adb_shell},
    {"name": "adb_reboot", "description": "adb reboot [bootloader|edl|recovery]。进 fastboot/EDL，不是分区写入。", "inputSchema": _schema({"serial": SERIAL, "mode": {"type": "string", "enum": ["bootloader", "edl", "recovery", "system"]}}), "fn": t_adb_reboot},
    {"name": "fastboot_devices", "description": "fastboot devices -l", "inputSchema": _schema({}), "fn": t_fastboot_devices},
    {"name": "fastboot_getvar", "description": "fastboot getvar all + unlocked/secure/variant 等。", "inputSchema": _schema({"serial": SERIAL}), "fn": t_fastboot_getvar},
    {"name": "fastboot_oem_help", "description": "只读探测 oem help / 隐藏命令面，不刷机。", "inputSchema": _schema({"serial": SERIAL}), "fn": t_fastboot_oem_help},
    {"name": "uart_list_ports", "description": "列出本机串口，供 UART 测试点接入。", "inputSchema": _schema({}), "fn": t_uart_list_ports},
    {"name": "uart_probe", "description": "打开串口读 banner，判断是否无认证 root/debug shell。", "inputSchema": _schema({"port": {"type": "string"}, "baud": {"type": "integer"}, "seconds": {"type": "number"}}, ["port"]), "fn": t_uart_probe},
    {"name": "fingerprint_classify", "description": "根据 getprop/VIDPID/fastboot 变量分类厂商与平台，输出利用假设与下一 Skill。", "inputSchema": _schema({"props": {"type": "object"}, "vidpid": {"type": "array", "items": {"type": "string"}}, "fastboot_vars": {"type": "object"}}), "fn": t_fingerprint_classify},
    {"name": "cve_match_kernel", "description": "security_patch / kernel 与已知 Android 内核 LPE 匹配，不含 exploit。", "inputSchema": _schema({"security_patch": {"type": "string"}, "kernel_release": {"type": "string"}, "platform": {"type": "string"}, "has_uvc": {"type": "boolean"}}), "fn": t_cve_match_kernel},
    {"name": "cve_match_paydroid", "description": "型号/指纹是否落入 CVE-2023-42134 PayDroid 影响面。", "inputSchema": _schema({"model": {"type": "string"}, "display_id": {"type": "string"}, "fingerprint": {"type": "string"}}), "fn": t_cve_match_paydroid},
    {"name": "cve_match_verifone", "description": "型号是否落入 CVE-2019-14715 SBI 影响面。", "inputSchema": _schema({"model": {"type": "string"}, "extra": {"type": "string"}}), "fn": t_cve_match_verifone},
    {"name": "magisk_feasibility", "description": "按 Android 版本和 AVB/锁状态评估 Magisk 持久化是否可行。", "inputSchema": _schema({"release": {"type": "string"}, "verifiedboot": {"type": "string"}, "flash_locked": {"type": "string"}, "slot_suffix": {"type": "string"}}), "fn": t_magisk_feasibility},
    {"name": "mtk_detect", "description": "检测 mtkclient 与 BROM/预载是否在线（printgpt 探测）。", "inputSchema": _schema({}), "fn": t_mtk_detect},
    {"name": "mtk_da_info", "description": "DA 模式只读 GPT。", "inputSchema": _schema({}), "fn": t_mtk_da_info},
    {"name": "mtk_read", "description": "DA 模式读分区到本地文件（只读 dump）。", "inputSchema": _schema({"partition": {"type": "string"}, "dest": {"type": "string"}}, ["partition", "dest"]), "fn": t_mtk_read},
    {"name": "fastboot_flashing_unlock", "description": "【写入】fastboot flashing unlock。无 token 只 proposed。", "inputSchema": _schema({"serial": SERIAL, "confirm_token": TOKEN}), "fn": t_fastboot_flashing_unlock},
    {"name": "fastboot_oem_unlock", "description": "【写入】fastboot oem unlock。无 token 只 proposed。", "inputSchema": _schema({"serial": SERIAL, "confirm_token": TOKEN}), "fn": t_fastboot_oem_unlock},
    {"name": "fastboot_flash", "description": "【写入】fastboot flash 分区。无 token 只 proposed。", "inputSchema": _schema({"serial": SERIAL, "partition": {"type": "string"}, "image": {"type": "string"}, "confirm_token": TOKEN}, ["partition", "image"]), "fn": t_fastboot_flash},
    {"name": "fastboot_erase", "description": "【写入】fastboot erase。无 token 只 proposed。", "inputSchema": _schema({"serial": SERIAL, "partition": {"type": "string"}, "confirm_token": TOKEN}, ["partition"]), "fn": t_fastboot_erase},
    {"name": "fastboot_boot_image", "description": "【写入/执行】fastboot boot 镜像。无 token 只 proposed。", "inputSchema": _schema({"serial": SERIAL, "image": {"type": "string"}, "confirm_token": TOKEN}, ["image"]), "fn": t_fastboot_boot_image},
    {"name": "mtk_seccfg_unlock", "description": "【写入】mtkclient seccfg unlock。无 token 只 proposed。", "inputSchema": _schema({"confirm_token": TOKEN}), "fn": t_mtk_seccfg_unlock},
    {"name": "mtk_partition_write", "description": "【写入】DA 写分区。无 token 只 proposed。", "inputSchema": _schema({"partition": {"type": "string"}, "image": {"type": "string"}, "confirm_token": TOKEN}, ["partition", "image"]), "fn": t_mtk_partition_write},
    {"name": "mtk_partition_erase", "description": "【写入】DA 擦分区。无 token 只 proposed。", "inputSchema": _schema({"partition": {"type": "string"}, "confirm_token": TOKEN}, ["partition"]), "fn": t_mtk_partition_erase},
    {"name": "sbi_overlay", "description": "【写入】Verifone SBI 覆盖，转发外部服务。无 token 只 proposed。", "inputSchema": _schema({"payload_path": {"type": "string"}, "port": {"type": "string"}, "confirm_token": TOKEN}, ["payload_path"]), "fn": t_sbi_overlay},
    {"name": "xdl_upload", "description": "【写入】RS232 XDL 上传。无 token 只 proposed。", "inputSchema": _schema({"payload_path": {"type": "string"}, "port": {"type": "string"}, "confirm_token": TOKEN}, ["payload_path"]), "fn": t_xdl_upload},
    {"name": "magisk_patch_boot", "description": "【写入】外部服务修补 boot。无 token 只 proposed。", "inputSchema": _schema({"boot_image": {"type": "string"}, "serial": SERIAL, "vbmeta_disable": {"type": "boolean"}, "confirm_token": TOKEN}, ["boot_image"]), "fn": t_magisk_patch_boot},
    {"name": "payload_deliver", "description": "【写入】把 CVE/阶段元数据交给外部 exploit 编译投递服务。无 token 只 proposed。", "inputSchema": _schema({"cve": {"type": "string"}, "stage": {"type": "string"}, "target": {"type": "string"}, "confirm_token": TOKEN}, ["cve"]), "fn": t_payload_deliver},
]

TOOL_FN = {t["name"]: t["fn"] for t in TOOLS}


def handle_rpc(msg: dict) -> dict | None:
    method = msg.get("method")
    rpc_id = msg.get("id")
    if method is None:
        return None
    if rpc_id is None and str(method).startswith("notifications/"):
        return None
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {
                "protocolVersion": PROTOCOL,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            },
        }
    if method == "ping":
        return {"jsonrpc": "2.0", "id": rpc_id, "result": {}}
    if method == "tools/list":
        tools = [{"name": t["name"], "description": t["description"], "inputSchema": t["inputSchema"]} for t in TOOLS]
        return {"jsonrpc": "2.0", "id": rpc_id, "result": {"tools": tools}}
    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        fn = TOOL_FN.get(name)
        if not fn:
            return {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": -32601, "message": f"unknown tool {name}"}}
        try:
            result = fn(args if isinstance(args, dict) else {})
        except Exception as e:
            result = _text({"error": str(e), "trace": traceback.format_exc()}, True)
        return {"jsonrpc": "2.0", "id": rpc_id, "result": result}
    if method in ("notifications/initialized", "notifications/cancelled"):
        return None
    return {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": -32601, "message": f"unknown method {method}"}}


def serve_stdio() -> None:
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer
    while True:
        line = stdin.readline()
        if not line:
            break
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line.decode("utf-8"))
        except json.JSONDecodeError:
            continue
        if isinstance(msg, list):
            replies = [handle_rpc(m) for m in msg]
            replies = [r for r in replies if r is not None]
            if replies:
                stdout.write((json.dumps(replies, ensure_ascii=False) + "\n").encode("utf-8"))
                stdout.flush()
            continue
        reply = handle_rpc(msg)
        if reply is not None:
            stdout.write((json.dumps(reply, ensure_ascii=False) + "\n").encode("utf-8"))
            stdout.flush()


class Handler(BaseHTTPRequestHandler):
    session = "pos-delivery-1"

    def log_message(self, fmt: str, *args: Any) -> None:
        _elog("[pos-delivery] " + (fmt % args))

    def _send(self, code: int, body: bytes | None, content_type: str = "application/json") -> None:
        self.send_response(code)
        self.send_header("Mcp-Session-Id", self.session)
        if body is not None:
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body is not None:
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path in ("/health", "/"):
            body = json.dumps({"ok": True, "server": SERVER_NAME, "version": SERVER_VERSION}).encode()
            self._send(200, body)
            return
        self._send(404, b'{"error":"not found"}')

    def do_POST(self) -> None:  # noqa: N802
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try:
            msg = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            self._send(400, b'{"error":"bad json"}')
            return
        if isinstance(msg, list):
            replies = [handle_rpc(m) for m in msg]
            replies = [r for r in replies if r is not None]
            self._send(200, json.dumps(replies, ensure_ascii=False).encode("utf-8"))
            return
        method = msg.get("method")
        if msg.get("id") is None and str(method or "").startswith("notifications/"):
            self.send_response(202)
            self.send_header("Mcp-Session-Id", self.session)
            self.end_headers()
            return
        reply = handle_rpc(msg)
        if reply is None:
            self.send_response(202)
            self.send_header("Mcp-Session-Id", self.session)
            self.end_headers()
            return
        self._send(200, json.dumps(reply, ensure_ascii=False).encode("utf-8"))

    def do_DELETE(self) -> None:  # noqa: N802
        # Streamable HTTP session close. ARTEX mcphttp.Client.Close() 会发 DELETE。
        self.send_response(200)
        self.send_header("Mcp-Session-Id", self.session)
        self.end_headers()


def serve_http(bind: str) -> None:
    host, _, port_s = bind.rpartition(":")
    host = host.strip() or "127.0.0.1"
    port = int(port_s or "9911")
    httpd = ThreadingHTTPServer((host, port), Handler)
    _elog(f"[pos-delivery] http://{host}:{port}", persist=True)
    httpd.serve_forever()


def main() -> int:
    args = sys.argv[1:]
    if "--http" in args:
        i = args.index("--http")
        bind = args[i + 1] if i + 1 < len(args) else "127.0.0.1:9911"
        serve_http(bind)
        return 0
    serve_stdio()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
