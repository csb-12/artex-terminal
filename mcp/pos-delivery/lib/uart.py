from __future__ import annotations

import sys
from .winproc import run, which


def list_ports() -> dict:
    try:
        from serial.tools import list_ports  # type: ignore
    except Exception:
        # Windows fallback without pyserial
        if sys.platform == "win32":
            ps = which("powershell") or which("pwsh")
            if not ps:
                return {"ok": False, "error": "pyserial 未安装且找不到 powershell"}
            r = run(
                [
                    ps,
                    "-NoProfile",
                    "-NonInteractive",
                    "-WindowStyle",
                    "Hidden",
                    "-Command",
                    "Get-CimInstance Win32_SerialPort | Select-Object DeviceID,Name,Description | ConvertTo-Json -Compress",
                ],
                timeout=20,
            )
            return {"ok": r.get("ok"), "via": "cim", "raw": r.get("stdout"), "stderr": r.get("stderr")}
        return {"ok": False, "error": "需要 pyserial: pip install pyserial"}
    ports = []
    for p in list_ports.comports():
        ports.append(
            {
                "device": p.device,
                "description": p.description,
                "hwid": p.hwid,
                "vid": getattr(p, "vid", None),
                "pid": getattr(p, "pid", None),
            }
        )
    return {"ok": True, "ports": ports}


def probe(port: str, baud: int = 115200, seconds: float = 3.0) -> dict:
    try:
        import serial  # type: ignore
        import time
    except Exception:
        return {"ok": False, "error": "需要 pyserial 才能读串口 banner"}
    try:
        ser = serial.Serial(port, baudrate=baud, timeout=0.4)
    except Exception as e:
        return {"ok": False, "error": f"打开串口失败: {e}"}
    buf = b""
    end = time.time() + seconds
    try:
        # 很多 POS UART 要先打 CR/LF 才吐 banner / 提示符。
        try:
            ser.write(b"\r\n")
            ser.flush()
        except Exception:
            pass
        while time.time() < end:
            chunk = ser.read(4096)
            if chunk:
                buf += chunk
    finally:
        ser.close()
    text = buf.decode("utf-8", errors="replace")
    lower = text.lower()
    hints = {
        "root_shell": ("root@" in lower) or ("# " in text and "login:" not in lower),
        "login_prompt": "login:" in lower,
        "uboot": "u-boot" in lower or "hit any key to stop autoboot" in lower,
        "android": "android" in lower or "console=" in lower,
        "unauthenticated": ("root@" in lower) or ("shell@" in lower and "password" not in lower),
    }
    return {"ok": True, "port": port, "baud": baud, "banner": text[-4000:], "hints": hints}
