"""Run host CLIs without a visible Windows console."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import Mapping, Sequence

CREATE_NO_WINDOW = 0x08000000

SEARCH_DIRS = [
    os.path.expandvars(r"%LOCALAPPDATA%\Android\Sdk\platform-tools"),
    r"C:\platform-tools",
    r"C:\Android\platform-tools",
    r"C:\adb",
]


def _startupinfo():
    if sys.platform != "win32":
        return None
    info = subprocess.STARTUPINFO()
    info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    info.wShowWindow = 0
    return info


def which(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    exe = name if name.lower().endswith(".exe") else f"{name}.exe"
    for d in SEARCH_DIRS:
        p = os.path.join(d, exe)
        if os.path.isfile(p):
            return p
    return None


def run(
    argv: Sequence[str],
    *,
    timeout: int = 30,
    env: Mapping[str, str] | None = None,
    input_text: str | None = None,
) -> dict:
    flags = CREATE_NO_WINDOW if sys.platform == "win32" else 0
    merged = os.environ.copy()
    if env:
        merged.update(env)
    try:
        proc = subprocess.run(
            list(argv),
            capture_output=True,
            text=True,
            timeout=timeout,
            env=merged,
            input=input_text,
            startupinfo=_startupinfo(),
            creationflags=flags,
            shell=False,
        )
    except FileNotFoundError as e:
        return {
            "ok": False,
            "argv": list(argv),
            "error": f"executable not found: {e}",
            "stdout": "",
            "stderr": "",
            "returncode": None,
        }
    except subprocess.TimeoutExpired as e:
        return {
            "ok": False,
            "argv": list(argv),
            "error": f"timeout after {timeout}s",
            "stdout": (e.stdout or "") if isinstance(e.stdout, str) else "",
            "stderr": (e.stderr or "") if isinstance(e.stderr, str) else "",
            "returncode": None,
        }
    return {
        "ok": proc.returncode == 0,
        "argv": list(argv),
        "returncode": proc.returncode,
        "stdout": proc.stdout or "",
        "stderr": proc.stderr or "",
    }
