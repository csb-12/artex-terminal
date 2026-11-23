# -*- coding: utf-8 -*-
"""Windowless HTTP entry for pos-delivery. No argv parsing."""
from __future__ import annotations

import traceback
from pathlib import Path

LOG = Path(__file__).with_name("http-9911.log")


def _log(msg: str) -> None:
    with LOG.open("a", encoding="utf-8") as f:
        f.write(msg + "\n")


if __name__ == "__main__":
    try:
        _log("wrapper start")
        from server import serve_http

        _log("imported serve_http")
        # 0.0.0.0：Docker host.docker.internal 才能打到宿主机。
        # 本机健康检查仍用 http://127.0.0.1:9911/health。
        serve_http("0.0.0.0:9911")
    except Exception:
        _log(traceback.format_exc())
        raise
