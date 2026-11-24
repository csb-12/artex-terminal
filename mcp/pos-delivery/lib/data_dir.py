from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "data"


def path(name: str) -> Path:
    return ROOT / name
