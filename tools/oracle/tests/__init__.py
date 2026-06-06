"""Tests for oracle validation tooling."""

from pathlib import Path

_TOOLS_DIR = Path(__file__).resolve().parents[2]
__path__ = [
    str(_TOOLS_DIR / "oracle" / "tests"),
    str(_TOOLS_DIR / "probe" / "tests"),
]
