from pathlib import Path

_TOOLS_DIR = Path(__file__).resolve().parents[2]
__path__ = [
    str(_TOOLS_DIR / "probe" / "tests"),
    str(_TOOLS_DIR / "oracle" / "tests"),
]
