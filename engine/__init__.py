"""Repo-root import shim for oracle engine modules."""

from __future__ import annotations

from pathlib import Path


_ORACLE_ENGINE = Path(__file__).resolve().parent.parent / "tools" / "oracle" / "engine"
if _ORACLE_ENGINE.is_dir():
    __path__.append(str(_ORACLE_ENGINE))
