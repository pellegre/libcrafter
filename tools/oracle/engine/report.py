"""Report and artifact path defaults for oracle validation."""

from __future__ import annotations

import os
from pathlib import Path


REPO_ROOT = Path(os.environ.get("ORACLE_REPO_ROOT", ".")).resolve()
DEFAULT_OUTPUT_ROOT = Path("target/oracle")
