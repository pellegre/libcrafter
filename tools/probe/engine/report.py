"""Report and artifact path defaults for probe validation."""

from __future__ import annotations

import os
from pathlib import Path


REPO_ROOT = Path(os.environ.get("PROBE_REPO_ROOT", ".")).resolve()
DEFAULT_OUTPUT_ROOT = Path("target/probe")
