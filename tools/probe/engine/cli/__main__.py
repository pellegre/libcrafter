"""Entry point for ``python -m engine.cli``."""

import sys

from .main import main

raise SystemExit(main(sys.argv[1:]))
