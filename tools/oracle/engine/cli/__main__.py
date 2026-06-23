"""Entrypoint for ``python -m engine.cli`` (and ``tools.oracle.engine.cli``)."""

import sys

from .main import main

raise SystemExit(main(sys.argv[1:]))
