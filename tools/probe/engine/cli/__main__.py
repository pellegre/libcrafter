"""Entry point for ``python -m engine.cli``.

Preserves the historical invocation used by ``tools/probe/run`` (which execs
``python -m engine.cli``): parse ``sys.argv[1:]`` through the CLI body and exit
with its return code, identical to the former ``if __name__ == "__main__"``
guard in ``engine/cli.py``.
"""

import sys

from .main import main

raise SystemExit(main(sys.argv[1:]))
