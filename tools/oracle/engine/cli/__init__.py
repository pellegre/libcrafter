"""Command-line interface for oracle packet validation.

This package preserves the historical ``engine.cli`` module surface. The CLI
body now lives in :mod:`.main`; this ``__init__`` re-exports that namespace so
that ``from ...engine import cli`` followed by ``cli.<name>`` behaves exactly as
it did when ``cli`` was a single module — including ``unittest.mock.patch.object``
against ``cli`` attributes, which the live-provider tests rely on to monkeypatch
helpers that the CLI body itself looks up by name.

To keep that behaviour byte-identical we alias the package to its ``main``
submodule: after this module imports ``main``, the dotted name
``...engine.cli`` resolves to the ``main`` module object, so a name patched on
``cli`` is the very name the CLI functions read from their own globals.
``python -m engine.cli`` still works because ``__main__`` imports ``.main``
directly, independent of this aliasing.
"""

from __future__ import annotations

import sys

from . import main as _main

# Carry the package's ``__path__`` onto the body module so the dotted name keeps
# behaving like a package: ``python -m engine.cli`` still locates ``__main__`` via
# this path after the identity swap below, and submodule imports keep working.
_main.__path__ = __path__  # type: ignore[attr-defined]

# Unify module identity: ``import cli`` / ``from ...engine import cli`` now yield
# the body module, so ``cli.<name>`` and the CLI functions share one namespace.
# This makes ``unittest.mock.patch.object(cli, "_live_provider")`` and friends
# patch the very globals the CLI body reads, exactly as when ``cli`` was a single
# module. (``main``'s own ``__package__`` already resolves its relative imports.)
sys.modules[__name__] = _main
