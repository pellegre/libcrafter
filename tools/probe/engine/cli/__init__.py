"""Command-line interface for probe validation (package).

This package was converted from the former ``engine/cli.py`` module without any
behavior change. The CLI body lives in :mod:`engine.cli.main`.

Patch parity is the load-bearing constraint here. Tests reach into the CLI two
ways:

* object-identity pins such as ``assertIs(cli._planned_cases,
  planning.planned_cases)`` and ``PLAN_BUILDERS[name] is _<builder>``; and
* ``mock.patch.object(cli, "_lab_endpoint_live_report", ...)`` /
  ``mock.patch.object(cli.lab_session_state, ...)`` where the patched name is
  then read *inside the CLI body* (e.g. ``_guarded_live_report`` looks up
  ``_lab_endpoint_live_report`` as a module global of the body).

A package and its ``main`` submodule are distinct module objects, so a patch on
the package would never reach a name the body reads through its own globals. To
keep behavior byte-identical to the former single ``cli`` module, this
``__init__`` makes ``engine.cli`` resolve to the *same module object* as the
body: the body's ``__dict__`` is adopted as this package's namespace, and the
``cli`` entries in :data:`sys.modules` are aliased to the body module. After the
alias, ``cli is engine.cli.main`` for attribute lookups, so any
``patch.object(cli, name)`` mutates the exact global the body reads, while the
package keeps its ``__path__`` so ``python -m engine.cli`` (``__main__``) and
``from .main import main`` keep working.
"""

from __future__ import annotations

import sys as _sys

from . import main as _main

# Preserve the package's import machinery on the body module so the body can
# masquerade as the ``engine.cli`` *package* (submodule discovery via
# ``__path__``, ``python -m engine.cli`` via ``__main__``, and a sane
# ``__spec__``/``__loader__``). ``__name__`` is intentionally left as
# ``...cli.main`` so the body's own relative imports and identity stay intact.
_main.__path__ = __path__
if getattr(_main, "__spec__", None) is None:
    _main.__spec__ = __spec__
_main.__package__ = __name__

# Alias every ``sys.modules`` entry that points at this package to the body
# module, so ``import ... as cli`` and ``patch.object(cli, ...)`` operate on the
# body's namespace (true patch parity with the former single ``cli`` module).
# The body keeps its own ``...cli.main`` entry untouched so ``from .main import
# main`` in ``__main__`` still resolves the submodule.
_package = _sys.modules[__name__]
for _alias, _module in list(_sys.modules.items()):
    if _module is _package:
        _sys.modules[_alias] = _main
