"""Live-provider execution machinery for the oracle CLI.

This subpackage is the forward-looking home for the CLI's live-provider
execution code. Most of that machinery — the ``_live_provider_*`` lifecycle,
the ``_wire_*`` comparison/exchange bridges, and the ``_run_libcrafter_*``
subprocess bridges — stays in :mod:`..main` because the live-provider tests
monkeypatch those helpers on the ``cli`` namespace with
``unittest.mock.patch.object(cli, "<helper>")`` and the CLI body looks them up
by bare name. Physically relocating a patched helper (or any helper a patched
function calls through an intra-module reference) would break that patch
parity, so those clusters remain in ``main``.

Only genuinely patch-independent helpers live here. Today that is the
IP-fragment workload planning in :mod:`.cases`, which references no patched
symbol and is itself never patched; ``main`` re-imports its names so the
public ``cli`` surface is unchanged.
"""

from __future__ import annotations
