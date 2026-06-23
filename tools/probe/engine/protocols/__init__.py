"""Per-protocol probe plugins, auto-discovered at import.

Each ``engine/protocols/<name>.py`` module declares one protocol's full probe
surface and calls :func:`base.register` at import time. Importing this package
auto-discovers and imports every such module so each self-registers into
:data:`base.PROTOCOL_REGISTRY`. No protocol is migrated yet, so this discovery
currently imports nothing beyond the shared ``base`` contract.

Discovery is ``__name__``-relative so it works under both engine import roots
(``engine.protocols`` for the CLI and ``tools.probe.engine.protocols`` for the
tests).
"""

from __future__ import annotations

from ..plugin_registry import autodiscover
from .base import (
    PROTOCOL_REGISTRY,
    ProtocolPlugin,
    all_cases,
    all_plan_builders,
    all_planned_only_cases,
    all_profile_counts,
    all_stimulus_endpoint_cases,
    register,
    registered_plugins,
)

__all__ = [
    "PROTOCOL_REGISTRY",
    "ProtocolPlugin",
    "all_cases",
    "all_plan_builders",
    "all_planned_only_cases",
    "all_profile_counts",
    "all_stimulus_endpoint_cases",
    "register",
    "registered_plugins",
]

autodiscover(__name__, __path__)
