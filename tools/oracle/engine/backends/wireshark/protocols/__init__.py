"""Wireshark-stage per-protocol decoder plugins, auto-discovered at import.

Dropping a module into this package self-registers its
:class:`~.base.WiresharkProtocol` plugin as a side effect of import. The package is
empty of protocols until they are migrated off the Wireshark normalizer's
``_normalize_protocol_fields`` if/elif; until then :data:`~.base.WIRESHARK_REGISTRY`
stays empty and the normalizer falls through to its legacy code. Auto-discovery uses
``__name__``-relative module names so it works under both the ``engine.*`` and
``tools.oracle.engine.*`` import roots.
"""

from __future__ import annotations

from ....plugin_registry import autodiscover
from .base import (
    WIRESHARK_REGISTRY,
    WiresharkProtocol,
    register,
)

autodiscover(__name__, __path__)

__all__ = [
    "WIRESHARK_REGISTRY",
    "WiresharkProtocol",
    "register",
]
