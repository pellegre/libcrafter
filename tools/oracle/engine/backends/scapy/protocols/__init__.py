"""Scapy-stage per-protocol encoder/decoder plugins, auto-discovered at import.

Dropping a module into this package self-registers its
:class:`~.base.ScapyProtocol` and :class:`~.base.StackEncoder` plugins as a side
effect of import. The package is empty of protocols until they are migrated off the
Scapy encoder's per-layer if/elif and whole-stack branches; until then
:data:`~.base.SCAPY_REGISTRY` and :data:`~.base.STACK_ENCODER_REGISTRY` stay empty
and the encoder/decoder fall through to their legacy code. Auto-discovery uses
``__name__``-relative module names so it works under both the ``engine.*`` and
``tools.oracle.engine.*`` import roots.
"""

from __future__ import annotations

from ....plugin_registry import autodiscover
from .base import (
    SCAPY_REGISTRY,
    STACK_ENCODER_REGISTRY,
    ScapyProtocol,
    StackEncoder,
    register,
    register_stack_encoder,
)

autodiscover(__name__, __path__)

__all__ = [
    "SCAPY_REGISTRY",
    "STACK_ENCODER_REGISTRY",
    "ScapyProtocol",
    "StackEncoder",
    "register",
    "register_stack_encoder",
]
