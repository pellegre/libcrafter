"""Generator-stage per-protocol sampler plugins, auto-discovered at import.

Dropping a module into this package self-registers its
:class:`~.base.ProtocolSampler` plugins as a side effect of import. The package is
empty of protocols until they are migrated off the generator's legacy if/elif
branches; until then :data:`~.base.SAMPLER_REGISTRY` stays empty and the generator
falls through to its in-line sampling. Auto-discovery uses ``__name__``-relative
module names so it works under both the ``engine.*`` and ``tools.oracle.engine.*``
import roots.
"""

from __future__ import annotations

from ..plugin_registry import autodiscover
from .base import SAMPLER_REGISTRY, ProtocolSampler, register

autodiscover(__name__, __path__)

__all__ = ["SAMPLER_REGISTRY", "ProtocolSampler", "register"]
