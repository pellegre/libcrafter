"""Scapy-stage protocol plugin contracts and registries.

A protocol module in this package registers a :class:`ScapyProtocol` per layer it
encodes/decodes through Scapy, and optionally a :class:`StackEncoder` for families
that bypass the per-layer build and emit whole-stack raw bytes (BLE advertising,
Dot11 phase-15, IGMP query/report/extension, IPsec SA). The Scapy encoder consults
:data:`STACK_ENCODER_REGISTRY` before its whole-stack special-case branches and
:data:`SCAPY_REGISTRY` before its per-layer ``_build_layer`` if/elif; the decoder
consults :data:`SCAPY_REGISTRY` for a layer's ``normalize`` before its legacy
branches. Both registries start empty, so until a protocol is migrated every layer
and stack falls through to the legacy code and behavior is unchanged.

Modules use relative imports only so the package works under both the ``engine.*``
(CLI) and ``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass

from ....model import JSONObject
from ....plugin_registry import PluginRegistry


@dataclass(frozen=True)
class ScapyProtocol:
    """Scapy-stage plugin for one layer's encode (and optional decode).

    ``layer`` is the layer name the plugin owns and ``scapy_class`` is the Scapy
    class name it materializes (or ``None`` for raw-bytes layers).
    ``supported_fields`` mirrors the encoder's per-layer field allowlist. ``build``
    materializes the layer as a Scapy object (or a raw-bytes wrapper):
    ``build(plan, fields, stack, index, scapy_all) -> object``. ``normalize`` is the
    optional decode-side hook ``normalize(fields) -> JSONObject`` consulted by the
    Scapy decoder before its legacy branches; it stays ``None`` for layers that use
    the generic alias path. ``layer_aliases`` and ``field_aliases`` carry the
    decode-side native-name aliases the layer owns.
    """

    layer: str
    scapy_class: str | None
    supported_fields: frozenset[str]
    build: Callable[..., object]
    normalize: Callable[[JSONObject], JSONObject] | None = None
    layer_aliases: tuple[tuple[str, str], ...] = ()
    field_aliases: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class StackEncoder:
    """Scapy-stage plugin for a whole-stack raw-bytes family.

    ``name`` identifies the family for diagnostics. ``matches(stack) -> bool``
    selects which stacks this encoder owns, and ``encode(plan, scapy_all) -> bytes``
    materializes the matched stack as raw wire bytes, bypassing the per-layer build.
    """

    name: str
    matches: Callable[[Sequence[str]], bool]
    encode: Callable[..., bytes]


SCAPY_REGISTRY: PluginRegistry[ScapyProtocol] = PluginRegistry("scapy-protocol")

# Ordered collection of whole-stack encoders. Consulted in registration order by
# the Scapy encoder before its legacy whole-stack branches; the first whose
# ``matches(stack)`` is true wins. Empty until a raw-bytes family is migrated.
STACK_ENCODER_REGISTRY: list[StackEncoder] = []


def register(plugin: ScapyProtocol) -> None:
    """Register ``plugin`` under its layer name in :data:`SCAPY_REGISTRY`."""

    SCAPY_REGISTRY.register(plugin.layer, plugin)


def register_stack_encoder(encoder: StackEncoder) -> None:
    """Append ``encoder`` to the ordered :data:`STACK_ENCODER_REGISTRY`."""

    STACK_ENCODER_REGISTRY.append(encoder)


__all__ = [
    "ScapyProtocol",
    "StackEncoder",
    "SCAPY_REGISTRY",
    "STACK_ENCODER_REGISTRY",
    "register",
    "register_stack_encoder",
]
