"""Wireshark-stage protocol plugin contract and registry.

A protocol module in this package registers a :class:`WiresharkProtocol` per layer
it decodes from tshark's JSON output. The parser-only Wireshark normalizer consults
:data:`WIRESHARK_REGISTRY` before its per-protocol ``_normalize_protocol_fields``
if/elif: when a layer has a registered plugin the normalizer delegates to
``plugin.normalize``, otherwise it falls through to the legacy branch. The registry
starts empty, so until a protocol is migrated every layer flows through the legacy
code and behavior is unchanged.

Modules use relative imports only so the package works under both the ``engine.*``
(CLI) and ``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ....model import JSONObject
from ....plugin_registry import PluginRegistry


@dataclass(frozen=True)
class WiresharkProtocol:
    """Wireshark-stage plugin for one layer's tshark decode.

    ``layer`` is the layer name the plugin owns. ``normalize`` is the decode-side
    hook ``normalize(layers, *, source_hex=None) -> JSONObject`` consulted by the
    Wireshark normalizer before its legacy branches; it receives the full tshark
    ``layers`` object and pulls the layer's fields via the shared decode helpers.
    ``tshark_aliases`` carries the per-protocol tshark field alias mapping the layer
    owns (the canonical-name -> native-tshark-name table the legacy ``_normalize_<l>``
    used).
    """

    layer: str
    normalize: Callable[..., JSONObject]
    tshark_aliases: JSONObject


WIRESHARK_REGISTRY: PluginRegistry[WiresharkProtocol] = PluginRegistry(
    "wireshark-protocol"
)


def register(plugin: WiresharkProtocol) -> None:
    """Register ``plugin`` under its layer name in :data:`WIRESHARK_REGISTRY`."""

    WIRESHARK_REGISTRY.register(plugin.layer, plugin)


__all__ = [
    "WiresharkProtocol",
    "WIRESHARK_REGISTRY",
    "register",
]
