"""Wireshark-stage decode plugins for the simple framing/wrapper layers.

Covers ``payload``, ``null_loopback`` and ``llc_snap``. The ``_normalize_payload``,
``_normalize_null_loopback`` and ``_normalize_llc_snap`` tshark normalizers and
their field aliases are moved verbatim out of :mod:`..normalize` and registered
through the :class:`~.base.WiresharkProtocol` contract; only the dispatch moves out
of the legacy if/elif. Behavior must stay byte-identical.

``linux_cooked`` is intentionally NOT migrated here on the Wireshark stage. A
``sll`` layer normalizes under the name ``linux_sll`` (not the spec layer name
``linux_cooked``) via the kept ``_PROTOCOL_LAYER_ALIASES`` routing table, so its
``_normalize_protocol_fields`` dispatch key is the non-spec name ``linux_sll``. The
registry is keyed by the spec layer name, so the registry lookup never resolves it;
its normalizer stays on the legacy ``linux_sll`` branch in :mod:`..normalize`.

``llc_snap`` also participates in the Wi-Fi stack; only its generic framing decode
(the ``llc`` layer normalizer) is migrated here. Wi-Fi-specific composition stays
with the Wi-Fi steps.

Shared primitives come from :mod:`..decode_helpers` so this plugin does not depend
on the ``normalize`` orchestrator (which would create a circular import). Relative
imports only so the package resolves under both the ``engine.*`` (CLI) and
``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from ....model import JSONObject
from ..decode_helpers import (
    _fields_from_aliases,
    _hex_bytes,
    _layer,
    _parse_int_fields,
    _string_field,
)
from .base import WiresharkProtocol, register


# tshark field aliases each layer owns: canonical oracle name -> the native-tshark
# field names that carry it.
_NULL_LOOPBACK_TSHARK_ALIASES: JSONObject = {"type": ("null.type",)}
_LLC_SNAP_TSHARK_ALIASES: JSONObject = {
    "dsap": ("llc.dsap",),
    "ssap": ("llc.ssap",),
    "control": ("llc.control",),
    "oui": ("llc.oui", "llc.snap.oui"),
    "ethertype": ("llc.type", "llc.etype", "llc.pid"),
}


def _normalize_payload(layers: JSONObject, *, source_hex: str | None = None) -> JSONObject:
    layer = _layer(layers, "data")
    data = _string_field(layer, "data.data", "data.text")
    if data is None:
        return {}
    hex_value = _hex_bytes(data)
    return {
        "hex": hex_value,
        "length": len(bytes.fromhex(hex_value)),
    }


def _normalize_null_loopback(
    layers: JSONObject, *, source_hex: str | None = None
) -> JSONObject:
    output = _fields_from_aliases(
        _layer(layers, "null"), dict(_NULL_LOOPBACK_TSHARK_ALIASES)
    )
    _parse_int_fields(output, "type")
    return output


def _normalize_llc_snap(layers: JSONObject, *, source_hex: str | None = None) -> JSONObject:
    output = _fields_from_aliases(_layer(layers, "llc"), dict(_LLC_SNAP_TSHARK_ALIASES))
    _parse_int_fields(output, "dsap", "ssap", "control", "ethertype")
    oui = output.get("oui")
    if isinstance(oui, str):
        output["oui"] = {"hex": _hex_bytes(oui)}
    return output


register(
    WiresharkProtocol(
        layer="payload",
        normalize=_normalize_payload,
        tshark_aliases={"hex": ("data.data", "data.text")},
    )
)

register(
    WiresharkProtocol(
        layer="null_loopback",
        normalize=_normalize_null_loopback,
        tshark_aliases=dict(_NULL_LOOPBACK_TSHARK_ALIASES),
    )
)

register(
    WiresharkProtocol(
        layer="llc_snap",
        normalize=_normalize_llc_snap,
        tshark_aliases=dict(_LLC_SNAP_TSHARK_ALIASES),
    )
)
