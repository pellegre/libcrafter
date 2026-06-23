"""Scapy-stage encode + decode plugin for the UDP layer.

Moves the ``_udp`` (UDP) builder verbatim out of :mod:`..packets` and registers it
through the :class:`~.base.ScapyProtocol` contract; only the dispatch moves out of
the legacy if/elif. Behavior must stay byte-identical. The ``_udp`` builder takes
``stack`` (the legacy ``_build_layer`` passed it) but does not read it — the
stack-aware UDP *port* defaults are resolved earlier by the generator-stage UDP
sampler, so the builder simply materializes the already-sampled
``sport``/``dport``/``chksum``/``len`` fields; the unused ``stack``/``index``
parameters are kept on the uniform ``build`` signature.

UDP has no dedicated ``if layer_name == "udp"`` block in the legacy
``_normalize_fields``; it decoded through the generic alias path. The plugin's
``_normalize`` reproduces that path exactly: each native Scapy field name is renamed
through UDP's effective field-name map (UDP owns no layer-specific field aliases, so
the map is just the global ``normalize._FIELD_ALIASES`` table the legacy
``_normalize_field_name`` consulted), and the generic value rules (``is_response``
and ``more_fragments`` ints to bools) are applied — neither appears on a decoded UDP
layer, so they are carried only for byte-identity with the legacy generic path. The
whole-stack UDP surplus-options normalization (``_apply_udp_surplus_normalization``)
is a separate post-decode pass keyed on the plan and is left on legacy dispatch.

Shared primitives come from the helper modules so this plugin does not depend on the
``packets``/``normalize`` orchestrators (which would create a circular import).
Relative imports only so the package resolves under both the ``engine.*`` (CLI) and
``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ....model import JSONObject, JSONValue
from ..encode_helpers import (
    _int,
    _layer_fields,
    _optional_field,
    _required_field,
)
from .base import ScapyProtocol, register


# Encode-side field allowlist for ``_validate_layer_fields`` — the canonical field
# names plus every Scapy/oracle alias the UDP builder accepts. Mirrors the former
# ``packets._SUPPORTED_FIELDS_BY_LAYER["udp"]`` entry exactly.
_SUPPORTED_FIELDS = frozenset(
    {
        "checksum",
        "chksum",
        "dport",
        "dst_port",
        "len",
        "length",
        "options",
        "sport",
        "src_port",
    }
)

# Decode-side native-name alias the UDP layer owns: the Scapy class name mapped to
# the oracle layer name (the former ``normalize._LAYER_ALIASES["UDP"]`` entry). UDP
# owns no layer-specific *field* aliases.
_LAYER_ALIASES = (("UDP", "udp"),)
_FIELD_ALIASES: tuple[tuple[str, str], ...] = ()

# Global cross-layer field aliases the legacy ``_normalize_field_name`` consulted as
# the fallback (mirrors ``normalize._FIELD_ALIASES``). UDP exercises ``sport``,
# ``dport``, ``len``, and ``chksum``; the rest never appear on a decoded UDP layer,
# so carrying the full map is harmless and keeps the lookup byte-identical to the
# legacy generic path.
_GLOBAL_FIELD_ALIASES: dict[str, str] = {
    "chksum": "checksum",
    "dataofs": "data_offset",
    "dport": "dst_port",
    "frag": "fragment_offset",
    "hlim": "hop_limit",
    "len": "length",
    "nh": "next_header",
    "proto": "protocol",
    "sport": "src_port",
    "urgptr": "urgent_pointer",
}
# Effective UDP field-name map: UDP owns no layer-specific aliases, so this is the
# global table — exactly the precedence ``_normalize_field_name("udp", ...)`` applied.
_UDP_FIELD_NAME_MAP: dict[str, str] = {**_GLOBAL_FIELD_ALIASES, **dict(_FIELD_ALIASES)}


# ---------------------------------------------------------------------------
# Encode
# ---------------------------------------------------------------------------


def _build(
    plan: Any,
    fields: Mapping[str, JSONObject],
    stack: Any,
    index: int,
    scapy_all: Any,
) -> Any:
    udp_fields = _layer_fields(fields, "udp")
    kwargs: dict[str, Any] = {
        "sport": _int(_required_field(udp_fields, "udp", "src_port", "sport"), 0),
        "dport": _int(_required_field(udp_fields, "udp", "dst_port", "dport"), 0),
    }
    if "checksum" in udp_fields or "chksum" in udp_fields:
        kwargs["chksum"] = _int(_optional_field(udp_fields, "checksum", "chksum"), 0)
    if "length" in udp_fields or "len" in udp_fields:
        kwargs["len"] = _int(_optional_field(udp_fields, "length", "len"), 0)
    return scapy_all.UDP(**kwargs)


# ---------------------------------------------------------------------------
# Decode
# ---------------------------------------------------------------------------


def _normalize(fields: JSONObject) -> JSONObject:
    """Normalize a decoded Scapy UDP layer to the comparable oracle shape.

    Byte-identical to the legacy generic ``_normalize_fields`` path for udp: each
    native field name is renamed via the UDP field-name map (the lookup order
    ``_normalize_field_name`` applied), and the generic value rules are applied.
    """

    output: JSONObject = {}
    for native_name, value in fields.items():
        normalized_name = _UDP_FIELD_NAME_MAP.get(native_name, native_name)
        output[normalized_name] = _normalize_field_value(normalized_name, value)
    return output


def _normalize_field_value(field_name: str, value: JSONValue) -> JSONValue:
    if field_name == "is_response" and isinstance(value, int):
        return bool(value)
    if field_name == "more_fragments" and isinstance(value, int):
        return bool(value)
    return value


register(
    ScapyProtocol(
        layer="udp",
        scapy_class="UDP",
        supported_fields=_SUPPORTED_FIELDS,
        build=_build,
        normalize=_normalize,
        layer_aliases=_LAYER_ALIASES,
        field_aliases=_FIELD_ALIASES,
    )
)
