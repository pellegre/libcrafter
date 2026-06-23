"""Wireshark-stage decode plugin for the ``ripng`` layer.

Moves the ``_normalize_ripng`` tshark normalizer and its field aliases verbatim
out of :mod:`..normalize` and registers them through the
:class:`~.base.WiresharkProtocol` contract; only the dispatch moves out of the
legacy if/elif. Behavior must stay byte-identical.

Scapy has no native RIPng dissector, so the parser (tshark) backend supplies the
RIPng cross-validation decode. The normalized names mirror the libcrafter
Ripng/RipngRte accessor names (``command``/``version``/``reserved`` plus an
``rtes`` list of ``prefix``/``route_tag``/``prefix_len``/``metric``) so the parser
decode aligns with the libcrafter surface.

Shared primitives come from :mod:`..decode_helpers` so this plugin does not depend
on the ``normalize`` orchestrator (which would create a circular import). Relative
imports only so the package resolves under both the ``engine.*`` (CLI) and
``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from ....model import JSONObject
from ..decode_helpers import (
    _field_list,
    _fields_from_aliases,
    _layer,
    _parse_int,
    _parse_int_fields,
)
from .base import WiresharkProtocol, register


# tshark field aliases the RIPng layer owns: canonical oracle name -> the native
# tshark field names that carry it. Wireshark's RIPng dissector
# (``packet-ripng.c``) exposes ``ripng.cmd``/``ripng.version``/``ripng.ip``/
# ``ripng.route_tag``/``ripng.prefix_length``/``ripng.metric``; the alternate
# ``ripng.command`` prefix is accepted defensively.
_RIPNG_TSHARK_ALIASES: JSONObject = {
    "command": ("ripng.cmd", "ripng.command"),
    "version": ("ripng.version",),
    "reserved": ("ripng.reserved", "ripng.null"),
}


def _normalize_ripng_layer(layer: JSONObject) -> JSONObject:
    """Normalize a tshark RIPng layer to the shared oracle field names."""

    output = _fields_from_aliases(layer, dict(_RIPNG_TSHARK_ALIASES))
    _parse_int_fields(output, "command", "version", "reserved")

    prefixes = [str(item) for item in _field_list(layer, "ripng.ip", "ripng.prefix")]
    route_tags = [_parse_int(item) for item in _field_list(layer, "ripng.route_tag", "ripng.tag")]
    prefix_lens = [
        _parse_int(item)
        for item in _field_list(layer, "ripng.prefix_length", "ripng.prefix_len")
    ]
    metrics = [_parse_int(item) for item in _field_list(layer, "ripng.metric")]

    rtes: list[JSONObject] = []
    for index, prefix in enumerate(prefixes):
        rte: JSONObject = {"prefix": prefix}
        if index < len(route_tags) and route_tags[index] is not None:
            rte["route_tag"] = route_tags[index]
        if index < len(prefix_lens) and prefix_lens[index] is not None:
            rte["prefix_len"] = prefix_lens[index]
        if index < len(metrics) and metrics[index] is not None:
            rte["metric"] = metrics[index]
        rtes.append(rte)
    if rtes:
        output["rtes"] = rtes
    return output


def _normalize_ripng(layers: JSONObject, *, source_hex: str | None = None) -> JSONObject:
    return _normalize_ripng_layer(_layer(layers, "ripng"))


register(
    WiresharkProtocol(
        layer="ripng",
        normalize=_normalize_ripng,
        tshark_aliases=dict(_RIPNG_TSHARK_ALIASES),
    )
)
