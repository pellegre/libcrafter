"""Wireshark-stage decode plugin for the Wi-Fi (802.11) stack.

This module is the home for the 802.11 tshark normalizers (``radiotap``,
``dot11``, ``eapol``, ``rsn``); this step migrates ``radiotap`` and later steps add
the rest. It moves the ``_normalize_radiotap`` tshark normalizer and its
``_parse_radiotap_rate`` / ``_radiotap_fcs_status`` helpers verbatim out of
:mod:`..normalize` and registers them through the :class:`~.base.WiresharkProtocol`
contract; only the dispatch moves out of the legacy if/elif. Behavior must stay
byte-identical.

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
    _truthy_field,
)
from .base import WiresharkProtocol, register


# tshark field aliases the radiotap layer owns: canonical oracle name -> the native
# tshark field names that carry it.
_RADIOTAP_TSHARK_ALIASES: JSONObject = {
    "version": ("radiotap.version",),
    "pad": ("radiotap.pad",),
    "length": ("radiotap.length",),
    "flags": ("radiotap.flags",),
    "rate": ("radiotap.datarate", "radiotap.rate"),
    "channel_frequency": ("radiotap.channel.freq", "radiotap.channel.frequency"),
    "channel_flags": ("radiotap.channel.flags",),
    "dbm_antenna_signal": ("radiotap.dbm_antsignal", "radiotap.dbm_antenna_signal"),
    "antenna": ("radiotap.antenna",),
    "rx_flags": ("radiotap.rxflags", "radiotap.rx_flags"),
    "tx_flags": ("radiotap.txflags", "radiotap.tx_flags"),
}


def _normalize_radiotap_layer(layer: JSONObject) -> JSONObject:
    output = _fields_from_aliases(layer, dict(_RADIOTAP_TSHARK_ALIASES))
    _parse_int_fields(
        output,
        "version",
        "pad",
        "length",
        "flags",
        "channel_frequency",
        "channel_flags",
        "dbm_antenna_signal",
        "antenna",
        "rx_flags",
        "tx_flags",
    )
    rate = _parse_radiotap_rate(output.get("rate"))
    if rate is not None:
        output["rate"] = rate
    else:
        output.pop("rate", None)

    present_words = [
        parsed
        for parsed in (
            _parse_int(item)
            for item in _field_list(
                layer,
                "radiotap.present.word",
                "radiotap.present",
            )
        )
        if parsed is not None
    ]
    if present_words:
        output["present_words"] = present_words

    flags = output.get("flags")
    if isinstance(flags, int):
        output["fcs_status"] = _radiotap_fcs_status(flags)
    elif _truthy_field(layer, "radiotap.flags.fcs"):
        output["fcs_status"] = (
            "present_failed"
            if _truthy_field(layer, "radiotap.flags.badfcs")
            else "present"
        )
    elif _truthy_field(layer, "radiotap.flags.badfcs"):
        output["fcs_status"] = "failed"
    return output


def _parse_radiotap_rate(value: object) -> int | None:
    parsed = _parse_int(value)
    if parsed is not None:
        return parsed
    if not isinstance(value, str):
        return None
    candidate = value.strip().split(" ", 1)[0]
    try:
        return int(round(float(candidate) * 2))
    except ValueError:
        return None


def _radiotap_fcs_status(flags: int) -> str:
    present = bool(flags & 0x10)
    failed = bool(flags & 0x40)
    if present and failed:
        return "present_failed"
    if present:
        return "present"
    if failed:
        return "failed"
    return "absent"


def _normalize_radiotap(
    layers: JSONObject, *, source_hex: str | None = None
) -> JSONObject:
    return _normalize_radiotap_layer(_layer(layers, "radiotap"))


register(
    WiresharkProtocol(
        layer="radiotap",
        normalize=_normalize_radiotap,
        tshark_aliases=dict(_RADIOTAP_TSHARK_ALIASES),
    )
)
