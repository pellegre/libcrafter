"""Scapy-stage encode plugin for the Wi-Fi (802.11) stack.

This module is the home for the 802.11 Scapy backend code (``radiotap``,
``dot11``, ``eapol``, ``rsn``); this step migrates ``radiotap`` and later steps add
the rest. It registers a :class:`~.base.ScapyProtocol` for ``radiotap`` so the
encoder resolves its ``scapy_class`` (``RadioTap``), encode-side field allowlist,
and decode-side ``RadioTap`` -> ``radiotap`` layer alias from the registry instead
of the legacy ``packets._SCAPY_LAYER_BY_LAYER`` / ``_SUPPORTED_FIELDS_BY_LAYER`` /
``normalize._LAYER_ALIASES`` tables. Behavior must stay byte-identical.

Radiotap is never materialized through the per-layer ``_build_layer`` dispatch: it
is part of the whole-stack Dot11 phase-1.5 raw-bytes path, so its
:meth:`ScapyProtocol.build` is never invoked and raises if called. The
``_radiotap_bytes`` serializer and its ``_radiotap_padding`` / ``_radiotap_flags``
/ ``_radiotap_channel_flags`` helpers are co-located here and re-imported by
:mod:`..packets`, which still owns the whole-stack ``_dot11_phase15_bytes`` driver
until the ``dot11`` raw-bytes stack encoder migrates. Likewise the radiotap decode
stays on the whole-stack byte-level Dot11 normalizer (``normalize._parse_radiotap``)
for now, so this plugin registers no ``normalize`` hook.

Shared primitives come from :mod:`..encode_helpers` so this plugin does not depend
on the ``packets`` orchestrator (which would create a circular import). Relative
imports only so the package resolves under both the ``engine.*`` (CLI) and
``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ....model import JSONObject
from ..encode_helpers import _int, _layer_fields
from .base import ScapyProtocol, register


# Encode-side field allowlist for ``_validate_layer_fields`` — mirrors the former
# ``packets._SUPPORTED_FIELDS_BY_LAYER["radiotap"]`` entry exactly.
_RADIOTAP_SUPPORTED_FIELDS = frozenset(
    {
        "antenna",
        "channel_flags",
        "channel_frequency",
        "dbm_antenna_signal",
        "fcs_status",
        "flags",
        "length",
        "pad",
        "present_words",
        "rate",
        "rx_flags",
        "tx_flags",
        "unknown_fields",
        "version",
    }
)

# Decode-side native-name alias the radiotap layer owns: the Scapy class name maps
# to the oracle layer name (the former ``normalize._LAYER_ALIASES["RadioTap"]``).
_RADIOTAP_LAYER_ALIASES = (("RadioTap", "radiotap"),)


def _radiotap_bytes(fields: Mapping[str, JSONObject]) -> bytes:
    radiotap = _layer_fields(fields, "radiotap")
    field_entries: list[tuple[int, int, bytes]] = []
    if "flags" in radiotap or "fcs_status" in radiotap:
        field_entries.append((1, 1, bytes([_radiotap_flags(radiotap)])))
    if "rate" in radiotap:
        field_entries.append((2, 1, bytes([_int(radiotap.get("rate"), 2) & 0xFF])))
    if "channel_frequency" in radiotap or "channel_flags" in radiotap:
        field_entries.append(
            (
                3,
                2,
                _int(radiotap.get("channel_frequency"), 2412).to_bytes(2, "little")
                + _radiotap_channel_flags(radiotap.get("channel_flags")).to_bytes(2, "little"),
            )
        )
    if "dbm_antenna_signal" in radiotap:
        signal = _int(radiotap.get("dbm_antenna_signal"), -42)
        field_entries.append((5, 1, int(signal).to_bytes(1, "little", signed=True)))
    if "antenna" in radiotap:
        field_entries.append((11, 1, bytes([_int(radiotap.get("antenna"), 0) & 0xFF])))
    if "rx_flags" in radiotap:
        field_entries.append((14, 2, _int(radiotap.get("rx_flags"), 0).to_bytes(2, "little")))
    if "tx_flags" in radiotap:
        field_entries.append((15, 2, _int(radiotap.get("tx_flags"), 0).to_bytes(2, "little")))

    present = 0
    for bit, _, _ in field_entries:
        present |= 1 << bit
    body = bytearray()
    offset = 8
    for _, alignment, value in sorted(field_entries, key=lambda item: item[0]):
        pad = _radiotap_padding(offset, alignment)
        body.extend(b"\x00" * pad)
        offset += pad
        body.extend(value)
        offset += len(value)

    version = _int(radiotap.get("version"), 0) & 0xFF
    pad_byte = _int(radiotap.get("pad"), 0) & 0xFF
    length = 8 + len(body)
    return (
        bytes([version, pad_byte])
        + length.to_bytes(2, "little")
        + present.to_bytes(4, "little")
        + bytes(body)
    )


def _radiotap_padding(offset: int, alignment: int) -> int:
    if alignment <= 1:
        return 0
    remainder = offset % alignment
    return 0 if remainder == 0 else alignment - remainder


def _radiotap_flags(fields: Mapping[str, object]) -> int:
    value = 0
    raw_flags = fields.get("flags")
    raw_status = fields.get("fcs_status")
    tokens = {str(item).lower().replace("-", "_") for item in (raw_flags, raw_status) if item is not None}
    if raw_flags is not None and not isinstance(raw_flags, str):
        value |= _int(raw_flags, 0)
    if "fcs_present" in tokens or "present" in tokens or "present_failed" in tokens:
        value |= 0x10
    if "failed_fcs" in tokens or "failed" in tokens or "present_failed" in tokens:
        value |= 0x40
    return value


def _radiotap_channel_flags(value: object) -> int:
    if value is None:
        return 0x00A0
    if not isinstance(value, str):
        return _int(value, 0)
    normalized = value.lower().replace("-", "_")
    mapping = {
        "two_ghz_cck": 0x00A0,
        "two_ghz_ofdm": 0x00C0,
        "five_ghz_ofdm": 0x0140,
    }
    if normalized in mapping:
        return mapping[normalized]
    return _int(value, 0)


def _build(
    plan: Any,
    fields: Mapping[str, JSONObject],
    stack: Any,
    index: int,
    scapy_all: Any,
) -> Any:
    """Radiotap is encoded by the whole-stack Dot11 raw-bytes path, never here."""

    raise ValueError(
        "radiotap is materialized by the Dot11 phase 1.5 byte path, not _build_layer"
    )


register(
    ScapyProtocol(
        layer="radiotap",
        scapy_class="RadioTap",
        supported_fields=_RADIOTAP_SUPPORTED_FIELDS,
        build=_build,
        normalize=None,
        layer_aliases=_RADIOTAP_LAYER_ALIASES,
    )
)
