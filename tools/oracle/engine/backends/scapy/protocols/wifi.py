"""Scapy-stage encode plugin for the Wi-Fi (802.11) stack.

This module is the home for the 802.11 Scapy backend code (``radiotap``,
``dot11``, ``eapol``, ``rsn``); ``radiotap``, ``eapol``, and ``rsn`` are migrated
here and ``dot11`` is added next. It registers a :class:`~.base.ScapyProtocol` for
each so the encoder resolves their ``scapy_class`` (``RadioTap`` / ``EAPOL`` /
``Dot11EltRSN``), encode-side field allowlists, and decode-side native-name layer
aliases (``RadioTap`` -> ``radiotap``, ``EAPOL`` -> ``eapol``, ``Dot11EltRSN`` ->
``rsn``) from the registry instead of the legacy
``packets._SCAPY_LAYER_BY_LAYER`` / ``_SUPPORTED_FIELDS_BY_LAYER`` /
``normalize._LAYER_ALIASES`` tables. Behavior must stay byte-identical.

None of these layers is materialized through the per-layer ``_build_layer``
dispatch: they are part of the whole-stack Dot11 phase-1.5 raw-bytes path, so each
:meth:`ScapyProtocol.build` is never invoked and raises if called. The
``_radiotap_bytes`` / ``_eapol_bytes`` / ``_rsn_element_bytes`` serializers and
their helpers are co-located here and re-imported by :mod:`..packets`, which still
owns the whole-stack ``_dot11_phase15_bytes`` driver until the ``dot11`` raw-bytes
stack encoder migrates. Likewise the radiotap/eapol/rsn decode stays on the
whole-stack byte-level Dot11 normalizer (``normalize._parse_radiotap`` /
``_decode_eapol`` / ``_parse_rsn_information``) for now, so these plugins register
no ``normalize`` hook.

Shared primitives come from :mod:`..encode_helpers` so this plugin does not depend
on the ``packets`` orchestrator (which would create a circular import). Relative
imports only so the package resolves under both the ``engine.*`` (CLI) and
``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from ....model import JSONObject
from ..encode_helpers import (
    _bytes_exact,
    _bytes_optional,
    _int,
    _layer_fields,
    _payload_bytes,
)
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


# Encode-side field allowlist for ``_validate_layer_fields`` — mirrors the former
# ``packets._SUPPORTED_FIELDS_BY_LAYER["eapol"]`` entry exactly.
_EAPOL_SUPPORTED_FIELDS = frozenset(
    {
        "body_length",
        "descriptor_type",
        "key_data",
        "key_data_length",
        "key_id",
        "key_information",
        "key_iv",
        "key_length",
        "key_mic",
        "key_nonce",
        "key_rsc",
        "packet_type",
        "replay_counter",
        "version",
    }
)

# Decode-side native-name alias the eapol layer owns: the Scapy class name maps to
# the oracle layer name (the former ``normalize._LAYER_ALIASES["EAPOL"]``).
_EAPOL_LAYER_ALIASES = (("EAPOL", "eapol"),)

# Encode-side field allowlist for ``_validate_layer_fields`` — mirrors the former
# ``packets._SUPPORTED_FIELDS_BY_LAYER["rsn"]`` entry exactly.
_RSN_SUPPORTED_FIELDS = frozenset(
    {
        "akm_suites",
        "capabilities",
        "element_id",
        "group_cipher_suite",
        "group_management_cipher_suite",
        "length",
        "pairwise_cipher_suites",
        "pmkid_list",
        "trailing_bytes",
        "version",
    }
)

# Decode-side native-name alias the rsn layer owns: the Scapy class name maps to
# the oracle layer name (the former ``normalize._LAYER_ALIASES["Dot11EltRSN"]``).
_RSN_LAYER_ALIASES = (("Dot11EltRSN", "rsn"),)


def _eapol_bytes(fields: Mapping[str, JSONObject], stack: Sequence[str], index: int) -> bytes:
    eapol = _layer_fields(fields, "eapol")
    packet_type = _eapol_type(eapol.get("packet_type"))
    body = _eapol_key_bytes(eapol) if packet_type == 3 or "descriptor_type" in eapol else b""
    trailing = _payload_bytes(fields) if "payload" in stack[index + 1 :] else b""
    body_length = len(body) + len(trailing)
    explicit_length = _int(eapol.get("body_length"), 0)
    if explicit_length:
        body_length = explicit_length
    return bytes(
        [
            _int(eapol.get("version"), 2) & 0xFF,
            packet_type & 0xFF,
        ]
    ) + body_length.to_bytes(2, "big") + body


def _eapol_type(value: object) -> int:
    if not isinstance(value, str):
        return _int(value, 1)
    mapping = {
        "eap_packet": 0,
        "eap-packet": 0,
        "start": 1,
        "logoff": 2,
        "key": 3,
        "asf_alert": 4,
        "asf-alert": 4,
        "unknown": 255,
    }
    normalized = value.lower()
    if normalized in mapping:
        return mapping[normalized]
    return _int(value, 1)


def _eapol_key_bytes(fields: Mapping[str, object]) -> bytes:
    key_data = _bytes_optional(fields.get("key_data"))
    key_data_length = _int(fields.get("key_data_length"), len(key_data))
    if key_data and key_data_length == 0:
        key_data_length = len(key_data)
    return (
        bytes([_eapol_descriptor_type(fields.get("descriptor_type"))])
        + _int(fields.get("key_information"), 0).to_bytes(2, "big")
        + _int(fields.get("key_length"), 0).to_bytes(2, "big")
        + _int(fields.get("replay_counter"), 0).to_bytes(8, "big")
        + _bytes_exact(fields.get("key_nonce"), 32)
        + _bytes_exact(fields.get("key_iv"), 16)
        + _bytes_exact(fields.get("key_rsc"), 8)
        + _bytes_exact(fields.get("key_id"), 8)
        + _bytes_exact(fields.get("key_mic"), 16)
        + key_data_length.to_bytes(2, "big")
        + key_data
    )


def _eapol_descriptor_type(value: object) -> int:
    if not isinstance(value, str):
        return _int(value, 2)
    mapping = {"rc4_key": 1, "rc4-key": 1, "rsn_key": 2, "rsn-key": 2, "unknown": 254}
    normalized = value.lower()
    if normalized in mapping:
        return mapping[normalized]
    return _int(value, 2)


def _rsn_element_bytes(fields: Mapping[str, JSONObject]) -> bytes:
    rsn = _layer_fields(fields, "rsn")
    value = _rsn_information_value_bytes(rsn)
    element_id = _int(rsn.get("element_id"), 48) & 0xFF
    length = _int(rsn.get("length"), len(value))
    if length == 0:
        length = len(value)
    return bytes([element_id, length & 0xFF]) + value


def _rsn_information_value_bytes(fields: Mapping[str, object] | None = None) -> bytes:
    fields = {} if fields is None else fields
    output = bytearray()
    output.extend(_int(fields.get("version"), 1).to_bytes(2, "little"))
    output.extend(_rsn_suite_selector(fields.get("group_cipher_suite"), default_type=4))
    pairwise = _suite_list(fields.get("pairwise_cipher_suites"), default_type=4)
    output.extend(len(pairwise).to_bytes(2, "little"))
    for suite in pairwise:
        output.extend(suite)
    akms = _suite_list(fields.get("akm_suites"), default_type=2)
    output.extend(len(akms).to_bytes(2, "little"))
    for suite in akms:
        output.extend(suite)
    if "capabilities" in fields or "group_management_cipher_suite" in fields:
        output.extend(_int(fields.get("capabilities"), 0).to_bytes(2, "little"))
    pmkids = _bytes_optional(fields.get("pmkid_list"))
    if pmkids:
        if len(pmkids) % 16 != 0:
            raise ValueError("rsn pmkid_list length must be a multiple of 16")
        output.extend((len(pmkids) // 16).to_bytes(2, "little"))
        output.extend(pmkids)
    elif "group_management_cipher_suite" in fields:
        output.extend((0).to_bytes(2, "little"))
    if "group_management_cipher_suite" in fields:
        output.extend(_rsn_suite_selector(fields.get("group_management_cipher_suite"), default_type=6))
    output.extend(_bytes_optional(fields.get("trailing_bytes")))
    return bytes(output)


def _suite_list(value: object, *, default_type: int) -> list[bytes]:
    if value is None:
        return [_rsn_suite_selector(None, default_type=default_type)]
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_rsn_suite_selector(item, default_type=default_type) for item in value]
    return [_rsn_suite_selector(value, default_type=default_type)]


def _rsn_suite_selector(value: object, *, default_type: int) -> bytes:
    if value is None:
        suite_type = default_type
    elif isinstance(value, Mapping) or isinstance(value, bytes):
        raw = _bytes_optional(value)
        if len(raw) != 4:
            raise ValueError("rsn suite selector must be exactly 4 bytes")
        return raw
    elif isinstance(value, int):
        suite_type = value
    elif isinstance(value, str):
        normalized = value.lower().replace("-", "_")
        suite_type = {
            "use_group": 0,
            "tkip": 2,
            "ccmp_128": 4,
            "aes_128_cmac": 6,
            "bip_cmac_128": 6,
            "psk": 2,
            "ieee8021x": 1,
            "sae": 8,
        }.get(normalized)
        if suite_type is None:
            return _bytes_optional(value)
    else:
        suite_type = default_type
    return b"\x00\x0f\xac" + bytes([suite_type & 0xFF])


def _build_eapol(
    plan: Any,
    fields: Mapping[str, JSONObject],
    stack: Any,
    index: int,
    scapy_all: Any,
) -> Any:
    """EAPOL is encoded by the whole-stack Dot11 raw-bytes path, never here."""

    raise ValueError(
        "eapol is materialized by the Dot11 phase 1.5 byte path, not _build_layer"
    )


def _build_rsn(
    plan: Any,
    fields: Mapping[str, JSONObject],
    stack: Any,
    index: int,
    scapy_all: Any,
) -> Any:
    """RSN is encoded by the whole-stack Dot11 raw-bytes path, never here."""

    raise ValueError(
        "rsn is materialized by the Dot11 phase 1.5 byte path, not _build_layer"
    )


register(
    ScapyProtocol(
        layer="eapol",
        scapy_class="EAPOL",
        supported_fields=_EAPOL_SUPPORTED_FIELDS,
        build=_build_eapol,
        normalize=None,
        layer_aliases=_EAPOL_LAYER_ALIASES,
    )
)


register(
    ScapyProtocol(
        layer="rsn",
        scapy_class="Dot11EltRSN",
        supported_fields=_RSN_SUPPORTED_FIELDS,
        build=_build_rsn,
        normalize=None,
        layer_aliases=_RSN_LAYER_ALIASES,
    )
)
