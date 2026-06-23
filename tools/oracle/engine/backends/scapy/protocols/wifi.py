"""Scapy-stage encode plugin for the Wi-Fi (802.11) stack.

This module is the home for the 802.11 Scapy backend code (``radiotap``,
``dot11``, ``eapol``, ``rsn``); all four are migrated here. It registers a
:class:`~.base.ScapyProtocol` for each so the encoder resolves their
``scapy_class`` (``RadioTap`` / ``Dot11`` / ``EAPOL`` / ``Dot11EltRSN``),
encode-side field allowlists, and decode-side native-name layer aliases
(``RadioTap`` -> ``radiotap``, ``Dot11`` -> ``dot11``, ``EAPOL`` -> ``eapol``,
``Dot11EltRSN`` -> ``rsn``) from the registry instead of the legacy
``packets._SCAPY_LAYER_BY_LAYER`` / ``_SUPPORTED_FIELDS_BY_LAYER`` /
``normalize._LAYER_ALIASES`` tables. Behavior must stay byte-identical.

None of these layers is materialized through the per-layer ``_build_layer``
dispatch: they are part of the whole-stack Dot11 phase-1.5 raw-bytes path, so each
:meth:`ScapyProtocol.build` is never invoked and raises if called. The whole-stack
driver ``_dot11_phase15_bytes`` and its stack predicate ``_is_dot11_phase15_stack``
are co-located here and registered through the :class:`~.base.StackEncoder`
contract; :func:`packets.encode_packet_plan` consults
:data:`~.base.STACK_ENCODER_REGISTRY` (which this encoder joins) before its legacy
whole-stack branches, so the Dot11 phase-1.5 path now resolves through the registry.
The ``_radiotap_bytes`` / ``_dot11_bytes`` / ``_llc_snap_bytes`` / ``_eapol_bytes``
/ ``_rsn_element_bytes`` serializers and their helpers all live here.

The radiotap/dot11/eapol/rsn decode stays on the whole-stack byte-level Dot11
normalizer (``normalize._decode_dot11_bytes`` and its ``_parse_radiotap`` /
``_parse_dot11`` / ``_decode_eapol`` / ``_parse_rsn_information`` cluster), so these
plugins register no per-layer ``normalize`` hook.

Shared primitives come from :mod:`..encode_helpers` so this plugin does not depend
on the ``packets`` orchestrator (which would create a circular import). Relative
imports only so the package resolves under both the ``engine.*`` (CLI) and
``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from ....model import JSONObject, PacketPlan
from ..encode_helpers import (
    _IP_PROTOCOLS,
    _IPV6_NEXT_HEADERS,
    _bytes_exact,
    _bytes_optional,
    _canonical_stack,
    _ethertype_value,
    _hardware_type_value,
    _int,
    _internet_checksum,
    _ipv4_address_bytes,
    _ipv6_address_bytes,
    _layer_fields,
    _payload_bytes,
    _protocol_value,
)
from .base import ScapyProtocol, StackEncoder, register, register_stack_encoder


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
# ``packets._SUPPORTED_FIELDS_BY_LAYER["dot11"]`` entry exactly.
_DOT11_SUPPORTED_FIELDS = frozenset(
    {
        "addr1",
        "addr2",
        "addr3",
        "addr4",
        "duration_id",
        "frame_control",
        "frame_type",
        "from_ds",
        "ht_control",
        "management_fixed_fields",
        "more_data",
        "more_fragments",
        "order",
        "payload",
        "power_management",
        "protected",
        "protocol_version",
        "qos_control",
        "retry",
        "sequence_control",
        "subtype",
        "tagged_parameters",
        "to_ds",
    }
)

# Decode-side native-name alias the dot11 layer owns: the Scapy class name maps to
# the oracle layer name (the former ``normalize._LAYER_ALIASES["Dot11"]``).
_DOT11_LAYER_ALIASES = (("Dot11", "dot11"),)

# The whole-stack Dot11 phase-1.5 raw-bytes path materializes these layers byte by
# byte instead of through the per-layer ``_build_layer`` dispatch (the former
# ``packets._DOT11_PHASE15_LAYERS`` / ``_DOT11_CONVENTIONAL_CHILDREN`` sets).
_DOT11_PHASE15_LAYERS = frozenset({"radiotap", "dot11", "llc_snap", "eapol", "rsn"})
_DOT11_CONVENTIONAL_CHILDREN = frozenset({"arp", "ipv4", "ipv6"})


def _is_dot11_phase15_stack(stack: Sequence[str]) -> bool:
    return any(layer in _DOT11_PHASE15_LAYERS for layer in stack)


def _dot11_phase15_bytes(plan: PacketPlan, stack: list[str], scapy_all: Any) -> bytes:
    output = bytearray()
    index = 0
    while index < len(stack):
        layer = stack[index]
        if layer == "radiotap":
            output.extend(_radiotap_bytes(plan.fields))
        elif layer == "dot11":
            output.extend(_dot11_bytes(plan.fields))
        elif layer == "llc_snap":
            output.extend(_llc_snap_bytes(plan.fields, stack))
        elif layer == "eapol":
            output.extend(_eapol_bytes(plan.fields, stack, index))
        elif layer == "rsn":
            output.extend(_rsn_element_bytes(plan.fields))
        elif layer in {"payload", "raw"}:
            output.extend(_payload_bytes(plan.fields))
        elif layer in _DOT11_CONVENTIONAL_CHILDREN:
            output.extend(_dot11_conventional_child_bytes(plan.fields, layer))
        else:
            raise ValueError(f"unsupported Dot11 phase 1.5 materialization layer: {layer}")
        index += 1
    return bytes(output)


def _dot11_bytes(fields: Mapping[str, JSONObject]) -> bytes:
    dot11 = _layer_fields(fields, "dot11")
    frame_control = _dot11_frame_control(dot11)
    frame_type = (frame_control >> 2) & 0x3
    subtype = (frame_control >> 4) & 0xF
    output = bytearray()
    output.extend(frame_control.to_bytes(2, "little"))
    output.extend(_int(dot11.get("duration_id"), 0).to_bytes(2, "little"))
    output.extend(_mac_bytes(dot11.get("addr1"), "00:00:5e:00:53:01"))

    if frame_type == 1:
        if subtype not in {12, 13}:
            output.extend(_mac_bytes(dot11.get("addr2"), "00:00:5e:00:53:02"))
        return bytes(output)

    output.extend(_mac_bytes(dot11.get("addr2"), "00:00:5e:00:53:02"))
    output.extend(_mac_bytes(dot11.get("addr3"), "00:00:5e:00:53:03"))
    output.extend(_int(dot11.get("sequence_control"), 0).to_bytes(2, "little"))
    if frame_type == 2 and (frame_control & 0x0300) == 0x0300:
        output.extend(_mac_bytes(dot11.get("addr4"), "00:00:5e:00:53:04"))
    if frame_type == 2 and (subtype & 0x8):
        output.extend(_int(dot11.get("qos_control"), 0).to_bytes(2, "little"))
    if frame_control & 0x8000 and "ht_control" in dot11:
        output.extend(_int(dot11.get("ht_control"), 0).to_bytes(4, "little"))
    if frame_type == 0:
        output.extend(_bytes_optional(dot11.get("management_fixed_fields")))
        output.extend(_tagged_parameters_bytes(dot11.get("tagged_parameters")))
    return bytes(output)


def _dot11_frame_control(fields: Mapping[str, object]) -> int:
    if "frame_control" in fields:
        return _int(fields.get("frame_control"), 0)
    value = (_int(fields.get("protocol_version"), 0) & 0x3)
    value |= (_dot11_frame_type_value(fields.get("frame_type")) & 0x3) << 2
    value |= (_dot11_subtype_value(fields.get("subtype")) & 0xF) << 4
    for name, mask in (
        ("to_ds", 0x0100),
        ("from_ds", 0x0200),
        ("more_fragments", 0x0400),
        ("retry", 0x0800),
        ("power_management", 0x1000),
        ("more_data", 0x2000),
        ("protected", 0x4000),
        ("order", 0x8000),
    ):
        if bool(fields.get(name)):
            value |= mask
    return value


def _dot11_frame_type_value(value: object) -> int:
    if not isinstance(value, str):
        return _int(value, 2)
    mapping = {"management": 0, "control": 1, "data": 2, "extension": 3}
    normalized = value.lower().replace("-", "_")
    if normalized in mapping:
        return mapping[normalized]
    return _int(value, 2)


def _dot11_subtype_value(value: object) -> int:
    if not isinstance(value, str):
        return _int(value, 0)
    mapping = {
        "association_request": 0,
        "probe_request": 4,
        "beacon": 8,
        "authentication": 11,
        "deauthentication": 12,
        "rts": 11,
        "cts": 12,
        "ack": 13,
        "data": 0,
        "qos_data": 8,
        "unknown": 15,
    }
    normalized = value.lower().replace("-", "_")
    if normalized in mapping:
        return mapping[normalized]
    return _int(value, 0)


def _tagged_parameters_bytes(value: object) -> bytes:
    if value is None:
        return b""
    if isinstance(value, Mapping):
        value = [value]
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return _bytes_optional(value)
    output = bytearray()
    for item in value:
        if not isinstance(item, Mapping):
            continue
        tag = _int(item.get("id", item.get("tag", item.get("element_id"))), 0)
        data = _bytes_optional(item.get("value", item.get("data", item.get("bytes"))))
        output.extend(bytes([tag & 0xFF, len(data) & 0xFF]))
        output.extend(data)
    return bytes(output)


def _llc_snap_bytes(fields: Mapping[str, JSONObject], stack: Sequence[str]) -> bytes:
    llc = _layer_fields(fields, "llc_snap")
    return bytes(
        [
            _int(llc.get("dsap"), 0xAA) & 0xFF,
            _int(llc.get("ssap"), 0xAA) & 0xFF,
            _int(llc.get("control"), 0x03) & 0xFF,
        ]
    ) + _oui_bytes(llc.get("oui")) + _ethertype_value(
        llc.get("ethertype", _llc_snap_ethertype_for_stack(stack))
    ).to_bytes(2, "big")


def _dot11_conventional_child_bytes(fields: Mapping[str, JSONObject], layer: str) -> bytes:
    if layer == "arp":
        return _arp_bytes(fields)
    if layer == "ipv4":
        return _ipv4_bytes(fields)
    if layer == "ipv6":
        return _ipv6_bytes(fields)
    raise ValueError(f"unsupported Dot11 child protocol: {layer}")


def _arp_bytes(fields: Mapping[str, JSONObject]) -> bytes:
    arp = _layer_fields(fields, "arp")
    hwlen = _int(arp.get("hardware_length"), 6)
    plen = _int(arp.get("protocol_length"), 4)
    return (
        _hardware_type_value(arp.get("hardware_type", "ethernet")).to_bytes(2, "big")
        + _ethertype_value(arp.get("protocol_type", "ipv4")).to_bytes(2, "big")
        + bytes([hwlen & 0xFF, plen & 0xFF])
        + _arp_opcode_value(arp.get("opcode", arp.get("op", "request"))).to_bytes(2, "big")
        + _bytes_exact(_arp_address_bytes(arp.get("sender_hardware_address", arp.get("hwsrc")), "hardware"), hwlen)
        + _bytes_exact(_arp_address_bytes(arp.get("sender_protocol_address", arp.get("sender_ip", arp.get("psrc"))), "protocol"), plen)
        + _bytes_exact(_arp_address_bytes(arp.get("target_hardware_address", arp.get("hwdst")), "hardware"), hwlen)
        + _bytes_exact(_arp_address_bytes(arp.get("target_protocol_address", arp.get("target_ip", arp.get("pdst"))), "protocol"), plen)
    )


def _arp_opcode_value(value: object) -> int:
    if not isinstance(value, str):
        return _int(value, 1)
    mapping = {"request": 1, "who-has": 1, "reply": 2, "is-at": 2}
    normalized = value.lower().replace("_", "-")
    if normalized in mapping:
        return mapping[normalized]
    return _int(value, 1)


def _arp_address_bytes(value: object, kind: str) -> bytes:
    if kind == "protocol" and isinstance(value, str) and "." in value:
        return bytes(int(part) & 0xFF for part in value.split("."))
    default = "00:00:5e:00:53:01" if kind == "hardware" else {"hex": "00000000"}
    return _bytes_optional(value if value is not None else default)


def _ipv4_bytes(fields: Mapping[str, JSONObject]) -> bytes:
    ipv4 = _layer_fields(fields, "ipv4")
    payload = b""
    ihl = 5
    version_ihl = (4 << 4) | ihl
    flags_fragment = _ipv4_flags_fragment(ipv4)
    total_length = 20 + len(payload)
    protocol = _protocol_value(ipv4.get("protocol", ipv4.get("proto", "unknown")), _IP_PROTOCOLS)
    header = bytearray(
        [
            version_ihl,
            _int(ipv4.get("ds_field", ipv4.get("tos")), 0) & 0xFF,
        ]
    )
    header.extend(total_length.to_bytes(2, "big"))
    header.extend(_int(ipv4.get("identification", ipv4.get("id")), 0).to_bytes(2, "big"))
    header.extend(flags_fragment.to_bytes(2, "big"))
    header.extend(bytes([_int(ipv4.get("ttl"), 64) & 0xFF, protocol & 0xFF]))
    header.extend(b"\x00\x00")
    header.extend(_ipv4_address_bytes(ipv4.get("src"), "192.0.2.1"))
    header.extend(_ipv4_address_bytes(ipv4.get("dst"), "198.51.100.1"))
    checksum = _internet_checksum(bytes(header))
    header[10:12] = checksum.to_bytes(2, "big")
    return bytes(header) + payload


def _ipv4_flags_fragment(fields: Mapping[str, object]) -> int:
    flags = fields.get("flags", "none")
    flag_bits = 0
    if isinstance(flags, str):
        normalized = flags.lower().replace("_", "-")
        if "df" in normalized:
            flag_bits |= 0x4000
        if "mf" in normalized:
            flag_bits |= 0x2000
    else:
        flag_bits = (_int(flags, 0) & 0x7) << 13
    return flag_bits | (_int(fields.get("fragment_offset", fields.get("frag")), 0) & 0x1FFF)


def _ipv6_bytes(fields: Mapping[str, JSONObject]) -> bytes:
    ipv6 = _layer_fields(fields, "ipv6")
    traffic_class = _int(ipv6.get("traffic_class", ipv6.get("tc")), 0) & 0xFF
    flow_label = _int(ipv6.get("flow_label", ipv6.get("fl")), 0) & 0xFFFFF
    first_word = (6 << 28) | (traffic_class << 20) | flow_label
    payload = b""
    next_header = _protocol_value(
        ipv6.get("next_header", ipv6.get("nh", "unknown")),
        _IPV6_NEXT_HEADERS,
    )
    return (
        first_word.to_bytes(4, "big")
        + len(payload).to_bytes(2, "big")
        + bytes([next_header & 0xFF, _int(ipv6.get("hop_limit", ipv6.get("hlim")), 64) & 0xFF])
        + _ipv6_address_bytes(ipv6.get("src"), "2001:db8::1")
        + _ipv6_address_bytes(ipv6.get("dst"), "2001:db8::2")
        + payload
    )


def _llc_snap_ethertype_for_stack(stack: Sequence[str]) -> str:
    try:
        index = list(stack).index("llc_snap")
    except ValueError:
        return "unknown"
    if index + 1 >= len(stack):
        return "unknown"
    next_layer = stack[index + 1]
    return "eapol" if next_layer == "eapol" else next_layer


def _mac_bytes(value: object, default: str) -> bytes:
    return _bytes_exact(value if value is not None else default, 6)


def _oui_bytes(value: object) -> bytes:
    return _bytes_exact(value if value is not None else {"hex": "000000"}, 3)


def _build_dot11(
    plan: Any,
    fields: Mapping[str, JSONObject],
    stack: Any,
    index: int,
    scapy_all: Any,
) -> Any:
    """Dot11 is encoded by the whole-stack phase-1.5 raw-bytes path, never here."""

    raise ValueError(
        "dot11 is materialized by the Dot11 phase 1.5 byte path, not _build_layer"
    )


def _encode_dot11_phase15(plan: PacketPlan, scapy_all: Any) -> bytes:
    """StackEncoder entry point: materialize a Dot11 phase-1.5 stack as raw bytes.

    ``StackEncoder.matches`` is :func:`_is_dot11_phase15_stack`, which receives the
    already-canonical stack from ``encode_packet_plan``. ``encode`` only gets the
    plan, so it re-derives the canonical layer list with :func:`_canonical_stack`
    (the same normalization ``encode_packet_plan`` applied) before running the byte
    driver, so the result is identical to the former in-line ``encode_packet_plan``
    branch.
    """

    return _dot11_phase15_bytes(plan, _canonical_stack(list(plan.stack)), scapy_all)


register(
    ScapyProtocol(
        layer="dot11",
        scapy_class="Dot11",
        supported_fields=_DOT11_SUPPORTED_FIELDS,
        build=_build_dot11,
        normalize=None,
        layer_aliases=_DOT11_LAYER_ALIASES,
    )
)


register_stack_encoder(
    StackEncoder(
        name="dot11_phase15",
        matches=_is_dot11_phase15_stack,
        encode=_encode_dot11_phase15,
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
