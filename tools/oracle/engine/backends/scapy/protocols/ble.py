"""Scapy-stage encode plugin for the BLE advertising stack (``ble_radio`` / ``ble_adv``).

BLE is the last protocol migration. Like the Dot11 phase-1.5 path, BLE bypasses the
per-layer ``_build_layer`` dispatch entirely: ``encode_packet_plan`` produces the
whole stack as deterministic wire bytes through :func:`_ble_bytes`, which builds the
BLE pcap pseudo-header plus the advertising LL packet (with a deterministic fallback
whenever Scapy's ``bluetooth4LE`` layers are unavailable or disagree). This module is
the home for that whole-stack byte driver, its helpers, and the ``_BLE_*`` codepoint
maps / ``_BLE_LAYERS`` set, moved verbatim from :mod:`packets` so behavior stays
byte-identical.

The stack predicate :func:`_is_ble_stack` and the byte driver :func:`_ble_bytes` are
registered through the :class:`~.base.StackEncoder` contract; :func:`packets.encode_packet_plan`
consults :data:`~.base.STACK_ENCODER_REGISTRY` before its legacy whole-stack branches,
so the BLE path resolves through the registry. ``_ble_bytes`` returns ``(bytes,
metadata)`` because the BLE materialization metadata (native-Scapy support, fallback
reason, scapy version) is reported on the encoded vector; ``encode_packet_plan`` calls
``_ble_bytes`` directly for the BLE-named encoder so it keeps that metadata while still
selecting the path through the registry.

Both BLE layers also register a per-layer :class:`~.base.ScapyProtocol` so the encoder
resolves their ``scapy_class`` (``BTLE_PHDR`` / ``BTLE_ADV_IND``) — which drives the
``scapy_stack`` metadata and ``_is_materialized_layer`` — and the encode-side field
allowlists from the registry instead of the legacy ``packets._SCAPY_LAYER_BY_LAYER`` /
``_SUPPORTED_FIELDS_BY_LAYER`` tables. Neither layer is built through ``_build_layer``
(they are materialized by the whole-stack byte path), so each ``build`` raises if
called. BLE has no per-layer Scapy ``normalize`` hook (its decode stays on the
whole-stack byte-level ``normalize._decode_ble_bytes`` path) and no Wireshark module.

Shared primitives come from :mod:`..encode_helpers` so this plugin does not depend on
the ``packets`` orchestrator (which would create a circular import). Relative imports
only so the package resolves under both the ``engine.*`` (CLI) and
``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from ....model import JSONObject, PacketPlan
from ..encode_helpers import (
    _bytes_exact,
    _bytes_optional,
    _int,
    _layer_fields,
    _optional_field,
    _string,
    _text,
)
from .base import ScapyProtocol, StackEncoder, register, register_stack_encoder


# Encode-side field allowlists for ``_validate_layer_fields`` — mirror the former
# ``packets._SUPPORTED_FIELDS_BY_LAYER["ble_radio"]`` / ``["ble_adv"]`` entries exactly.
_BLE_RADIO_SUPPORTED_FIELDS = frozenset(
    {
        "access_address",
        "access_address_offenses",
        "channel",
        "crc_init",
        "flags",
        "noise_power",
        "ref_access_address",
        "reference_access_address",
        "rf_channel",
        "signal_power",
    }
)
_BLE_ADV_SUPPORTED_FIELDS = frozenset(
    {
        "ad",
        "ad_list",
        "adv_a",
        "adva",
        "channel_selection",
        "chsel",
        "length",
        "pdu_type",
        "rfu",
        "rx_add",
        "rxaddr",
        "tx_add",
        "txaddr",
    }
)


_BLE_LAYERS = frozenset({"ble_radio", "ble_adv"})
_BLE_ADV_PDU_TYPES: dict[str, int] = {
    "adv_ind": 0,
    "adv_direct_ind": 1,
    "adv_nonconn_ind": 2,
    "scan_req": 3,
    "scan_rsp": 4,
    "connect_ind": 5,
    "adv_scan_ind": 6,
    "adv_ext_ind": 7,
}
_BLE_ADV_PDU_TYPE_NAMES = {value: key for key, value in _BLE_ADV_PDU_TYPES.items()}
_BLE_AD_TYPES: dict[str, int] = {
    "flags": 0x01,
    "shortened_local_name": 0x08,
    "shortened_name": 0x08,
    "complete_local_name": 0x09,
    "local_name": 0x09,
    "name": 0x09,
}
_BLE_PHDR_FLAG_BITS: dict[str, int] = {
    "dewhitened": 0x0001,
    "signal_power_valid": 0x0002,
    "noise_power_valid": 0x0004,
    "decrypted": 0x0008,
    "reference_access_address_valid": 0x0010,
    "ref_access_address_valid": 0x0010,
    "access_address_offenses_valid": 0x0020,
    "rf_channel_aliased": 0x0040,
    "crc_checked": 0x0400,
    "crc_valid": 0x0800,
    "mic_checked": 0x1000,
    "mic_valid": 0x2000,
}
_BLE_ADV_FLAG_BITS: dict[str, int] = {
    "limited_disc_mode": 0x01,
    "le_limited_discoverable_mode": 0x01,
    "general_disc_mode": 0x02,
    "le_general_discoverable_mode": 0x02,
    "br_edr_not_supported": 0x04,
    "simultaneous_le_br_edr_controller": 0x08,
    "simultaneous_le_br_edr_host": 0x10,
}


def _is_ble_stack(stack: Sequence[str]) -> bool:
    return any(layer in _BLE_LAYERS for layer in stack)


def _ble_bytes(plan: PacketPlan, stack: list[str]) -> tuple[bytes, JSONObject]:
    if stack != ["ble_radio", "ble_adv"]:
        joined = ", ".join(stack)
        raise ValueError(f"unsupported BLE materialization stack: {joined}")

    radio = _layer_fields(plan.fields, "ble_radio")
    adv = _layer_fields(plan.fields, "ble_adv")
    pdu_type = _ble_adv_pdu_type(adv.get("pdu_type"))
    tx_add = _ble_address_type_bit(_optional_field(adv, "tx_add", "txaddr"), 0)
    rx_add = _ble_address_type_bit(_optional_field(adv, "rx_add", "rxaddr"), 0)
    channel_selection = 1 if bool(_optional_field(adv, "channel_selection", "chsel")) else 0
    rfu = _int(adv.get("rfu"), 0) & 0x01
    adv_a_wire = _ble_address_wire(_optional_field(adv, "adv_a", "adva"))
    adv_a = _ble_address_text(adv_a_wire)
    ad_items = _ble_ad_items(_optional_field(adv, "ad_list", "ad"))
    adv_data = b"".join(data for _code, data in ad_items)
    payload = adv_a_wire + adv_data
    length = _int(adv.get("length"), len(payload)) & 0xFF
    header0 = (
        (pdu_type & 0x0F)
        | ((rfu & 0x01) << 4)
        | ((channel_selection & 0x01) << 5)
        | ((tx_add & 0x01) << 6)
        | ((rx_add & 0x01) << 7)
    )
    pdu = bytes([header0, length]) + payload
    access_address = _ble_access_address(radio.get("access_address"))
    crc_init = _ble_crc_init(radio.get("crc_init"))
    fallback_ll_packet = (
        access_address.to_bytes(4, "little")
        + pdu
        + _ble_crc(pdu, init=crc_init)
    )
    native_ll_packet, native_metadata = _ble_native_adv_ll_packet_bytes(
        access_address=access_address,
        pdu_type=pdu_type,
        tx_add=tx_add,
        rx_add=rx_add,
        channel_selection=channel_selection,
        rfu=rfu,
        length=length,
        adv_a=adv_a,
        ad_items=ad_items,
    )

    materialization = "deterministic_wire_bytes"
    ll_packet = fallback_ll_packet
    if native_ll_packet == fallback_ll_packet:
        materialization = "scapy_btle_layers"
        ll_packet = native_ll_packet
    elif native_ll_packet is not None:
        native_metadata["fallback_reason"] = "native_scapy_btle_bytes_mismatch"

    pseudoheader = _ble_pseudoheader_bytes(radio, default_access_address=access_address)
    metadata: JSONObject = {
        "native_scapy_support": native_ll_packet is not None,
        "materialization": materialization,
        "scapy_version": _string(native_metadata.get("scapy_version"), "not-required"),
    }
    fallback_reason = native_metadata.get("fallback_reason")
    if isinstance(fallback_reason, str):
        metadata["fallback_reason"] = fallback_reason
    return pseudoheader + ll_packet, metadata


def _ble_native_adv_ll_packet_bytes(
    *,
    access_address: int,
    pdu_type: int,
    tx_add: int,
    rx_add: int,
    channel_selection: int,
    rfu: int,
    length: int,
    adv_a: str,
    ad_items: Sequence[tuple[int, bytes]],
) -> tuple[bytes | None, JSONObject]:
    metadata: JSONObject = {"scapy_version": "not-required"}
    if pdu_type != 0:
        metadata["fallback_reason"] = "native_scapy_supports_only_adv_ind"
        return None, metadata
    try:
        import scapy  # type: ignore[import-untyped]
        import scapy.all as scapy_all  # type: ignore[import-untyped]
        from scapy.layers.bluetooth import (  # type: ignore[import-untyped]
            EIR_CompleteLocalName,
            EIR_Flags,
            EIR_Hdr,
        )
        from scapy.layers.bluetooth4LE import (  # type: ignore[import-untyped]
            BTLE,
            BTLE_ADV,
            BTLE_ADV_IND,
        )
    except Exception as exc:
        metadata["fallback_reason"] = f"scapy_btle_layers_unavailable: {type(exc).__name__}"
        return None, metadata

    metadata["scapy_version"] = _string(getattr(scapy, "__version__", "unknown"), "unknown")
    eir_packets: list[Any] = []
    for code, encoded in ad_items:
        raw = encoded[2:] if len(encoded) >= 2 else b""
        if code == 0x01:
            eir_packets.append(EIR_Hdr(len=len(raw) + 1, type=code) / EIR_Flags(flags=raw[0] if raw else 0))
        elif code == 0x09:
            eir_packets.append(EIR_Hdr(len=len(raw) + 1, type=code) / EIR_CompleteLocalName(local_name=raw))
        else:
            metadata["fallback_reason"] = f"native_scapy_eir_type_unsupported: {code}"
            return None, metadata

    try:
        packet = (
            BTLE(access_addr=access_address)
            / BTLE_ADV(
                PDU_type=pdu_type,
                TxAdd=tx_add,
                RxAdd=rx_add,
                ChSel=channel_selection,
                RFU=rfu,
                Length=length,
            )
            / BTLE_ADV_IND(AdvA=adv_a, data=eir_packets)
        )
        return bytes(scapy_all.raw(packet)), metadata
    except Exception as exc:  # pragma: no cover - Scapy exception types vary.
        metadata["fallback_reason"] = f"native_scapy_btle_build_failed: {type(exc).__name__}"
        return None, metadata


def _ble_pseudoheader_bytes(
    radio: Mapping[str, object],
    *,
    default_access_address: int,
) -> bytes:
    flags = _ble_phdr_flags(radio)
    signal_power = _signed_byte(_optional_field(radio, "signal_power"), 0)
    noise_power = _signed_byte(_optional_field(radio, "noise_power"), 0)
    offenses = _int(radio.get("access_address_offenses"), 0) & 0xFF
    ref_access_address = _ble_access_address(
        _optional_field(radio, "ref_access_address", "reference_access_address"),
        default=default_access_address,
    )
    return (
        bytes([_int(radio.get("rf_channel", radio.get("channel")), 37) & 0xFF])
        + signal_power
        + noise_power
        + bytes([offenses])
        + ref_access_address.to_bytes(4, "little")
        + flags.to_bytes(2, "little")
    )


def _ble_phdr_flags(radio: Mapping[str, object]) -> int:
    raw_flags = radio.get("flags")
    if raw_flags is None:
        flags = (
            _BLE_PHDR_FLAG_BITS["dewhitened"]
            | _BLE_PHDR_FLAG_BITS["reference_access_address_valid"]
            | _BLE_PHDR_FLAG_BITS["crc_checked"]
            | _BLE_PHDR_FLAG_BITS["crc_valid"]
        )
    else:
        flags = _ble_flag_value(raw_flags, _BLE_PHDR_FLAG_BITS, default=0)
    if "signal_power" in radio:
        flags |= _BLE_PHDR_FLAG_BITS["signal_power_valid"]
    if "noise_power" in radio:
        flags |= _BLE_PHDR_FLAG_BITS["noise_power_valid"]
    if "access_address_offenses" in radio:
        flags |= _BLE_PHDR_FLAG_BITS["access_address_offenses_valid"]
    return flags & 0xFFFF


def _ble_ad_items(value: object) -> list[tuple[int, bytes]]:
    if value is None:
        return []
    if isinstance(value, Mapping):
        value = [value]
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError("BLE advertising data requires an AD structure list")

    output: list[tuple[int, bytes]] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise ValueError(f"BLE AD structure must be an object, got {item!r}")
        code = _ble_ad_type_code(_optional_field(item, "type_code", "ad_type", "type"))
        data = _ble_ad_data(code, item)
        if len(data) > 254:
            raise ValueError("BLE AD structure data exceeds 254 octets")
        output.append((code, bytes([len(data) + 1, code]) + data))
    return output


def _ble_ad_data(code: int, item: Mapping[str, object]) -> bytes:
    raw = _optional_field(item, "data_hex", "hex", "bytes")
    if raw is not None:
        return _bytes_optional(raw)
    if code == 0x01:
        return bytes([_ble_flag_value(_optional_field(item, "value", "flags"), _BLE_ADV_FLAG_BITS, default=0x06)])
    if code in {0x08, 0x09}:
        value = _optional_field(item, "value", "name", "local_name", "text")
        return _text(value, "").encode("utf-8")
    value = item.get("value")
    if value is None:
        return b""
    return _bytes_optional(value)


def _ble_ad_type_code(value: object) -> int:
    if isinstance(value, str):
        normalized = value.lower().replace("-", "_").replace(" ", "_")
        if normalized in _BLE_AD_TYPES:
            return _BLE_AD_TYPES[normalized]
        return int(normalized, 0)
    return _int(value, 0)


def _ble_adv_pdu_type(value: object) -> int:
    if isinstance(value, str):
        normalized = value.lower().replace("-", "_").replace(" ", "_")
        if normalized in _BLE_ADV_PDU_TYPES:
            return _BLE_ADV_PDU_TYPES[normalized]
        return int(normalized, 0)
    return _int(value, 0)


def _ble_address_type_bit(value: object, default: int) -> int:
    if value is None:
        return default
    if isinstance(value, str):
        normalized = value.lower().replace("-", "_").replace(" ", "_")
        if normalized == "public":
            return 0
        if normalized == "random":
            return 1
    return 1 if bool(_int(value, default)) else 0


def _ble_access_address(value: object, *, default: int = 0x8E89BED6) -> int:
    return _int(value, default) & 0xFFFF_FFFF


def _ble_crc_init(value: object) -> int:
    return _int(value, 0x555555) & 0xFF_FFFF


def _ble_flag_value(value: object, mapping: Mapping[str, int], *, default: int) -> int:
    if value is None:
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        normalized = value.lower().replace("-", "_").replace(" ", "_")
        if normalized in mapping:
            return mapping[normalized]
        if "|" in normalized or "," in normalized:
            flags = 0
            for token in normalized.replace(",", "|").split("|"):
                token = token.strip()
                if token:
                    flags |= mapping.get(token, int(token, 0) if token[:1].isdigit() else 0)
            return flags
        return int(normalized, 0)
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        flags = 0
        for item in value:
            flags |= _ble_flag_value(item, mapping, default=0)
        return flags
    raise ValueError(f"expected BLE flag-compatible value, got {value!r}")


def _ble_address_wire(value: object) -> bytes:
    if value is None:
        value = "a1:a2:a3:a4:a5:a6"
    if isinstance(value, str) and ":" in value:
        parts = value.split(":")
        if len(parts) != 6:
            raise ValueError(f"BLE address requires six octets, got {value!r}")
        return bytes(int(part, 16) for part in reversed(parts))
    return _bytes_exact(value, 6)


def _ble_address_text(wire: bytes) -> str:
    return ":".join(f"{octet:02x}" for octet in reversed(wire[:6]))


def _signed_byte(value: object, default: int) -> bytes:
    number = _int(value, default)
    if not -128 <= number <= 127:
        raise ValueError(f"expected signed byte value, got {number}")
    return int(number).to_bytes(1, "little", signed=True)


def _ble_crc(pdu: bytes, *, init: int) -> bytes:
    state = (
        _ble_swap_bits(init & 0xFF)
        | (_ble_swap_bits((init >> 8) & 0xFF) << 8)
        | (_ble_swap_bits((init >> 16) & 0xFF) << 16)
    )
    lfsr_mask = 0x5A6000
    for byte in pdu:
        current = byte
        for _bit in range(8):
            next_bit = (state ^ current) & 0x01
            current >>= 1
            state >>= 1
            if next_bit:
                state |= 1 << 23
                state ^= lfsr_mask
    return state.to_bytes(4, "little")[:3]


def _ble_swap_bits(value: int) -> int:
    output = 0
    for bit in range(8):
        if value & (1 << bit):
            output |= 1 << (7 - bit)
    return output


def _build_ble(
    plan: Any,
    fields: Mapping[str, JSONObject],
    stack: Any,
    index: int,
    scapy_all: Any,
) -> Any:
    """BLE is encoded by the whole-stack raw-bytes path, never by ``_build_layer``."""

    raise ValueError(
        "BLE layers are materialized by the whole-stack byte path, not _build_layer"
    )


def _encode_ble(plan: PacketPlan, scapy_all: Any) -> bytes:
    """StackEncoder entry point: materialize a BLE advertising stack as raw bytes.

    The BLE-specific materialization metadata (native-Scapy support, fallback reason,
    scapy version) is reported on the encoded vector, so ``encode_packet_plan`` calls
    :func:`_ble_bytes` directly for the BLE-named encoder to keep that metadata. This
    entry point exists for the :class:`StackEncoder` contract and returns only the
    bytes (the same ``raw_bytes`` half of the tuple).
    """

    raw_bytes, _metadata = _ble_bytes(plan, list(plan.stack))
    return raw_bytes


register(
    ScapyProtocol(
        layer="ble_radio",
        scapy_class="BTLE_PHDR",
        supported_fields=_BLE_RADIO_SUPPORTED_FIELDS,
        build=_build_ble,
        normalize=None,
    )
)


register(
    ScapyProtocol(
        layer="ble_adv",
        scapy_class="BTLE_ADV_IND",
        supported_fields=_BLE_ADV_SUPPORTED_FIELDS,
        build=_build_ble,
        normalize=None,
    )
)


register_stack_encoder(
    StackEncoder(
        name="ble_advertising",
        matches=_is_ble_stack,
        encode=_encode_ble,
    )
)
