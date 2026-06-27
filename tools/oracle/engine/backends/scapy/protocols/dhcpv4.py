"""Scapy-stage encode + decode plugin for the DHCPv4 layer.

The builder materializes a ``BOOTP`` / ``DHCP`` Scapy chain while the oracle layer
name remains ``dhcpv4``. Decode normalizes BOOTP/DHCP fields to the comparable
DHCPv4 model, folds the magic-cookie artifact into ``magic_cookie``, and expands
the raw option TLV region into backend-neutral ``{code, payload_hex}`` details.
The option-region helpers are also imported by :mod:`..normalize` for whole-packet
capture and focused unit tests.

Shared primitives come from the helper modules so this plugin does not depend on the
``packets``/``normalize`` orchestrators (which would create a circular import).
Relative imports only so the package resolves under both the ``engine.*`` (CLI) and
``tools.oracle.engine.*`` (tests) import roots.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ....model import JSONObject, JSONValue
from ..decode_helpers import _normalize_flags
from ..encode_helpers import (
    _hardware_type_value,
    _int,
    _layer_fields,
    _optional_field,
    _required_field,
    _text,
)
from .base import ScapyProtocol, register


# Encode-side field allowlist for ``_validate_layer_fields``: canonical field names
# plus every Scapy/oracle alias the DHCPv4 builder accepts.
_SUPPORTED_FIELDS = frozenset(
    {
        "op",
        "hardware_type",
        "htype",
        "hardware_length",
        "hlen",
        "transaction_id",
        "xid",
        "flags",
        "client_ip",
        "ciaddr",
        "your_ip",
        "yiaddr",
        "client_hardware_address",
        "chaddr",
        "options",
    }
)


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
    return _dhcpv4(fields, scapy_all)


def _dhcpv4(fields: Mapping[str, JSONObject], scapy_all: Any) -> Any:
    dhcpv4_fields = _layer_fields(fields, "dhcpv4")
    bootp = scapy_all.BOOTP(
        op=_dhcpv4_op(_required_field(dhcpv4_fields, "dhcpv4", "op")),
        htype=_hardware_type_value(_required_field(dhcpv4_fields, "dhcpv4", "hardware_type", "htype")),
        hlen=_int(_required_field(dhcpv4_fields, "dhcpv4", "hardware_length", "hlen"), 0),
        xid=_int(_optional_field(dhcpv4_fields, "transaction_id", "xid"), 0),
        flags=_dhcpv4_flags(_required_field(dhcpv4_fields, "dhcpv4", "flags")),
        ciaddr=_text(_optional_field(dhcpv4_fields, "client_ip", "ciaddr"), "0.0.0.0"),
        yiaddr=_text(_optional_field(dhcpv4_fields, "your_ip", "yiaddr"), "0.0.0.0"),
        chaddr=_dhcpv4_chaddr(
            _optional_field(dhcpv4_fields, "client_hardware_address", "chaddr")
        ),
    )
    return bootp / scapy_all.DHCP(
        options=_dhcpv4_options(_required_field(dhcpv4_fields, "dhcpv4", "options"))
    )


def _dhcpv4_op(value: object) -> int:
    if isinstance(value, str):
        lowered = value.lower().replace("_", "-")
        if lowered in {"bootrequest", "request"}:
            return 1
        if lowered in {"bootreply", "reply"}:
            return 2
    return _int(value, 1)


def _dhcpv4_flags(value: object) -> int:
    if isinstance(value, str):
        lowered = value.lower().replace("_", "-")
        if lowered in {"broadcast", "b"}:
            return 0x8000
        if lowered in {"none", "0"}:
            return 0
    return _int(value, 0)


def _dhcpv4_chaddr(value: object) -> bytes:
    mac = _text(value, "00:00:5e:00:53:01")
    raw = bytes.fromhex(mac.replace(":", ""))
    return raw.ljust(16, b"\x00")


# Scapy DHCP option names differ from the backend-neutral / libcrafter option
# names for several byte-identical options. Mapping the neutral name to the
# Scapy field name lets the same ``name=value`` option string materialize to
# identical option bytes through both backends; an unmapped name passes through
# unchanged so Scapy still recognizes its own native option names.
_DHCPV4_OPTION_NAME_TO_SCAPY: dict[str, str] = {
    "message_type": "message-type",
    "host_name": "hostname",
    "domain_name": "domain",
    "requested_ip": "requested_addr",
    "requested_ip_address": "requested_addr",
    "server_identifier": "server_id",
    "dns": "name_server",
    "domain_name_server": "name_server",
}
# Options whose Scapy field is an integer; the generator carries the value as a
# JSON string, so it must be coerced back to int before Scapy serializes it.
_DHCPV4_INTEGER_OPTIONS = frozenset({"lease_time", "renewal_time", "rebinding_time"})


def _dhcpv4_options(value: object) -> list[object]:
    if not isinstance(value, list):
        return [("message-type", "discover"), "end"]
    options: list[object] = []
    for item in value:
        if isinstance(item, str):
            if item in {"end", "pad"}:
                options.append(item)
                continue
            if "=" in item:
                name, raw_value = item.split("=", 1)
                options.append(_dhcpv4_name_value_option(name, raw_value))
                continue
        if isinstance(item, (list, tuple)) and len(item) == 2 and isinstance(item[0], str):
            options.append((item[0], _dhcpv4_option_value(item[1])))
            continue
        options.append(item)
    if not options or options[-1] != "end":
        options.append("end")
    return options


def _dhcpv4_name_value_option(name: str, raw_value: str) -> tuple[str, object]:
    """Translate a ``name=value`` option string into a Scapy option tuple.

    The option name is normalized to the Scapy field name for the byte-safe
    option set so the neutral/libcrafter option names round-trip strict-bytes,
    and integer-valued options are coerced from their JSON string form.
    """

    scapy_name = _DHCPV4_OPTION_NAME_TO_SCAPY.get(name, name)
    if name in _DHCPV4_INTEGER_OPTIONS:
        return scapy_name, int(raw_value, 0)
    return scapy_name, raw_value


def _dhcpv4_option_value(value: object) -> object:
    """Translate a JSON-safe option value into a Scapy option payload.

    A string value is interpreted as raw option bytes encoded as hex so byte
    payloads (client identifiers, raw relay-agent option 82, vendor class data)
    survive JSON transport. List values pass through for Scapy fields that take
    lists, such as the parameter request list and classless static routes.
    """

    if isinstance(value, str):
        return bytes.fromhex(value)
    if isinstance(value, (list, tuple)):
        return list(value)
    return value


# ---------------------------------------------------------------------------
# Decode
# ---------------------------------------------------------------------------


# Synthetic field key carrying the raw DHCP option TLV region (hex) captured from
# the live Scapy DHCP sub-layer by the whole-packet ``_packet_layers`` pass in
# :mod:`..normalize`. Consumed and removed during DHCP field normalization so it
# never leaks into the comparable model. Re-imported back into ``normalize`` (which
# owns the capture) so the key stays a single source of truth.
_DHCPV4_OPTION_REGION_KEY = "__option_region_hex__"

# DHCP option codes whose payload is a single message-type octet (option 53), plus
# the single-octet pad (0) / end (255) options.
_DHCPV4_OPTION_MESSAGE_TYPE = 53
_DHCPV4_OPTION_PAD = 0
_DHCPV4_OPTION_END = 255

# Decode-side native-name aliases the DHCPv4 layer owns. ``_LAYER_ALIASES`` maps
# Scapy class names to the oracle layer name; ``_FIELD_ALIASES`` records the
# layer-specific field renames used by normalization.
_LAYER_ALIASES = (("BOOTP", "dhcpv4"), ("DHCP", "dhcpv4"))
_FIELD_ALIASES = (
    ("ciaddr", "client_ip"),
    ("chaddr", "client_hardware_address"),
    ("giaddr", "relay_ip"),
    ("htype", "hardware_type"),
    ("hlen", "hardware_length"),
    ("siaddr", "server_ip"),
    ("xid", "transaction_id"),
    ("yiaddr", "your_ip"),
)

# Global cross-layer field aliases used as a fallback after the layer-specific map.
# No native DHCPv4 field name collides with any of these, so carrying the full map
# keeps generic normalization behavior consistent across layers.
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

# The richer per-field rename table checked first, adding ``op -> opcode`` and
# ``secs -> seconds`` on top of ``_FIELD_ALIASES``.
_DHCPV4_FIELD_NAME_ALIASES: dict[str, str] = {
    "op": "opcode",
    "htype": "hardware_type",
    "hlen": "hardware_length",
    "xid": "transaction_id",
    "secs": "seconds",
    "ciaddr": "client_ip",
    "yiaddr": "your_ip",
    "siaddr": "server_ip",
    "giaddr": "relay_ip",
    "chaddr": "client_hardware_address",
}

# Effective DHCPv4 field-name map: global aliases overlaid by layer-specific aliases
# and then the richer local rename table.
_DHCPV4_FIELD_NAME_MAP: dict[str, str] = {
    **_GLOBAL_FIELD_ALIASES,
    **dict(_FIELD_ALIASES),
    **_DHCPV4_FIELD_NAME_ALIASES,
}

# Native DHCPv4 fields dropped before the rename pass.
_DHCPV4_SKIP_FIELDS = frozenset({"sname", "file", _DHCPV4_OPTION_REGION_KEY})


def _normalize(fields: JSONObject) -> JSONObject:
    """Normalize a decoded Scapy BOOTP/DHCP layer to the comparable oracle shape.

    ``sname`` / ``file`` and the synthetic option-region key are dropped, a typed
    ``options`` list is reduced to ``option_count``, each remaining native field
    name is renamed via the DHCPv4 field-name map, and the ``flags`` value is
    reduced through ``_normalize_dhcpv4_flags``. The ``client_hardware_address`` is
    trimmed to the hardware length, the magic-cookie ``options`` artifact is folded
    into ``magic_cookie``, and the raw option TLV region (if captured) is expanded
    into backend-neutral ``{code, payload_hex}`` option details.
    """

    option_region_hex = fields.get(_DHCPV4_OPTION_REGION_KEY)
    output: JSONObject = {}
    for native_name, value in fields.items():
        if native_name in _DHCPV4_SKIP_FIELDS:
            continue
        if native_name == "options" and isinstance(value, list):
            output["option_count"] = len(value)
            continue
        normalized_name = _DHCPV4_FIELD_NAME_MAP.get(native_name, native_name)
        output[normalized_name] = _normalize_field_value(normalized_name, value)
    if "client_hardware_address" in output:
        output["client_hardware_address"] = _normalize_dhcpv4_chaddr(
            output["client_hardware_address"],
            output.get("hardware_length"),
        )
    options = output.get("options")
    if isinstance(options, Mapping) and options.get("hex") == "63825363":
        output["magic_cookie"] = 0x63825363
        output.pop("options", None)
    if isinstance(option_region_hex, str):
        _apply_dhcpv4_option_details(output, option_region_hex)
    return output


def _normalize_field_value(field_name: str, value: JSONValue) -> JSONValue:
    # Mirror the generic ``normalize._normalize_field_value`` for the DHCP layer:
    # the ``flags`` value is reduced through ``_normalize_dhcpv4_flags`` and the
    # ``is_response``/``more_fragments`` int-to-bool guards are kept for fidelity
    # (no DHCP field is ``linux_sll`` ``source_address``).
    if field_name == "flags":
        return _normalize_dhcpv4_flags(value)
    if field_name == "is_response" and isinstance(value, int):
        return bool(value)
    if field_name == "more_fragments" and isinstance(value, int):
        return bool(value)
    return value


def _normalize_dhcpv4_flags(value: JSONValue) -> JSONValue:
    if value == "B":
        return 0x8000
    if value in {"", "none", "0"}:
        return 0
    return _normalize_flags(value)


def _normalize_dhcpv4_chaddr(value: JSONValue, hardware_length: JSONValue) -> JSONValue:
    if not isinstance(value, Mapping):
        return value
    hex_value = value.get("hex")
    if not isinstance(hex_value, str):
        return value
    length = hardware_length if isinstance(hardware_length, int) else 6
    return {"hex": hex_value[: length * 2]}


def _apply_dhcpv4_option_details(output: JSONObject, option_region_hex: str) -> None:
    """Record backend-neutral DHCP option details from the raw TLV region.

    Each option is normalized to a stable ``{code, payload_hex}`` pair carrying
    the raw option payload (no typed reinterpretation), which compares cleanly
    against the libcrafter decoded option view regardless of how either backend
    types the value. The message type (option 53) is also surfaced as an integer
    so option coverage records it directly rather than only as a count.
    """

    options = _decode_dhcpv4_option_tlvs(option_region_hex)
    if options is None:
        return
    output["options"] = options
    output["option_count"] = len(options)
    for option in options:
        if option["code"] == _DHCPV4_OPTION_MESSAGE_TYPE:
            payload = bytes.fromhex(option["payload_hex"])
            if len(payload) == 1:
                output["message_type"] = payload[0]
            break


def _decode_dhcpv4_option_tlvs(option_region_hex: str) -> list[JSONObject] | None:
    """Parse a DHCP option TLV region into ``{code, payload_hex}`` entries.

    Pad (0) and end (255) are single-octet options with empty payloads. A
    truncated or malformed region returns ``None`` so the raw typed option list
    handling is preserved instead of emitting partial option details.
    """

    try:
        raw = bytes.fromhex(option_region_hex)
    except ValueError:
        return None
    options: list[JSONObject] = []
    index = 0
    length = len(raw)
    while index < length:
        code = raw[index]
        index += 1
        if code == _DHCPV4_OPTION_PAD:
            options.append({"code": code, "payload_hex": ""})
            continue
        if code == _DHCPV4_OPTION_END:
            options.append({"code": code, "payload_hex": ""})
            break
        if index >= length:
            return None
        option_length = raw[index]
        index += 1
        if index + option_length > length:
            return None
        payload = raw[index : index + option_length]
        index += option_length
        options.append({"code": code, "payload_hex": payload.hex()})
    return options


register(
    ScapyProtocol(
        layer="dhcpv4",
        scapy_class="DHCP",
        supported_fields=_SUPPORTED_FIELDS,
        build=_build,
        normalize=_normalize,
        layer_aliases=_LAYER_ALIASES,
        field_aliases=_FIELD_ALIASES,
    )
)
