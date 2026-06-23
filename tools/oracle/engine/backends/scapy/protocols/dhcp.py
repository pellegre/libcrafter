"""Scapy-stage encode + decode plugin for the DHCP layer.

Moves the ``_dhcp`` (BOOTP / DHCP) builder and its option helpers verbatim out of
:mod:`..packets`, and the per-layer ``_normalize_dhcp_fields`` decoder (the ``dhcp``
branch of ``normalize._normalize_fields``) plus its tightly-coupled option-region
helpers out of :mod:`..normalize`, and registers the ``dhcp`` layer through the
:class:`~.base.ScapyProtocol` contract; only the dispatch moves out of the legacy
``_build_layer`` / ``_normalize_fields`` if/elif. Behavior must stay byte-identical.

The ``_dhcp`` builder materializes a ``BOOTP`` / ``DHCP`` Scapy chain; the layer's
``scapy_class`` mirrors the former ``packets._SCAPY_LAYER_BY_LAYER["dhcp"]`` value
(``"DHCP"``) so the materialized-layer metadata stays unchanged.

DHCP decode has two surfaces. The per-layer field normalizer (the former
``normalize._normalize_dhcp_fields`` dispatched from ``_normalize_fields``) moves here
and is wired up as this plugin's :func:`_normalize` callback, byte-identical to the
legacy ``dhcp`` branch: the four BOOTP IPv4/hardware fields are renamed through the
DHCP field-name map (the lookup order the legacy code applied), the ``flags`` value is
reduced through ``_normalize_dhcp_flags``, ``client_hardware_address`` is trimmed to
the hardware length, the magic-cookie ``options`` artifact is folded into
``magic_cookie``, and the raw option TLV region is decoded into backend-neutral
``{code, payload_hex}`` details. The option-region decode helpers
(``_apply_dhcp_option_details`` / ``_decode_dhcp_option_tlvs``) and the synthetic
option-region key (``_DHCP_OPTION_REGION_KEY``) are also consumed by the whole-packet
``_packet_layers`` capture in :mod:`..normalize`, so — like the IPv6 ext-header
option-region helpers — they are re-imported back there (where the existing
``test_dhcp_oracle.py`` references resolve them through the ``normalize`` module).

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


# Encode-side field allowlist for ``_validate_layer_fields`` — the canonical field
# names plus every Scapy/oracle alias the DHCP builder accepts. Mirrors the former
# ``packets._SUPPORTED_FIELDS_BY_LAYER["dhcp"]`` entry exactly.
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
    return _dhcp(fields, scapy_all)


def _dhcp(fields: Mapping[str, JSONObject], scapy_all: Any) -> Any:
    dhcp_fields = _layer_fields(fields, "dhcp")
    bootp = scapy_all.BOOTP(
        op=_dhcp_op(_required_field(dhcp_fields, "dhcp", "op")),
        htype=_hardware_type_value(_required_field(dhcp_fields, "dhcp", "hardware_type", "htype")),
        hlen=_int(_required_field(dhcp_fields, "dhcp", "hardware_length", "hlen"), 0),
        xid=_int(_optional_field(dhcp_fields, "transaction_id", "xid"), 0),
        flags=_dhcp_flags(_required_field(dhcp_fields, "dhcp", "flags")),
        ciaddr=_text(_optional_field(dhcp_fields, "client_ip", "ciaddr"), "0.0.0.0"),
        yiaddr=_text(_optional_field(dhcp_fields, "your_ip", "yiaddr"), "0.0.0.0"),
        chaddr=_dhcp_chaddr(
            _optional_field(dhcp_fields, "client_hardware_address", "chaddr")
        ),
    )
    return bootp / scapy_all.DHCP(
        options=_dhcp_options(_required_field(dhcp_fields, "dhcp", "options"))
    )


def _dhcp_op(value: object) -> int:
    if isinstance(value, str):
        lowered = value.lower().replace("_", "-")
        if lowered in {"bootrequest", "request"}:
            return 1
        if lowered in {"bootreply", "reply"}:
            return 2
    return _int(value, 1)


def _dhcp_flags(value: object) -> int:
    if isinstance(value, str):
        lowered = value.lower().replace("_", "-")
        if lowered in {"broadcast", "b"}:
            return 0x8000
        if lowered in {"none", "0"}:
            return 0
    return _int(value, 0)


def _dhcp_chaddr(value: object) -> bytes:
    mac = _text(value, "00:00:5e:00:53:01")
    raw = bytes.fromhex(mac.replace(":", ""))
    return raw.ljust(16, b"\x00")


# Scapy DHCP option names differ from the backend-neutral / libcrafter option
# names for several byte-identical options. Mapping the neutral name to the
# Scapy field name lets the same ``name=value`` option string materialize to
# identical option bytes through both backends; an unmapped name passes through
# unchanged so Scapy still recognizes its own native option names.
_DHCP_OPTION_NAME_TO_SCAPY: dict[str, str] = {
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
_DHCP_INTEGER_OPTIONS = frozenset({"lease_time", "renewal_time", "rebinding_time"})


def _dhcp_options(value: object) -> list[object]:
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
                options.append(_dhcp_name_value_option(name, raw_value))
                continue
        if isinstance(item, (list, tuple)) and len(item) == 2 and isinstance(item[0], str):
            options.append((item[0], _dhcp_option_value(item[1])))
            continue
        options.append(item)
    if not options or options[-1] != "end":
        options.append("end")
    return options


def _dhcp_name_value_option(name: str, raw_value: str) -> tuple[str, object]:
    """Translate a ``name=value`` option string into a Scapy option tuple.

    The option name is normalized to the Scapy field name for the byte-safe
    option set so the neutral/libcrafter option names round-trip strict-bytes,
    and integer-valued options are coerced from their JSON string form.
    """

    scapy_name = _DHCP_OPTION_NAME_TO_SCAPY.get(name, name)
    if name in _DHCP_INTEGER_OPTIONS:
        return scapy_name, int(raw_value, 0)
    return scapy_name, raw_value


def _dhcp_option_value(value: object) -> object:
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
_DHCP_OPTION_REGION_KEY = "__option_region_hex__"

# DHCP option codes whose payload is a single message-type octet (option 53), plus
# the single-octet pad (0) / end (255) options.
_DHCP_OPTION_MESSAGE_TYPE = 53
_DHCP_OPTION_PAD = 0
_DHCP_OPTION_END = 255

# Decode-side native-name aliases the DHCP layer owns. ``_LAYER_ALIASES`` maps the
# Scapy class names to the oracle layer name (the former ``normalize._LAYER_ALIASES``
# ``"BOOTP"``/``"DHCP" -> "dhcp"`` entries); ``_FIELD_ALIASES`` records the DHCP
# layer-specific field renames the legacy ``_normalize_field_name("dhcp", ...)``
# consulted (the former ``normalize._LAYER_FIELD_ALIASES["dhcp"]`` entry).
_LAYER_ALIASES = (("BOOTP", "dhcp"), ("DHCP", "dhcp"))
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

# Global cross-layer field aliases the legacy ``_normalize_field_name`` consulted as
# a fallback after the layer-specific map (mirrors ``normalize._FIELD_ALIASES``). No
# native DHCP field name collides with any of these, so carrying the full map is
# harmless and keeps the lookup byte-identical to the legacy generic path.
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

# The richer per-field rename table the former ``_normalize_dhcp_fields`` checked
# first (a superset of ``_FIELD_ALIASES``, adding ``op -> opcode`` and
# ``secs -> seconds``). Mirrors the local ``aliases`` mapping verbatim.
_DHCP_FIELD_NAME_ALIASES: dict[str, str] = {
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

# Effective DHCP field-name map: global aliases overlaid by the DHCP layer-specific
# aliases and then the richer local rename table, exactly the precedence the legacy
# ``aliases.get(native_name, _normalize_field_name("dhcp", native_name))`` applied.
_DHCP_FIELD_NAME_MAP: dict[str, str] = {
    **_GLOBAL_FIELD_ALIASES,
    **dict(_FIELD_ALIASES),
    **_DHCP_FIELD_NAME_ALIASES,
}

# Native DHCP fields the former normalizer dropped before the rename pass.
_DHCP_SKIP_FIELDS = frozenset({"sname", "file", _DHCP_OPTION_REGION_KEY})


def _normalize(fields: JSONObject) -> JSONObject:
    """Normalize a decoded Scapy BOOTP/DHCP layer to the comparable oracle shape.

    Byte-identical to the legacy ``_normalize_dhcp_fields`` path: ``sname`` /
    ``file`` and the synthetic option-region key are dropped, a typed ``options``
    list is reduced to ``option_count``, each remaining native field name is renamed
    via the DHCP field-name map (the lookup order the legacy code applied), and the
    ``flags`` value is reduced through ``_normalize_dhcp_flags``. The
    ``client_hardware_address`` is trimmed to the hardware length, the magic-cookie
    ``options`` artifact is folded into ``magic_cookie``, and the raw option TLV
    region (if captured) is expanded into backend-neutral ``{code, payload_hex}``
    option details.
    """

    option_region_hex = fields.get(_DHCP_OPTION_REGION_KEY)
    output: JSONObject = {}
    for native_name, value in fields.items():
        if native_name in _DHCP_SKIP_FIELDS:
            continue
        if native_name == "options" and isinstance(value, list):
            output["option_count"] = len(value)
            continue
        normalized_name = _DHCP_FIELD_NAME_MAP.get(native_name, native_name)
        output[normalized_name] = _normalize_field_value(normalized_name, value)
    if "client_hardware_address" in output:
        output["client_hardware_address"] = _normalize_dhcp_chaddr(
            output["client_hardware_address"],
            output.get("hardware_length"),
        )
    options = output.get("options")
    if isinstance(options, Mapping) and options.get("hex") == "63825363":
        output["magic_cookie"] = 0x63825363
        output.pop("options", None)
    if isinstance(option_region_hex, str):
        _apply_dhcp_option_details(output, option_region_hex)
    return output


def _normalize_field_value(field_name: str, value: JSONValue) -> JSONValue:
    # Mirror the generic ``normalize._normalize_field_value`` for the DHCP layer:
    # the ``flags`` value is reduced through ``_normalize_dhcp_flags`` and the
    # ``is_response``/``more_fragments`` int-to-bool guards are kept for fidelity
    # (no DHCP field is ``linux_sll`` ``source_address``).
    if field_name == "flags":
        return _normalize_dhcp_flags(value)
    if field_name == "is_response" and isinstance(value, int):
        return bool(value)
    if field_name == "more_fragments" and isinstance(value, int):
        return bool(value)
    return value


def _normalize_dhcp_flags(value: JSONValue) -> JSONValue:
    if value == "B":
        return 0x8000
    if value in {"", "none", "0"}:
        return 0
    return _normalize_flags(value)


def _normalize_dhcp_chaddr(value: JSONValue, hardware_length: JSONValue) -> JSONValue:
    if not isinstance(value, Mapping):
        return value
    hex_value = value.get("hex")
    if not isinstance(hex_value, str):
        return value
    length = hardware_length if isinstance(hardware_length, int) else 6
    return {"hex": hex_value[: length * 2]}


def _apply_dhcp_option_details(output: JSONObject, option_region_hex: str) -> None:
    """Record backend-neutral DHCP option details from the raw TLV region.

    Each option is normalized to a stable ``{code, payload_hex}`` pair carrying
    the raw option payload (no typed reinterpretation), which compares cleanly
    against the libcrafter decoded option view regardless of how either backend
    types the value. The message type (option 53) is also surfaced as an integer
    so option coverage records it directly rather than only as a count.
    """

    options = _decode_dhcp_option_tlvs(option_region_hex)
    if options is None:
        return
    output["options"] = options
    output["option_count"] = len(options)
    for option in options:
        if option["code"] == _DHCP_OPTION_MESSAGE_TYPE:
            payload = bytes.fromhex(option["payload_hex"])
            if len(payload) == 1:
                output["message_type"] = payload[0]
            break


def _decode_dhcp_option_tlvs(option_region_hex: str) -> list[JSONObject] | None:
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
        if code == _DHCP_OPTION_PAD:
            options.append({"code": code, "payload_hex": ""})
            continue
        if code == _DHCP_OPTION_END:
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
        layer="dhcp",
        scapy_class="DHCP",
        supported_fields=_SUPPORTED_FIELDS,
        build=_build,
        normalize=_normalize,
        layer_aliases=_LAYER_ALIASES,
        field_aliases=_FIELD_ALIASES,
    )
)
