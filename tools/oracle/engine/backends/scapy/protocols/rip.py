"""Scapy-stage encode plugin for the RIP layer.

Moves the ``_rip`` builder and its ``_rip_command`` / ``_rip_entries`` /
``_rip_entry`` / ``_rip_auth`` / ``_rip_password_bytes`` helpers, plus the
``_RIP_COMMANDS`` command map and the ``_RIP_AFI_IP`` / ``_RIP_AFI_AUTH``
address-family constants, verbatim out of :mod:`..packets` and registers them
through the :class:`~.base.ScapyProtocol` contract; only the dispatch moves out of
the legacy if/elif. Behavior must stay byte-identical.

Scapy ships a native RIP layer (``scapy.layers.rip``): ``RIP`` carries the 4-octet
header (cmd/version/null), ``RIPEntry`` carries a 20-octet route entry, and
``RIPAuth`` carries the AFI 0xFFFF authentication entry. The builder seeds the
header scalars and chains one ``RIPEntry`` / ``RIPAuth`` per planned entry, exactly
as before.

RIP decode is special: Scapy dissects a RIP message into a ``RIP`` header layer
followed by standalone ``RIPEntry`` / ``RIPAuth`` payload layers, which the
whole-packet ``_canonicalize_rip`` pass in :mod:`..normalize` collapses back into
libcrafter's single ``rip`` layer. That pass operates on the assembled packet
rather than a single decoded layer, so — following the step-22/24/25/26 precedent
for whole-packet canonicalizers — it stays in :mod:`..normalize` and is not moved
here. The per-layer ``rip`` decode uses only the generic alias path (no RIP entries
ever lived in ``normalize._LAYER_ALIASES`` / ``_FIELD_ALIASES`` / ``_LAYER_FIELD_
ALIASES``, and ``RIP`` resolves to ``rip`` through the generic ``.lower()`` fallback),
so this plugin registers no ``normalize`` hook and no decode aliases.

``_rip_command`` is re-imported into :mod:`..packets` because the still-resident
RIPng builder (``_ripng``) shares it; RIPng migrates in its own later step.

Shared primitives come from the helper modules so this plugin does not depend on the
``packets`` orchestrator (which would create a circular import). ``import_scapy``
(for the Scapy RIP layer) comes from :mod:`..bootstrap`. Relative imports only so the
package resolves under both the ``engine.*`` (CLI) and ``tools.oracle.engine.*``
(tests) import roots.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from ....model import JSONObject
from ..bootstrap import import_scapy
from ..encode_helpers import (
    _bytes_field,
    _int,
    _layer_fields,
    _optional_field,
    _required_field,
    _text,
)
from .base import ScapyProtocol, register


# Encode-side field allowlist for ``_validate_layer_fields`` — mirrors the former
# ``packets._SUPPORTED_FIELDS_BY_LAYER["rip"]`` entry exactly. RIP header fields
# mirror the libcrafter accessor names; per-entry fields live under the "entries"
# list, and the AFI 0xFFFF authentication entry lives under "auth".
_SUPPORTED_FIELDS = frozenset(
    {
        "command",
        "version",
        "reserved",
        "entries",
        "auth",
    }
)

# Named RIP command codes (RFC 1058 / RFC 2453 / RFC 2091) for plans that carry
# a symbolic command instead of a numeric one. Mirrors the former
# ``packets._RIP_COMMANDS`` map.
_RIP_COMMANDS: dict[str, int] = {
    "request": 1,
    "response": 2,
    "traceon": 3,
    "traceoff": 4,
    "sun": 5,
    "update-request": 9,
    "update_request": 9,
    "update-response": 10,
    "update_response": 10,
    "update-ack": 11,
    "update_acknowledge": 11,
    "update_ack": 11,
}
_RIP_AFI_IP = 2
_RIP_AFI_AUTH = 0xFFFF


def _build(
    plan: Any,
    fields: Mapping[str, JSONObject],
    stack: Any,
    index: int,
    scapy_all: Any,
) -> Any:
    return _rip(fields, scapy_all)


def _rip(fields: Mapping[str, JSONObject], scapy_all: Any) -> Any:
    scapy_rip = import_scapy()["rip"]
    rip_fields = _layer_fields(fields, "rip")
    rip = scapy_rip.RIP(
        cmd=_rip_command(_required_field(rip_fields, "rip", "command", "cmd")),
        version=_int(_optional_field(rip_fields, "version"), 2),
        null=_int(_optional_field(rip_fields, "reserved", "null"), 0),
    )

    packet = rip
    auth = _optional_field(rip_fields, "auth")
    if auth is not None:
        packet = packet / _rip_auth(auth, scapy_rip)
    for entry in _rip_entries(rip_fields):
        packet = packet / _rip_entry(entry, scapy_rip)
    return packet


def _rip_command(value: object) -> int:
    if isinstance(value, str):
        normalized = value.lower().replace(" ", "-")
        if normalized in _RIP_COMMANDS:
            return _RIP_COMMANDS[normalized]
        return int(normalized, 0)
    return _int(value, 0)


def _rip_entries(rip_fields: Mapping[str, object]) -> list[Mapping[str, object]]:
    entries = rip_fields.get("entries")
    if entries is None:
        return []
    if not isinstance(entries, Sequence) or isinstance(entries, (str, bytes, bytearray)):
        raise ValueError("RIP entries materialization requires an entry list")
    result: list[Mapping[str, object]] = []
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise ValueError(f"RIP entry must be an object, got {entry!r}")
        result.append(entry)
    return result


def _rip_entry(entry: Mapping[str, object], scapy_rip: Any) -> Any:
    return scapy_rip.RIPEntry(
        AF=_int(_optional_field(entry, "address_family", "af"), _RIP_AFI_IP),
        RouteTag=_int(_optional_field(entry, "route_tag", "tag", "routetag"), 0),
        addr=_text(_optional_field(entry, "address", "addr"), "0.0.0.0"),
        mask=_text(_optional_field(entry, "subnet_mask", "mask"), "0.0.0.0"),
        nextHop=_text(_optional_field(entry, "next_hop", "nexthop"), "0.0.0.0"),
        metric=_int(_optional_field(entry, "metric"), 0),
    )


def _rip_auth(auth: object, scapy_rip: Any) -> Any:
    if not isinstance(auth, Mapping):
        raise ValueError(f"RIP auth entry must be an object, got {auth!r}")
    auth_type = _int(_optional_field(auth, "type", "authtype", "auth_type"), 2)
    if auth_type == 2:
        # Simple password (RFC 2453 §4.1): up to 16 octets of cleartext password
        # carried in the AFI 0xFFFF entry.
        password = _rip_password_bytes(
            _optional_field(auth, "simple_password", "password", "secret")
        )
        return scapy_rip.RIPAuth(authtype=2, password=password)
    # Keyed message digest (RFC 2082 / RFC 4822): the AFI 0xFFFF leading entry
    # is a digest header. Scapy's RIPAuth carries the digest-header region; the
    # pinned key id / sequence map onto the header fields.
    kwargs: dict[str, Any] = {"authtype": auth_type}
    if _optional_field(auth, "digest_offset", "digestoffset") is not None:
        kwargs["digestoffset"] = _int(
            _optional_field(auth, "digest_offset", "digestoffset"), 0
        )
    if _optional_field(auth, "key_id", "keyid") is not None:
        kwargs["keyid"] = _int(_optional_field(auth, "key_id", "keyid"), 0)
    if _optional_field(auth, "auth_data_len", "authdatalen") is not None:
        kwargs["authdatalen"] = _int(
            _optional_field(auth, "auth_data_len", "authdatalen"), 0
        )
    if _optional_field(auth, "sequence", "seqnum") is not None:
        kwargs["seqnum"] = _int(_optional_field(auth, "sequence", "seqnum"), 0)
    return scapy_rip.RIPAuth(**kwargs)


def _rip_password_bytes(value: object) -> bytes:
    if value is None:
        return b"\x00" * 16
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, Mapping):
        raw = _bytes_field(value)
    elif isinstance(value, str):
        raw = value.encode("utf-8")
    else:
        raise ValueError(f"RIP simple password must be bytes or str, got {value!r}")
    return (raw + b"\x00" * 16)[:16]


register(
    ScapyProtocol(
        # ``scapy_class`` mirrors the former ``packets._SCAPY_LAYER_BY_LAYER["rip"]``
        # value (``"RIP"``, the native Scapy RIP header class), which drives
        # ``_scapy_layer_name`` and the ``scapy_stack`` encode metadata.
        layer="rip",
        scapy_class="RIP",
        supported_fields=_SUPPORTED_FIELDS,
        build=_build,
        # RIP decode uses the generic alias path plus the whole-packet
        # ``_canonicalize_rip`` pass in ``normalize``; no per-layer hook or aliases.
        normalize=None,
    )
)
