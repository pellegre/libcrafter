"""Shared, protocol-agnostic Wireshark/tshark decode helpers.

These primitives are reused by every per-protocol ``_normalize_<l>`` decoder.
They live here (rather than in ``normalize.py``) so per-protocol decoder plugins
can import them without depending on the parser-only orchestrator, avoiding a
circular import. This module must not import from ``normalize.py``.
"""

from __future__ import annotations

from ...model import JSONObject


_ROOT_ALIASES: dict[str, str] = {
    "Dot11": "link:dot11",
    "Ether": "link:ethernet",
    "IP": "l3:ipv4",
    "IPv6": "l3:ipv6",
    "RadioTap": "link:radiotap",
    "Raw": "link:raw",
    "link:ieee80211": "link:dot11",
    "link:linux-sll": "link:linux-cooked",
}


def _fields_from_aliases(layer: JSONObject, aliases: dict[str, tuple[str, ...]]) -> JSONObject:
    output: JSONObject = {}
    for target, field_names in aliases.items():
        value = _field(layer, *field_names)
        if value is not None:
            output[target] = value
    return output


def _parse_int_fields(output: JSONObject, *names: str) -> None:
    for name in names:
        value = output.get(name)
        parsed = _parse_int(value)
        if parsed is not None:
            output[name] = parsed


def _field(layer: JSONObject, *names: str) -> object | None:
    for name in names:
        value = layer.get(name)
        if value is None:
            continue
        return _scalar_value(value)
    return None


def _field_list(layer: JSONObject, *names: str) -> list[object]:
    for name in names:
        value = layer.get(name)
        if value is None:
            continue
        if isinstance(value, list):
            return [_scalar_value(item) for item in value if _scalar_value(item) is not None]
        scalar = _scalar_value(value)
        return [] if scalar is None else [scalar]
    return []


def _string_field(layer: JSONObject, *names: str) -> str | None:
    value = _field(layer, *names)
    if value is None:
        return None
    return str(value)


def _scalar_value(value: object) -> object:
    if isinstance(value, list):
        if not value:
            return None
        return _scalar_value(value[0])
    if isinstance(value, dict):
        show = value.get("show")
        if show is not None:
            return _scalar_value(show)
        value_value = value.get("value")
        if value_value is not None:
            return _scalar_value(value_value)
        return value
    return value


def _parse_int(value: object) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate:
        return None
    if " " in candidate:
        candidate = candidate.split(" ", 1)[0]
    try:
        return int(candidate, 0)
    except ValueError:
        return None


def _normalize_root_name(root: str | None) -> str | None:
    if root is None:
        return None
    return _ROOT_ALIASES.get(root, root)


def _layer(layers: JSONObject, name: str) -> JSONObject:
    value = layers.get(name)
    return value if isinstance(value, dict) else {}


def _layer_any(layers: JSONObject, *names: str) -> JSONObject:
    for name in names:
        value = layers.get(name)
        if isinstance(value, dict):
            return value
    return {}


def _hex_bytes(value: str) -> str:
    return "".join(char for char in value.lower() if char in "0123456789abcdef")


def _truthy_field(layer: JSONObject, name: str) -> bool:
    value = _field(layer, name)
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        return value not in {"", "0", "0x0", "False", "false"}
    return False
