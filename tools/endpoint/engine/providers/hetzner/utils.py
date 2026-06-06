"""Shared Hetzner provider parsing and naming helpers."""

from __future__ import annotations

import secrets
from collections.abc import Mapping
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from pathlib import Path

from ...process import CommandResult
from ...ssh import create_key_pair
from .constants import HCLOUD_TOKEN_ENV, TOKEN_ENV



def _path_component(value: str) -> str:
    output = "".join(character if character.isalnum() else "-" for character in value.lower())
    output = "-".join(part for part in output.split("-") if part)
    return output or "value"


def _hetzner_token(environ: Mapping[str, str]) -> str | None:
    return environ.get(TOKEN_ENV) or environ.get(HCLOUD_TOKEN_ENV) or None


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _real_endpoint_id(*, provider: str, exposure: str, role: str) -> str:
    timestamp = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
    suffix = secrets.token_hex(3)
    return "-".join(
        _path_component(part) for part in (provider, exposure, role, timestamp, suffix)
    )


def _server_name(endpoint_id: str) -> str:
    name = f"wire-{endpoint_id}"
    if len(name) <= 63:
        return name
    return name[:63].rstrip("-") or "wire-endpoint"


def _label_value(value: str) -> str:
    output = "".join(character if character.isalnum() else "-" for character in value.lower())
    output = "-".join(part for part in output.split("-") if part)
    return (output or "value")[:63].rstrip("-") or "value"


def _env_or_default(environ: Mapping[str, str], name: str, default: str) -> str:
    value = environ.get(name)
    if value is None or value == "":
        return default
    return value


def _ensure_endpoint_key(private_key_path: Path, endpoint_id: str) -> None:
    public_key_path = _public_key_path(private_key_path)
    if private_key_path.exists() and public_key_path.exists():
        return
    if private_key_path.exists() != public_key_path.exists():
        raise FileExistsError(
            f"endpoint SSH key is incomplete: {private_key_path} and {public_key_path}"
        )
    result = create_key_pair(private_key_path, comment=f"libcrafter-wire {endpoint_id}", timeout=30)
    if not result.ok:
        raise RuntimeError(_command_error("ssh-keygen failed", result))


def _public_key_path(private_key_path: Path) -> Path:
    return private_key_path.with_name(f"{private_key_path.name}.pub")


def _command_error(message: str, result: CommandResult) -> str:
    details = result.stderr.strip() or result.stdout.strip() or result.error or "no output"
    return f"{message}: {result.command}: {details}"


def _json_object(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise RuntimeError(f"{name} must be a JSON object")
    return dict(value)


def _object_id(value: Mapping[str, object]) -> str:
    provider_id = value.get("id")
    if isinstance(provider_id, int):
        return str(provider_id)
    if isinstance(provider_id, str) and provider_id:
        return provider_id
    raise RuntimeError("hcloud output did not include an object id")


def _ip_address(value: object) -> str | None:
    if isinstance(value, Mapping):
        ip = value.get("ip")
        return ip if isinstance(ip, str) and ip else None
    return None


def _network_resource_id(network_resource: Mapping[str, object]) -> str | None:
    for key in ("network_id", "provider_id", "id"):
        value = network_resource.get(key)
        if isinstance(value, int):
            return str(value)
        if isinstance(value, str) and value:
            return value
    return None


def _optional_mapping_string(value: Mapping[str, object], key: str) -> str | None:
    item = value.get(key)
    return item if isinstance(item, str) and item else None


def _optional_mapping_int(value: Mapping[str, object], key: str) -> int | None:
    item = value.get(key)
    if isinstance(item, bool):
        return None
    if isinstance(item, int):
        return item
    return None


def _ipv4_network(value: str) -> IPv4Network:
    try:
        network = ip_network(value)
    except ValueError as exc:
        raise ValueError(f"private_cidr must be a valid IPv4 CIDR: {value}") from exc
    if not isinstance(network, IPv4Network):
        raise ValueError(f"private_cidr must be an IPv4 CIDR: {value}")
    return network


def _ipv4_address(value: str, name: str) -> IPv4Address:
    try:
        address = ip_address(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be a valid IPv4 address: {value}") from exc
    if not isinstance(address, IPv4Address):
        raise ValueError(f"{name} must be an IPv4 address: {value}")
    return address


def _positive_float(value: float, name: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be a positive number")
    output = float(value)
    if output <= 0:
        raise ValueError(f"{name} must be a positive number")
    return output
