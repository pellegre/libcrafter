"""VirtualBox bridged interface discovery helpers."""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence

from ...process import run_command
from ..vm import command_error
from .constants import VBOXMANAGE_COMMAND, VBOX_BRIDGE_IFACE_ENV, VirtualBoxRunner


def requested_bridge_interface(env: Mapping[str, str] | None = None) -> str | None:
    """Return the explicitly requested host bridge interface, if configured."""

    source = os.environ if env is None else env
    value = source.get(VBOX_BRIDGE_IFACE_ENV)
    if value is None:
        return None
    if value.strip() == "":
        raise ValueError(f"{VBOX_BRIDGE_IFACE_ENV} must not be empty when set")
    return value.strip()


def planned_bridge_interface(env: Mapping[str, str] | None = None) -> dict[str, object]:
    """Return dry-run bridge selection metadata without touching VirtualBox."""

    requested = requested_bridge_interface(env)
    return {
        "name": requested or "auto",
        "selection": "env" if requested is not None else "auto",
        "env": VBOX_BRIDGE_IFACE_ENV,
        "validated": False,
    }


def discover_bridge_interfaces(
    *,
    command_runner: VirtualBoxRunner = run_command,
) -> list[dict[str, object]]:
    """Return host bridged interfaces reported by ``VBoxManage list bridgedifs``."""

    result = command_runner([VBOXMANAGE_COMMAND, "list", "bridgedifs"], timeout=30)
    if not result.ok:
        raise RuntimeError(command_error("VBoxManage bridged interface discovery failed", result))
    return parse_bridged_interfaces(result.stdout)


def select_bridge_interface(
    interfaces: Sequence[Mapping[str, object]],
    *,
    env: Mapping[str, str] | None = None,
) -> dict[str, object] | None:
    """Return the requested or first usable bridged interface."""

    requested = requested_bridge_interface(env)
    normalized = [dict(item) for item in interfaces]
    if requested is not None:
        for interface in normalized:
            if interface.get("name") == requested:
                return interface
        return None

    up_interfaces = [
        interface
        for interface in normalized
        if str(interface.get("status", "")).strip().lower() == "up"
    ]
    if up_interfaces:
        return up_interfaces[0]
    return normalized[0] if normalized else None


def parse_bridged_interfaces(output: str) -> list[dict[str, object]]:
    """Parse ``VBoxManage list bridgedifs`` into JSON-compatible records."""

    interfaces: list[dict[str, object]] = []
    current: dict[str, object] = {}
    for raw_line in output.splitlines():
        line = raw_line.rstrip()
        if not line:
            if current:
                interfaces.append(current)
                current = {}
            continue
        key, separator, value = line.partition(":")
        if not separator:
            continue
        normalized_key = _field_name(key)
        normalized_value: object = value.strip()
        if normalized_key in {"dhcp", "wireless"}:
            normalized_value = str(normalized_value).lower() in {"enabled", "yes", "true", "1"}
        current[normalized_key] = normalized_value

    if current:
        interfaces.append(current)
    return [interface for interface in interfaces if isinstance(interface.get("name"), str)]


def _field_name(value: str) -> str:
    normalized = value.strip().lower().replace(" ", "_")
    return {
        "hardwareaddress": "hardware_address",
        "mediumtype": "medium_type",
        "vboxnetworkname": "vbox_network_name",
        "ipaddress": "ip_address",
        "networkmask": "network_mask",
        "ipv6address": "ipv6_address",
        "ipv6networkmaskprefixlength": "ipv6_network_mask_prefix_length",
    }.get(normalized, normalized)

