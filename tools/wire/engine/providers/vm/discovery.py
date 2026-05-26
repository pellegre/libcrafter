"""Provider-neutral Linux guest interface discovery helpers."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from ipaddress import IPv4Network, ip_address, ip_network
from pathlib import Path

from ...model import NetworkInterface
from ...process import CommandResult, run_command
from ...ssh import CommandRunner, run_ssh_command

LINUX_INTERFACE_DISCOVERY_MARKERS = {
    "addr": "__WIRE_IP_ADDR__",
    "link": "__WIRE_IP_LINK__",
    "route": "__WIRE_IP_ROUTE__",
}
LINUX_INTERFACE_DISCOVERY_COMMAND = "\n".join(
    [
        "set -eu",
        f"printf '%s\\n' {LINUX_INTERFACE_DISCOVERY_MARKERS['addr']}",
        "ip -j address show scope global",
        f"printf '%s\\n' {LINUX_INTERFACE_DISCOVERY_MARKERS['link']}",
        "ip -j link show",
        f"printf '%s\\n' {LINUX_INTERFACE_DISCOVERY_MARKERS['route']}",
        "ip -j route get 1.1.1.1 || true",
    ]
)
DEFAULT_CONTROL_CIDRS = ("10.0.2.0/24",)


def discover_linux_endpoint_interfaces(
    *,
    host: str,
    user: str,
    identity_file: str | Path,
    known_hosts: str | Path,
    exposure: str,
    public_ipv4: str | None = None,
    public_ipv6: str | None = None,
    command: str = LINUX_INTERFACE_DISCOVERY_COMMAND,
    port: int = 22,
    timeout: float | None = 30,
    runner: CommandRunner = run_command,
    source: str = "ip-ssh-discovery",
    metadata: Mapping[str, object] | None = None,
    prefer_public_or_default: bool = True,
) -> list[NetworkInterface]:
    """Discover Linux endpoint interfaces through SSH and parse the result."""

    result = run_ssh_command(
        host=host,
        user=user,
        identity_file=identity_file,
        known_hosts=known_hosts,
        command=command,
        port=port,
        runner=runner,
        timeout=timeout,
    )
    if not result.ok:
        raise RuntimeError(_command_error("interface discovery over ssh failed", result))
    return parse_linux_interface_discovery(
        result.stdout,
        exposure=exposure,
        public_ipv4=public_ipv4,
        public_ipv6=public_ipv6,
        source=source,
        metadata=metadata,
        prefer_public_or_default=prefer_public_or_default,
    )


def parse_linux_interface_discovery(
    output: str,
    *,
    exposure: str,
    public_ipv4: str | None = None,
    public_ipv6: str | None = None,
    source: str = "ip-ssh-discovery",
    metadata: Mapping[str, object] | None = None,
    prefer_public_or_default: bool = True,
) -> list[NetworkInterface]:
    """Parse marker-delimited Linux ip JSON discovery output."""

    sections = parse_interface_discovery_sections(output)
    addresses = _json_list(sections["addr"], "ip address output")
    links = _json_list(sections["link"], "ip link output")
    routes = _json_list(sections["route"], "ip route output") if sections["route"] else []
    link_by_name = {
        item.get("ifname"): item for item in links if isinstance(item.get("ifname"), str)
    }
    route_dev = default_route_interface_name(routes)

    discovered: list[NetworkInterface] = []
    for item in addresses:
        ifname = item.get("ifname")
        if not isinstance(ifname, str) or ifname == "":
            continue
        addr_info = item.get("addr_info")
        if not isinstance(addr_info, list):
            continue

        ipv4 = _interface_address(addr_info, family="inet")
        ipv6 = _interface_address(addr_info, family="inet6")
        if ipv4 is None and ipv6 is None:
            continue

        link = link_by_name.get(ifname, {})
        mac = _optional_mapping_string(link, "address") or _optional_mapping_string(item, "address")
        matched_public = (
            (public_ipv4 is not None and ipv4 == public_ipv4)
            or (public_ipv6 is not None and ipv6 == public_ipv6)
        )
        default_route = route_dev == ifname
        interface_metadata: dict[str, object] = {
            "source": source,
            "ifindex": _optional_mapping_int(item, "ifindex"),
            "operstate": _optional_mapping_string(link, "operstate")
            or _optional_mapping_string(item, "operstate"),
            "mtu": _optional_mapping_int(link, "mtu") or _optional_mapping_int(item, "mtu"),
            "matched_public_address": matched_public,
            "default_route": default_route,
            "public_ipv4": public_ipv4,
            "public_ipv6": public_ipv6,
        }
        if metadata is not None:
            interface_metadata.update(dict(metadata))
        discovered.append(
            NetworkInterface(
                name=ifname,
                exposure=exposure,
                ipv4=ipv4,
                ipv6=ipv6,
                mac=mac,
                metadata=interface_metadata,
            )
        )

    if not prefer_public_or_default:
        return discovered

    if public_ipv4 is not None or public_ipv6 is not None:
        public_matches = select_public_address_interfaces(discovered)
        if public_matches:
            return public_matches
    route_matches = select_default_route_interfaces(discovered)
    return route_matches or discovered


def parse_interface_discovery_sections(output: str) -> dict[str, str]:
    """Return marker-delimited `addr`, `link`, and `route` JSON sections."""

    lines = output.splitlines()
    positions: dict[str, int] = {}
    for name, marker in LINUX_INTERFACE_DISCOVERY_MARKERS.items():
        try:
            positions[name] = lines.index(marker)
        except ValueError as exc:
            raise RuntimeError(f"interface discovery output missing marker {marker}") from exc

    return {
        "addr": "\n".join(lines[positions["addr"] + 1 : positions["link"]]).strip(),
        "link": "\n".join(lines[positions["link"] + 1 : positions["route"]]).strip(),
        "route": "\n".join(lines[positions["route"] + 1 :]).strip(),
    }


def default_route_interface_name(routes: Sequence[Mapping[str, object]]) -> str | None:
    """Return the route device from `ip -j route get ...` output."""

    for route in routes:
        dev = route.get("dev")
        if isinstance(dev, str) and dev:
            return dev
    return None


def select_default_route_interfaces(
    interfaces: Sequence[NetworkInterface],
) -> list[NetworkInterface]:
    """Return interfaces marked as the guest default-route device."""

    return [interface for interface in interfaces if bool(interface.metadata.get("default_route"))]


def select_public_address_interfaces(
    interfaces: Sequence[NetworkInterface],
) -> list[NetworkInterface]:
    """Return interfaces whose address matched the provider public address."""

    return [
        interface
        for interface in interfaces
        if bool(interface.metadata.get("matched_public_address"))
    ]


def select_lan_candidate_interfaces(
    interfaces: Sequence[NetworkInterface],
    *,
    excluded_cidrs: Sequence[str] = DEFAULT_CONTROL_CIDRS,
    require_ipv4: bool = True,
) -> list[NetworkInterface]:
    """Return LAN packet interfaces after excluding NAT/control IPv4 ranges."""

    control_networks = tuple(_ipv4_network(cidr) for cidr in excluded_cidrs)
    candidates = [
        interface
        for interface in interfaces
        if not _is_control_interface(interface, control_networks)
        and (interface.ipv4 is not None or not require_ipv4)
    ]
    return [
        *select_default_route_interfaces(candidates),
        *[
            interface
            for interface in candidates
            if not bool(interface.metadata.get("default_route"))
        ],
    ]


def _json_list(value: str, name: str) -> list[dict[str, object]]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{name} was not valid JSON") from exc
    if not isinstance(parsed, list):
        raise RuntimeError(f"{name} must be a JSON list")
    output: list[dict[str, object]] = []
    for item in parsed:
        if isinstance(item, Mapping):
            output.append(dict(item))
    return output


def _interface_address(addr_info: Sequence[object], *, family: str) -> str | None:
    for address in addr_info:
        if not isinstance(address, Mapping):
            continue
        if address.get("family") != family:
            continue
        local = address.get("local")
        if isinstance(local, str) and local:
            return local
    return None


def _is_control_interface(
    interface: NetworkInterface,
    control_networks: Sequence[IPv4Network],
) -> bool:
    if interface.ipv4 is None:
        return False
    try:
        address = ip_address(interface.ipv4)
    except ValueError:
        return False
    if address.version != 4:
        return False
    return any(address in network for network in control_networks)


def _ipv4_network(value: str) -> IPv4Network:
    try:
        network = ip_network(value)
    except ValueError as exc:
        raise ValueError(f"control CIDR is invalid: {value}") from exc
    if not isinstance(network, IPv4Network):
        raise ValueError(f"control CIDR must be IPv4: {value}")
    return network


def _optional_mapping_string(mapping: Mapping[str, object], key: str) -> str | None:
    value = mapping.get(key)
    return value if isinstance(value, str) and value else None


def _optional_mapping_int(mapping: Mapping[str, object], key: str) -> int | None:
    value = mapping.get(key)
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return None


def _command_error(message: str, result: CommandResult) -> str:
    details = result.stderr.strip() or result.stdout.strip() or result.error or "no output"
    return f"{message}: {result.command}: {details}"
