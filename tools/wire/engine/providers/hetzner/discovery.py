"""Hetzner server readiness and interface discovery."""

from __future__ import annotations

import json
import time
from collections.abc import Mapping
from pathlib import Path

from ...model import NetworkInterface
from ...process import run_command
from ...ssh import run_ssh_command
from .constants import (
    DEFAULT_SERVER_RUNNING_INTERVAL,
    DEFAULT_SERVER_RUNNING_TIMEOUT,
    HCLOUD_COMMAND,
    INTERFACE_DISCOVERY_COMMAND,
    HcloudRunner,
)
from .hcloud import _hcloud_json
from .utils import (
    _command_error,
    _json_object,
    _optional_mapping_int,
    _optional_mapping_string,
    _positive_float,
)



def wait_for_server_running(
    *,
    server_id: str,
    env: Mapping[str, str],
    timeout: float = DEFAULT_SERVER_RUNNING_TIMEOUT,
    interval: float = DEFAULT_SERVER_RUNNING_INTERVAL,
    command_runner: HcloudRunner = run_command,
) -> dict[str, object]:
    """Wait for a Hetzner server to report the running state."""

    deadline = time.monotonic() + _positive_float(timeout, "timeout")
    sleep_interval = _positive_float(interval, "interval")
    last_status = "unknown"

    while True:
        server = _hcloud_json(
            [HCLOUD_COMMAND, "server", "describe", server_id, "-o", "json"],
            env=env,
            command_runner=command_runner,
        )
        server_object = _json_object(server.get("server", server), "server")
        status = server_object.get("status")
        if isinstance(status, str) and status:
            last_status = status
        if last_status == "running":
            return server_object

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError(
                f"server running wait timed out for Hetzner server {server_id}: "
                f"last status={last_status}"
            )
        time.sleep(min(sleep_interval, remaining))


def discover_endpoint_interfaces(
    *,
    host: str,
    user: str,
    identity_file: str | Path,
    known_hosts: str | Path,
    exposure: str,
    public_ipv4: str | None = None,
    public_ipv6: str | None = None,
) -> list[NetworkInterface]:
    """Discover endpoint interfaces with Linux ip commands over SSH."""

    result = run_ssh_command(
        host=host,
        user=user,
        identity_file=identity_file,
        known_hosts=known_hosts,
        command=INTERFACE_DISCOVERY_COMMAND,
        timeout=30,
    )
    if not result.ok:
        raise RuntimeError(_command_error("interface discovery over ssh failed", result))
    return parse_ip_interface_discovery(
        result.stdout,
        exposure=exposure,
        public_ipv4=public_ipv4,
        public_ipv6=public_ipv6,
    )


def parse_ip_interface_discovery(
    output: str,
    *,
    exposure: str,
    public_ipv4: str | None = None,
    public_ipv6: str | None = None,
) -> list[NetworkInterface]:
    """Parse JSON emitted by the endpoint interface discovery command."""

    sections = _interface_discovery_sections(output)
    addresses = _json_list(sections["addr"], "ip address output")
    links = _json_list(sections["link"], "ip link output")
    routes = _json_list(sections["route"], "ip route output") if sections["route"] else []
    link_by_name = {
        item.get("ifname"): item for item in links if isinstance(item.get("ifname"), str)
    }
    route_dev = _route_dev(routes)

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
        discovered.append(
            NetworkInterface(
                name=ifname,
                exposure=exposure,
                ipv4=ipv4,
                ipv6=ipv6,
                mac=mac,
                metadata={
                    "source": "ip-ssh-discovery",
                    "ifindex": _optional_mapping_int(item, "ifindex"),
                    "operstate": _optional_mapping_string(link, "operstate")
                    or _optional_mapping_string(item, "operstate"),
                    "mtu": _optional_mapping_int(link, "mtu")
                    or _optional_mapping_int(item, "mtu"),
                    "matched_public_address": matched_public,
                    "default_route": default_route,
                    "hcloud_public_ipv4": public_ipv4,
                    "hcloud_public_ipv6": public_ipv6,
                },
            )
        )

    if public_ipv4 is not None or public_ipv6 is not None:
        public_matches = [
            interface
            for interface in discovered
            if bool(interface.metadata.get("matched_public_address"))
        ]
        if public_matches:
            return public_matches
    route_matches = [
        interface for interface in discovered if bool(interface.metadata.get("default_route"))
    ]
    return route_matches or discovered


def _interface_discovery_sections(output: str) -> dict[str, str]:
    lines = output.splitlines()
    markers = {
        "addr": "__WIRE_IP_ADDR__",
        "link": "__WIRE_IP_LINK__",
        "route": "__WIRE_IP_ROUTE__",
    }
    positions: dict[str, int] = {}
    for name, marker in markers.items():
        try:
            positions[name] = lines.index(marker)
        except ValueError as exc:
            raise RuntimeError(f"interface discovery output missing marker {marker}") from exc

    return {
        "addr": "\n".join(lines[positions["addr"] + 1 : positions["link"]]).strip(),
        "link": "\n".join(lines[positions["link"] + 1 : positions["route"]]).strip(),
        "route": "\n".join(lines[positions["route"] + 1 :]).strip(),
    }


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


def _route_dev(routes: list[dict[str, object]]) -> str | None:
    for route in routes:
        dev = route.get("dev")
        if isinstance(dev, str) and dev:
            return dev
    return None


def _interface_address(addr_info: list[object], *, family: str) -> str | None:
    for address in addr_info:
        if not isinstance(address, Mapping):
            continue
        if address.get("family") != family:
            continue
        local = address.get("local")
        if isinstance(local, str) and local:
            return local
    return None
