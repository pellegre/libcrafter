"""Private network helpers for Hetzner endpoints."""

from __future__ import annotations

from collections.abc import Mapping

from ...model import NetworkInterface
from ...state import read_private_group_record
from .constants import HCLOUD_COMMAND, HcloudRunner
from .hcloud import _hcloud_json, _hcloud_json_optional, _hcloud_ok
from .utils import (
    _ipv4_address,
    _ipv4_network,
    _json_object,
    _label_value,
    _network_resource_id,
    _object_id,
    _optional_mapping_string,
    _path_component,
)



def _ensure_private_network(
    *,
    provider: str,
    private_group: str,
    private_cidr: str,
    network_zone: str,
    env: Mapping[str, str],
    command_runner: HcloudRunner,
) -> dict[str, object]:
    network_name = _private_network_name(private_group)
    created = False

    network_object: dict[str, object] | None = None
    try:
        record = read_private_group_record(provider, private_group)
    except FileNotFoundError:
        record = None

    if record is not None:
        network_id = _network_resource_id(record.network_resource)
        if network_id is not None:
            network_object = _hcloud_json_optional(
                [HCLOUD_COMMAND, "network", "describe", network_id, "-o", "json"],
                env=env,
                command_runner=command_runner,
            )

    if network_object is None:
        network_object = _hcloud_json_optional(
            [HCLOUD_COMMAND, "network", "describe", network_name, "-o", "json"],
            env=env,
            command_runner=command_runner,
        )

    if network_object is None:
        created = True
        network_created = _hcloud_json(
            [
                HCLOUD_COMMAND,
                "network",
                "create",
                "--name",
                network_name,
                "--ip-range",
                private_cidr,
                "--label",
                "libcrafter-wire=true",
                "--label",
                f"libcrafter-wire-private-group={_label_value(private_group)}",
                "-o",
                "json",
            ],
            env=env,
            command_runner=command_runner,
        )
        network_object = _json_object(network_created.get("network", network_created), "network")
    else:
        network_object = _json_object(network_object.get("network", network_object), "network")

    if not _network_has_subnet(
        network_object,
        private_cidr=private_cidr,
        network_zone=network_zone,
    ):
        # `hcloud network add-subnet` is an action command and rejects
        # `-o/--output`; `_hcloud_ok` only checks success, so emit no output flag.
        _hcloud_ok(
            [
                HCLOUD_COMMAND,
                "network",
                "add-subnet",
                _object_id(network_object),
                "--type",
                "server",
                "--network-zone",
                network_zone,
                "--ip-range",
                private_cidr,
            ],
            env=env,
            command_runner=command_runner,
        )
        described = _hcloud_json(
            [HCLOUD_COMMAND, "network", "describe", _object_id(network_object), "-o", "json"],
            env=env,
            command_runner=command_runner,
        )
        network_object = _json_object(described.get("network", described), "network")

    return {
        "created": created,
        "resource": _private_network_resource(
            network_object,
            private_group=private_group,
            private_cidr=private_cidr,
            network_zone=network_zone,
        ),
    }


def _attach_server_to_private_network(
    *,
    server_id: str,
    network_resource: Mapping[str, object],
    private_ipv4: str,
    env: Mapping[str, str],
    command_runner: HcloudRunner,
) -> dict[str, object]:
    network_id = _network_resource_id(network_resource)
    if network_id is None:
        raise RuntimeError("private network resource did not include a network id")
    # `hcloud server attach-to-network` is an action command and rejects
    # `-o/--output`; it emits human-readable text, not JSON. `_hcloud_ok` raises
    # on failure, and callers do not consume the return payload.
    _hcloud_ok(
        [
            HCLOUD_COMMAND,
            "server",
            "attach-to-network",
            server_id,
            "--network",
            network_id,
            "--ip",
            private_ipv4,
        ],
        env=env,
        command_runner=command_runner,
    )
    return {}


def _allocate_private_ipv4(
    *,
    provider: str,
    private_group: str,
    private_cidr: str,
    requested_private_ip: str | None,
) -> str:
    network = _ipv4_network(private_cidr)
    try:
        record = read_private_group_record(provider, private_group)
        allocated = set(record.allocated_private_ipv4s)
    except FileNotFoundError:
        allocated = set()

    if requested_private_ip is not None:
        address = _ipv4_address(requested_private_ip, "private_ip")
        if address not in network:
            raise ValueError(f"private_ip {requested_private_ip} is outside {private_cidr}")
        if requested_private_ip in allocated:
            raise ValueError(f"private_ip {requested_private_ip} is already allocated")
        return requested_private_ip

    for address in network.hosts():
        private_ipv4 = str(address)
        if private_ipv4.endswith(".1"):
            continue
        if private_ipv4 not in allocated:
            return private_ipv4
    raise RuntimeError(f"no private IPv4 addresses are available in {private_cidr}")


def _private_network_interface(
    *,
    exposure: str,
    private_group: str,
    private_ipv4: str,
    network_resource: Mapping[str, object],
    server_id: str,
    server_name: str,
) -> NetworkInterface:
    return NetworkInterface(
        name="private",
        exposure=exposure,
        ipv4=private_ipv4,
        provider_network_id=_network_resource_id(network_resource),
        metadata={
            "source": "hcloud",
            "private_group": private_group,
            "private_ip": private_ipv4,
            "server_id": server_id,
            "server_name": server_name,
            "network": dict(network_resource),
        },
    )


def _private_network_name(private_group: str) -> str:
    return f"wire-{_path_component(private_group)}"


def _network_has_subnet(
    network_object: Mapping[str, object],
    *,
    private_cidr: str,
    network_zone: str,
) -> bool:
    subnets = network_object.get("subnets")
    if not isinstance(subnets, list):
        return False
    for item in subnets:
        if not isinstance(item, Mapping):
            continue
        if item.get("type") != "server":
            continue
        if item.get("ip_range") != private_cidr:
            continue
        return True
    return False


def _private_network_resource(
    network_object: Mapping[str, object],
    *,
    private_group: str,
    private_cidr: str,
    network_zone: str,
) -> dict[str, object]:
    raw_subnets = network_object.get("subnets", [])
    if not isinstance(raw_subnets, list):
        raw_subnets = []
    subnets = [
        dict(item)
        for item in raw_subnets
        if isinstance(item, Mapping)
        and item.get("type") == "server"
        and item.get("ip_range") == private_cidr
    ]
    name = network_object.get("name")
    return {
        "type": "network",
        "provider": "hetzner",
        "network_id": _object_id(network_object),
        "network_name": name if isinstance(name, str) and name else _private_network_name(private_group),
        "private_group": private_group,
        "ip_range": _optional_mapping_string(network_object, "ip_range") or private_cidr,
        "subnet": subnets[0] if subnets else {
            "type": "server",
            "network_zone": network_zone,
            "ip_range": private_cidr,
        },
    }
