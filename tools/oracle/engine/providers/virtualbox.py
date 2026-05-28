"""VirtualBox oracle live orchestration planning.

This adapter maps the oracle two-endpoint live lab onto the local VirtualBox
wire provider. VirtualBox currently exposes packet exchange through a bridged
LAN interface, so it does not use private groups or requested private IPs.
"""

from __future__ import annotations

import os
import shlex
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace

from tools.lab.engine.model import (
    LabCommandPlan,
    LabRequest,
    LabRole,
)
from tools.lab.engine.providers.common import validate_remote_dir
from tools.lab.engine.providers.virtualbox import VIRTUALBOX_LAB_PROVIDER_ADAPTER
from tools.lab.engine import wire_client
from tools.wire.engine.model import (
    EndpointManifest,
    EndpointSSHInfo,
    NetworkInterface,
    ProviderResources,
)

from .base import LiveProviderAdapter
from .policy import wire_comparison_policy
from .. import bootstrap as oracle_bootstrap
from ..live import (
    LiveCommandPlan,
    LiveEndpoint,
    LiveExchangePlan,
    LiveValidationCheck,
    live_endpoint_from_lab_endpoint,
)
from ..model import JSONObject, PacketPlan


PROVIDER_NAME = "virtualbox"
WIRE_ENTRYPOINT = "tools/wire/run"
ORACLE_LIVE_SUITE = "oracle-live"
BRIDGE_INTERFACE_ENV = "LIBCRAFTER_VBOX_BRIDGE_IFACE"
PLANNED_LIBCRAFTER_LAN_ADDRESS = "192.0.2.110"
PLANNED_REFERENCE_LAN_ADDRESS = "192.0.2.120"
CAPABILITY_REPORT_ARTIFACT = "live-artifacts/oracle-live/capabilities.json"
PROVIDER_CAPABILITY_NAMES = (
    "ipv4_unicast",
    "ipv6_unicast",
    "link_layer_send",
    "link_layer_capture",
    "broadcast",
    "provider_mac_known",
    "controlled_services",
    "controlled_router",
)
VIRTUALBOX_WIRE_POLICY: JSONObject = {
    "ipv4_header_mutable": False,
    "l3_send_adds_link_layer_metadata": False,
    "transit_decrements_ipv4_ttl": False,
}


def virtualbox_default_provider_capabilities(
    *,
    dry_run: bool,
    source: str = "planned-defaults",
) -> JSONObject:
    """Return conservative VirtualBox bridged-LAN capability defaults."""

    capabilities = VIRTUALBOX_LAB_PROVIDER_ADAPTER.default_provider_capabilities(
        dry_run=dry_run,
        source=source,
    )
    capabilities["capability_report_artifact"] = CAPABILITY_REPORT_ARTIFACT
    capabilities.setdefault("wire_policy", dict(VIRTUALBOX_WIRE_POLICY))
    return capabilities


def normalize_virtualbox_provider_capabilities(
    raw: JSONObject,
    *,
    dry_run: bool | None = None,
    source: str | None = None,
) -> JSONObject:
    """Return flat capability keys plus legacy aliases consumed by corpus logic."""

    normalized = VIRTUALBOX_LAB_PROVIDER_ADAPTER.normalize_provider_capabilities(
        raw,
        dry_run=dry_run,
        source=source,
    )
    normalized["capability_report_artifact"] = raw.get(
        "capability_report_artifact",
        CAPABILITY_REPORT_ARTIFACT,
    )
    normalized.setdefault("wire_policy", dict(VIRTUALBOX_WIRE_POLICY))
    return normalized


def virtualbox_token_configured() -> bool:
    """Return whether VirtualBox execution passes the generic credential gate."""

    return VIRTUALBOX_LAB_PROVIDER_ADAPTER.credentials_available()


def virtualbox_lan_plan(*, dry_run: bool) -> JSONObject:
    """Return local VM resources required for an oracle VirtualBox LAN lab."""

    return _oracle_planned_infrastructure(dry_run=dry_run)


def virtualbox_packet_exchange_metadata(*, dry_run: bool) -> JSONObject:
    """Return packet-exchange network metadata for the VirtualBox LAN lab."""

    return _oracle_packet_exchange_metadata(dry_run=dry_run)


def virtualbox_endpoints(*, dry_run: bool) -> dict[str, LiveEndpoint]:
    """Return planned endpoint roles for VirtualBox reports."""

    return _oracle_planned_endpoints(dry_run=dry_run)


def _planned_virtualbox_endpoint(
    *,
    role: str,
    address: str,
    peer_role: str,
    peer_address: str,
    dry_run: bool,
) -> LiveEndpoint:
    metadata: JSONObject = {
        "provider": PROVIDER_NAME,
        "exposure": "lan",
        "dry_run": dry_run,
        "creates_infrastructure": not dry_run,
        "would_create_infrastructure": dry_run,
        "isolated_network": False,
        "private_network": False,
        "bridged_lan": True,
        "resource_type": "virtualbox-vm",
        "peer_role": peer_role,
        "peer_address": peer_address,
        "planned_address": True,
        "address_source": "oracle-planned-lan-placeholder",
        "bridge_interface_env": BRIDGE_INTERFACE_ENV,
    }
    if role == "reference_backend":
        metadata["backend"] = "scapy"
    return LiveEndpoint(
        endpoint_id=f"virtualbox-planned-{role}",
        role=role,
        interface="lan",
        address=address,
        metadata=metadata,
    )


def virtualbox_wire_endpoint_plan(
    *,
    dry_run: bool,
    client: wire_client.WireClient | None = None,
    confirm_live_run: bool = False,
    created_endpoint_ids: list[str] | None = None,
) -> dict[str, object]:
    """Create or plan the two LAN wire endpoints used by VirtualBox oracle runs."""

    return _oracle_wire_endpoint_plan(
        dry_run=dry_run,
        client=client,
        confirm_live_run=confirm_live_run,
        created_endpoint_ids=created_endpoint_ids,
    )


def _live_endpoint_from_wire_plan(
    endpoint_plan: JSONObject,
    *,
    role: str,
    planned_address: str,
    dry_run: bool,
) -> LiveEndpoint:
    interface = _lan_interface(endpoint_plan)
    discovered_address = _optional_string(interface.get("ipv4"))
    if discovered_address is None and not dry_run:
        endpoint_id = _string_or(endpoint_plan.get("endpoint_id"), f"virtualbox-{role}")
        raise RuntimeError(
            f"virtualbox wire manifest {endpoint_id!r} lacks a LAN packet-exchange IPv4 address"
        )
    address = discovered_address or planned_address
    interface_metadata = _json_object(interface.get("metadata", {}))
    metadata: JSONObject = {
        "provider": PROVIDER_NAME,
        "exposure": "lan",
        "dry_run": dry_run,
        "creates_infrastructure": not dry_run,
        "would_create_infrastructure": dry_run,
        "isolated_network": False,
        "private_network": False,
        "bridged_lan": True,
        "resource_type": "wire-endpoint",
        "planned_address": discovered_address is None,
        "address_source": (
            "oracle-planned-lan-placeholder"
            if discovered_address is None
            else "manifest-lan-interface"
        ),
        "wire_endpoint_plan": endpoint_plan,
        "manifest_path": endpoint_plan.get("manifest_path"),
        "artifact_dir": endpoint_plan.get("artifact_dir"),
        "bridge_interface": interface_metadata.get("bridge_interface"),
        "bridge_selection": interface_metadata.get("bridge_selection"),
        "bridge_env": interface_metadata.get("bridge_env", BRIDGE_INTERFACE_ENV),
        "mac_address": interface.get("mac"),
        **({"backend": "scapy"} if role == "reference_backend" else {}),
    }
    return LiveEndpoint(
        endpoint_id=_string_or(endpoint_plan.get("endpoint_id"), f"virtualbox-planned-{role}"),
        role=role,
        interface=_string_or(interface.get("name"), "lan"),
        address=address,
        ipv6_address=_optional_string(interface.get("ipv6")),
        metadata=metadata,
    )


def _with_peer_metadata(endpoints: dict[str, LiveEndpoint]) -> dict[str, LiveEndpoint]:
    if "libcrafter" not in endpoints or "reference_backend" not in endpoints:
        return endpoints
    libcrafter = endpoints["libcrafter"]
    reference = endpoints["reference_backend"]
    return {
        "libcrafter": replace(
            libcrafter,
            metadata={
                **libcrafter.metadata,
                "peer_role": "reference_backend",
                "peer_address": reference.address,
            },
        ),
        "reference_backend": replace(
            reference,
            metadata={
                **reference.metadata,
                "peer_role": "libcrafter",
                "peer_address": libcrafter.address,
            },
        ),
    }


def _lan_interface(endpoint_plan: JSONObject) -> JSONObject:
    interfaces = endpoint_plan.get("interfaces")
    if isinstance(interfaces, list):
        for item in interfaces:
            if isinstance(item, dict) and item.get("exposure") == "lan":
                return {str(key): value for key, value in item.items() if isinstance(key, str)}
    return {}


def _json_object(value: object) -> JSONObject:
    return {
        str(key): item
        for key, item in value.items()
        if isinstance(key, str)
    } if isinstance(value, Mapping) else {}


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _string_or(value: object, default: str) -> str:
    return value if isinstance(value, str) and value else default


def virtualbox_provider_workflow(*, dry_run: bool) -> list[LiveCommandPlan]:
    """Plan the provider lifecycle commands used by a VirtualBox oracle run."""

    return _oracle_provider_workflow(dry_run=dry_run)


def virtualbox_endpoint_bootstrap_plan(*, dry_run: bool) -> list[LiveCommandPlan]:
    """Plan role-specific endpoint bootstrap work for the VirtualBox LAN lab."""

    return oracle_bootstrap.endpoint_bootstrap_plan(
        PROVIDER_NAME,
        dry_run,
        virtualbox_default_provider_capabilities(dry_run=dry_run),
        _virtualbox_endpoint_bootstrap_topology(),
    )


def _virtualbox_endpoint_bootstrap_topology() -> JSONObject:
    return {
        "private_network": False,
        "bridged_lan": True,
        "bridge_interface_env": BRIDGE_INTERFACE_ENV,
        "capability_artifact": CAPABILITY_REPORT_ARTIFACT,
    }


def validate_virtualbox_endpoint_bootstrap(
    commands: list[LiveCommandPlan],
    *,
    dry_run: bool,
) -> LiveValidationCheck:
    """Validate that both VirtualBox endpoint roles are bootstrapped."""

    return oracle_bootstrap.validate_endpoint_bootstrap(
        PROVIDER_NAME,
        commands,
        dry_run=dry_run,
        topology_metadata=_virtualbox_endpoint_bootstrap_topology(),
    )


def validate_virtualbox_provider_workflow(
    commands: list[LiveCommandPlan],
    *,
    dry_run: bool,
) -> LiveValidationCheck:
    """Validate VirtualBox provider lifecycle planning invariants."""

    errors: list[str] = []
    purposes = {command.purpose for command in commands}
    required = {
        "check-virtualbox-provider",
        "create-libcrafter-lan-wire-endpoint",
        "create-reference-lan-wire-endpoint",
        "run-oracle-live-exchange-suite",
        "collect-live-endpoint-artifacts",
        "teardown-disposable-virtualbox-endpoints",
    }
    missing = sorted(required - purposes)
    if missing:
        errors.append(f"missing provider workflow phases: {', '.join(missing)}")

    for command in commands:
        if command.role != "provider":
            errors.append(f"unexpected provider workflow role: {command.role}")
        if len(command.argv) < 2 or command.argv[0] != WIRE_ENTRYPOINT:
            errors.append(f"provider command must route through {WIRE_ENTRYPOINT}")
        if command.metadata.get("wire_command") is not True:
            errors.append("provider command must be marked as wire_command")
        if command.metadata.get("provider") != PROVIDER_NAME:
            errors.append("provider command must target VirtualBox")
        if command.metadata.get("private_network") is True:
            errors.append("provider command must not require a private network")
        if "--private-group" in command.argv or "--private-ip" in command.argv:
            errors.append("VirtualBox provider commands must not pass private network flags")
        if dry_run and command.metadata.get("operation") in {
            "doctor",
            "create",
        } and "--dry-run" not in command.argv:
            errors.append(f"dry-run provider command lacks --dry-run: {command.shell()}")
        if (
            not dry_run
            and command.metadata.get("operation") == "create"
            and "--confirm-live-run" not in command.argv
        ):
            errors.append("real provider create command lacks --confirm-live-run")
        if command.sends_live_packets or command.expects_live_packets:
            errors.append("provider lifecycle commands cannot be endpoint packet commands")

    return LiveValidationCheck(
        name="virtualbox-provider-workflow",
        passed=not errors,
        subject=PROVIDER_NAME,
        errors=errors,
        metadata={
            "provider": PROVIDER_NAME,
            "dry_run": dry_run,
            "creates_infrastructure": not dry_run,
            "bridged_lan": True,
            "always_collect_artifacts": True,
            "always_teardown": True,
        },
    )


def validate_virtualbox_dry_run_exchange(
    exchange: LiveExchangePlan,
) -> LiveValidationCheck:
    """Validate that a VirtualBox dry-run exchange is LAN-backed and non-mutating."""

    errors: list[str] = []
    if exchange.provider != PROVIDER_NAME:
        errors.append(f"unexpected provider: {exchange.provider}")
    if exchange.live_packet_exchange:
        errors.append("VirtualBox dry-run cannot claim live packet exchange")
    if exchange.sender.role == exchange.receiver.role:
        errors.append("sender and receiver roles must differ")
    if bool(exchange.sender.metadata.get("private_network")):
        errors.append("sender endpoint must not use a private network")
    if bool(exchange.receiver.metadata.get("private_network")):
        errors.append("receiver endpoint must not use a private network")
    if not bool(exchange.sender.metadata.get("bridged_lan")):
        errors.append("sender endpoint must use bridged LAN")
    if not bool(exchange.receiver.metadata.get("bridged_lan")):
        errors.append("receiver endpoint must use bridged LAN")
    if exchange.sender.metadata.get("provider") != PROVIDER_NAME:
        errors.append("sender endpoint must be a VirtualBox endpoint")
    if exchange.receiver.metadata.get("provider") != PROVIDER_NAME:
        errors.append("receiver endpoint must be a VirtualBox endpoint")
    if exchange.sender.address == exchange.receiver.address:
        errors.append("sender and receiver LAN addresses must differ")
    if (
        exchange.sender_command.sends_live_packets
        or exchange.receiver_command.sends_live_packets
    ):
        errors.append("VirtualBox dry-run endpoint commands must not send packets")
    if (
        exchange.sender_command.expects_live_packets
        or exchange.receiver_command.expects_live_packets
    ):
        errors.append("VirtualBox dry-run endpoint commands must not expect packets")

    return LiveValidationCheck(
        name="virtualbox-dry-run-live-invariant",
        passed=not errors,
        subject=f"{exchange.direction}:index-{exchange.index:06d}",
        errors=errors,
        metadata={
            "provider": PROVIDER_NAME,
            "direction": exchange.direction,
            "packet_index": exchange.index,
            "bridged_lan": True,
            "creates_infrastructure": False,
            "live_packet_exchange": False,
        },
    )


def virtualbox_wire_remote_dir() -> str:
    """Return the repository directory used by VirtualBox wire endpoints."""

    return validate_remote_dir(os.environ.get("LIBCRAFTER_WIRE_REMOTE_DIR"))


def virtualbox_endpoint_remote_command(
    *,
    endpoint_role: str,
    remote_dir: str,
    request_path: str,
    out_dir: str,
) -> list[str]:
    """Return the endpoint protocol command executed on a VirtualBox endpoint."""

    quoted_remote_dir = shlex.quote(remote_dir)
    quoted_request = shlex.quote(request_path)
    quoted_out = shlex.quote(out_dir)
    if endpoint_role == "libcrafter":
        script = "\n".join(
            [
                "set -euo pipefail",
                f"cd {quoted_remote_dir}",
                'if [ -f "$HOME/.cargo/env" ]; then . "$HOME/.cargo/env"; fi',
                (
                    "cargo run -q -p oracle-adapters --bin live_endpoint -- "
                    f"--live --input {quoted_request} --out {quoted_out}"
                ),
            ]
        )
    else:
        script = "\n".join(
            [
                "set -euo pipefail",
                f"cd {quoted_remote_dir}",
                'export PYTHONPATH="tools/oracle${PYTHONPATH:+:$PYTHONPATH}"',
                (
                    "python3 -m engine.backends.scapy.live "
                    f"--live --input {quoted_request} --out {quoted_out}"
                ),
            ]
        )
    return ["bash", "-lc", script]


def virtualbox_endpoint_bootstrap_command(
    *,
    endpoint: LiveEndpoint,
    peer: LiveEndpoint,
    remote_archive: str,
    remote_dir: str,
) -> list[str]:
    """Return the repository bootstrap command for one VirtualBox endpoint."""

    return oracle_bootstrap.endpoint_bootstrap_command(
        provider=PROVIDER_NAME,
        endpoint=endpoint,
        peer=peer,
        remote_archive=remote_archive,
        remote_dir=remote_dir,
        topology_metadata=_virtualbox_endpoint_bootstrap_topology(),
    )


def virtualbox_endpoint_bootstrap_command_hook():
    """Return the lab repository bootstrap hook for VirtualBox oracle roles."""

    return oracle_bootstrap.endpoint_bootstrap_command_hook(
        PROVIDER_NAME,
        _virtualbox_endpoint_bootstrap_topology(),
    )


def virtualbox_live_transit_plan(plan: PacketPlan) -> PacketPlan:
    """Apply VirtualBox live policy without provider-routed transit rewrites."""

    wire_policy = virtualbox_wire_comparison_policy(plan)
    fields = {
        layer: dict(layer_fields)
        for layer, layer_fields in plan.fields.items()
    }
    return replace(
        plan,
        fields=fields,
        strict_bytes=bool(wire_policy.get("strict_bytes", plan.strict_bytes)),
        metadata={
            **plan.metadata,
            "wire": wire_policy,
            "live_transit_rewrites": [],
            "live_mutable_fields": list(wire_policy.get("mutable_fields", [])),
            "strict_bytes": bool(wire_policy.get("strict_bytes", plan.strict_bytes)),
        },
    )


def virtualbox_wire_comparison_policy(plan: PacketPlan) -> JSONObject:
    """Return VirtualBox wire comparison policy for one packet plan."""

    raw_policy = plan.metadata.get("wire")
    if isinstance(raw_policy, Mapping):
        policy = {
            key: value
            for key, value in raw_policy.items()
            if isinstance(key, str)
        }
    else:
        policy = wire_comparison_policy(
            plan,
            provider=PROVIDER_NAME,
            provider_capabilities=virtualbox_default_provider_capabilities(dry_run=True),
        )

    mutable_fields = policy.get("mutable_fields", [])
    if not isinstance(mutable_fields, Sequence) or isinstance(
        mutable_fields,
        (str, bytes, bytearray),
    ):
        mutable_fields = []
    policy["mutable_fields"] = [
        field
        for field in mutable_fields
        if isinstance(field, str) and field
    ]

    byte_mutable_fields = policy.get("byte_mutable_fields", [])
    if not isinstance(byte_mutable_fields, Sequence) or isinstance(
        byte_mutable_fields,
        (str, bytes, bytearray),
    ):
        byte_mutable_fields = []
    policy["byte_mutable_fields"] = [
        field
        for field in byte_mutable_fields
        if isinstance(field, str) and field
    ]

    strict_bytes = policy.get("strict_bytes")
    if not isinstance(strict_bytes, bool):
        strict_bytes = bool(plan.strict_bytes and not policy["byte_mutable_fields"])
    policy["strict_bytes"] = strict_bytes

    compare_root = policy.get("compare_root")
    if compare_root is not None and not isinstance(compare_root, str):
        compare_root = None
    policy["compare_root"] = compare_root
    policy.setdefault("provider", PROVIDER_NAME)
    return policy


def _oracle_lab_request(
    *,
    dry_run: bool,
    confirm_live_run: bool = False,
) -> LabRequest:
    return LabRequest(
        provider=PROVIDER_NAME,
        profile=ORACLE_LIVE_SUITE,
        seed=0,
        roles=[
            LabRole(name="libcrafter", planned_ipv4=PLANNED_LIBCRAFTER_LAN_ADDRESS),
            LabRole(name="reference_backend", planned_ipv4=PLANNED_REFERENCE_LAN_ADDRESS),
        ],
        dry_run=dry_run,
        confirm_live_run=confirm_live_run,
        workload_label=ORACLE_LIVE_SUITE,
        metadata={
            "session_id": ORACLE_LIVE_SUITE,
            "role_lan_ipv4s": {
                "libcrafter": PLANNED_LIBCRAFTER_LAN_ADDRESS,
                "reference_backend": PLANNED_REFERENCE_LAN_ADDRESS,
            },
        },
    )


def _oracle_planned_infrastructure(*, dry_run: bool) -> JSONObject:
    request = _oracle_lab_request(dry_run=dry_run)
    infrastructure = VIRTUALBOX_LAB_PROVIDER_ADAPTER.planned_infrastructure(request)
    network = infrastructure.get("network")
    if isinstance(network, dict):
        network.setdefault("bridge_interface_env", network.get("bridge_env", BRIDGE_INTERFACE_ENV))
    provider_capabilities = infrastructure.get("provider_capabilities")
    if isinstance(provider_capabilities, dict):
        provider_capabilities["capability_report_artifact"] = CAPABILITY_REPORT_ARTIFACT
    infrastructure.setdefault("wire_policy", dict(VIRTUALBOX_WIRE_POLICY))
    return infrastructure


def _oracle_packet_exchange_metadata(*, dry_run: bool) -> JSONObject:
    return {
        "provider": PROVIDER_NAME,
        "wire_provider": VIRTUALBOX_LAB_PROVIDER_ADAPTER.wire_provider,
        "wire_exposure": VIRTUALBOX_LAB_PROVIDER_ADAPTER.wire_exposure,
        "endpoint_roles": ["libcrafter", "reference_backend"],
        "private_group": None,
        "isolated_network": False,
        "private_network": False,
        "bridged_lan": True,
        "packet_exchange_network": VIRTUALBOX_LAB_PROVIDER_ADAPTER.wire_exposure,
        "packet_exchange_network_label": "virtualbox-bridged-lan",
        "address_source": "guest-lan-interface-discovery",
        "bridge_interface_env": BRIDGE_INTERFACE_ENV,
        "dry_run": dry_run,
    }


def _oracle_planned_endpoints(*, dry_run: bool) -> dict[str, LiveEndpoint]:
    request = _oracle_lab_request(
        dry_run=dry_run,
        confirm_live_run=not dry_run,
    )
    roles = VIRTUALBOX_LAB_PROVIDER_ADAPTER.plan_roles(request)
    endpoints: dict[str, LiveEndpoint] = {}
    for role in roles:
        manifest = _planned_manifest_for_role(role, request=request)
        lab_endpoint = VIRTUALBOX_LAB_PROVIDER_ADAPTER.normalize_endpoint(
            manifest,
            role=role,
            peer_roles=_peer_roles_for(role, roles),
            request=request,
        )
        endpoints[role.name] = live_endpoint_from_lab_endpoint(lab_endpoint)
    return endpoints


def _oracle_wire_endpoint_plan(
    *,
    dry_run: bool,
    client: wire_client.WireClient | None = None,
    confirm_live_run: bool = False,
    created_endpoint_ids: list[str] | None = None,
) -> dict[str, object]:
    request = _oracle_lab_request(
        dry_run=dry_run,
        confirm_live_run=confirm_live_run,
    )
    plan = VIRTUALBOX_LAB_PROVIDER_ADAPTER.wire_endpoint_plan(
        request,
        client=_OracleLabWireClient(client or wire_client.WireClient()),
        created_endpoint_ids=created_endpoint_ids,
    )
    return _oracle_wire_plan_from_lab_plan(plan)


def _oracle_wire_plan_from_lab_plan(plan: JSONObject) -> dict[str, object]:
    endpoints: dict[str, LiveEndpoint] = {}
    raw_endpoints = plan.get("endpoints")
    if isinstance(raw_endpoints, Mapping):
        for role, endpoint in raw_endpoints.items():
            if isinstance(role, str) and isinstance(endpoint, Mapping):
                endpoints[role] = live_endpoint_from_lab_endpoint(endpoint)
    return {
        **plan,
        "wire_exposure": plan.get("exposure", VIRTUALBOX_LAB_PROVIDER_ADAPTER.wire_exposure),
        "command_metadata": plan.get("command_records", []),
        "live_endpoints": endpoints,
    }


def _oracle_provider_workflow(*, dry_run: bool) -> list[LiveCommandPlan]:
    request = _oracle_lab_request(
        dry_run=dry_run,
        confirm_live_run=not dry_run,
    )
    commands = [
        _live_provider_command_from_lab(command)
        for command in VIRTUALBOX_LAB_PROVIDER_ADAPTER.provider_workflow(request)
    ]
    insert_at = next(
        (
            index
            for index, command in enumerate(commands)
            if command.purpose == "collect-live-endpoint-artifacts"
        ),
        len(commands),
    )
    commands.insert(
        insert_at,
        LiveCommandPlan(
            role="provider",
            purpose="run-oracle-live-exchange-suite",
            argv=[
                WIRE_ENTRYPOINT,
                "exec",
                "<endpoint-id>",
                "--",
                "tools/oracle/run",
                "live-endpoint",
                "--suite",
                ORACLE_LIVE_SUITE,
            ],
            sends_live_packets=False,
            expects_live_packets=False,
            metadata={
                "provider": PROVIDER_NAME,
                "exposure": VIRTUALBOX_LAB_PROVIDER_ADAPTER.wire_exposure,
                "dry_run": dry_run,
                "creates_infrastructure": False,
                "would_create_infrastructure": False,
                "oracle_two_endpoint": True,
                "private_network": False,
                "bridged_lan": True,
                "bridge_interface_env": BRIDGE_INTERFACE_ENV,
                "wire_policy": dict(VIRTUALBOX_WIRE_POLICY),
                "wire_command": True,
                "operation": "exec",
            },
        ),
    )
    return commands


def _live_provider_command_from_lab(command: LabCommandPlan) -> LiveCommandPlan:
    metadata: JSONObject = dict(command.metadata)
    metadata["lab_operation"] = command.operation
    metadata["operation"] = _oracle_operation(command.operation)
    metadata.setdefault("provider", PROVIDER_NAME)
    metadata.setdefault("exposure", VIRTUALBOX_LAB_PROVIDER_ADAPTER.wire_exposure)
    metadata.setdefault("private_network", False)
    metadata.setdefault("bridged_lan", True)
    metadata.setdefault("bridge_interface_env", BRIDGE_INTERFACE_ENV)
    metadata.setdefault("wire_policy", dict(VIRTUALBOX_WIRE_POLICY))
    metadata.setdefault("wire_command", True)
    return LiveCommandPlan(
        role="provider",
        purpose=_oracle_workflow_purpose(command),
        argv=list(command.argv),
        sends_live_packets=False,
        expects_live_packets=False,
        metadata=metadata,
    )


def _oracle_workflow_purpose(command: LabCommandPlan) -> str:
    if command.operation == "wire.doctor":
        return "check-virtualbox-provider"
    if command.operation == "wire.create":
        suffix = "libcrafter" if command.role == "libcrafter" else "reference"
        return f"create-{suffix}-lan-wire-endpoint"
    if command.operation == "wire.collect_artifacts":
        return "collect-live-endpoint-artifacts"
    if command.operation == "wire.destroy":
        return "teardown-disposable-virtualbox-endpoints"
    return command.purpose


def _oracle_operation(operation: str) -> str:
    return {
        "wire.doctor": "doctor",
        "wire.create": "create",
        "wire.collect_artifacts": "download",
        "wire.destroy": "destroy",
    }.get(operation, operation)


def _peer_roles_for(role: LabRole, roles: Sequence[LabRole]) -> list[LabRole]:
    if role.peer_roles:
        requested = set(role.peer_roles)
        return [peer for peer in roles if peer.name in requested]
    return [peer for peer in roles if peer.name != role.name]


def _planned_manifest_for_role(role: LabRole, *, request: LabRequest) -> EndpointManifest:
    return EndpointManifest(
        endpoint_id=f"virtualbox-planned-{role.name}",
        provider=VIRTUALBOX_LAB_PROVIDER_ADAPTER.wire_provider,
        exposure=VIRTUALBOX_LAB_PROVIDER_ADAPTER.wire_exposure,
        status="planned" if request.dry_run else "created",
        role=role.name,
        created_at="1970-01-01T00:00:00Z",
        ssh=EndpointSSHInfo(host="127.0.0.1", user="root"),
        interfaces=[
            NetworkInterface(
                name="lan",
                exposure=VIRTUALBOX_LAB_PROVIDER_ADAPTER.wire_exposure,
                ipv4=role.planned_ipv4,
                metadata={
                    "bridge_interface": "auto",
                    "bridge_selection": "auto",
                    "bridge_env": BRIDGE_INTERFACE_ENV,
                    "type": "bridged-lan",
                },
            )
        ],
        provider_resources=ProviderResources(),
        artifact_dir=f"/tmp/libcrafter-wire/{PROVIDER_NAME}/{role.name}",
        metadata={
            "planned": True,
            "bridge_interface": "auto",
            "bridge_selection": "auto",
            "bridge_env": BRIDGE_INTERFACE_ENV,
            "type": "bridged-lan",
        },
    )


@dataclass(frozen=True, slots=True)
class _LabWireCreateResponse:
    source: object
    manifest: EndpointManifest
    json_data: JSONObject
    provider: str
    exposure: str
    role: str
    dry_run: bool

    def command_plan(
        self,
        *,
        purpose: str | None = None,
        role: str | None = None,
        artifacts: Sequence[str] = (),
    ) -> LabCommandPlan:
        metadata = _source_record_metadata(self.source)
        metadata.update(
            {
                "provider": self.provider,
                "exposure": self.exposure,
                "private_group": None,
                "private_ip": None,
                "private_network": False,
                "bridged_lan": True,
                "bridge_interface_env": BRIDGE_INTERFACE_ENV,
                "wire_policy": dict(VIRTUALBOX_WIRE_POLICY),
                "wire_command": True,
            }
        )
        return LabCommandPlan(
            purpose=purpose or f"create {self.role} endpoint",
            role=role or self.role,
            argv=_wire_create_argv(
                provider=self.provider,
                exposure=self.exposure,
                role=self.role,
                dry_run=self.dry_run,
            ),
            operation="wire.create",
            dry_run=self.dry_run,
            live_mutation=not self.dry_run,
            artifacts=list(artifacts),
            metadata=metadata,
        )


class _OracleLabWireClient:
    def __init__(self, client: object) -> None:
        self._client = client

    def create(
        self,
        *,
        provider: str,
        exposure: str,
        role: str,
        private_group: str | None,
        private_ip: str | None,
        dry_run: bool,
        write_manifest: bool,
        confirm_live_run: bool,
    ) -> _LabWireCreateResponse:
        create = getattr(self._client, "create")
        try:
            response = create(
                provider=provider,
                exposure=exposure,
                role=role,
                private_group=private_group,
                private_ip=private_ip,
                dry_run=dry_run,
                write_manifest=write_manifest,
                confirm_live_run=confirm_live_run,
            )
        except TypeError:
            response = create(
                provider=provider,
                exposure=exposure,
                role=role,
                private_group=private_group,
                private_ip=private_ip,
                dry_run=dry_run,
                confirm_live_run=confirm_live_run,
            )
        manifest = _response_manifest_for_lab(
            response,
            provider=provider,
            exposure=exposure,
            role=role,
            dry_run=dry_run,
        )
        json_data = _response_json_for_lab(response, manifest)
        return _LabWireCreateResponse(
            source=response,
            manifest=manifest,
            json_data=json_data,
            provider=provider,
            exposure=exposure,
            role=role,
            dry_run=dry_run,
        )


def _response_manifest_for_lab(
    response: object,
    *,
    provider: str,
    exposure: str,
    role: str,
    dry_run: bool,
) -> EndpointManifest:
    manifest = getattr(response, "manifest", None)
    if isinstance(manifest, EndpointManifest):
        return manifest
    json_data = getattr(response, "json_data", None)
    if isinstance(json_data, Mapping):
        return _manifest_from_wire_json(
            json_data,
            provider=provider,
            exposure=exposure,
            role=role,
            dry_run=dry_run,
        )
    endpoint_id = getattr(manifest, "endpoint_id", None)
    return _manifest_from_wire_json(
        {"endpoint_id": endpoint_id} if isinstance(endpoint_id, str) else {},
        provider=provider,
        exposure=exposure,
        role=role,
        dry_run=dry_run,
    )


def _response_json_for_lab(response: object, manifest: EndpointManifest) -> JSONObject:
    json_data = getattr(response, "json_data", None)
    if isinstance(json_data, Mapping):
        return {str(key): value for key, value in json_data.items() if isinstance(key, str)}
    return manifest.to_dict()


def _manifest_from_wire_json(
    data: Mapping[str, object],
    *,
    provider: str,
    exposure: str,
    role: str,
    dry_run: bool,
) -> EndpointManifest:
    endpoint_id = data.get("endpoint_id")
    interfaces = data.get("interfaces")
    interface_models = (
        [
            _network_interface_from_json(interface)
            for interface in interfaces
            if isinstance(interface, Mapping)
        ]
        if isinstance(interfaces, list)
        else []
    )
    if not interface_models:
        interface_models = [
            NetworkInterface(
                name="lan",
                exposure=exposure,
                metadata={
                    "bridge_interface": "auto",
                    "bridge_selection": "auto",
                    "bridge_env": BRIDGE_INTERFACE_ENV,
                    "type": "bridged-lan",
                },
            )
        ]
    metadata = data.get("metadata")
    return EndpointManifest(
        endpoint_id=endpoint_id if isinstance(endpoint_id, str) else f"{provider}-{exposure}-{role}",
        provider=provider,
        exposure=exposure,
        status="planned" if dry_run else "created",
        role=role,
        created_at="1970-01-01T00:00:00Z",
        ssh=EndpointSSHInfo(host="127.0.0.1", user="root"),
        interfaces=interface_models,
        provider_resources=ProviderResources(),
        artifact_dir=f"/tmp/libcrafter-wire/{provider}/{role}",
        metadata={
            **({str(key): value for key, value in metadata.items() if isinstance(key, str)}
               if isinstance(metadata, Mapping) else {}),
            "bridge_env": BRIDGE_INTERFACE_ENV,
        },
    )


def _network_interface_from_json(value: Mapping[str, object]) -> NetworkInterface:
    metadata = value.get("metadata")
    return NetworkInterface(
        name=_string_or(value.get("name"), "lan"),
        exposure=_string_or(value.get("exposure"), "lan"),
        ipv4=_optional_string(value.get("ipv4")),
        ipv6=_optional_string(value.get("ipv6")),
        mac=_optional_string(value.get("mac")),
        provider_network_id=_optional_string(value.get("provider_network_id")),
        metadata={
            str(key): item
            for key, item in metadata.items()
            if isinstance(key, str)
        } if isinstance(metadata, Mapping) else {},
    )


def _source_record_metadata(response: object) -> JSONObject:
    record = getattr(response, "record", None)
    if record is not None:
        to_dict = getattr(record, "to_dict", None)
        if callable(to_dict):
            value = to_dict()
            if isinstance(value, Mapping):
                return {str(key): item for key, item in value.items() if isinstance(key, str)}
    return {}


def _wire_create_argv(
    *,
    provider: str,
    exposure: str,
    role: str,
    dry_run: bool,
) -> list[str]:
    argv = [
        WIRE_ENTRYPOINT,
        "create-endpoint",
        "--provider",
        provider,
        "--exposure",
        exposure,
        "--role",
        role,
        "--json",
    ]
    if dry_run:
        argv.append("--dry-run")
    return argv


@dataclass(frozen=True, slots=True)
class VirtualBoxLiveProviderAdapter:
    """Oracle live adapter for the local VirtualBox bridged-LAN wire lab."""

    name: str = PROVIDER_NAME
    wire_provider: str = PROVIDER_NAME
    wire_exposure: str = "lan"
    endpoint_roles: tuple[str, str] = ("libcrafter", "reference_backend")
    private_group: str | None = None
    endpoint_private_ips: Mapping[str, str] = field(default_factory=dict)
    artifact_collection_purpose: str = "collect-live-endpoint-artifacts"
    teardown_purpose: str = "teardown-disposable-virtualbox-endpoints"
    credential_label: str = "VirtualBox host prerequisites"
    missing_credential_reason: str = "missing VirtualBox host prerequisites"

    def token_configured(self) -> bool:
        """Return whether VirtualBox execution passes the generic credential gate."""

        return virtualbox_token_configured()

    def default_provider_capabilities(
        self,
        *,
        dry_run: bool,
        source: str = "planned-defaults",
    ) -> JSONObject:
        """Return VirtualBox capability defaults before endpoint discovery."""

        return virtualbox_default_provider_capabilities(dry_run=dry_run, source=source)

    def normalize_provider_capabilities(
        self,
        raw: JSONObject,
        *,
        dry_run: bool | None = None,
        source: str | None = None,
    ) -> JSONObject:
        """Normalize VirtualBox provider capabilities for corpus filtering."""

        return normalize_virtualbox_provider_capabilities(
            raw,
            dry_run=dry_run,
            source=source,
        )

    def planned_infrastructure(self, *, dry_run: bool) -> JSONObject:
        """Return planned VirtualBox LAN lab infrastructure."""

        return virtualbox_lan_plan(dry_run=dry_run)

    def packet_exchange_metadata(self, *, dry_run: bool) -> JSONObject:
        """Return VirtualBox packet-exchange network metadata."""

        return virtualbox_packet_exchange_metadata(dry_run=dry_run)

    def endpoints(self, *, dry_run: bool) -> dict[str, LiveEndpoint]:
        """Return the two VirtualBox endpoint roles."""

        return virtualbox_endpoints(dry_run=dry_run)

    def wire_endpoint_plan(
        self,
        *,
        dry_run: bool,
        client: wire_client.WireClient | None = None,
        private_group: str | None = None,
        confirm_live_run: bool = False,
        created_endpoint_ids: list[str] | None = None,
    ) -> dict[str, object]:
        """Create or plan the two VirtualBox LAN wire endpoints."""

        if private_group is not None:
            raise ValueError("VirtualBox oracle live adapter does not support private_group")
        return virtualbox_wire_endpoint_plan(
            dry_run=dry_run,
            client=client,
            confirm_live_run=confirm_live_run,
            created_endpoint_ids=created_endpoint_ids,
        )

    def provider_workflow(self, *, dry_run: bool) -> list[LiveCommandPlan]:
        """Return VirtualBox provider lifecycle command plans."""

        return virtualbox_provider_workflow(dry_run=dry_run)

    def endpoint_bootstrap_plan(self, *, dry_run: bool) -> list[LiveCommandPlan]:
        """Return VirtualBox endpoint bootstrap command plans."""

        return virtualbox_endpoint_bootstrap_plan(dry_run=dry_run)

    def validate_provider_workflow(
        self,
        commands: list[LiveCommandPlan],
        *,
        dry_run: bool,
    ) -> LiveValidationCheck:
        """Validate VirtualBox provider lifecycle planning."""

        return validate_virtualbox_provider_workflow(commands, dry_run=dry_run)

    def validate_endpoint_bootstrap(
        self,
        commands: list[LiveCommandPlan],
        *,
        dry_run: bool,
    ) -> LiveValidationCheck:
        """Validate VirtualBox endpoint bootstrap planning."""

        return validate_virtualbox_endpoint_bootstrap(commands, dry_run=dry_run)

    def validate_dry_run_exchange(
        self,
        exchange: LiveExchangePlan,
    ) -> LiveValidationCheck:
        """Validate a VirtualBox provider-backed dry-run exchange."""

        return validate_virtualbox_dry_run_exchange(exchange)

    def remote_dir(self) -> str:
        """Return the remote repository directory for VirtualBox wire endpoints."""

        return virtualbox_wire_remote_dir()

    def endpoint_bootstrap_command(
        self,
        *,
        endpoint: LiveEndpoint,
        peer: LiveEndpoint,
        remote_archive: str,
        remote_dir: str,
    ) -> list[str]:
        """Return the VirtualBox repository bootstrap command for one endpoint."""

        return virtualbox_endpoint_bootstrap_command(
            endpoint=endpoint,
            peer=peer,
            remote_archive=remote_archive,
            remote_dir=remote_dir,
        )

    def endpoint_bootstrap_command_hook(self):
        """Return the lab repository bootstrap hook for VirtualBox endpoints."""

        return virtualbox_endpoint_bootstrap_command_hook()

    def endpoint_remote_command(
        self,
        *,
        endpoint_role: str,
        remote_dir: str,
        request_path: str,
        out_dir: str,
    ) -> list[str]:
        """Return the VirtualBox endpoint protocol command for one role."""

        return virtualbox_endpoint_remote_command(
            endpoint_role=endpoint_role,
            remote_dir=remote_dir,
            request_path=request_path,
            out_dir=out_dir,
        )

    def apply_transit_plan(self, plan: PacketPlan) -> PacketPlan:
        """Apply VirtualBox live policy without provider transit rewrites."""

        return virtualbox_live_transit_plan(plan)

    def wire_comparison_policy(self, plan: PacketPlan) -> JSONObject:
        """Return the VirtualBox wire comparison policy for one packet."""

        return virtualbox_wire_comparison_policy(plan)


VIRTUALBOX_LIVE_PROVIDER_ADAPTER: LiveProviderAdapter = VirtualBoxLiveProviderAdapter()
