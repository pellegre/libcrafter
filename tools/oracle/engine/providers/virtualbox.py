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

from .base import LiveProviderAdapter
from .policy import wire_comparison_policy
from .. import wire_client
from ..live import (
    LiveCommandPlan,
    LiveEndpoint,
    LiveExchangePlan,
    LiveValidationCheck,
)
from ..model import JSONObject, PacketPlan


PROVIDER_NAME = "virtualbox"
WIRE_ENTRYPOINT = "tools/wire/run"
ORACLE_LIVE_SUITE = "oracle-live"
BRIDGE_INTERFACE_ENV = "LIBCRAFTER_VBOX_BRIDGE_IFACE"
PLANNED_LIBCRAFTER_LAN_ADDRESS = "192.0.2.110"
PLANNED_REFERENCE_LAN_ADDRESS = "192.0.2.120"
LIBCRAFTER_BOOTSTRAP_PACKAGES = [
    "build-essential",
    "ca-certificates",
    "clang",
    "curl",
    "git",
    "iproute2",
    "iputils-ping",
    "libpcap-dev",
    "pkg-config",
    "python3",
]
REFERENCE_BOOTSTRAP_PACKAGES = [
    "ca-certificates",
    "curl",
    "git",
    "iproute2",
    "iputils-ping",
    "python3",
]
PYTHON_DEPENDENCY_RUNNER = "uv"
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

    capabilities: JSONObject = {
        "provider": PROVIDER_NAME,
        "dry_run": dry_run,
        "source": source,
        "live_packet_exchange": True,
        "ipv4_unicast": True,
        "ipv6_unicast": False,
        "link_layer_send": False,
        "link_layer_capture": False,
        "broadcast": False,
        "provider_mac_known": False,
        "controlled_services": True,
        "controlled_router": False,
        "capability_report_artifact": CAPABILITY_REPORT_ARTIFACT,
        "wire_policy": dict(VIRTUALBOX_WIRE_POLICY),
        "checks": {
            "ipv4_unicast": {
                "status": "planned" if dry_run else "manifest_required",
                "value": True,
                "reason": "VirtualBox LAN endpoint IPv4 addresses come from guest discovery",
            },
            "ipv6_unicast": {
                "status": "not_planned",
                "value": False,
                "reason": "VirtualBox oracle LAN endpoints are currently IPv4-only",
            },
            "link_layer_send": {
                "status": "not_proven",
                "value": False,
                "reason": "link-layer frame preservation is not assumed by default",
            },
            "link_layer_capture": {
                "status": "not_proven",
                "value": False,
                "reason": "link-layer capture preservation is not assumed by default",
            },
            "broadcast": {
                "status": "not_proven",
                "value": False,
                "reason": "broadcast delivery is not part of the VirtualBox smoke profile",
            },
            "provider_mac_known": {
                "status": "manifest_required",
                "value": False,
                "reason": "real bootstrap records LAN interface MACs after provisioning",
            },
            "controlled_services": {
                "status": "planned" if dry_run else "default",
                "value": True,
                "reason": "both VirtualBox endpoints are controlled by endpoint bootstrap",
            },
            "controlled_router": {
                "status": "not_available",
                "value": False,
                "reason": "the VirtualBox bridged LAN lab is same-segment, not routed transit",
            },
        },
    }
    return normalize_virtualbox_provider_capabilities(capabilities)


def normalize_virtualbox_provider_capabilities(
    raw: JSONObject,
    *,
    dry_run: bool | None = None,
    source: str | None = None,
) -> JSONObject:
    """Return flat capability keys plus legacy aliases consumed by corpus logic."""

    capabilities = raw.get("capabilities")
    if isinstance(capabilities, dict):
        base = {key: value for key, value in raw.items() if key != "capabilities"}
        base.update(
            {
                key: value
                for key, value in capabilities.items()
                if isinstance(key, str)
            }
        )
    else:
        base = dict(raw)

    if dry_run is not None:
        base["dry_run"] = dry_run
    if source is not None:
        base["source"] = source
    base.setdefault("provider", PROVIDER_NAME)
    base.setdefault("live_packet_exchange", True)
    base.setdefault("wire_policy", dict(VIRTUALBOX_WIRE_POLICY))

    for key in PROVIDER_CAPABILITY_NAMES:
        base[key] = bool(base.get(key, False))

    base["ipv4"] = bool(base["ipv4_unicast"])
    base["ipv6"] = bool(base["ipv6_unicast"])
    base["l2"] = bool(base["link_layer_send"] and base["link_layer_capture"])
    base["provider_mac"] = bool(base["provider_mac_known"])
    base["controlled_service"] = bool(base["controlled_services"])
    base["capability_names"] = list(PROVIDER_CAPABILITY_NAMES)
    return base


def virtualbox_token_configured() -> bool:
    """Return whether VirtualBox execution passes the generic credential gate."""

    return True


def virtualbox_lan_plan(*, dry_run: bool) -> JSONObject:
    """Return local VM resources required for an oracle VirtualBox LAN lab."""

    provider_capabilities = virtualbox_default_provider_capabilities(dry_run=dry_run)
    return {
        "provider": PROVIDER_NAME,
        "dry_run": dry_run,
        "creates_infrastructure": not dry_run,
        "would_create_infrastructure": dry_run,
        "network": {
            "resource_type": "virtualbox-bridged-lan",
            "wire_exposure": "lan",
            "bridge_interface_env": BRIDGE_INTERFACE_ENV,
            "bridge_interface": os.environ.get(BRIDGE_INTERFACE_ENV) or "auto",
            "address_source": "guest-lan-interface-discovery",
        },
        "servers": [
            {
                "role": "libcrafter",
                "name_suffix": "libcrafter",
                "planned_lan_address": PLANNED_LIBCRAFTER_LAN_ADDRESS,
            },
            {
                "role": "reference_backend",
                "name_suffix": "reference",
                "planned_lan_address": PLANNED_REFERENCE_LAN_ADDRESS,
            },
        ],
        "resource_counts": {
            "vms": 2,
            "bridged_lan_adapters": 2,
            "nat_control_adapters": 2,
            "ssh_keys": 2,
        },
        "public_network_policy": "bridged_lan_packet_exchange",
        "packet_exchange_network": "lan",
        "provider_capabilities": provider_capabilities,
        "endpoint_bootstrap": {
            "repository_sync": "both_endpoints",
            "libcrafter": {
                "system_packages": LIBCRAFTER_BOOTSTRAP_PACKAGES,
                "python_dependency_runner": PYTHON_DEPENDENCY_RUNNER,
                "uv": "install_if_missing",
                "rust": "install_if_missing",
                "validation": "cargo build -p oracle-adapters --bin live_endpoint",
                "artifact": "live-artifacts/bootstrap/libcrafter/bootstrap.env",
                "capability_artifact": CAPABILITY_REPORT_ARTIFACT,
            },
            "reference_backend": {
                "system_packages": REFERENCE_BOOTSTRAP_PACKAGES,
                "python_dependency_runner": PYTHON_DEPENDENCY_RUNNER,
                "uv": "install_if_missing",
                "validation": "tools/oracle/run backend-info --backend scapy",
                "tshark": {
                    "availability_reported": True,
                    "required_for_scapy_live_exchange": False,
                },
                "artifact": "live-artifacts/bootstrap/reference_backend/bootstrap.env",
                "capability_artifact": CAPABILITY_REPORT_ARTIFACT,
            },
        },
    }


def virtualbox_packet_exchange_metadata(*, dry_run: bool) -> JSONObject:
    """Return packet-exchange network metadata for the VirtualBox LAN lab."""

    return {
        "provider": PROVIDER_NAME,
        "wire_provider": PROVIDER_NAME,
        "wire_exposure": "lan",
        "endpoint_roles": ["libcrafter", "reference_backend"],
        "private_group": None,
        "isolated_network": False,
        "private_network": False,
        "bridged_lan": True,
        "packet_exchange_network": "lan",
        "packet_exchange_network_label": "virtualbox-bridged-lan",
        "address_source": "guest-lan-interface-discovery",
        "bridge_interface_env": BRIDGE_INTERFACE_ENV,
        "dry_run": dry_run,
    }


def virtualbox_endpoints(*, dry_run: bool) -> dict[str, LiveEndpoint]:
    """Return planned endpoint roles for VirtualBox reports."""

    return _with_peer_metadata(
        {
            "libcrafter": _planned_virtualbox_endpoint(
                role="libcrafter",
                address=PLANNED_LIBCRAFTER_LAN_ADDRESS,
                peer_role="reference_backend",
                peer_address=PLANNED_REFERENCE_LAN_ADDRESS,
                dry_run=dry_run,
            ),
            "reference_backend": _planned_virtualbox_endpoint(
                role="reference_backend",
                address=PLANNED_REFERENCE_LAN_ADDRESS,
                peer_role="libcrafter",
                peer_address=PLANNED_LIBCRAFTER_LAN_ADDRESS,
                dry_run=dry_run,
            ),
        }
    )


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

    wire = client or wire_client.WireClient()
    roles = (
        ("libcrafter", PLANNED_LIBCRAFTER_LAN_ADDRESS),
        ("reference_backend", PLANNED_REFERENCE_LAN_ADDRESS),
    )
    endpoint_plans: list[JSONObject] = []
    endpoints: dict[str, LiveEndpoint] = {}
    command_records: list[JSONObject] = []
    for role, planned_address in roles:
        response = wire.create(
            provider=PROVIDER_NAME,
            exposure="lan",
            role=role,
            dry_run=dry_run,
            confirm_live_run=confirm_live_run,
        )
        if not dry_run and created_endpoint_ids is not None and response.manifest is not None:
            created_endpoint_ids.append(response.manifest.endpoint_id)
        command_records.append(response.record.to_dict())
        endpoint_plan = response.json_data or response.metadata()
        endpoint_plans.append(endpoint_plan)
        endpoints[role] = _live_endpoint_from_wire_plan(
            endpoint_plan,
            role=role,
            planned_address=planned_address,
            dry_run=dry_run,
        )

    endpoints = _with_peer_metadata(endpoints)
    return {
        "provider": PROVIDER_NAME,
        "wire_provider": PROVIDER_NAME,
        "exposure": "lan",
        "dry_run": dry_run,
        "private_group": None,
        "endpoint_count": len(endpoint_plans),
        "command_metadata": command_records,
        "endpoint_plans": endpoint_plans,
        "endpoints": {role: endpoint.to_dict() for role, endpoint in endpoints.items()},
        "live_endpoints": endpoints,
    }


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

    dry_run_flag = ["--dry-run"] if dry_run else []
    create_guard = [] if dry_run else ["--confirm-live-run"]
    workflow = [
        (
            "doctor",
            "check-virtualbox-provider",
            [
                WIRE_ENTRYPOINT,
                "doctor",
                "--provider",
                PROVIDER_NAME,
                "--exposure",
                "lan",
                *dry_run_flag,
                "--json",
            ],
        ),
        (
            "create",
            "create-libcrafter-lan-wire-endpoint",
            [
                WIRE_ENTRYPOINT,
                "create-endpoint",
                "--provider",
                PROVIDER_NAME,
                "--exposure",
                "lan",
                "--role",
                "libcrafter",
                *dry_run_flag,
                *create_guard,
                "--json",
                "--write-manifest",
            ],
        ),
        (
            "create",
            "create-reference-lan-wire-endpoint",
            [
                WIRE_ENTRYPOINT,
                "create-endpoint",
                "--provider",
                PROVIDER_NAME,
                "--exposure",
                "lan",
                "--role",
                "reference_backend",
                *dry_run_flag,
                *create_guard,
                "--json",
                "--write-manifest",
            ],
        ),
        (
            "exec",
            "run-oracle-live-exchange-suite",
            [
                WIRE_ENTRYPOINT,
                "exec",
                "<endpoint-id>",
                "--",
                "tools/oracle/run",
                "live-endpoint",
                "--suite",
                ORACLE_LIVE_SUITE,
            ],
        ),
        (
            "download",
            "collect-live-endpoint-artifacts",
            [WIRE_ENTRYPOINT, "download", "<endpoint-id>", "<remote>", "<local>"],
        ),
        (
            "destroy",
            "teardown-disposable-virtualbox-endpoints",
            [WIRE_ENTRYPOINT, "destroy-endpoint", "<endpoint-id>", "--json"],
        ),
    ]
    commands: list[LiveCommandPlan] = []
    for operation, purpose, argv in workflow:
        commands.append(
            LiveCommandPlan(
                role="provider",
                purpose=purpose,
                argv=list(argv),
                sends_live_packets=False,
                expects_live_packets=False,
                metadata={
                    "provider": PROVIDER_NAME,
                    "exposure": "lan",
                    "dry_run": dry_run,
                    "creates_infrastructure": operation == "create" and not dry_run,
                    "would_create_infrastructure": operation == "create" and dry_run,
                    "always_attempt": operation in {"download", "destroy"},
                    "oracle_two_endpoint": True,
                    "private_network": False,
                    "bridged_lan": True,
                    "bridge_interface_env": BRIDGE_INTERFACE_ENV,
                    "wire_command": True,
                    "operation": operation,
                },
            )
        )
    return commands


def virtualbox_endpoint_bootstrap_plan(*, dry_run: bool) -> list[LiveCommandPlan]:
    """Plan role-specific endpoint bootstrap work for the VirtualBox LAN lab."""

    provider_capabilities = virtualbox_default_provider_capabilities(dry_run=dry_run)
    return [
        LiveCommandPlan(
            role="libcrafter",
            purpose="bootstrap-libcrafter-endpoint",
            argv=[
                "bash",
                "-lc",
                (
                    "sync-repository && apt-get install libcrafter packages && "
                    "rustup install-if-missing && "
                    "cargo build -p oracle-adapters --bin live_endpoint"
                ),
            ],
            sends_live_packets=False,
            expects_live_packets=False,
            metadata={
                "provider": PROVIDER_NAME,
                "dry_run": dry_run,
                "repository_sync": True,
                "private_network": False,
                "bridged_lan": True,
                "bridge_interface_env": BRIDGE_INTERFACE_ENV,
                "system_packages": LIBCRAFTER_BOOTSTRAP_PACKAGES,
                "python_dependency_runner": PYTHON_DEPENDENCY_RUNNER,
                "uv": "install_if_missing",
                "rust": "install_if_missing",
                "validation": "cargo build -p oracle-adapters --bin live_endpoint",
                "artifact_path": "live-artifacts/bootstrap/libcrafter/bootstrap.env",
                "capability_artifact": CAPABILITY_REPORT_ARTIFACT,
                "provider_capabilities": provider_capabilities,
            },
        ),
        LiveCommandPlan(
            role="reference_backend",
            purpose="bootstrap-reference-endpoint",
            argv=[
                "bash",
                "-lc",
                (
                    "sync-repository && apt-get install reference packages && "
                    "tools/oracle/run backend-info --backend scapy && "
                    "report optional tshark availability"
                ),
            ],
            sends_live_packets=False,
            expects_live_packets=False,
            metadata={
                "provider": PROVIDER_NAME,
                "backend": "scapy",
                "dry_run": dry_run,
                "repository_sync": True,
                "private_network": False,
                "bridged_lan": True,
                "bridge_interface_env": BRIDGE_INTERFACE_ENV,
                "system_packages": REFERENCE_BOOTSTRAP_PACKAGES,
                "python_dependency_runner": PYTHON_DEPENDENCY_RUNNER,
                "uv": "install_if_missing",
                "validation": "tools/oracle/run backend-info --backend scapy",
                "tshark": {
                    "availability_reported": True,
                    "required_for_scapy_live_exchange": False,
                },
                "artifact_path": "live-artifacts/bootstrap/reference_backend/bootstrap.env",
                "capability_artifact": CAPABILITY_REPORT_ARTIFACT,
                "provider_capabilities": provider_capabilities,
            },
        ),
    ]


def validate_virtualbox_endpoint_bootstrap(
    commands: list[LiveCommandPlan],
    *,
    dry_run: bool,
) -> LiveValidationCheck:
    """Validate that both VirtualBox endpoint roles are bootstrapped."""

    errors: list[str] = []
    commands_by_role = {command.role: command for command in commands}
    for role in ("libcrafter", "reference_backend"):
        if role not in commands_by_role:
            errors.append(f"missing endpoint bootstrap role: {role}")

    for command in commands:
        if command.sends_live_packets or command.expects_live_packets:
            errors.append("endpoint bootstrap commands cannot exchange live packets")
        if command.metadata.get("provider") != PROVIDER_NAME:
            errors.append(f"endpoint bootstrap must target VirtualBox: {command.role}")
        if not bool(command.metadata.get("repository_sync")):
            errors.append(f"endpoint bootstrap must sync repository: {command.role}")
        if bool(command.metadata.get("private_network")):
            errors.append(f"endpoint bootstrap must not require private network: {command.role}")
        if not bool(command.metadata.get("bridged_lan")):
            errors.append(f"endpoint bootstrap must preserve bridged LAN topology: {command.role}")
        if not command.metadata.get("artifact_path"):
            errors.append(f"endpoint bootstrap must write artifacts: {command.role}")
        if command.metadata.get("capability_artifact") != CAPABILITY_REPORT_ARTIFACT:
            errors.append(f"endpoint bootstrap must report capabilities: {command.role}")

    libcrafter = commands_by_role.get("libcrafter")
    if libcrafter is not None:
        packages = set(libcrafter.metadata.get("system_packages", []))
        for package in ("libpcap-dev", "pkg-config", "clang"):
            if package not in packages:
                errors.append(f"libcrafter bootstrap missing package: {package}")
        if libcrafter.metadata.get("python_dependency_runner") != PYTHON_DEPENDENCY_RUNNER:
            errors.append("libcrafter bootstrap must use uv for Python dependencies")
        if libcrafter.metadata.get("uv") != "install_if_missing":
            errors.append("libcrafter bootstrap must install uv when missing")
        if libcrafter.metadata.get("rust") != "install_if_missing":
            errors.append("libcrafter bootstrap must install Rust when missing")
        if (
            libcrafter.metadata.get("validation")
            != "cargo build -p oracle-adapters --bin live_endpoint"
        ):
            errors.append("libcrafter bootstrap must validate live_endpoint build")

    reference = commands_by_role.get("reference_backend")
    if reference is not None:
        packages = set(reference.metadata.get("system_packages", []))
        for package in ("python3", "curl"):
            if package not in packages:
                errors.append(f"reference bootstrap missing package: {package}")
        if reference.metadata.get("python_dependency_runner") != PYTHON_DEPENDENCY_RUNNER:
            errors.append("reference bootstrap must use uv for Python dependencies")
        if reference.metadata.get("uv") != "install_if_missing":
            errors.append("reference bootstrap must install uv when missing")
        if reference.metadata.get("validation") != (
            "tools/oracle/run backend-info --backend scapy"
        ):
            errors.append("reference bootstrap must validate Scapy backend availability")
        tshark = reference.metadata.get("tshark")
        if not isinstance(tshark, dict):
            errors.append("reference bootstrap must report tshark availability")
        elif tshark.get("required_for_scapy_live_exchange") is not False:
            errors.append("tshark must remain optional for Scapy live exchange")

    return LiveValidationCheck(
        name="virtualbox-endpoint-bootstrap",
        passed=not errors,
        subject="libcrafter,reference_backend",
        errors=errors,
        metadata={
            "provider": PROVIDER_NAME,
            "dry_run": dry_run,
            "endpoint_count": 2,
            "repository_sync": "both_endpoints",
            "bridged_lan": True,
            "tshark_required": False,
        },
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

    remote_dir = os.environ.get("LIBCRAFTER_WIRE_REMOTE_DIR") or "/root/libcrafter"
    if not remote_dir.startswith("/"):
        raise RuntimeError("VirtualBox wire remote_dir must be an absolute path")
    if "'" in remote_dir:
        raise RuntimeError("VirtualBox wire remote_dir must not contain single quotes")
    return remote_dir.rstrip("/") or "/"


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

    return [
        "bash",
        "-lc",
        _virtualbox_endpoint_bootstrap_script(
            endpoint=endpoint,
            peer=peer,
            remote_archive=remote_archive,
            remote_dir=remote_dir,
        ),
    ]


def _virtualbox_endpoint_bootstrap_script(
    *,
    endpoint: LiveEndpoint,
    peer: LiveEndpoint,
    remote_archive: str,
    remote_dir: str,
) -> str:
    role = shlex.quote(endpoint.role)
    lan_ipv4 = shlex.quote(endpoint.address)
    peer_lan_ipv4 = shlex.quote(peer.address)
    lan_interface = shlex.quote(endpoint.interface)
    quoted_archive = shlex.quote(remote_archive)
    quoted_remote_dir = shlex.quote(remote_dir)

    common = "\n".join(
        [
            "set -euo pipefail",
            "if command -v cloud-init >/dev/null 2>&1; then "
            "cloud-init status --wait >/dev/null 2>&1 || true; fi",
            f"rm -rf {quoted_remote_dir}",
            f"mkdir -p {quoted_remote_dir}",
            f"tar -xzf {quoted_archive} -C {quoted_remote_dir}",
            f"cd {quoted_remote_dir}",
            f"export LIBCRAFTER_ENDPOINT_ROLE={role}",
            f"export LIBCRAFTER_LAN_IPV4={lan_ipv4}",
            f"export LIBCRAFTER_PEER_LAN_IPV4={peer_lan_ipv4}",
            f"export LIBCRAFTER_LAN_INTERFACE={lan_interface}",
            "export DEBIAN_FRONTEND=noninteractive",
            "mkdir -p \"live-artifacts/bootstrap/$LIBCRAFTER_ENDPOINT_ROLE\"",
            "apt-get update",
        ]
    )
    install_uv = "\n".join(
        [
            "install_uv() {",
            "  if ! command -v uv >/dev/null 2>&1; then",
            "    curl -LsSf https://astral.sh/uv/install.sh | sh",
            "    export PATH=\"$HOME/.local/bin:$PATH\"",
            "    ln -sf \"$(command -v uv)\" /usr/local/bin/uv || true",
            "  fi",
            "  export PATH=\"$HOME/.local/bin:$PATH\"",
            "  command -v uv >/dev/null 2>&1",
            "}",
            "install_uv",
        ]
    )
    if endpoint.role == "libcrafter":
        return "\n".join(
            [
                common,
                (
                    "apt-get install -y --no-install-recommends "
                    "build-essential ca-certificates clang curl git iproute2 "
                    "iputils-ping libpcap-dev pkg-config python3"
                ),
                install_uv,
                "if ! command -v cargo >/dev/null 2>&1; then "
                "curl -fsS https://sh.rustup.rs | sh -s -- -y; fi",
                "if [ -f \"$HOME/.cargo/env\" ]; then . \"$HOME/.cargo/env\"; fi",
                "cargo build -p oracle-adapters --bin live_endpoint",
                "{",
                "  echo \"role=$LIBCRAFTER_ENDPOINT_ROLE\"",
                "  echo \"lan_ipv4=$LIBCRAFTER_LAN_IPV4\"",
                "  echo \"peer_lan_ipv4=$LIBCRAFTER_PEER_LAN_IPV4\"",
                "  echo \"lan_interface=$LIBCRAFTER_LAN_INTERFACE\"",
                "  echo \"repository_synced=true\"",
                "  echo \"python_dependency_runner=uv\"",
                "  echo \"uv=$(command -v uv)\"",
                "  echo \"rustc=$(rustc --version)\"",
                "  echo \"cargo=$(cargo --version)\"",
                "  echo \"libcrafter_oracle_bin=live_endpoint\"",
                "  echo \"libcrafter_oracle_bin_build=ok\"",
                "  echo \"finished_at=$(date -u +\"%Y-%m-%dT%H:%M:%SZ\")\"",
                "} > \"live-artifacts/bootstrap/$LIBCRAFTER_ENDPOINT_ROLE/bootstrap.env\"",
            ]
        )

    return "\n".join(
        [
            common,
            (
                "apt-get install -y --no-install-recommends "
                "ca-certificates curl git iproute2 iputils-ping python3"
            ),
            install_uv,
            "tools/oracle/run backend-info --backend scapy "
            "> \"live-artifacts/bootstrap/$LIBCRAFTER_ENDPOINT_ROLE/reference-backend.json\"",
            "if command -v tshark >/dev/null 2>&1; then "
            "tshark_available=true; else tshark_available=false; fi",
            "{",
            "  echo \"role=$LIBCRAFTER_ENDPOINT_ROLE\"",
            "  echo \"lan_ipv4=$LIBCRAFTER_LAN_IPV4\"",
            "  echo \"peer_lan_ipv4=$LIBCRAFTER_PEER_LAN_IPV4\"",
            "  echo \"lan_interface=$LIBCRAFTER_LAN_INTERFACE\"",
            "  echo \"repository_synced=true\"",
            "  echo \"python_dependency_runner=uv\"",
            "  echo \"uv=$(command -v uv)\"",
            "  echo \"reference_backend_info=ok\"",
            "  echo \"tshark_available=$tshark_available\"",
            "  echo \"tshark_required=false\"",
            "  echo \"finished_at=$(date -u +\"%Y-%m-%dT%H:%M:%SZ\")\"",
            "} > \"live-artifacts/bootstrap/$LIBCRAFTER_ENDPOINT_ROLE/bootstrap.env\"",
        ]
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
