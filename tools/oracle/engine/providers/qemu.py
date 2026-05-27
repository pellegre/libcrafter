"""QEMU oracle live orchestration planning.

This adapter maps the oracle two-endpoint live lab onto the local QEMU wire
provider. QEMU uses a private same-segment VM network, so it does not inherit
Hetzner's routed-transit TTL or checksum mutation policy.
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


PROVIDER_NAME = "qemu"
WIRE_ENTRYPOINT = "tools/wire/run"
ORACLE_LIVE_SUITE = "oracle-live"
ORACLE_PRIVATE_GROUP = "oracle-live-private"
PRIVATE_NETWORK_CIDR = "10.77.0.0/24"
LIBCRAFTER_PRIVATE_ADDRESS = "10.77.0.10"
REFERENCE_PRIVATE_ADDRESS = "10.77.0.20"
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
QEMU_WIRE_POLICY: JSONObject = {
    "ipv4_header_mutable": False,
    "l3_send_adds_link_layer_metadata": False,
    "transit_decrements_ipv4_ttl": False,
}


def qemu_default_provider_capabilities(
    *,
    dry_run: bool,
    source: str = "planned-defaults",
) -> JSONObject:
    """Return conservative QEMU private-network capability defaults."""

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
        "wire_policy": dict(QEMU_WIRE_POLICY),
        "checks": {
            "ipv4_unicast": {
                "status": "planned" if dry_run else "default",
                "value": True,
                "reason": "QEMU private endpoint IPv4 addresses are planned",
            },
            "ipv6_unicast": {
                "status": "not_planned",
                "value": False,
                "reason": "QEMU oracle private endpoints are currently IPv4-only",
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
                "reason": "broadcast delivery is not part of the QEMU smoke profile",
            },
            "provider_mac_known": {
                "status": "manifest_required",
                "value": False,
                "reason": "real bootstrap records private interface MACs after provisioning",
            },
            "controlled_services": {
                "status": "planned" if dry_run else "default",
                "value": True,
                "reason": "both QEMU endpoints are controlled by the endpoint bootstrap",
            },
            "controlled_router": {
                "status": "not_available",
                "value": False,
                "reason": "the QEMU private lab is same-segment, not routed transit",
            },
        },
    }
    return normalize_qemu_provider_capabilities(capabilities)


def normalize_qemu_provider_capabilities(
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
    base.setdefault("wire_policy", dict(QEMU_WIRE_POLICY))

    for key in PROVIDER_CAPABILITY_NAMES:
        base[key] = bool(base.get(key, False))

    base["ipv4"] = bool(base["ipv4_unicast"])
    base["ipv6"] = bool(base["ipv6_unicast"])
    base["l2"] = bool(base["link_layer_send"] and base["link_layer_capture"])
    base["provider_mac"] = bool(base["provider_mac_known"])
    base["controlled_service"] = bool(base["controlled_services"])
    base["capability_names"] = list(PROVIDER_CAPABILITY_NAMES)
    return base


def qemu_token_configured() -> bool:
    """Return whether QEMU provider execution can pass credential gating."""

    return True


def qemu_private_network_plan(*, dry_run: bool) -> JSONObject:
    """Return the local VM resources required for an oracle QEMU lab."""

    provider_capabilities = qemu_default_provider_capabilities(dry_run=dry_run)
    return {
        "provider": PROVIDER_NAME,
        "dry_run": dry_run,
        "creates_infrastructure": not dry_run,
        "would_create_infrastructure": dry_run,
        "network": {
            "resource_type": "qemu-private-segment",
            "private_group": ORACLE_PRIVATE_GROUP,
            "ip_range": PRIVATE_NETWORK_CIDR,
            "backend": "socket-mcast",
        },
        "servers": [
            {
                "role": "libcrafter",
                "name_suffix": "libcrafter",
                "private_address": LIBCRAFTER_PRIVATE_ADDRESS,
            },
            {
                "role": "reference_backend",
                "name_suffix": "reference",
                "private_address": REFERENCE_PRIVATE_ADDRESS,
            },
        ],
        "resource_counts": {
            "vms": 2,
            "private_groups": 1,
            "ssh_keys": 2,
        },
        "public_network_policy": "ssh_control_plane_only",
        "packet_exchange_network": "private",
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


def qemu_packet_exchange_metadata(*, dry_run: bool) -> JSONObject:
    """Return packet-exchange network metadata for the QEMU private lab."""

    return {
        "provider": PROVIDER_NAME,
        "wire_provider": PROVIDER_NAME,
        "wire_exposure": "private",
        "endpoint_roles": ["libcrafter", "reference_backend"],
        "private_group": ORACLE_PRIVATE_GROUP,
        "isolated_network": True,
        "private_network": True,
        "private_network_cidr": PRIVATE_NETWORK_CIDR,
        "packet_exchange_network": "private",
        "packet_exchange_network_label": "qemu-private-segment",
        "dry_run": dry_run,
    }


def qemu_endpoints(*, dry_run: bool) -> dict[str, LiveEndpoint]:
    """Return deterministic endpoint roles for the QEMU oracle lab."""

    common_metadata: JSONObject = {
        "provider": PROVIDER_NAME,
        "dry_run": dry_run,
        "creates_infrastructure": not dry_run,
        "would_create_infrastructure": dry_run,
        "isolated_network": True,
        "private_network": True,
        "private_network_cidr": PRIVATE_NETWORK_CIDR,
        "resource_type": "qemu-vm",
        "private_group": ORACLE_PRIVATE_GROUP,
    }
    return {
        "libcrafter": LiveEndpoint(
            endpoint_id="qemu-planned-libcrafter",
            role="libcrafter",
            interface="private",
            address=LIBCRAFTER_PRIVATE_ADDRESS,
            metadata={
                **common_metadata,
                "peer_role": "reference_backend",
                "peer_address": REFERENCE_PRIVATE_ADDRESS,
            },
        ),
        "reference_backend": LiveEndpoint(
            endpoint_id="qemu-planned-reference",
            role="reference_backend",
            interface="private",
            address=REFERENCE_PRIVATE_ADDRESS,
            metadata={
                **common_metadata,
                "backend": "scapy",
                "peer_role": "libcrafter",
                "peer_address": LIBCRAFTER_PRIVATE_ADDRESS,
            },
        ),
    }


def qemu_wire_endpoint_plan(
    *,
    dry_run: bool,
    client: wire_client.WireClient | None = None,
    private_group: str = ORACLE_PRIVATE_GROUP,
    confirm_live_run: bool = False,
    created_endpoint_ids: list[str] | None = None,
) -> dict[str, object]:
    """Create or plan the two private wire endpoints used by QEMU oracle runs."""

    wire = client or wire_client.WireClient()
    roles = (
        ("libcrafter", LIBCRAFTER_PRIVATE_ADDRESS, REFERENCE_PRIVATE_ADDRESS),
        ("reference_backend", REFERENCE_PRIVATE_ADDRESS, LIBCRAFTER_PRIVATE_ADDRESS),
    )
    endpoint_plans: list[JSONObject] = []
    endpoints: dict[str, LiveEndpoint] = {}
    command_records: list[JSONObject] = []
    for role, private_ip, peer_address in roles:
        response = wire.create(
            provider=PROVIDER_NAME,
            exposure="private",
            role=role,
            private_group=private_group,
            private_ip=private_ip,
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
            private_ip=private_ip,
            peer_address=peer_address,
            dry_run=dry_run,
        )

    return {
        "provider": PROVIDER_NAME,
        "wire_provider": PROVIDER_NAME,
        "exposure": "private",
        "dry_run": dry_run,
        "private_group": private_group,
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
    private_ip: str,
    peer_address: str,
    dry_run: bool,
) -> LiveEndpoint:
    interface = _private_interface(endpoint_plan)
    address = _string_or(interface.get("ipv4"), private_ip)
    return LiveEndpoint(
        endpoint_id=_string_or(endpoint_plan.get("endpoint_id"), f"qemu-planned-{role}"),
        role=role,
        interface=_string_or(interface.get("name"), "private"),
        address=address,
        ipv6_address=_optional_string(interface.get("ipv6")),
        metadata={
            "provider": PROVIDER_NAME,
            "exposure": "private",
            "dry_run": dry_run,
            "creates_infrastructure": not dry_run,
            "would_create_infrastructure": dry_run,
            "isolated_network": True,
            "private_network": True,
            "private_network_cidr": PRIVATE_NETWORK_CIDR,
            "resource_type": "wire-endpoint",
            "peer_role": (
                "reference_backend" if role == "libcrafter" else "libcrafter"
            ),
            "peer_address": peer_address,
            "wire_endpoint_plan": endpoint_plan,
            "manifest_path": endpoint_plan.get("manifest_path"),
            "artifact_dir": endpoint_plan.get("artifact_dir"),
            "private_group": _wire_private_group(endpoint_plan),
            "provider_network_id": interface.get("provider_network_id"),
            "mac_address": interface.get("mac"),
            **({"backend": "scapy"} if role == "reference_backend" else {}),
        },
    )


def _private_interface(endpoint_plan: JSONObject) -> JSONObject:
    interfaces = endpoint_plan.get("interfaces")
    if isinstance(interfaces, list):
        for item in interfaces:
            if isinstance(item, dict) and item.get("exposure") == "private":
                return {str(key): value for key, value in item.items() if isinstance(key, str)}
        for item in interfaces:
            if isinstance(item, dict):
                return {str(key): value for key, value in item.items() if isinstance(key, str)}
    return {}


def _wire_private_group(endpoint_plan: JSONObject) -> str | None:
    metadata = endpoint_plan.get("metadata")
    if isinstance(metadata, dict):
        private_group = metadata.get("private_group")
        if isinstance(private_group, str):
            return private_group
    interface = _private_interface(endpoint_plan)
    interface_metadata = interface.get("metadata")
    if isinstance(interface_metadata, dict):
        private_group = interface_metadata.get("private_group")
        if isinstance(private_group, str):
            return private_group
    return None


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _string_or(value: object, default: str) -> str:
    return value if isinstance(value, str) and value else default


def qemu_provider_workflow(*, dry_run: bool) -> list[LiveCommandPlan]:
    """Plan the provider lifecycle commands used by an oracle QEMU run."""

    dry_run_flag = ["--dry-run"] if dry_run else []
    create_guard = [] if dry_run else ["--confirm-live-run"]
    workflow = [
        (
            "doctor",
            "check-qemu-provider",
            [
                WIRE_ENTRYPOINT,
                "doctor",
                "--provider",
                PROVIDER_NAME,
                "--exposure",
                "private",
                *dry_run_flag,
                "--json",
            ],
        ),
        (
            "create",
            "create-libcrafter-private-wire-endpoint",
            [
                WIRE_ENTRYPOINT,
                "create-endpoint",
                "--provider",
                PROVIDER_NAME,
                "--exposure",
                "private",
                "--role",
                "libcrafter",
                "--private-group",
                ORACLE_PRIVATE_GROUP,
                "--private-ip",
                LIBCRAFTER_PRIVATE_ADDRESS,
                *dry_run_flag,
                *create_guard,
                "--json",
                "--write-manifest",
            ],
        ),
        (
            "create",
            "create-reference-private-wire-endpoint",
            [
                WIRE_ENTRYPOINT,
                "create-endpoint",
                "--provider",
                PROVIDER_NAME,
                "--exposure",
                "private",
                "--role",
                "reference_backend",
                "--private-group",
                ORACLE_PRIVATE_GROUP,
                "--private-ip",
                REFERENCE_PRIVATE_ADDRESS,
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
            "teardown-disposable-qemu-endpoints",
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
                    "exposure": "private",
                    "dry_run": dry_run,
                    "creates_infrastructure": operation == "create" and not dry_run,
                    "would_create_infrastructure": operation == "create" and dry_run,
                    "always_attempt": operation in {"download", "destroy"},
                    "oracle_two_endpoint": True,
                    "private_network": True,
                    "private_group": ORACLE_PRIVATE_GROUP,
                    "wire_command": True,
                    "operation": operation,
                },
            )
        )
    return commands


def qemu_endpoint_bootstrap_plan(*, dry_run: bool) -> list[LiveCommandPlan]:
    """Plan role-specific endpoint bootstrap work for the QEMU lab."""

    provider_capabilities = qemu_default_provider_capabilities(dry_run=dry_run)
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
                "private_network": True,
                "private_group": ORACLE_PRIVATE_GROUP,
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
                "private_network": True,
                "private_group": ORACLE_PRIVATE_GROUP,
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


def validate_qemu_endpoint_bootstrap(
    commands: list[LiveCommandPlan],
    *,
    dry_run: bool,
) -> LiveValidationCheck:
    """Validate that both QEMU endpoint roles are bootstrapped."""

    errors: list[str] = []
    commands_by_role = {command.role: command for command in commands}
    for role in ("libcrafter", "reference_backend"):
        if role not in commands_by_role:
            errors.append(f"missing endpoint bootstrap role: {role}")

    for command in commands:
        if command.sends_live_packets or command.expects_live_packets:
            errors.append("endpoint bootstrap commands cannot exchange live packets")
        if command.metadata.get("provider") != PROVIDER_NAME:
            errors.append(f"endpoint bootstrap must target QEMU: {command.role}")
        if not bool(command.metadata.get("repository_sync")):
            errors.append(f"endpoint bootstrap must sync repository: {command.role}")
        if not bool(command.metadata.get("private_network")):
            errors.append(f"endpoint bootstrap must preserve private topology: {command.role}")
        if command.metadata.get("private_group") != ORACLE_PRIVATE_GROUP:
            errors.append(f"endpoint bootstrap must use QEMU private group: {command.role}")
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
        name="qemu-endpoint-bootstrap",
        passed=not errors,
        subject="libcrafter,reference_backend",
        errors=errors,
        metadata={
            "provider": PROVIDER_NAME,
            "dry_run": dry_run,
            "endpoint_count": 2,
            "repository_sync": "both_endpoints",
            "private_network": True,
            "private_group": ORACLE_PRIVATE_GROUP,
            "tshark_required": False,
        },
    )


def validate_qemu_provider_workflow(
    commands: list[LiveCommandPlan],
    *,
    dry_run: bool,
) -> LiveValidationCheck:
    """Validate QEMU provider lifecycle planning invariants."""

    errors: list[str] = []
    purposes = {command.purpose for command in commands}
    required = {
        "check-qemu-provider",
        "create-libcrafter-private-wire-endpoint",
        "create-reference-private-wire-endpoint",
        "run-oracle-live-exchange-suite",
        "collect-live-endpoint-artifacts",
        "teardown-disposable-qemu-endpoints",
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
            errors.append("provider command must target QEMU")
        if command.metadata.get("private_group") != ORACLE_PRIVATE_GROUP:
            errors.append("provider command must use the QEMU oracle private group")
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
        name="qemu-provider-workflow",
        passed=not errors,
        subject=PROVIDER_NAME,
        errors=errors,
        metadata={
            "provider": PROVIDER_NAME,
            "dry_run": dry_run,
            "creates_infrastructure": not dry_run,
            "private_group": ORACLE_PRIVATE_GROUP,
            "always_collect_artifacts": True,
            "always_teardown": True,
        },
    )


def validate_qemu_dry_run_exchange(
    exchange: LiveExchangePlan,
) -> LiveValidationCheck:
    """Validate that a QEMU dry-run exchange is two-endpoint and non-mutating."""

    errors: list[str] = []
    if exchange.provider != PROVIDER_NAME:
        errors.append(f"unexpected provider: {exchange.provider}")
    if exchange.live_packet_exchange:
        errors.append("QEMU dry-run cannot claim live packet exchange")
    if exchange.sender.role == exchange.receiver.role:
        errors.append("sender and receiver roles must differ")
    if not bool(exchange.sender.metadata.get("private_network")):
        errors.append("sender endpoint must use a private network")
    if not bool(exchange.receiver.metadata.get("private_network")):
        errors.append("receiver endpoint must use a private network")
    if exchange.sender.metadata.get("private_group") != ORACLE_PRIVATE_GROUP:
        errors.append("sender endpoint must use the QEMU oracle private group")
    if exchange.receiver.metadata.get("private_group") != ORACLE_PRIVATE_GROUP:
        errors.append("receiver endpoint must use the QEMU oracle private group")
    if exchange.sender.metadata.get("provider") != PROVIDER_NAME:
        errors.append("sender endpoint must be a QEMU endpoint")
    if exchange.receiver.metadata.get("provider") != PROVIDER_NAME:
        errors.append("receiver endpoint must be a QEMU endpoint")
    if exchange.sender.address == exchange.receiver.address:
        errors.append("sender and receiver private addresses must differ")
    if (
        exchange.sender_command.sends_live_packets
        or exchange.receiver_command.sends_live_packets
    ):
        errors.append("QEMU dry-run endpoint commands must not send packets")
    if (
        exchange.sender_command.expects_live_packets
        or exchange.receiver_command.expects_live_packets
    ):
        errors.append("QEMU dry-run endpoint commands must not expect packets")

    return LiveValidationCheck(
        name="qemu-dry-run-live-invariant",
        passed=not errors,
        subject=f"{exchange.direction}:index-{exchange.index:06d}",
        errors=errors,
        metadata={
            "provider": PROVIDER_NAME,
            "direction": exchange.direction,
            "packet_index": exchange.index,
            "private_network": True,
            "private_group": ORACLE_PRIVATE_GROUP,
            "creates_infrastructure": False,
            "live_packet_exchange": False,
        },
    )


def qemu_wire_remote_dir() -> str:
    """Return the repository directory used by QEMU wire endpoints."""

    remote_dir = os.environ.get("LIBCRAFTER_WIRE_REMOTE_DIR") or "/root/libcrafter"
    if not remote_dir.startswith("/"):
        raise RuntimeError("QEMU wire remote_dir must be an absolute path")
    if "'" in remote_dir:
        raise RuntimeError("QEMU wire remote_dir must not contain single quotes")
    return remote_dir.rstrip("/") or "/"


def qemu_endpoint_remote_command(
    *,
    endpoint_role: str,
    remote_dir: str,
    request_path: str,
    out_dir: str,
) -> list[str]:
    """Return the endpoint protocol command executed on a QEMU wire endpoint."""

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


def qemu_endpoint_bootstrap_command(
    *,
    endpoint: LiveEndpoint,
    peer: LiveEndpoint,
    remote_archive: str,
    remote_dir: str,
) -> list[str]:
    """Return the repository bootstrap command for one QEMU endpoint."""

    return [
        "bash",
        "-lc",
        _qemu_endpoint_bootstrap_script(
            endpoint=endpoint,
            peer=peer,
            remote_archive=remote_archive,
            remote_dir=remote_dir,
        ),
    ]


def _qemu_endpoint_bootstrap_script(
    *,
    endpoint: LiveEndpoint,
    peer: LiveEndpoint,
    remote_archive: str,
    remote_dir: str,
) -> str:
    role = shlex.quote(endpoint.role)
    private_ipv4 = shlex.quote(endpoint.address)
    peer_private_ipv4 = shlex.quote(peer.address)
    private_interface = shlex.quote(endpoint.interface)
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
            f"export LIBCRAFTER_PRIVATE_IPV4={private_ipv4}",
            f"export LIBCRAFTER_PEER_PRIVATE_IPV4={peer_private_ipv4}",
            f"export LIBCRAFTER_PRIVATE_INTERFACE={private_interface}",
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
                "  echo \"private_ipv4=$LIBCRAFTER_PRIVATE_IPV4\"",
                "  echo \"peer_private_ipv4=$LIBCRAFTER_PEER_PRIVATE_IPV4\"",
                "  echo \"private_interface=$LIBCRAFTER_PRIVATE_INTERFACE\"",
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
            "  echo \"private_ipv4=$LIBCRAFTER_PRIVATE_IPV4\"",
            "  echo \"peer_private_ipv4=$LIBCRAFTER_PEER_PRIVATE_IPV4\"",
            "  echo \"private_interface=$LIBCRAFTER_PRIVATE_INTERFACE\"",
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


def qemu_live_transit_plan(plan: PacketPlan) -> PacketPlan:
    """Apply QEMU live policy without modeling provider-routed transit rewrites."""

    wire_policy = qemu_wire_comparison_policy(plan)
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


def qemu_wire_comparison_policy(plan: PacketPlan) -> JSONObject:
    """Return QEMU wire comparison policy for one packet plan."""

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
            provider_capabilities=qemu_default_provider_capabilities(dry_run=True),
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
class QemuLiveProviderAdapter:
    """Oracle live adapter for the local QEMU private wire lab."""

    name: str = PROVIDER_NAME
    wire_provider: str = PROVIDER_NAME
    wire_exposure: str = "private"
    endpoint_roles: tuple[str, str] = ("libcrafter", "reference_backend")
    private_group: str | None = ORACLE_PRIVATE_GROUP
    endpoint_private_ips: Mapping[str, str] = field(
        default_factory=lambda: {
            "libcrafter": LIBCRAFTER_PRIVATE_ADDRESS,
            "reference_backend": REFERENCE_PRIVATE_ADDRESS,
        }
    )
    artifact_collection_purpose: str = "collect-live-endpoint-artifacts"
    teardown_purpose: str = "teardown-disposable-qemu-endpoints"
    credential_label: str = "QEMU host prerequisites"
    missing_credential_reason: str = "missing QEMU host prerequisites"

    def token_configured(self) -> bool:
        """Return whether QEMU execution passes the generic credential gate."""

        return qemu_token_configured()

    def default_provider_capabilities(
        self,
        *,
        dry_run: bool,
        source: str = "planned-defaults",
    ) -> JSONObject:
        """Return QEMU capability defaults before endpoint discovery."""

        return qemu_default_provider_capabilities(dry_run=dry_run, source=source)

    def normalize_provider_capabilities(
        self,
        raw: JSONObject,
        *,
        dry_run: bool | None = None,
        source: str | None = None,
    ) -> JSONObject:
        """Normalize QEMU provider capabilities for corpus filtering."""

        return normalize_qemu_provider_capabilities(
            raw,
            dry_run=dry_run,
            source=source,
        )

    def planned_infrastructure(self, *, dry_run: bool) -> JSONObject:
        """Return planned QEMU private lab infrastructure."""

        return qemu_private_network_plan(dry_run=dry_run)

    def packet_exchange_metadata(self, *, dry_run: bool) -> JSONObject:
        """Return QEMU packet-exchange network metadata."""

        return qemu_packet_exchange_metadata(dry_run=dry_run)

    def endpoints(self, *, dry_run: bool) -> dict[str, LiveEndpoint]:
        """Return the two QEMU endpoint roles."""

        return qemu_endpoints(dry_run=dry_run)

    def wire_endpoint_plan(
        self,
        *,
        dry_run: bool,
        client: wire_client.WireClient | None = None,
        private_group: str | None = None,
        confirm_live_run: bool = False,
        created_endpoint_ids: list[str] | None = None,
    ) -> dict[str, object]:
        """Create or plan the two QEMU private wire endpoints."""

        return qemu_wire_endpoint_plan(
            dry_run=dry_run,
            client=client,
            private_group=private_group or self.private_group or ORACLE_PRIVATE_GROUP,
            confirm_live_run=confirm_live_run,
            created_endpoint_ids=created_endpoint_ids,
        )

    def provider_workflow(self, *, dry_run: bool) -> list[LiveCommandPlan]:
        """Return QEMU provider lifecycle command plans."""

        return qemu_provider_workflow(dry_run=dry_run)

    def endpoint_bootstrap_plan(self, *, dry_run: bool) -> list[LiveCommandPlan]:
        """Return QEMU endpoint bootstrap command plans."""

        return qemu_endpoint_bootstrap_plan(dry_run=dry_run)

    def validate_provider_workflow(
        self,
        commands: list[LiveCommandPlan],
        *,
        dry_run: bool,
    ) -> LiveValidationCheck:
        """Validate QEMU provider lifecycle planning."""

        return validate_qemu_provider_workflow(commands, dry_run=dry_run)

    def validate_endpoint_bootstrap(
        self,
        commands: list[LiveCommandPlan],
        *,
        dry_run: bool,
    ) -> LiveValidationCheck:
        """Validate QEMU endpoint bootstrap planning."""

        return validate_qemu_endpoint_bootstrap(commands, dry_run=dry_run)

    def validate_dry_run_exchange(
        self,
        exchange: LiveExchangePlan,
    ) -> LiveValidationCheck:
        """Validate a QEMU provider-backed dry-run exchange."""

        return validate_qemu_dry_run_exchange(exchange)

    def remote_dir(self) -> str:
        """Return the remote repository directory for QEMU wire endpoints."""

        return qemu_wire_remote_dir()

    def endpoint_bootstrap_command(
        self,
        *,
        endpoint: LiveEndpoint,
        peer: LiveEndpoint,
        remote_archive: str,
        remote_dir: str,
    ) -> list[str]:
        """Return the QEMU repository bootstrap command for one endpoint."""

        return qemu_endpoint_bootstrap_command(
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
        """Return the QEMU endpoint protocol command for one role."""

        return qemu_endpoint_remote_command(
            endpoint_role=endpoint_role,
            remote_dir=remote_dir,
            request_path=request_path,
            out_dir=out_dir,
        )

    def apply_transit_plan(self, plan: PacketPlan) -> PacketPlan:
        """Apply QEMU live policy without provider transit rewrites."""

        return qemu_live_transit_plan(plan)

    def wire_comparison_policy(self, plan: PacketPlan) -> JSONObject:
        """Return the QEMU wire comparison policy for one packet."""

        return qemu_wire_comparison_policy(plan)


QEMU_LIVE_PROVIDER_ADAPTER: LiveProviderAdapter = QemuLiveProviderAdapter()
