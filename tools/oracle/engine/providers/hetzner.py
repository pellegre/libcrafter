"""Hetzner oracle live orchestration planning.

This adapter models the oracle-specific two-endpoint Hetzner lab. The dry-run
path is intentionally report-only: it does not invoke provider commands, create
infrastructure, or send packets.
"""

from __future__ import annotations

import os
import shlex
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace

from .base import LiveProviderAdapter
from ..live import (
    LiveCommandPlan,
    LiveEndpoint,
    LiveExchangePlan,
    LiveValidationCheck,
)
from ..model import JSONObject, PacketPlan
from .. import wire_client


PROVIDER_NAME = "hetzner"
WIRE_ENTRYPOINT = "tools/wire/run"
ORACLE_LIVE_SUITE = "oracle-live"
ORACLE_PRIVATE_GROUP = "oracle-live-private"
PRIVATE_NETWORK_CIDR = "10.42.19.0/24"
PRIVATE_NETWORK_ZONE = "provider-selected"
LIBCRAFTER_PRIVATE_ADDRESS = "10.42.19.10"
REFERENCE_PRIVATE_ADDRESS = "10.42.19.20"
LIBCRAFTER_PRIVATE_IPV6_ADDRESS = "fd42:19::10"
REFERENCE_PRIVATE_IPV6_ADDRESS = "fd42:19::20"
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


def hetzner_default_provider_capabilities(
    *,
    dry_run: bool,
    source: str = "planned-defaults",
) -> JSONObject:
    """Return conservative Hetzner capability defaults used before discovery."""

    capabilities = {
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
        "checks": {
            "ipv4_unicast": {
                "status": "planned" if dry_run else "default",
                "value": True,
                "reason": "Hetzner private network endpoint IPv4 addresses are planned",
            },
            "ipv6_unicast": {
                "status": "not_planned",
                "value": False,
                "reason": "private-network IPv6 is not configured by the current lab bootstrap",
            },
            "link_layer_send": {
                "status": "not_proven",
                "value": False,
                "reason": "link-layer frame preservation is not assumed for the provider path",
            },
            "link_layer_capture": {
                "status": "not_proven",
                "value": False,
                "reason": "link-layer capture preservation is not assumed for the provider path",
            },
            "broadcast": {
                "status": "not_proven",
                "value": False,
                "reason": "broadcast delivery is not assumed for the provider private network",
            },
            "provider_mac_known": {
                "status": "manifest_required",
                "value": False,
                "reason": "real bootstrap records provider interface MACs after provisioning",
            },
            "controlled_services": {
                "status": "planned" if dry_run else "default",
                "value": True,
                "reason": "both disposable endpoints are controlled by the endpoint bootstrap",
            },
            "controlled_router": {
                "status": "not_available",
                "value": False,
                "reason": "the two-endpoint lab has no controlled routed hop",
            },
        },
    }
    return normalize_hetzner_provider_capabilities(capabilities)


def normalize_hetzner_provider_capabilities(
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

    for key in PROVIDER_CAPABILITY_NAMES:
        base[key] = bool(base.get(key, False))

    base["ipv4"] = bool(base["ipv4_unicast"])
    base["ipv6"] = bool(base["ipv6_unicast"])
    base["l2"] = bool(base["link_layer_send"] and base["link_layer_capture"])
    base["provider_mac"] = bool(base["provider_mac_known"])
    base["controlled_service"] = bool(base["controlled_services"])
    base["capability_names"] = list(PROVIDER_CAPABILITY_NAMES)
    return base


def hetzner_token_configured() -> bool:
    """Return whether the process environment has Hetzner credentials."""

    return bool(os.environ.get("HETZNER_API_TOKEN") or os.environ.get("HCLOUD_TOKEN"))


def hetzner_private_network_plan(*, dry_run: bool) -> JSONObject:
    """Return the provider resources required for an oracle wire lab."""

    provider_capabilities = hetzner_default_provider_capabilities(dry_run=dry_run)
    return {
        "provider": PROVIDER_NAME,
        "dry_run": dry_run,
        "creates_infrastructure": not dry_run,
        "would_create_infrastructure": dry_run,
        "network": {
            "resource_type": "hetzner-cloud-network",
            "name_prefix": "oracle-adapters-live",
            "ip_range": PRIVATE_NETWORK_CIDR,
            "network_zone": PRIVATE_NETWORK_ZONE,
        },
        "servers": [
            {
                "role": "libcrafter",
                "name_suffix": "libcrafter",
                "private_address": LIBCRAFTER_PRIVATE_ADDRESS,
                "private_ipv6_address": LIBCRAFTER_PRIVATE_IPV6_ADDRESS,
            },
            {
                "role": "reference_backend",
                "name_suffix": "reference",
                "private_address": REFERENCE_PRIVATE_ADDRESS,
                "private_ipv6_address": REFERENCE_PRIVATE_IPV6_ADDRESS,
            },
        ],
        "resource_counts": {
            "servers": 2,
            "private_networks": 1,
            "ssh_keys": 1,
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


def hetzner_endpoints(*, dry_run: bool) -> dict[str, LiveEndpoint]:
    """Return deterministic endpoint roles for the Hetzner oracle lab."""

    common_metadata: JSONObject = {
        "provider": PROVIDER_NAME,
        "dry_run": dry_run,
        "creates_infrastructure": not dry_run,
        "would_create_infrastructure": dry_run,
        "isolated_network": True,
        "private_network": True,
        "private_network_cidr": PRIVATE_NETWORK_CIDR,
        "network_zone": PRIVATE_NETWORK_ZONE,
        "resource_type": "hetzner-cloud-server",
    }
    return {
        "libcrafter": LiveEndpoint(
            endpoint_id="hetzner-planned-libcrafter",
            role="libcrafter",
            interface="oracle0",
            address=LIBCRAFTER_PRIVATE_ADDRESS,
            ipv6_address=LIBCRAFTER_PRIVATE_IPV6_ADDRESS,
            metadata={
                **common_metadata,
                "peer_role": "reference_backend",
                "peer_address": REFERENCE_PRIVATE_ADDRESS,
            },
        ),
        "reference_backend": LiveEndpoint(
            endpoint_id="hetzner-planned-reference",
            role="reference_backend",
            interface="oracle0",
            address=REFERENCE_PRIVATE_ADDRESS,
            ipv6_address=REFERENCE_PRIVATE_IPV6_ADDRESS,
            metadata={
                **common_metadata,
                "backend": "scapy",
                "peer_role": "libcrafter",
                "peer_address": LIBCRAFTER_PRIVATE_ADDRESS,
            },
        ),
    }


def hetzner_wire_endpoint_plan(
    *,
    dry_run: bool,
    client: wire_client.WireClient | None = None,
    private_group: str = ORACLE_PRIVATE_GROUP,
    confirm_live_run: bool = False,
    created_endpoint_ids: list[str] | None = None,
) -> dict[str, object]:
    """Create or plan the two private wire endpoints used by Hetzner oracle runs."""

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
        endpoint_id=_string_or(endpoint_plan.get("endpoint_id"), f"planned-{role}"),
        role=role,
        interface=_string_or(interface.get("name"), "private"),
        address=address,
        ipv6_address=(
            LIBCRAFTER_PRIVATE_IPV6_ADDRESS
            if role == "libcrafter"
            else REFERENCE_PRIVATE_IPV6_ADDRESS
        ),
        metadata={
            "provider": PROVIDER_NAME,
            "exposure": "private",
            "dry_run": dry_run,
            "creates_infrastructure": not dry_run,
            "would_create_infrastructure": dry_run,
            "isolated_network": True,
            "private_network": True,
            "private_network_cidr": PRIVATE_NETWORK_CIDR,
            "network_zone": PRIVATE_NETWORK_ZONE,
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


def _string_or(value: object, default: str) -> str:
    return value if isinstance(value, str) and value else default


def hetzner_provider_workflow(*, dry_run: bool) -> list[LiveCommandPlan]:
    """Plan the provider lifecycle commands used by an oracle live run."""

    return _hetzner_wire_provider_workflow(dry_run=dry_run)


def _hetzner_wire_provider_workflow(*, dry_run: bool) -> list[LiveCommandPlan]:
    dry_run_flag = ["--dry-run"] if dry_run else []
    create_guard = [] if dry_run else ["--confirm-live-run"]
    workflow = [
        (
            "doctor",
            "check-hetzner-provider",
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
            "teardown-disposable-hetzner-endpoints",
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


def hetzner_endpoint_bootstrap_plan(*, dry_run: bool) -> list[LiveCommandPlan]:
    """Plan role-specific endpoint bootstrap work for the Hetzner lab."""

    provider_capabilities = hetzner_default_provider_capabilities(dry_run=dry_run)
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


def validate_hetzner_endpoint_bootstrap(
    commands: list[LiveCommandPlan],
    *,
    dry_run: bool,
) -> LiveValidationCheck:
    """Validate that both Hetzner endpoint roles are bootstrapped."""

    errors: list[str] = []
    commands_by_role = {command.role: command for command in commands}
    for role in ("libcrafter", "reference_backend"):
        if role not in commands_by_role:
            errors.append(f"missing endpoint bootstrap role: {role}")

    for command in commands:
        if command.sends_live_packets or command.expects_live_packets:
            errors.append("endpoint bootstrap commands cannot exchange live packets")
        if command.metadata.get("provider") != PROVIDER_NAME:
            errors.append(f"endpoint bootstrap must target Hetzner: {command.role}")
        if not bool(command.metadata.get("repository_sync")):
            errors.append(f"endpoint bootstrap must sync repository: {command.role}")
        if not bool(command.metadata.get("private_network")):
            errors.append(f"endpoint bootstrap must preserve private topology: {command.role}")
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
        if (
            libcrafter.metadata.get("python_dependency_runner")
            != PYTHON_DEPENDENCY_RUNNER
        ):
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
        if (
            reference.metadata.get("python_dependency_runner")
            != PYTHON_DEPENDENCY_RUNNER
        ):
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
        name="hetzner-endpoint-bootstrap",
        passed=not errors,
        subject="libcrafter,reference_backend",
        errors=errors,
        metadata={
            "provider": PROVIDER_NAME,
            "dry_run": dry_run,
            "endpoint_count": 2,
            "repository_sync": "both_endpoints",
            "private_network": True,
            "tshark_required": False,
        },
    )


def validate_hetzner_provider_workflow(
    commands: list[LiveCommandPlan],
    *,
    dry_run: bool,
) -> LiveValidationCheck:
    """Validate provider lifecycle planning invariants."""

    errors: list[str] = []
    purposes = {command.purpose for command in commands}
    required = {
        "check-hetzner-provider",
        "create-libcrafter-private-wire-endpoint",
        "create-reference-private-wire-endpoint",
        "run-oracle-live-exchange-suite",
        "collect-live-endpoint-artifacts",
        "teardown-disposable-hetzner-endpoints",
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
            errors.append("provider command must target Hetzner")
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
        name="hetzner-provider-workflow",
        passed=not errors,
        subject=PROVIDER_NAME,
        errors=errors,
        metadata={
            "provider": PROVIDER_NAME,
            "dry_run": dry_run,
            "creates_infrastructure": not dry_run,
            "always_collect_artifacts": True,
            "always_teardown": True,
        },
    )


def validate_hetzner_dry_run_exchange(
    exchange: LiveExchangePlan,
) -> LiveValidationCheck:
    """Validate that a Hetzner dry-run exchange is two-endpoint and non-mutating."""

    errors: list[str] = []
    if exchange.provider != PROVIDER_NAME:
        errors.append(f"unexpected provider: {exchange.provider}")
    if exchange.live_packet_exchange:
        errors.append("Hetzner dry-run cannot claim live packet exchange")
    if exchange.sender.role == exchange.receiver.role:
        errors.append("sender and receiver roles must differ")
    if not bool(exchange.sender.metadata.get("private_network")):
        errors.append("sender endpoint must use a private network")
    if not bool(exchange.receiver.metadata.get("private_network")):
        errors.append("receiver endpoint must use a private network")
    if exchange.sender.metadata.get("provider") != PROVIDER_NAME:
        errors.append("sender endpoint must be a Hetzner endpoint")
    if exchange.receiver.metadata.get("provider") != PROVIDER_NAME:
        errors.append("receiver endpoint must be a Hetzner endpoint")
    if (
        exchange.sender_command.sends_live_packets
        or exchange.receiver_command.sends_live_packets
    ):
        errors.append("Hetzner dry-run endpoint commands must not send packets")
    if (
        exchange.sender_command.expects_live_packets
        or exchange.receiver_command.expects_live_packets
    ):
        errors.append("Hetzner dry-run endpoint commands must not expect packets")

    return LiveValidationCheck(
        name="hetzner-dry-run-live-invariant",
        passed=not errors,
        subject=f"{exchange.direction}:index-{exchange.index:06d}",
        errors=errors,
        metadata={
            "provider": PROVIDER_NAME,
            "direction": exchange.direction,
            "packet_index": exchange.index,
            "private_network": True,
            "creates_infrastructure": False,
            "live_packet_exchange": False,
        },
    )


def hetzner_wire_remote_dir() -> str:
    """Return the repository directory used by Hetzner wire endpoints."""

    remote_dir = os.environ.get("LIBCRAFTER_WIRE_REMOTE_DIR") or "/root/libcrafter"
    if not remote_dir.startswith("/"):
        raise RuntimeError("Hetzner wire remote_dir must be an absolute path")
    if "'" in remote_dir:
        raise RuntimeError("Hetzner wire remote_dir must not contain single quotes")
    return remote_dir.rstrip("/") or "/"


def hetzner_endpoint_remote_command(
    *,
    endpoint_role: str,
    remote_dir: str,
    request_path: str,
    out_dir: str,
) -> list[str]:
    """Return the endpoint protocol command executed on a Hetzner wire endpoint."""

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


def hetzner_live_transit_plan(plan: PacketPlan) -> PacketPlan:
    """Apply Hetzner transit rewrites before expected-model generation."""

    fields = {
        layer: dict(layer_fields)
        for layer, layer_fields in plan.fields.items()
    }
    wire_policy = hetzner_wire_comparison_policy(plan)
    rewrites: list[JSONObject] = []
    ipv4 = fields.get("ipv4")
    if isinstance(ipv4, dict) and int(ipv4.get("ttl", 64)) < 2:
        rewrites.append(
            {
                "field": "ipv4.ttl",
                "from": ipv4.get("ttl"),
                "to": 64,
                "reason": "provider live transit decrements TTL before capture",
            }
        )
        ipv4["ttl"] = 64

    return replace(
        plan,
        fields=fields,
        strict_bytes=bool(wire_policy.get("strict_bytes", plan.strict_bytes)),
        metadata={
            **plan.metadata,
            "wire": wire_policy,
            "live_transit_rewrites": rewrites,
            "live_mutable_fields": list(wire_policy.get("mutable_fields", [])),
            "strict_bytes": bool(wire_policy.get("strict_bytes", plan.strict_bytes)),
        },
    )


def hetzner_wire_comparison_policy(plan: PacketPlan) -> JSONObject:
    """Return Hetzner wire comparison policy for one packet plan."""

    raw_policy = plan.metadata.get("wire")
    if isinstance(raw_policy, Mapping):
        policy = {
            key: value
            for key, value in raw_policy.items()
            if isinstance(key, str)
        }
    else:
        from .policy import wire_comparison_policy

        policy = wire_comparison_policy(plan, provider=PROVIDER_NAME)

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

    strict_bytes = policy.get("strict_bytes")
    if not isinstance(strict_bytes, bool):
        byte_mutable_fields = policy.get("byte_mutable_fields", policy["mutable_fields"])
        strict_bytes = bool(plan.strict_bytes and not byte_mutable_fields)
    policy["strict_bytes"] = strict_bytes

    compare_root = policy.get("compare_root")
    if compare_root is not None and not isinstance(compare_root, str):
        compare_root = None
    policy["compare_root"] = compare_root
    policy.setdefault("provider", PROVIDER_NAME)
    return policy


@dataclass(frozen=True, slots=True)
class HetznerLiveProviderAdapter:
    """Oracle live adapter for the existing Hetzner private wire lab."""

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
    teardown_purpose: str = "teardown-disposable-hetzner-endpoints"
    credential_label: str = "HETZNER_API_TOKEN"
    missing_credential_reason: str = "missing HETZNER_API_TOKEN"

    def token_configured(self) -> bool:
        """Return whether Hetzner credentials are present."""

        return hetzner_token_configured()

    def default_provider_capabilities(
        self,
        *,
        dry_run: bool,
        source: str = "planned-defaults",
    ) -> JSONObject:
        """Return Hetzner capability defaults before endpoint discovery."""

        return hetzner_default_provider_capabilities(dry_run=dry_run, source=source)

    def normalize_provider_capabilities(
        self,
        raw: JSONObject,
        *,
        dry_run: bool | None = None,
        source: str | None = None,
    ) -> JSONObject:
        """Normalize Hetzner provider capabilities for corpus filtering."""

        return normalize_hetzner_provider_capabilities(
            raw,
            dry_run=dry_run,
            source=source,
        )

    def planned_infrastructure(self, *, dry_run: bool) -> JSONObject:
        """Return planned Hetzner private lab infrastructure."""

        return hetzner_private_network_plan(dry_run=dry_run)

    def endpoints(self, *, dry_run: bool) -> dict[str, LiveEndpoint]:
        """Return the two Hetzner endpoint roles."""

        return hetzner_endpoints(dry_run=dry_run)

    def wire_endpoint_plan(
        self,
        *,
        dry_run: bool,
        client: wire_client.WireClient | None = None,
        private_group: str | None = None,
        confirm_live_run: bool = False,
        created_endpoint_ids: list[str] | None = None,
    ) -> dict[str, object]:
        """Create or plan the two Hetzner private wire endpoints."""

        return hetzner_wire_endpoint_plan(
            dry_run=dry_run,
            client=client,
            private_group=private_group or self.private_group or ORACLE_PRIVATE_GROUP,
            confirm_live_run=confirm_live_run,
            created_endpoint_ids=created_endpoint_ids,
        )

    def provider_workflow(self, *, dry_run: bool) -> list[LiveCommandPlan]:
        """Return Hetzner provider lifecycle command plans."""

        return hetzner_provider_workflow(dry_run=dry_run)

    def endpoint_bootstrap_plan(self, *, dry_run: bool) -> list[LiveCommandPlan]:
        """Return Hetzner endpoint bootstrap command plans."""

        return hetzner_endpoint_bootstrap_plan(dry_run=dry_run)

    def validate_provider_workflow(
        self,
        commands: list[LiveCommandPlan],
        *,
        dry_run: bool,
    ) -> LiveValidationCheck:
        """Validate Hetzner provider lifecycle planning."""

        return validate_hetzner_provider_workflow(commands, dry_run=dry_run)

    def validate_endpoint_bootstrap(
        self,
        commands: list[LiveCommandPlan],
        *,
        dry_run: bool,
    ) -> LiveValidationCheck:
        """Validate Hetzner endpoint bootstrap planning."""

        return validate_hetzner_endpoint_bootstrap(commands, dry_run=dry_run)

    def validate_dry_run_exchange(
        self,
        exchange: LiveExchangePlan,
    ) -> LiveValidationCheck:
        """Validate a Hetzner provider-backed dry-run exchange."""

        return validate_hetzner_dry_run_exchange(exchange)

    def remote_dir(self) -> str:
        """Return the remote repository directory for Hetzner wire endpoints."""

        return hetzner_wire_remote_dir()

    def endpoint_remote_command(
        self,
        *,
        endpoint_role: str,
        remote_dir: str,
        request_path: str,
        out_dir: str,
    ) -> list[str]:
        """Return the Hetzner endpoint protocol command for one role."""

        return hetzner_endpoint_remote_command(
            endpoint_role=endpoint_role,
            remote_dir=remote_dir,
            request_path=request_path,
            out_dir=out_dir,
        )

    def apply_transit_plan(self, plan: PacketPlan) -> PacketPlan:
        """Apply Hetzner transit rewrites before live comparison."""

        return hetzner_live_transit_plan(plan)

    def wire_comparison_policy(self, plan: PacketPlan) -> JSONObject:
        """Return the Hetzner wire comparison policy for one packet."""

        return hetzner_wire_comparison_policy(plan)


HETZNER_LIVE_PROVIDER_ADAPTER: LiveProviderAdapter = HetznerLiveProviderAdapter()
