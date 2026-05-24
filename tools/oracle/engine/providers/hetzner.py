"""Hetzner oracle live orchestration planning.

This adapter models the oracle-specific two-endpoint Hetzner lab. The dry-run
path is intentionally report-only: it does not invoke provider commands, create
infrastructure, or send packets.
"""

from __future__ import annotations

import os
from pathlib import Path

from ..live import (
    LiveCommandPlan,
    LiveEndpoint,
    LiveExchangePlan,
    LiveValidationCheck,
)
from ..model import JSONObject


PROVIDER_NAME = "hetzner"
LIVE_LAB_ENTRYPOINT = "tools/live-lab/libcrafter-live-lab"
ORACLE_LIVE_SUITE = "oracle-live"
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
    "libpcap-dev",
    "pkg-config",
    "python3",
]
REFERENCE_BOOTSTRAP_PACKAGES = [
    "ca-certificates",
    "curl",
    "git",
    "iproute2",
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
                "reason": "both disposable endpoints are controlled by the live-lab bootstrap",
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

    if os.environ.get("HETZNER_API_TOKEN"):
        return True

    env_file = Path(
        os.environ.get(
            "LIBCRAFTER_LIVE_LAB_ENV",
            "~/.config/libcrafter/live-test.env",
        )
    ).expanduser()
    try:
        lines = env_file.read_text(encoding="utf-8").splitlines()
    except OSError:
        return False

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("export "):
            stripped = stripped.removeprefix("export ").lstrip()
        if not stripped.startswith("HETZNER_API_TOKEN="):
            continue
        value = stripped.split("=", 1)[1].strip().strip("\"'")
        return bool(value)
    return False


def hetzner_private_network_plan(*, dry_run: bool) -> JSONObject:
    """Return the provider resources required for an oracle live lab."""

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
                "validation": "cargo build -p oracle-adapters --bin oracle_live_endpoint",
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


def hetzner_provider_workflow(*, dry_run: bool) -> list[LiveCommandPlan]:
    """Plan the provider lifecycle commands used by an oracle live run."""

    workflow = [
        ("doctor", "check-hetzner-provider"),
        ("create", "create-two-endpoint-private-network-lab"),
        ("run", "run-oracle-live-exchange-suite"),
        ("artifact", "collect-live-endpoint-artifacts"),
        ("destroy", "teardown-disposable-hetzner-lab"),
    ]
    commands: list[LiveCommandPlan] = []
    for command, purpose in workflow:
        argv = [LIVE_LAB_ENTRYPOINT, command, "--provider", PROVIDER_NAME]
        if command == "run":
            argv.extend(["--suite", ORACLE_LIVE_SUITE])
        if dry_run and command in {"doctor", "create", "run"}:
            argv.append("--dry-run")

        commands.append(
            LiveCommandPlan(
                role="provider",
                purpose=purpose,
                argv=argv,
                sends_live_packets=False,
                expects_live_packets=False,
                metadata={
                    "provider": PROVIDER_NAME,
                    "dry_run": dry_run,
                    "creates_infrastructure": (command == "create" and not dry_run),
                    "would_create_infrastructure": (command == "create" and dry_run),
                    "always_attempt": command in {"artifact", "destroy"},
                    "oracle_two_endpoint": True,
                    "private_network": True,
                    "runs_endpoint_bootstrap": command == "run",
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
                    "cargo build -p oracle-adapters --bin oracle_live_endpoint"
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
                "validation": "cargo build -p oracle-adapters --bin oracle_live_endpoint",
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
            != "cargo build -p oracle-adapters --bin oracle_live_endpoint"
        ):
            errors.append("libcrafter bootstrap must validate oracle_live_endpoint build")

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
        "create-two-endpoint-private-network-lab",
        "run-oracle-live-exchange-suite",
        "collect-live-endpoint-artifacts",
        "teardown-disposable-hetzner-lab",
    }
    missing = sorted(required - purposes)
    if missing:
        errors.append(f"missing provider workflow phases: {', '.join(missing)}")

    for command in commands:
        if command.role != "provider":
            errors.append(f"unexpected provider workflow role: {command.role}")
        if (
            len(command.argv) < 4
            or command.argv[0] != LIVE_LAB_ENTRYPOINT
            or command.argv[2:4] != ["--provider", PROVIDER_NAME]
        ):
            errors.append(f"provider command must route through {LIVE_LAB_ENTRYPOINT}")
        if PROVIDER_NAME not in command.argv:
            errors.append("provider command must target Hetzner")
        if dry_run and command.purpose in {
            "check-hetzner-provider",
            "create-two-endpoint-private-network-lab",
            "run-oracle-live-exchange-suite",
        } and "--dry-run" not in command.argv:
            errors.append(f"dry-run provider command lacks --dry-run: {command.shell()}")
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
