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

    return {
        "provider": PROVIDER_NAME,
        "dry_run": dry_run,
        "creates_infrastructure": not dry_run,
        "would_create_infrastructure": dry_run,
        "network": {
            "resource_type": "hetzner-cloud-network",
            "name_prefix": "libcrafter-oracle-live",
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
                },
            )
        )
    return commands


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
