"""Live oracle orchestration contracts.

The local dry-run provider validates orchestration plans only. It never sends
or captures packets and must not be treated as provider-backed live exchange.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field

from .model import JSONObject, JsonModel, PacketPlan


LOCAL_DRY_RUN_PROVIDER = "local-dry-run"
LIVE_PROTOCOL_SPEC = "tools/oracle/LIVE.md"
LIVE_SELECTED_SPECS = [
    LIVE_PROTOCOL_SPEC,
    "tools/oracle/specs/stacks.yaml",
    "tools/oracle/specs/profiles.yaml",
]
LIVE_EXCHANGE_DIRECTIONS = ("libcrafter_to_reference", "reference_to_libcrafter")


@dataclass(frozen=True, slots=True)
class LiveEndpoint(JsonModel):
    """One planned live endpoint role."""

    endpoint_id: str
    role: str
    interface: str
    address: str
    ipv6_address: str | None = None
    metadata: JSONObject = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class LiveCommandPlan(JsonModel):
    """A command that a live provider would run on an endpoint."""

    role: str
    purpose: str
    argv: list[str]
    sends_live_packets: bool = False
    expects_live_packets: bool = False
    metadata: JSONObject = field(default_factory=dict)

    def shell(self) -> str:
        return shlex.join(self.argv)


@dataclass(frozen=True, slots=True)
class LiveExchangePlan(JsonModel):
    """A planned live exchange phase."""

    provider: str
    backend: str
    direction: str
    index: int
    packet_plan: PacketPlan
    sender: LiveEndpoint
    receiver: LiveEndpoint
    sender_command: LiveCommandPlan
    receiver_command: LiveCommandPlan
    live_packet_exchange: bool = False
    metadata: JSONObject = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class LiveValidationCheck(JsonModel):
    """A validation performed on dry-run orchestration data."""

    name: str
    passed: bool
    subject: str
    errors: list[str] = field(default_factory=list)
    metadata: JSONObject = field(default_factory=dict)


def live_execution_directions(direction: str) -> list[str]:
    """Expand a live direction request into concrete one-way phases."""

    if direction == "live_exchange":
        return list(LIVE_EXCHANGE_DIRECTIONS)
    if direction in LIVE_EXCHANGE_DIRECTIONS:
        return [direction]
    raise ValueError(f"unsupported live direction: {direction}")


def local_dry_run_endpoints() -> dict[str, LiveEndpoint]:
    """Return the deterministic endpoint roles for local dry-run reports."""

    return {
        "libcrafter": LiveEndpoint(
            endpoint_id="local-dry-run-libcrafter",
            role="libcrafter",
            interface="dry-run0",
            address="192.0.2.10",
            ipv6_address="2001:db8:1::10",
            metadata={
                "provider": LOCAL_DRY_RUN_PROVIDER,
                "isolated_network": False,
                "live_packet_exchange": False,
            },
        ),
        "reference_backend": LiveEndpoint(
            endpoint_id="local-dry-run-reference",
            role="reference_backend",
            interface="dry-run1",
            address="192.0.2.20",
            ipv6_address="2001:db8:1::20",
            metadata={
                "provider": LOCAL_DRY_RUN_PROVIDER,
                "isolated_network": False,
                "live_packet_exchange": False,
            },
        ),
    }


def libcrafter_dry_run_command_plan(
    *,
    plan: PacketPlan,
    direction: str,
    role: str,
) -> LiveCommandPlan:
    """Build a libcrafter command plan that is safe for dry-run validation."""

    if role == "sender":
        purpose = "dry-run-materialize-libcrafter-vector"
        argv = [
            "cargo",
            "run",
            "-q",
            "-p",
            "crafter",
            "--example",
            "oracle_vectors",
            "--",
            "--json",
        ]
    elif role == "receiver":
        purpose = "dry-run-decode-reference-vector"
        argv = [
            "cargo",
            "run",
            "-q",
            "-p",
            "crafter",
            "--example",
            "oracle_decode_vectors",
            "--",
            "--input",
            f"artifacts/live/index-{plan.index:06d}.reference-vectors.json",
        ]
    else:
        raise ValueError(f"unsupported libcrafter live role: {role}")

    return LiveCommandPlan(
        role="libcrafter",
        purpose=purpose,
        argv=argv,
        sends_live_packets=False,
        expects_live_packets=False,
        metadata={
            "direction": direction,
            "packet_index": plan.index,
            "dry_run": True,
            "live_packet_exchange": False,
        },
    )


def validate_libcrafter_command_plan(command: LiveCommandPlan) -> LiveValidationCheck:
    """Validate that a libcrafter command plan remains dry-run only."""

    errors: list[str] = []
    argv = command.argv
    if command.role != "libcrafter":
        errors.append(f"unexpected libcrafter command role: {command.role}")
    expected_prefix = ["cargo", "run", "-q", "-p", "crafter", "--example"]
    if len(argv) < 8 or argv[:6] != expected_prefix:
        errors.append(
            "libcrafter command must use `cargo run -q -p crafter --example`"
        )
    elif argv[6] not in {"oracle_vectors", "oracle_decode_vectors"}:
        errors.append(f"unsupported libcrafter dry-run example: {argv[6]}")
    if "--live" in argv:
        errors.append("local dry-run libcrafter command must not include --live")
    if command.sends_live_packets:
        errors.append("local dry-run libcrafter command must not send live packets")
    if command.expects_live_packets:
        errors.append("local dry-run libcrafter command must not expect live packets")

    return LiveValidationCheck(
        name="libcrafter-command-plan",
        passed=not errors,
        subject=command.shell(),
        errors=errors,
        metadata={
            "purpose": command.purpose,
            "dry_run": True,
            "live_packet_exchange": False,
        },
    )


def validate_local_dry_run_exchange(exchange: LiveExchangePlan) -> LiveValidationCheck:
    """Validate provider invariants for a local dry-run exchange plan."""

    errors: list[str] = []
    if exchange.provider != LOCAL_DRY_RUN_PROVIDER:
        errors.append(f"unexpected dry-run provider: {exchange.provider}")
    if exchange.live_packet_exchange:
        errors.append("local-dry-run exchange cannot claim live packet exchange")
    if exchange.sender.role == exchange.receiver.role:
        errors.append("sender and receiver roles must differ")
    if (
        exchange.sender_command.sends_live_packets
        or exchange.receiver_command.sends_live_packets
    ):
        errors.append("local-dry-run exchange command cannot send live packets")
    if (
        exchange.sender_command.expects_live_packets
        or exchange.receiver_command.expects_live_packets
    ):
        errors.append("local-dry-run exchange command cannot expect live packets")

    return LiveValidationCheck(
        name="local-dry-run-live-invariant",
        passed=not errors,
        subject=f"{exchange.direction}:index-{exchange.index:06d}",
        errors=errors,
        metadata={
            "provider": exchange.provider,
            "direction": exchange.direction,
            "packet_index": exchange.index,
            "live_packet_exchange": False,
        },
    )
