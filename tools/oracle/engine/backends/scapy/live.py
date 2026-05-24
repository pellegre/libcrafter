"""Scapy live backend dry-run planning helpers."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence

from ...live import LiveCommandPlan, LiveValidationCheck
from ...model import PacketPlan
from ..registry import BackendCapabilities, BackendRegistration, get_backend


BACKEND_NAME = "scapy"


def backend_bootstrap_command_plan() -> LiveCommandPlan:
    """Return the command plan that validates Scapy bootstrap availability."""

    return LiveCommandPlan(
        role="reference_backend",
        purpose="validate-scapy-bootstrap",
        argv=["tools/oracle/run", "backend-info", "--backend", BACKEND_NAME],
        sends_live_packets=False,
        expects_live_packets=False,
        metadata={
            "backend": BACKEND_NAME,
            "dry_run": True,
            "live_packet_exchange": False,
        },
    )


def dry_run_command_plan(
    *,
    plan: PacketPlan,
    direction: str,
    role: str,
    capabilities: BackendCapabilities | BackendRegistration | None = None,
) -> LiveCommandPlan:
    """Build a Scapy endpoint command plan for local dry-run validation."""

    _require_live_capability(capabilities)
    if role not in {"sender", "receiver"}:
        raise ValueError(f"unsupported Scapy live dry-run role: {role}")

    argv = [
        "python3",
        "-m",
        "engine.backends.scapy.live",
        "--dry-run",
        "--direction",
        direction,
        "--role",
        role,
        "--index",
        str(plan.index),
    ]
    if role == "sender":
        purpose = "dry-run-materialize-scapy-vector"
        argv.append("--emit-vector")
    else:
        purpose = "dry-run-decode-libcrafter-vector"
        argv.extend(
            [
                "--decode-vector",
                f"artifacts/live/index-{plan.index:06d}.libcrafter-vectors.json",
            ]
        )

    return LiveCommandPlan(
        role="reference_backend",
        purpose=purpose,
        argv=argv,
        sends_live_packets=False,
        expects_live_packets=False,
        metadata={
            "backend": BACKEND_NAME,
            "direction": direction,
            "packet_index": plan.index,
            "phase_role": role,
            "dry_run": True,
            "live_packet_exchange": False,
        },
    )


def validate_backend_bootstrap_command(command: LiveCommandPlan) -> LiveValidationCheck:
    """Validate the planned Scapy bootstrap command."""

    expected = backend_bootstrap_command_plan()
    errors: list[str] = []
    if command.role != "reference_backend":
        errors.append(f"unexpected Scapy bootstrap role: {command.role}")
    if command.argv != expected.argv:
        errors.append("Scapy bootstrap command must route through tools/oracle/run backend-info")
    if command.sends_live_packets or command.expects_live_packets:
        errors.append("Scapy bootstrap validation cannot send or expect live packets")

    return LiveValidationCheck(
        name="scapy-bootstrap-command-plan",
        passed=not errors,
        subject=command.shell(),
        errors=errors,
        metadata={
            "backend": BACKEND_NAME,
            "dry_run": True,
            "live_packet_exchange": False,
        },
    )


def validate_dry_run_command_plan(command: LiveCommandPlan) -> LiveValidationCheck:
    """Validate that a Scapy live command plan is dry-run only."""

    errors: list[str] = []
    argv = command.argv
    if command.role != "reference_backend":
        errors.append(f"unexpected Scapy command role: {command.role}")
    expected_prefix = [
        "python3",
        "-m",
        "engine.backends.scapy.live",
        "--dry-run",
        "--direction",
    ]
    if len(argv) < 9 or argv[:5] != expected_prefix:
        errors.append(
            "Scapy live command must invoke engine.backends.scapy.live with --dry-run"
        )
    if "--live" in argv:
        errors.append("local dry-run Scapy command must not include --live")
    if "--dry-run" not in argv:
        errors.append("local dry-run Scapy command must include --dry-run")
    if command.sends_live_packets:
        errors.append("local dry-run Scapy command must not send live packets")
    if command.expects_live_packets:
        errors.append("local dry-run Scapy command must not expect live packets")

    return LiveValidationCheck(
        name="scapy-command-plan",
        passed=not errors,
        subject=command.shell(),
        errors=errors,
        metadata={
            "backend": BACKEND_NAME,
            "purpose": command.purpose,
            "dry_run": True,
            "live_packet_exchange": False,
        },
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Emit dry-run Scapy endpoint metadata without sending packets."""

    parser = argparse.ArgumentParser(description="Scapy live dry-run endpoint helper.")
    parser.add_argument("--dry-run", action="store_true", help="required dry-run guard")
    parser.add_argument(
        "--direction",
        choices=("libcrafter_to_reference", "reference_to_libcrafter"),
        required=True,
    )
    parser.add_argument("--role", choices=("sender", "receiver"), required=True)
    parser.add_argument("--index", type=int, required=True)
    parser.add_argument("--emit-vector", action="store_true")
    parser.add_argument("--decode-vector")
    args = parser.parse_args(argv)

    if not args.dry_run:
        parser.error("Scapy live helper only supports --dry-run in this step")
    _require_live_capability(None)

    print(
        json.dumps(
            {
                "backend": BACKEND_NAME,
                "direction": args.direction,
                "dry_run": True,
                "index": args.index,
                "live_packet_exchange": False,
                "role": args.role,
            },
            sort_keys=True,
        )
    )
    return 0


def _require_live_capability(
    capabilities: BackendCapabilities | BackendRegistration | None,
) -> None:
    resolved = _capability_contract(capabilities)
    if not resolved.live_endpoint:
        raise ValueError("unsupported backend capability: Scapy live helper requires live_endpoint")


def _capability_contract(
    capabilities: BackendCapabilities | BackendRegistration | None,
) -> BackendCapabilities:
    if capabilities is None:
        return get_backend(BACKEND_NAME).capabilities
    if isinstance(capabilities, BackendRegistration):
        return capabilities.capabilities
    return capabilities


if __name__ == "__main__":
    raise SystemExit(main())
