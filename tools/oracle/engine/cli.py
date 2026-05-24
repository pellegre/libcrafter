"""Command-line interface for oracle packet validation."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import tomllib
import time
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

from .backends import (
    BackendCapabilityName,
    BackendRegistration,
    UnknownBackendError,
    backend_report_metadata,
    get_backend,
    get_backend_capability_registration,
    registered_backend_names,
)
from .compare import compare_decoded_models, failure_indexes
from .model import (
    ComparisonResult,
    DecodedModel,
    EncodedVector,
    JSONObject,
    PacketPlan,
    RunReport,
    dumps_json,
    write_json,
)
from .report import DEFAULT_OUTPUT_ROOT, REPO_ROOT


PCAP_CONTRACT_SPEC = "features/pcap.yaml"
PCAP_LINK_TYPES_SPEC = "features/pcap-link-types.yaml"
GENERATOR_SELECTED_SPECS = (
    "tools/oracle/specs/stacks.yaml",
    "tools/oracle/specs/profiles.yaml",
)
PCAP_SELECTED_SPECS = (
    PCAP_CONTRACT_SPEC,
    PCAP_LINK_TYPES_SPEC,
    *GENERATOR_SELECTED_SPECS,
)
FINAL_REPORT_COMMANDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("formatting", ("cargo", "fmt", "--all", "--", "--check")),
    ("clippy", ("cargo", "clippy", "--workspace", "--all-targets")),
    ("workspace-tests", ("cargo", "test", "--workspace")),
    ("example-builds", ("cargo", "build", "--examples")),
    (
        "oracle-offline-ci",
        (
            "tools/oracle/run",
            "offline",
            "--backend",
            "scapy",
            "--profile",
            "ci",
            "--seed",
            "12345",
            "--count",
            "2000",
        ),
    ),
    (
        "oracle-offline-smoke",
        (
            "tools/oracle/run",
            "offline",
            "--backend",
            "scapy",
            "--profile",
            "smoke",
            "--seed",
            "1",
            "--count",
            "50",
        ),
    ),
    (
        "oracle-pcap-smoke",
        (
            "tools/oracle/run",
            "pcap",
            "--backend",
            "scapy",
            "--profile",
            "smoke",
            "--seed",
            "1",
            "--count",
            "50",
        ),
    ),
    (
        "oracle-live-local-dry-run",
        (
            "tools/oracle/run",
            "live",
            "--backend",
            "scapy",
            "--provider",
            "local-dry-run",
            "--profile",
            "smoke",
            "--seed",
            "1",
            "--count",
            "10",
        ),
    ),
    (
        "legacy-reference-interop-smoke",
        ("tools/reference/check-reference-interop", "--smoke"),
    ),
    (
        "legacy-scapy-interop-smoke",
        ("tools/reference/check-scapy-interop", "--smoke"),
    ),
)
SCAPY_IMPORT_RE = re.compile(r"\b(?:from\s+scapy\b|import\s+scapy\b)")
REPORT_SCAN_ROOTS = (
    ".github",
    ".agents",
    "crates",
    "docs",
    "examples",
    "tests",
    "tools",
    "Cargo.toml",
    "README.md",
)
REPORT_SCAN_EXCLUDED_DIRS = {
    ".git",
    ".libcrafter-live",
    ".mypy_cache",
    ".pytest_cache",
    ".venv",
    "__pycache__",
    "target",
    "venv",
}

def _add_common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--out",
        default=str(DEFAULT_OUTPUT_ROOT),
        help="artifact output root (default: %(default)s)",
    )


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def _non_negative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be non-negative")
    return parsed


def _add_generation_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--backend",
        choices=registered_backend_names(),
        default="scapy",
        help="reference backend to target (default: %(default)s)",
    )
    parser.add_argument(
        "--profile",
        default="smoke",
        help="sampling profile from profiles.yaml (default: %(default)s)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=1,
        help="deterministic generator seed (default: %(default)s)",
    )
    parser.add_argument(
        "--count",
        type=_positive_int,
        default=10,
        help="number of generated packet plans (default: %(default)s)",
    )
    parser.add_argument(
        "--case",
        dest="case_name",
        help="case name filter or reproduction coordinate",
    )
    parser.add_argument(
        "--feature",
        help="feature name filter or reproduction coordinate",
    )
    parser.add_argument(
        "--family",
        help="protocol family filter from stacks.yaml",
    )
    parser.add_argument(
        "--root",
        help="root decoder filter from stacks.yaml, such as link:ethernet or l3:ipv4",
    )
    parser.add_argument(
        "--index",
        type=_non_negative_int,
        help="generate one packet plan at the selected index",
    )


def _not_implemented(args: argparse.Namespace) -> int:
    print(
        f"oracle {args.mode} mode is not implemented yet; parsed output root: {args.out}",
        file=sys.stderr,
    )
    return 2


def _generate(args: argparse.Namespace) -> int:
    from .generator import generate_plans

    try:
        plans = generate_plans(
            seed=args.seed,
            profile=args.profile,
            backend=args.backend,
            count=args.count,
            root=args.root,
            family=args.family,
            case=args.case_name,
            feature=args.feature,
            direction=args.direction,
            index=args.index,
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    output_dir = Path(args.out)
    if not output_dir.is_absolute():
        output_dir = REPO_ROOT / output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    plans_path = output_dir / "plans.json"
    report = RunReport(
        mode="generate",
        backend=args.backend,
        profile=args.profile,
        seed=args.seed,
        count=len(plans),
        status="generated",
        selected_specs=list(GENERATOR_SELECTED_SPECS),
        artifacts=[str(plans_path)],
        artifact_paths=[str(plans_path)],
        metadata={
            "direction": args.direction,
            "requested_count": args.count,
            "generated_count": len(plans),
            "root": args.root,
            "family": args.family,
            "case": args.case_name,
            "feature": args.feature,
            "plans": [plan.to_dict() for plan in plans],
        },
    )
    write_json(plans_path, report)
    print(f"generate: status=generated count={len(plans)} plans={plans_path}")
    return 0


def _offline_required_capabilities(
    args: argparse.Namespace,
) -> tuple[BackendCapabilityName, ...]:
    if args.emit_decoded:
        return ("encode", "decode")
    if args.emit_vectors:
        return ("encode",)
    if args.dry_plan:
        return ()
    if args.direction == "reference_to_libcrafter":
        return ("encode", "decode")
    if args.direction == "libcrafter_to_reference":
        return ("decode",)
    return ()


def _pcap_required_capabilities(
    args: argparse.Namespace,
) -> tuple[BackendCapabilityName, ...]:
    if args.direction == "reference_to_libcrafter":
        return ("encode", "pcap_write", "pcap_read")
    if args.direction == "libcrafter_to_reference":
        return ("pcap_read",)
    if args.direction == "roundtrip":
        return ("encode", "pcap_write", "pcap_read")
    return ()


def _require_backend_capabilities(
    args: argparse.Namespace,
    *,
    mode: str,
    required: tuple[BackendCapabilityName, ...],
    operation: str,
    report_path: Path | None,
    selected_specs: Sequence[str] = (),
) -> int | None:
    try:
        backend = get_backend(args.backend)
    except UnknownBackendError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    missing = backend.capabilities.missing(required)
    if missing:
        message = _missing_capability_message(backend, missing, operation)
        return _write_backend_support_report(
            args=args,
            mode=mode,
            backend=backend,
            message=message,
            operation=operation,
            required=required,
            missing=missing,
            report_path=report_path,
            selected_specs=selected_specs,
        )

    if required and not backend.availability.available:
        reason = backend.availability.reason or "backend dependency is unavailable"
        message = (
            f"unsupported backend availability: backend {backend.name} is unavailable: "
            f"{reason}; {operation} requires {', '.join(required)}"
        )
        return _write_backend_support_report(
            args=args,
            mode=mode,
            backend=backend,
            message=message,
            operation=operation,
            required=required,
            missing=(),
            report_path=report_path,
            selected_specs=selected_specs,
        )

    return None


def _missing_capability_message(
    backend: BackendRegistration,
    missing: Sequence[str],
    operation: str,
) -> str:
    required = ", ".join(missing)
    if backend.parser_only and any(
        capability in {"encode", "pcap_write"} for capability in missing
    ):
        return (
            f"unsupported backend capability: backend {backend.name} is parser-only "
            f"and cannot write; {operation} requires {required}"
        )
    if backend.parser_only and "live_endpoint" in missing:
        return (
            f"unsupported backend capability: backend {backend.name} is parser-only "
            f"and cannot act as a live endpoint; {operation} requires {required}"
        )
    return (
        f"unsupported backend capability: backend {backend.name} lacks {required}; "
        f"{operation} requires {required}"
    )


def _backend_not_implemented_report(
    args: argparse.Namespace,
    *,
    mode: str,
    operation: str,
    report_path: Path | None,
    selected_specs: Sequence[str] = (),
) -> int:
    backend = get_backend(args.backend)
    message = (
        f"unsupported backend implementation: backend {backend.name} has compatible "
        f"capabilities, but {operation} is not wired to an oracle adapter yet"
    )
    return _write_backend_support_report(
        args=args,
        mode=mode,
        backend=backend,
        message=message,
        operation=operation,
        required=(),
        missing=(),
        report_path=report_path,
        selected_specs=selected_specs,
    )


def _write_backend_support_report(
    *,
    args: argparse.Namespace,
    mode: str,
    backend: BackendRegistration,
    message: str,
    operation: str,
    required: Sequence[str],
    missing: Sequence[str],
    report_path: Path | None,
    selected_specs: Sequence[str],
) -> int:
    artifacts = [] if report_path is None else [str(report_path)]
    direction = getattr(args, "direction", "backend")
    if not isinstance(direction, str):
        direction = "backend"
    differences: list[JSONObject] = [
        {
            "path": "capabilities.enabled",
            "expected": list(required),
            "actual": backend.capabilities.enabled(),
        }
    ]
    if not backend.availability.available:
        differences.append(
            {
                "path": "availability",
                "expected": "available",
                "actual": backend.availability.to_dict(),
            }
        )

    reproduction_command = _requested_command()
    result = ComparisonResult(
        passed=False,
        direction=direction,
        expected={
            "operation": operation,
            "required_capabilities": list(required),
            "backend_available": True,
        },
        actual={
            "missing_capabilities": list(missing),
            "message": message,
        },
        strict_bytes=False,
        byte_equal=None,
        differences=differences,
        reproduction_command=reproduction_command,
        metadata={
            "operation": operation,
            "unsupported": True,
            "required_capabilities": list(required),
            "missing_capabilities": list(missing),
            "backend_metadata": {
                "actual": backend.to_dict(),
            },
        },
    )
    report = RunReport(
        mode=mode,
        backend=backend.name,
        profile=_arg_int_or_string(args, "profile", "unknown"),
        seed=_arg_int(args, "seed", 0),
        count=0,
        status="unsupported",
        selected_specs=list(selected_specs),
        artifacts=artifacts,
        artifact_paths=artifacts,
        results=[result],
        failures=[result],
        reproduction_commands=[reproduction_command],
        backend_versions=_backend_versions(backend.name),
        libcrafter=_libcrafter_info(),
        metadata={
            "operation": operation,
            "backend": backend.to_dict(),
            "requested_count": _arg_int(args, "count", 0),
            "unsupported_reason": message,
        },
    )
    if report_path is not None:
        write_json(report_path, report)
        print(f"{message}; report={report_path}", file=sys.stderr)
    else:
        print(message, file=sys.stderr)
    return 2


def _arg_int(args: argparse.Namespace, name: str, default: int) -> int:
    value = getattr(args, name, default)
    return value if isinstance(value, int) else default


def _arg_int_or_string(args: argparse.Namespace, name: str, default: str) -> str:
    value = getattr(args, name, default)
    return value if isinstance(value, str) else default


def _requested_command() -> str:
    return shlex.join(["tools/oracle/run", *sys.argv[1:]])


def _pcap(args: argparse.Namespace) -> int:
    if args.dry_plan:
        return _pcap_dry_plan(args)

    unsupported = _require_backend_capabilities(
        args,
        mode="pcap",
        required=_pcap_required_capabilities(args),
        operation=f"pcap {args.direction}",
        report_path=_pcap_output_dir(args.out) / "report.json",
        selected_specs=PCAP_SELECTED_SPECS,
    )
    if unsupported is not None:
        return unsupported
    if args.backend != "scapy" and args.direction != "libcrafter_to_reference":
        return _backend_not_implemented_report(
            args,
            mode="pcap",
            operation=f"pcap {args.direction}",
            report_path=_pcap_output_dir(args.out) / "report.json",
            selected_specs=PCAP_SELECTED_SPECS,
        )

    return _pcap_execute(args)


def _live(args: argparse.Namespace) -> int:
    unsupported = _require_backend_capabilities(
        args,
        mode="live",
        required=("live_endpoint",),
        operation=f"live {args.provider}",
        report_path=_live_output_dir(args.out) / "report.json",
        selected_specs=("live",),
    )
    if unsupported is not None:
        return unsupported

    if args.provider == "local-dry-run":
        return _live_local_dry_run(args)
    if args.provider == "hetzner":
        return _live_hetzner(args)

    print(f"unsupported live provider: {args.provider}", file=sys.stderr)
    return 2


def _live_hetzner(args: argparse.Namespace) -> int:
    from .backends.scapy.live import (
        backend_bootstrap_command_plan,
        dry_run_command_plan as scapy_dry_run_command_plan,
        validate_backend_bootstrap_command,
        validate_dry_run_command_plan as validate_scapy_dry_run_command_plan,
    )
    from .generator import generate_plans
    from .live import (
        LIVE_SELECTED_SPECS,
        LiveExchangePlan,
        libcrafter_dry_run_command_plan,
        live_execution_directions,
        validate_libcrafter_command_plan,
    )
    from .providers.hetzner import (
        hetzner_endpoints,
        hetzner_private_network_plan,
        hetzner_provider_workflow,
        hetzner_token_configured,
        validate_hetzner_dry_run_exchange,
        validate_hetzner_provider_workflow,
    )

    try:
        directions = live_execution_directions(args.direction)
        plans = generate_plans(
            seed=args.seed,
            profile=args.profile,
            backend=args.backend,
            count=args.count,
            root=args.root,
            family=args.family,
            case=args.case_name,
            feature=args.feature,
            index=args.index,
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    output_dir = _live_output_dir(args.out)
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "report.json"

    token_configured = hetzner_token_configured()
    dry_run = bool(args.dry_run)
    if not dry_run and not token_configured:
        return _live_hetzner_skip_no_token(
            args=args,
            report_path=report_path,
            directions=directions,
            generated_count=len(plans),
        )
    if not dry_run:
        return _live_hetzner_requires_dry_run_report(
            args=args,
            report_path=report_path,
            directions=directions,
            generated_count=len(plans),
        )

    endpoints = hetzner_endpoints(dry_run=True)
    provider_workflow = hetzner_provider_workflow(dry_run=True)
    bootstrap_command = backend_bootstrap_command_plan()
    validations = [
        validate_backend_bootstrap_command(bootstrap_command),
        validate_hetzner_provider_workflow(provider_workflow, dry_run=True),
    ]
    exchanges: list[LiveExchangePlan] = []

    for plan in plans:
        for direction in directions:
            if direction == "reference_to_libcrafter":
                sender = endpoints["reference_backend"]
                receiver = endpoints["libcrafter"]
                sender_command = scapy_dry_run_command_plan(
                    plan=plan,
                    direction=direction,
                    role="sender",
                )
                receiver_command = libcrafter_dry_run_command_plan(
                    plan=plan,
                    direction=direction,
                    role="receiver",
                )
                validations.append(validate_scapy_dry_run_command_plan(sender_command))
                validations.append(validate_libcrafter_command_plan(receiver_command))
            elif direction == "libcrafter_to_reference":
                sender = endpoints["libcrafter"]
                receiver = endpoints["reference_backend"]
                sender_command = libcrafter_dry_run_command_plan(
                    plan=plan,
                    direction=direction,
                    role="sender",
                )
                receiver_command = scapy_dry_run_command_plan(
                    plan=plan,
                    direction=direction,
                    role="receiver",
                )
                validations.append(validate_libcrafter_command_plan(sender_command))
                validations.append(validate_scapy_dry_run_command_plan(receiver_command))
            else:
                print(f"unsupported live direction: {direction}", file=sys.stderr)
                return 2

            exchange = LiveExchangePlan(
                provider=args.provider,
                backend=args.backend,
                direction=direction,
                index=plan.index,
                packet_plan=replace(plan, direction=direction),
                sender=sender,
                receiver=receiver,
                sender_command=sender_command,
                receiver_command=receiver_command,
                live_packet_exchange=False,
                metadata={
                    "dry_run": True,
                    "creates_infrastructure": False,
                    "planned_live_packet_exchange": True,
                    "live_packet_exchange": False,
                    "no_live_packets_sent": True,
                    "private_network": True,
                },
            )
            exchanges.append(exchange)
            validations.append(validate_hetzner_dry_run_exchange(exchange))

    failed_validations = [validation for validation in validations if not validation.passed]
    status = "dry-run" if not failed_validations else "failed"
    result = ComparisonResult(
        passed=not failed_validations,
        direction=args.direction,
        expected={
            "provider": args.provider,
            "dry_run": True,
            "creates_infrastructure": False,
            "private_network": True,
            "endpoint_count": 2,
            "validations_pass": True,
        },
        actual={
            "provider": args.provider,
            "dry_run": True,
            "creates_infrastructure": False,
            "private_network": True,
            "endpoint_count": len(endpoints),
            "validations_pass": not failed_validations,
            "failed_validations": [validation.to_dict() for validation in failed_validations],
        },
        strict_bytes=False,
        byte_equal=None,
        differences=[
            {
                "path": validation.name,
                "expected": "passed",
                "actual": validation.errors,
                "subject": validation.subject,
            }
            for validation in failed_validations
        ],
        reproduction_command=None
        if not failed_validations
        else _live_reproduction_command(args),
        metadata={
            "provider": args.provider,
            "dry_run": True,
            "creates_infrastructure": False,
            "planned_live_packet_exchange": True,
            "live_packet_exchange": False,
            "validation_count": len(validations),
        },
    )

    report = RunReport(
        mode="live",
        backend=args.backend,
        profile=args.profile,
        seed=args.seed,
        count=len(exchanges),
        status=status,
        selected_specs=LIVE_SELECTED_SPECS,
        artifacts=[str(report_path)],
        artifact_paths=[str(report_path)],
        results=[result],
        failures=[] if result.passed else [result],
        reproduction_commands=(
            [] if result.reproduction_command is None else [result.reproduction_command]
        ),
        backend_versions=_backend_versions(args.backend),
        libcrafter=_libcrafter_info(),
        metadata={
            "provider": args.provider,
            "dry_run": True,
            "creates_infrastructure": False,
            "would_create_infrastructure": True,
            "planned_live_packet_exchange": True,
            "live_packet_exchange": False,
            "no_live_packets_sent": True,
            "token_configured": token_configured,
            "requested_count": args.count,
            "generated_count": len(plans),
            "execution_directions": directions,
            "planned_infrastructure": hetzner_private_network_plan(dry_run=True),
            "provider_workflow": [command.to_dict() for command in provider_workflow],
            "artifact_collection": {
                "always_attempt": True,
                "command": provider_workflow[3].to_dict(),
            },
            "teardown": {
                "always_attempt": True,
                "command": provider_workflow[4].to_dict(),
            },
            "backend_bootstrap": {
                "command": bootstrap_command.to_dict(),
                "validation": validations[0].to_dict(),
            },
            "endpoints": {
                name: endpoint.to_dict() for name, endpoint in endpoints.items()
            },
            "exchanges": [exchange.to_dict() for exchange in exchanges],
            "validations": [validation.to_dict() for validation in validations],
        },
    )
    write_json(report_path, report)

    print(
        f"live {args.provider}: status={status} exchanges={len(exchanges)} "
        f"creates_infrastructure=false report={report_path}"
    )
    if failed_validations:
        print(f"failed_validations={len(failed_validations)}", file=sys.stderr)
        print(f"reproduce: {_live_reproduction_command(args)}", file=sys.stderr)

    return 0 if status == "dry-run" else 1


def _live_hetzner_skip_no_token(
    *,
    args: argparse.Namespace,
    report_path: Path,
    directions: list[str],
    generated_count: int,
) -> int:
    from .live import LIVE_SELECTED_SPECS
    from .providers.hetzner import (
        hetzner_endpoints,
        hetzner_private_network_plan,
        hetzner_provider_workflow,
    )

    endpoints = hetzner_endpoints(dry_run=False)
    provider_workflow = hetzner_provider_workflow(dry_run=False)
    result = ComparisonResult(
        passed=True,
        direction=args.direction,
        expected={
            "provider": args.provider,
            "credential": "HETZNER_API_TOKEN",
            "token_configured": True,
        },
        actual={
            "provider": args.provider,
            "skipped": True,
            "reason": "missing HETZNER_API_TOKEN",
            "token_configured": False,
            "creates_infrastructure": False,
        },
        strict_bytes=False,
        byte_equal=None,
        metadata={
            "provider": args.provider,
            "skipped": True,
            "skip_reason": "missing HETZNER_API_TOKEN",
            "creates_infrastructure": False,
            "live_packet_exchange": False,
        },
    )
    report = RunReport(
        mode="live",
        backend=args.backend,
        profile=args.profile,
        seed=args.seed,
        count=0,
        status="skipped",
        selected_specs=LIVE_SELECTED_SPECS,
        artifacts=[str(report_path)],
        artifact_paths=[str(report_path)],
        results=[result],
        failures=[],
        backend_versions=_backend_versions(args.backend),
        libcrafter=_libcrafter_info(),
        metadata={
            "provider": args.provider,
            "dry_run": False,
            "skipped": True,
            "skip_reason": "missing HETZNER_API_TOKEN",
            "creates_infrastructure": False,
            "would_create_infrastructure_with_credentials": True,
            "live_packet_exchange": False,
            "no_live_packets_sent": True,
            "token_configured": False,
            "requested_count": args.count,
            "generated_count": generated_count,
            "execution_directions": directions,
            "planned_infrastructure_if_credentials_available": hetzner_private_network_plan(
                dry_run=False
            ),
            "provider_workflow_if_credentials_available": [
                command.to_dict() for command in provider_workflow
            ],
            "artifact_collection": {
                "always_attempt": True,
                "command": provider_workflow[3].to_dict(),
            },
            "teardown": {
                "always_attempt": True,
                "command": provider_workflow[4].to_dict(),
            },
            "endpoints": {
                name: endpoint.to_dict() for name, endpoint in endpoints.items()
            },
        },
    )
    write_json(report_path, report)
    print(
        f"live {args.provider}: status=skipped reason=missing_HETZNER_API_TOKEN "
        f"creates_infrastructure=false report={report_path}"
    )
    return 0


def _live_hetzner_requires_dry_run_report(
    *,
    args: argparse.Namespace,
    report_path: Path,
    directions: list[str],
    generated_count: int,
) -> int:
    from .live import LIVE_SELECTED_SPECS
    from .providers.hetzner import (
        hetzner_endpoints,
        hetzner_private_network_plan,
        hetzner_provider_workflow,
    )

    endpoints = hetzner_endpoints(dry_run=False)
    provider_workflow = hetzner_provider_workflow(dry_run=False)
    result = ComparisonResult(
        passed=False,
        direction=args.direction,
        expected={
            "provider": args.provider,
            "dry_run": False,
            "live_packet_exchange": True,
        },
        actual={
            "provider": args.provider,
            "dry_run": False,
            "live_packet_exchange": False,
            "reason": "provider execution requires the live-lab operator path",
        },
        strict_bytes=False,
        byte_equal=None,
        differences=[
            {
                "path": "provider_execution",
                "expected": "two-endpoint live exchange",
                "actual": "not executed by oracle dry-run adapter",
            }
        ],
        reproduction_command=_live_reproduction_command(args),
        metadata={
            "provider": args.provider,
            "creates_infrastructure": False,
            "live_packet_exchange": False,
            "planned_infrastructure": True,
        },
    )
    report = RunReport(
        mode="live",
        backend=args.backend,
        profile=args.profile,
        seed=args.seed,
        count=0,
        status="failed",
        selected_specs=LIVE_SELECTED_SPECS,
        artifacts=[str(report_path)],
        artifact_paths=[str(report_path)],
        results=[result],
        failures=[result],
        reproduction_commands=[result.reproduction_command]
        if result.reproduction_command is not None
        else [],
        backend_versions=_backend_versions(args.backend),
        libcrafter=_libcrafter_info(),
        metadata={
            "provider": args.provider,
            "dry_run": False,
            "creates_infrastructure": False,
            "planned_infrastructure": hetzner_private_network_plan(dry_run=False),
            "provider_workflow": [command.to_dict() for command in provider_workflow],
            "artifact_collection": {
                "always_attempt": True,
                "command": provider_workflow[3].to_dict(),
            },
            "teardown": {
                "always_attempt": True,
                "command": provider_workflow[4].to_dict(),
            },
            "endpoints": {
                name: endpoint.to_dict() for name, endpoint in endpoints.items()
            },
            "execution_directions": directions,
            "generated_count": generated_count,
        },
    )
    write_json(report_path, report)
    print(
        f"live {args.provider}: status=failed reason=requires_live_lab_operator_path "
        f"creates_infrastructure=false report={report_path}",
        file=sys.stderr,
    )
    return 2


def _live_local_dry_run(args: argparse.Namespace) -> int:
    from .backends.scapy.live import (
        backend_bootstrap_command_plan,
        dry_run_command_plan as scapy_dry_run_command_plan,
        validate_backend_bootstrap_command,
        validate_dry_run_command_plan as validate_scapy_dry_run_command_plan,
    )
    from .generator import generate_plans
    from .live import (
        LIVE_SELECTED_SPECS,
        LiveExchangePlan,
        build_live_endpoint_batch_request,
        dry_run_live_endpoint_batch_response,
        libcrafter_dry_run_command_plan,
        live_endpoint_artifact_paths,
        live_execution_directions,
        local_dry_run_endpoints,
        validate_live_endpoint_batch_contract,
        validate_libcrafter_command_plan,
        validate_local_dry_run_exchange,
    )

    try:
        directions = live_execution_directions(args.direction)
        plans = generate_plans(
            seed=args.seed,
            profile=args.profile,
            backend=args.backend,
            count=args.count,
            root=args.root,
            family=args.family,
            case=args.case_name,
            feature=args.feature,
            index=args.index,
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    output_dir = _live_output_dir(args.out)
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "report.json"

    endpoints = local_dry_run_endpoints()
    bootstrap_command = backend_bootstrap_command_plan()
    validations = [validate_backend_bootstrap_command(bootstrap_command)]
    exchanges: list[LiveExchangePlan] = []

    for plan in plans:
        for direction in directions:
            if direction == "reference_to_libcrafter":
                sender = endpoints["reference_backend"]
                receiver = endpoints["libcrafter"]
                sender_command = scapy_dry_run_command_plan(
                    plan=plan,
                    direction=direction,
                    role="sender",
                )
                receiver_command = libcrafter_dry_run_command_plan(
                    plan=plan,
                    direction=direction,
                    role="receiver",
                )
                validations.append(validate_scapy_dry_run_command_plan(sender_command))
                validations.append(validate_libcrafter_command_plan(receiver_command))
            elif direction == "libcrafter_to_reference":
                sender = endpoints["libcrafter"]
                receiver = endpoints["reference_backend"]
                sender_command = libcrafter_dry_run_command_plan(
                    plan=plan,
                    direction=direction,
                    role="sender",
                )
                receiver_command = scapy_dry_run_command_plan(
                    plan=plan,
                    direction=direction,
                    role="receiver",
                )
                validations.append(validate_libcrafter_command_plan(sender_command))
                validations.append(validate_scapy_dry_run_command_plan(receiver_command))
            else:
                print(f"unsupported live direction: {direction}", file=sys.stderr)
                return 2

            exchange = LiveExchangePlan(
                provider=args.provider,
                backend=args.backend,
                direction=direction,
                index=plan.index,
                packet_plan=replace(plan, direction=direction),
                sender=sender,
                receiver=receiver,
                sender_command=sender_command,
                receiver_command=receiver_command,
                live_packet_exchange=False,
                metadata={
                    "dry_run": True,
                    "live_packet_exchange": False,
                    "no_live_packets_sent": True,
                },
            )
            exchanges.append(exchange)
            validations.append(validate_local_dry_run_exchange(exchange))

    endpoint_protocol_batches: list[JSONObject] = []
    for direction in directions:
        direction_plans = [replace(plan, direction=direction) for plan in plans]
        if direction == "reference_to_libcrafter":
            sender = endpoints["reference_backend"]
            receiver = endpoints["libcrafter"]
        elif direction == "libcrafter_to_reference":
            sender = endpoints["libcrafter"]
            receiver = endpoints["reference_backend"]
        else:
            print(f"unsupported live direction: {direction}", file=sys.stderr)
            return 2

        for phase_role, endpoint, peer in (
            ("sender", sender, receiver),
            ("receiver", receiver, sender),
        ):
            request = build_live_endpoint_batch_request(
                provider=args.provider,
                backend=args.backend,
                seed=args.seed,
                profile=args.profile,
                packet_plans=direction_plans,
                direction=direction,
                endpoint=endpoint,
                peer=peer,
                artifact_paths=live_endpoint_artifact_paths(
                    output_dir=str(output_dir),
                    direction=direction,
                    endpoint_role=endpoint.role,
                ),
                metadata={
                    "phase_role": phase_role,
                    "dry_run": True,
                    "live_packet_exchange": False,
                    "no_live_packets_sent": True,
                },
            )
            response = dry_run_live_endpoint_batch_response(request)
            validation = validate_live_endpoint_batch_contract(
                request,
                response,
                dry_run=True,
            )
            validations.append(validation)
            endpoint_protocol_batches.append(
                {
                    "phase_role": phase_role,
                    "request": request.to_dict(),
                    "response": response.to_dict(),
                    "validation": validation.to_dict(),
                }
            )

    failed_validations = [validation for validation in validations if not validation.passed]
    status = "passed" if not failed_validations else "failed"
    result = ComparisonResult(
        passed=not failed_validations,
        direction=args.direction,
        expected={
            "provider": args.provider,
            "dry_run": True,
            "live_packet_exchange": False,
            "validations_pass": True,
            "endpoint_protocol_batches": len(directions) * 2,
        },
        actual={
            "provider": args.provider,
            "dry_run": True,
            "live_packet_exchange": False,
            "validations_pass": not failed_validations,
            "endpoint_protocol_batches": len(endpoint_protocol_batches),
            "failed_validations": [validation.to_dict() for validation in failed_validations],
        },
        strict_bytes=False,
        byte_equal=None,
        differences=[
            {
                "path": validation.name,
                "expected": "passed",
                "actual": validation.errors,
                "subject": validation.subject,
            }
            for validation in failed_validations
        ],
        reproduction_command=None
        if not failed_validations
        else _live_reproduction_command(args),
        metadata={
            "provider": args.provider,
            "dry_run": True,
            "live_packet_exchange": False,
            "validation_count": len(validations),
        },
    )

    report = RunReport(
        mode="live",
        backend=args.backend,
        profile=args.profile,
        seed=args.seed,
        count=len(exchanges),
        status=status,
        selected_specs=LIVE_SELECTED_SPECS,
        artifacts=[str(report_path)],
        artifact_paths=[str(report_path)],
        results=[result],
        failures=[] if result.passed else [result],
        reproduction_commands=(
            [] if result.reproduction_command is None else [result.reproduction_command]
        ),
        backend_versions=_backend_versions(args.backend),
        libcrafter=_libcrafter_info(),
        metadata={
            "provider": args.provider,
            "dry_run": True,
            "live_packet_exchange": False,
            "no_live_packets_sent": True,
            "real_provider_backed_live_mode": "not executed by local-dry-run",
            "requested_count": args.count,
            "generated_count": len(plans),
            "execution_directions": directions,
            "backend_bootstrap": {
                "command": bootstrap_command.to_dict(),
                "validation": validations[0].to_dict(),
            },
            "endpoints": {
                name: endpoint.to_dict() for name, endpoint in endpoints.items()
            },
            "endpoint_protocol": {
                "version": 1,
                "batches": endpoint_protocol_batches,
            },
            "exchanges": [exchange.to_dict() for exchange in exchanges],
            "validations": [validation.to_dict() for validation in validations],
        },
    )
    write_json(report_path, report)

    print(
        f"live {args.provider}: status={status} exchanges={len(exchanges)} "
        f"live_packet_exchange=false report={report_path}"
    )
    if failed_validations:
        print(f"failed_validations={len(failed_validations)}", file=sys.stderr)
        print(f"reproduce: {_live_reproduction_command(args)}", file=sys.stderr)

    return 0 if status == "passed" else 1


class PcapUnsupportedError(ValueError):
    """Raised when a selected pcap spec case cannot execute in this repository."""


def _pcap_dry_plan(args: argparse.Namespace) -> int:
    from .generator import PacketGenerator

    try:
        directions = _pcap_execution_directions(args.direction)
        pcap_cases = [
            pcap_case
            for direction in directions
            for pcap_case in _pcap_cases_for_direction(
                args=args,
                direction=direction,
                dry_plan=True,
            )
        ]
        generator = PacketGenerator(seed=args.seed, profile=args.profile, backend=args.backend)
        plans = []
        indices = _pcap_indices(args)
        for offset, index in enumerate(indices):
            pcap_case = pcap_cases[offset % len(pcap_cases)]
            link_type = _pcap_link_types_for_case(pcap_case)[offset % len(_pcap_link_types_for_case(pcap_case))]
            root = _pcap_generation_root(args.root, link_type, index)
            plan = generator.generate(
                index=index,
                root=root,
                family=args.family,
                case=_pcap_generator_case(link_type, root),
                direction=directions[offset % len(directions)],
            )
            plans.append(
                _pcap_plan(
                    plan,
                    pcap_case,
                    directions[offset % len(directions)],
                    link_type=link_type,
                    file_format=_pcap_file_format_for_case(pcap_case),
                )
            )
    except (ValueError, PcapUnsupportedError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    report = RunReport(
        mode="pcap",
        backend=args.backend,
        profile=args.profile,
        seed=args.seed,
        count=len(plans),
        status="dry-plan",
        selected_specs=list(PCAP_SELECTED_SPECS),
        metadata={
            "dry_plan": True,
            "requested_count": args.count,
            "direction": args.direction,
            "execution_directions": directions,
            "timestamp_policy": {
                "deterministic": "exact",
                "backend_precision_differs": "normalized",
                "backend_generated_or_unavailable": "ignored",
            },
            "pcap_cases": pcap_cases,
            "plans": [plan.to_dict() for plan in plans],
        },
    )
    sys.stdout.write(dumps_json(report))
    return 0


def _pcap_execute(args: argparse.Namespace) -> int:
    output_dir = _pcap_output_dir(args.out)
    artifacts_root = output_dir / "artifacts"
    artifacts_root.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "report.json"

    try:
        directions = _pcap_execution_directions(args.direction)
        direction_groups = [
            (direction, _pcap_vector_groups(args, direction))
            for direction in directions
        ]
    except PcapUnsupportedError as exc:
        return _write_pcap_unsupported_report(
            args=args,
            message=str(exc),
            report_path=report_path,
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    run_dir = Path(
        tempfile.mkdtemp(
            prefix=f"{args.direction}.",
            dir=artifacts_root,
        )
    )

    try:
        backend_versions = _backend_versions(args.backend)
        libcrafter_info = _libcrafter_info()

        results: list[ComparisonResult] = []
        direction_metadata: list[JSONObject] = []
        direction_artifacts: list[str] = []
        bridge_exit_codes: list[int] = []
        generated_count = 0
        for direction, groups in direction_groups:
            for group in groups:
                vectors = group["vectors"]
                plans = group["plans"]
                if not isinstance(vectors, list) or not isinstance(plans, list):
                    raise RuntimeError("pcap vector group is malformed")
                generated_count += len(plans)
                link_type = group["link_type"]
                if not isinstance(link_type, str):
                    raise RuntimeError("pcap vector group link_type must be a string")
                label = _pcap_group_label(direction, link_type)
                vector_path = run_dir / f"{label}.vectors.json"
                vector_report = RunReport(
                    mode="pcap",
                    backend=args.backend,
                    profile=args.profile,
                    seed=args.seed,
                    count=len(vectors),
                    status="vectors",
                    selected_specs=list(PCAP_SELECTED_SPECS),
                    backend_versions=backend_versions,
                    libcrafter=libcrafter_info,
                    metadata={
                        "direction": direction,
                        "execution_directions": directions,
                        "requested_count": args.count,
                        "pcap_case": group["pcap_case"],
                        "file_format": group["file_format"],
                        "link_type": group["link_type"],
                        "vectors": [vector.to_dict() for vector in vectors],
                    },
                )
                write_json(vector_path, vector_report)

                if direction == "reference_to_libcrafter":
                    run = _pcap_reference_to_libcrafter(
                        args=args,
                        run_dir=run_dir,
                        vector_path=vector_path,
                        vectors=vectors,  # type: ignore[arg-type]
                        plans=plans,  # type: ignore[arg-type]
                        label=label,
                    )
                elif direction == "libcrafter_to_reference":
                    run = _pcap_libcrafter_to_reference(
                        args=args,
                        run_dir=run_dir,
                        vector_path=vector_path,
                        vectors=vectors,  # type: ignore[arg-type]
                        plans=plans,  # type: ignore[arg-type]
                        label=label,
                    )
                else:
                    raise RuntimeError(f"unsupported pcap execution direction: {direction}")

                results.extend(run["results"])  # type: ignore[arg-type]
                direction_metadata.append(_json_object(run["metadata"], "pcap direction metadata"))
                direction_artifacts.extend(_string_values(run["artifacts"]))
                exit_code = run.get("bridge_exit_code")
                if isinstance(exit_code, int):
                    bridge_exit_codes.append(exit_code)

        failures = [result for result in results if not result.passed]
        status = "passed" if not failures and all(code == 0 for code in bridge_exit_codes) else "failed"
        preserve_artifacts = args.keep_artifacts or status != "passed"

        artifacts = [str(report_path)]
        if preserve_artifacts:
            artifacts.append(str(run_dir))
            artifacts.extend(direction_artifacts)
        artifacts.extend(_comparison_artifact_paths(failures))
        artifacts = _dedupe_paths(artifacts)

        report = RunReport(
            mode="pcap",
            backend=args.backend,
            profile=args.profile,
            seed=args.seed,
            count=len(results),
            status=status,
            selected_specs=list(PCAP_SELECTED_SPECS),
            artifacts=artifacts,
            artifact_paths=artifacts,
            results=results,
            failures=failures,
            reproduction_commands=[
                command
                for command in (result.reproduction_command for result in failures)
                if command is not None
            ],
            backend_versions=backend_versions,
            libcrafter=libcrafter_info,
            metadata={
                "direction": args.direction,
                "execution_directions": directions,
                "requested_count": args.count,
                "generated_count": generated_count,
                "artifact_dir": str(run_dir) if preserve_artifacts else None,
                "directions": direction_metadata,
                "timestamp_policy": {
                    "deterministic": "exact",
                    "precision": "microseconds",
                },
            },
        )
        write_json(report_path, report)

        if not preserve_artifacts:
            shutil.rmtree(run_dir)

        passed_count = len(results) - len(failures)
        print(
            f"pcap {args.direction}: status={status} "
            f"passed={passed_count}/{len(results)} report={report_path}"
        )
        if failures:
            indexes = ", ".join(str(index) for index in failure_indexes(failures))
            print(f"failing_indexes={indexes}", file=sys.stderr)
            if failures[0].reproduction_command:
                print(f"reproduce: {failures[0].reproduction_command}", file=sys.stderr)

        return 0 if status == "passed" else 1
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1


def _offline(args: argparse.Namespace) -> int:
    required_capabilities = _offline_required_capabilities(args)
    if required_capabilities:
        unsupported = _require_backend_capabilities(
            args,
            mode="offline",
            required=required_capabilities,
            operation=f"offline {args.direction}",
            report_path=_offline_output_dir(args.out) / "report.json",
            selected_specs=GENERATOR_SELECTED_SPECS,
        )
        if unsupported is not None:
            return unsupported
        if args.backend not in {"scapy", "wireshark"}:
            return _backend_not_implemented_report(
                args,
                mode="offline",
                operation=f"offline {args.direction}",
                report_path=_offline_output_dir(args.out) / "report.json",
                selected_specs=GENERATOR_SELECTED_SPECS,
            )

    if not args.dry_plan and not args.emit_vectors and not args.emit_decoded:
        if args.direction == "reference_to_libcrafter":
            return _offline_reference_to_libcrafter(args)
        if args.direction == "libcrafter_to_reference":
            return _offline_libcrafter_to_reference(args)
        print(f"unsupported offline direction: {args.direction}", file=sys.stderr)
        return 2

    from .generator import generate_plans

    plans = generate_plans(
        seed=args.seed,
        profile=args.profile,
        backend=args.backend,
        count=args.count,
        root=args.root,
        family=args.family,
        case=args.case_name,
        feature=args.feature,
        direction=args.direction,
        index=args.index,
    )
    if args.emit_vectors or args.emit_decoded:
        if args.backend == "scapy":
            from .backends.scapy.packets import encode_packet_plans

            vectors = encode_packet_plans(plans)
        else:
            print(f"unsupported backend: {args.backend}", file=sys.stderr)
            return 2

        if args.emit_decoded:
            from .backends.scapy.normalize import decode_vectors, validate_smoke_decodes

            decoded = decode_vectors(vectors)
            if args.profile == "smoke":
                validate_smoke_decodes(vectors, decoded)

            metadata = {
                "emit_decoded": True,
                "requested_count": args.count,
                "decoded": [model.to_dict() for model in decoded],
            }
            if args.emit_vectors:
                metadata["vectors"] = [vector.to_dict() for vector in vectors]

            report = RunReport(
                mode="offline",
                backend=args.backend,
                profile=args.profile,
                seed=args.seed,
                count=len(decoded),
                status="decoded",
                selected_specs=list(GENERATOR_SELECTED_SPECS),
                backend_versions=_backend_versions(args.backend),
                libcrafter=_libcrafter_info(),
                metadata=metadata,
            )
            sys.stdout.write(dumps_json(report))
            return 0

        report = RunReport(
            mode="offline",
            backend=args.backend,
            profile=args.profile,
            seed=args.seed,
            count=len(vectors),
            status="vectors",
            selected_specs=list(GENERATOR_SELECTED_SPECS),
            backend_versions=_backend_versions(args.backend),
            libcrafter=_libcrafter_info(),
            metadata={
                "emit_vectors": True,
                "requested_count": args.count,
                "vectors": [vector.to_dict() for vector in vectors],
            },
        )
        sys.stdout.write(dumps_json(report))
        return 0

    report = RunReport(
        mode="offline",
        backend=args.backend,
        profile=args.profile,
        seed=args.seed,
        count=len(plans),
        status="dry-plan",
        selected_specs=list(GENERATOR_SELECTED_SPECS),
        metadata={
            "dry_plan": True,
            "requested_count": args.count,
            "plans": [plan.to_dict() for plan in plans],
        },
    )
    sys.stdout.write(dumps_json(report))
    return 0


def _offline_reference_to_libcrafter(args: argparse.Namespace) -> int:
    if args.direction != "reference_to_libcrafter":
        print(f"unsupported offline direction: {args.direction}", file=sys.stderr)
        return 2

    from .backends.scapy.normalize import decode_vectors
    from .backends.scapy.packets import encode_packet_plans
    from .generator import generate_plans

    if args.backend != "scapy":
        print(f"unsupported backend: {args.backend}", file=sys.stderr)
        return 2

    output_dir = _offline_output_dir(args.out)
    artifacts_root = output_dir / "artifacts"
    artifacts_root.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "report.json"
    run_dir = Path(
        tempfile.mkdtemp(
            prefix=f"{args.direction}.",
            dir=artifacts_root,
        )
    )

    plans = generate_plans(
        seed=args.seed,
        profile=args.profile,
        backend=args.backend,
        count=args.count,
        root=args.root,
        family=args.family,
        case=args.case_name,
        feature=args.feature,
        direction=args.direction,
        index=args.index,
    )
    selected_specs = _selected_specs_for_plans(plans)
    backend_capabilities = _offline_backend_capabilities(args)
    vectors = encode_packet_plans(plans)
    expected_decoded = decode_vectors(vectors)
    backend_versions = _backend_versions(args.backend)
    libcrafter_info = _libcrafter_info()

    vector_report = RunReport(
        mode="offline",
        backend=args.backend,
        profile=args.profile,
        seed=args.seed,
        count=len(vectors),
        status="vectors",
        selected_specs=selected_specs,
        backend_versions=backend_versions,
        libcrafter=libcrafter_info,
        metadata={
            "direction": args.direction,
            "requested_count": args.count,
            "backend_capabilities": backend_capabilities,
            "vectors": [vector.to_dict() for vector in vectors],
        },
    )
    vector_path = run_dir / "reference-vectors.json"
    write_json(vector_path, vector_report)

    expected_path = run_dir / "reference-decoded.json"
    write_json(
        expected_path,
        RunReport(
            mode="offline",
            backend=args.backend,
            profile=args.profile,
            seed=args.seed,
            count=len(expected_decoded),
            status="decoded",
            selected_specs=selected_specs,
            backend_versions=backend_versions,
            libcrafter=libcrafter_info,
            metadata={
                "direction": args.direction,
                "backend_capabilities": backend_capabilities,
                "decoded": [model.to_dict() for model in expected_decoded],
            },
        ),
    )

    bridge = _run_libcrafter_decode_bridge(vector_path, run_dir)
    actual_decoded = _decoded_models(bridge["report"]) if bridge["exit_code"] == 0 else []
    actual_path = run_dir / "libcrafter-decoded.json"
    write_json(actual_path, bridge["report"])

    results = _compare_offline_results(
        args=args,
        expected=expected_decoded,
        actual=actual_decoded,
        plans=plans,
    )
    results = _with_failure_artifacts(
        run_dir=run_dir,
        results=results,
        vectors=vectors,
        backend_decoded=expected_decoded,
        libcrafter_decoded=actual_decoded,
    )
    failures = [result for result in results if not result.passed]
    status = "passed" if not failures and bridge["exit_code"] == 0 else "failed"
    preserve_artifacts = args.keep_artifacts or status != "passed"

    artifacts = [str(report_path)]
    if preserve_artifacts:
        artifacts.extend(
            [
                str(run_dir),
                str(vector_path),
                str(expected_path),
                str(actual_path),
                str(bridge["stdout_path"]),
                str(bridge["stderr_path"]),
            ]
        )
    artifacts.extend(_comparison_artifact_paths(failures))
    artifacts = _dedupe_paths(artifacts)

    report = RunReport(
        mode="offline",
        backend=args.backend,
        profile=args.profile,
        seed=args.seed,
        count=len(results),
        status=status,
        selected_specs=selected_specs,
        artifacts=artifacts,
        artifact_paths=artifacts,
        results=results,
        failures=failures,
        reproduction_commands=[
            command
            for command in (result.reproduction_command for result in failures)
            if command is not None
        ],
        backend_versions=backend_versions,
        libcrafter=libcrafter_info,
        metadata={
            "direction": args.direction,
            "requested_count": args.count,
            "generated_count": len(plans),
            "artifact_dir": str(run_dir) if preserve_artifacts else None,
            "backend_capabilities": backend_capabilities,
            "libcrafter_bridge": {
                "argv": bridge["argv"],
                "exit_code": bridge["exit_code"],
            },
            "vectors": _vector_summaries(vectors),
        },
    )
    write_json(report_path, report)

    if not preserve_artifacts:
        shutil.rmtree(run_dir)

    passed_count = len(results) - len(failures)
    print(
        f"offline {args.direction}: status={status} "
        f"passed={passed_count}/{len(results)} report={report_path}"
    )
    if failures:
        indexes = ", ".join(str(index) for index in failure_indexes(failures))
        print(f"failing_indexes={indexes}", file=sys.stderr)
        if failures[0].reproduction_command:
            print(f"reproduce: {failures[0].reproduction_command}", file=sys.stderr)

    return 0 if status == "passed" else 1


def _offline_libcrafter_to_reference(args: argparse.Namespace) -> int:
    if args.direction != "libcrafter_to_reference":
        print(f"unsupported offline direction: {args.direction}", file=sys.stderr)
        return 2
    if args.backend not in {"scapy", "wireshark"}:
        print(f"unsupported backend: {args.backend}", file=sys.stderr)
        return 2

    from .generator import generate_plans
    if args.backend == "scapy":
        from .backends.scapy.normalize import decode_vectors
    else:
        from .backends.wireshark.normalize import decode_vectors

    output_dir = _offline_output_dir(args.out)
    artifacts_root = output_dir / "artifacts"
    artifacts_root.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "report.json"
    backend_decoded_path = output_dir / f"{args.backend}-decoded.json"
    run_dir = Path(
        tempfile.mkdtemp(
            prefix=f"{args.direction}.",
            dir=artifacts_root,
        )
    )

    backend_versions = _backend_versions(args.backend)
    libcrafter_info = _libcrafter_info()
    plans = generate_plans(
        seed=args.seed,
        profile=args.profile,
        backend=args.backend,
        count=args.count,
        root=args.root,
        family=args.family,
        case=args.case_name,
        feature=args.feature,
        direction=args.direction,
        index=args.index,
    )
    selected_specs = _selected_specs_for_plans(plans)
    backend_capabilities = _offline_backend_capabilities(args)

    plan_report = RunReport(
        mode="offline",
        backend=args.backend,
        profile=args.profile,
        seed=args.seed,
        count=len(plans),
        status="generated",
        selected_specs=selected_specs,
        backend_versions=backend_versions,
        libcrafter=libcrafter_info,
        metadata={
            "direction": args.direction,
            "requested_count": args.count,
            "generated_count": len(plans),
            "backend_capabilities": backend_capabilities,
            "plans": [plan.to_dict() for plan in plans],
        },
    )
    plan_path = run_dir / "libcrafter-plans.json"
    write_json(plan_path, plan_report)

    materializer = _run_libcrafter_plan_materializer(plan_path, run_dir)
    vector_report = materializer["report"]
    vectors = _encoded_vectors(vector_report) if materializer["exit_code"] == 0 else []
    vector_path = run_dir / "libcrafter-vectors.json"
    write_json(vector_path, vector_report)

    bridge = _run_libcrafter_decode_bridge(vector_path, run_dir) if vectors else {
        "argv": [],
        "exit_code": 1,
        "report": RunReport(
            mode="offline",
            backend="libcrafter",
            profile=args.profile,
            seed=args.seed,
            count=0,
            status="failed",
            selected_specs=selected_specs,
            backend_versions=backend_versions,
            libcrafter=libcrafter_info,
            metadata={
                "decoded": [],
                "error": "libcrafter plan materializer did not emit vectors",
                "materializer_exit_code": materializer["exit_code"],
            },
        ).to_dict(),
        "stdout_path": materializer["stdout_path"],
        "stderr_path": materializer["stderr_path"],
    }
    expected_decoded = _decoded_models(bridge["report"]) if bridge["exit_code"] == 0 else []
    expected_path = run_dir / "libcrafter-expected-decoded.json"
    write_json(
        expected_path,
        bridge["report"],
    )

    actual_decoded = decode_vectors(vectors) if vectors else []
    backend_report = RunReport(
        mode="offline",
        backend=args.backend,
        profile=args.profile,
        seed=args.seed,
        count=len(actual_decoded),
        status="decoded",
        selected_specs=selected_specs,
        backend_versions=backend_versions,
        libcrafter=libcrafter_info,
        metadata={
            "direction": args.direction,
            "backend_capabilities": backend_capabilities,
            "decoded": [model.to_dict() for model in actual_decoded],
        },
    )
    actual_path = run_dir / f"{args.backend}-decoded.json"
    write_json(actual_path, backend_report)
    write_json(backend_decoded_path, backend_report)

    results = _compare_offline_results(
        args=args,
        expected=expected_decoded,
        actual=actual_decoded,
        plans=plans,
    )
    results = _with_failure_artifacts(
        run_dir=run_dir,
        results=results,
        vectors=vectors,
        backend_decoded=actual_decoded,
        libcrafter_decoded=expected_decoded,
    )
    failures = [result for result in results if not result.passed]
    status = (
        "passed"
        if not failures and materializer["exit_code"] == 0 and bridge["exit_code"] == 0
        else "failed"
    )
    preserve_artifacts = args.keep_artifacts or status != "passed"

    artifacts = [str(report_path), str(backend_decoded_path)]
    if preserve_artifacts:
        artifacts.extend(
            [
                str(run_dir),
                str(plan_path),
                str(vector_path),
                str(expected_path),
                str(actual_path),
                str(materializer["stdout_path"]),
                str(materializer["stderr_path"]),
                str(bridge["stdout_path"]),
                str(bridge["stderr_path"]),
            ]
        )
    artifacts.extend(_comparison_artifact_paths(failures))
    artifacts = _dedupe_paths(artifacts)

    report = RunReport(
        mode="offline",
        backend=args.backend,
        profile=args.profile,
        seed=args.seed,
        count=len(results),
        status=status,
        selected_specs=selected_specs,
        artifacts=artifacts,
        artifact_paths=artifacts,
        results=results,
        failures=failures,
        reproduction_commands=[
            command
            for command in (result.reproduction_command for result in failures)
            if command is not None
        ],
        backend_versions=backend_versions,
        libcrafter=libcrafter_info,
        metadata={
            "direction": args.direction,
            "requested_count": args.count,
            "generated_count": len(plans),
            "artifact_dir": str(run_dir) if preserve_artifacts else None,
            "backend_capabilities": backend_capabilities,
            "libcrafter_materializer": {
                "argv": materializer["argv"],
                "exit_code": materializer["exit_code"],
            },
            "libcrafter_bridge": {
                "argv": bridge["argv"],
                "exit_code": bridge["exit_code"],
            },
            "vectors": _vector_summaries(vectors),
        },
    )
    write_json(report_path, report)

    if not preserve_artifacts:
        shutil.rmtree(run_dir)

    passed_count = len(results) - len(failures)
    print(
        f"offline {args.direction}: status={status} "
        f"passed={passed_count}/{len(results)} report={report_path}"
    )
    if failures:
        indexes = ", ".join(str(index) for index in failure_indexes(failures))
        print(f"failing_indexes={indexes}", file=sys.stderr)
        if failures[0].reproduction_command:
            print(f"reproduce: {failures[0].reproduction_command}", file=sys.stderr)

    return 0 if status == "passed" else 1


def _pcap_reference_to_libcrafter(
    *,
    args: argparse.Namespace,
    run_dir: Path,
    vector_path: Path,
    vectors: list[EncodedVector],
    plans: list[PacketPlan],
    label: str,
) -> JSONObject:
    from .backends.scapy.pcap import read_pcap, write_pcap

    pcap_path = run_dir / f"{label}.scapy-reference.pcap"
    write_pcap(pcap_path, vectors)
    expected_records = read_pcap(pcap_path)
    expected_path = run_dir / f"{label}.scapy-reference-read.json"
    write_json(expected_path, {"records": expected_records})

    bridge = _run_libcrafter_pcap_reader(pcap_path, run_dir, f"{label}.scapy-reference")
    actual_records = _pcap_records(bridge["report"])
    actual_path = run_dir / f"{label}.libcrafter-read-scapy-reference.json"
    write_json(actual_path, bridge["report"])

    results = _compare_pcap_records(
        args=args,
        direction="reference_to_libcrafter",
        expected=expected_records,
        actual=actual_records,
        plans=plans,
    )

    artifacts = _dedupe_paths(
        [
            str(vector_path),
            str(pcap_path),
            str(expected_path),
            str(actual_path),
            str(bridge["stdout_path"]),
            str(bridge["stderr_path"]),
        ]
    )
    return {
        "results": results,
        "artifacts": artifacts,
        "bridge_exit_code": bridge["exit_code"],
        "metadata": {
            "direction": "reference_to_libcrafter",
            "writer": "scapy",
            "reader": "libcrafter",
            "label": label,
            "pcap": str(pcap_path),
            "record_count": len(expected_records),
            "libcrafter_bridge": {
                "argv": bridge["argv"],
                "exit_code": bridge["exit_code"],
            },
        },
    }


def _pcap_libcrafter_to_reference(
    *,
    args: argparse.Namespace,
    run_dir: Path,
    vector_path: Path,
    vectors: list[EncodedVector],
    plans: list[PacketPlan],
    label: str,
) -> JSONObject:
    from .backends.scapy.pcap import pcap_link_type_for_vectors

    pcap_path = run_dir / f"{label}.libcrafter-reference.pcap"
    bridge = _run_libcrafter_pcap_writer(
        vector_path=vector_path,
        pcap_path=pcap_path,
        run_dir=run_dir,
        label=f"{label}.libcrafter-reference",
        link_type=pcap_link_type_for_vectors(vectors, requested="ethernet"),
    )
    expected_records = _pcap_records(bridge["report"])
    expected_path = run_dir / f"{label}.libcrafter-reference-written.json"
    write_json(expected_path, bridge["report"])

    actual_records = _pcap_read_reference_records(args.backend, pcap_path)
    actual_path = run_dir / f"{label}.{args.backend}-read-libcrafter-reference.json"
    write_json(actual_path, {"records": actual_records})

    results = _compare_pcap_records(
        args=args,
        direction="libcrafter_to_reference",
        expected=expected_records,
        actual=actual_records,
        plans=plans,
    )

    artifacts = _dedupe_paths(
        [
            str(vector_path),
            str(pcap_path),
            str(expected_path),
            str(actual_path),
            str(bridge["stdout_path"]),
            str(bridge["stderr_path"]),
        ]
    )
    return {
        "results": results,
        "artifacts": artifacts,
        "bridge_exit_code": bridge["exit_code"],
        "metadata": {
            "direction": "libcrafter_to_reference",
            "writer": "libcrafter",
            "reader": args.backend,
            "label": label,
            "pcap": str(pcap_path),
            "record_count": len(expected_records),
            "libcrafter_bridge": {
                "argv": bridge["argv"],
                "exit_code": bridge["exit_code"],
            },
        },
    }


def _pcap_read_reference_records(backend: str, pcap_path: Path) -> list[JSONObject]:
    if backend == "scapy":
        from .backends.scapy.pcap import read_pcap

        return read_pcap(pcap_path)
    if backend == "wireshark":
        from .backends.wireshark.pcap import read_pcap

        return read_pcap(pcap_path)
    raise RuntimeError(f"unsupported pcap read backend: {backend}")


def _compare_pcap_records(
    *,
    args: argparse.Namespace,
    direction: str,
    expected: list[JSONObject],
    actual: list[JSONObject],
    plans: list[PacketPlan],
) -> list[ComparisonResult]:
    results: list[ComparisonResult] = []
    shared_count = min(len(expected), len(actual), len(plans))
    for position in range(shared_count):
        plan = replace(plans[position], direction=direction)
        differences: list[JSONObject] = []
        _pcap_diff("raw_hex", expected[position], actual[position], differences)
        _pcap_diff("link_type.name", expected[position], actual[position], differences)
        _pcap_diff("link_type.datalink", expected[position], actual[position], differences)
        _pcap_diff("timestamp", expected[position], actual[position], differences)
        _pcap_diff("layers", expected[position], actual[position], differences)

        passed = not differences
        results.append(
            ComparisonResult(
                passed=passed,
                direction=direction,
                expected=expected[position],
                actual=actual[position],
                plan=plan,
                strict_bytes=plan.strict_bytes,
                byte_equal=_pcap_value(expected[position], "raw_hex")
                == _pcap_value(actual[position], "raw_hex"),
                differences=differences,
                reproduction_command=None
                if passed
                else _pcap_reproduction_command(args, plan.index, direction),
                metadata={
                    "checks": [
                        "packet_count",
                        "link_type",
                        "raw_packet_bytes",
                        "normalized_layers",
                        "timestamp_policy",
                    ],
                    "timestamp_policy": "exact",
                },
            )
        )

    if len(actual) == len(expected) == len(plans):
        return results

    count_difference: JSONObject = {
        "path": "packet_count",
        "expected": len(expected),
        "actual": len(actual),
    }
    for position in range(shared_count, max(len(expected), len(actual), len(plans))):
        plan = replace(plans[min(position, len(plans) - 1)], direction=direction)
        results.append(
            ComparisonResult(
                passed=False,
                direction=direction,
                expected=expected[position] if position < len(expected) else {},
                actual=actual[position] if position < len(actual) else {},
                plan=plan,
                strict_bytes=plan.strict_bytes,
                byte_equal=False,
                differences=[count_difference],
                reproduction_command=_pcap_reproduction_command(args, plan.index, direction),
            )
        )
    return results


def _compare_offline_results(
    *,
    args: argparse.Namespace,
    expected: list[object],
    actual: list[object],
    plans: list[PacketPlan],
    partial_expected: bool = False,
) -> list[ComparisonResult]:
    results: list[ComparisonResult] = []
    shared_count = min(len(expected), len(actual), len(plans))
    for item in range(shared_count):
        plan = plans[item]
        results.append(
            compare_decoded_models(
                expected=expected[item],
                actual=actual[item],
                plan=plan,
                direction=args.direction,
                reproduction_command=_reproduction_command(args, plan.index),
                partial_expected=partial_expected,
                actual_strict_bytes_hex=_strict_bytes_hex(actual[item]),
            )
        )

    if len(actual) == len(expected) == len(plans):
        return results

    for item in range(shared_count, len(plans)):
        plan = plans[item]
        results.append(
            ComparisonResult(
                passed=False,
                direction=args.direction,
                expected=_model_to_object(expected[item]) if item < len(expected) else {},
                actual=_model_to_object(actual[item]) if item < len(actual) else {},
                plan=plan,
                strict_bytes=plan.strict_bytes,
                byte_equal=False,
                differences=[
                    {
                        "path": "decoded_count",
                        "expected": len(expected),
                        "actual": len(actual),
                    }
                ],
                reproduction_command=_reproduction_command(args, plan.index),
            )
        )
    return results


def _with_failure_artifacts(
    *,
    run_dir: Path,
    results: list[ComparisonResult],
    vectors: list[EncodedVector],
    backend_decoded: list[object],
    libcrafter_decoded: list[object],
) -> list[ComparisonResult]:
    """Write exact per-packet reproduction artifacts for failed comparisons."""

    updated: list[ComparisonResult] = []
    for position, result in enumerate(results):
        if result.passed:
            updated.append(result)
            continue

        index = result.plan.index if result.plan is not None else position
        failure_dir = run_dir / "failures" / f"index-{index:06d}"
        failure_dir.mkdir(parents=True, exist_ok=True)

        plan_path = failure_dir / "packet-plan.json"
        raw_path = failure_dir / "raw.hex"
        backend_path = failure_dir / "backend-decoded.json"
        libcrafter_path = failure_dir / "libcrafter-decoded.json"
        diff_path = failure_dir / "comparison-diff.json"

        write_json(plan_path, result.plan if result.plan is not None else {})
        raw_hex = vectors[position].raw_hex if position < len(vectors) else ""
        raw_path.write_text(f"{raw_hex}\n", encoding="utf-8")
        write_json(
            backend_path,
            _model_to_object(backend_decoded[position]) if position < len(backend_decoded) else {},
        )
        write_json(
            libcrafter_path,
            (
                _model_to_object(libcrafter_decoded[position])
                if position < len(libcrafter_decoded)
                else {}
            ),
        )

        artifact_paths = [
            str(plan_path),
            str(raw_path),
            str(backend_path),
            str(libcrafter_path),
            str(diff_path),
        ]
        result_with_artifacts = replace(result, artifacts=artifact_paths)
        write_json(diff_path, result_with_artifacts)
        updated.append(result_with_artifacts)

    return updated


def _comparison_artifact_paths(results: Sequence[ComparisonResult]) -> list[str]:
    paths: list[str] = []
    for result in results:
        paths.extend(result.artifacts)
    return paths


def _selected_specs_for_plans(plans: Sequence[PacketPlan]) -> list[str]:
    selected: list[str] = []
    seen: set[str] = set()
    for spec in GENERATOR_SELECTED_SPECS:
        if spec not in seen:
            selected.append(spec)
            seen.add(spec)

    for plan in plans:
        for spec in _string_values(plan.metadata.get("selected_specs", [])):
            if spec in seen:
                continue
            selected.append(spec)
            seen.add(spec)
    return selected


def _offline_backend_capabilities(args: argparse.Namespace) -> JSONObject:
    capabilities: JSONObject = {}
    try:
        capabilities["reference_backend"] = get_backend(args.backend).to_dict()
    except UnknownBackendError as exc:
        capabilities["reference_backend"] = {"name": args.backend, "error": str(exc)}
    try:
        capabilities["libcrafter"] = get_backend_capability_registration("libcrafter").to_dict()
    except UnknownBackendError as exc:
        capabilities["libcrafter"] = {"name": "libcrafter", "error": str(exc)}
    return capabilities


def _vector_summaries(vectors: Sequence[EncodedVector]) -> list[JSONObject]:
    summaries: list[JSONObject] = []
    for vector in vectors:
        summaries.append(
            {
                "index": vector.plan.index,
                "backend": vector.backend,
                "root": vector.root,
                "decoder": vector.decoder,
                "raw_hex": vector.raw_hex,
                "selected_specs": _string_values(
                    vector.plan.metadata.get("selected_specs", [])
                ),
            }
        )
    return summaries


def _dedupe_paths(paths: Sequence[str]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for path in paths:
        if path in seen:
            continue
        seen.add(path)
        output.append(path)
    return output


def _run_libcrafter_decode_bridge(vector_path: Path, run_dir: Path) -> JSONObject:
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
        str(vector_path),
    ]
    process = subprocess.run(
        argv,
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    stdout_path = run_dir / "libcrafter-decode.stdout.json"
    stderr_path = run_dir / "libcrafter-decode.stderr.txt"
    stdout_path.write_text(process.stdout, encoding="utf-8")
    stderr_path.write_text(process.stderr, encoding="utf-8")

    if process.returncode != 0:
        report = RunReport(
            mode="offline",
            backend="libcrafter",
            profile="unknown",
            seed=0,
            count=0,
            status="failed",
            artifact_paths=[str(stdout_path), str(stderr_path)],
            artifacts=[str(stdout_path), str(stderr_path)],
            libcrafter=_libcrafter_info(),
            metadata={
                "decoded": [],
                "error": "libcrafter decode bridge failed",
                "exit_code": process.returncode,
            },
        )
        return {
            "argv": argv,
            "exit_code": process.returncode,
            "report": report.to_dict(),
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
        }

    try:
        report = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        report = RunReport(
            mode="offline",
            backend="libcrafter",
            profile="unknown",
            seed=0,
            count=0,
            status="failed",
            artifact_paths=[str(stdout_path), str(stderr_path)],
            artifacts=[str(stdout_path), str(stderr_path)],
            libcrafter=_libcrafter_info(),
            metadata={
                "decoded": [],
                "error": f"libcrafter decode bridge emitted invalid JSON: {exc}",
                "exit_code": process.returncode,
            },
        )
        return {
            "argv": argv,
            "exit_code": 1,
            "report": report.to_dict(),
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
        }
    if not isinstance(report, dict):
        report = RunReport(
            mode="offline",
            backend="libcrafter",
            profile="unknown",
            seed=0,
            count=0,
            status="failed",
            artifact_paths=[str(stdout_path), str(stderr_path)],
            artifacts=[str(stdout_path), str(stderr_path)],
            libcrafter=_libcrafter_info(),
            metadata={
                "decoded": [],
                "error": "libcrafter decode bridge report must be a JSON object",
                "exit_code": process.returncode,
            },
        ).to_dict()
        return {
            "argv": argv,
            "exit_code": 1,
            "report": report,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
        }

    return {
        "argv": argv,
        "exit_code": process.returncode,
        "report": report,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
    }


def _run_libcrafter_plan_materializer(plan_path: Path, run_dir: Path) -> JSONObject:
    argv = [
        "cargo",
        "run",
        "-q",
        "-p",
        "crafter",
        "--example",
        "oracle_materialize_plans",
        "--",
        "--input",
        str(plan_path),
    ]
    process = subprocess.run(
        argv,
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    stdout_path = run_dir / "libcrafter-materialize.stdout.json"
    stderr_path = run_dir / "libcrafter-materialize.stderr.txt"
    stdout_path.write_text(process.stdout, encoding="utf-8")
    stderr_path.write_text(process.stderr, encoding="utf-8")

    if process.returncode != 0:
        report = RunReport(
            mode="offline",
            backend="libcrafter",
            profile="unknown",
            seed=0,
            count=0,
            status="failed",
            artifact_paths=[str(stdout_path), str(stderr_path)],
            artifacts=[str(stdout_path), str(stderr_path)],
            libcrafter=_libcrafter_info(),
            metadata={
                "vectors": [],
                "error": "libcrafter plan materializer failed",
                "exit_code": process.returncode,
            },
        ).to_dict()
        return {
            "argv": argv,
            "exit_code": process.returncode,
            "report": report,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
        }

    try:
        report = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        report = RunReport(
            mode="offline",
            backend="libcrafter",
            profile="unknown",
            seed=0,
            count=0,
            status="failed",
            artifact_paths=[str(stdout_path), str(stderr_path)],
            artifacts=[str(stdout_path), str(stderr_path)],
            libcrafter=_libcrafter_info(),
            metadata={
                "vectors": [],
                "error": f"libcrafter plan materializer emitted invalid JSON: {exc}",
                "exit_code": process.returncode,
            },
        ).to_dict()
        return {
            "argv": argv,
            "exit_code": 1,
            "report": report,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
        }

    if not isinstance(report, dict):
        report = RunReport(
            mode="offline",
            backend="libcrafter",
            profile="unknown",
            seed=0,
            count=0,
            status="failed",
            artifact_paths=[str(stdout_path), str(stderr_path)],
            artifacts=[str(stdout_path), str(stderr_path)],
            libcrafter=_libcrafter_info(),
            metadata={
                "vectors": [],
                "error": "libcrafter plan materializer report must be a JSON object",
                "exit_code": process.returncode,
            },
        ).to_dict()
        return {
            "argv": argv,
            "exit_code": 1,
            "report": report,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
        }

    return {
        "argv": argv,
        "exit_code": process.returncode,
        "report": report,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
    }


def _run_libcrafter_vector_emitter(run_dir: Path) -> JSONObject:
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
    process = subprocess.run(
        argv,
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    stdout_path = run_dir / "libcrafter-vectors.stdout.json"
    stderr_path = run_dir / "libcrafter-vectors.stderr.txt"
    stdout_path.write_text(process.stdout, encoding="utf-8")
    stderr_path.write_text(process.stderr, encoding="utf-8")

    if process.returncode != 0:
        raise RuntimeError(
            "libcrafter vector emitter failed with exit "
            f"{process.returncode}; stderr={stderr_path}"
        )

    try:
        manifest = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"libcrafter vector emitter emitted invalid JSON: {exc}") from exc
    if not isinstance(manifest, dict):
        raise RuntimeError("libcrafter vector emitter manifest must be a JSON object")

    return {
        "argv": argv,
        "exit_code": process.returncode,
        "manifest": manifest,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
    }


def _run_libcrafter_pcap_reader(pcap_path: Path, run_dir: Path, label: str) -> JSONObject:
    argv = [
        "cargo",
        "run",
        "-q",
        "-p",
        "crafter",
        "--example",
        "oracle_pcap",
        "--",
        "--read-pcap",
        str(pcap_path),
    ]
    return _run_libcrafter_json_command(argv, run_dir, f"{label}.libcrafter-read")


def _run_libcrafter_pcap_writer(
    *,
    vector_path: Path,
    pcap_path: Path,
    run_dir: Path,
    label: str,
    link_type: str,
) -> JSONObject:
    argv = [
        "cargo",
        "run",
        "-q",
        "-p",
        "crafter",
        "--example",
        "oracle_pcap",
        "--",
        "--write-pcap",
        str(pcap_path),
        "--input",
        str(vector_path),
        "--link-type",
        link_type,
    ]
    return _run_libcrafter_json_command(argv, run_dir, f"{label}.libcrafter-write")


def _run_libcrafter_json_command(argv: list[str], run_dir: Path, label: str) -> JSONObject:
    process = subprocess.run(
        argv,
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    stdout_path = run_dir / f"{label}.stdout.json"
    stderr_path = run_dir / f"{label}.stderr.txt"
    stdout_path.write_text(process.stdout, encoding="utf-8")
    stderr_path.write_text(process.stderr, encoding="utf-8")

    if process.returncode != 0:
        report = RunReport(
            mode="pcap",
            backend="libcrafter",
            profile="unknown",
            seed=0,
            count=0,
            status="failed",
            artifact_paths=[str(stdout_path), str(stderr_path)],
            artifacts=[str(stdout_path), str(stderr_path)],
            libcrafter=_libcrafter_info(),
            metadata={
                "records": [],
                "error": "libcrafter pcap bridge failed",
                "exit_code": process.returncode,
            },
        ).to_dict()
        return {
            "argv": argv,
            "exit_code": process.returncode,
            "report": report,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
        }

    try:
        report = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        report = RunReport(
            mode="pcap",
            backend="libcrafter",
            profile="unknown",
            seed=0,
            count=0,
            status="failed",
            artifact_paths=[str(stdout_path), str(stderr_path)],
            artifacts=[str(stdout_path), str(stderr_path)],
            libcrafter=_libcrafter_info(),
            metadata={
                "records": [],
                "error": f"libcrafter pcap bridge emitted invalid JSON: {exc}",
                "exit_code": process.returncode,
            },
        ).to_dict()
        return {
            "argv": argv,
            "exit_code": 1,
            "report": report,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
        }

    if not isinstance(report, dict):
        report = RunReport(
            mode="pcap",
            backend="libcrafter",
            profile="unknown",
            seed=0,
            count=0,
            status="failed",
            artifact_paths=[str(stdout_path), str(stderr_path)],
            artifacts=[str(stdout_path), str(stderr_path)],
            libcrafter=_libcrafter_info(),
            metadata={
                "records": [],
                "error": "libcrafter pcap bridge report must be a JSON object",
                "exit_code": process.returncode,
            },
        ).to_dict()
        return {
            "argv": argv,
            "exit_code": 1,
            "report": report,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
        }

    return {
        "argv": argv,
        "exit_code": process.returncode,
        "report": report,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
    }


def _decoded_models(report: object) -> list[JSONObject]:
    report_object = _json_object(report, "libcrafter report")
    metadata = _json_object(report_object.get("metadata", {}), "libcrafter report metadata")
    decoded = metadata.get("decoded")
    if not isinstance(decoded, list):
        raise RuntimeError("libcrafter report metadata.decoded must be a list")

    output: list[JSONObject] = []
    for index, item in enumerate(decoded):
        output.append(_json_object(item, f"decoded[{index}]"))
    return output


def _encoded_vectors(report: object) -> list[EncodedVector]:
    report_object = _json_object(report, "libcrafter materializer report")
    metadata = _json_object(
        report_object.get("metadata", {}),
        "libcrafter materializer report metadata",
    )
    vectors = metadata.get("vectors")
    if not isinstance(vectors, list):
        raise RuntimeError("libcrafter materializer report metadata.vectors must be a list")

    output: list[EncodedVector] = []
    for index, item in enumerate(vectors):
        vector = _json_object(item, f"vectors[{index}]")
        raw_hex = _optional_string(vector.get("raw_hex")) or _optional_string(vector.get("hex"))
        if raw_hex is None:
            raise RuntimeError(f"libcrafter materialized vector {index} is missing raw_hex")
        plan = _packet_plan_from_object(vector.get("plan"), f"vectors[{index}].plan")
        root = _optional_string(vector.get("root")) or _optional_string(vector.get("decoder"))
        if root is None:
            raise RuntimeError(f"libcrafter materialized vector {index} is missing root")
        output.append(
            EncodedVector(
                plan=plan,
                backend=_optional_string(vector.get("backend")) or "libcrafter",
                raw_hex=raw_hex,
                root=root,
                decoder=_optional_string(vector.get("decoder")) or root,
                metadata=_json_object(vector.get("metadata", {}), f"vectors[{index}].metadata"),
            )
        )
    return output


def _packet_plan_from_object(value: object, name: str) -> PacketPlan:
    plan = _json_object(value, name)
    fields_object = _json_object(plan.get("fields", {}), f"{name}.fields")
    fields = {
        layer: _json_object(layer_fields, f"{name}.fields.{layer}")
        for layer, layer_fields in fields_object.items()
    }
    return PacketPlan(
        stack=_string_values(plan.get("stack", [])),
        fields=fields,
        profile=_optional_string(plan.get("profile")) or "unknown",
        seed=_object_int(plan.get("seed"), 0),
        index=_object_int(plan.get("index"), 0),
        direction=_optional_string(plan.get("direction")) or "libcrafter_to_reference",
        family=_optional_string(plan.get("family")),
        feature_tags=_string_values(plan.get("feature_tags", [])),
        case=_optional_string(plan.get("case")),
        strict_bytes=plan.get("strict_bytes") is not False,
        metadata=_json_object(plan.get("metadata", {}), f"{name}.metadata"),
    )


def _object_int(value: object, default: int) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    return default


def _pcap_records(report: object) -> list[JSONObject]:
    report_object = _json_object(report, "pcap report")
    metadata = _json_object(report_object.get("metadata", {}), "pcap report metadata")
    records = metadata.get("records")
    if not isinstance(records, list):
        raise RuntimeError("pcap report metadata.records must be a list")

    output: list[JSONObject] = []
    for index, item in enumerate(records):
        output.append(_json_object(item, f"records[{index}]"))
    return output


def _select_libcrafter_cases(
    manifest: object,
    args: argparse.Namespace,
) -> list[tuple[int, JSONObject]]:
    manifest_object = _json_object(manifest, "libcrafter vector manifest")
    cases = manifest_object.get("cases")
    if not isinstance(cases, list):
        raise RuntimeError("libcrafter vector manifest cases must be a list")

    entries: list[tuple[int, JSONObject]] = []
    for index, case in enumerate(cases):
        case_object = _json_object(case, f"cases[{index}]")
        if not _case_supports_direction(case_object, args.direction):
            continue
        entries.append((index, case_object))

    if args.case_name is not None:
        entries = [
            (index, case)
            for index, case in entries
            if case.get("name") == args.case_name
        ]
    if args.family is not None:
        entries = [
            (index, case)
            for index, case in entries
            if case.get("family") == args.family
        ]
    if args.feature is not None:
        entries = [
            (index, case)
            for index, case in entries
            if args.feature in _string_values(case.get("features", []))
            or args.feature in _string_values(case.get("feature_tags", []))
        ]
    if args.index is not None:
        entries = [
            (index, case)
            for index, case in entries
            if index == args.index
        ]
    else:
        entries = entries[: args.count]

    if not entries:
        raise RuntimeError("no libcrafter oracle vector cases selected")
    return entries


def _case_supports_direction(case: JSONObject, direction: str) -> bool:
    directions = case.get("directions")
    if isinstance(directions, list) and direction in directions:
        return True
    return case.get("direction") == direction


def _libcrafter_case_plan(
    case: JSONObject,
    args: argparse.Namespace,
    index: int,
) -> PacketPlan:
    expected = _json_object(case.get("expected_decoded", {}), f"case[{index}].expected_decoded")
    stack = _string_values(expected.get("layers", []))
    fields = _json_object(expected.get("fields", {}), f"case[{index}].expected_decoded.fields")
    name = _optional_string(case.get("name"))
    family = _optional_string(case.get("family"))
    strict_bytes = case.get("strict_bytes")
    return PacketPlan(
        stack=stack,
        fields=fields,
        profile=args.profile,
        seed=args.seed,
        index=index,
        direction=args.direction,
        family=family,
        feature_tags=_string_values(case.get("feature_tags", [])),
        case=name,
        strict_bytes=strict_bytes is not False,
        metadata={
            "plan_id": f"libcrafter:{index}",
            "case": name,
            "generator": "cargo run -q -p crafter --example oracle_vectors -- --json",
            "source": "libcrafter oracle vector emitter",
        },
    )


def _libcrafter_case_vector(case: JSONObject, plan: PacketPlan) -> EncodedVector:
    raw_hex = _optional_string(case.get("raw_hex")) or _optional_string(case.get("hex"))
    if raw_hex is None:
        raise RuntimeError(f"libcrafter case {plan.index} is missing raw_hex")
    root = _optional_string(case.get("root_decoder")) or _optional_string(case.get("root"))
    if root is None:
        raise RuntimeError(f"libcrafter case {plan.index} is missing root/root_decoder")
    return EncodedVector(
        plan=plan,
        backend="libcrafter",
        raw_hex=raw_hex,
        root=root,
        decoder=root,
        metadata={
            "case": plan.case,
            "length": len(bytes.fromhex(raw_hex)),
            "strict_bytes": plan.strict_bytes,
            "summary": case.get("summary"),
        },
    )


def _strict_bytes_hex(model: object) -> str | None:
    model_object = model.to_dict() if isinstance(model, DecodedModel) else model
    if not isinstance(model_object, dict):
        return None
    metadata = model_object.get("metadata")
    if not isinstance(metadata, dict):
        return None
    value = metadata.get("reencoded_hex")
    if isinstance(value, str):
        return value
    error = metadata.get("reencoded_error")
    if isinstance(error, str):
        return f"<scapy re-encode failed: {error}>"
    return None


def _model_to_object(model: object) -> JSONObject:
    value = model.to_dict() if hasattr(model, "to_dict") else model
    return _json_object(value, "oracle model")


def _backend_versions(backend: str) -> JSONObject:
    try:
        return {
            backend: backend_report_metadata(
                backend,
                include_dependency_metadata=True,
            )
        }
    except UnknownBackendError:
        return {}


def _libcrafter_info() -> JSONObject:
    info: JSONObject = {}
    version = _workspace_package_version()
    if version is not None:
        info["version"] = version
    commit = _git_head_commit()
    if commit is not None:
        info["commit"] = commit
    return info


def _workspace_package_version() -> str | None:
    try:
        document = tomllib.loads((REPO_ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return None

    workspace = document.get("workspace")
    if not isinstance(workspace, dict):
        return None
    package = workspace.get("package")
    if not isinstance(package, dict):
        return None
    version = package.get("version")
    return version if isinstance(version, str) else None


def _git_head_commit() -> str | None:
    git_dir = REPO_ROOT / ".git"
    try:
        if git_dir.is_file():
            content = git_dir.read_text(encoding="utf-8").strip()
            if not content.startswith("gitdir:"):
                return None
            raw_path = Path(content.split(":", 1)[1].strip())
            git_dir = raw_path if raw_path.is_absolute() else (REPO_ROOT / raw_path).resolve()

        head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
        if not head:
            return None
        if not head.startswith("ref:"):
            return head

        ref_name = head.removeprefix("ref:").strip()
        common_dir = _git_common_dir(git_dir)
        ref_path = git_dir / ref_name
        if ref_path.exists():
            return ref_path.read_text(encoding="utf-8").strip() or None
        ref_path = common_dir / ref_name
        if ref_path.exists():
            return ref_path.read_text(encoding="utf-8").strip() or None

        for packed_refs in (git_dir / "packed-refs", common_dir / "packed-refs"):
            if not packed_refs.exists():
                continue
            for line in packed_refs.read_text(encoding="utf-8").splitlines():
                if not line or line.startswith(("#", "^")):
                    continue
                commit, _, packed_ref = line.partition(" ")
                if packed_ref == ref_name:
                    return commit
    except OSError:
        return None
    return None


def _git_common_dir(git_dir: Path) -> Path:
    common_dir_file = git_dir / "commondir"
    if not common_dir_file.exists():
        return git_dir
    try:
        raw_path = Path(common_dir_file.read_text(encoding="utf-8").strip())
    except OSError:
        return git_dir
    return raw_path if raw_path.is_absolute() else (git_dir / raw_path).resolve()


def _offline_output_dir(out: str) -> Path:
    output_root = Path(out)
    if not output_root.is_absolute():
        output_root = REPO_ROOT / output_root
    if output_root.resolve() != (REPO_ROOT / DEFAULT_OUTPUT_ROOT).resolve():
        return output_root
    return output_root / "offline"


def _pcap_output_dir(out: str) -> Path:
    output_root = Path(out)
    if not output_root.is_absolute():
        output_root = REPO_ROOT / output_root
    return output_root / "pcap"


def _live_output_dir(out: str) -> Path:
    output_root = Path(out)
    if not output_root.is_absolute():
        output_root = REPO_ROOT / output_root
    if output_root.resolve() != (REPO_ROOT / DEFAULT_OUTPUT_ROOT).resolve():
        return output_root
    return output_root / "live"


def _reproduction_command(args: argparse.Namespace, index: int) -> str:
    argv = [
        "tools/oracle/run",
        "offline",
        "--backend",
        args.backend,
        "--direction",
        args.direction,
        "--profile",
        args.profile,
        "--seed",
        str(args.seed),
        "--count",
        "1",
        "--index",
        str(index),
    ]
    if args.case_name is not None:
        argv.extend(["--case", args.case_name])
    if args.feature is not None:
        argv.extend(["--feature", args.feature])
    if args.family is not None:
        argv.extend(["--family", args.family])
    if args.root is not None:
        argv.extend(["--root", args.root])
    return shlex.join(argv)


def _live_reproduction_command(args: argparse.Namespace) -> str:
    argv = [
        "tools/oracle/run",
        "live",
        "--backend",
        args.backend,
        "--provider",
        args.provider,
        "--direction",
        args.direction,
        "--profile",
        args.profile,
        "--seed",
        str(args.seed),
        "--count",
        str(args.count),
    ]
    if args.index is not None:
        argv.extend(["--index", str(args.index)])
    if args.case_name is not None:
        argv.extend(["--case", args.case_name])
    if args.feature is not None:
        argv.extend(["--feature", args.feature])
    if args.family is not None:
        argv.extend(["--family", args.family])
    if args.root is not None:
        argv.extend(["--root", args.root])
    if getattr(args, "dry_run", False):
        argv.append("--dry-run")
    return shlex.join(argv)


def _pcap_reproduction_command(args: argparse.Namespace, index: int, direction: str) -> str:
    argv = [
        "tools/oracle/run",
        "pcap",
        "--backend",
        args.backend,
        "--direction",
        direction,
        "--profile",
        args.profile,
        "--seed",
        str(args.seed),
        "--count",
        "1",
        "--index",
        str(index),
    ]
    if args.case_name is not None:
        argv.extend(["--case", args.case_name])
    if args.feature is not None:
        argv.extend(["--feature", args.feature])
    if args.family is not None:
        argv.extend(["--family", args.family])
    if args.root is not None:
        argv.extend(["--root", args.root])
    return shlex.join(argv)


def _pcap_diff(
    path: str,
    expected: JSONObject,
    actual: JSONObject,
    differences: list[JSONObject],
) -> None:
    expected_value = _pcap_value(expected, path)
    actual_value = _pcap_value(actual, path)
    if expected_value != actual_value:
        differences.append(
            {
                "path": path,
                "expected": expected_value,
                "actual": actual_value,
            }
        )


def _pcap_value(record: JSONObject, path: str) -> object:
    value: object = record
    for part in path.split("."):
        if not isinstance(value, dict):
            return "<missing>"
        value = value.get(part, "<missing>")
    return value


def _json_object(value: object, name: str) -> JSONObject:
    if not isinstance(value, dict):
        raise RuntimeError(f"{name} must be a JSON object")
    output: JSONObject = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise RuntimeError(f"{name} keys must be strings")
        output[key] = item  # type: ignore[assignment]
    return output


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return str(value)


def _string_values(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _pcap_execution_directions(direction: str) -> list[str]:
    if direction == "roundtrip":
        return ["reference_to_libcrafter", "libcrafter_to_reference"]
    if direction in {"reference_to_libcrafter", "libcrafter_to_reference"}:
        return [direction]
    raise ValueError(f"unsupported pcap direction: {direction}")


def _pcap_cases_for_direction(
    *,
    args: argparse.Namespace,
    direction: str,
    dry_plan: bool,
) -> list[JSONObject]:
    all_cases = [
        pcap_case
        for pcap_case in _pcap_spec_cases()
        if _pcap_case_supports_direction(pcap_case, direction)
        and _pcap_case_matches_filter(pcap_case, args.case_name, args.feature)
    ]
    if dry_plan:
        selected = all_cases
    else:
        selected = [
            pcap_case
            for pcap_case in all_cases
            if _pcap_case_roles_match(pcap_case, direction, args.backend)
        ]
        if (
            not selected
            and args.case_name is None
            and (direction == "libcrafter_to_reference" or args.feature == "pcap_link_types")
        ):
            selected = [
                _pcap_case_with_roles(pcap_case, direction, args.backend)
                for pcap_case in all_cases
                if pcap_case.get("writer") is None
                and pcap_case.get("reader") is None
                and _pcap_case_has_link_or_format(pcap_case)
                and _pcap_file_format_for_case(pcap_case) == "pcap"
            ]
        if not selected and args.case_name is not None:
            selected = [
                _pcap_case_with_roles(pcap_case, direction, args.backend)
                for pcap_case in all_cases
                if _pcap_case_has_link_or_format(pcap_case)
            ]

    if not selected:
        detail = f" direction={direction!r}"
        if args.case_name is not None:
            detail += f" case={args.case_name!r}"
        if args.feature is not None:
            detail += f" feature={args.feature!r}"
        raise ValueError(f"no pcap spec cases match{detail}")

    return [dict(pcap_case) for pcap_case in selected]


def _pcap_spec_cases() -> list[JSONObject]:
    from .spec_loader import load_oracle_specs

    specs = load_oracle_specs()
    feature = specs.features.get("pcap_contracts")
    if feature is None:
        raise ValueError("pcap feature spec is missing: pcap_contracts")
    raw_cases = feature.raw.get("supported_cases", [])
    if not isinstance(raw_cases, list):
        raise ValueError("features/pcap.yaml supported_cases must be a list")
    cases: list[JSONObject] = []
    for raw_case in raw_cases:
        if not isinstance(raw_case, dict):
            raise ValueError("features/pcap.yaml supported_cases entries must be objects")
        pcap_case = dict(raw_case)
        pcap_case.setdefault("strict_bytes", feature.strict_bytes)
        pcap_case.setdefault("timestamp_policy", "exact")
        pcap_case["feature"] = feature.name
        cases.append(pcap_case)  # type: ignore[arg-type]
    return cases


def _pcap_vector_groups(args: argparse.Namespace, direction: str) -> list[JSONObject]:
    from .backends.scapy.packets import encode_packet_plan
    from .backends.scapy.pcap import with_pcap_metadata
    from .generator import PacketGenerator

    cases = _pcap_cases_for_direction(args=args, direction=direction, dry_plan=False)
    generator = PacketGenerator(seed=args.seed, profile=args.profile, backend=args.backend)
    groups: dict[tuple[str, str], JSONObject] = {}
    for offset, index in enumerate(_pcap_indices(args)):
        pcap_case = cases[offset % len(cases)]
        file_format = _pcap_file_format_for_case(pcap_case)
        if file_format != "pcap":
            raise PcapUnsupportedError(
                f"unsupported pcap file format: {file_format} from case "
                f"{pcap_case.get('name')}; libcrafter pcap mode supports classic pcap only"
            )
        link_types = _pcap_link_types_for_case(pcap_case)
        link_type = link_types[offset % len(link_types)]
        root = _pcap_generation_root(args.root, link_type, index)
        plan = generator.generate(
            index=index,
            root=root,
            family=args.family,
            case=_pcap_generator_case(link_type, root),
            direction=direction,
        )
        plan = _pcap_plan(
            plan,
            pcap_case,
            direction,
            link_type=link_type,
            file_format=file_format,
        )
        vector = encode_packet_plan(plan)
        vector = with_pcap_metadata(
            [vector],
            link_type=_pcap_writer_link_type(link_type),
        )[0]
        record_link_type = _pcap_vector_link_type(vector)
        key = (file_format, record_link_type)
        group = groups.setdefault(
            key,
            {
                "file_format": file_format,
                "link_type": record_link_type,
                "pcap_case": pcap_case,
                "plans": [],
                "vectors": [],
            },
        )
        group["plans"].append(plan)  # type: ignore[union-attr]
        group["vectors"].append(vector)  # type: ignore[union-attr]
    return list(groups.values())


def _pcap_plan(
    plan: PacketPlan,
    pcap_case: JSONObject,
    direction: str,
    *,
    link_type: str,
    file_format: str,
) -> PacketPlan:
    strict_bytes = pcap_case.get("strict_bytes")
    metadata = dict(plan.metadata)
    metadata["pcap"] = pcap_case
    metadata["selected_spec"] = PCAP_CONTRACT_SPEC
    metadata["timestamp_policy"] = pcap_case.get("timestamp_policy")
    metadata["pcap_file_format"] = file_format
    metadata["pcap_link_type"] = link_type
    selected_specs = _string_values(metadata.get("selected_specs", []))
    for spec in PCAP_SELECTED_SPECS:
        if spec not in selected_specs:
            selected_specs.append(spec)
    metadata["selected_specs"] = selected_specs
    feature_tags = list(dict.fromkeys([*plan.feature_tags, "pcap"]))
    case_name = pcap_case.get("name")
    return replace(
        plan,
        direction=direction,
        case=case_name if isinstance(case_name, str) else plan.case,
        strict_bytes=strict_bytes if isinstance(strict_bytes, bool) else plan.strict_bytes,
        feature_tags=feature_tags,
        metadata=metadata,
    )


def _pcap_indices(args: argparse.Namespace) -> list[int]:
    if args.index is not None:
        return [args.index]
    return list(range(args.count))


def _pcap_case_supports_direction(pcap_case: JSONObject, direction: str) -> bool:
    directions = _pcap_case_directions(pcap_case)
    return direction in directions or "roundtrip" in directions


def _pcap_case_directions(pcap_case: JSONObject) -> list[str]:
    directions = _string_values(pcap_case.get("directions"))
    direction = pcap_case.get("direction")
    if isinstance(direction, str):
        directions.append(direction)
    return list(dict.fromkeys(directions))


def _pcap_case_matches_filter(
    pcap_case: JSONObject,
    case_name: str | None,
    feature: str | None,
) -> bool:
    if case_name is not None and pcap_case.get("name") != case_name:
        return False
    if feature is None:
        return True
    if feature in {"pcap", "pcap_contracts"}:
        return True
    if feature == "pcap_link_types":
        return pcap_case.get("writer") is None and pcap_case.get("reader") is None
    return False


def _pcap_case_roles_match(
    pcap_case: JSONObject,
    direction: str,
    backend: str,
) -> bool:
    writer = pcap_case.get("writer")
    reader = pcap_case.get("reader")
    if direction == "reference_to_libcrafter":
        return writer == backend and reader == "libcrafter"
    if direction == "libcrafter_to_reference":
        return writer == "libcrafter" and reader == backend
    return False


def _pcap_case_with_roles(
    pcap_case: JSONObject,
    direction: str,
    backend: str,
) -> JSONObject:
    output = dict(pcap_case)
    if direction == "reference_to_libcrafter":
        output["writer"] = backend
        output["reader"] = "libcrafter"
    elif direction == "libcrafter_to_reference":
        output["writer"] = "libcrafter"
        output["reader"] = backend
    return output


def _pcap_case_has_link_or_format(pcap_case: JSONObject) -> bool:
    return any(
        key in pcap_case
        for key in ("file_format", "file_formats", "link_type", "link_types", "roots")
    )


def _pcap_file_format_for_case(pcap_case: JSONObject) -> str:
    file_formats = _string_values(pcap_case.get("file_formats"))
    file_format = pcap_case.get("file_format")
    if isinstance(file_format, str):
        file_formats.insert(0, file_format)
    file_formats = list(dict.fromkeys(file_formats))
    if not file_formats:
        return "pcap"
    if "pcap" in file_formats:
        return "pcap"
    return file_formats[0]


def _pcap_link_types_for_case(pcap_case: JSONObject) -> list[str]:
    link_types = [_pcap_canonical_link_type(item) for item in _string_values(pcap_case.get("link_types"))]
    link_type = pcap_case.get("link_type")
    if isinstance(link_type, str):
        link_types.insert(0, _pcap_canonical_link_type(link_type))
    roots = _string_values(pcap_case.get("roots"))
    for root in roots:
        link_types.append(_pcap_link_type_for_root(root))
    link_types = list(dict.fromkeys(link_types))
    if link_types:
        return link_types
    return ["ethernet"]


def _pcap_generation_root(requested_root: str | None, link_type: str, index: int) -> str:
    if requested_root is not None:
        requested_link_type = _pcap_link_type_for_root(requested_root)
        if requested_link_type != link_type:
            raise ValueError(
                f"root {requested_root!r} is incompatible with pcap link type {link_type!r}"
            )
        return requested_root
    if link_type == "ethernet":
        return "link:ethernet"
    if link_type == "linux_cooked":
        return "link:linux-cooked"
    if link_type == "null_loopback":
        return "link:null-loopback"
    if link_type == "raw":
        return "l3:ipv6" if index % 2 else "l3:ipv4"
    raise ValueError(f"unsupported pcap link type: {link_type}")


def _pcap_generator_case(link_type: str, root: str) -> str:
    if link_type == "ethernet":
        return "arp-request"
    if link_type == "linux_cooked":
        return "linux-cooked-ipv4-udp"
    if link_type == "null_loopback":
        return "null-loopback-ipv4-little-endian"
    if link_type == "raw" and root == "link:raw":
        return "raw-payload-link"
    if link_type == "raw" and root == "l3:ipv6":
        return "udp-ipv6-checksum-length"
    if link_type == "raw":
        return "ipv4-udp"
    raise ValueError(f"unsupported pcap link type: {link_type}")


def _pcap_link_type_for_root(root: str) -> str:
    normalized = root.replace("_", "-")
    if normalized in {"link:ethernet", "ether"}:
        return "ethernet"
    if normalized in {"link:linux-cooked", "link:linux-sll", "cookedlinux"}:
        return "linux_cooked"
    if normalized in {"link:null-loopback", "loopback"}:
        return "null_loopback"
    if normalized in {"link:raw", "l3:ipv4", "l3:ipv6", "ip", "ipv6", "raw"}:
        return "raw"
    raise ValueError(f"unsupported pcap root for link type selection: {root}")


def _pcap_canonical_link_type(link_type: str) -> str:
    normalized = link_type.replace("-", "_")
    if normalized in {"linux_sll", "linux_cooked"}:
        return "linux_cooked"
    if normalized in {"ether", "ethernet"}:
        return "ethernet"
    if normalized in {"null", "null_loopback", "loopback"}:
        return "null_loopback"
    if normalized in {"raw", "raw_ip"}:
        return "raw"
    raise ValueError(f"unsupported pcap link type: {link_type}")


def _pcap_writer_link_type(link_type: str) -> str:
    if link_type == "linux_cooked":
        return "linux_sll"
    return link_type


def _pcap_vector_link_type(vector: EncodedVector) -> str:
    record = vector.metadata.get("pcap_record")
    if not isinstance(record, dict):
        raise ValueError("pcap vector metadata is missing pcap_record")
    link_type = record.get("link_type")
    if not isinstance(link_type, dict):
        raise ValueError("pcap vector metadata is missing link_type")
    name = link_type.get("name")
    if not isinstance(name, str):
        raise ValueError("pcap vector link_type.name must be a string")
    return name


def _pcap_group_label(direction: str, link_type: str) -> str:
    safe_link_type = re.sub(r"[^A-Za-z0-9_.-]+", "-", link_type)
    return f"{direction}.{safe_link_type}"


def _write_pcap_unsupported_report(
    *,
    args: argparse.Namespace,
    message: str,
    report_path: Path,
) -> int:
    try:
        backend = get_backend(args.backend)
    except UnknownBackendError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return _write_backend_support_report(
        args=args,
        mode="pcap",
        backend=backend,
        message=message,
        operation=f"pcap {args.direction}",
        required=(),
        missing=(),
        report_path=report_path,
        selected_specs=PCAP_SELECTED_SPECS,
    )


def _backend_info(args: argparse.Namespace) -> int:
    try:
        metadata = backend_report_metadata(
            args.backend,
            include_dependency_metadata=True,
        )
    except UnknownBackendError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    sys.stdout.write(dumps_json(metadata))
    return 0


def _self_check(args: argparse.Namespace) -> int:
    from .generator import run_self_checks
    from .spec_loader import run_self_checks as run_spec_self_checks

    spec_checks = run_spec_self_checks()
    run_self_checks()
    scapy_backend = get_backend("scapy")
    wireshark_backend = get_backend("wireshark")
    if (
        not scapy_backend.capabilities.encode
        or not scapy_backend.capabilities.pcap_write
    ):
        raise AssertionError("Scapy backend must expose writer capabilities")
    if (
        wireshark_backend.capabilities.encode
        or wireshark_backend.capabilities.pcap_write
    ):
        raise AssertionError("Wireshark backend must remain parser-only")
    if (
        not wireshark_backend.capabilities.decode
        or not wireshark_backend.capabilities.pcap_read
    ):
        raise AssertionError("Wireshark backend must expose parser capabilities")
    sys.stdout.write(
        dumps_json(
            {
                "status": "ok",
                "checks": [*spec_checks, "generator", "backends"],
            }
        )
    )
    return 0


def _specs_validate(args: argparse.Namespace) -> int:
    from .spec_loader import SpecValidationError, load_oracle_specs

    try:
        specs = load_oracle_specs(strict=args.strict)
    except SpecValidationError as exc:
        print(f"spec validation failed: {exc}", file=sys.stderr)
        return 2

    summary = specs.summary()
    summary["strict"] = bool(args.strict)
    if args.json:
        sys.stdout.write(dumps_json(summary))
    else:
        counts = _json_object(summary["counts"], "spec validation counts")
        print(
            "oracle specs: "
            f"status=ok roots={counts['roots']} families={counts['families']} "
            f"stacks={counts['stacks']} profiles={counts['profiles']} "
            f"layers={counts['layers']} features={counts['features']}"
        )
    return 0


def _fixtures(args: argparse.Namespace) -> int:
    if args.backend != "scapy":
        print(f"unsupported backend: {args.backend}", file=sys.stderr)
        return 2

    from .backends.scapy.fixtures import FixtureGenerationOptions, generate_fixtures

    output_dir = Path(args.out)
    if not output_dir.is_absolute():
        output_dir = REPO_ROOT / output_dir

    names = list(args.only)
    if args.case_name is not None:
        names.append(args.case_name)

    return generate_fixtures(
        FixtureGenerationOptions(
            out_dir=output_dir,
            profile=args.profile,
            seed=args.seed,
            names=names,
            families=list(args.fixture_family),
            directions=list(args.fixture_direction),
            check_drift=args.check_drift,
            list_only=args.list_cases,
        )
    )


def _report(args: argparse.Namespace) -> int:
    output_dir = Path(args.out)
    if not output_dir.is_absolute():
        output_dir = REPO_ROOT / output_dir
    commands_dir = output_dir / "commands"
    commands_dir.mkdir(parents=True, exist_ok=True)

    command_results = [
        _run_final_report_command(label, list(argv), commands_dir)
        for label, argv in FINAL_REPORT_COMMANDS
    ]
    failed_commands = [
        result
        for result in command_results
        if result.get("exit_code") != 0
    ]
    scapy_imports = _remaining_scapy_imports()
    import_classifications = _classification_counts(scapy_imports)
    status = "passed" if not failed_commands else "failed"

    summary_path = output_dir / "summary.json"
    summary: JSONObject = {
        "mode": "report",
        "status": status,
        "generated_at": dt.datetime.now(dt.timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
        "summary_path": str(summary_path),
        "backend": "scapy",
        "backend_versions": _backend_versions("scapy"),
        "libcrafter": _libcrafter_info(),
        "commands": command_results,
        "command_summary": {
            "passed": len(command_results) - len(failed_commands),
            "failed": len(failed_commands),
            "total": len(command_results),
        },
        "remaining_scapy_imports": scapy_imports,
        "remaining_scapy_import_summary": import_classifications,
        "hetzner_provider_backed_live_validation": {
            "status": "not_run",
            "reason": (
                "provider-backed Hetzner live validation requires explicit request "
                "and credentials"
            ),
        },
    }
    write_json(summary_path, summary)

    print(
        f"final report: status={status} "
        f"commands={len(command_results) - len(failed_commands)}/{len(command_results)} "
        f"scapy_import_matches={len(scapy_imports)} summary={summary_path}"
    )
    if failed_commands:
        labels = ", ".join(str(result.get("label")) for result in failed_commands)
        print(f"failed_commands={labels}", file=sys.stderr)
        return 1
    return 0


def _run_final_report_command(
    label: str,
    argv: list[str],
    commands_dir: Path,
) -> JSONObject:
    stdout_path = commands_dir / f"{label}.stdout.log"
    stderr_path = commands_dir / f"{label}.stderr.log"
    started_at = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    started = time.monotonic()

    try:
        process = subprocess.run(
            argv,
            cwd=REPO_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        exit_code = process.returncode
        stdout = process.stdout
        stderr = process.stderr
    except OSError as exc:
        exit_code = 127
        stdout = ""
        stderr = str(exc)

    duration_seconds = round(time.monotonic() - started, 3)
    stdout_path.write_text(stdout, encoding="utf-8")
    stderr_path.write_text(stderr, encoding="utf-8")

    return {
        "label": label,
        "command": shlex.join(argv),
        "exit_code": exit_code,
        "duration_seconds": duration_seconds,
        "started_at": started_at,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "stdout_tail": _tail_text(stdout),
        "stderr_tail": _tail_text(stderr),
    }


def _tail_text(text: str, *, max_lines: int = 40, max_chars: int = 6000) -> str:
    tail = "\n".join(text.splitlines()[-max_lines:])
    if len(tail) > max_chars:
        return tail[-max_chars:]
    return tail


def _remaining_scapy_imports() -> list[JSONObject]:
    matches: list[JSONObject] = []
    for root_name in REPORT_SCAN_ROOTS:
        root = REPO_ROOT / root_name
        if not root.exists():
            continue
        paths = [root] if root.is_file() else root.rglob("*")
        for path in paths:
            if not path.is_file() or _skip_report_scan_path(path):
                continue
            relative = path.relative_to(REPO_ROOT).as_posix()
            if relative.startswith("tools/oracle/engine/backends/scapy/"):
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            except OSError:
                continue
            if "\0" in text:
                continue
            for line_number, line in enumerate(text.splitlines(), start=1):
                if not SCAPY_IMPORT_RE.search(line):
                    continue
                matches.append(
                    {
                        "path": relative,
                        "line": line_number,
                        "text": line.strip(),
                        "classification": _classify_scapy_import_match(relative),
                    }
                )
    return matches


def _skip_report_scan_path(path: Path) -> bool:
    try:
        relative = path.relative_to(REPO_ROOT)
    except ValueError:
        return True
    return any(part in REPORT_SCAN_EXCLUDED_DIRS for part in relative.parts)


def _classify_scapy_import_match(relative_path: str) -> str:
    if (
        relative_path == "tools/reference/scapy-fixtures.py"
        or relative_path.startswith("tests/fixtures/")
        or "/fixtures/" in relative_path
    ):
        return "fixture data"
    if (
        relative_path.startswith("tools/reference/")
        or relative_path.startswith("tests/live/")
        or relative_path.startswith("tools/live-lab/")
    ):
        return "legacy wrapper"
    if (
        relative_path.startswith("docs/")
        or relative_path.startswith(".agents/skills/")
        or relative_path.endswith((".md", ".rst", ".txt"))
    ):
        return "allowed compatibility docs"
    return "follow-up cleanup"


def _classification_counts(matches: Sequence[JSONObject]) -> JSONObject:
    counts: dict[str, int] = {}
    for match in matches:
        classification = match.get("classification")
        if not isinstance(classification, str):
            classification = "follow-up cleanup"
        counts[classification] = counts.get(classification, 0) + 1
    return counts


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tools/oracle/run",
        description="Run libcrafter oracle validation.",
    )
    subparsers = parser.add_subparsers(
        dest="mode",
        metavar="MODE",
        required=True,
    )

    generate_parser = subparsers.add_parser(
        "generate",
        help="generate deterministic packet plans",
        description="Generate deterministic oracle packet plans.",
    )
    _add_common_options(generate_parser)
    _add_generation_options(generate_parser)
    generate_parser.add_argument(
        "--direction",
        default="reference_to_libcrafter",
        choices=(
            "reference_to_libcrafter",
            "libcrafter_to_reference",
            "roundtrip",
            "live",
            "live_exchange",
        ),
        help="plan direction metadata (default: %(default)s)",
    )
    generate_parser.set_defaults(func=_generate)

    offline_parser = subparsers.add_parser(
        "offline",
        help="run offline validation",
        description="Run offline oracle validation.",
    )
    _add_common_options(offline_parser)
    _add_generation_options(offline_parser)
    offline_parser.add_argument(
        "--direction",
        choices=("reference_to_libcrafter", "libcrafter_to_reference"),
        default="reference_to_libcrafter",
        help="offline validation direction (default: %(default)s)",
    )
    offline_parser.add_argument(
        "--keep-artifacts",
        action="store_true",
        help="keep intermediate vector and decoded artifacts for successful runs",
    )
    offline_parser.add_argument(
        "--dry-plan",
        action="store_true",
        help="print generated packet plans without invoking a backend",
    )
    offline_parser.add_argument(
        "--emit-vectors",
        action="store_true",
        help="print Scapy-materialized packet vectors without invoking libcrafter",
    )
    offline_parser.add_argument(
        "--emit-decoded",
        action="store_true",
        help="print normalized Scapy-decoded packet models without invoking libcrafter",
    )
    offline_parser.set_defaults(func=_offline)

    pcap_parser = subparsers.add_parser(
        "pcap",
        help="run pcap validation",
        description="Run pcap oracle validation.",
    )
    _add_common_options(pcap_parser)
    _add_generation_options(pcap_parser)
    pcap_parser.add_argument(
        "--direction",
        choices=("reference_to_libcrafter", "libcrafter_to_reference", "roundtrip"),
        default="roundtrip",
        help="pcap validation direction (default: %(default)s)",
    )
    pcap_parser.add_argument(
        "--keep-artifacts",
        action="store_true",
        help="keep intermediate pcap and bridge artifacts for successful runs",
    )
    pcap_parser.add_argument(
        "--dry-plan",
        action="store_true",
        help="print deterministic pcap plans without invoking a backend",
    )
    pcap_parser.set_defaults(func=_pcap)

    live_parser = subparsers.add_parser(
        "live",
        help="run live validation",
        description="Run live oracle validation.",
    )
    _add_common_options(live_parser)
    _add_generation_options(live_parser)
    live_parser.add_argument(
        "--provider",
        choices=("local-dry-run", "hetzner"),
        required=True,
        help="live provider to use",
    )
    live_parser.add_argument(
        "--direction",
        choices=("libcrafter_to_reference", "reference_to_libcrafter", "live_exchange"),
        default="live_exchange",
        help="live validation direction (default: %(default)s)",
    )
    live_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="plan provider-backed live validation without creating infrastructure",
    )
    live_parser.set_defaults(func=_live)

    fixtures_parser = subparsers.add_parser(
        "fixtures",
        help="generate deterministic oracle fixture artifacts",
        description="Generate deterministic oracle fixture artifacts.",
    )
    fixtures_parser.add_argument(
        "--backend",
        choices=("scapy",),
        default="scapy",
        help="reference backend to target (default: %(default)s)",
    )
    fixtures_parser.add_argument(
        "--profile",
        default="smoke",
        help="fixture generation profile metadata from profiles.yaml (default: %(default)s)",
    )
    fixtures_parser.add_argument(
        "--seed",
        type=int,
        default=1,
        help="fixture generation seed metadata (default: %(default)s)",
    )
    fixtures_parser.add_argument(
        "--out",
        default=str(DEFAULT_OUTPUT_ROOT / "fixtures"),
        help="fixture output directory (default: %(default)s)",
    )
    fixtures_parser.add_argument(
        "--case",
        dest="case_name",
        help="fixture case name to generate",
    )
    fixtures_parser.add_argument(
        "--only",
        action="append",
        default=[],
        metavar="NAME",
        help="legacy fixture name filter; can be passed multiple times or comma-separated",
    )
    fixtures_parser.add_argument(
        "--family",
        dest="fixture_family",
        action="append",
        default=[],
        metavar="FAMILY",
        help="legacy fixture family filter; can be passed multiple times or comma-separated",
    )
    fixtures_parser.add_argument(
        "--direction",
        dest="fixture_direction",
        action="append",
        default=[],
        metavar="DIRECTION",
        help="legacy fixture direction filter; can be passed multiple times or comma-separated",
    )
    fixtures_parser.add_argument(
        "--check-drift",
        action="store_true",
        help="compare generated fixture bytes and legacy metadata with checked-in fixtures",
    )
    fixtures_parser.add_argument(
        "--list",
        dest="list_cases",
        action="store_true",
        help="list available fixture cases and exit",
    )
    fixtures_parser.set_defaults(func=_fixtures)

    backend_info_parser = subparsers.add_parser(
        "backend-info",
        help="print backend dependency and version metadata",
        description="Print oracle backend dependency and version metadata.",
    )
    backend_info_parser.add_argument(
        "--backend",
        choices=registered_backend_names(),
        default="scapy",
        help="backend to inspect (default: %(default)s)",
    )
    backend_info_parser.set_defaults(func=_backend_info)

    specs_parser = subparsers.add_parser(
        "specs",
        help="inspect executable oracle specs",
        description="Inspect executable oracle specs.",
    )
    specs_subparsers = specs_parser.add_subparsers(
        dest="specs_command",
        metavar="COMMAND",
        required=True,
    )
    specs_validate_parser = specs_subparsers.add_parser(
        "validate",
        help="load and validate all executable oracle specs",
        description="Load and validate all executable oracle specs.",
    )
    specs_validate_parser.add_argument(
        "--json",
        action="store_true",
        help="print the validation summary as JSON",
    )
    specs_validate_parser.add_argument(
        "--strict",
        action="store_true",
        help="run strict cross-file spec validation",
    )
    specs_validate_parser.set_defaults(func=_specs_validate)

    report_parser = subparsers.add_parser(
        "report",
        help="run final oracle migration validation and write a summary",
        description="Run final oracle migration validation and write a summary.",
    )
    report_parser.add_argument(
        "--out",
        default=str(DEFAULT_OUTPUT_ROOT / "final"),
        help="final report output directory (default: %(default)s)",
    )
    report_parser.set_defaults(func=_report)

    self_check_parser = subparsers.add_parser(
        "self-check",
        help="run oracle engine self checks",
        description="Run lightweight oracle engine self checks.",
    )
    self_check_parser.set_defaults(func=_self_check)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
