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
PCAP_DRY_PLAN_CASES: tuple[JSONObject, ...] = (
    {
        "name": "scapy-writes-pcap-libcrafter-reads",
        "directions": ["reference_to_libcrafter"],
        "writer": "scapy",
        "reader": "libcrafter",
        "file_format": "pcap",
        "link_type": "ethernet",
        "strict_bytes": True,
        "timestamp_policy": "exact_when_deterministic_else_normalized",
    },
    {
        "name": "libcrafter-writes-pcap-scapy-reads",
        "directions": ["libcrafter_to_reference"],
        "writer": "libcrafter",
        "reader": "scapy",
        "file_format": "pcap",
        "link_type": "ethernet",
        "strict_bytes": True,
        "timestamp_policy": "exact_when_deterministic_else_normalized",
    },
    {
        "name": "ethernet-link-type",
        "directions": ["reference_to_libcrafter", "libcrafter_to_reference"],
        "file_format": "pcap",
        "link_type": "ethernet",
        "roots": ["link:ethernet"],
        "strict_bytes": True,
        "timestamp_policy": "exact_when_deterministic_else_normalized",
    },
    {
        "name": "linux-cooked-link-type",
        "directions": ["reference_to_libcrafter", "libcrafter_to_reference"],
        "file_format": "pcap",
        "link_type": "linux_cooked",
        "roots": ["link:linux-cooked", "link:linux-sll"],
        "strict_bytes": True,
        "timestamp_policy": "exact_when_deterministic_else_normalized",
    },
    {
        "name": "null-loopback-link-type",
        "directions": ["reference_to_libcrafter", "libcrafter_to_reference"],
        "file_format": "pcap",
        "link_type": "null_loopback",
        "roots": ["link:null-loopback"],
        "strict_bytes": True,
        "timestamp_policy": "exact_when_deterministic_else_normalized",
    },
    {
        "name": "raw-link-type",
        "directions": ["reference_to_libcrafter", "libcrafter_to_reference"],
        "file_format": "pcap",
        "link_type": "raw",
        "roots": ["link:raw", "l3:ipv4", "l3:ipv6"],
        "strict_bytes": True,
        "support": "where_supported",
        "timestamp_policy": "exact_when_deterministic_else_normalized",
    },
    {
        "name": "pcapng-mixed-link-types",
        "directions": ["reference_to_libcrafter", "libcrafter_to_reference", "roundtrip"],
        "file_format": "pcapng",
        "link_types": ["ethernet", "linux_cooked", "null_loopback", "raw"],
        "strict_bytes": False,
        "support": "where_supported",
        "timestamp_policy": "exact_when_deterministic_else_normalized_or_ignored",
    },
)


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
        choices=("smoke", "ci", "wild", "boundary", "fuzz"),
        default="smoke",
        help="sampling profile (default: %(default)s)",
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
        choices=("ipv4", "ipv6"),
        help="protocol family filter",
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
            "path": "backend.capabilities",
            "expected": list(required),
            "actual": backend.capabilities.enabled(),
        }
    ]
    if not backend.availability.available:
        differences.append(
            {
                "path": "backend.availability",
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
            "backend": backend.to_dict(),
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
        selected_specs=(PCAP_CONTRACT_SPEC, "builtin-stack-grammar"),
    )
    if unsupported is not None:
        return unsupported
    if args.backend != "scapy":
        return _backend_not_implemented_report(
            args,
            mode="pcap",
            operation=f"pcap {args.direction}",
            report_path=_pcap_output_dir(args.out) / "report.json",
            selected_specs=(PCAP_CONTRACT_SPEC, "builtin-stack-grammar"),
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
            count=args.count,
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
        libcrafter_dry_run_command_plan,
        live_execution_directions,
        local_dry_run_endpoints,
        validate_libcrafter_command_plan,
        validate_local_dry_run_exchange,
    )

    try:
        directions = live_execution_directions(args.direction)
        plans = generate_plans(
            seed=args.seed,
            profile=args.profile,
            count=args.count,
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
        },
        actual={
            "provider": args.provider,
            "dry_run": True,
            "live_packet_exchange": False,
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


def _pcap_dry_plan(args: argparse.Namespace) -> int:
    from .generator import generate_plans

    directions = _pcap_execution_directions(args.direction)
    pcap_cases: list[JSONObject] = []
    try:
        for direction in directions:
            pcap_cases.extend(
                _select_pcap_cases(
                    direction=direction,
                    case_name=args.case_name,
                    feature=args.feature,
                )
            )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    base_plans = generate_plans(
        seed=args.seed,
        profile=args.profile,
        count=args.count,
        family=args.family,
        case=args.case_name,
        feature=args.feature,
        index=args.index,
    )
    plans = [
        _pcap_plan(plan, pcap_cases[offset % len(pcap_cases)], args.direction)
        for offset, plan in enumerate(base_plans)
    ]

    report = RunReport(
        mode="pcap",
        backend=args.backend,
        profile=args.profile,
        seed=args.seed,
        count=len(plans),
        status="dry-plan",
        selected_specs=[PCAP_CONTRACT_SPEC, "builtin-stack-grammar"],
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
    from .backends.scapy.packets import encode_packet_plans
    from .backends.scapy.pcap import with_pcap_metadata
    from .generator import generate_plans

    directions = _pcap_execution_directions(args.direction)
    output_dir = _pcap_output_dir(args.out)
    artifacts_root = output_dir / "artifacts"
    artifacts_root.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "report.json"
    run_dir = Path(
        tempfile.mkdtemp(
            prefix=f"{args.direction}.",
            dir=artifacts_root,
        )
    )

    try:
        plans = generate_plans(
            seed=args.seed,
            profile=args.profile,
            count=args.count,
            family=args.family,
            case=args.case_name,
            feature=args.feature,
            index=args.index,
        )
        vectors = with_pcap_metadata(encode_packet_plans(plans), link_type="ethernet")
        backend_versions = _backend_versions(args.backend)
        libcrafter_info = _libcrafter_info()

        vector_report = RunReport(
            mode="pcap",
            backend=args.backend,
            profile=args.profile,
            seed=args.seed,
            count=len(vectors),
            status="vectors",
            selected_specs=[PCAP_CONTRACT_SPEC, "builtin-stack-grammar"],
            backend_versions=backend_versions,
            libcrafter=libcrafter_info,
            metadata={
                "direction": args.direction,
                "execution_directions": directions,
                "requested_count": args.count,
                "vectors": [vector.to_dict() for vector in vectors],
            },
        )
        vector_path = run_dir / "pcap-vectors.json"
        write_json(vector_path, vector_report)

        results: list[ComparisonResult] = []
        direction_metadata: list[JSONObject] = []
        direction_artifacts: list[str] = [str(vector_path)]
        bridge_exit_codes: list[int] = []
        for direction in directions:
            if direction == "reference_to_libcrafter":
                run = _pcap_reference_to_libcrafter(
                    args=args,
                    run_dir=run_dir,
                    vector_path=vector_path,
                    vectors=vectors,
                    plans=plans,
                )
            elif direction == "libcrafter_to_reference":
                run = _pcap_libcrafter_to_reference(
                    args=args,
                    run_dir=run_dir,
                    vector_path=vector_path,
                    vectors=vectors,
                    plans=plans,
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
            selected_specs=[PCAP_CONTRACT_SPEC, "builtin-stack-grammar"],
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
                "generated_count": len(plans),
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
            selected_specs=("builtin-stack-grammar",),
        )
        if unsupported is not None:
            return unsupported
        if args.backend != "scapy":
            return _backend_not_implemented_report(
                args,
                mode="offline",
                operation=f"offline {args.direction}",
                report_path=_offline_output_dir(args.out) / "report.json",
                selected_specs=("builtin-stack-grammar",),
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
        count=args.count,
        family=args.family,
        case=args.case_name,
        feature=args.feature,
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
                selected_specs=["builtin-stack-grammar"],
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
            selected_specs=["builtin-stack-grammar"],
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
        selected_specs=["builtin-stack-grammar"],
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
        count=args.count,
        family=args.family,
        case=args.case_name,
        feature=args.feature,
        index=args.index,
    )
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
        selected_specs=["builtin-stack-grammar"],
        backend_versions=backend_versions,
        libcrafter=libcrafter_info,
        metadata={
            "direction": args.direction,
            "requested_count": args.count,
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
            selected_specs=["builtin-stack-grammar"],
            backend_versions=backend_versions,
            libcrafter=libcrafter_info,
            metadata={
                "direction": args.direction,
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
        selected_specs=["builtin-stack-grammar"],
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
            "libcrafter_bridge": {
                "argv": bridge["argv"],
                "exit_code": bridge["exit_code"],
            },
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
    if args.backend != "scapy":
        print(f"unsupported backend: {args.backend}", file=sys.stderr)
        return 2

    from .backends.scapy.normalize import decode_vectors

    output_dir = _offline_output_dir(args.out)
    artifacts_root = output_dir / "artifacts"
    artifacts_root.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "report.json"
    scapy_decoded_path = output_dir / "scapy-decoded.json"
    run_dir = Path(
        tempfile.mkdtemp(
            prefix=f"{args.direction}.",
            dir=artifacts_root,
        )
    )

    emitter = _run_libcrafter_vector_emitter(run_dir)
    entries = _select_libcrafter_cases(emitter["manifest"], args)
    plans: list[PacketPlan] = []
    vectors: list[EncodedVector] = []
    expected_decoded: list[JSONObject] = []
    for index, case in entries:
        plan = _libcrafter_case_plan(case, args, index)
        plans.append(plan)
        vectors.append(_libcrafter_case_vector(case, plan))
        expected_decoded.append(
            _json_object(case.get("expected_decoded", {}), f"case[{index}].expected_decoded")
        )
    backend_versions = _backend_versions(args.backend)
    libcrafter_info = _libcrafter_info()

    vector_report = RunReport(
        mode="offline",
        backend=args.backend,
        profile=args.profile,
        seed=args.seed,
        count=len(vectors),
        status="vectors",
        selected_specs=["libcrafter-oracle-vectors"],
        backend_versions=backend_versions,
        libcrafter=libcrafter_info,
        metadata={
            "direction": args.direction,
            "requested_count": args.count,
            "generated_count": len(entries),
            "vector_backend": "libcrafter",
            "vectors": [vector.to_dict() for vector in vectors],
        },
    )
    vector_path = run_dir / "libcrafter-vectors.json"
    write_json(vector_path, vector_report)

    expected_path = run_dir / "libcrafter-expected-decoded.json"
    write_json(
        expected_path,
        RunReport(
            mode="offline",
            backend="libcrafter",
            profile=args.profile,
            seed=args.seed,
            count=len(expected_decoded),
            status="decoded",
            selected_specs=["libcrafter-oracle-vectors"],
            backend_versions=backend_versions,
            libcrafter=libcrafter_info,
            metadata={
                "direction": args.direction,
                "decoded": expected_decoded,
            },
        ),
    )

    actual_decoded = decode_vectors(vectors)
    scapy_report = RunReport(
        mode="offline",
        backend=args.backend,
        profile=args.profile,
        seed=args.seed,
        count=len(actual_decoded),
        status="decoded",
        selected_specs=["libcrafter-oracle-vectors"],
        metadata={
            "direction": args.direction,
            "decoded": [model.to_dict() for model in actual_decoded],
        },
    )
    actual_path = run_dir / "scapy-decoded.json"
    write_json(actual_path, scapy_report)
    write_json(scapy_decoded_path, scapy_report)

    results = _compare_offline_results(
        args=args,
        expected=expected_decoded,
        actual=actual_decoded,
        plans=plans,
        partial_expected=True,
    )
    results = _with_failure_artifacts(
        run_dir=run_dir,
        results=results,
        vectors=vectors,
        backend_decoded=actual_decoded,
        libcrafter_decoded=expected_decoded,
    )
    failures = [result for result in results if not result.passed]
    status = "passed" if not failures and emitter["exit_code"] == 0 else "failed"
    preserve_artifacts = args.keep_artifacts or status != "passed"

    artifacts = [str(report_path), str(scapy_decoded_path)]
    if preserve_artifacts:
        artifacts.extend(
            [
                str(run_dir),
                str(vector_path),
                str(expected_path),
                str(actual_path),
                str(emitter["stdout_path"]),
                str(emitter["stderr_path"]),
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
        selected_specs=["libcrafter-oracle-vectors"],
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
            "generated_count": len(entries),
            "artifact_dir": str(run_dir) if preserve_artifacts else None,
            "libcrafter_emitter": {
                "argv": emitter["argv"],
                "exit_code": emitter["exit_code"],
            },
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
) -> JSONObject:
    from .backends.scapy.pcap import read_pcap, write_pcap

    pcap_path = run_dir / "scapy-reference.pcap"
    write_pcap(pcap_path, vectors)
    expected_records = read_pcap(pcap_path)
    expected_path = run_dir / "scapy-reference-read.json"
    write_json(expected_path, {"records": expected_records})

    bridge = _run_libcrafter_pcap_reader(pcap_path, run_dir, "scapy-reference")
    actual_records = _pcap_records(bridge["report"])
    actual_path = run_dir / "libcrafter-read-scapy-reference.json"
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
) -> JSONObject:
    from .backends.scapy.pcap import read_pcap

    pcap_path = run_dir / "libcrafter-reference.pcap"
    bridge = _run_libcrafter_pcap_writer(
        vector_path=vector_path,
        pcap_path=pcap_path,
        run_dir=run_dir,
        label="libcrafter-reference",
        link_type="ethernet",
    )
    expected_records = _pcap_records(bridge["report"])
    expected_path = run_dir / "libcrafter-reference-written.json"
    write_json(expected_path, bridge["report"])

    actual_records = read_pcap(pcap_path)
    actual_path = run_dir / "scapy-read-libcrafter-reference.json"
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
            "reader": "scapy",
            "pcap": str(pcap_path),
            "record_count": len(expected_records),
            "libcrafter_bridge": {
                "argv": bridge["argv"],
                "exit_code": bridge["exit_code"],
            },
        },
    }


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


def _select_pcap_cases(
    *,
    direction: str,
    case_name: str | None,
    feature: str | None,
) -> list[JSONObject]:
    selected: list[JSONObject] = []
    for pcap_case in PCAP_DRY_PLAN_CASES:
        directions = _string_values(pcap_case.get("directions"))
        if direction not in directions:
            continue
        if case_name is not None and pcap_case.get("name") != case_name:
            continue
        if feature is not None and feature not in {"pcap", "pcap_contracts"}:
            continue
        selected.append(dict(pcap_case))

    if selected:
        return selected

    detail = f" direction={direction!r}"
    if case_name is not None:
        detail += f" case={case_name!r}"
    if feature is not None:
        detail += f" feature={feature!r}"
    raise ValueError(f"no pcap dry-plan contracts match{detail}")


def _pcap_plan(plan: PacketPlan, pcap_case: JSONObject, direction: str) -> PacketPlan:
    strict_bytes = pcap_case.get("strict_bytes")
    metadata = dict(plan.metadata)
    metadata["pcap"] = pcap_case
    metadata["selected_spec"] = PCAP_CONTRACT_SPEC
    metadata["timestamp_policy"] = pcap_case.get("timestamp_policy")
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


def _legacy_live_example(args: argparse.Namespace) -> int:
    if args.backend == "scapy":
        from .backends.scapy.live_examples import run_case

        return run_case(
            case_name=args.case_name,
            suite_dir=Path(args.suite_dir),
            host_if=args.host_if,
            host_mac=args.host_mac,
        )

    print(f"unsupported backend: {args.backend}", file=sys.stderr)
    return 2


def _self_check(args: argparse.Namespace) -> int:
    from .generator import run_self_checks

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
    sys.stdout.write(dumps_json({"status": "ok", "checks": ["generator", "backends"]}))
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
        choices=("smoke", "ci", "wild", "boundary", "fuzz"),
        default="smoke",
        help="fixture generation profile metadata (default: %(default)s)",
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

    legacy_live_example_parser = subparsers.add_parser(
        "legacy-live-example",
        help="run legacy live example helpers",
        description=(
            "Run legacy Scapy-backed live example smoke helpers. These helpers "
            "are not oracle validation contracts."
        ),
    )
    legacy_live_example_parser.add_argument(
        "--backend",
        choices=("scapy",),
        default="scapy",
        help="reference backend to target (default: %(default)s)",
    )
    legacy_live_example_parser.add_argument(
        "--case",
        dest="case_name",
        choices=(
            "loopback-icmp-bytes",
            "loopback-icmp-live",
            "loopback-udp-tcp-bytes",
            "loopback-udp-tcp-live",
            "veth-arp-bytes",
            "veth-arp-live",
            "dns-local-bytes",
            "dns-local-live",
            "pcap-generate-live-pcap",
        ),
        required=True,
        help="legacy example helper to run",
    )
    legacy_live_example_parser.add_argument(
        "--suite-dir",
        required=True,
        help="suite artifact directory",
    )
    legacy_live_example_parser.add_argument("--host-if")
    legacy_live_example_parser.add_argument("--host-mac")
    legacy_live_example_parser.set_defaults(func=_legacy_live_example)

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
