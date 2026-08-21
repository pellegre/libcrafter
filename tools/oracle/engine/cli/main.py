"""Command-line interface for oracle packet validation."""

from __future__ import annotations

import argparse
import datetime as dt
import importlib
import json
import os
import posixpath
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import tempfile
import tomllib
import time
from collections.abc import Mapping, Sequence
from dataclasses import replace
from pathlib import Path

from ..backends import (
    BackendCapabilityName,
    BackendRegistration,
    UnknownBackendError,
    backend_report_metadata,
    get_backend,
    get_backend_capability_registration,
    registered_backend_names,
)
from ..compare import compare_decoded_models, failure_indexes
from ..directions import normalize_direction, normalize_direction_list
from ..model import (
    ComparisonResult,
    DecodedModel,
    EncodedVector,
    JSONObject,
    JSONValue,
    PacketPlan,
    RunReport,
    dumps_json,
    read_json,
    write_json,
)
from ..report import DEFAULT_OUTPUT_ROOT, REPO_ROOT

PCAP_CONTRACT_SPEC = "features/pcap.yaml"
PCAP_LINK_TYPES_SPEC = "features/pcap-link-types.yaml"
PCAP_DOT11_LINK_TYPES_SPEC = "features/dot11-pcap-link-types.yaml"
GENERATOR_SELECTED_SPECS = (
    "tools/oracle/specs/stacks.yaml",
    "tools/oracle/specs/profiles.yaml",
)
PCAP_SELECTED_SPECS = (
    PCAP_CONTRACT_SPEC,
    PCAP_LINK_TYPES_SPEC,
    PCAP_DOT11_LINK_TYPES_SPEC,
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
    ".mypy_cache",
    ".pytest_cache",
    ".venv",
    "__pycache__",
    "target",
    "venv",
}

# Shared argparse option helpers live in ``.options`` so the per-command modules
# can reuse one deterministic offline validation surface.
from .options import (  # noqa: E402
    _add_common_options,
    _add_generation_options,
    _non_negative_int,
    _positive_int,
)


def _not_implemented(args: argparse.Namespace) -> int:
    print(
        f"oracle {args.mode} mode is not implemented yet; parsed output root: {args.out}",
        file=sys.stderr,
    )
    return 2


def _with_canonical_direction(args: argparse.Namespace) -> argparse.Namespace:
    direction = getattr(args, "direction", None)
    if not isinstance(direction, str):
        return args
    normalized = normalize_direction(direction)
    if normalized == direction:
        return args
    values = vars(args).copy()
    values["direction"] = normalized
    return argparse.Namespace(**values)


def _generate(args: argparse.Namespace) -> int:
    from ..generator import generate_plans

    args = _with_canonical_direction(args)
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
        packet_plans=plans,
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


def _corpus(args: argparse.Namespace) -> int:
    from ..corpus import write_corpus_report

    args = _with_canonical_direction(args)
    direction = getattr(args, "direction", "backend_to_libcrafter")
    try:
        report = _build_corpus_report_from_generation(args, direction=direction)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    output_dir = Path(args.out)
    if not output_dir.is_absolute():
        output_dir = REPO_ROOT / output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    plans_path = output_dir / "plans.json"
    write_corpus_report(plans_path, report)
    print(f"corpus: status=generated count={len(report.packets)} plans={plans_path}")
    return 0


def _build_corpus_report_from_generation(
    args: argparse.Namespace,
    *,
    direction: str = "backend_to_libcrafter",
):
    from ..corpus import build_corpus_report
    from ..generator import generate_plans

    materialization_backend = _offline_materialization_backend(args.backend, direction)
    plans = generate_plans(
        seed=args.seed,
        profile=args.profile,
        backend=materialization_backend,
        count=args.count,
        root=args.root,
        family=args.family,
        case=args.case_name,
        feature=args.feature,
        direction=direction,
        index=args.index,
    )
    backend_versions = _backend_versions(args.backend)
    libcrafter_info = _libcrafter_info()
    return build_corpus_report(
        backend=args.backend,
        profile=args.profile,
        seed=args.seed,
        count=args.count,
        plans=plans,
        selected_specs=GENERATOR_SELECTED_SPECS,
        metadata={
            "requested_count": args.count,
            "generated_count": len(plans),
            "materialization_backend": materialization_backend,
            "filters": {
                "root": args.root,
                "family": args.family,
                "case": args.case_name,
                "feature": args.feature,
                "index": args.index,
            },
            "backend_metadata": backend_versions.get(args.backend, {}),
            "backend_versions": backend_versions,
            "libcrafter": libcrafter_info,
        },
    )


def _offline_materialization_backend(backend: str, direction: str) -> str:
    """Select the encoder used to materialize a deterministic corpus.

    Wireshark is a parser-only reference backend. For traffic flowing from the
    reference side to libcrafter, Scapy supplies the bytes that Wireshark later
    decodes; every other backend/direction materializes itself.
    """

    if (
        backend == "wireshark"
        and normalize_direction(direction) == "backend_to_libcrafter"
    ):
        return "scapy"
    return backend


def _offline_required_capabilities(
    args: argparse.Namespace,
) -> tuple[BackendCapabilityName, ...]:
    direction = normalize_direction(args.direction)
    if args.emit_decoded:
        return ("encode", "decode")
    if args.emit_vectors:
        return ("encode",)
    if args.dry_plan:
        return ()
    if direction == "backend_to_libcrafter":
        if args.backend == "wireshark":
            return ("decode",)
        return ("encode", "decode")
    if direction == "libcrafter_to_backend":
        return ("decode",)
    return ()


def _optional_wireshark_offline_skip(
    args: argparse.Namespace,
    required: Sequence[BackendCapabilityName],
) -> bool:
    """Return true for parser-optional Wireshark SCTP offline skips.

    SCTP Wireshark coverage is parser-only and optional: when `tshark` is not
    installed, the capability gate has already written a structured unsupported
    report. Return success for this focused SCTP offline profile so CI machines
    without tshark record a deterministic skip instead of a hard failure.
    """

    return (
        getattr(args, "backend", None) == "wireshark"
        and getattr(args, "family", None) == "sctp"
        and normalize_direction(getattr(args, "direction", "backend_to_libcrafter"))
        in {"backend_to_libcrafter", "libcrafter_to_backend"}
        and tuple(required) == ("decode",)
    )


def _offline_corpus_plans(
    args: argparse.Namespace,
) -> tuple[list[PacketPlan], list[str], JSONObject]:
    from ..corpus import (
        CorpusFormatError,
        load_corpus_report,
        populate_corpus_eligibility,
    )

    corpus_path: Path | None = None
    corpus_source = "generated"
    if args.corpus is None:
        corpus_report = _build_corpus_report_from_generation(
            args, direction=args.direction
        )
    else:
        corpus_source = "provided"
        corpus_path = Path(args.corpus)
        if not corpus_path.is_absolute():
            corpus_path = REPO_ROOT / corpus_path
        corpus_report = load_corpus_report(corpus_path)
        if corpus_report.backend != args.backend:
            raise CorpusFormatError(
                f"{corpus_path}: backend {corpus_report.backend!r} does not match "
                f"requested backend {args.backend!r}"
            )

    packets = list(corpus_report.packets)
    materialization_backend = _offline_materialization_backend(
        args.backend, args.direction
    )
    if materialization_backend != corpus_report.backend:
        packets = populate_corpus_eligibility(
            backend=materialization_backend,
            packets=packets,
        )
    if args.index is not None:
        packets = [packet for packet in packets if packet.plan.index == args.index]

    plans: list[PacketPlan] = []
    eligibility: list[JSONObject] = []
    skipped_count = 0
    for position, packet in enumerate(packets):
        eligible = packet.offline.eligible is not False
        reason = (
            None
            if eligible
            else packet.offline.reason or "offline eligibility marked false"
        )
        decision: JSONObject = {
            "position": position,
            "packet_id": packet.packet_id,
            "corpus_index": packet.index,
            "packet_index": packet.plan.index,
            "direction": args.direction,
            "eligible": eligible,
            "reason": reason,
        }
        eligibility.append(decision)
        if not eligible:
            skipped_count += 1
            continue
        plans.append(replace(packet.plan, direction=args.direction))

    selected_specs = list(
        dict.fromkeys(
            [*corpus_report.selected_specs, *_selected_specs_for_plans(plans)]
        )
    )
    metadata: JSONObject = {
        "corpus_id": corpus_report.corpus_id,
        "corpus_source": corpus_source,
        "corpus_path": str(corpus_path) if corpus_path is not None else None,
        "corpus_backend": corpus_report.backend,
        "materialization_backend": materialization_backend,
        "corpus_profile": corpus_report.profile,
        "corpus_seed": corpus_report.seed,
        "corpus_count": corpus_report.count,
        "generated_count": len(packets),
        "offline_eligible_count": len(plans),
        "offline_skipped_count": skipped_count,
        "packet_indexes": [plan.index for plan in plans],
        "offline_eligibility": eligibility,
    }
    return plans, selected_specs, metadata


def _pcap_required_capabilities(
    args: argparse.Namespace,
) -> tuple[BackendCapabilityName, ...]:
    if args.direction == "backend_to_libcrafter":
        return ("encode", "pcap_write", "pcap_read")
    if args.direction == "libcrafter_to_backend":
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

    if (
        required
        and not backend.availability.available
        and not _backend_has_local_pcap_read_fallback(
            args,
            backend,
            required,
            mode=mode,
        )
    ):
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


def _backend_has_local_pcap_read_fallback(
    args: argparse.Namespace,
    backend: BackendRegistration,
    required: Sequence[BackendCapabilityName],
    *,
    mode: str,
) -> bool:
    """Return true for pcap-read paths with an explicit in-process fallback."""

    return (
        mode == "pcap"
        and backend.name == "wireshark"
        and tuple(required) == ("pcap_read",)
        and _pcap_fallback_family(args) in {"dhcpv6", "quic"}
    )


def _pcap_fallback_family(args: argparse.Namespace) -> str | None:
    family = getattr(args, "family", None)
    if isinstance(family, str) and family:
        return family
    case_name = getattr(args, "case_name", None)
    if isinstance(case_name, str):
        if case_name.startswith("dhcpv6-"):
            return "dhcpv6"
        if case_name.startswith("quic-"):
            return "quic"
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
    args = _with_canonical_direction(args)
    args = _pcap_effective_args(args)
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
    if args.backend != "scapy" and args.direction != "libcrafter_to_backend":
        return _backend_not_implemented_report(
            args,
            mode="pcap",
            operation=f"pcap {args.direction}",
            report_path=_pcap_output_dir(args.out) / "report.json",
            selected_specs=PCAP_SELECTED_SPECS,
        )

    return _pcap_execute(args)


def _pcap_effective_args(args: argparse.Namespace) -> argparse.Namespace:
    """Use the read-only pcap direction by default for parser-only backends."""

    if getattr(args, "direction", None) != "roundtrip":
        return args
    try:
        backend = get_backend(args.backend)
    except UnknownBackendError:
        return args
    if not backend.parser_only:
        return args
    values = vars(args).copy()
    values["direction"] = "libcrafter_to_backend"
    return argparse.Namespace(**values)


class PcapUnsupportedError(ValueError):
    """Raised when a selected pcap spec case cannot execute in this repository."""


def _pcap_dry_plan(args: argparse.Namespace) -> int:
    try:
        directions = _pcap_execution_directions(args.direction)
        direction_groups, selected_specs, corpus_metadata = _pcap_corpus_plan_groups(
            args,
            directions,
            materialize=False,
        )
        plans = [
            plan
            for groups in direction_groups.values()
            for group in groups
            for plan in group["plans"]  # type: ignore[index]
            if isinstance(plan, PacketPlan)
        ]
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
        selected_specs=selected_specs,
        metadata={
            "dry_plan": True,
            "requested_count": args.count,
            "direction": args.direction,
            "execution_directions": directions,
            **corpus_metadata,
            "timestamp_policy": {
                "deterministic": "exact",
                "backend_precision_differs": "normalized",
                "backend_generated_or_unavailable": "ignored",
            },
            "directions": _pcap_group_summaries(direction_groups),
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
        groups_by_direction, selected_specs, corpus_metadata = _pcap_corpus_plan_groups(
            args,
            directions,
            materialize=True,
        )
        direction_groups = [
            (direction, groups_by_direction.get(direction, []))
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
                    selected_specs=selected_specs,
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

                if direction == "backend_to_libcrafter":
                    run = _pcap_backend_to_libcrafter(
                        args=args,
                        run_dir=run_dir,
                        vector_path=vector_path,
                        vectors=vectors,  # type: ignore[arg-type]
                        plans=plans,  # type: ignore[arg-type]
                        label=label,
                    )
                elif direction == "libcrafter_to_backend":
                    run = _pcap_libcrafter_to_backend(
                        args=args,
                        run_dir=run_dir,
                        vector_path=vector_path,
                        vectors=vectors,  # type: ignore[arg-type]
                        plans=plans,  # type: ignore[arg-type]
                        label=label,
                    )
                else:
                    raise RuntimeError(
                        f"unsupported pcap execution direction: {direction}"
                    )

                results.extend(run["results"])  # type: ignore[arg-type]
                direction_metadata.append(
                    _json_object(run["metadata"], "pcap direction metadata")
                )
                direction_artifacts.extend(_string_values(run["artifacts"]))
                exit_code = run.get("bridge_exit_code")
                if isinstance(exit_code, int):
                    bridge_exit_codes.append(exit_code)

        failures = [result for result in results if not result.passed]
        status = (
            "passed"
            if not failures and all(code == 0 for code in bridge_exit_codes)
            else "failed"
        )
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
            selected_specs=selected_specs,
            artifacts=artifacts,
            artifact_paths=artifacts,
            results=results,
            failures=failures,
            reproduction_commands=list(
                dict.fromkeys(
                    command
                    for command in (result.reproduction_command for result in failures)
                    if command is not None
                )
            ),
            backend_versions=backend_versions,
            libcrafter=libcrafter_info,
            metadata={
                "direction": args.direction,
                "execution_directions": directions,
                "requested_count": args.count,
                "generated_count": generated_count,
                **corpus_metadata,
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
    args = _with_canonical_direction(args)
    required_capabilities = _offline_required_capabilities(args)
    if required_capabilities:
        unsupported = _require_backend_capabilities(
            args,
            mode="offline",
            required=required_capabilities,
            operation=f"offline {args.direction}",
            report_path=_offline_report_output_dir(args) / "report.json",
            selected_specs=GENERATOR_SELECTED_SPECS,
        )
        if unsupported is not None:
            if _optional_wireshark_offline_skip(args, required_capabilities):
                return 0
            return unsupported
        if args.backend not in {"scapy", "wireshark"}:
            return _backend_not_implemented_report(
                args,
                mode="offline",
                operation=f"offline {args.direction}",
                report_path=_offline_report_output_dir(args) / "report.json",
                selected_specs=GENERATOR_SELECTED_SPECS,
            )

    if not args.dry_plan and not args.emit_vectors and not args.emit_decoded:
        if args.direction == "backend_to_libcrafter":
            return _offline_backend_to_libcrafter(args)
        if args.direction == "libcrafter_to_backend":
            return _offline_libcrafter_to_backend(args)
        print(f"unsupported offline direction: {args.direction}", file=sys.stderr)
        return 2

    try:
        plans, selected_specs, corpus_metadata = _offline_corpus_plans(args)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if args.emit_vectors or args.emit_decoded:
        if args.backend == "scapy":
            from ..backends.scapy.packets import encode_packet_plans

            vectors = encode_packet_plans(plans)
        else:
            print(f"unsupported backend: {args.backend}", file=sys.stderr)
            return 2

        if args.emit_decoded:
            from ..backends.scapy.normalize import (
                decode_vectors,
                validate_smoke_decodes,
            )

            decoded = decode_vectors(vectors)
            if args.profile == "smoke":
                validate_smoke_decodes(vectors, decoded)

            metadata = {
                "emit_decoded": True,
                "requested_count": args.count,
                **corpus_metadata,
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
                selected_specs=selected_specs,
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
            selected_specs=selected_specs,
            backend_versions=_backend_versions(args.backend),
            libcrafter=_libcrafter_info(),
            metadata={
                "emit_vectors": True,
                "requested_count": args.count,
                **corpus_metadata,
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
        selected_specs=selected_specs,
        metadata={
            "dry_plan": True,
            "requested_count": args.count,
            **corpus_metadata,
            "plans": [plan.to_dict() for plan in plans],
        },
    )
    sys.stdout.write(dumps_json(report))
    return 0


def _offline_backend_to_libcrafter(args: argparse.Namespace) -> int:
    if args.direction != "backend_to_libcrafter":
        print(f"unsupported offline direction: {args.direction}", file=sys.stderr)
        return 2

    from ..backends.scapy.packets import encode_packet_plans

    if args.backend == "scapy":
        from ..backends.scapy.normalize import decode_vectors
    elif args.backend == "wireshark":
        from ..backends.wireshark.normalize import decode_vectors
    else:
        print(f"unsupported backend: {args.backend}", file=sys.stderr)
        return 2

    output_dir = _offline_report_output_dir(args)
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
        plans, selected_specs, corpus_metadata = _offline_corpus_plans(args)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
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
            **corpus_metadata,
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
                **corpus_metadata,
                "backend_capabilities": backend_capabilities,
                "decoded": [model.to_dict() for model in expected_decoded],
            },
        ),
    )

    bridge = _run_libcrafter_decode_bridge(vector_path, run_dir)
    actual_decoded = (
        _decoded_models(bridge["report"]) if bridge["exit_code"] == 0 else []
    )
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
            **corpus_metadata,
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


def _offline_libcrafter_to_backend(args: argparse.Namespace) -> int:
    if args.direction != "libcrafter_to_backend":
        print(f"unsupported offline direction: {args.direction}", file=sys.stderr)
        return 2
    if args.backend not in {"scapy", "wireshark"}:
        print(f"unsupported backend: {args.backend}", file=sys.stderr)
        return 2

    if args.backend == "scapy":
        from ..backends.scapy.normalize import decode_vectors
    else:
        from ..backends.wireshark.normalize import decode_vectors

    output_dir = _offline_report_output_dir(args)
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
    try:
        plans, selected_specs, corpus_metadata = _offline_corpus_plans(args)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
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
            **corpus_metadata,
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

    bridge = (
        _run_libcrafter_decode_bridge(vector_path, run_dir)
        if vectors
        else {
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
    )
    expected_decoded = (
        _decoded_models(bridge["report"]) if bridge["exit_code"] == 0 else []
    )
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
            **corpus_metadata,
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
            **corpus_metadata,
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


def _pcap_backend_to_libcrafter(
    *,
    args: argparse.Namespace,
    run_dir: Path,
    vector_path: Path,
    vectors: list[EncodedVector],
    plans: list[PacketPlan],
    label: str,
) -> JSONObject:
    from ..backends.scapy.pcap import read_pcap, write_pcap

    pcap_path = run_dir / f"{label}.scapy-reference.pcap"
    artifacts: list[str] = [str(vector_path)]
    try:
        write_pcap(pcap_path, vectors)
        artifacts.append(str(pcap_path))
        expected_records = [
            _canonical_pcap_record(record, f"{label}.reference records[{index}]")
            for index, record in enumerate(read_pcap(pcap_path))
        ]
        expected_path = run_dir / f"{label}.scapy-reference-read.json"
        write_json(expected_path, {"records": expected_records})
        artifacts.append(str(expected_path))

        bridge = _run_libcrafter_pcap_reader(
            pcap_path, run_dir, f"{label}.scapy-reference"
        )
        actual_records = _pcap_records(bridge["report"])
        actual_path = run_dir / f"{label}.libcrafter-read-scapy-reference.json"
        write_json(actual_path, bridge["report"])
        artifacts.extend(
            [
                str(actual_path),
                str(bridge["stdout_path"]),
                str(bridge["stderr_path"]),
            ]
        )

        results = _compare_pcap_records(
            args=args,
            direction="backend_to_libcrafter",
            expected=expected_records,
            actual=actual_records,
            plans=plans,
        )

        return {
            "results": results,
            "artifacts": _dedupe_existing_paths(artifacts),
            "bridge_exit_code": bridge["exit_code"],
            "metadata": {
                "direction": "backend_to_libcrafter",
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
    except (ValueError, RuntimeError) as exc:
        return _pcap_group_failure_run(
            args=args,
            direction="backend_to_libcrafter",
            plans=plans,
            label=label,
            writer="scapy",
            reader="libcrafter",
            pcap_path=pcap_path,
            artifacts=artifacts,
            error=exc,
        )


def _pcap_libcrafter_to_backend(
    *,
    args: argparse.Namespace,
    run_dir: Path,
    vector_path: Path,
    vectors: list[EncodedVector],
    plans: list[PacketPlan],
    label: str,
) -> JSONObject:
    from ..backends.scapy.pcap import pcap_link_type_for_vectors

    pcap_path = run_dir / f"{label}.libcrafter-reference.pcap"
    artifacts: list[str] = [str(vector_path)]
    bridge: JSONObject | None = None
    try:
        bridge = _run_libcrafter_pcap_writer(
            vector_path=vector_path,
            pcap_path=pcap_path,
            run_dir=run_dir,
            label=f"{label}.libcrafter-reference",
            link_type=pcap_link_type_for_vectors(vectors, requested="ethernet"),
        )
        artifacts.extend(
            [
                str(pcap_path),
                str(bridge["stdout_path"]),
                str(bridge["stderr_path"]),
            ]
        )
        expected_records = _pcap_records(bridge["report"])
        expected_path = run_dir / f"{label}.libcrafter-reference-written.json"
        write_json(expected_path, bridge["report"])
        artifacts.append(str(expected_path))

        actual_records = _pcap_read_reference_records(args.backend, pcap_path)
        actual_path = run_dir / f"{label}.{args.backend}-read-libcrafter-reference.json"
        write_json(actual_path, {"records": actual_records})
        artifacts.append(str(actual_path))

        results = _compare_pcap_records(
            args=args,
            direction="libcrafter_to_backend",
            expected=expected_records,
            actual=actual_records,
            plans=plans,
        )

        return {
            "results": results,
            "artifacts": _dedupe_existing_paths(artifacts),
            "bridge_exit_code": bridge["exit_code"],
            "metadata": {
                "direction": "libcrafter_to_backend",
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
    except (ValueError, RuntimeError) as exc:
        metadata = {}
        if bridge is not None:
            metadata["libcrafter_bridge"] = {
                "argv": bridge["argv"],
                "exit_code": bridge["exit_code"],
            }
        return _pcap_group_failure_run(
            args=args,
            direction="libcrafter_to_backend",
            plans=plans,
            label=label,
            writer="libcrafter",
            reader=args.backend,
            pcap_path=pcap_path,
            artifacts=artifacts,
            error=exc,
            metadata=metadata,
        )


def _pcap_group_failure_run(
    *,
    args: argparse.Namespace,
    direction: str,
    plans: list[PacketPlan],
    label: str,
    writer: str,
    reader: str,
    pcap_path: Path,
    artifacts: Sequence[str],
    error: Exception,
    metadata: JSONObject | None = None,
) -> JSONObject:
    error_text = str(error)
    differences: list[JSONObject] = [
        {
            "path": "pcap_execution",
            "expected": "completed",
            "actual": error_text,
        }
    ]
    results = [
        ComparisonResult(
            passed=False,
            direction=direction,
            expected={"pcap_execution": "completed"},
            actual={
                "error": error_text,
                "group_failure": True,
                "label": label,
            },
            plan=replace(plan, direction=direction),
            strict_bytes=plan.strict_bytes,
            byte_equal=False,
            differences=differences,
            reproduction_command=_pcap_group_reproduction_command(args, direction),
            metadata={
                "group_failure": True,
                "group_reproduction": True,
                "label": label,
                "writer": writer,
                "reader": reader,
            },
        )
        for plan in plans
    ]
    return {
        "results": results,
        "artifacts": _dedupe_existing_paths(artifacts),
        "bridge_exit_code": 1,
        "metadata": {
            "direction": direction,
            "writer": writer,
            "reader": reader,
            "label": label,
            "pcap": str(pcap_path),
            "record_count": 0,
            "group_failure": True,
            "error": error_text,
            **(metadata or {}),
        },
    }


def _dedupe_existing_paths(paths: Sequence[str]) -> list[str]:
    return _dedupe_paths([path for path in paths if Path(path).exists()])


def _pcap_read_reference_records(backend: str, pcap_path: Path) -> list[JSONObject]:
    if backend == "scapy":
        from ..backends.scapy.pcap import read_pcap

        records = read_pcap(pcap_path)
        return [
            _canonical_pcap_record(record, f"{backend} pcap records[{index}]")
            for index, record in enumerate(records)
        ]
    if backend == "wireshark":
        from ..backends.wireshark.pcap import read_pcap

        records = read_pcap(pcap_path)
        return [
            _canonical_pcap_record(record, f"{backend} pcap records[{index}]")
            for index, record in enumerate(records)
        ]
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
        _pcap_diff(
            "link_type.datalink", expected[position], actual[position], differences
        )
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
                reproduction_command=(
                    None
                    if passed
                    else _pcap_reproduction_command(args, plan.index, direction)
                ),
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
                reproduction_command=_pcap_reproduction_command(
                    args, plan.index, direction
                ),
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
                expected=(
                    _model_to_object(expected[item]) if item < len(expected) else {}
                ),
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
            (
                _model_to_object(backend_decoded[position])
                if position < len(backend_decoded)
                else {}
            ),
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
        capabilities["libcrafter"] = get_backend_capability_registration(
            "libcrafter"
        ).to_dict()
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
        "oracle-adapters",
        "--bin",
        "decode_vectors",
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
        "oracle-adapters",
        "--bin",
        "materialize_plans",
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
        "oracle-adapters",
        "--bin",
        "vectors",
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
        raise RuntimeError(
            f"libcrafter vector emitter emitted invalid JSON: {exc}"
        ) from exc
    if not isinstance(manifest, dict):
        raise RuntimeError("libcrafter vector emitter manifest must be a JSON object")

    return {
        "argv": argv,
        "exit_code": process.returncode,
        "manifest": manifest,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
    }


def _run_libcrafter_pcap_reader(
    pcap_path: Path, run_dir: Path, label: str
) -> JSONObject:
    argv = [
        "cargo",
        "run",
        "-q",
        "-p",
        "oracle-adapters",
        "--bin",
        "pcap",
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
        "oracle-adapters",
        "--bin",
        "pcap",
        "--",
        "--write-pcap",
        str(pcap_path),
        "--input",
        str(vector_path),
        "--link-type",
        link_type,
    ]
    return _run_libcrafter_json_command(argv, run_dir, f"{label}.libcrafter-write")


def _run_libcrafter_json_command(
    argv: list[str], run_dir: Path, label: str
) -> JSONObject:
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
    metadata = _json_object(
        report_object.get("metadata", {}), "libcrafter report metadata"
    )
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
        raise RuntimeError(
            "libcrafter materializer report metadata.vectors must be a list"
        )

    output: list[EncodedVector] = []
    for index, item in enumerate(vectors):
        vector = _json_object(item, f"vectors[{index}]")
        raw_hex = _optional_string(vector.get("raw_hex")) or _optional_string(
            vector.get("hex")
        )
        if raw_hex is None:
            raise RuntimeError(
                f"libcrafter materialized vector {index} is missing raw_hex"
            )
        plan = _packet_plan_from_object(vector.get("plan"), f"vectors[{index}].plan")
        root = _optional_string(vector.get("root")) or _optional_string(
            vector.get("decoder")
        )
        if root is None:
            raise RuntimeError(
                f"libcrafter materialized vector {index} is missing root"
            )
        output.append(
            EncodedVector(
                plan=plan,
                backend=_optional_string(vector.get("backend")) or "libcrafter",
                raw_hex=raw_hex,
                root=root,
                decoder=_optional_string(vector.get("decoder")) or root,
                metadata=_json_object(
                    vector.get("metadata", {}), f"vectors[{index}].metadata"
                ),
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
        direction=normalize_direction(
            _optional_string(plan.get("direction")) or "libcrafter_to_backend"
        ),
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
        output.append(_canonical_pcap_record(item, f"records[{index}]"))
    return output


def _canonical_pcap_record(value: object, context: str) -> JSONObject:
    record = dict(_json_object(value, context))
    record["layers"] = _canonical_pcap_layers(record.get("layers", []))
    return record


def _canonical_pcap_layers(value: object) -> list[str]:
    aliases = {
        "Coap": "coap",
        "CoapReliable": "coap",
        "Dhcpv6": "dhcpv6",
        "Ipv6DestinationOptionsHeader": "ipv6_destination_options",
        "Ipv6HopByHopOptionsHeader": "ipv6_hop_by_hop",
        "SSDP": "ssdp",
        "Sctp": "sctp",
        "Snmp": "snmp",
    }
    layers = [aliases.get(layer, layer) for layer in _string_values(value)]
    canonical: list[str] = []
    for layer in layers:
        if layer == "rsn" and canonical and canonical[-1] == "dot11":
            continue
        canonical.append(layer)
    return canonical


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
        entries = [(index, case) for index, case in entries if index == args.index]
    else:
        entries = entries[: args.count]

    if not entries:
        raise RuntimeError("no libcrafter oracle vector cases selected")
    return entries


def _case_supports_direction(case: JSONObject, direction: str) -> bool:
    direction = normalize_direction(direction)
    directions = normalize_direction_list(case.get("directions"))
    if direction in directions:
        return True
    case_direction = case.get("direction")
    return (
        isinstance(case_direction, str)
        and normalize_direction(case_direction) == direction
    )


def _libcrafter_case_plan(
    case: JSONObject,
    args: argparse.Namespace,
    index: int,
) -> PacketPlan:
    expected = _json_object(
        case.get("expected_decoded", {}), f"case[{index}].expected_decoded"
    )
    stack = _string_values(expected.get("layers", []))
    fields = _json_object(
        expected.get("fields", {}), f"case[{index}].expected_decoded.fields"
    )
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
            "generator": "cargo run -q -p oracle-adapters --bin vectors -- --json",
            "source": "libcrafter oracle vector emitter",
        },
    )


def _libcrafter_case_vector(case: JSONObject, plan: PacketPlan) -> EncodedVector:
    raw_hex = _optional_string(case.get("raw_hex")) or _optional_string(case.get("hex"))
    if raw_hex is None:
        raise RuntimeError(f"libcrafter case {plan.index} is missing raw_hex")
    root = _optional_string(case.get("root_decoder")) or _optional_string(
        case.get("root")
    )
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
            git_dir = (
                raw_path if raw_path.is_absolute() else (REPO_ROOT / raw_path).resolve()
            )

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


def _offline_report_output_dir(args: argparse.Namespace) -> Path:
    output_root = Path(args.out)
    if not output_root.is_absolute():
        output_root = REPO_ROOT / output_root
    if getattr(args, "corpus", None) is not None:
        return output_root / "offline"
    return _offline_output_dir(args.out)


def _pcap_output_dir(out: str) -> Path:
    output_root = Path(out)
    if not output_root.is_absolute():
        output_root = REPO_ROOT / output_root
    if output_root.resolve() != (REPO_ROOT / DEFAULT_OUTPUT_ROOT).resolve():
        return output_root
    return output_root / "pcap"


def _reproduction_command(args: argparse.Namespace, index: int) -> str:
    if getattr(args, "corpus", None) is not None:
        return shlex.join(
            [
                "tools/oracle/run",
                "offline",
                "--backend",
                args.backend,
                "--direction",
                args.direction,
                "--corpus",
                args.corpus,
                "--index",
                str(index),
            ]
        )

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


def _pcap_reproduction_command(
    args: argparse.Namespace, index: int, direction: str
) -> str:
    if getattr(args, "corpus", None) is not None:
        argv = [
            "tools/oracle/run",
            "pcap",
            "--backend",
            args.backend,
            "--direction",
            direction,
            "--corpus",
            args.corpus,
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


def _pcap_group_reproduction_command(args: argparse.Namespace, direction: str) -> str:
    argv = [
        "tools/oracle/run",
        "pcap",
        "--backend",
        args.backend,
        "--direction",
        direction,
    ]
    if getattr(args, "corpus", None) is not None:
        argv.extend(["--corpus", args.corpus])
    else:
        argv.extend(
            [
                "--profile",
                args.profile,
                "--seed",
                str(args.seed),
                "--count",
                str(args.count),
            ]
        )
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
    direction = normalize_direction(direction)
    if direction == "roundtrip":
        return ["backend_to_libcrafter", "libcrafter_to_backend"]
    if direction in {"backend_to_libcrafter", "libcrafter_to_backend"}:
        return [direction]
    raise ValueError(f"unsupported pcap direction: {direction}")


def _pcap_cases_for_direction(
    *,
    args: argparse.Namespace,
    direction: str,
    dry_plan: bool,
) -> list[JSONObject]:
    # `--case` carries a packet-generation case (e.g. dhcpv4-discover) that selects
    # which packets the corpus generator emits. It is a different namespace from
    # the pcap contract case names declared in features/pcap.yaml (e.g.
    # raw-link-type, scapy-writes-pcap-libcrafter-reads). Only filter the pcap
    # contract cases by name when `--case` actually names a contract case; a
    # packet-generation case has already been applied during corpus generation,
    # so it must not eliminate every link-type contract here.
    contract_case_name = (
        args.case_name if _pcap_case_name_is_contract(args.case_name) else None
    )
    all_cases = [
        pcap_case
        for pcap_case in _pcap_spec_cases()
        if _pcap_case_supports_direction(pcap_case, direction)
        and _pcap_case_matches_filter(pcap_case, contract_case_name, args.feature)
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
            and contract_case_name is None
            and (
                direction == "libcrafter_to_backend"
                or args.feature == "pcap_link_types"
            )
        ):
            selected = [
                _pcap_case_with_roles(pcap_case, direction, args.backend)
                for pcap_case in all_cases
                if pcap_case.get("writer") is None
                and pcap_case.get("reader") is None
                and _pcap_case_has_link_or_format(pcap_case)
                and _pcap_file_format_for_case(pcap_case) == "pcap"
            ]
        if not selected and contract_case_name is not None:
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


def _pcap_case_name_is_contract(case_name: str | None) -> bool:
    if case_name is None:
        return False
    return any(pcap_case.get("name") == case_name for pcap_case in _pcap_spec_cases())


def _pcap_spec_cases() -> list[JSONObject]:
    from ..spec_loader import load_oracle_specs

    specs = load_oracle_specs()
    cases: list[JSONObject] = []
    for spec_name, feature_name in (
        (PCAP_CONTRACT_SPEC, "pcap_contracts"),
        (PCAP_DOT11_LINK_TYPES_SPEC, "dot11_pcap_link_types"),
    ):
        feature = specs.features.get(feature_name)
        if feature is None:
            raise ValueError(f"pcap feature spec is missing: {feature_name}")
        raw_cases = feature.raw.get("supported_cases", [])
        if not isinstance(raw_cases, list):
            raise ValueError(f"{spec_name} supported_cases must be a list")
        for raw_case in raw_cases:
            if not isinstance(raw_case, dict):
                raise ValueError(f"{spec_name} supported_cases entries must be objects")
            pcap_case = dict(raw_case)
            pcap_case.setdefault("strict_bytes", feature.strict_bytes)
            pcap_case.setdefault("timestamp_policy", "exact")
            pcap_case["feature"] = feature.name
            cases.append(pcap_case)  # type: ignore[arg-type]
    return cases


def _pcap_corpus_plan_groups(
    args: argparse.Namespace,
    directions: Sequence[str],
    *,
    materialize: bool,
) -> tuple[dict[str, list[JSONObject]], list[str], JSONObject]:
    from ..corpus import CorpusFormatError, load_corpus_report

    corpus_path: Path | None = None
    corpus_source = "generated"
    if getattr(args, "corpus", None) is None:
        corpus_direction = directions[0] if directions else "backend_to_libcrafter"
        generation_args = _pcap_generation_args(args)
        corpus_report = _build_corpus_report_from_generation(
            generation_args,
            direction=corpus_direction,
        )
    else:
        corpus_source = "provided"
        corpus_path = Path(args.corpus)
        if not corpus_path.is_absolute():
            corpus_path = REPO_ROOT / corpus_path
        corpus_report = load_corpus_report(corpus_path)
        if corpus_report.backend != args.backend:
            raise CorpusFormatError(
                f"{corpus_path}: backend {corpus_report.backend!r} does not match "
                f"requested backend {args.backend!r}"
            )

    packets = list(corpus_report.packets)
    if args.index is not None:
        packets = [packet for packet in packets if packet.plan.index == args.index]

    cases_by_direction: dict[str, list[JSONObject]] = {}
    case_filter_reasons: dict[str, str] = {}
    for direction in directions:
        try:
            cases_by_direction[direction] = _pcap_cases_for_direction(
                args=args,
                direction=direction,
                dry_plan=False,
            )
        except ValueError as exc:
            if not str(exc).startswith("no pcap spec cases match"):
                raise
            cases_by_direction[direction] = []
            case_filter_reasons[direction] = str(exc)

    requested_link_type = (
        _pcap_link_type_for_root(args.root) if args.root is not None else None
    )

    encode_packet_plan = None
    with_pcap_metadata = None
    if materialize:
        from ..backends.scapy.packets import (
            encode_packet_plan as scapy_encode_packet_plan,
        )
        from ..backends.scapy.pcap import with_pcap_metadata as scapy_with_pcap_metadata

        encode_packet_plan = scapy_encode_packet_plan
        with_pcap_metadata = scapy_with_pcap_metadata

    groups_by_direction: dict[str, list[JSONObject]] = {
        direction: [] for direction in directions
    }
    group_maps: dict[str, dict[tuple[str, str], JSONObject]] = {
        direction: {} for direction in directions
    }
    selected_plans: list[PacketPlan] = []
    eligibility: list[JSONObject] = []
    skip_reasons: dict[str, int] = {}
    eligible_positions: set[int] = set()
    eligible_packet_indexes: list[int] = []

    for position, packet in enumerate(packets):
        root = _pcap_packet_root(packet.plan)
        packet_link_type: str | None = None
        root_reason: str | None = None
        if root is None:
            root_reason = "pcap_link_type_unavailable"
        else:
            try:
                packet_link_type = _pcap_link_type_for_root(root)
            except ValueError:
                root_reason = "pcap_link_type_unavailable"
        if (
            requested_link_type is not None
            and packet_link_type is not None
            and packet_link_type != requested_link_type
        ):
            root_reason = "pcap_link_type_unavailable"

        direction_decisions: list[JSONObject] = []
        packet_eligible = False
        corpus_skip_reason = None
        if packet.pcap.eligible is False:
            corpus_skip_reason = _pcap_normalized_skip_reason(packet.pcap.reason)

        for direction in directions:
            decision: JSONObject = {
                "direction": direction,
                "eligible": False,
                "reason": None,
                "root": root,
                "pcap_link_type": packet_link_type,
            }
            if corpus_skip_reason is not None:
                decision["reason"] = corpus_skip_reason
                direction_decisions.append(decision)
                continue
            if root_reason is not None or packet_link_type is None:
                decision["reason"] = root_reason or "pcap_link_type_unavailable"
                direction_decisions.append(decision)
                continue

            pcap_case_selection = _select_pcap_case_for_packet(
                cases_by_direction[direction],
                packet_link_type,
            )
            if pcap_case_selection is None:
                decision["reason"] = _pcap_unavailable_reason_for_cases(
                    cases_by_direction[direction],
                    packet_link_type,
                    case_filter_empty=direction in case_filter_reasons,
                )
                direction_decisions.append(decision)
                continue

            pcap_case, file_format = pcap_case_selection
            plan = _pcap_plan(
                _pcap_corpus_packet_plan(
                    packet.plan,
                    corpus_id=corpus_report.corpus_id,
                    packet_id=packet.packet_id,
                    corpus_index=packet.index,
                    direction=direction,
                ),
                pcap_case,
                direction,
                link_type=packet_link_type,
                file_format=file_format,
            )
            group_link_type = _pcap_record_link_type_for_plan(packet_link_type)
            vector = None
            if materialize:
                if encode_packet_plan is None or with_pcap_metadata is None:
                    raise RuntimeError("pcap corpus materialization is not initialized")
                vector = encode_packet_plan(plan)
                vector = with_pcap_metadata(
                    [vector],
                    link_type=_pcap_writer_link_type(packet_link_type),
                )[0]
                group_link_type = _pcap_vector_link_type(vector)

            key = (file_format, group_link_type)
            group = group_maps[direction].setdefault(
                key,
                {
                    "file_format": file_format,
                    "link_type": group_link_type,
                    "pcap_case": pcap_case,
                    "plans": [],
                    "vectors": [],
                },
            )
            group["plans"].append(plan)  # type: ignore[union-attr]
            if vector is not None:
                group["vectors"].append(vector)  # type: ignore[union-attr]
            decision.update(
                {
                    "eligible": True,
                    "reason": None,
                    "pcap_case": pcap_case.get("name"),
                    "pcap_file_format": file_format,
                    "pcap_record_link_type": group_link_type,
                }
            )
            direction_decisions.append(decision)
            packet_eligible = True
            selected_plans.append(plan)

        if packet_eligible:
            eligible_positions.add(position)
            eligible_packet_indexes.append(packet.plan.index)
        else:
            reason = _pcap_packet_skip_reason(direction_decisions)
            skip_reasons[reason] = skip_reasons.get(reason, 0) + 1

        eligibility.append(
            {
                "position": position,
                "packet_id": packet.packet_id,
                "corpus_index": packet.index,
                "packet_index": packet.plan.index,
                "eligible": packet_eligible,
                "reason": (
                    None
                    if packet_eligible
                    else _pcap_packet_skip_reason(direction_decisions)
                ),
                "directions": direction_decisions,
            }
        )

    for direction in directions:
        groups_by_direction[direction] = list(group_maps[direction].values())

    selected_specs = list(
        dict.fromkeys(
            [
                *corpus_report.selected_specs,
                *PCAP_SELECTED_SPECS,
                *_selected_specs_for_plans(selected_plans),
            ]
        )
    )
    metadata: JSONObject = {
        "corpus_id": corpus_report.corpus_id,
        "corpus_source": corpus_source,
        "corpus_path": str(corpus_path) if corpus_path is not None else None,
        "corpus_backend": corpus_report.backend,
        "corpus_profile": corpus_report.profile,
        "corpus_seed": corpus_report.seed,
        "corpus_count": corpus_report.count,
        "generated_count": len(packets),
        "pcap_eligible_count": len(eligible_positions),
        "pcap_skipped_count": len(packets) - len(eligible_positions),
        "pcap_skip_reasons": skip_reasons,
        "packet_indexes": list(dict.fromkeys(eligible_packet_indexes)),
        "pcap_eligibility": eligibility,
    }
    return groups_by_direction, selected_specs, metadata


def _pcap_packet_root(plan: PacketPlan) -> str | None:
    root = plan.metadata.get("root_decoder", plan.metadata.get("root"))
    return root if isinstance(root, str) and root else None


def _pcap_corpus_packet_plan(
    plan: PacketPlan,
    *,
    corpus_id: str,
    packet_id: str,
    corpus_index: int,
    direction: str,
) -> PacketPlan:
    metadata = dict(plan.metadata)
    metadata["corpus"] = {
        "corpus_id": corpus_id,
        "packet_id": packet_id,
        "corpus_index": corpus_index,
        "packet_index": plan.index,
        "packet_case": plan.case,
    }
    return replace(plan, direction=direction, metadata=metadata)


def _select_pcap_case_for_packet(
    pcap_cases: Sequence[JSONObject],
    link_type: str,
) -> tuple[JSONObject, str] | None:
    for pcap_case in pcap_cases:
        file_format = _pcap_file_format_for_case(pcap_case)
        if file_format != "pcap":
            continue
        if link_type not in _pcap_link_types_for_case(pcap_case):
            continue
        return pcap_case, file_format
    return None


def _pcap_unavailable_reason_for_cases(
    pcap_cases: Sequence[JSONObject],
    link_type: str,
    *,
    case_filter_empty: bool,
) -> str:
    if case_filter_empty:
        return "pcap_case_filter"
    for pcap_case in pcap_cases:
        if link_type not in _pcap_link_types_for_case(pcap_case):
            continue
        if _pcap_file_format_for_case(pcap_case) != "pcap":
            return "pcap_case_filter"
    return "pcap_link_type_unavailable"


def _pcap_record_link_type_for_plan(link_type: str) -> str:
    if link_type == "linux_cooked":
        return "linux_sll"
    return link_type


_PCAP_PASSTHROUGH_SKIP_REASONS = {
    "pcap_link_type_unavailable",
    "pcap_case_filter",
    # Corpus-declared byte-policy skips (a normalized-only or structured-error
    # case is not safely representable through pcap). Preserve the explicit
    # reason instead of collapsing it so the report records why each case was
    # skipped rather than silently dropping it.
    "pcap_normalized_only",
    "pcap_structured_error",
}


def _pcap_normalized_skip_reason(reason: str | None) -> str:
    if reason in _PCAP_PASSTHROUGH_SKIP_REASONS:
        return reason
    return "pcap_case_filter"


def _pcap_packet_skip_reason(direction_decisions: Sequence[JSONObject]) -> str:
    reasons = [
        decision.get("reason")
        for decision in direction_decisions
        if isinstance(decision.get("reason"), str)
    ]
    if "pcap_link_type_unavailable" in reasons:
        return "pcap_link_type_unavailable"
    for reason in ("pcap_normalized_only", "pcap_structured_error"):
        if reason in reasons:
            return reason
    if "pcap_case_filter" in reasons:
        return "pcap_case_filter"
    return "pcap_case_filter"


def _pcap_group_summaries(
    groups_by_direction: Mapping[str, list[JSONObject]],
) -> list[JSONObject]:
    summaries: list[JSONObject] = []
    for direction, groups in groups_by_direction.items():
        group_summaries: list[JSONObject] = []
        for group in groups:
            plans = group.get("plans")
            plan_list = (
                [plan for plan in plans if isinstance(plan, PacketPlan)]
                if isinstance(plans, list)
                else []
            )
            group_summaries.append(
                {
                    "file_format": group.get("file_format"),
                    "link_type": group.get("link_type"),
                    "pcap_case": group.get("pcap_case"),
                    "count": len(plan_list),
                    "packet_indexes": [plan.index for plan in plan_list],
                }
            )
        summaries.append(
            {
                "direction": direction,
                "groups": group_summaries,
            }
        )
    return summaries


def _pcap_vector_groups(args: argparse.Namespace, direction: str) -> list[JSONObject]:
    from ..backends.scapy.packets import encode_packet_plan
    from ..backends.scapy.pcap import with_pcap_metadata
    from ..generator import PacketGenerator

    cases = _pcap_cases_for_direction(args=args, direction=direction, dry_plan=False)
    generator = PacketGenerator(
        seed=args.seed,
        profile=args.profile,
        backend=_pcap_generation_backend(args.backend),
    )
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


def _pcap_generation_args(args: argparse.Namespace) -> argparse.Namespace:
    generation_backend = _pcap_generation_backend(args.backend)
    if generation_backend == args.backend:
        return args
    values = vars(args).copy()
    values["backend"] = generation_backend
    return argparse.Namespace(**values)


def _pcap_generation_backend(backend: str) -> str:
    # Wireshark is parser-only. Pcap mode still needs a writer-capable generator
    # to produce deterministic packet bytes before the requested backend reads
    # the pcap. The actual comparison remains under the requested backend.
    if backend == "wireshark":
        return "scapy"
    return backend


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
        strict_bytes=(
            strict_bytes if isinstance(strict_bytes, bool) else plan.strict_bytes
        ),
        feature_tags=feature_tags,
        metadata=metadata,
    )


def _pcap_indices(args: argparse.Namespace) -> list[int]:
    if args.index is not None:
        return [args.index]
    return list(range(args.count))


def _pcap_case_supports_direction(pcap_case: JSONObject, direction: str) -> bool:
    direction = normalize_direction(direction)
    directions = _pcap_case_directions(pcap_case)
    return direction in directions or "roundtrip" in directions


def _pcap_case_directions(pcap_case: JSONObject) -> list[str]:
    directions = normalize_direction_list(pcap_case.get("directions"))
    direction = pcap_case.get("direction")
    if isinstance(direction, str):
        directions.append(normalize_direction(direction))
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
        return (
            pcap_case.get("feature") == "pcap_contracts"
            and pcap_case.get("writer") is None
            and pcap_case.get("reader") is None
        )
    if feature == "dot11_pcap_link_types":
        return pcap_case.get("feature") == "dot11_pcap_link_types"
    return False


def _pcap_case_roles_match(
    pcap_case: JSONObject,
    direction: str,
    backend: str,
) -> bool:
    writer = pcap_case.get("writer")
    reader = pcap_case.get("reader")
    if direction == "backend_to_libcrafter":
        return writer == backend and reader == "libcrafter"
    if direction == "libcrafter_to_backend":
        return writer == "libcrafter" and reader == backend
    return False


def _pcap_case_with_roles(
    pcap_case: JSONObject,
    direction: str,
    backend: str,
) -> JSONObject:
    output = dict(pcap_case)
    if direction == "backend_to_libcrafter":
        output["writer"] = backend
        output["reader"] = "libcrafter"
    elif direction == "libcrafter_to_backend":
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
    link_types = [
        _pcap_canonical_link_type(item)
        for item in _string_values(pcap_case.get("link_types"))
    ]
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


def _pcap_generation_root(
    requested_root: str | None, link_type: str, index: int
) -> str:
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
    if link_type == "ieee80211":
        return "link:dot11"
    if link_type == "radiotap":
        return "link:radiotap"
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
    if link_type == "ieee80211":
        return "dot11-qos-data"
    if link_type == "radiotap":
        return "radiotap-basic"
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
    if normalized in {"link:dot11", "link:ieee80211", "dot11", "ieee80211"}:
        return "ieee80211"
    if normalized in {"link:radiotap", "radiotap"}:
        return "radiotap"
    if normalized in {"link:linux-cooked", "link:linux-sll", "cookedlinux"}:
        return "linux_cooked"
    if normalized in {"link:null-loopback", "loopback"}:
        return "null_loopback"
    if normalized in {
        "link:raw",
        "l3:ipv4",
        "l3:ipv4-ntp",
        "l3:ipv6",
        "l3:ipv6-ntp",
        "ip",
        "ipv6",
        "raw",
    }:
        return "raw"
    raise ValueError(f"unsupported pcap root for link type selection: {root}")


def _pcap_canonical_link_type(link_type: str) -> str:
    normalized = link_type.replace("-", "_")
    if normalized in {"linux_sll", "linux_cooked"}:
        return "linux_cooked"
    if normalized in {"ether", "ethernet"}:
        return "ethernet"
    if normalized in {"dot11", "ieee80211", "ieee802_11"}:
        return "ieee80211"
    if normalized in {"radiotap", "ieee80211_radio", "ieee80211_radiotap"}:
        return "radiotap"
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
    from ..generator import run_self_checks
    from ..spec_loader import run_self_checks as run_spec_self_checks

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


_SUITE_FEATURE_BY_FAMILY = {
    "ble": "ble-pcap-link-types",
    "coap": (
        "coap_datagram",
        "coap_reliable",
        "coap_observe",
        "coap_blockwise",
        "coap_extended_token",
        "coap_link_format",
        "coap_oscore",
        "coap_malformed",
        "coap_pcap",
    ),
    "dhcpv6": "dhcpv6_behavior",
    "dns": "dns_behavior",
    "igmp": "igmp_header",
    "ip": "ip_fragment_transforms",
    "ipv6": "ipv6_fragment_routing",
    "quic": "quic_behavior",
    "sctp": "sctp_core",
    "snmp": ("snmp_basic", "snmp_pdu_matrix", "snmp_v3"),
    "ssdp": "ssdp_core",
    "tls": ("tls_records", "tls_handshake", "tls_extensions"),
}
_LAYER_ONLY_SUITE_FAMILIES = frozenset({"igmp", "sctp", "ssdp"})
_SUITE_OFFLINE_DIRECTIONS = (
    "backend_to_libcrafter",
    "libcrafter_to_backend",
)


def _suite_feature_names(feature_entry: str | Sequence[str]) -> tuple[str, ...]:
    if isinstance(feature_entry, str):
        return (feature_entry,)
    names: list[str] = []
    for name in feature_entry:
        if not isinstance(name, str):
            raise ValueError(f"invalid suite feature entry: {feature_entry!r}")
        names.append(name)
    if not names:
        raise ValueError("suite feature entry must not be empty")
    return tuple(names)


def _suite_offline_cases(
    feature_name: str, *, include_feature: bool = False
) -> list[JSONObject]:
    """Derive the offline suite case matrix from a feature's supported_cases.

    Each entry pairs a declared case with one supported offline direction and
    its byte policy, excluding structured_error cases (the oracle has no offline
    malformed comparison pathway). Contract-only cases are returned for JSON
    reporting but are not emitted as runnable offline commands. The result is
    sorted for reproducibility.
    """

    from ..generator import load_stack_grammar

    grammar = load_stack_grammar()
    features = grammar.get("features", {})
    if not isinstance(features, Mapping) or feature_name not in features:
        raise ValueError(f"unknown suite feature: {feature_name}")
    feature_spec = features[feature_name]
    supported = (
        feature_spec.get("supported_cases", [])
        if isinstance(feature_spec, Mapping)
        else []
    )
    entries: list[JSONObject] = []
    for raw_case in supported:
        if not isinstance(raw_case, Mapping):
            continue
        name = raw_case.get("name")
        if not isinstance(name, str):
            continue
        byte_policy = raw_case.get("byte_policy")
        if byte_policy == "structured_error":
            continue
        contract_only = raw_case.get("contract_only") is True
        profiles = raw_case.get("profiles", [])
        profile_names = (
            [profile for profile in profiles if isinstance(profile, str)]
            if isinstance(profiles, Sequence) and not isinstance(profiles, str)
            else []
        )
        directions = raw_case.get("directions", [])
        if not isinstance(directions, Sequence) or isinstance(directions, str):
            directions = []
        for direction in _SUITE_OFFLINE_DIRECTIONS:
            if direction not in directions and "roundtrip" not in directions:
                continue
            entry: JSONObject = {
                "case": name,
                "direction": direction,
                "byte_policy": byte_policy if isinstance(byte_policy, str) else None,
            }
            if include_feature:
                entry["feature"] = feature_name
            if contract_only:
                entry["contract_only"] = True
            if profile_names:
                entry["profiles"] = profile_names
            entries.append(entry)
    entries.sort(key=lambda entry: (entry["case"], entry["direction"]))
    return entries


def _suite_layer_exists(layer: str) -> bool:
    from ..generator import load_stack_grammar

    grammar = load_stack_grammar()
    layers = grammar.get("layers", {})
    return isinstance(layers, Mapping) and layer in layers


def _specs_suite(args: argparse.Namespace) -> int:
    family = args.family
    feature_entry = _SUITE_FEATURE_BY_FAMILY.get(family)
    if feature_entry is None:
        print(
            f"no offline suite is defined for family {family!r}; "
            f"known families: {', '.join(sorted(_SUITE_FEATURE_BY_FAMILY))}",
            file=sys.stderr,
        )
        return 2

    try:
        feature_names = _suite_feature_names(feature_entry)
        include_feature = len(feature_names) > 1
        cases = [
            entry
            for feature_name in feature_names
            for entry in _suite_offline_cases(
                feature_name, include_feature=include_feature
            )
        ]
    except ValueError as exc:
        if family not in _LAYER_ONLY_SUITE_FAMILIES or not _suite_layer_exists(family):
            print(str(exc), file=sys.stderr)
            return 2
        feature_names = _suite_feature_names(feature_entry)
        include_feature = len(feature_names) > 1
        cases = []

    out_root = posixpath.join(args.out, f"{family}-offline-suite")
    commands: list[JSONObject] = []
    contract_cases: list[JSONObject] = []
    for entry in cases:
        if entry.get("contract_only") is True:
            contract_cases.append(dict(entry))
            continue
        case = entry["case"]
        direction = entry["direction"]
        feature = entry.get("feature") if include_feature else None
        seed = _derive_suite_seed(args.seed, family, case, direction)
        artifact = posixpath.join(out_root, direction, case)
        argv = [
            "tools/oracle/run",
            "offline",
            "--backend",
            args.backend,
            "--profile",
            args.profile,
            "--family",
            family,
        ]
        if isinstance(feature, str):
            argv.extend(["--feature", feature])
            artifact = posixpath.join(out_root, direction, feature, case)
        argv.extend(
            [
                "--case",
                case,
                "--direction",
                direction,
                "--seed",
                str(seed),
                "--count",
                "1",
                "--out",
                artifact,
            ]
        )
        command: JSONObject = {
            "case": case,
            "direction": direction,
            "byte_policy": entry["byte_policy"],
            "seed": seed,
            "artifact": artifact,
            "command": argv,
        }
        if isinstance(feature, str):
            command["feature"] = feature
        commands.append(command)

    feature_label = (
        feature_names[0] if len(feature_names) == 1 else ",".join(feature_names)
    )
    summary: JSONObject = {
        "mode": "specs.suite",
        "family": family,
        "feature": feature_label,
        "backend": args.backend,
        "profile": args.profile,
        "base_seed": args.seed,
        "out": out_root,
        "count": len(commands),
        "directions": list(_SUITE_OFFLINE_DIRECTIONS),
        "commands": commands,
    }
    if len(feature_names) > 1:
        summary["features"] = list(feature_names)
    if contract_cases:
        summary["contract_count"] = len(contract_cases)
        summary["contract_cases"] = contract_cases
    if not commands and not contract_cases and family in _LAYER_ONLY_SUITE_FAMILIES:
        summary["layer_only"] = True
        summary["pending_feature"] = feature_label

    if args.run:
        return _run_specs_suite(summary, commands)

    if args.json:
        sys.stdout.write(dumps_json(summary))
    else:
        print(
            f"offline suite: family={family} feature={feature_label} "
            f"backend={args.backend} profile={args.profile} cases={len(commands)}"
        )
        if summary.get("layer_only") is True:
            print(f"  layer-only suite; pending feature={feature_label}")
        for command in commands:
            print(
                f"  {command['direction']:<26} {command['case']:<34} "
                f"seed={command['seed']} -> {command['artifact']}"
            )
        for entry in contract_cases:
            print(
                f"  {entry['direction']:<26} {entry['case']:<34} "
                f"contract-only byte_policy={entry['byte_policy']}"
            )
    return 0


def _derive_suite_seed(base_seed: int, family: str, case: str, direction: str) -> int:
    import hashlib

    material = "\0".join((str(base_seed), family, case, direction)).encode("utf-8")
    digest = int.from_bytes(hashlib.sha256(material).digest()[:4], byteorder="big")
    return digest % 1_000_000


def _run_specs_suite(summary: JSONObject, commands: Sequence[JSONObject]) -> int:
    results: list[JSONObject] = []
    failed = 0
    for command in commands:
        argv = list(command["command"])
        runner = REPO_ROOT / "tools" / "oracle" / "run"
        process = subprocess.run(
            [str(runner), *argv[1:]],
            cwd=REPO_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if process.returncode != 0:
            failed += 1
        results.append(
            {
                "case": command["case"],
                "direction": command["direction"],
                "seed": command["seed"],
                "exit_code": process.returncode,
            }
        )
    status = "passed" if failed == 0 else "failed"
    summary = {
        **summary,
        "status": status,
        "passed": len(results) - failed,
        "failed": failed,
        "results": results,
    }
    sys.stdout.write(dumps_json(summary))
    return 0 if failed == 0 else 1


def _specs_validate(args: argparse.Namespace) -> int:
    from ..spec_loader import SpecValidationError, load_oracle_specs

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
        result for result in command_results if result.get("exit_code") != 0
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
        relative_path.startswith("crafter/tests/fixtures/")
        or "/fixtures/" in relative_path
    ):
        return "fixture data"
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

    # Import the commands package by its canonical name rather than ``from .``.
    # ``__init__`` aliases this module onto the ``cli`` package and copies its
    # ``__path__`` onto us, so a plain relative ``from . import commands`` would
    # root the subpackage under ``...cli.main.commands`` and break the command
    # modules' relative imports. ``__package__`` resolves to the true ``cli``
    # package under both the ``engine.*`` and ``tools.oracle.engine.*`` roots.
    commands = importlib.import_module(f"{__package__}.commands")

    commands.register_all(subparsers)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
