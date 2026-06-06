#!/usr/bin/env python3
"""Run one corpus through offline, pcap, and provider-backed live checks."""

from __future__ import annotations

import argparse
import os
from collections.abc import Mapping, Sequence
from pathlib import Path
import subprocess
import sys
from typing import Any


_SCRIPT_PATH = Path(__file__).resolve()
_REPO_ROOT = _SCRIPT_PATH.parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tools.oracle.engine.model import JSONObject, read_json, write_json
from tools.oracle.engine.providers.base import LiveProviderAdapter
from tools.oracle.engine.providers.registry import (
    registered_provider_names,
    resolve_live_provider,
)


REAL_VM_PROVIDERS = ("qemu", "virtualbox")
STRICT_VM_SMOKE_ENV = "LIBCRAFTER_ORACLE_VM_SMOKE_STRICT"
ALLOW_VM_CREATE_ENV = "LIBCRAFTER_ORACLE_VM_SMOKE_ALLOW_CREATE"
REAL_MAX_COUNT_ENV = "LIBCRAFTER_ORACLE_VM_SMOKE_MAX_COUNT"
DEFAULT_REAL_MAX_COUNT = 5


class MatrixValidationError(RuntimeError):
    """Raised when a matrix report is missing required provider-neutral data."""


def parse_provider_list(raw: str) -> list[str]:
    providers = [item.strip() for item in raw.split(",") if item.strip()]
    if not providers:
        raise argparse.ArgumentTypeError("at least one provider is required")
    return providers


def validate_live_report(
    report: Mapping[str, Any],
    *,
    provider: str,
    adapter: LiveProviderAdapter,
    corpus_id: str,
    corpus_path: Path,
    report_path: Path,
    dry_run: bool = True,
    doctor: JSONObject | None = None,
) -> JSONObject:
    """Return compact provider summary after validating live report metadata."""

    metadata = _object(report.get("metadata"), "report.metadata")
    if (
        dry_run
        and report.get("status") == "skipped"
        and metadata.get("skip_reason") == "no_wire_eligible_packets"
    ):
        return _validate_no_wire_eligible_dry_run_report(
            report,
            metadata=metadata,
            provider=provider,
            adapter=adapter,
            corpus_id=corpus_id,
            corpus_path=corpus_path,
            report_path=report_path,
            doctor=doctor,
        )

    errors: list[str] = []
    expected_status = "dry-run" if dry_run else "passed"
    expected_roles = list(adapter.endpoint_roles)
    planned_infrastructure = _object_or_error(
        metadata.get("planned_infrastructure"),
        "metadata.planned_infrastructure",
        errors,
    )
    endpoint_plan = _object_or_error(
        metadata.get("endpoint_plan", metadata.get("wire_endpoint_plan")),
        "metadata.endpoint_plan",
        errors,
    )
    endpoint_lifecycle = _object_or_error(
        metadata.get("endpoint_lifecycle", metadata.get("wire_endpoint_lifecycle")),
        "metadata.endpoint_lifecycle",
        errors,
    )
    artifact_collection = _object_or_error(
        metadata.get("artifact_collection"),
        "metadata.artifact_collection",
        errors,
    )
    teardown = _object_or_error(metadata.get("teardown"), "metadata.teardown", errors)
    lab_session = _object_or_error(
        metadata.get("lab_session"),
        "metadata.lab_session",
        errors,
    )
    lab_cleanup_state = _object_or_error(
        lab_session.get("cleanup_state"),
        "metadata.lab_session.cleanup_state",
        errors,
    )
    lifecycle_cleanup_state = _object_or_error(
        endpoint_lifecycle.get("cleanup_state"),
        "metadata.endpoint_lifecycle.cleanup_state",
        errors,
    )
    provider_workflow = _json_list(metadata.get("provider_workflow", []))
    lab_provider_workflow = _json_list(metadata.get("lab_provider_workflow", []))
    provider_commands = _json_list(metadata.get("provider_commands", []))
    command_records = _json_list(metadata.get("command_records", []))
    lab_session_workflow = _json_list(lab_session.get("provider_workflow", []))
    lab_session_commands = _json_list(lab_session.get("command_records", []))
    lab_validation_checks = _json_list(lab_session.get("validation_checks", []))
    failed_lab_validations = [
        _optional_string(check.get("name")) or "validation"
        for check in lab_validation_checks
        if check.get("passed") is not True
    ]
    lab_role_names = _role_names_from_roles(lab_session.get("roles", []))
    lab_endpoint_roles = _role_names_from_endpoints(lab_session.get("endpoints", []))
    plan_endpoint_roles = _role_names_from_plan(endpoint_plan)
    lifecycle_endpoint_ids = _string_values(endpoint_lifecycle.get("created_endpoint_ids", []))
    lab_endpoint_ids = _string_values(lab_session.get("created_endpoint_ids", []))
    plan_endpoint_ids = _string_values(endpoint_plan.get("created_endpoint_ids", []))
    lab_session_id = _optional_string(lab_session.get("session_id"))
    plan_session_id = _optional_string(endpoint_plan.get("lab_session_id"))
    lab_remote_artifact_root = _optional_string(lab_session.get("remote_artifact_root"))
    lifecycle_remote_artifact_root = _optional_string(
        endpoint_lifecycle.get("remote_artifact_root")
    )
    lifecycle_lab_remote_artifact_root = _optional_string(
        endpoint_lifecycle.get("lab_remote_artifact_root")
    )

    _expect(report.get("mode") == "live", "mode must be 'live'", errors)
    _expect(
        report.get("status") == expected_status,
        f"status must be {expected_status!r}",
        errors,
    )
    _expect(metadata.get("provider") == provider, "metadata.provider mismatch", errors)
    _expect(metadata.get("dry_run") is dry_run, "metadata.dry_run mismatch", errors)
    if dry_run:
        _expect(
            metadata.get("creates_infrastructure") is False,
            "metadata.creates_infrastructure must be false",
            errors,
        )
        _expect(
            metadata.get("no_live_packets_sent") is True,
            "metadata.no_live_packets_sent must be true",
            errors,
        )
    else:
        _expect(
            metadata.get("planned_live_packet_exchange") is True,
            "metadata.planned_live_packet_exchange must be true",
            errors,
        )
        _expect(
            isinstance(metadata.get("provider_commands"), list),
            "metadata.provider_commands must be present",
            errors,
        )
        _expect(
            isinstance(
                metadata.get("endpoint_lifecycle", metadata.get("wire_endpoint_lifecycle")),
                dict,
            ),
            "metadata.endpoint_lifecycle must be present",
            errors,
        )
    _expect(
        metadata.get("corpus_id") == corpus_id,
        "metadata.corpus_id must match matrix corpus",
        errors,
    )
    _expect(
        _same_path(metadata.get("corpus_path"), corpus_path),
        "metadata.corpus_path must match matrix corpus path",
        errors,
    )
    _expect(
        metadata.get("wire_provider") == adapter.wire_provider,
        "metadata.wire_provider mismatch",
        errors,
    )
    _expect(
        metadata.get("wire_exposure") == adapter.wire_exposure,
        "metadata.wire_exposure mismatch",
        errors,
    )
    _expect(
        metadata.get("endpoint_roles") == list(adapter.endpoint_roles),
        "metadata.endpoint_roles mismatch",
        errors,
    )
    _expect(
        isinstance(metadata.get("provider_workflow"), list)
        and bool(metadata["provider_workflow"]),
        "metadata.provider_workflow must be a non-empty list",
        errors,
    )
    _expect(
        isinstance(metadata.get("endpoint_bootstrap"), list)
        and _roles_from_commands(metadata["endpoint_bootstrap"]) == set(adapter.endpoint_roles),
        "metadata.endpoint_bootstrap must cover all endpoint roles",
        errors,
    )
    _expect(
        planned_infrastructure.get("provider") == provider,
        "metadata.planned_infrastructure.provider mismatch",
        errors,
    )
    _expect(
        planned_infrastructure.get("wire_provider") == adapter.wire_provider,
        "metadata.planned_infrastructure.wire_provider mismatch",
        errors,
    )
    _expect(
        planned_infrastructure.get("wire_exposure") == adapter.wire_exposure,
        "metadata.planned_infrastructure.wire_exposure mismatch",
        errors,
    )
    _expect(
        planned_infrastructure.get("dry_run") is dry_run,
        "metadata.planned_infrastructure.dry_run mismatch",
        errors,
    )
    _expect(
        endpoint_plan.get("provider") == provider,
        "metadata.endpoint_plan.provider mismatch",
        errors,
    )
    _expect(
        endpoint_plan.get("wire_provider") == adapter.wire_provider,
        "metadata.endpoint_plan.wire_provider mismatch",
        errors,
    )
    _expect(
        endpoint_plan.get("wire_exposure", endpoint_plan.get("exposure"))
        == adapter.wire_exposure,
        "metadata.endpoint_plan.wire_exposure mismatch",
        errors,
    )
    _expect(
        endpoint_plan.get("dry_run") is dry_run,
        "metadata.endpoint_plan.dry_run mismatch",
        errors,
    )
    _expect(
        endpoint_plan.get("endpoint_count") == len(expected_roles),
        "metadata.endpoint_plan.endpoint_count mismatch",
        errors,
    )
    _expect(
        _same_role_set(plan_endpoint_roles, expected_roles),
        "metadata.endpoint_plan endpoints must match endpoint roles",
        errors,
    )
    _expect(
        plan_endpoint_ids == lab_endpoint_ids,
        "metadata.endpoint_plan.created_endpoint_ids must match lab_session",
        errors,
    )
    _expect(
        plan_session_id is not None and plan_session_id == lab_session_id,
        "metadata.endpoint_plan.lab_session_id must match lab_session",
        errors,
    )
    _expect(
        lab_session.get("provider") == provider,
        "metadata.lab_session.provider mismatch",
        errors,
    )
    _expect(
        lab_session.get("wire_provider") == adapter.wire_provider,
        "metadata.lab_session.wire_provider mismatch",
        errors,
    )
    _expect(
        lab_session.get("wire_exposure") == adapter.wire_exposure,
        "metadata.lab_session.wire_exposure mismatch",
        errors,
    )
    _expect(
        lab_session.get("dry_run") is dry_run,
        "metadata.lab_session.dry_run mismatch",
        errors,
    )
    _expect(
        lab_session_id is not None,
        "metadata.lab_session.session_id must be present",
        errors,
    )
    _expect(
        _same_role_set(lab_role_names, expected_roles),
        "metadata.lab_session.roles must match endpoint roles",
        errors,
    )
    _expect(
        _same_role_set(lab_endpoint_roles, expected_roles),
        "metadata.lab_session.endpoints must match endpoint roles",
        errors,
    )
    _expect(
        bool(lab_validation_checks),
        "metadata.lab_session.validation_checks must be present",
        errors,
    )
    _expect(
        not failed_lab_validations,
        "metadata.lab_session.validation_checks must pass: "
        + ", ".join(failed_lab_validations),
        errors,
    )
    _expect(
        bool(lab_session_workflow),
        "metadata.lab_session.provider_workflow must be a non-empty list",
        errors,
    )
    _expect(
        bool(lab_provider_workflow),
        "metadata.lab_provider_workflow must be a non-empty list",
        errors,
    )
    _expect(
        len(lab_provider_workflow) == len(lab_session_workflow),
        "metadata.lab_provider_workflow must mirror lab_session.provider_workflow",
        errors,
    )
    _expect(
        bool(lab_session_commands),
        "metadata.lab_session.command_records must be a non-empty list",
        errors,
    )
    _expect(
        bool(command_records),
        "metadata.command_records must be a non-empty list",
        errors,
    )
    _expect(
        len(command_records) == len(lab_session_commands),
        "metadata.command_records must mirror lab_session.command_records",
        errors,
    )
    _expect(
        bool(provider_commands),
        "metadata.provider_commands must be a non-empty list",
        errors,
    )
    _expect(
        len(provider_commands) == len(command_records),
        "metadata.provider_commands must mirror metadata.command_records",
        errors,
    )
    _expect(
        isinstance(artifact_collection.get("always_attempt"), bool),
        "metadata.artifact_collection.always_attempt must be present",
        errors,
    )
    _expect(
        isinstance(teardown.get("always_attempt"), bool),
        "metadata.teardown.always_attempt must be present",
        errors,
    )
    _expect(
        lifecycle_endpoint_ids == lab_endpoint_ids,
        "metadata.endpoint_lifecycle.created_endpoint_ids must match lab_session",
        errors,
    )
    _expect(
        lifecycle_cleanup_state == lab_cleanup_state,
        "metadata.endpoint_lifecycle.cleanup_state must match lab_session.cleanup_state",
        errors,
    )
    _expect(
        lab_remote_artifact_root is not None,
        "metadata.lab_session.remote_artifact_root must be present",
        errors,
    )
    _expect(
        lifecycle_remote_artifact_root is not None,
        "metadata.endpoint_lifecycle.remote_artifact_root must be present",
        errors,
    )
    _expect(
        lab_remote_artifact_root is None
        or lifecycle_remote_artifact_root == lab_remote_artifact_root
        or lifecycle_lab_remote_artifact_root == lab_remote_artifact_root,
        "metadata.endpoint_lifecycle remote artifact roots must reference lab_session",
        errors,
    )
    _expect(
        isinstance(metadata.get("endpoint_protocol"), dict)
        and isinstance(_object(metadata["endpoint_protocol"], "endpoint_protocol").get("batches"), list),
        "metadata.endpoint_protocol.batches must be present",
        errors,
    )
    _expect(
        isinstance(metadata.get("wire_eligible_count"), int),
        "metadata.wire_eligible_count must be present",
        errors,
    )
    _expect(
        isinstance(metadata.get("wire_skipped_count"), int),
        "metadata.wire_skipped_count must be present",
        errors,
    )
    _expect(
        isinstance(metadata.get("wire_skip_reasons"), dict),
        "metadata.wire_skip_reasons must be present",
        errors,
    )

    if errors:
        raise MatrixValidationError(f"{report_path}: " + "; ".join(errors))

    artifact_paths = _string_values(
        report.get("artifact_paths", report.get("artifacts", []))
    )

    return {
        "provider": provider,
        "wire_provider": adapter.wire_provider,
        "wire_exposure": adapter.wire_exposure,
        "endpoint_roles": list(adapter.endpoint_roles),
        "status": str(report["status"]),
        "dry_run": dry_run,
        "report_path": str(report_path),
        "corpus_id": corpus_id,
        "wire_eligible_count": int(metadata["wire_eligible_count"]),
        "wire_skipped_count": int(metadata["wire_skipped_count"]),
        "wire_skip_reasons": dict(metadata["wire_skip_reasons"]),
        "exchange_count": int(report.get("count", 0)),
        "no_live_packets_sent": dry_run,
        "live_packet_exchange": bool(metadata.get("live_packet_exchange", False)),
        "artifact_paths": artifact_paths,
        "lifecycle": {
            "provider_workflow_count": len(provider_workflow),
            "lab_provider_workflow_count": len(lab_provider_workflow),
            "endpoint_bootstrap_count": len(metadata["endpoint_bootstrap"]),
            "provider_command_count": len(provider_commands),
            "command_record_count": len(command_records),
            "artifact_collection": artifact_collection,
            "teardown": teardown,
            "endpoint_lifecycle": endpoint_lifecycle,
            "wire_endpoint_lifecycle": endpoint_lifecycle,
            "endpoint_ids": lifecycle_endpoint_ids,
            "remote_artifact_root": _optional_string(
                endpoint_lifecycle.get("remote_artifact_root")
            ),
        },
        "lab_session": {
            "session_id": lab_session_id,
            "provider": provider,
            "wire_provider": adapter.wire_provider,
            "wire_exposure": adapter.wire_exposure,
            "roles": lab_role_names,
            "endpoint_roles": lab_endpoint_roles,
            "endpoint_ids": lab_endpoint_ids,
            "remote_artifact_root": lab_remote_artifact_root,
            "cleanup_state": lab_cleanup_state,
            "validation_count": len(lab_validation_checks),
            "failed_validation_count": len(failed_lab_validations),
            "provider_workflow_count": len(lab_provider_workflow),
            "command_record_count": len(command_records),
        },
        "provider_workflow": provider_workflow,
        "provider_commands": provider_commands,
        **({"doctor": doctor} if doctor is not None else {}),
    }


def _validate_no_wire_eligible_dry_run_report(
    report: Mapping[str, Any],
    *,
    metadata: Mapping[str, Any],
    provider: str,
    adapter: LiveProviderAdapter,
    corpus_id: str,
    corpus_path: Path,
    report_path: Path,
    doctor: JSONObject | None = None,
) -> JSONObject:
    """Validate a dry-run live report where the corpus has no wire cases."""

    errors: list[str] = []
    expected_roles = list(adapter.endpoint_roles)
    planned_infrastructure = _object_or_error(
        metadata.get("planned_infrastructure_if_packets_eligible"),
        "metadata.planned_infrastructure_if_packets_eligible",
        errors,
    )
    provider_workflow = _json_list(
        metadata.get("provider_workflow_if_packets_eligible", [])
    )
    endpoint_bootstrap = _json_list(
        metadata.get("endpoint_bootstrap_if_packets_eligible", [])
    )

    _expect(report.get("mode") == "live", "mode must be 'live'", errors)
    _expect(report.get("status") == "skipped", "status must be 'skipped'", errors)
    _expect(metadata.get("provider") == provider, "metadata.provider mismatch", errors)
    _expect(metadata.get("dry_run") is True, "metadata.dry_run mismatch", errors)
    _expect(
        metadata.get("skipped") is True,
        "metadata.skipped must be true",
        errors,
    )
    _expect(
        metadata.get("skip_reason") == "no_wire_eligible_packets",
        "metadata.skip_reason must be no_wire_eligible_packets",
        errors,
    )
    _expect(
        metadata.get("creates_infrastructure") is False,
        "metadata.creates_infrastructure must be false",
        errors,
    )
    _expect(
        metadata.get("no_live_packets_sent") is True,
        "metadata.no_live_packets_sent must be true",
        errors,
    )
    _expect(
        metadata.get("planned_live_packet_exchange") is False,
        "metadata.planned_live_packet_exchange must be false",
        errors,
    )
    _expect(
        metadata.get("live_packet_exchange") is False,
        "metadata.live_packet_exchange must be false",
        errors,
    )
    _expect(
        metadata.get("corpus_id") == corpus_id,
        "metadata.corpus_id must match matrix corpus",
        errors,
    )
    _expect(
        _same_path(metadata.get("corpus_path"), corpus_path),
        "metadata.corpus_path must match matrix corpus path",
        errors,
    )
    _expect(
        metadata.get("wire_provider") == adapter.wire_provider,
        "metadata.wire_provider mismatch",
        errors,
    )
    _expect(
        metadata.get("wire_exposure") == adapter.wire_exposure,
        "metadata.wire_exposure mismatch",
        errors,
    )
    _expect(
        metadata.get("endpoint_roles") == expected_roles,
        "metadata.endpoint_roles mismatch",
        errors,
    )
    _expect(
        metadata.get("wire_eligible_count") == 0,
        "metadata.wire_eligible_count must be zero",
        errors,
    )
    _expect(
        isinstance(metadata.get("wire_skipped_count"), int),
        "metadata.wire_skipped_count must be present",
        errors,
    )
    _expect(
        isinstance(metadata.get("wire_skip_reasons"), dict),
        "metadata.wire_skip_reasons must be present",
        errors,
    )
    _expect(
        planned_infrastructure.get("provider") == provider,
        "metadata.planned_infrastructure_if_packets_eligible.provider mismatch",
        errors,
    )
    _expect(
        planned_infrastructure.get("wire_provider") == adapter.wire_provider,
        "metadata.planned_infrastructure_if_packets_eligible.wire_provider mismatch",
        errors,
    )
    _expect(
        planned_infrastructure.get("wire_exposure") == adapter.wire_exposure,
        "metadata.planned_infrastructure_if_packets_eligible.wire_exposure mismatch",
        errors,
    )
    _expect(
        planned_infrastructure.get("dry_run") is True,
        "metadata.planned_infrastructure_if_packets_eligible.dry_run mismatch",
        errors,
    )
    _expect(
        bool(provider_workflow),
        "metadata.provider_workflow_if_packets_eligible must be a non-empty list",
        errors,
    )
    _expect(
        bool(endpoint_bootstrap)
        and _roles_from_commands(endpoint_bootstrap) == set(expected_roles),
        "metadata.endpoint_bootstrap_if_packets_eligible must cover all endpoint roles",
        errors,
    )

    if errors:
        raise MatrixValidationError(f"{report_path}: " + "; ".join(errors))

    artifact_paths = _string_values(report.get("artifact_paths", report.get("artifacts", [])))

    return {
        "provider": provider,
        "wire_provider": adapter.wire_provider,
        "wire_exposure": adapter.wire_exposure,
        "endpoint_roles": expected_roles,
        "status": "skipped",
        "dry_run": True,
        "skip_reason": "no_wire_eligible_packets",
        "report_path": str(report_path),
        "corpus_id": corpus_id,
        "wire_eligible_count": 0,
        "wire_skipped_count": int(metadata["wire_skipped_count"]),
        "wire_skip_reasons": dict(metadata["wire_skip_reasons"]),
        "exchange_count": int(report.get("count", 0)),
        "no_live_packets_sent": True,
        "live_packet_exchange": False,
        "artifact_paths": artifact_paths,
        "lifecycle": {
            "provider_workflow_count": len(provider_workflow),
            "lab_provider_workflow_count": 0,
            "endpoint_bootstrap_count": len(endpoint_bootstrap),
            "provider_command_count": 0,
            "command_record_count": 0,
            "artifact_collection": {"always_attempt": False},
            "teardown": {"always_attempt": False},
            "endpoint_lifecycle": {},
            "wire_endpoint_lifecycle": {},
            "endpoint_ids": [],
            "remote_artifact_root": None,
        },
        "provider_workflow": provider_workflow,
        "provider_commands": [],
        **({"doctor": doctor} if doctor is not None else {}),
    }


def build_matrix_summary(
    *,
    status: str = "passed",
    backend: str,
    profile: str,
    seed: int,
    count: int,
    dry_run: bool,
    skip_unavailable: bool = False,
    strict_vm_smoke: bool = False,
    allow_vm_create: bool = False,
    confirm_live_run: bool = False,
    corpus_path: Path,
    corpus_report: Mapping[str, Any],
    offline_report_path: Path,
    pcap_report_path: Path,
    providers: Sequence[JSONObject],
    commands: Sequence[JSONObject],
) -> JSONObject:
    return {
        "status": status,
        "dry_run": dry_run,
        "real_run": not dry_run,
        "skip_unavailable": skip_unavailable,
        "strict_vm_smoke": strict_vm_smoke,
        "allow_vm_create": allow_vm_create,
        "confirm_live_run": confirm_live_run,
        "backend": backend,
        "profile": profile,
        "seed": seed,
        "count": count,
        "corpus": {
            "corpus_id": _required_string(corpus_report, "corpus_id", "corpus"),
            "path": str(corpus_path),
            "packet_count": int(corpus_report.get("count", 0)),
        },
        "baseline": {
            "offline_report_path": str(offline_report_path),
            "pcap_report_path": str(pcap_report_path),
        },
        "providers": list(providers),
        "commands": list(commands),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run one oracle corpus through provider-backed live checks.",
    )
    parser.add_argument(
        "--providers",
        type=parse_provider_list,
        default=None,
        help="comma-separated provider-backed oracle live providers",
    )
    parser.add_argument("--backend", default="scapy")
    parser.add_argument("--profile", default="smoke")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--count", type=_positive_int, default=10)
    parser.add_argument(
        "--case",
        dest="case_name",
        default=None,
        help=(
            "focused packet-generation case (e.g. dhcp-discover) threaded into "
            "the corpus and provider live commands"
        ),
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--dry-run",
        action="store_true",
        help="run provider-backed live validations in dry-run mode",
    )
    mode.add_argument(
        "--real",
        action="store_true",
        help="run guarded real VM provider-backed live validations",
    )
    parser.add_argument(
        "--out",
        default="target/oracle/provider-matrix-dry-run",
        help="matrix output directory",
    )
    parser.add_argument(
        "--skip-unavailable",
        action="store_true",
        default=True,
        help="skip real VM providers whose doctor checks fail (default)",
    )
    parser.add_argument(
        "--strict-vm-smoke",
        action="store_true",
        help=(
            "return a failure when a real VM provider is skipped; also enabled by "
            f"{STRICT_VM_SMOKE_ENV}=1"
        ),
    )
    parser.add_argument(
        "--allow-vm-create",
        action="store_true",
        help=(
            "allow guarded real VM smoke to create local VM endpoints; also enabled by "
            f"{ALLOW_VM_CREATE_ENV}=1"
        ),
    )
    parser.add_argument(
        "--real-max-count",
        type=_positive_int,
        default=_default_real_max_count(),
        help="maximum packet count allowed for guarded real VM smoke",
    )
    parser.add_argument(
        "--confirm-live-run",
        action="store_true",
        help=(
            "confirm protected non-dry-run provider execution; required for --real "
            "(ignored for --dry-run, which never sends packets)"
        ),
    )
    args = parser.parse_args(argv)

    if args.providers is None:
        args.providers = list(REAL_VM_PROVIDERS if args.real else registered_provider_names())
    strict_vm_smoke = bool(args.strict_vm_smoke or _env_flag(STRICT_VM_SMOKE_ENV))
    allow_vm_create = bool(args.allow_vm_create or _env_flag(ALLOW_VM_CREATE_ENV))
    if args.real:
        invalid_real_providers = [
            provider for provider in args.providers if provider not in REAL_VM_PROVIDERS
        ]
        if invalid_real_providers:
            print(
                "error: --real matrix supports VM providers only: "
                f"{','.join(REAL_VM_PROVIDERS)}; got {','.join(invalid_real_providers)}",
                file=sys.stderr,
            )
            return 2
        if args.count > args.real_max_count:
            print(
                "error: --real count must be bounded for VM smoke "
                f"(count={args.count}, max={args.real_max_count})",
                file=sys.stderr,
            )
            return 2

    if args.real and not args.confirm_live_run:
        print(
            "error: real VM matrix requires --confirm-live-run to send live packets; "
            "no infrastructure was created (use --dry-run to plan without confirmation)",
            file=sys.stderr,
        )
        return 2

    if not args.skip_unavailable and args.real and not strict_vm_smoke:
        print("error: real VM matrix requires skip-unavailable or strict mode", file=sys.stderr)
        return 2

    repo_root = Path(os.environ.get("ORACLE_REPO_ROOT", _REPO_ROOT)).resolve()
    out_dir = Path(args.out)
    if not out_dir.is_absolute():
        out_dir = repo_root / out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        commands: list[JSONObject] = []
        corpus_out = out_dir / "corpus"
        corpus_command = [
            "tools/oracle/run",
            "corpus",
            "--backend",
            args.backend,
            "--profile",
            args.profile,
            "--seed",
            str(args.seed),
            "--count",
            str(args.count),
            *(["--case", args.case_name] if args.case_name is not None else []),
            "--out",
            str(corpus_out),
        ]
        commands.append(_run_command(corpus_command, cwd=repo_root, out_dir=out_dir, label="corpus"))
        corpus_path = corpus_out / "plans.json"
        corpus_report = _object(read_json(corpus_path), "corpus report")
        corpus_id = _required_string(corpus_report, "corpus_id", "corpus")

        baseline_out = out_dir / "baseline"
        offline_command = _oracle_command(
            "offline",
            args=args,
            corpus_path=corpus_path,
            out_dir=baseline_out,
        )
        pcap_command = _oracle_command(
            "pcap",
            args=args,
            corpus_path=corpus_path,
            out_dir=baseline_out,
        )
        commands.append(
            _run_command(offline_command, cwd=repo_root, out_dir=out_dir, label="offline")
        )
        commands.append(_run_command(pcap_command, cwd=repo_root, out_dir=out_dir, label="pcap"))
        offline_report_path = baseline_out / "offline" / "report.json"
        pcap_report_path = baseline_out / "pcap" / "report.json"

        provider_summaries: list[JSONObject] = []
        skipped_providers: list[str] = []
        for provider in args.providers:
            adapter = resolve_live_provider(provider)
            provider_out = out_dir / "providers" / provider
            doctor_summary: JSONObject | None = None
            if args.real:
                doctor_record = _run_command(
                    _provider_doctor_command(adapter),
                    cwd=repo_root,
                    out_dir=out_dir,
                    label=f"doctor-{provider}",
                    check=False,
                )
                commands.append(doctor_record)
                doctor_summary = _doctor_summary(doctor_record)
                if doctor_record["exit_code"] != 0 or not doctor_summary.get("ok"):
                    reason = _doctor_skip_reason(doctor_summary)
                    provider_summaries.append(
                        _provider_skip_summary(
                            provider=provider,
                            adapter=adapter,
                            corpus_id=corpus_id,
                            corpus_path=corpus_path,
                            provider_out=provider_out,
                            reason=reason,
                            doctor=doctor_summary,
                        )
                    )
                    skipped_providers.append(provider)
                    continue
                if not allow_vm_create:
                    provider_summaries.append(
                        _provider_skip_summary(
                            provider=provider,
                            adapter=adapter,
                            corpus_id=corpus_id,
                            corpus_path=corpus_path,
                            provider_out=provider_out,
                            reason=(
                                "real VM creation not enabled; pass --allow-vm-create "
                                f"or set {ALLOW_VM_CREATE_ENV}=1"
                            ),
                            doctor=doctor_summary,
                        )
                    )
                    skipped_providers.append(provider)
                    continue

            live_command = [
                *_oracle_command(
                    "live",
                    args=args,
                    corpus_path=corpus_path,
                    out_dir=provider_out,
                ),
                "--provider",
                provider,
                *(
                    ["--dry-run"]
                    if args.dry_run
                    else (["--confirm-live-run"] if args.confirm_live_run else [])
                ),
            ]
            live_record = _run_command(
                live_command,
                cwd=repo_root,
                out_dir=out_dir,
                label=f"live-{provider}",
                check=args.dry_run,
            )
            commands.append(live_record)
            report_path = provider_out / "live" / "report.json"
            if live_record["exit_code"] != 0:
                live_report = _read_optional_json(report_path)
                if args.real and _live_failure_is_unavailable(live_report):
                    reason = _live_skip_reason(live_report)
                    provider_summaries.append(
                        _provider_skip_summary(
                            provider=provider,
                            adapter=adapter,
                            corpus_id=corpus_id,
                            corpus_path=corpus_path,
                            provider_out=provider_out,
                            reason=reason,
                            doctor=doctor_summary,
                            live_command=live_record,
                            live_report=live_report,
                        )
                    )
                    skipped_providers.append(provider)
                    continue
                raise MatrixValidationError(
                    f"live-{provider} command exited {live_record['exit_code']}; "
                    f"stdout={live_record['stdout_path']} stderr={live_record['stderr_path']}"
                )

            report = _object(read_json(report_path), f"{provider} live report")
            provider_summaries.append(
                validate_live_report(
                    report,
                    provider=provider,
                    adapter=adapter,
                    corpus_id=corpus_id,
                    corpus_path=corpus_path,
                    report_path=report_path,
                    dry_run=args.dry_run,
                    doctor=doctor_summary,
                )
            )

        summary_path = out_dir / "matrix-summary.json"
        summary_status = "failed" if skipped_providers and strict_vm_smoke else "passed"
        summary = build_matrix_summary(
            status=summary_status,
            backend=args.backend,
            profile=args.profile,
            seed=args.seed,
            count=args.count,
            dry_run=args.dry_run,
            skip_unavailable=bool(args.skip_unavailable),
            strict_vm_smoke=strict_vm_smoke,
            allow_vm_create=allow_vm_create,
            confirm_live_run=bool(args.confirm_live_run),
            corpus_path=corpus_path,
            corpus_report=corpus_report,
            offline_report_path=offline_report_path,
            pcap_report_path=pcap_report_path,
            providers=provider_summaries,
            commands=commands,
        )
        write_json(summary_path, summary)
        print(
            f"provider matrix: status={summary_status} "
            f"providers={','.join(args.providers)} summary={summary_path}"
        )
        if skipped_providers and strict_vm_smoke:
            print(
                "error: strict VM smoke skipped providers: "
                f"{','.join(skipped_providers)}",
                file=sys.stderr,
            )
            return 1
        return 0
    except (MatrixValidationError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _oracle_command(
    mode: str,
    *,
    args: argparse.Namespace,
    corpus_path: Path,
    out_dir: Path,
) -> list[str]:
    case_name = getattr(args, "case_name", None)
    return [
        "tools/oracle/run",
        mode,
        "--backend",
        args.backend,
        "--profile",
        args.profile,
        "--seed",
        str(args.seed),
        "--count",
        str(args.count),
        *(["--case", case_name] if case_name is not None else []),
        "--corpus",
        str(corpus_path),
        "--out",
        str(out_dir),
    ]


def _run_command(
    argv: Sequence[str],
    *,
    cwd: Path,
    out_dir: Path,
    label: str,
    check: bool = True,
) -> JSONObject:
    logs_dir = out_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = logs_dir / f"{label}.stdout.txt"
    stderr_path = logs_dir / f"{label}.stderr.txt"
    process = subprocess.run(
        list(argv),
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    stdout_path.write_text(process.stdout, encoding="utf-8")
    stderr_path.write_text(process.stderr, encoding="utf-8")
    record: JSONObject = {
        "label": label,
        "argv": list(argv),
        "exit_code": process.returncode,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
    }
    if process.returncode != 0 and check:
        raise MatrixValidationError(
            f"{label} command exited {process.returncode}; "
            f"stdout={stdout_path} stderr={stderr_path}"
        )
    return record


def _provider_doctor_command(adapter: LiveProviderAdapter) -> list[str]:
    return [
        "tools/endpoint/run",
        "doctor",
        "--provider",
        adapter.wire_provider,
        "--exposure",
        adapter.wire_exposure,
        "--json",
    ]


def _doctor_summary(record: JSONObject) -> JSONObject:
    report = _read_optional_json(Path(str(record["stdout_path"])))
    checks = _json_list(report.get("checks", []) if report is not None else [])
    failed_checks = [
        check
        for check in checks
        if isinstance(check, dict) and check.get("ok") is not True
    ]
    return {
        "ok": bool(report.get("ok")) if report is not None else False,
        "command": record,
        "report": report,
        "failed_checks": failed_checks,
    }


def _doctor_skip_reason(doctor: JSONObject) -> str:
    failed_checks = _json_list(doctor.get("failed_checks", []))
    if failed_checks:
        details = []
        for check in failed_checks:
            if not isinstance(check, dict):
                continue
            name = _optional_string(check.get("name")) or "check"
            message = _optional_string(check.get("message")) or "failed"
            details.append(f"{name}: {message}")
        if details:
            return "provider doctor failed: " + "; ".join(details)
    command = _object(doctor.get("command", {}), "doctor.command")
    return f"provider doctor exited {command.get('exit_code', 'unknown')}"


def _provider_skip_summary(
    *,
    provider: str,
    adapter: LiveProviderAdapter,
    corpus_id: str,
    corpus_path: Path,
    provider_out: Path,
    reason: str,
    doctor: JSONObject | None,
    live_command: JSONObject | None = None,
    live_report: JSONObject | None = None,
) -> JSONObject:
    report_path = provider_out / "live" / "report.json"
    output: JSONObject = {
        "provider": provider,
        "wire_provider": adapter.wire_provider,
        "wire_exposure": adapter.wire_exposure,
        "endpoint_roles": list(adapter.endpoint_roles),
        "status": "skipped",
        "dry_run": False,
        "skip_reason": reason,
        "report_path": str(report_path) if report_path.is_file() else None,
        "planned_report_path": str(report_path),
        "corpus_id": corpus_id,
        "corpus_path": str(corpus_path),
        "no_live_packets_sent": True,
        "live_packet_exchange": False,
        "doctor": doctor,
    }
    if live_command is not None:
        output["live_command"] = live_command
    if live_report is not None:
        output["live_report_status"] = live_report.get("status")
        output["live_report_metadata"] = _object(
            live_report.get("metadata", {}),
            "live_report.metadata",
        )
    return output


def _live_failure_is_unavailable(report: JSONObject | None) -> bool:
    if report is None:
        return False
    metadata = _object(report.get("metadata", {}), "live_report.metadata")
    if metadata.get("live_packet_exchange") is True:
        return False
    exchanges = metadata.get("exchanges")
    if isinstance(exchanges, list) and exchanges:
        return False
    lifecycle = _object(
        metadata.get("endpoint_lifecycle", metadata.get("wire_endpoint_lifecycle", {})),
        "live_report.metadata.endpoint_lifecycle",
    )
    created_endpoint_ids = _string_values(lifecycle.get("created_endpoint_ids", []))
    if not created_endpoint_ids and metadata.get("creates_infrastructure") is not True:
        return True
    errors = _string_values(metadata.get("execution_errors", []))
    return bool(errors)


def _live_skip_reason(report: JSONObject | None) -> str:
    if report is None:
        return "real provider run failed before writing a report"
    metadata = _object(report.get("metadata", {}), "live_report.metadata")
    errors = _string_values(metadata.get("execution_errors", []))
    if errors:
        return "real provider unavailable: " + "; ".join(errors)
    return "real provider unavailable"


def _read_optional_json(path: Path) -> JSONObject | None:
    try:
        value = read_json(path)
    except (OSError, ValueError):
        return None
    return _object(value, str(path))


def _object(value: Any, name: str) -> JSONObject:
    if not isinstance(value, dict):
        raise MatrixValidationError(f"{name} must be a JSON object")
    output: JSONObject = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise MatrixValidationError(f"{name} keys must be strings")
        output[key] = item
    return output


def _object_or_error(value: Any, name: str, errors: list[str]) -> JSONObject:
    if not isinstance(value, dict):
        errors.append(f"{name} must be present")
        return {}
    try:
        return _object(value, name)
    except MatrixValidationError as exc:
        errors.append(str(exc))
        return {}


def _json_list(value: Any) -> list[JSONObject]:
    if not isinstance(value, list):
        return []
    output: list[JSONObject] = []
    for item in value:
        if isinstance(item, dict):
            output.append(
                {str(key): value for key, value in item.items() if isinstance(key, str)}
            )
    return output


def _string_values(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _optional_string(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _roles_from_commands(value: Any) -> set[str]:
    if not isinstance(value, list):
        return set()
    roles: set[str] = set()
    for item in value:
        if isinstance(item, dict) and isinstance(item.get("role"), str):
            roles.add(item["role"])
    return roles


def _role_names_from_roles(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [
        item["name"]
        for item in value
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    ]


def _role_names_from_endpoints(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [
        item["role"]
        for item in value
        if isinstance(item, dict) and isinstance(item.get("role"), str)
    ]


def _role_names_from_plan(plan: Mapping[str, Any]) -> list[str]:
    endpoints = plan.get("endpoints")
    if isinstance(endpoints, dict):
        return [role for role in endpoints if isinstance(role, str)]
    endpoint_plans = plan.get("endpoint_plans")
    if isinstance(endpoint_plans, list):
        return _role_names_from_endpoints(endpoint_plans)
    return []


def _same_role_set(actual: Sequence[str], expected: Sequence[str]) -> bool:
    return set(actual) == set(expected)


def _required_string(value: Mapping[str, Any], key: str, name: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item:
        raise MatrixValidationError(f"{name}.{key} must be a non-empty string")
    return item


def _same_path(value: Any, expected: Path) -> bool:
    if not isinstance(value, str) or not value:
        return False
    return Path(value).resolve() == expected.resolve()


def _expect(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(message)


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def _env_flag(name: str) -> bool:
    value = os.environ.get(name, "").strip().lower()
    return value in {"1", "true", "yes", "on", "strict"}


def _default_real_max_count() -> int:
    value = os.environ.get(REAL_MAX_COUNT_ENV)
    if value is None:
        return DEFAULT_REAL_MAX_COUNT
    try:
        parsed = int(value)
    except ValueError:
        return DEFAULT_REAL_MAX_COUNT
    return parsed if parsed > 0 else DEFAULT_REAL_MAX_COUNT


if __name__ == "__main__":
    raise SystemExit(main())
