"""Command-line interface for probe validation."""

from __future__ import annotations

import argparse
import os
import posixpath
import shlex
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

_REPO_ROOT_FOR_IMPORTS = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT_FOR_IMPORTS) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT_FOR_IMPORTS))

from tools.lab.engine.model import LabRequest, LabRole, LabSession
from tools.lab.engine import repo as lab_repo
from tools.lab.engine import session as lab_session_state
from tools.lab.engine import wire_client as lab_wire_client

from .capabilities import (
    SKIP_CAPABILITY_UNAVAILABLE,
    SKIP_CONFIRMATION_REQUIRED,
    SKIP_REQUIRES_BROADCAST,
    SKIP_REQUIRES_CONTROLLED_ROUTER,
    SKIP_REQUIRES_CONTROLLED_SERVICE,
    SKIP_REQUIRES_LINK_LAYER,
    SKIP_REQUIRES_PRIVILEGED_PORT,
    SKIP_REQUIRES_PROVIDER_MAC,
    capability_skip_result as _capability_skip_result,
    capability_skip_state as _capability_skip_state,
    missing_capabilities as _missing_capabilities,
    primary_endpoint_role as _primary_endpoint_role,
    probe_capabilities_for_request as _probe_capabilities_for_request,
    skip_class_counts as _skip_class_counts,
    skip_reason_for_missing_capability as _skip_reason_for_missing_capability,
)
from .cases import (
    DEFAULT_PROFILE,
    ENDPOINT_ROLES as _ENDPOINT_ROLES,
    PROBE_CASES as _PROBE_CASES,
    PROBE_CASE_BY_NAME as _PROBE_CASE_BY_NAME,
    case_name_filters as _case_name_filters,
    profile_default_count as _profile_default_count,
    profile_selected_cases as _profile_selected_cases,
    selected_cases as _selected_cases,
)
from .lab import (
    LOCAL_DRY_RUN_PROVIDER,
    PROBE_LAB_ROLES,
    STIMULUS_ROLE,
    TARGET_ROLE,
    is_probe_lab_provider,
    probe_address_context_from_lab_session,
    probe_capabilities_from_lab_capabilities,
    probe_provider_names,
    resolve_probe_lab_provider,
)
from . import live as probe_live
from .live import (
    cleanup_wire_probe_target as _cleanup_wire_probe_target,
    cleanup_wire_stimulus_rst_guards as _cleanup_wire_stimulus_rst_guards,
    command_artifact_paths as _command_artifact_paths,
    dedupe_paths as _dedupe_paths,
    dedupe_strings as _dedupe_strings,
    download_wire_probe_artifacts as _download_wire_probe_artifacts,
    existing_paths_from_stdout as _existing_paths_from_stdout,
    install_wire_stimulus_rst_guards as _install_wire_stimulus_rst_guards,
    json_list as _json_list,
    json_mapping as _json_mapping,
    lab_endpoint_id as _lab_endpoint_id,
    lab_endpoint_interface as _lab_endpoint_interface,
    lab_endpoint_ipv4 as _lab_endpoint_ipv4,
    parse_json_stdout as _parse_json_stdout,
    prepare_wire_probe_target as _prepare_wire_probe_target,
    probe_endpoint_response_from_path as _probe_endpoint_response_from_path,
    probe_lab_remote_dir as _probe_lab_remote_dir,
    probe_process_timeout_seconds as _probe_process_timeout_seconds,
    probe_timeout_seconds as _probe_timeout_seconds,
    rst_guard_iptables_args as _rst_guard_iptables_args,
    rst_guard_script as _rst_guard_script,
    run_lab_wire_command as _run_lab_wire_command,
    run_wire_stimulus_endpoint as _run_wire_stimulus_endpoint,
    string_list as _string_list,
    string_or as _string_or,
    upload_wire_probe_request as _upload_wire_probe_request,
    wire_command_failed as _wire_command_failed,
)
from . import results as probe_results
from .results import (
    failed_counts_by_reason as _failed_counts_by_reason,
    failed_live_probe_results as _failed_live_probe_results,
    probe_results_from_endpoint_response as _probe_results_from_endpoint_response,
)
from .model import (
    JSONObject,
    JSONValue,
    ObservedResponse,
    ProbeCase,
    ProbeReport,
    ProbeResult,
    ProbeRunRequest,
    ProbeSkip,
    json_object,
    write_json,
)
from .planning import (
    deterministic_bytes as _deterministic_bytes,
    deterministic_documentation_mac as _deterministic_documentation_mac,
    deterministic_ipv4_pair as _deterministic_ipv4_pair,
    deterministic_router_ipv4 as _deterministic_router_ipv4,
    dns_label as _dns_label,
    dns_query_name as _dns_query_name,
    planned_cases as _planned_cases,
    probe_plan_for_case as _probe_plan_for_case,
    probe_plans_for_cases as _probe_plans_for_cases,
)
from .report import DEFAULT_OUTPUT_ROOT, REPO_ROOT
from .target_services import (
    target_service_setup_plan as _target_service_setup_plan,
)


PROBE_SELECTED_SPECS = ("probe-contracts",)
STATUS_DRY_RUN = "dry-run"
STATUS_FAILED = "failed"
STATUS_PASSED = "passed"
STATUS_UNSUPPORTED = "unsupported"
FAILURE_TIMEOUT = "timeout"
FAILURE_WRONG_PEER = "wrong_peer"
FAILURE_WRONG_PAYLOAD = "wrong_payload"
FAILURE_WRONG_FLAGS = "wrong_flags"
FAILURE_DECODE_FAILED = "decode_failed"
FAILURE_TARGET_SETUP_FAILED = "target_setup_failed"


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tools/probe/run",
        description="Run libcrafter probe validation.",
    )
    parser.add_argument(
        "--provider",
        choices=probe_provider_names(),
        required=True,
        help="probe provider to use",
    )
    parser.add_argument(
        "--profile",
        default=DEFAULT_PROFILE,
        help=(
            "probe sampling profile (default: %(default)s); "
            "'behavior' selects the full DNS/DHCP/ARP/UDP suite"
        ),
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=1,
        help="deterministic probe selection seed (default: %(default)s)",
    )
    parser.add_argument(
        "--count",
        type=_positive_int,
        default=None,
        help=(
            "number of probe cases to plan "
            "(default: profile default, smoke=5, behavior=40)"
        ),
    )
    parser.add_argument(
        "--case",
        dest="case_names",
        action="append",
        help="probe case name to include; may be repeated or comma-separated",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="write a deterministic non-mutating probe plan and report",
    )
    parser.add_argument(
        "--confirm-live-run",
        action="store_true",
        help="confirm protected non-dry-run provider execution",
    )
    parser.add_argument(
        "--out",
        help="probe report output directory or report.json path",
    )
    return parser


def _run(args: argparse.Namespace) -> int:
    try:
        request = _request_from_args(args)
        selected_cases = _profile_selected_cases(request.profile, request.case_names)
        planned_cases = _planned_cases(
            selected_cases,
            seed=request.seed,
            count=request.count,
        )
        probe_plans = _probe_plans_for_cases(request, planned_cases)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    status = STATUS_DRY_RUN if request.dry_run else _live_status(request)
    report_path = _report_path(args.out, request=request, status=status)
    if request.dry_run:
        report = _dry_run_report(
            request=request,
            selected_cases=selected_cases,
            planned_cases=planned_cases,
            probe_plans=probe_plans,
            report_path=report_path,
        )
        write_json(report_path, report)
        print(
            f"probe: status={report.status} provider={request.provider} "
            f"planned={len(report.results)} report={report_path}"
        )
        return 0

    report = _guarded_live_report(
        request=request,
        selected_cases=selected_cases,
        planned_cases=planned_cases,
        probe_plans=probe_plans,
        report_path=report_path,
        status=status,
    )
    write_json(report_path, report)
    print(
        f"probe: status={report.status} provider={request.provider} "
        f"planned={len(report.results)} report={report_path}",
        file=sys.stderr,
    )
    return 0 if report.status == STATUS_PASSED else 2


def _request_from_args(args: argparse.Namespace) -> ProbeRunRequest:
    case_names = _case_name_filters(args.case_names)
    count_explicit = args.count is not None
    count = args.count if count_explicit else _profile_default_count(args.profile)
    metadata: JSONObject = {
        "requested_count": count,
        "count_explicit": count_explicit,
        "profile_default_count": _profile_default_count(args.profile),
        "requested_cases": list(case_names),
        "selected_specs": list(PROBE_SELECTED_SPECS),
        "command": _requested_command(),
    }
    return ProbeRunRequest(
        provider=args.provider,
        profile=args.profile,
        seed=args.seed,
        count=count,
        case_names=case_names,
        dry_run=bool(args.dry_run),
        confirm_live_run=bool(args.confirm_live_run),
        out=args.out,
        metadata=metadata,
    )


def _dry_run_report(
    *,
    request: ProbeRunRequest,
    selected_cases: Sequence[ProbeCase],
    planned_cases: Sequence[ProbeCase],
    probe_plans: Sequence[JSONObject],
    report_path: Path,
) -> ProbeReport:
    provider_context: JSONObject = {}
    stimulus_endpoint: JSONObject = {}
    provider_capabilities = _probe_capabilities_for_request(request, dry_run=True)
    if is_probe_lab_provider(request.provider):
        lab_session = _probe_lab_dry_run_session(request)
        address_context = probe_address_context_from_lab_session(lab_session)
        stimulus_endpoint = _stimulus_endpoint_context(address_context)
        probe_plans = _probe_plans_with_lab_endpoint_addresses(
            probe_plans,
            address_context=address_context,
        )
        provider_capabilities = probe_capabilities_from_lab_capabilities(
            request.provider,
            lab_session.provider_capabilities,
            dry_run=True,
        )
        provider_context = _lab_session_probe_report_metadata(
            lab_session,
            address_context=address_context,
            provider_capabilities=provider_capabilities,
        )

    return _build_report(
        request=request,
        selected_cases=selected_cases,
        planned_cases=planned_cases,
        probe_plans=probe_plans,
        report_path=report_path,
        status=STATUS_DRY_RUN,
        dry_run=True,
        provider_context=provider_context,
        provider_capabilities=provider_capabilities,
        stimulus_endpoint=stimulus_endpoint,
    )


def _guarded_live_report(
    *,
    request: ProbeRunRequest,
    selected_cases: Sequence[ProbeCase],
    planned_cases: Sequence[ProbeCase],
    probe_plans: Sequence[JSONObject],
    report_path: Path,
    status: str,
) -> ProbeReport:
    if is_probe_lab_provider(request.provider) and request.confirm_live_run:
        provider_capabilities = _probe_capabilities_for_request(request, dry_run=False)
        skipped_sequences = {
            sequence
            for sequence, case in enumerate(planned_cases)
            if _missing_capabilities(case, provider_capabilities)
        }
        executable_plans = [
            plan
            for plan in _stimulus_endpoint_plans(probe_plans)
            if int(plan.get("sequence", -1)) not in skipped_sequences
        ]
        unsupported = [
            case.name
            for sequence, case in enumerate(planned_cases)
            if sequence not in skipped_sequences and case.name not in _STIMULUS_ENDPOINT_CASES
        ]
        if (executable_plans or skipped_sequences) and not unsupported:
            return _lab_endpoint_live_report(
                request=request,
                selected_cases=selected_cases,
                planned_cases=planned_cases,
                probe_plans=probe_plans,
                report_path=report_path,
            )

    return _build_report(
        request=request,
        selected_cases=selected_cases,
        planned_cases=planned_cases,
        probe_plans=probe_plans,
        report_path=report_path,
        status=status,
        dry_run=False,
    )


def _build_report(
    *,
    request: ProbeRunRequest,
    selected_cases: Sequence[ProbeCase],
    planned_cases: Sequence[ProbeCase],
    probe_plans: Sequence[JSONObject],
    report_path: Path,
    status: str,
    dry_run: bool,
    provider_context: JSONObject | None = None,
    provider_capabilities: Mapping[str, JSONValue] | None = None,
    stimulus_endpoint: Mapping[str, JSONValue] | None = None,
) -> ProbeReport:
    provider_capabilities = provider_capabilities or _probe_capabilities_for_request(
        request,
        dry_run=dry_run,
    )
    probe_plans_by_sequence = {
        int(plan["sequence"]): plan
        for plan in probe_plans
        if isinstance(plan.get("sequence"), int)
    }
    endpoint_request_path = _write_stimulus_endpoint_request_artifact(
        report_path=report_path,
        request=request,
        probe_plans=probe_plans,
        dry_run=dry_run,
        stimulus_endpoint=stimulus_endpoint,
    )
    results: list[ProbeResult] = []
    skips: list[ProbeSkip] = []
    observed_responses: list[ObservedResponse] = []
    skip_counts: dict[str, int] = {}

    for sequence, case in enumerate(planned_cases):
        probe_plan = probe_plans_by_sequence.get(sequence, {})
        capability_skip = _capability_skip_result(
            request=request,
            case=case,
            sequence=sequence,
            probe_plan=probe_plan,
            dry_run=dry_run,
            provider_capabilities=provider_capabilities,
        )
        if capability_skip is not None:
            skip, result = capability_skip
            skips.append(skip)
            skip_counts[skip.reason] = skip_counts.get(skip.reason, 0) + 1
            results.append(result)
            continue

        if not dry_run and not request.confirm_live_run:
            skip = ProbeSkip(
                case=case.name,
                sequence=sequence,
                reason=SKIP_CONFIRMATION_REQUIRED,
                metadata={
                    "provider": request.provider,
                    "requires_confirm_live_run": True,
                    "probe_plan": probe_plan,
                },
            )
            skips.append(skip)
            skip_counts[skip.reason] = skip_counts.get(skip.reason, 0) + 1
            results.append(
                ProbeResult(
                    case=case.name,
                    sequence=sequence,
                    status="skipped",
                    endpoint_role=_primary_endpoint_role(case),
                    passed=None,
                    skip=skip,
                    metadata={"dry_run": dry_run, "probe_plan": probe_plan},
                )
            )
            continue

        observed = ObservedResponse(
            case=case.name,
            sequence=sequence,
            endpoint_role=_primary_endpoint_role(case),
            observed=False,
            response_type=case.expected_response,
            metadata={
                "dry_run": dry_run,
                "planned_only": True,
                "stimulus": case.stimulus,
                "expected_response": case.expected_response,
                "probe_plan": probe_plan,
                "failure_reasons": _failure_reasons_for_case(case.name),
            },
        )
        observed_responses.append(observed)
        results.append(
            ProbeResult(
                case=case.name,
                sequence=sequence,
                status="planned" if dry_run else STATUS_UNSUPPORTED,
                endpoint_role=_primary_endpoint_role(case),
                passed=None,
                observed_response=observed,
                metadata={
                    "dry_run": dry_run,
                    "provider": request.provider,
                    "planned_only": True,
                    "probe_plan": probe_plan,
                    "failure_reasons": _failure_reasons_for_case(case.name),
                },
            )
        )

    artifact_paths = [str(report_path)]
    if endpoint_request_path is not None:
        artifact_paths.append(str(endpoint_request_path))

    # Separate provider skips from real outcomes. A dry run executes nothing, so
    # executed/passed/failed stay zero; the skip total is split by class so a
    # capability skip can never be confused with a confirmation skip -- or, more
    # importantly, with a behavioral failure. A case the provider can support but
    # that builds the wrong packet, returns an undecodable response, or fails
    # validation must surface as `failed`, fixed in libcrafter or the probe
    # infrastructure, and rerun -- never relabeled as a skip.
    skip_class = _skip_class_counts(skips)
    metadata: JSONObject = {
        "provider": request.provider,
        "cases": [case.name for case in selected_cases],
        "requested_count": request.count,
        "planned_count": len(planned_cases),
        "selected_count": len(selected_cases),
        "executed_count": 0,
        "executed": 0,
        "passed_count": 0,
        "passed": 0,
        "failed_count": 0,
        "failed": 0,
        "executed_cases": [],
        "failed_counts_by_reason": {},
        "skipped_count": len(skips),
        "skipped_by_capability": skip_class["skipped_by_capability"],
        "skipped_by_confirmation": skip_class["skipped_by_confirmation"],
        "observed_count": sum(1 for response in observed_responses if response.observed),
        "provider_capabilities": dict(provider_capabilities),
        "skip_reasons": list(skip_counts),
        "skip_counts_by_reason": skip_counts,
        "selected_case_names": [case.name for case in selected_cases],
        "planned_case_names": [case.name for case in planned_cases],
        "probe_plans": list(probe_plans),
        "selected_specs": list(PROBE_SELECTED_SPECS),
        "dry_run": dry_run,
        "creates_infrastructure": False,
        "requires_provider_lifecycle": is_probe_lab_provider(request.provider),
        "mutates_lab": False if dry_run else None,
        "target_service_setup": _target_service_setup_plan(
            probe_plans=probe_plans,
            dry_run=dry_run,
        ),
    }
    if provider_context:
        metadata.update(provider_context)
    return ProbeReport(
        mode="probe",
        provider=request.provider,
        profile=request.profile,
        seed=request.seed,
        count=len(planned_cases),
        status=status,
        request=request,
        cases=list(selected_cases),
        endpoint_roles=list(_ENDPOINT_ROLES),
        results=results,
        skips=skips,
        observed_responses=observed_responses,
        artifacts=artifact_paths,
        artifact_paths=artifact_paths,
        metadata=metadata,
    )


def _write_stimulus_endpoint_request_artifact(
    *,
    report_path: Path,
    request: ProbeRunRequest,
    probe_plans: Sequence[JSONObject],
    dry_run: bool,
    stimulus_endpoint: Mapping[str, JSONValue] | None = None,
) -> Path | None:
    endpoint_plans = _stimulus_endpoint_request_plans(probe_plans, dry_run=dry_run)
    if not endpoint_plans:
        return None

    artifact_dir = report_path.parent / "artifacts" / "stimulus-endpoint"
    request_path = artifact_dir / "stimulus.request.json"
    endpoint_request = _stimulus_endpoint_request_object(
        request=request,
        probe_plans=endpoint_plans,
        dry_run=dry_run,
        interface=_stimulus_interface(
            stimulus_endpoint or {},
            provider=request.provider,
            dry_run=dry_run,
        ),
        artifact_root=str(artifact_dir),
        request_path=str(request_path),
        stimulus_endpoint=stimulus_endpoint,
    )
    write_json(request_path, endpoint_request)
    return request_path


_STIMULUS_ENDPOINT_CASES = frozenset(
    {
        "icmp-echo",
        "tcp-syn-open",
        "tcp-syn-closed",
        "dns-query",
        "ttl-expired",
        "dns-a-success",
        "dns-aaaa-success",
        "dns-cname-chain",
        "dns-nxdomain",
        "dns-nodata",
        "dns-txt-answer",
        "dns-mx-answer",
        "dns-srv-answer",
        "dns-edns-opt",
        "dns-repeat-transaction",
        "dhcp-discover-offer",
        "dhcp-request-ack",
        "dhcp-client-identifier",
        "dhcp-hostname",
        "dhcp-parameter-request-list",
        "dhcp-lease-time",
        "dhcp-renewal-unicast-ack",
        "dhcp-inform-ack",
        "dhcp-request-nak",
        "dhcp-rapid-repeat",
        "arp-basic-who-has",
        "arp-repeat-two-replies",
        "arp-source-address-preserved",
        "arp-alias-address-reply",
        "arp-unicast-request-reply",
        "arp-padding-reply",
        "arp-cache-flush-reply",
        "arp-mac-validation",
        "arp-spa-variation",
        "arp-broadcast-filtered-capture",
        "udp-echo-empty",
        "udp-echo-short",
        "udp-echo-binary",
        "udp-echo-large",
        "udp-source-port-reflection",
        "udp-multi-shot-order",
        "udp-closed-port-icmp",
        "udp-zero-checksum-ipv4",
        "udp-options-surplus-echo",
    }
)


def _stimulus_endpoint_plans(probe_plans: Sequence[JSONObject]) -> list[JSONObject]:
    return [plan for plan in probe_plans if plan.get("case") in _STIMULUS_ENDPOINT_CASES]


def _stimulus_endpoint_request_plans(
    probe_plans: Sequence[JSONObject],
    *,
    dry_run: bool,
) -> list[JSONObject]:
    """Select the probe plans embedded in the stimulus-endpoint request artifact.

    Live execution still gates on :data:`_STIMULUS_ENDPOINT_CASES` (the cases
    the Rust endpoint wires to a protocol module); that gating is owned by
    :func:`_guarded_live_report` and is unchanged here. The dry-run request
    artifact, however, carries every planned case so each behavioral case has a
    deterministic stimulus-endpoint request to dry-run against — even cases that
    are still planned-only and route through the endpoint's structured
    ``decode_failed`` outcome.
    """

    if dry_run:
        return [
            plan
            for plan in probe_plans
            if isinstance(plan.get("case"), str) and plan.get("case")
        ]
    return _stimulus_endpoint_plans(probe_plans)


def _probe_lab_dry_run_session(request: ProbeRunRequest) -> LabSession:
    adapter = resolve_probe_lab_provider(request.provider)
    return adapter.plan_session(_probe_lab_request(request, dry_run=True))


def _probe_lab_request(
    request: ProbeRunRequest,
    *,
    dry_run: bool,
    confirm_live_run: bool = False,
    remote_dir: str | None = None,
) -> LabRequest:
    return LabRequest(
        provider=request.provider,
        profile=request.profile,
        seed=request.seed,
        roles=[
            LabRole(
                name=STIMULUS_ROLE,
                peer_roles=[TARGET_ROLE],
                capabilities=["raw_send", "packet_capture"],
                workload_metadata={"workload": "probe", "role": STIMULUS_ROLE},
            ),
            LabRole(
                name=TARGET_ROLE,
                peer_roles=[STIMULUS_ROLE],
                capabilities=["kernel_reply", "controlled_services"],
                workload_metadata={"workload": "probe", "role": TARGET_ROLE},
            ),
        ],
        dry_run=dry_run,
        confirm_live_run=confirm_live_run,
        remote_dir=remote_dir,
        workload_label="probe",
        metadata={
            "workload": "probe",
            "role_names": list(PROBE_LAB_ROLES),
            "probe": {
                "provider": request.provider,
                "profile": request.profile,
                "seed": request.seed,
                "count": request.count,
                "case_names": list(request.case_names),
                "dry_run": dry_run,
                "confirm_live_run": confirm_live_run,
            },
        },
    )


def _lab_session_probe_report_metadata(
    session: LabSession,
    *,
    address_context: JSONObject,
    provider_capabilities: Mapping[str, JSONValue],
) -> JSONObject:
    infrastructure = json_object(
        session.infrastructure_metadata,
        "lab_session.infrastructure_metadata",
    )
    endpoint_context = json_object(
        address_context.get("endpoints", {}),
        "lab_address_context.endpoints",
    )
    provider_workflow = [command.to_dict() for command in session.provider_workflow]
    command_records = [command.to_dict() for command in session.command_records]

    metadata: JSONObject = {
        "provider": session.provider,
        "wire_provider": session.wire_provider,
        "wire_exposure": session.wire_exposure,
        "dry_run": session.dry_run,
        "creates_infrastructure": _metadata_bool(
            infrastructure,
            "creates_infrastructure",
            default=bool(session.created_endpoint_ids),
        ),
        "would_create_infrastructure": _metadata_bool(
            infrastructure,
            "would_create_infrastructure",
            default=session.dry_run,
        ),
        "endpoint_count": len(session.endpoints),
        "planned_infrastructure": infrastructure,
        "wire_endpoint_plan": _lab_session_wire_endpoint_plan(
            session,
            endpoints=endpoint_context,
        ),
        "wire_endpoint_lifecycle": {
            "remote_dir": session.remote_dir,
            "remote_artifact_root": session.remote_artifact_root,
            "created_endpoint_ids": list(session.created_endpoint_ids),
            "cleanup_state": dict(session.cleanup_state),
        },
        "provider_workflow": provider_workflow,
        "provider_commands": command_records,
        "command_records": command_records,
        "endpoints": endpoint_context,
        "lab_address_context": address_context,
        "lab_session": session.to_dict(),
        "provider_capabilities": dict(provider_capabilities),
    }
    metadata.update(_selected_lab_session_metadata(session.metadata))
    return metadata


def _lab_session_wire_endpoint_plan(
    session: LabSession,
    *,
    endpoints: Mapping[str, JSONValue],
) -> JSONObject:
    raw_plan = session.metadata.get("wire_endpoint_plan")
    plan: JSONObject = (
        json_object(raw_plan, "lab_session.wire_endpoint_plan")
        if isinstance(raw_plan, Mapping)
        else {}
    )
    plan.pop("live_endpoints", None)
    plan.setdefault("provider", session.provider)
    plan.setdefault("wire_provider", session.wire_provider)
    plan.setdefault("exposure", session.wire_exposure)
    plan.setdefault("wire_exposure", session.wire_exposure)
    plan.setdefault("dry_run", session.dry_run)
    plan.setdefault("endpoint_count", len(session.endpoints))
    plan.setdefault("endpoints", dict(endpoints))
    plan.setdefault(
        "endpoint_plans",
        [
            dict(endpoint.wire_manifest)
            for endpoint in session.endpoints
            if endpoint.wire_manifest
        ],
    )
    plan.setdefault(
        "command_metadata",
        [command.to_dict() for command in session.command_records],
    )
    plan.setdefault("created_endpoint_ids", list(session.created_endpoint_ids))
    if "private_group" not in plan and "private_group" in session.metadata:
        plan["private_group"] = _json_metadata_value(session.metadata["private_group"])
    if "private_network" not in plan and "private_network" in session.metadata:
        plan["private_network"] = _json_metadata_value(session.metadata["private_network"])
    if "bridged_lan" not in plan and "bridged_lan" in session.metadata:
        plan["bridged_lan"] = _json_metadata_value(session.metadata["bridged_lan"])
    plan["lab_session_id"] = session.session_id
    return plan


def _selected_lab_session_metadata(metadata: Mapping[str, object]) -> JSONObject:
    selected: JSONObject = {}
    for key in (
        "private_group",
        "private_network",
        "bridged_lan",
        "wire_policy",
        "credential_label",
        "credentials_available",
        "missing_credential_reason",
    ):
        if key in metadata:
            selected[key] = _json_metadata_value(metadata[key])
    return selected


def _json_metadata_value(value: object) -> JSONValue:
    return json_object({"value": value}, "lab_session.metadata")["value"]


def _metadata_bool(
    metadata: Mapping[str, JSONValue],
    key: str,
    *,
    default: bool,
) -> bool:
    value = metadata.get(key)
    return value if isinstance(value, bool) else default


def _probe_plans_with_lab_endpoint_addresses(
    probe_plans: Sequence[JSONObject],
    *,
    address_context: Mapping[str, JSONValue],
) -> list[JSONObject]:
    stimulus_ipv4 = _string_or(
        address_context.get("stimulus_ipv4"),
        _first_plan_address(probe_plans, "source_ipv4", "192.0.2.10"),
    )
    target_ipv4 = _string_or(
        address_context.get("target_ipv4"),
        _first_plan_address(probe_plans, "destination_ipv4", "192.0.2.20"),
    )
    return [
        _probe_plan_with_endpoint_addresses(
            plan,
            source_ipv4=stimulus_ipv4,
            target_ipv4=target_ipv4,
            rewrite_source="lab_session",
        )
        for plan in probe_plans
    ]


def _first_plan_address(
    probe_plans: Sequence[JSONObject],
    key: str,
    default: str,
) -> str:
    for plan in probe_plans:
        value = plan.get(key)
        if isinstance(value, str) and value:
            return value
    return default


def _lab_endpoint_live_report(
    *,
    request: ProbeRunRequest,
    selected_cases: Sequence[ProbeCase],
    planned_cases: Sequence[ProbeCase],
    probe_plans: Sequence[JSONObject],
    report_path: Path,
) -> ProbeReport:
    """Assemble a lab-backed live probe report via the live orchestration module.

    The live execution domain (lab session lifecycle, wire transport, target
    setup, stimulus execution, artifact download, and result assembly) lives in
    :mod:`tools.probe.engine.live`. This thin wrapper injects the CLI-owned
    plan-rewrite, report-metadata, and address helpers so the live module stays
    free of an import cycle back into the CLI.
    """

    return probe_live.lab_endpoint_live_report(
        request=request,
        selected_cases=selected_cases,
        planned_cases=planned_cases,
        probe_plans=probe_plans,
        report_path=report_path,
        endpoint_roles=_ENDPOINT_ROLES,
        probe_lab_request=_probe_lab_request,
        probe_plan_with_endpoint_addresses=_probe_plan_with_endpoint_addresses,
        stimulus_endpoint_request_object=_stimulus_endpoint_request_object,
        lab_session_probe_report_metadata=_lab_session_probe_report_metadata,
        probe_interface=_probe_interface,
        first_plan_address=_first_plan_address,
        selected_specs=PROBE_SELECTED_SPECS,
    )


def _stimulus_endpoint_request_object(
    *,
    request: ProbeRunRequest,
    probe_plans: Sequence[JSONObject],
    dry_run: bool,
    interface: str,
    artifact_root: str,
    request_path: str,
    stimulus_endpoint: Mapping[str, JSONValue] | None = None,
) -> JSONObject:
    first_plan = probe_plans[0] if probe_plans else {}
    endpoint_metadata = _stimulus_endpoint_request_metadata(
        stimulus_endpoint or {},
        provider=request.provider,
        interface=interface,
        dry_run=dry_run,
    )
    return {
        "schema_version": 1,
        "provider": request.provider,
        "profile": request.profile,
        "seed": request.seed,
        "dry_run": dry_run,
        "endpoint_role": "stimulus",
        "interface": interface,
        "local_ipv4": str(first_plan.get("source_ipv4", "")),
        "peer_ipv4": str(first_plan.get("destination_ipv4", "")),
        "timeout_seconds": _probe_timeout_seconds(len(probe_plans)),
        "probe_plans": list(probe_plans),
        "artifact_paths": {
            "request": request_path,
            "response": posixpath.join(artifact_root, "stimulus.response.json"),
            "captures": posixpath.join(artifact_root, "captures"),
        },
        "metadata": {
            "planned_only": dry_run,
            "case_count": len(probe_plans),
            "stimulus_endpoint": endpoint_metadata,
            "failure_reasons_by_case": {
                str(plan.get("case", "")): _failure_reasons_for_case(
                    str(plan.get("case", ""))
                )
                for plan in probe_plans
            },
        },
    }


def _stimulus_endpoint_context(
    address_context: Mapping[str, JSONValue],
) -> JSONObject:
    endpoints = _json_mapping(
        address_context.get("endpoints", {}),
        "lab_address_context.endpoints",
    )
    return _json_mapping(
        endpoints.get(STIMULUS_ROLE, {}),
        "lab_address_context.endpoints.stimulus",
    )


def _stimulus_interface(
    stimulus_endpoint: Mapping[str, JSONValue],
    *,
    provider: str,
    dry_run: bool,
) -> str:
    interface = _string_or(stimulus_endpoint.get("interface"), "")
    return interface or _probe_interface(provider, dry_run=dry_run)


def _stimulus_endpoint_request_metadata(
    stimulus_endpoint: Mapping[str, JSONValue],
    *,
    provider: str,
    interface: str,
    dry_run: bool,
) -> JSONObject:
    metadata = _json_mapping(
        stimulus_endpoint.get("metadata", {}),
        "stimulus_endpoint.metadata",
    )
    output: JSONObject = {
        "provider": provider,
        "role": STIMULUS_ROLE,
        "interface": interface,
        "interface_source": "lab_endpoint" if stimulus_endpoint else "probe_default",
        "dry_run": dry_run,
    }
    for source_key, target_key in (
        ("endpoint_id", "endpoint_id"),
        ("address", "ipv4"),
        ("ipv4", "ipv4"),
        ("peer_address", "peer_ipv4"),
    ):
        value = stimulus_endpoint.get(source_key)
        if isinstance(value, str) and value:
            output[target_key] = value
    for key in (
        "wire_provider",
        "wire_exposure",
        "lab_session_id",
        "private_group",
        "private_network",
        "bridged_lan",
    ):
        value = metadata.get(key)
        if value is not None:
            output[key] = value
    return output


def _lab_arp_alias_ipv4(target_ipv4: str, source_ipv4: str) -> str:
    """Derive a deterministic secondary IPv4 alias host on the lab segment.

    ``arp-alias-address-reply`` configures the target kernel to answer ARP for a
    *secondary* address added to the private interface, distinct from both the
    target endpoint's primary IPv4 (``target_ipv4``) and the stimulus endpoint
    (``source_ipv4``). The alias must therefore be a different host in the same
    /24 lab subnet as the target. The host octet is derived deterministically
    from the target's last octet and kept clear of the source/target hosts, the
    network (0), broadcast (255), and the conventional router (1).
    """

    octets = target_ipv4.split(".")
    if len(octets) != 4:
        raise ValueError(f"unexpected lab target IPv4 {target_ipv4!r}")
    prefix = ".".join(octets[:3])
    target_host = int(octets[3])
    source_host = int(source_ipv4.split(".")[3]) if source_ipv4.count(".") == 3 else -1
    reserved = {0, 1, 255, target_host, source_host}
    host = (target_host + 7) % 256
    while host in reserved:
        host = (host + 1) % 256
    return f"{prefix}.{host}"


def _probe_plan_with_endpoint_addresses(
    plan: JSONObject,
    *,
    source_ipv4: str,
    target_ipv4: str,
    rewrite_source: str = "wire_endpoint_plan",
) -> JSONObject:
    if plan.get("case") not in _STIMULUS_ENDPOINT_CASES:
        return dict(plan)
    updated = dict(plan)
    updated["source_ipv4"] = source_ipv4
    updated["destination_ipv4"] = target_ipv4
    updated["expected_reply_source_ipv4"] = target_ipv4
    updated["expected_reply_destination_ipv4"] = source_ipv4
    case_name = str(updated.get("case", ""))
    if case_name == "icmp-echo":
        updated["capture_filter"] = (
            f"icmp and src host {target_ipv4} and dst host {source_ipv4}"
        )
    elif case_name == "ttl-expired":
        router_ipv4 = str(
            updated.get("controlled_router_ipv4") or target_ipv4
        )
        updated["source_ipv4"] = source_ipv4
        updated["destination_ipv4"] = target_ipv4
        updated["controlled_router_ipv4"] = router_ipv4
        updated["expected_reply_source_ipv4"] = router_ipv4
        updated["expected_reply_destination_ipv4"] = source_ipv4
        updated["capture_filter"] = (
            f"icmp and src host {router_ipv4} and dst host {source_ipv4}"
        )
    elif case_name.startswith("tcp-syn-"):
        source_port = int(updated.get("source_port", 0))
        destination_port = int(updated.get("destination_port", 0))
        updated["capture_filter"] = (
            f"tcp and src host {target_ipv4} and dst host {source_ipv4} "
            f"and src port {destination_port} and dst port {source_port}"
        )
        target_service = dict(
            json_object(updated.get("target_service", {}), "probe_plan.target_service")
        )
        target_service.update(
            {
                "bind_ipv4": target_ipv4,
                "source_ipv4": source_ipv4,
            }
        )
        updated["target_service"] = target_service
        rst_guard = dict(
            json_object(updated.get("stimulus_rst_guard", {}), "probe_plan.rst_guard")
        )
        rst_guard.update(
            {
                "source_ipv4": source_ipv4,
                "destination_ipv4": target_ipv4,
                "source_port": source_port,
                "destination_port": destination_port,
            }
        )
        updated["stimulus_rst_guard"] = rst_guard
    elif case_name in {
        "dns-query",
        "dns-aaaa-success",
        "dns-cname-chain",
        "dns-nxdomain",
        "dns-nodata",
        "dns-txt-answer",
        "dns-mx-answer",
        "dns-srv-answer",
        "dns-edns-opt",
        "dns-repeat-transaction",
    }:
        source_port = int(updated.get("source_port", 0))
        destination_port = int(updated.get("destination_port", 53))
        updated["capture_filter"] = (
            f"udp and src host {target_ipv4} and dst host {source_ipv4} "
            f"and src port {destination_port} and dst port {source_port}"
        )
        target_service = dict(
            json_object(updated.get("target_service", {}), "probe_plan.target_service")
        )
        target_service.update(
            {
                "bind_ipv4": target_ipv4,
                "port": destination_port,
                "source_ipv4": source_ipv4,
            }
        )
        updated["target_service"] = target_service
        # dns-repeat-transaction carries a per-send array; rewrite each send's
        # addresses, capture filter, and validation for the lab segment so every
        # send is matched against its own response (its own source port) and not
        # confused with the sibling send.
        sends = updated.get("sends")
        if isinstance(sends, list):
            rewritten_sends: list[JSONObject] = []
            for raw_send in sends:
                send = dict(json_object(raw_send, "probe_plan.send"))
                send_source_port = int(send.get("source_port", 0))
                send_destination_port = int(send.get("destination_port", 53))
                send["source_ipv4"] = source_ipv4
                send["destination_ipv4"] = target_ipv4
                send["expected_reply_source_ipv4"] = target_ipv4
                send["expected_reply_destination_ipv4"] = source_ipv4
                send["capture_filter"] = (
                    f"udp and src host {target_ipv4} and dst host {source_ipv4} "
                    f"and src port {send_destination_port} and dst port {send_source_port}"
                )
                send_validation = dict(
                    json_object(send.get("validation", {}), "probe_plan.send.validation")
                )
                send_validation["source_ipv4"] = target_ipv4
                send_validation["destination_ipv4"] = source_ipv4
                send["validation"] = send_validation
                rewritten_sends.append(send)
            updated["sends"] = rewritten_sends
    elif case_name in {
        "dhcp-discover-offer",
        "dhcp-request-ack",
        "dhcp-client-identifier",
        "dhcp-hostname",
        "dhcp-parameter-request-list",
        "dhcp-lease-time",
        "dhcp-renewal-unicast-ack",
        "dhcp-inform-ack",
        "dhcp-request-nak",
        "dhcp-rapid-repeat",
    }:
        # DHCP uses fixed privileged ports (client 68 -> server 67). The Offer/Ack
        # flows from the responder (target) back to the client (stimulus); the
        # server identifier names the responder, so it follows the target
        # address onto the lab segment. For a SELECTING-state Request the client
        # also names the chosen server (option 54), so the stimulus server
        # identifier is rewritten to the target as well. A RENEWING-state
        # renewal Request (dhcp-renewal-unicast-ack) is unicast directly to the
        # leasing server and carries no server-identifier (54) option, so the
        # rewrite below only touches the stimulus server identifier when one is
        # present. The client identifier (option 61), the hostname (option 12),
        # and the already-bound client address (ciaddr) are opaque identities or
        # documentation-space leases that carry no transport IP, so they stay
        # unchanged across the lab-segment rewrite.
        source_port = int(updated.get("source_port", 68))
        destination_port = int(updated.get("destination_port", 67))
        updated["capture_filter"] = (
            f"udp and src host {target_ipv4} and dst host {source_ipv4} "
            f"and src port {destination_port} and dst port {source_port}"
        )
        updated["expected_server_identifier"] = target_ipv4
        if "server_identifier" in updated:
            updated["server_identifier"] = target_ipv4
        target_service = dict(
            json_object(updated.get("target_service", {}), "probe_plan.target_service")
        )
        target_service.update(
            {
                "bind_ipv4": target_ipv4,
                "port": destination_port,
                "source_ipv4": source_ipv4,
                "server_identifier": target_ipv4,
            }
        )
        updated["target_service"] = target_service
        # dhcp-rapid-repeat carries a per-send array: rewrite each send's
        # transport addresses, capture filter, server identifier (option 54), and
        # validation onto the lab segment so every Discover->Offer send is matched
        # against its own Offer (its own xid/chaddr) and never confused with the
        # sibling send. Each send keeps its distinct transaction id, client MAC,
        # and offered address (those are per-send identities, not transport IPs).
        dhcp_sends = updated.get("dhcp_sends")
        if isinstance(dhcp_sends, list):
            rewritten_dhcp_sends: list[JSONObject] = []
            for raw_send in dhcp_sends:
                send = dict(json_object(raw_send, "probe_plan.dhcp_send"))
                send_source_port = int(send.get("source_port", 68))
                send_destination_port = int(send.get("destination_port", 67))
                send["source_ipv4"] = source_ipv4
                send["destination_ipv4"] = target_ipv4
                send["expected_reply_source_ipv4"] = target_ipv4
                send["expected_reply_destination_ipv4"] = source_ipv4
                send["expected_server_identifier"] = target_ipv4
                send["capture_filter"] = (
                    f"udp and src host {target_ipv4} and dst host {source_ipv4} "
                    f"and src port {send_destination_port} and dst port {send_source_port}"
                )
                send_target_service = dict(
                    json_object(
                        send.get("target_service", {}), "probe_plan.dhcp_send.target_service"
                    )
                )
                send_target_service.update(
                    {
                        "bind_ipv4": target_ipv4,
                        "port": send_destination_port,
                        "source_ipv4": source_ipv4,
                        "server_identifier": target_ipv4,
                    }
                )
                send["target_service"] = send_target_service
                send_validation = dict(
                    json_object(send.get("validation", {}), "probe_plan.dhcp_send.validation")
                )
                send_validation["source_ipv4"] = target_ipv4
                send_validation["destination_ipv4"] = source_ipv4
                send_validation["server_identifier"] = target_ipv4
                send["validation"] = send_validation
                rewritten_dhcp_sends.append(send)
            updated["dhcp_sends"] = rewritten_dhcp_sends
        dhcp_validation = dict(
            json_object(updated.get("validation", {}), "probe_plan.validation")
        )
        dhcp_validation["server_identifier"] = target_ipv4
        updated["validation"] = dhcp_validation
    elif case_name in {
        "udp-echo-empty",
        "udp-echo-short",
        "udp-echo-binary",
        "udp-echo-large",
        "udp-source-port-reflection",
        "udp-multi-shot-order",
        "udp-closed-port-icmp",
        "udp-zero-checksum-ipv4",
        "udp-options-surplus-echo",
    }:
        source_port = int(updated.get("source_port", 0))
        destination_port = int(updated.get("destination_port", 0))
        if case_name == "udp-closed-port-icmp":
            updated["capture_filter"] = (
                f"icmp and src host {target_ipv4} and dst host {source_ipv4}"
            )
        else:
            updated["capture_filter"] = (
                f"udp and src host {target_ipv4} and dst host {source_ipv4} "
                f"and src port {destination_port} and dst port {source_port}"
            )
        target_service = dict(
            json_object(updated.get("target_service", {}), "probe_plan.target_service")
        )
        target_service.update(
            {
                "bind_ipv4": target_ipv4,
                "port": destination_port,
                "source_ipv4": source_ipv4,
            }
        )
        updated["target_service"] = target_service
        udp_validation = dict(
            json_object(updated.get("validation", {}), "probe_plan.validation")
        )
        udp_validation["source_ipv4"] = target_ipv4
        udp_validation["destination_ipv4"] = source_ipv4
        updated["validation"] = udp_validation
        # udp-multi-shot-order carries a per-send array: rewrite each datagram's
        # transport addresses, capture filter, and validation contract onto the
        # lab segment while preserving the ordered payload markers.
        udp_sends = updated.get("udp_sends")
        if isinstance(udp_sends, list):
            rewritten_udp_sends: list[JSONObject] = []
            for raw_send in udp_sends:
                send = dict(json_object(raw_send, "probe_plan.udp_send"))
                send_source_port = int(send.get("source_port", source_port))
                send_destination_port = int(send.get("destination_port", destination_port))
                send["source_ipv4"] = source_ipv4
                send["destination_ipv4"] = target_ipv4
                send["expected_reply_source_ipv4"] = target_ipv4
                send["expected_reply_destination_ipv4"] = source_ipv4
                send["capture_filter"] = (
                    f"udp and src host {target_ipv4} and dst host {source_ipv4} "
                    f"and src port {send_destination_port} and dst port {send_source_port}"
                )
                send_validation = dict(
                    json_object(send.get("validation", {}), "probe_plan.udp_send.validation")
                )
                send_validation["source_ipv4"] = target_ipv4
                send_validation["destination_ipv4"] = source_ipv4
                send["validation"] = send_validation
                rewritten_udp_sends.append(send)
            updated["udp_sends"] = rewritten_udp_sends
    elif case_name in {
        "arp-basic-who-has",
        "arp-repeat-two-replies",
        "arp-source-address-preserved",
        "arp-alias-address-reply",
        "arp-unicast-request-reply",
        "arp-padding-reply",
        "arp-cache-flush-reply",
        "arp-mac-validation",
        "arp-spa-variation",
        "arp-broadcast-filtered-capture",
    }:
        # ARP rides Ethernet directly (no IP/UDP), so the lab rewrite touches the
        # ARP protocol addresses rather than transport IPs: the stimulus resolves
        # the target endpoint's IPv4 (target protocol address) from its own IPv4
        # (sender protocol address). The Ethernet source stays the stimulus MAC
        # and the request is broadcast; the target hardware/protocol addresses the
        # reply resolves are the target endpoint's on-segment MAC/IPv4. The
        # capture filter is link-layer (ARP plus the reply opcode), so it carries
        # no host/IP terms to rewrite. ARP carries no transport source/destination
        # IPv4 to overwrite, so this branch returns directly rather than falling
        # into the shared IP-layer validation tail.
        #
        # arp-alias-address-reply is the exception: the kernel answers for a
        # *configured secondary* IPv4 alias, not its primary on-segment address.
        # The resolved target protocol address (and the expected reply sender
        # protocol address) is therefore a distinct alias host in the lab subnet,
        # derived deterministically from the target endpoint's IPv4 and threaded
        # into the target_service setup/cleanup (alias add/del) and the expected
        # reply sender-proto.
        is_alias_case = case_name == "arp-alias-address-reply"
        is_spa_case = case_name == "arp-spa-variation"
        is_filtered_capture_case = case_name == "arp-broadcast-filtered-capture"
        resolved_ipv4 = (
            _lab_arp_alias_ipv4(target_ipv4, source_ipv4)
            if is_alias_case
            else target_ipv4
        )
        # arp-spa-variation is the sender-side exception: the who-has carries an
        # ALTERNATE sender protocol address (SPA), distinct from the stimulus
        # endpoint's primary on-segment IPv4 (``source_ipv4``). The SPA is a single
        # source of truth: the request's sender_protocol_addr and the expected
        # reply target_protocol_addr are both the alternate SPA. Derive it as a
        # distinct host on the lab segment (reuse the alias-style host derivation,
        # which already avoids the source/target/router/broadcast hosts).
        sender_proto = (
            _lab_arp_alias_ipv4(source_ipv4, target_ipv4)
            if is_spa_case
            else source_ipv4
        )
        updated["source_ipv4"] = source_ipv4
        updated["destination_ipv4"] = resolved_ipv4
        updated["expected_reply_source_ipv4"] = resolved_ipv4
        updated["expected_reply_destination_ipv4"] = sender_proto
        updated["sender_protocol_addr"] = sender_proto
        updated["target_protocol_addr"] = resolved_ipv4
        if is_alias_case:
            updated["alias_ipv4"] = resolved_ipv4
        if is_spa_case:
            updated["alt_sender_ipv4"] = sender_proto
        target_service = dict(
            json_object(updated.get("target_service", {}), "probe_plan.target_service")
        )
        target_service.update(
            {
                # The kernel's primary on-segment address is the endpoint IPv4; the
                # alias is added on top of it, so the interface still binds the
                # endpoint address.
                "bind_ipv4": target_ipv4,
                "source_ipv4": source_ipv4,
                "target_protocol_addr": resolved_ipv4,
            }
        )
        if is_alias_case:
            # Target setup adds the secondary alias to the private interface (and
            # removes it during cleanup); rewrite the alias onto the lab segment so
            # the live setup configures the on-segment alias the who-has resolves.
            target_service["alias_ipv4"] = resolved_ipv4
            target_service["alias_address"] = True
        if is_spa_case:
            # For live execution the target kernel may need the alternate SPA
            # configured as a secondary sender address so it accepts/answers the
            # who-has; thread the on-segment SPA into the target service so setup
            # adds (and cleanup removes) the secondary sender address.
            target_service["alt_sender_ipv4"] = sender_proto
            target_service["alt_sender_address"] = True
        if is_filtered_capture_case:
            decoy_sender_ipv4 = _lab_arp_alias_ipv4(target_ipv4, source_ipv4)
            decoy_target_ipv4 = _lab_arp_alias_ipv4(source_ipv4, target_ipv4)

            def _rewrite_decoy_arp_event(raw_event: object) -> JSONObject:
                event = dict(json_object(raw_event, "probe_plan.decoy_arp_event"))
                event["sender_protocol_addr"] = decoy_sender_ipv4
                event["target_protocol_addr"] = decoy_target_ipv4
                return event

            if isinstance(updated.get("decoy_arp_event"), dict):
                updated["decoy_arp_event"] = _rewrite_decoy_arp_event(
                    updated["decoy_arp_event"]
                )
            target_service["decoy_arp_event"] = updated.get("decoy_arp_event")
        updated["target_service"] = target_service
        arp_validation = dict(
            json_object(updated.get("validation", {}), "probe_plan.validation")
        )
        arp_validation["sender_protocol_addr"] = resolved_ipv4
        # The reply is addressed back to the request's sender protocol address: the
        # alternate SPA for arp-spa-variation, the stimulus IPv4 otherwise.
        arp_validation["target_protocol_addr"] = sender_proto
        updated["validation"] = arp_validation
        if case_name == "arp-unicast-request-reply":
            # The unicast case sends the request directly to the known target MAC
            # rather than the broadcast address. Pin the request's Ethernet
            # destination to the target endpoint's hardware address (the resolved
            # target MAC the reply also carries) so the request stays unicast and
            # the target MAC remains a single source of truth across the request
            # frame, the target service, and the is-at validation contract.
            target_mac = target_service.get("target_hardware_addr")
            if isinstance(target_mac, str) and target_mac:
                updated["ethernet_destination"] = target_mac
        if case_name == "arp-cache-flush-reply":
            # The cache-flush case carries an explicit pre-stimulus neighbor flush
            # (a `flush_neighbor` marker plus the setup/cleanup `ip neigh` commands)
            # both at the top level (read by the endpoint via the flattened plan)
            # and mirrored into the target service. The documentation-space commands
            # name the stimulus IPv4; rewrite that onto the lab segment so the live
            # setup flushes the querier the on-segment who-has actually resolves.
            doc_stimulus_ipv4 = str(plan.get("source_ipv4", ""))

            def _rewrite_flush(commands: object) -> object:
                if not isinstance(commands, list):
                    return commands
                return [
                    command.replace(doc_stimulus_ipv4, source_ipv4)
                    if isinstance(command, str) and doc_stimulus_ipv4
                    else command
                    for command in commands
                ]

            for key in ("neighbor_flush_commands", "neighbor_flush_cleanup_commands"):
                if key in updated:
                    updated[key] = _rewrite_flush(updated[key])
                if key in target_service:
                    target_service[key] = _rewrite_flush(target_service[key])
            updated["target_service"] = target_service
        # arp-repeat-two-replies carries a per-send array: rewrite each who-has
        # send's ARP protocol addresses and is-at validation contract onto the lab
        # segment so every send resolves the same target and each decoded is-at
        # reply is validated against its own send. The two sends share the target
        # (the case point is a repeated who-has for one target), so they all
        # resolve the same on-segment protocol addresses.
        arp_sends = updated.get("arp_sends")
        if isinstance(arp_sends, list):
            rewritten_arp_sends: list[JSONObject] = []
            for raw_send in arp_sends:
                send = dict(json_object(raw_send, "probe_plan.arp_send"))
                send["source_ipv4"] = source_ipv4
                send["destination_ipv4"] = target_ipv4
                send["expected_reply_source_ipv4"] = target_ipv4
                send["expected_reply_destination_ipv4"] = source_ipv4
                send["sender_protocol_addr"] = source_ipv4
                send["target_protocol_addr"] = target_ipv4
                send_validation = dict(
                    json_object(send.get("validation", {}), "probe_plan.arp_send.validation")
                )
                send_validation["sender_protocol_addr"] = target_ipv4
                send_validation["target_protocol_addr"] = source_ipv4
                send["validation"] = send_validation
                rewritten_arp_sends.append(send)
            updated["arp_sends"] = rewritten_arp_sends
        live_rewrite: JSONObject = {
            "source": rewrite_source,
            "stimulus_ipv4": source_ipv4,
            "target_ipv4": target_ipv4,
        }
        if is_alias_case:
            live_rewrite["alias_ipv4"] = resolved_ipv4
        if is_filtered_capture_case:
            decoy_arp_event = updated.get("decoy_arp_event")
            if isinstance(decoy_arp_event, dict):
                live_rewrite["decoy_sender_ipv4"] = decoy_arp_event.get(
                    "sender_protocol_addr"
                )
                live_rewrite["decoy_target_ipv4"] = decoy_arp_event.get(
                    "target_protocol_addr"
                )
        updated["live_address_rewrite"] = live_rewrite
        return updated
    validation = dict(json_object(updated.get("validation", {}), "probe_plan.validation"))
    validation["source_ipv4"] = (
        str(updated.get("controlled_router_ipv4"))
        if case_name == "ttl-expired" and updated.get("controlled_router_ipv4")
        else target_ipv4
    )
    validation["destination_ipv4"] = source_ipv4
    updated["validation"] = validation
    updated["live_address_rewrite"] = {
        "source": rewrite_source,
        "stimulus_ipv4": source_ipv4,
        "target_ipv4": target_ipv4,
    }
    return updated


def _run_command(
    argv: Sequence[str],
    *,
    output_dir: Path,
    label: str,
    input_text: str | None = None,
    timeout_seconds: int | None = None,
    parse_json: bool = False,
) -> JSONObject:
    stdout_path = output_dir / f"{label}.stdout.txt"
    stderr_path = output_dir / f"{label}.stderr.txt"
    try:
        process = subprocess.run(
            list(argv),
            cwd=REPO_ROOT,
            input=input_text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
        )
        stdout = process.stdout
        stderr = process.stderr
        exit_code = process.returncode
        errors: list[str] = []
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        exit_code = 124
        errors = [f"{label}: command timed out after {timeout_seconds}s"]
    stdout_path.write_text(stdout, encoding="utf-8")
    stderr_path.write_text(stderr, encoding="utf-8")
    response: JSONObject | None = None
    if parse_json:
        response, parse_errors = _parse_json_stdout(stdout, label)
        errors.extend(parse_errors)
    return {
        "argv": _redacted_argv(argv),
        "exit_code": exit_code,
        "label": label,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "response": response,
        "errors": errors,
    }


def _redacted_argv(argv: Sequence[str]) -> list[str]:
    redacted: list[str] = []
    redact_next = False
    for arg in argv:
        if redact_next:
            redacted.append("<redacted>")
            redact_next = False
            continue
        if arg == "-i":
            redacted.append(arg)
            redact_next = True
            continue
        if arg.startswith("UserKnownHostsFile="):
            redacted.append("UserKnownHostsFile=<redacted>")
            continue
        if "@" in arg and not arg.startswith("-"):
            user, _, _host = arg.partition("@")
            redacted.append(f"{user}@<redacted>")
            continue
        redacted.append(arg)
    return redacted


def _probe_interface(provider: str, *, dry_run: bool) -> str:
    if provider == LOCAL_DRY_RUN_PROVIDER:
        return "dry-run0"
    configured = os.environ.get("LIBCRAFTER_PRIVATE_INTERFACE")
    if configured:
        return configured
    if dry_run:
        return "eth1"
    return "auto"


def _failure_reasons_for_case(case_name: str) -> list[str]:
    if case_name == "icmp-echo":
        return [
            FAILURE_TIMEOUT,
            FAILURE_WRONG_PEER,
            FAILURE_WRONG_PAYLOAD,
            FAILURE_DECODE_FAILED,
        ]
    if case_name in {"tcp-syn-open", "tcp-syn-closed"}:
        return [
            FAILURE_TIMEOUT,
            FAILURE_WRONG_PEER,
            FAILURE_WRONG_FLAGS,
            FAILURE_DECODE_FAILED,
            FAILURE_TARGET_SETUP_FAILED,
        ]
    if case_name in {
        "dns-query",
        "dns-aaaa-success",
        "dns-cname-chain",
        "dns-nxdomain",
        "dns-nodata",
        "dns-txt-answer",
        "dns-mx-answer",
        "dns-srv-answer",
        "dns-edns-opt",
        "dns-repeat-transaction",
    }:
        return [
            FAILURE_TIMEOUT,
            FAILURE_WRONG_PEER,
            FAILURE_WRONG_PAYLOAD,
            FAILURE_WRONG_FLAGS,
            FAILURE_DECODE_FAILED,
            FAILURE_TARGET_SETUP_FAILED,
        ]
    if case_name in {
        "dhcp-discover-offer",
        "dhcp-request-ack",
        "dhcp-client-identifier",
        "dhcp-hostname",
        "dhcp-parameter-request-list",
        "dhcp-lease-time",
        "dhcp-renewal-unicast-ack",
        "dhcp-inform-ack",
        "dhcp-request-nak",
        "dhcp-rapid-repeat",
    }:
        return [
            FAILURE_TIMEOUT,
            FAILURE_WRONG_PEER,
            FAILURE_WRONG_PAYLOAD,
            FAILURE_WRONG_FLAGS,
            FAILURE_DECODE_FAILED,
            FAILURE_TARGET_SETUP_FAILED,
        ]
    if case_name == "ttl-expired":
        return [
            FAILURE_TIMEOUT,
            FAILURE_WRONG_PEER,
            FAILURE_WRONG_PAYLOAD,
            FAILURE_DECODE_FAILED,
        ]
    if case_name in {
        "arp-alias-address-reply",
        "arp-cache-flush-reply",
        "arp-spa-variation",
        "arp-broadcast-filtered-capture",
    }:
        # The alias case adds (and removes) a secondary IPv4 on the target
        # interface as part of target setup; the cache-flush case flushes the
        # neighbor cache before the stimulus as part of target setup; the
        # spa-variation case may configure a secondary *sender* IPv4 so the kernel
        # accepts the reply addressed to the alternate SPA; the filtered-capture
        # case may emit a decoy ARP setup event. Any setup step failing is a
        # distinct failure mode on top of the shared ARP reasons.
        return [
            FAILURE_TIMEOUT,
            FAILURE_WRONG_PEER,
            FAILURE_WRONG_PAYLOAD,
            FAILURE_DECODE_FAILED,
            FAILURE_TARGET_SETUP_FAILED,
        ]
    if case_name in {
        "arp-resolution",
        "arp-basic-who-has",
        "arp-repeat-two-replies",
        "arp-source-address-preserved",
        "arp-unicast-request-reply",
        "arp-padding-reply",
        "arp-mac-validation",
    }:
        return [
            FAILURE_TIMEOUT,
            FAILURE_WRONG_PEER,
            FAILURE_WRONG_PAYLOAD,
            FAILURE_DECODE_FAILED,
        ]
    if case_name in {
        "udp-echo-empty",
        "udp-echo-short",
        "udp-echo-binary",
        "udp-echo-large",
        "udp-source-port-reflection",
        "udp-multi-shot-order",
        "udp-closed-port-icmp",
        "udp-zero-checksum-ipv4",
        "udp-options-surplus-echo",
    }:
        return [
            FAILURE_TIMEOUT,
            FAILURE_WRONG_PEER,
            FAILURE_WRONG_PAYLOAD,
            FAILURE_DECODE_FAILED,
            FAILURE_TARGET_SETUP_FAILED,
        ]
    return []


def _live_status(request: ProbeRunRequest) -> str:
    if not request.confirm_live_run:
        return "requires-confirmation"
    return STATUS_UNSUPPORTED


def _report_path(
    out: str | None,
    *,
    request: ProbeRunRequest,
    status: str,
) -> Path:
    if out:
        output = Path(out)
    else:
        output = DEFAULT_OUTPUT_ROOT / _run_name(request=request, status=status)
    if not output.is_absolute():
        output = REPO_ROOT / output
    if output.suffix == ".json":
        return output
    return output / "report.json"


def _run_name(*, request: ProbeRunRequest, status: str) -> str:
    return "-".join(
        _slug(part)
        for part in (
            status,
            request.provider,
            request.profile,
            f"seed-{request.seed}",
            f"count-{request.count}",
        )
        if part
    )


def _slug(value: object) -> str:
    raw = str(value).strip().lower()
    chars = [char if char.isalnum() else "-" for char in raw]
    slug = "-".join(part for part in "".join(chars).split("-") if part)
    return slug or "run"


def _requested_command() -> str:
    return shlex.join(["tools/probe/run", *sys.argv[1:]])


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return _run(args)


if __name__ == "__main__":
    raise SystemExit(main())
