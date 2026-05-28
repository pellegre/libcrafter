"""Command-line interface for probe validation."""

from __future__ import annotations

import argparse
import hashlib
import json
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

from .lab import (
    LOCAL_DRY_RUN_PROVIDER,
    PROBE_LAB_ROLES,
    STIMULUS_ROLE,
    TARGET_ROLE,
    is_probe_lab_provider,
    probe_address_context_from_lab_session,
    probe_capabilities_for_provider,
    probe_capabilities_from_lab_capabilities,
    probe_provider_names,
    resolve_probe_lab_provider,
)
from .model import (
    EndpointRole,
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
from .report import DEFAULT_OUTPUT_ROOT, REPO_ROOT


PROBE_SELECTED_SPECS = ("probe-contracts",)
WIRE_ENTRYPOINT = "tools/wire/run"
HETZNER_PROBE_PRIVATE_GROUP_PREFIX = "probe"
HETZNER_PROBE_STIMULUS_PRIVATE_IPV4 = "10.0.25.10"
HETZNER_PROBE_TARGET_PRIVATE_IPV4 = "10.0.25.20"
SKIP_CAPABILITY_UNAVAILABLE = "provider_capability_unavailable"
SKIP_CONFIRMATION_REQUIRED = "confirm_live_run_required"
SKIP_REQUIRES_CONTROLLED_ROUTER = "requires_controlled_router"
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


_PROBE_CASES: tuple[ProbeCase, ...] = (
    ProbeCase(
        name="icmp-echo",
        description="Send ICMP echo request and validate echo reply from peer kernel.",
        stimulus="icmp_echo_request",
        expected_response="icmp_echo_reply",
        required_capabilities=["icmp_echo"],
        endpoint_roles=["stimulus", "target"],
        metadata={"protocol": "icmp", "service": "kernel"},
    ),
    ProbeCase(
        name="tcp-syn-open",
        description="Send TCP SYN to controlled listener and validate SYN/ACK.",
        stimulus="tcp_syn",
        expected_response="tcp_syn_ack",
        required_capabilities=["tcp_open_port"],
        endpoint_roles=["stimulus", "target"],
        metadata={"protocol": "tcp", "service": "controlled_listener"},
    ),
    ProbeCase(
        name="tcp-syn-closed",
        description="Send TCP SYN to closed port and validate RST response.",
        stimulus="tcp_syn",
        expected_response="tcp_rst",
        required_capabilities=["tcp_closed_port"],
        endpoint_roles=["stimulus", "target"],
        metadata={"protocol": "tcp", "service": "kernel"},
    ),
    ProbeCase(
        name="dns-query",
        description="Send DNS query to controlled DNS service and validate matching reply.",
        stimulus="dns_query",
        expected_response="dns_response",
        required_capabilities=["dns_service"],
        endpoint_roles=["stimulus", "target"],
        metadata={"protocol": "dns", "service": "controlled_dns"},
    ),
    ProbeCase(
        name="ttl-expired",
        description="Send low-TTL packet and validate ICMP TTL-expired from controlled hop.",
        stimulus="low_ttl_probe",
        expected_response="icmp_ttl_expired",
        required_capabilities=["controlled_router"],
        endpoint_roles=["stimulus", "router"],
        metadata={"protocol": "icmp", "service": "controlled_router"},
    ),
)
_PROBE_CASE_BY_NAME = {case.name: case for case in _PROBE_CASES}
_ENDPOINT_ROLES: tuple[EndpointRole, ...] = (
    EndpointRole(
        role="stimulus",
        responsibilities=["send_probe", "capture_response", "validate_response"],
        capabilities=["raw_send", "packet_capture"],
    ),
    EndpointRole(
        role="target",
        responsibilities=["expose_kernel_behavior", "run_controlled_services"],
        capabilities=["kernel_reply", "tcp_listener", "dns_service"],
    ),
    EndpointRole(
        role="router",
        responsibilities=["emit_ttl_expired"],
        capabilities=["controlled_router"],
    ),
)


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
        default="smoke",
        help="probe sampling profile (default: %(default)s)",
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
        default=5,
        help="number of probe cases to plan (default: %(default)s)",
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
        selected_cases = _selected_cases(request.case_names)
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
    metadata: JSONObject = {
        "requested_count": args.count,
        "requested_cases": list(case_names),
        "selected_specs": list(PROBE_SELECTED_SPECS),
        "command": _requested_command(),
    }
    return ProbeRunRequest(
        provider=args.provider,
        profile=args.profile,
        seed=args.seed,
        count=args.count,
        case_names=case_names,
        dry_run=bool(args.dry_run),
        confirm_live_run=bool(args.confirm_live_run),
        out=args.out,
        metadata=metadata,
    )


def _case_name_filters(values: Sequence[str] | None) -> list[str]:
    if not values:
        return []
    names: list[str] = []
    for value in values:
        for raw_name in value.split(","):
            name = raw_name.strip()
            if name:
                names.append(name)
    return list(dict.fromkeys(names))


def _selected_cases(case_names: Sequence[str]) -> list[ProbeCase]:
    if not case_names:
        return list(_PROBE_CASES)
    unknown = [name for name in case_names if name not in _PROBE_CASE_BY_NAME]
    if unknown:
        available = ", ".join(sorted(_PROBE_CASE_BY_NAME))
        raise ValueError(
            f"unknown probe case {unknown[0]!r}; available cases: {available}"
        )
    return [_PROBE_CASE_BY_NAME[name] for name in case_names]


def _planned_cases(
    selected_cases: Sequence[ProbeCase],
    *,
    seed: int,
    count: int,
) -> list[ProbeCase]:
    if not selected_cases:
        return []
    offset = seed % len(selected_cases)
    ordered = [*selected_cases[offset:], *selected_cases[:offset]]
    return [ordered[index % len(ordered)] for index in range(count)]


def _probe_plans_for_cases(
    request: ProbeRunRequest,
    planned_cases: Sequence[ProbeCase],
) -> list[JSONObject]:
    return [
        _probe_plan_for_case(request=request, case=case, sequence=sequence)
        for sequence, case in enumerate(planned_cases)
    ]


def _probe_plan_for_case(
    *,
    request: ProbeRunRequest,
    case: ProbeCase,
    sequence: int,
) -> JSONObject:
    if case.name == "icmp-echo":
        return _icmp_echo_probe_plan(
            profile=request.profile,
            seed=request.seed,
            sequence=sequence,
        )
    if case.name in {"tcp-syn-open", "tcp-syn-closed"}:
        return _tcp_syn_probe_plan(
            case_name=case.name,
            profile=request.profile,
            seed=request.seed,
            sequence=sequence,
        )
    if case.name == "dns-query":
        return _dns_query_probe_plan(
            profile=request.profile,
            seed=request.seed,
            sequence=sequence,
        )
    if case.name == "ttl-expired":
        return _ttl_expired_probe_plan(
            profile=request.profile,
            seed=request.seed,
            sequence=sequence,
        )
    return {
        "schema_version": 1,
        "case": case.name,
        "sequence": sequence,
        "index": sequence,
        "profile": request.profile,
        "seed": request.seed,
        "stimulus": case.stimulus,
        "expected_response": case.expected_response,
        "planned_only": True,
    }


def _icmp_echo_probe_plan(
    *,
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    digest = _deterministic_bytes("icmp-echo", profile, seed, sequence)
    identifier = int.from_bytes(digest[0:2], "big") or 1
    sequence_number = int.from_bytes(digest[2:4], "big")
    stimulus_ipv4, target_ipv4 = _deterministic_ipv4_pair(profile, seed, sequence)
    payload = (
        f"libcrafter-probe:icmp-echo:{profile}:{seed}:{sequence}:"
        f"{digest.hex()[:16]}"
    ).encode("ascii")
    return {
        "schema_version": 1,
        "case": "icmp-echo",
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "icmp_echo_request",
        "expected_response": "icmp_echo_reply",
        "identifier": identifier,
        "sequence_number": sequence_number,
        "payload_hex": payload.hex(),
        "payload_length": len(payload),
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "capture_filter": (
            f"icmp and src host {target_ipv4} and dst host {stimulus_ipv4}"
        ),
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "icmp_type": 0,
            "icmp_code": 0,
            "identifier": identifier,
            "sequence_number": sequence_number,
            "payload_hex": payload.hex(),
        },
    }


def _tcp_syn_probe_plan(
    *,
    case_name: str,
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    digest = _deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = _deterministic_ipv4_pair(profile, seed, sequence)
    source_port = 61000 + int.from_bytes(digest[0:2], "big") % 4000
    destination_base = 18000 if case_name == "tcp-syn-open" else 22000
    destination_port = destination_base + int.from_bytes(digest[2:4], "big") % 3000
    sequence_number = int.from_bytes(digest[4:8], "big")
    expected_ack = (sequence_number + 1) & 0xFFFF_FFFF
    expected_response = "tcp_syn_ack" if case_name == "tcp-syn-open" else "tcp_rst"
    expected_flags = ["syn", "ack"] if case_name == "tcp-syn-open" else ["rst"]
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "tcp_syn",
        "expected_response": expected_response,
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "tcp_sequence_number": sequence_number,
        "expected_acknowledgment_number": expected_ack,
        "window": 64240,
        "target_service": {
            "required": case_name == "tcp-syn-open",
            "kind": "tcp-listener" if case_name == "tcp-syn-open" else "closed-port",
            "port": destination_port,
        },
        "stimulus_rst_guard": {
            "required": True,
            "source_ipv4": stimulus_ipv4,
            "destination_ipv4": target_ipv4,
            "source_port": source_port,
            "destination_port": destination_port,
        },
        "capture_filter": (
            f"tcp and src host {target_ipv4} and dst host {stimulus_ipv4} "
            f"and src port {destination_port} and dst port {source_port}"
        ),
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "source_port": destination_port,
            "destination_port": source_port,
            "flags": expected_flags,
            "acknowledgment_number": expected_ack,
            "allow_rst_ack": case_name == "tcp-syn-closed",
        },
    }


def _dns_query_probe_plan(
    *,
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    digest = _deterministic_bytes("dns-query", profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = _deterministic_ipv4_pair(profile, seed, sequence)
    query_id = int.from_bytes(digest[0:2], "big") or 1
    source_port = 40000 + int.from_bytes(digest[2:4], "big") % 20000
    query_type_value = 1 if sequence % 2 == 0 else 28
    query_type = "A" if query_type_value == 1 else "AAAA"
    query_name = _dns_query_name(profile=profile, seed=seed, sequence=sequence, digest=digest)
    if query_type == "A":
        answer_data = f"203.0.113.{1 + digest[4] % 250}"
    else:
        answer_data = (
            "2001:db8:"
            f"{int.from_bytes(digest[4:6], 'big'):x}:"
            f"{int.from_bytes(digest[6:8], 'big'):x}::"
            f"{1 + digest[8] % 65534:x}"
        )
    destination_port = 53
    answer_ttl = 60 + digest[9] % 180
    return {
        "schema_version": 1,
        "case": "dns-query",
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "dns_query",
        "expected_response": "dns_response",
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "query_id": query_id,
        "query_name": query_name,
        "query_type": query_type,
        "query_type_value": query_type_value,
        "query_class": "IN",
        "query_class_value": 1,
        "expected_answer_name": query_name,
        "expected_answer_type": query_type,
        "expected_answer_type_value": query_type_value,
        "expected_answer_data": answer_data,
        "expected_response_code": 0,
        "answer_ttl": answer_ttl,
        "target_service": {
            "required": True,
            "kind": "udp-dns-responder",
            "port": destination_port,
            "query_name": query_name,
            "query_type": query_type,
            "answer_data": answer_data,
        },
        "capture_filter": (
            f"udp and src host {target_ipv4} and dst host {stimulus_ipv4} "
            f"and src port {destination_port} and dst port {source_port}"
        ),
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "source_port": destination_port,
            "destination_port": source_port,
            "query_id": query_id,
            "qr": True,
            "response_code": 0,
            "question": {
                "name": query_name,
                "type": query_type,
                "class": "IN",
            },
            "answer": {
                "name": query_name,
                "type": query_type,
                "data": answer_data,
                "ttl": answer_ttl,
            },
        },
    }


def _dns_query_name(*, profile: str, seed: int, sequence: int, digest: bytes) -> str:
    label = _dns_label(profile)
    suffix = digest.hex()[:10]
    return f"probe-{seed}-{sequence}-{suffix}.{label}.libcrafter.test."


def _ttl_expired_probe_plan(
    *,
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    digest = _deterministic_bytes("ttl-expired", profile, seed, sequence)
    stimulus_ipv4, destination_ipv4 = _deterministic_ipv4_pair(
        profile,
        seed,
        sequence,
    )
    router_ipv4 = _deterministic_router_ipv4(profile, seed, sequence)
    identifier = int.from_bytes(digest[0:2], "big") or 1
    sequence_number = int.from_bytes(digest[2:4], "big")
    payload = (
        f"libcrafter-probe:ttl-expired:{profile}:{seed}:{sequence}:"
        f"{digest.hex()[:16]}"
    ).encode("ascii")
    embedded_prefix_length = 28
    return {
        "schema_version": 1,
        "case": "ttl-expired",
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "low_ttl_probe",
        "expected_response": "icmp_ttl_expired",
        "ttl": 1,
        "identifier": identifier,
        "sequence_number": sequence_number,
        "payload_hex": payload.hex(),
        "payload_length": len(payload),
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": destination_ipv4,
        "controlled_router_ipv4": router_ipv4,
        "expected_reply_source_ipv4": router_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "expected_icmp_type": 11,
        "expected_icmp_code": 0,
        "expected_embedded_prefix_length": embedded_prefix_length,
        "capture_filter": (
            f"icmp and src host {router_ipv4} and dst host {stimulus_ipv4}"
        ),
        "validation": {
            "source_ipv4": router_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "icmp_type": 11,
            "icmp_code": 0,
            "embedded_prefix": {
                "source": "stimulus_sent_bytes",
                "length": embedded_prefix_length,
                "meaning": "original IPv4 header plus first eight bytes of payload",
            },
        },
    }


def _dns_label(value: str) -> str:
    label = "".join(char.lower() if char.isalnum() else "-" for char in value)
    label = "-".join(part for part in label.split("-") if part)
    return (label or "profile")[:32].strip("-") or "profile"


def _deterministic_bytes(case: str, profile: str, seed: int, sequence: int) -> bytes:
    material = f"{case}\0{profile}\0{seed}\0{sequence}".encode("utf-8")
    return hashlib.sha256(material).digest()


def _deterministic_ipv4_pair(profile: str, seed: int, sequence: int) -> tuple[str, str]:
    digest = _deterministic_bytes("endpoint-addresses", profile, seed, sequence)
    second = 64 + digest[0] % 64
    third = digest[1]
    return f"10.{second}.{third}.10", f"10.{second}.{third}.20"


def _deterministic_router_ipv4(profile: str, seed: int, sequence: int) -> str:
    digest = _deterministic_bytes("endpoint-addresses", profile, seed, sequence)
    second = 64 + digest[0] % 64
    third = digest[1]
    return f"10.{second}.{third}.1"


def _dry_run_report(
    *,
    request: ProbeRunRequest,
    selected_cases: Sequence[ProbeCase],
    planned_cases: Sequence[ProbeCase],
    probe_plans: Sequence[JSONObject],
    report_path: Path,
) -> ProbeReport:
    provider_context: JSONObject = {}
    provider_capabilities = _probe_capabilities_for_request(request, dry_run=True)
    if is_probe_lab_provider(request.provider):
        lab_session = _probe_lab_dry_run_session(request)
        address_context = probe_address_context_from_lab_session(lab_session)
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
    if request.provider == "hetzner" and request.confirm_live_run:
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
            return _hetzner_endpoint_live_report(
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

    metadata: JSONObject = {
        "provider": request.provider,
        "cases": [case.name for case in selected_cases],
        "requested_count": request.count,
        "planned_count": len(planned_cases),
        "selected_count": len(selected_cases),
        "executed_count": 0,
        "passed_count": 0,
        "failed_count": 0,
        "executed_cases": [],
        "failed_counts_by_reason": {},
        "skipped_count": len(skips),
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
) -> Path | None:
    endpoint_plans = _stimulus_endpoint_plans(probe_plans)
    if not endpoint_plans:
        return None

    artifact_dir = report_path.parent / "artifacts" / "stimulus-endpoint"
    request_path = artifact_dir / "stimulus.request.json"
    first_plan = endpoint_plans[0]
    endpoint_request: JSONObject = {
        "schema_version": 1,
        "provider": request.provider,
        "profile": request.profile,
        "seed": request.seed,
        "dry_run": dry_run,
        "endpoint_role": "stimulus",
        "interface": _probe_interface(request.provider, dry_run=dry_run),
        "local_ipv4": str(first_plan.get("source_ipv4", "")),
        "peer_ipv4": str(first_plan.get("destination_ipv4", "")),
        "timeout_seconds": _probe_timeout_seconds(len(endpoint_plans)),
        "probe_plans": list(endpoint_plans),
        "artifact_paths": {
            "request": str(request_path),
            "response": str(artifact_dir / "stimulus.response.json"),
            "captures": str(artifact_dir / "captures"),
        },
        "metadata": {
            "planned_only": dry_run,
            "case_count": len(endpoint_plans),
            "failure_reasons_by_case": {
                str(plan.get("case", "")): _failure_reasons_for_case(
                    str(plan.get("case", ""))
                )
                for plan in endpoint_plans
            },
        },
    }
    write_json(request_path, endpoint_request)
    return request_path


_STIMULUS_ENDPOINT_CASES = frozenset(
    {"icmp-echo", "tcp-syn-open", "tcp-syn-closed", "dns-query", "ttl-expired"}
)


def _stimulus_endpoint_plans(probe_plans: Sequence[JSONObject]) -> list[JSONObject]:
    return [plan for plan in probe_plans if plan.get("case") in _STIMULUS_ENDPOINT_CASES]


def _probe_capabilities_for_request(
    request: ProbeRunRequest,
    *,
    dry_run: bool,
) -> JSONObject:
    return probe_capabilities_for_provider(request.provider, dry_run=dry_run)


def _probe_lab_dry_run_session(request: ProbeRunRequest) -> LabSession:
    adapter = resolve_probe_lab_provider(request.provider)
    return adapter.plan_session(_probe_lab_request(request))


def _probe_lab_request(request: ProbeRunRequest) -> LabRequest:
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
        dry_run=True,
        confirm_live_run=False,
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
                "dry_run": True,
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


def _hetzner_probe_provider_workflow(
    *,
    request: ProbeRunRequest,
    dry_run: bool,
) -> list[JSONObject]:
    dry_run_flag = ["--dry-run"] if dry_run else []
    create_guard = [] if dry_run else ["--confirm-live-run", "--write-manifest"]
    private_group = _hetzner_probe_private_group(request)
    workflow = [
        (
            "doctor",
            "check-hetzner-private-wire",
            [
                WIRE_ENTRYPOINT,
                "doctor",
                "--provider",
                "hetzner",
                "--exposure",
                "private",
                *dry_run_flag,
                "--json",
            ],
        ),
        (
            "create",
            "create-stimulus-private-wire-endpoint",
            [
                WIRE_ENTRYPOINT,
                "create-endpoint",
                "--provider",
                "hetzner",
                "--exposure",
                "private",
                "--role",
                "stimulus",
                "--private-group",
                private_group,
                "--private-ip",
                HETZNER_PROBE_STIMULUS_PRIVATE_IPV4,
                *dry_run_flag,
                *create_guard,
                "--json",
            ],
        ),
        (
            "create",
            "create-target-private-wire-endpoint",
            [
                WIRE_ENTRYPOINT,
                "create-endpoint",
                "--provider",
                "hetzner",
                "--exposure",
                "private",
                "--role",
                "target",
                "--private-group",
                private_group,
                "--private-ip",
                HETZNER_PROBE_TARGET_PRIVATE_IPV4,
                *dry_run_flag,
                *create_guard,
                "--json",
            ],
        ),
        (
            "upload",
            "upload-probe-stimulus-request",
            [WIRE_ENTRYPOINT, "upload", "<endpoint-id>", "<local-abs>", "<remote-abs>"],
        ),
        (
            "exec",
            "run-probe-controlled-services-and-stimulus",
            [WIRE_ENTRYPOINT, "exec", "<endpoint-id>", "--", "bash", "-lc", "<script>"],
        ),
        (
            "download",
            "download-probe-response-artifacts",
            [WIRE_ENTRYPOINT, "download", "<endpoint-id>", "<remote-abs>", "<local-abs>"],
        ),
        (
            "destroy",
            "teardown-disposable-hetzner-wire-endpoints",
            [WIRE_ENTRYPOINT, "destroy-endpoint", "<endpoint-id>", "--json"],
        ),
    ]
    return [
        {
            "role": "provider",
            "purpose": purpose,
            "argv": argv,
            "sends_live_packets": False,
            "expects_live_packets": False,
            "metadata": {
                "provider": "hetzner",
                "exposure": "private",
                "dry_run": dry_run,
                "creates_infrastructure": operation == "create" and not dry_run,
                "would_create_infrastructure": operation == "create" and dry_run,
                "private_group": private_group,
                "private_network": True,
                "wire_command": True,
                "operation": operation,
                "always_attempt": operation in {"download", "destroy"},
            },
        }
        for operation, purpose, argv in workflow
    ]


def _hetzner_probe_wire_endpoint_plan(
    *,
    request: ProbeRunRequest,
    dry_run: bool,
    output_dir: Path,
    confirm_live_run: bool = False,
    created_endpoint_ids: list[str] | None = None,
) -> JSONObject:
    private_group = _hetzner_probe_private_group(request)
    provider_commands: list[JSONObject] = []
    endpoint_plans: list[JSONObject] = []
    endpoints: dict[str, JSONObject] = {}

    doctor_args = [
        "doctor",
        "--provider",
        "hetzner",
        "--exposure",
        "private",
        "--json",
    ]
    if dry_run:
        doctor_args.append("--dry-run")
    doctor = _run_wire_command(
        doctor_args,
        output_dir=output_dir,
        label="01-wire-doctor-private",
        parse_json=True,
    )
    provider_commands.append(doctor)

    roles = (
        (
            "stimulus",
            HETZNER_PROBE_STIMULUS_PRIVATE_IPV4,
            HETZNER_PROBE_TARGET_PRIVATE_IPV4,
            "02-wire-create-stimulus",
        ),
        (
            "target",
            HETZNER_PROBE_TARGET_PRIVATE_IPV4,
            HETZNER_PROBE_STIMULUS_PRIVATE_IPV4,
            "03-wire-create-target",
        ),
    )
    for role, private_ip, peer_ip, label in roles:
        create_args = [
            "create-endpoint",
            "--provider",
            "hetzner",
            "--exposure",
            "private",
            "--role",
            role,
            "--private-group",
            private_group,
            "--private-ip",
            private_ip,
            "--json",
        ]
        if dry_run:
            create_args.append("--dry-run")
        else:
            create_args.extend(["--confirm-live-run", "--write-manifest"])
        if confirm_live_run and "--confirm-live-run" not in create_args:
            create_args.append("--confirm-live-run")

        create = _run_wire_command(
            create_args,
            output_dir=output_dir,
            label=label,
            parse_json=True,
            timeout_seconds=900,
        )
        provider_commands.append(create)
        endpoint_plan = _wire_command_json(create, f"wire.{role}.create")
        endpoint_plans.append(endpoint_plan)
        endpoints[role] = _wire_endpoint_from_plan(
            endpoint_plan,
            role=role,
            private_ip=private_ip,
            peer_private_ip=peer_ip,
            dry_run=dry_run,
        )
        if (
            not dry_run
            and created_endpoint_ids is not None
            and not _wire_command_failed(create)
        ):
            endpoint_id = endpoints[role].get("endpoint_id")
            if isinstance(endpoint_id, str) and endpoint_id:
                created_endpoint_ids.append(endpoint_id)

    return {
        "provider": "hetzner",
        "exposure": "private",
        "dry_run": dry_run,
        "private_group": private_group,
        "endpoint_count": len(endpoint_plans),
        "endpoint_plans": endpoint_plans,
        "endpoints": endpoints,
        "provider_commands": provider_commands,
    }


def _run_wire_command(
    args: Sequence[str],
    *,
    output_dir: Path,
    label: str,
    parse_json: bool = False,
    timeout_seconds: int | None = None,
) -> JSONObject:
    command_dir = output_dir / "provider"
    command_dir.mkdir(parents=True, exist_ok=True)
    command = _run_command(
        [_wire_path(), *args],
        output_dir=command_dir,
        label=label,
        timeout_seconds=timeout_seconds,
        parse_json=parse_json,
    )
    argv = _string_list(command.get("argv", []))
    command.update(
        {
            "wire_command": True,
            "operation": args[0] if args else "",
            "wire_path": _wire_path(),
            "command": shlex.join(argv),
        }
    )
    return command


def _wire_path() -> str:
    return str((REPO_ROOT / WIRE_ENTRYPOINT).resolve())


def _wire_command_json(command: Mapping[str, JSONValue], name: str) -> JSONObject:
    response = command.get("response")
    if isinstance(response, Mapping):
        return json_object(response, name)
    return {}


def _wire_command_failed(command: Mapping[str, JSONValue]) -> bool:
    exit_code = command.get("exit_code")
    return not isinstance(exit_code, int) or exit_code != 0


def _wire_endpoint_from_plan(
    endpoint_plan: JSONObject,
    *,
    role: str,
    private_ip: str,
    peer_private_ip: str,
    dry_run: bool,
) -> JSONObject:
    interface = _wire_private_interface(endpoint_plan)
    address = _string_or(interface.get("ipv4"), private_ip)
    endpoint_id = _string_or(endpoint_plan.get("endpoint_id"), f"planned-{role}")
    return {
        "endpoint_id": endpoint_id,
        "role": role,
        "interface": _string_or(interface.get("name"), "private"),
        "address": address,
        "peer_address": peer_private_ip,
        "metadata": {
            "provider": "hetzner",
            "exposure": "private",
            "dry_run": dry_run,
            "private_network": True,
            "wire_endpoint_plan": endpoint_plan,
            "manifest_path": endpoint_plan.get("manifest_path"),
            "artifact_dir": endpoint_plan.get("artifact_dir"),
            "private_group": _wire_private_group(endpoint_plan),
            "provider_network_id": interface.get("provider_network_id"),
        },
    }


def _wire_private_interface(endpoint_plan: JSONObject) -> JSONObject:
    interfaces = endpoint_plan.get("interfaces")
    if isinstance(interfaces, Sequence) and not isinstance(
        interfaces,
        (str, bytes, bytearray),
    ):
        for item in interfaces:
            if isinstance(item, Mapping) and item.get("exposure") == "private":
                return json_object(item, "wire.interface")
        for item in interfaces:
            if isinstance(item, Mapping):
                return json_object(item, "wire.interface")
    return {}


def _wire_private_group(endpoint_plan: JSONObject) -> str | None:
    metadata = endpoint_plan.get("metadata")
    if isinstance(metadata, Mapping):
        private_group = metadata.get("private_group")
        if isinstance(private_group, str):
            return private_group
    interface = _wire_private_interface(endpoint_plan)
    interface_metadata = interface.get("metadata")
    if isinstance(interface_metadata, Mapping):
        private_group = interface_metadata.get("private_group")
        if isinstance(private_group, str):
            return private_group
    return None


def _probe_plans_with_wire_endpoint_addresses(
    probe_plans: Sequence[JSONObject],
    *,
    endpoints: Mapping[str, JSONValue],
) -> list[JSONObject]:
    stimulus_ipv4 = _wire_endpoint_address(
        endpoints,
        "stimulus",
        HETZNER_PROBE_STIMULUS_PRIVATE_IPV4,
    )
    target_ipv4 = _wire_endpoint_address(
        endpoints,
        "target",
        HETZNER_PROBE_TARGET_PRIVATE_IPV4,
    )
    return [
        _probe_plan_with_endpoint_addresses(
            plan,
            source_ipv4=stimulus_ipv4,
            target_ipv4=target_ipv4,
        )
        for plan in probe_plans
    ]


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


def _wire_endpoint_address(
    endpoints: Mapping[str, JSONValue],
    role: str,
    fallback: str,
) -> str:
    endpoint = endpoints.get(role)
    if isinstance(endpoint, Mapping):
        address = endpoint.get("address")
        if isinstance(address, str) and address:
            return address
    return fallback


def _hetzner_probe_private_group(request: ProbeRunRequest) -> str:
    return "-".join(
        part
        for part in (
            HETZNER_PROBE_PRIVATE_GROUP_PREFIX,
            _slug(request.profile),
            f"seed-{request.seed}",
        )
        if part
    )


def _hetzner_endpoint_live_report(
    *,
    request: ProbeRunRequest,
    selected_cases: Sequence[ProbeCase],
    planned_cases: Sequence[ProbeCase],
    probe_plans: Sequence[JSONObject],
    report_path: Path,
) -> ProbeReport:
    output_dir = report_path.parent
    endpoint_dir = output_dir / "artifacts" / "hetzner-stimulus-endpoint"
    endpoint_dir.mkdir(parents=True, exist_ok=True)
    provider_commands: list[JSONObject] = []
    execution_errors: list[str] = []
    endpoint_response: JSONObject | None = None
    wire_endpoint_plan: JSONObject = {}
    endpoints: JSONObject = {}
    created_endpoint_ids: list[str] = []
    endpoint_artifact_paths: list[str] = []
    provider_capabilities = _probe_capabilities_for_request(request, dry_run=False)
    skipped_results, skips, skip_counts, skipped_sequences = _capability_skip_state(
        request=request,
        planned_cases=planned_cases,
        probe_plans=probe_plans,
        dry_run=False,
        provider_capabilities=provider_capabilities,
    )
    all_live_plans = list(probe_plans)
    live_plans = [
        plan
        for plan in probe_plans
        if int(plan.get("sequence", -1)) not in skipped_sequences
    ]
    executable_planned_cases = [
        case
        for sequence, case in enumerate(planned_cases)
        if sequence not in skipped_sequences
    ]
    local_request_path = endpoint_dir / "stimulus.request.json"
    target_setup_attempted = False
    rst_guard_attempted = False
    target_endpoint_id = ""
    stimulus_endpoint_id = ""
    remote_dir = _hetzner_wire_remote_dir()
    remote_artifact_root = posixpath.join(
        remote_dir,
        "live-artifacts",
        "probe",
        "endpoint",
    )

    if live_plans:
        try:
            wire_endpoint_plan = _hetzner_probe_wire_endpoint_plan(
                request=request,
                dry_run=False,
                output_dir=output_dir,
                confirm_live_run=True,
                created_endpoint_ids=created_endpoint_ids,
            )
            provider_commands.extend(
                _json_list(
                    wire_endpoint_plan.get("provider_commands", []),
                    "wire.provider_commands",
                )
            )
            failed_provider_commands = [
                command
                for command in provider_commands
                if _wire_command_failed(command)
            ]
            if failed_provider_commands:
                execution_errors.append("Hetzner wire endpoint creation failed")
                raise RuntimeError("Hetzner wire endpoint creation failed")

            endpoints = json_object(wire_endpoint_plan.get("endpoints", {}), "wire.endpoints")
            stimulus_endpoint = _json_mapping(
                endpoints.get("stimulus", {}),
                "wire.endpoints.stimulus",
            )
            target_endpoint = _json_mapping(
                endpoints.get("target", {}),
                "wire.endpoints.target",
            )
            stimulus_endpoint_id = _string_or(
                stimulus_endpoint.get("endpoint_id"),
                "",
            )
            target_endpoint_id = _string_or(target_endpoint.get("endpoint_id"), "")
            if not stimulus_endpoint_id or not target_endpoint_id:
                raise RuntimeError("wire endpoint plan did not include endpoint IDs")

            source_ipv4 = _string_or(
                stimulus_endpoint.get("address"),
                HETZNER_PROBE_STIMULUS_PRIVATE_IPV4,
            )
            target_ipv4 = _string_or(
                target_endpoint.get("address"),
                HETZNER_PROBE_TARGET_PRIVATE_IPV4,
            )
            interface = _string_or(
                stimulus_endpoint.get("interface"),
                _probe_interface("hetzner", dry_run=False),
            )
            all_live_plans = [
                _probe_plan_with_endpoint_addresses(
                    plan,
                    source_ipv4=source_ipv4,
                    target_ipv4=target_ipv4,
                )
                for plan in probe_plans
            ]
            live_plans = [
                plan
                for plan in all_live_plans
                if int(plan.get("sequence", -1)) not in skipped_sequences
            ]

            repo_archive = _create_wire_repo_archive(output_dir)
            endpoint_artifact_paths.append(str(repo_archive))
            for role, endpoint, peer in (
                ("stimulus", stimulus_endpoint, target_endpoint),
                ("target", target_endpoint, stimulus_endpoint),
            ):
                bootstrap_records = _bootstrap_wire_probe_endpoint(
                    endpoint=endpoint,
                    peer=peer,
                    repo_archive=repo_archive,
                    remote_dir=remote_dir,
                    output_dir=endpoint_dir,
                    label=f"04-bootstrap-{role}",
                )
                provider_commands.extend(bootstrap_records)
                if any(_wire_command_failed(record) for record in bootstrap_records):
                    execution_errors.append(f"Hetzner endpoint bootstrap failed: {role}")
                    raise RuntimeError(f"Hetzner endpoint bootstrap failed: {role}")

            remote_request_path = posixpath.join(
                remote_artifact_root,
                "inputs",
                "stimulus.request.json",
            )
            endpoint_request = _stimulus_endpoint_request_object(
                request=request,
                probe_plans=live_plans,
                dry_run=False,
                interface=interface,
                artifact_root=remote_artifact_root,
                request_path=remote_request_path,
            )
            write_json(local_request_path, endpoint_request)

            target_setup = _prepare_wire_probe_target(
                endpoint_id=target_endpoint_id,
                bind_ipv4=target_ipv4,
                remote_dir=remote_dir,
                probe_plans=live_plans,
                output_dir=endpoint_dir,
            )
            if target_setup is not None:
                target_setup_attempted = True
                provider_commands.append(target_setup)
                execution_errors.extend(_string_list(target_setup.get("errors", [])))
                if target_setup["exit_code"] != 0:
                    execution_errors.append("target endpoint setup failed")

            rst_setup = _install_wire_stimulus_rst_guards(
                endpoint_id=stimulus_endpoint_id,
                probe_plans=live_plans,
                output_dir=endpoint_dir,
            )
            if rst_setup is not None:
                rst_guard_attempted = True
                provider_commands.append(rst_setup)
                execution_errors.extend(_string_list(rst_setup.get("errors", [])))
                if rst_setup["exit_code"] != 0:
                    execution_errors.append("stimulus RST guard setup failed")

            if not execution_errors:
                upload = _upload_wire_probe_request(
                    endpoint_id=stimulus_endpoint_id,
                    local_request_path=local_request_path,
                    remote_request_path=remote_request_path,
                    output_dir=endpoint_dir,
                )
                provider_commands.append(upload)
                if upload["exit_code"] != 0:
                    execution_errors.append("failed to upload stimulus endpoint request")
            else:
                upload = None

            if not execution_errors and upload is not None:
                execution = _run_wire_stimulus_endpoint(
                    endpoint_id=stimulus_endpoint_id,
                    remote_dir=remote_dir,
                    remote_request_path=remote_request_path,
                    remote_artifact_root=remote_artifact_root,
                    output_dir=endpoint_dir,
                    timeout_seconds=_probe_process_timeout_seconds(len(live_plans)),
                )
                provider_commands.append(execution)
                endpoint_response = execution.get("response") if isinstance(
                    execution.get("response"), dict
                ) else None
                execution_errors.extend(_string_list(execution.get("errors", [])))
                if execution["exit_code"] != 0:
                    execution_errors.append("stimulus endpoint command failed")

                downloads = _download_wire_probe_artifacts(
                    endpoint_id=stimulus_endpoint_id,
                    artifact_paths=json_object(
                        endpoint_request.get("artifact_paths", {}),
                        "stimulus.artifact_paths",
                    ),
                    output_dir=endpoint_dir,
                    response_path=endpoint_dir / "stimulus.response.json",
                )
                provider_commands.extend(downloads)
                endpoint_artifact_paths.extend(
                    [
                        path
                        for command in downloads
                        for path in _command_artifact_paths(command)
                    ]
                )
                if endpoint_response is None:
                    endpoint_response = _probe_endpoint_response_from_path(
                        endpoint_dir / "stimulus.response.json"
                    )
                if endpoint_response is None:
                    execution_errors.append("stimulus endpoint did not return JSON")
        except Exception as exc:  # pragma: no cover - live-provider only.
            execution_errors.append(str(exc))
        finally:
            if stimulus_endpoint_id and rst_guard_attempted:
                rst_cleanup = _cleanup_wire_stimulus_rst_guards(
                    endpoint_id=stimulus_endpoint_id,
                    probe_plans=live_plans,
                    output_dir=endpoint_dir,
                )
                provider_commands.append(rst_cleanup)
                execution_errors.extend(_string_list(rst_cleanup.get("errors", [])))
                if rst_cleanup["exit_code"] != 0:
                    execution_errors.append("stimulus RST guard cleanup failed")
            if target_endpoint_id and target_setup_attempted:
                target_cleanup = _cleanup_wire_probe_target(
                    endpoint_id=target_endpoint_id,
                    remote_dir=remote_dir,
                    output_dir=endpoint_dir,
                )
                provider_commands.append(target_cleanup)
                execution_errors.extend(_string_list(target_cleanup.get("errors", [])))
                if target_cleanup["exit_code"] != 0:
                    execution_errors.append("target endpoint cleanup failed")
            for role, endpoint_id in (
                ("stimulus", stimulus_endpoint_id),
                ("target", target_endpoint_id),
            ):
                if not endpoint_id:
                    continue
                artifact = _run_wire_command(
                    ["collect-artifacts", endpoint_id, "--remote", remote_artifact_root],
                    output_dir=output_dir,
                    label=f"98-wire-artifacts-{role}",
                    parse_json=False,
                    timeout_seconds=300,
                )
                provider_commands.append(artifact)
            for endpoint_id in reversed(created_endpoint_ids):
                destroy = _run_wire_command(
                    ["destroy-endpoint", endpoint_id, "--json"],
                    output_dir=output_dir,
                    label=f"99-wire-destroy-{endpoint_id}",
                    parse_json=True,
                    timeout_seconds=300,
                )
                provider_commands.append(destroy)

    if not live_plans:
        endpoint_results: list[ProbeResult] = []
        observed_responses = []
    elif endpoint_response is None:
        endpoint_results, observed_responses = _failed_live_probe_results(
            planned_cases=executable_planned_cases,
            probe_plans=live_plans,
            reason=FAILURE_DECODE_FAILED,
            errors=execution_errors,
        )
    else:
        endpoint_results, observed_responses = _probe_results_from_endpoint_response(
            endpoint_response
        )

    results = sorted(
        [*skipped_results, *endpoint_results],
        key=lambda result: result.sequence,
    )
    failures = [result for result in results if result.passed is False]
    status = STATUS_PASSED if results and not failures and not execution_errors else STATUS_FAILED
    failed_counts = _failed_counts_by_reason(results)
    executed_count = sum(1 for result in results if result.status != "skipped")
    artifact_paths = [str(report_path)]
    if local_request_path.exists():
        artifact_paths.append(str(local_request_path))
    artifact_paths.extend(endpoint_artifact_paths)
    artifact_paths.extend(
        [
            path
            for command in provider_commands
            for path in _command_artifact_paths(command)
        ]
    )
    if endpoint_response is not None:
        artifact_paths.extend(_string_list(endpoint_response.get("artifacts", [])))
        artifact_paths.extend(_string_list(endpoint_response.get("artifact_paths", [])))
    artifact_paths = _dedupe_paths(artifact_paths)

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
        metadata={
            "provider": request.provider,
            "cases": [case.name for case in selected_cases],
            "requested_count": request.count,
            "planned_count": len(planned_cases),
            "selected_count": len(selected_cases),
            "executed_count": sum(1 for result in results if result.status != "skipped"),
            "passed_count": sum(1 for result in results if result.passed is True),
            "failed_count": len(failures),
            "executed_cases": _dedupe_strings(
                [result.case for result in results if result.status != "skipped"]
            ),
            "failed_counts_by_reason": failed_counts,
            "skipped_count": len(skips),
            "observed_count": sum(
                1 for response in observed_responses if response.observed
            ),
            "provider_capabilities": dict(provider_capabilities),
            "skip_reasons": list(skip_counts),
            "skip_counts_by_reason": skip_counts,
            "selected_case_names": [case.name for case in selected_cases],
            "planned_case_names": [case.name for case in planned_cases],
            "probe_plans": all_live_plans,
            "selected_specs": list(PROBE_SELECTED_SPECS),
            "dry_run": False,
            "creates_infrastructure": bool(created_endpoint_ids),
            "requires_provider_lifecycle": True,
            "mutates_lab": True,
            "live_packet_exchange": status == STATUS_PASSED and executed_count > 0,
            "provider_workflow": _hetzner_probe_provider_workflow(
                request=request,
                dry_run=False,
            ),
            "wire_endpoint_plan": wire_endpoint_plan,
            "endpoints": endpoints,
            "wire_endpoint_lifecycle": {
                "remote_dir": remote_dir,
                "remote_artifact_root": remote_artifact_root,
                "created_endpoint_ids": list(created_endpoint_ids),
                "destroy_attempted": bool(created_endpoint_ids),
            },
            "provider_commands": provider_commands,
            "execution_errors": execution_errors,
            "target_service_setup": _target_service_setup_plan(
                probe_plans=live_plans,
                dry_run=False,
            ),
        },
    )


def _stimulus_endpoint_request_object(
    *,
    request: ProbeRunRequest,
    probe_plans: Sequence[JSONObject],
    dry_run: bool,
    interface: str,
    artifact_root: str,
    request_path: str,
) -> JSONObject:
    first_plan = probe_plans[0] if probe_plans else {}
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
            "failure_reasons_by_case": {
                str(plan.get("case", "")): _failure_reasons_for_case(
                    str(plan.get("case", ""))
                )
                for plan in probe_plans
            },
        },
    }


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
    elif case_name == "dns-query":
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


def _hetzner_wire_remote_dir() -> str:
    remote_dir = os.environ.get("LIBCRAFTER_WIRE_REMOTE_DIR") or "/root/libcrafter"
    if not remote_dir.startswith("/"):
        raise RuntimeError("Hetzner wire remote_dir must be an absolute path")
    if "'" in remote_dir:
        raise RuntimeError("Hetzner wire remote_dir must not contain single quotes")
    return remote_dir.rstrip("/") or "/"


def _create_wire_repo_archive(output_dir: Path) -> Path:
    artifact_dir = output_dir / "artifacts" / "wire"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    archive_path = artifact_dir / "libcrafter-repo.tar.gz"
    command = _run_command(
        [
            "tar",
            "-C",
            str(REPO_ROOT),
            "--exclude=.git",
            "--exclude=target",
            "--exclude=tools/wire/.state",
            "--exclude=tools/wire/artifacts",
            "-czf",
            str(archive_path),
            ".",
        ],
        output_dir=artifact_dir,
        label="repo-archive",
    )
    if command["exit_code"] != 0:
        raise RuntimeError("failed to create wire repo archive")
    return archive_path


def _bootstrap_wire_probe_endpoint(
    *,
    endpoint: Mapping[str, JSONValue],
    peer: Mapping[str, JSONValue],
    repo_archive: Path,
    remote_dir: str,
    output_dir: Path,
    label: str,
) -> list[JSONObject]:
    endpoint_id = _string_or(endpoint.get("endpoint_id"), "")
    if not endpoint_id:
        raise RuntimeError("wire endpoint is missing endpoint_id")
    remote_parent = posixpath.dirname(remote_dir.rstrip("/")) or "/"
    remote_archive = posixpath.join(remote_parent, "libcrafter-repo.tar.gz")
    upload = _run_wire_command(
        ["upload", endpoint_id, str(repo_archive.resolve()), remote_archive],
        output_dir=output_dir,
        label=f"{label}-upload-repo",
        timeout_seconds=900,
    )
    if upload["exit_code"] != 0:
        return [upload]

    bootstrap = _run_wire_command(
        [
            "exec",
            endpoint_id,
            "--",
            "bash",
            "-lc",
            _wire_probe_bootstrap_script(
                endpoint=endpoint,
                peer=peer,
                remote_archive=remote_archive,
                remote_dir=remote_dir,
            ),
        ],
        output_dir=output_dir,
        label=f"{label}-exec",
        timeout_seconds=1800,
    )
    return [upload, bootstrap]


def _wire_probe_bootstrap_script(
    *,
    endpoint: Mapping[str, JSONValue],
    peer: Mapping[str, JSONValue],
    remote_archive: str,
    remote_dir: str,
) -> str:
    role = shlex.quote(_string_or(endpoint.get("role"), "probe"))
    private_ipv4 = shlex.quote(_string_or(endpoint.get("address"), ""))
    peer_private_ipv4 = shlex.quote(_string_or(peer.get("address"), ""))
    private_interface = shlex.quote(_string_or(endpoint.get("interface"), "private"))
    quoted_archive = shlex.quote(remote_archive)
    quoted_remote_dir = shlex.quote(remote_dir)
    common = "\n".join(
        [
            "set -euo pipefail",
            "if command -v cloud-init >/dev/null 2>&1; then "
            "cloud-init status --wait >/dev/null 2>&1 || true; fi",
            f"rm -rf {quoted_remote_dir}",
            f"mkdir -p {quoted_remote_dir}",
            f"tar -xzf {quoted_archive} -C {quoted_remote_dir}",
            f"cd {quoted_remote_dir}",
            f"export LIBCRAFTER_ENDPOINT_ROLE={role}",
            f"export LIBCRAFTER_PRIVATE_IPV4={private_ipv4}",
            f"export LIBCRAFTER_PEER_PRIVATE_IPV4={peer_private_ipv4}",
            f"export LIBCRAFTER_PRIVATE_INTERFACE={private_interface}",
            "export DEBIAN_FRONTEND=noninteractive",
            "mkdir -p \"live-artifacts/probe/bootstrap/$LIBCRAFTER_ENDPOINT_ROLE\"",
            "apt-get update",
        ]
    )
    if _string_or(endpoint.get("role"), "") == "stimulus":
        return "\n".join(
            [
                common,
                (
                    "apt-get install -y --no-install-recommends "
                    "build-essential ca-certificates clang curl git iproute2 "
                    "iptables iputils-ping libpcap-dev pkg-config python3"
                ),
                "if ! command -v cargo >/dev/null 2>&1; then "
                "curl -fsS https://sh.rustup.rs | sh -s -- -y; fi",
                "if [ -f \"$HOME/.cargo/env\" ]; then . \"$HOME/.cargo/env\"; fi",
                "cargo build -p probe-adapters --bin stimulus_endpoint",
                "{",
                "  echo \"role=$LIBCRAFTER_ENDPOINT_ROLE\"",
                "  echo \"private_ipv4=$LIBCRAFTER_PRIVATE_IPV4\"",
                "  echo \"peer_private_ipv4=$LIBCRAFTER_PEER_PRIVATE_IPV4\"",
                "  echo \"private_interface=$LIBCRAFTER_PRIVATE_INTERFACE\"",
                "  echo \"repository_synced=true\"",
                "  echo \"libcrafter_probe_bin=stimulus_endpoint\"",
                "  echo \"libcrafter_probe_bin_build=ok\"",
                "  echo \"finished_at=$(date -u +\"%Y-%m-%dT%H:%M:%SZ\")\"",
                "} > \"live-artifacts/probe/bootstrap/$LIBCRAFTER_ENDPOINT_ROLE/bootstrap.env\"",
            ]
        )

    return "\n".join(
        [
            common,
            (
                "apt-get install -y --no-install-recommends "
                "ca-certificates curl git iproute2 iputils-ping python3"
            ),
            "{",
            "  echo \"role=$LIBCRAFTER_ENDPOINT_ROLE\"",
            "  echo \"private_ipv4=$LIBCRAFTER_PRIVATE_IPV4\"",
            "  echo \"peer_private_ipv4=$LIBCRAFTER_PEER_PRIVATE_IPV4\"",
            "  echo \"private_interface=$LIBCRAFTER_PRIVATE_INTERFACE\"",
            "  echo \"repository_synced=true\"",
            "  echo \"target_service_runtime=python3\"",
            "  echo \"finished_at=$(date -u +\"%Y-%m-%dT%H:%M:%SZ\")\"",
            "} > \"live-artifacts/probe/bootstrap/$LIBCRAFTER_ENDPOINT_ROLE/bootstrap.env\"",
        ]
    )


def _upload_wire_probe_request(
    *,
    endpoint_id: str,
    local_request_path: Path,
    remote_request_path: str,
    output_dir: Path,
) -> JSONObject:
    remote_parent = posixpath.dirname(remote_request_path)
    mkdir = _run_wire_command(
        [
            "exec",
            endpoint_id,
            "--",
            "bash",
            "-lc",
            f"mkdir -p {shlex.quote(remote_parent)}",
        ],
        output_dir=output_dir,
        label="upload-stimulus-request-mkdir",
        timeout_seconds=60,
    )
    upload = (
        _run_wire_command(
            ["upload", endpoint_id, str(local_request_path.resolve()), remote_request_path],
            output_dir=output_dir,
            label="upload-stimulus-request",
            timeout_seconds=120,
        )
        if mkdir["exit_code"] == 0
        else None
    )
    commands = [mkdir] + ([] if upload is None else [upload])
    exit_code = next(
        (
            int(command.get("exit_code", 1))
            for command in commands
            if command.get("exit_code") != 0
        ),
        0,
    )
    return {
        "wire_command": True,
        "operation": "upload",
        "endpoint_id": endpoint_id,
        "label": "upload-stimulus-request",
        "exit_code": exit_code,
        "request_path": str(local_request_path),
        "remote_request_path": remote_request_path,
        "commands": commands,
        "errors": [
            error
            for command in commands
            for error in _string_list(command.get("errors", []))
        ],
    }


def _run_wire_stimulus_endpoint(
    *,
    endpoint_id: str,
    remote_dir: str,
    remote_request_path: str,
    remote_artifact_root: str,
    output_dir: Path,
    timeout_seconds: int,
) -> JSONObject:
    quoted_remote_dir = shlex.quote(remote_dir)
    quoted_request = shlex.quote(remote_request_path)
    quoted_out = shlex.quote(remote_artifact_root)
    script = "\n".join(
        [
            "set -euo pipefail",
            f"cd {quoted_remote_dir}",
            'if [ -f "$HOME/.cargo/env" ]; then . "$HOME/.cargo/env"; fi',
            (
                "cargo run -q -p probe-adapters --bin stimulus_endpoint -- "
                f"--live --input {quoted_request} --out {quoted_out}"
            ),
        ]
    )
    return _run_wire_command(
        ["exec", endpoint_id, "--", "bash", "-lc", script],
        output_dir=output_dir,
        label="stimulus-endpoint",
        timeout_seconds=timeout_seconds,
        parse_json=True,
    )


def _prepare_wire_probe_target(
    *,
    endpoint_id: str,
    bind_ipv4: str,
    remote_dir: str,
    probe_plans: Sequence[JSONObject],
    output_dir: Path,
) -> JSONObject | None:
    tcp_plans = _tcp_probe_plans(probe_plans)
    dns_plans = _dns_probe_plans(probe_plans)
    if not tcp_plans and not dns_plans:
        return None
    remote_artifact_root = posixpath.join(
        remote_dir,
        "live-artifacts",
        "probe",
        "target-services",
    )
    open_ports = _dedupe_ints(
        int(plan["destination_port"])
        for plan in tcp_plans
        if plan.get("case") == "tcp-syn-open"
    )
    closed_ports = _dedupe_ints(
        int(plan["destination_port"])
        for plan in tcp_plans
        if plan.get("case") == "tcp-syn-closed"
    )
    script = _target_service_setup_script(
        artifact_root=remote_artifact_root,
        bind_ipv4=bind_ipv4,
        open_ports=open_ports,
        closed_ports=closed_ports,
        dns_plans=dns_plans,
    )
    return _run_wire_command(
        ["exec", endpoint_id, "--", "bash", "-lc", script],
        output_dir=output_dir,
        label="probe-target-setup",
        timeout_seconds=60,
    )


def _cleanup_wire_probe_target(
    *,
    endpoint_id: str,
    remote_dir: str,
    output_dir: Path,
) -> JSONObject:
    remote_artifact_root = posixpath.join(
        remote_dir,
        "live-artifacts",
        "probe",
        "target-services",
    )
    cleanup_script = posixpath.join(remote_artifact_root, "cleanup.sh")
    script = "\n".join(
        [
            "set -euo pipefail",
            f"if [ -x {shlex.quote(cleanup_script)} ]; then {shlex.quote(cleanup_script)}; fi",
        ]
    )
    return _run_wire_command(
        ["exec", endpoint_id, "--", "bash", "-lc", script],
        output_dir=output_dir,
        label="probe-target-cleanup",
        timeout_seconds=60,
    )


def _install_wire_stimulus_rst_guards(
    *,
    endpoint_id: str,
    probe_plans: Sequence[JSONObject],
    output_dir: Path,
) -> JSONObject | None:
    tcp_plans = _tcp_probe_plans(probe_plans)
    if not tcp_plans:
        return None
    return _run_wire_command(
        ["exec", endpoint_id, "--", "bash", "-lc", _rst_guard_script(tcp_plans, install=True)],
        output_dir=output_dir,
        label="probe-stimulus-rst-guard-setup",
        timeout_seconds=60,
    )


def _cleanup_wire_stimulus_rst_guards(
    *,
    endpoint_id: str,
    probe_plans: Sequence[JSONObject],
    output_dir: Path,
) -> JSONObject:
    return _run_wire_command(
        [
            "exec",
            endpoint_id,
            "--",
            "bash",
            "-lc",
            _rst_guard_script(_tcp_probe_plans(probe_plans), install=False),
        ],
        output_dir=output_dir,
        label="probe-stimulus-rst-guard-cleanup",
        timeout_seconds=60,
    )


def _download_wire_probe_artifacts(
    *,
    endpoint_id: str,
    artifact_paths: Mapping[str, JSONValue],
    output_dir: Path,
    response_path: Path,
) -> list[JSONObject]:
    local_root = output_dir / "downloads" / "stimulus"
    downloads: list[JSONObject] = []
    local_by_key = {
        "response": response_path,
        "captures": local_root / "captures",
    }
    for key, local_path in local_by_key.items():
        remote_path = artifact_paths.get(key)
        if not isinstance(remote_path, str) or not remote_path.startswith("/"):
            continue
        record = _run_wire_command(
            ["download", endpoint_id, remote_path, str(local_path.resolve())],
            output_dir=output_dir,
            label=f"download-stimulus-{key}",
            timeout_seconds=300,
        )
        record.update(
            {
                "endpoint_id": endpoint_id,
                "endpoint_role": "stimulus",
                "artifact_key": key,
                "remote_path": remote_path,
                "local_path": str(local_path),
            }
        )
        downloads.append(record)
    return downloads


def _probe_endpoint_response_from_path(path: Path) -> JSONObject | None:
    if not path.exists():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    if not isinstance(value, Mapping):
        return None
    return json_object(value, "stimulus.response")


def _target_service_setup_script(
    *,
    artifact_root: str,
    bind_ipv4: str,
    open_ports: Sequence[int],
    closed_ports: Sequence[int],
    dns_plans: Sequence[JSONObject],
) -> str:
    dns_plan_json = json.dumps(list(dns_plans), sort_keys=True)
    dns_ports = _dedupe_ints(
        int(plan["destination_port"])
        for plan in dns_plans
        if isinstance(plan.get("destination_port"), int)
    )
    lines = [
        "set -euo pipefail",
        f"artifact_root={shlex.quote(artifact_root)}",
        f"dns_bind_ipv4={shlex.quote(bind_ipv4)}",
        'mkdir -p "$artifact_root"',
        'cleanup="$artifact_root/cleanup.sh"',
        ': > "$cleanup"',
        'chmod 700 "$cleanup"',
        "check_port_free() {",
        "  python3 - \"$1\" <<'PY'",
        "import socket",
        "import sys",
        "port = int(sys.argv[1])",
        "sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)",
        "try:",
        "    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)",
        "    sock.bind(('0.0.0.0', port))",
        "except OSError as exc:",
        "    print(f'port {port} is not free: {exc}', file=sys.stderr)",
        "    sys.exit(1)",
        "finally:",
        "    sock.close()",
        "PY",
        "}",
    ]
    for port in dns_ports:
        lines.extend(
            [
                "python3 - \"$dns_bind_ipv4\" \"$1\" <<'PY'".replace("$1", str(port)),
                "import socket",
                "import sys",
                "bind_ip = sys.argv[1]",
                "port = int(sys.argv[2])",
                "sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)",
                "try:",
                "    sock.bind((bind_ip, port))",
                "except OSError as exc:",
                "    print(f'udp port {bind_ip}:{port} is not free: {exc}', file=sys.stderr)",
                "    sys.exit(1)",
                "finally:",
                "    sock.close()",
                "PY",
            ]
        )
    for port in closed_ports:
        lines.append(f"check_port_free {port}")
        lines.append(f"echo closed_port_{port}=free")
    for port in open_ports:
        listener_path = posixpath.join(artifact_root, f"tcp-listener-{port}.py")
        stdout_path = posixpath.join(artifact_root, f"tcp-listener-{port}.stdout.txt")
        stderr_path = posixpath.join(artifact_root, f"tcp-listener-{port}.stderr.txt")
        pid_path = posixpath.join(artifact_root, f"tcp-listener-{port}.pid")
        lines.extend(
            [
                f"check_port_free {port}",
                f"cat > {shlex.quote(listener_path)} <<'PY'",
                "import signal",
                "import socket",
                "import sys",
                "",
                "stop = False",
                "",
                "def handle_stop(_signum, _frame):",
                "    global stop",
                "    stop = True",
                "",
                "signal.signal(signal.SIGTERM, handle_stop)",
                "signal.signal(signal.SIGINT, handle_stop)",
                "port = int(sys.argv[1])",
                "sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)",
                "sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)",
                "sock.bind(('0.0.0.0', port))",
                "sock.listen(128)",
                "sock.settimeout(1.0)",
                "print(f'listening on {port}', flush=True)",
                "while not stop:",
                "    try:",
                "        conn, _addr = sock.accept()",
                "    except socket.timeout:",
                "        continue",
                "    conn.close()",
                "sock.close()",
                "PY",
                (
                    f"python3 {shlex.quote(listener_path)} {port} "
                    f">{shlex.quote(stdout_path)} 2>{shlex.quote(stderr_path)} &"
                ),
                "pid=$!",
                f"echo \"$pid\" > {shlex.quote(pid_path)}",
                "printf '%s\\n' \"kill $pid 2>/dev/null || true\" >> \"$cleanup\"",
                f"printf '%s\\n' \"rm -f {shlex.quote(pid_path)}\" >> \"$cleanup\"",
                "sleep 0.5",
                "if ! kill -0 \"$pid\" 2>/dev/null; then",
                f"  cat {shlex.quote(stderr_path)} >&2 || true",
                f"  echo listener_{port}=failed >&2",
                "  exit 73",
                "fi",
                f"echo listener_{port}=running",
            ]
        )
    if dns_ports:
        zone_path = posixpath.join(artifact_root, "dns-zone.json")
        service_path = posixpath.join(artifact_root, "dns-responder.py")
        lines.extend(
            [
                f"cat > {shlex.quote(zone_path)} <<'JSON'",
                dns_plan_json,
                "JSON",
                f"cat > {shlex.quote(service_path)} <<'PY'",
                "import ipaddress",
                "import json",
                "import signal",
                "import socket",
                "import struct",
                "import sys",
                "import time",
                "",
                "stop = False",
                "",
                "def handle_stop(_signum, _frame):",
                "    global stop",
                "    stop = True",
                "",
                "signal.signal(signal.SIGTERM, handle_stop)",
                "signal.signal(signal.SIGINT, handle_stop)",
                "",
                "zone_path, bind_ip, port_text = sys.argv[1:4]",
                "port = int(port_text)",
                "plans = json.load(open(zone_path, encoding='utf-8'))",
                "records = {}",
                "for plan in plans:",
                "    name = str(plan['query_name']).lower().rstrip('.') + '.'",
                "    qtype = int(plan['query_type_value'])",
                "    records[(name, qtype)] = {",
                "        'answer_data': str(plan['expected_answer_data']),",
                "        'ttl': int(plan.get('answer_ttl', 60)),",
                "    }",
                "",
                "def read_name(message, offset):",
                "    labels = []",
                "    jumped = False",
                "    consumed = 0",
                "    seen = set()",
                "    while True:",
                "        if offset >= len(message):",
                "            raise ValueError('name offset out of range')",
                "        length = message[offset]",
                "        if length & 0xc0 == 0xc0:",
                "            if offset + 1 >= len(message):",
                "                raise ValueError('truncated compression pointer')",
                "            pointer = ((length & 0x3f) << 8) | message[offset + 1]",
                "            if pointer in seen:",
                "                raise ValueError('compression pointer loop')",
                "            seen.add(pointer)",
                "            if not jumped:",
                "                consumed += 2",
                "            offset = pointer",
                "            jumped = True",
                "            continue",
                "        offset += 1",
                "        if not jumped:",
                "            consumed += 1",
                "        if length == 0:",
                "            return '.'.join(labels).lower() + '.', consumed",
                "        if length & 0xc0:",
                "            raise ValueError('unsupported dns label kind')",
                "        label = message[offset:offset + length]",
                "        if len(label) != length:",
                "            raise ValueError('truncated dns label')",
                "        labels.append(label.decode('ascii'))",
                "        offset += length",
                "        if not jumped:",
                "            consumed += length",
                "",
                "def encode_name(name):",
                "    out = bytearray()",
                "    for label in name.rstrip('.').split('.'):",
                "        raw = label.encode('ascii')",
                "        out.append(len(raw))",
                "        out.extend(raw)",
                "    out.append(0)",
                "    return bytes(out)",
                "",
                "def response_for(query):",
                "    if len(query) < 12:",
                "        raise ValueError('query shorter than dns header')",
                "    txid, flags, qdcount, _ancount, _nscount, _arcount = struct.unpack('!HHHHHH', query[:12])",
                "    if qdcount < 1:",
                "        raise ValueError('query has no question')",
                "    name, consumed = read_name(query, 12)",
                "    question_end = 12 + consumed + 4",
                "    if question_end > len(query):",
                "        raise ValueError('truncated dns question')",
                "    qtype, qclass = struct.unpack('!HH', query[12 + consumed:question_end])",
                "    question = query[12:question_end]",
                "    record = records.get((name, qtype))",
                "    rd = flags & 0x0100",
                "    if record is None or qclass != 1:",
                "        header = struct.pack('!HHHHHH', txid, 0x8000 | rd | 3, 1, 0, 0, 0)",
                "        return header + question, {'name': name, 'qtype': qtype, 'rcode': 3}",
                "    if qtype == 1:",
                "        rdata = ipaddress.IPv4Address(record['answer_data']).packed",
                "    elif qtype == 28:",
                "        rdata = ipaddress.IPv6Address(record['answer_data']).packed",
                "    else:",
                "        raise ValueError(f'unsupported qtype {qtype}')",
                "    answer = b'\\xc0\\x0c' + struct.pack('!HHIH', qtype, 1, record['ttl'], len(rdata)) + rdata",
                "    header = struct.pack('!HHHHHH', txid, 0x8000 | rd | 0x0400 | 0x0080, 1, 1, 0, 0)",
                "    return header + question + answer, {'name': name, 'qtype': qtype, 'rcode': 0}",
                "",
                "sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)",
                "sock.bind((bind_ip, port))",
                "sock.settimeout(1.0)",
                "print(json.dumps({'event': 'listening', 'bind_ip': bind_ip, 'port': port}), flush=True)",
                "while not stop:",
                "    try:",
                "        data, addr = sock.recvfrom(4096)",
                "    except socket.timeout:",
                "        continue",
                "    try:",
                "        response, meta = response_for(data)",
                "        sock.sendto(response, addr)",
                "        meta.update({'event': 'answered', 'client': addr[0], 'client_port': addr[1]})",
                "        print(json.dumps(meta, sort_keys=True), flush=True)",
                "    except Exception as exc:",
                "        print(json.dumps({'event': 'error', 'error': str(exc)}), file=sys.stderr, flush=True)",
                "sock.close()",
                "print(json.dumps({'event': 'stopped', 'ts': time.time()}), flush=True)",
                "PY",
            ]
        )
    for port in dns_ports:
        stdout_path = posixpath.join(artifact_root, f"dns-responder-{port}.stdout.txt")
        stderr_path = posixpath.join(artifact_root, f"dns-responder-{port}.stderr.txt")
        pid_path = posixpath.join(artifact_root, f"dns-responder-{port}.pid")
        lines.extend(
            [
                (
                    f"python3 {shlex.quote(posixpath.join(artifact_root, 'dns-responder.py'))} "
                    f"{shlex.quote(posixpath.join(artifact_root, 'dns-zone.json'))} "
                    f"\"$dns_bind_ipv4\" {port} "
                    f">{shlex.quote(stdout_path)} 2>{shlex.quote(stderr_path)} &"
                ),
                "pid=$!",
                f"echo \"$pid\" > {shlex.quote(pid_path)}",
                "printf '%s\\n' \"kill $pid 2>/dev/null || true\" >> \"$cleanup\"",
                f"printf '%s\\n' \"rm -f {shlex.quote(pid_path)}\" >> \"$cleanup\"",
                "sleep 0.5",
                "if ! kill -0 \"$pid\" 2>/dev/null; then",
                f"  cat {shlex.quote(stderr_path)} >&2 || true",
                f"  echo dns_responder_{port}=failed >&2",
                "  exit 73",
                "fi",
                f"echo dns_responder_{port}=running",
            ]
        )
    lines.append("echo target_service_setup=ok")
    return "\n".join(lines)


def _rst_guard_script(probe_plans: Sequence[JSONObject], *, install: bool) -> str:
    lines = [
        "set -euo pipefail",
        "if ! command -v iptables >/dev/null 2>&1; then",
        "  echo 'iptables is required for TCP raw SYN probes' >&2",
        "  exit 69",
        "fi",
    ]
    for argv in _rst_guard_iptables_args(probe_plans):
        quoted_args = " ".join(shlex.quote(arg) for arg in argv)
        check = f"iptables -C OUTPUT {quoted_args}"
        if install:
            lines.extend(
                [
                    f"if ! {check} >/dev/null 2>&1; then",
                    f"  iptables -I OUTPUT 1 {quoted_args}",
                    "fi",
                ]
            )
        else:
            lines.extend(
                [
                    f"while {check} >/dev/null 2>&1; do",
                    f"  iptables -D OUTPUT {quoted_args}",
                    "done",
                ]
            )
    lines.append(
        "echo stimulus_rst_guard={}".format("installed" if install else "removed")
    )
    return "\n".join(lines)


def _rst_guard_iptables_args(probe_plans: Sequence[JSONObject]) -> list[list[str]]:
    rules: list[list[str]] = []
    for plan in probe_plans:
        guard = json_object(plan.get("stimulus_rst_guard", {}), "stimulus_rst_guard")
        if guard.get("required") is not True:
            continue
        rules.append(
            [
                "-p",
                "tcp",
                "-s",
                str(guard.get("source_ipv4", plan.get("source_ipv4", ""))),
                "-d",
                str(guard.get("destination_ipv4", plan.get("destination_ipv4", ""))),
                "--sport",
                str(guard.get("source_port", plan.get("source_port", ""))),
                "--dport",
                str(guard.get("destination_port", plan.get("destination_port", ""))),
                "--tcp-flags",
                "RST",
                "RST",
                "-j",
                "DROP",
            ]
        )
    return rules


def _tcp_probe_plans(probe_plans: Sequence[JSONObject]) -> list[JSONObject]:
    return [
        plan
        for plan in probe_plans
        if str(plan.get("case", "")).startswith("tcp-syn-")
    ]


def _dns_probe_plans(probe_plans: Sequence[JSONObject]) -> list[JSONObject]:
    return [plan for plan in probe_plans if plan.get("case") == "dns-query"]


def _dedupe_ints(values: Sequence[int]) -> list[int]:
    return list(dict.fromkeys(values))


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


def _parse_json_stdout(stdout: str, label: str) -> tuple[JSONObject | None, list[str]]:
    if not stdout.strip():
        return None, [f"{label}: endpoint produced no JSON response"]
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError:
        start = stdout.find("{")
        end = stdout.rfind("}")
        if start < 0 or end <= start:
            return None, [f"{label}: endpoint stdout was not JSON"]
        try:
            value = json.loads(stdout[start : end + 1])
        except json.JSONDecodeError as exc:
            return None, [f"{label}: endpoint stdout JSON parse failed: {exc}"]
    if not isinstance(value, Mapping):
        return None, [f"{label}: endpoint response must be a JSON object"]
    return json_object(value, f"{label}.response"), []


def _probe_results_from_endpoint_response(
    response: JSONObject,
) -> tuple[list[ProbeResult], list[ObservedResponse]]:
    results: list[ProbeResult] = []
    observed_responses: list[ObservedResponse] = []
    raw_results = response.get("results", [])
    if not isinstance(raw_results, Sequence) or isinstance(
        raw_results, (str, bytes, bytearray)
    ):
        raw_results = []

    for raw_result in raw_results:
        if not isinstance(raw_result, Mapping):
            continue
        result_obj = json_object(raw_result, "endpoint.results[]")
        observed = None
        raw_observed = result_obj.get("observed_response")
        if isinstance(raw_observed, Mapping):
            observed_obj = json_object(raw_observed, "endpoint.observed_response")
            observed = ObservedResponse(
                case=str(observed_obj.get("case", result_obj.get("case", ""))),
                sequence=int(observed_obj.get("sequence", result_obj.get("sequence", 0))),
                endpoint_role=str(observed_obj.get("endpoint_role", "stimulus")),
                observed=bool(observed_obj.get("observed")),
                response_type=_optional_string(observed_obj.get("response_type")),
                raw_hex=_optional_string(observed_obj.get("raw_hex")),
                decoded=json_object(observed_obj.get("decoded", {}), "observed.decoded"),
                metadata=json_object(observed_obj.get("metadata", {}), "observed.metadata"),
            )
            observed_responses.append(observed)
        results.append(
            ProbeResult(
                case=str(result_obj.get("case", "")),
                sequence=int(result_obj.get("sequence", 0)),
                status=str(result_obj.get("status", STATUS_FAILED)),
                endpoint_role=str(result_obj.get("endpoint_role", "stimulus")),
                passed=(
                    bool(result_obj["passed"])
                    if isinstance(result_obj.get("passed"), bool)
                    else None
                ),
                observed_response=observed,
                metadata=json_object(result_obj.get("metadata", {}), "result.metadata"),
            )
        )
    return results, observed_responses


def _failed_live_probe_results(
    *,
    planned_cases: Sequence[ProbeCase],
    probe_plans: Sequence[JSONObject],
    reason: str,
    errors: Sequence[str],
) -> tuple[list[ProbeResult], list[ObservedResponse]]:
    results: list[ProbeResult] = []
    for index, case in enumerate(planned_cases):
        plan = probe_plans[index] if index < len(probe_plans) else {}
        sequence = (
            int(plan["sequence"])
            if isinstance(plan.get("sequence"), int)
            else index
        )
        results.append(
            ProbeResult(
                case=case.name,
                sequence=sequence,
                status=STATUS_FAILED,
                endpoint_role=_primary_endpoint_role(case),
                passed=False,
                metadata={
                    "failure_reason": reason,
                    "errors": list(errors),
                    "probe_plan": plan,
                },
            )
        )
    return results, []


def _failed_counts_by_reason(results: Sequence[ProbeResult]) -> JSONObject:
    counts: dict[str, int] = {}
    for result in results:
        if result.passed is not False:
            continue
        reason = result.metadata.get("failure_reason")
        if isinstance(reason, str) and reason:
            counts[reason] = counts.get(reason, 0) + 1
    return counts


def _command_artifact_paths(command: Mapping[str, JSONValue]) -> list[str]:
    paths: list[str] = []
    for key in ("stdout_path", "stderr_path", "request_path"):
        value = command.get(key)
        if isinstance(value, str) and value:
            paths.append(value)
    return paths


def _probe_process_timeout_seconds(plan_count: int) -> int:
    return (_probe_timeout_seconds(plan_count) * max(plan_count, 1)) + 60


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _string_or(value: object, default: str) -> str:
    return value if isinstance(value, str) and value else default


def _string_list(value: object) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return []
    return [str(item) for item in value if isinstance(item, str)]


def _json_mapping(value: object, name: str) -> JSONObject:
    if isinstance(value, Mapping):
        return json_object(value, name)
    return {}


def _json_list(value: object, name: str) -> list[JSONObject]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return []
    return [
        json_object(item, f"{name}[]")
        for item in value
        if isinstance(item, Mapping)
    ]


def _dedupe_paths(paths: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(path for path in paths if path))


def _dedupe_strings(values: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def _probe_interface(provider: str, *, dry_run: bool) -> str:
    if provider == LOCAL_DRY_RUN_PROVIDER:
        return "dry-run0"
    if dry_run:
        return os.environ.get("HETZNER_PRIVATE_INTERFACE", "eth1")
    return os.environ.get("HETZNER_PRIVATE_INTERFACE", "auto")


def _probe_timeout_seconds(plan_count: int) -> int:
    return 3


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
    if case_name == "dns-query":
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
    return []


def _capability_skip_result(
    *,
    request: ProbeRunRequest,
    case: ProbeCase,
    sequence: int,
    probe_plan: JSONObject,
    dry_run: bool,
    provider_capabilities: Mapping[str, JSONValue],
) -> tuple[ProbeSkip, ProbeResult] | None:
    missing = _missing_capabilities(case, provider_capabilities)
    if not missing:
        return None

    skip = ProbeSkip(
        case=case.name,
        sequence=sequence,
        reason=_skip_reason_for_missing_capability(case, missing[0]),
        capability=missing[0],
        metadata={
            "missing_capabilities": list(missing),
            "provider": request.provider,
            "dry_run": dry_run,
            "probe_plan": probe_plan,
        },
    )
    result = ProbeResult(
        case=case.name,
        sequence=sequence,
        status="skipped",
        endpoint_role=_primary_endpoint_role(case),
        passed=None,
        skip=skip,
        metadata={"dry_run": dry_run, "probe_plan": probe_plan},
    )
    return skip, result


def _capability_skip_state(
    *,
    request: ProbeRunRequest,
    planned_cases: Sequence[ProbeCase],
    probe_plans: Sequence[JSONObject],
    dry_run: bool,
    provider_capabilities: Mapping[str, JSONValue],
) -> tuple[list[ProbeResult], list[ProbeSkip], dict[str, int], set[int]]:
    probe_plans_by_sequence = {
        int(plan["sequence"]): plan
        for plan in probe_plans
        if isinstance(plan.get("sequence"), int)
    }
    results: list[ProbeResult] = []
    skips: list[ProbeSkip] = []
    skip_counts: dict[str, int] = {}
    skipped_sequences: set[int] = set()
    for sequence, case in enumerate(planned_cases):
        capability_skip = _capability_skip_result(
            request=request,
            case=case,
            sequence=sequence,
            probe_plan=probe_plans_by_sequence.get(sequence, {}),
            dry_run=dry_run,
            provider_capabilities=provider_capabilities,
        )
        if capability_skip is None:
            continue
        skip, result = capability_skip
        skips.append(skip)
        results.append(result)
        skipped_sequences.add(sequence)
        skip_counts[skip.reason] = skip_counts.get(skip.reason, 0) + 1
    return results, skips, skip_counts, skipped_sequences


def _missing_capabilities(
    case: ProbeCase,
    provider_capabilities: Mapping[str, JSONValue],
) -> list[str]:
    missing: list[str] = []
    for capability in case.required_capabilities:
        if provider_capabilities.get(capability) is not True:
            missing.append(capability)
    return missing


def _skip_reason_for_missing_capability(case: ProbeCase, capability: str) -> str:
    if case.name == "ttl-expired" and capability == "controlled_router":
        return SKIP_REQUIRES_CONTROLLED_ROUTER
    return SKIP_CAPABILITY_UNAVAILABLE


def _primary_endpoint_role(case: ProbeCase) -> str:
    return case.endpoint_roles[0] if case.endpoint_roles else "stimulus"


def _live_status(request: ProbeRunRequest) -> str:
    if not request.confirm_live_run:
        return "requires-confirmation"
    return STATUS_UNSUPPORTED


def _target_service_setup_plan(
    *,
    probe_plans: Sequence[JSONObject],
    dry_run: bool,
) -> JSONObject:
    tcp_open_ports = _dedupe_ints(
        int(plan["destination_port"])
        for plan in probe_plans
        if plan.get("case") == "tcp-syn-open"
    )
    tcp_closed_ports = _dedupe_ints(
        int(plan["destination_port"])
        for plan in probe_plans
        if plan.get("case") == "tcp-syn-closed"
    )
    dns_plans = _dns_probe_plans(probe_plans)
    dns_ports = _dedupe_ints(
        int(plan["destination_port"])
        for plan in dns_plans
        if isinstance(plan.get("destination_port"), int)
    )
    return {
        "role": "target",
        "planned": True,
        "starts_services": not dry_run and bool(tcp_open_ports or dns_ports),
        "dry_run_starts_services": False,
        "services": [
            *[
                {
                    "name": "tcp-open-listener",
                    "protocol": "tcp",
                    "port": port,
                    "purpose": "tcp-syn-open",
                    "deterministic": True,
                }
                for port in tcp_open_ports
            ],
            *[
                {
                    "name": "dns-responder",
                    "protocol": "udp",
                    "port": port,
                    "purpose": "dns-query",
                    "deterministic": True,
                    "query_count": sum(
                        1
                        for plan in dns_plans
                        if int(plan.get("destination_port", 0)) == port
                    ),
                    "log_paths": [
                        f"live-artifacts/probe/target-services/dns-responder-{port}.stdout.txt",
                        f"live-artifacts/probe/target-services/dns-responder-{port}.stderr.txt",
                    ],
                }
                for port in dns_ports
            ],
        ],
        "closed_tcp_ports": [
            {
                "port": port,
                "state": "verified-unbound" if not dry_run else "planned-unbound",
                "purpose": "tcp-syn-closed",
                "deterministic": True,
            }
            for port in tcp_closed_ports
        ],
        "controlled_router": {
            "available": False,
            "skip_reason": SKIP_REQUIRES_CONTROLLED_ROUTER,
        },
    }


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
