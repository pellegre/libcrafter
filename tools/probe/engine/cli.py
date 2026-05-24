"""Command-line interface for probe validation."""

from __future__ import annotations

import argparse
import shlex
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

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
    write_json,
)
from .report import DEFAULT_OUTPUT_ROOT, REPO_ROOT


PROBE_SELECTED_SPECS = ("probe-contracts",)
SKIP_CAPABILITY_UNAVAILABLE = "provider_capability_unavailable"
SKIP_CONFIRMATION_REQUIRED = "confirm_live_run_required"
STATUS_DRY_RUN = "dry-run"
STATUS_UNSUPPORTED = "unsupported"


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
        required_capabilities=["controlled_routed_hop"],
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
        capabilities=["controlled_routed_hop"],
    ),
)
_PROVIDER_CAPABILITIES: dict[str, JSONObject] = {
    "local-dry-run": {
        "provider": "local-dry-run",
        "live_packet_exchange": False,
        "icmp_echo": True,
        "tcp_open_port": True,
        "tcp_closed_port": True,
        "dns_service": True,
        "controlled_routed_hop": False,
    },
    "hetzner": {
        "provider": "hetzner",
        "live_packet_exchange": True,
        "icmp_echo": True,
        "tcp_open_port": True,
        "tcp_closed_port": True,
        "dns_service": True,
        "controlled_routed_hop": False,
    },
}


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
        choices=sorted(_PROVIDER_CAPABILITIES),
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
        report_path=report_path,
        status=status,
    )
    write_json(report_path, report)
    print(
        f"probe: status={report.status} provider={request.provider} "
        f"planned={len(report.results)} report={report_path}",
        file=sys.stderr,
    )
    return 2


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


def _dry_run_report(
    *,
    request: ProbeRunRequest,
    selected_cases: Sequence[ProbeCase],
    planned_cases: Sequence[ProbeCase],
    report_path: Path,
) -> ProbeReport:
    return _build_report(
        request=request,
        selected_cases=selected_cases,
        planned_cases=planned_cases,
        report_path=report_path,
        status=STATUS_DRY_RUN,
        dry_run=True,
    )


def _guarded_live_report(
    *,
    request: ProbeRunRequest,
    selected_cases: Sequence[ProbeCase],
    planned_cases: Sequence[ProbeCase],
    report_path: Path,
    status: str,
) -> ProbeReport:
    return _build_report(
        request=request,
        selected_cases=selected_cases,
        planned_cases=planned_cases,
        report_path=report_path,
        status=status,
        dry_run=False,
    )


def _build_report(
    *,
    request: ProbeRunRequest,
    selected_cases: Sequence[ProbeCase],
    planned_cases: Sequence[ProbeCase],
    report_path: Path,
    status: str,
    dry_run: bool,
) -> ProbeReport:
    provider_capabilities = _PROVIDER_CAPABILITIES[request.provider]
    results: list[ProbeResult] = []
    skips: list[ProbeSkip] = []
    observed_responses: list[ObservedResponse] = []
    skip_counts: dict[str, int] = {}

    for sequence, case in enumerate(planned_cases):
        missing = _missing_capabilities(case, provider_capabilities)
        if missing:
            skip = ProbeSkip(
                case=case.name,
                sequence=sequence,
                reason=SKIP_CAPABILITY_UNAVAILABLE,
                capability=missing[0],
                metadata={
                    "missing_capabilities": list(missing),
                    "provider": request.provider,
                    "dry_run": dry_run,
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
                    metadata={"dry_run": dry_run},
                )
            )
            continue

        if not dry_run and not request.confirm_live_run:
            skip = ProbeSkip(
                case=case.name,
                sequence=sequence,
                reason=SKIP_CONFIRMATION_REQUIRED,
                metadata={
                    "provider": request.provider,
                    "requires_confirm_live_run": True,
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
                    metadata={"dry_run": dry_run},
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
                },
            )
        )

    metadata: JSONObject = {
        "requested_count": request.count,
        "planned_count": len(planned_cases),
        "selected_count": len(selected_cases),
        "skipped_count": len(skips),
        "observed_count": sum(1 for response in observed_responses if response.observed),
        "provider_capabilities": dict(provider_capabilities),
        "skip_counts_by_reason": skip_counts,
        "selected_case_names": [case.name for case in selected_cases],
        "planned_case_names": [case.name for case in planned_cases],
        "selected_specs": list(PROBE_SELECTED_SPECS),
        "dry_run": dry_run,
        "mutates_lab": False if dry_run else None,
    }
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
        artifacts=[str(report_path)],
        artifact_paths=[str(report_path)],
        metadata=metadata,
    )


def _missing_capabilities(
    case: ProbeCase,
    provider_capabilities: Mapping[str, JSONValue],
) -> list[str]:
    missing: list[str] = []
    for capability in case.required_capabilities:
        if provider_capabilities.get(capability) is not True:
            missing.append(capability)
    return missing


def _primary_endpoint_role(case: ProbeCase) -> str:
    return case.endpoint_roles[0] if case.endpoint_roles else "stimulus"


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
