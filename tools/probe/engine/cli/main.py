"""Deterministic, substrate-independent probe plan CLI."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[4]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from ..cases import (
    ENDPOINT_ROLES as _ENDPOINT_ROLES,
    PROBE_CASES as _PROBE_CASES,
    PROBE_CASE_BY_NAME as _PROBE_CASE_BY_NAME,
    case_name_filters as _case_name_filters,
    profile_default_count as _profile_default_count,
    profile_selected_cases as _profile_selected_cases,
    selected_cases as _selected_cases,
)
from ..model import (
    EndpointRole,
    JSONObject,
    ProbeReport,
    ProbeResult,
    ProbeRunRequest,
    write_json,
)
from ..planning import (
    deterministic_bytes as _deterministic_bytes,
    deterministic_documentation_mac as _deterministic_documentation_mac,
    deterministic_ipv4_pair as _deterministic_ipv4_pair,
    deterministic_router_ipv4 as _deterministic_router_ipv4,
    dns_label as _dns_label,
    dns_query_name as _dns_query_name,
    planned_cases as _planned_cases,
    probe_plan_for_case as _probe_plan_for_case,
    probe_plans_for_cases as _probe_plans_for_cases,
    solicited_node_multicast as _solicited_node_multicast,
)
from ..protocols import all_stimulus_endpoint_cases as _registry_stimulus_endpoint_cases
from ..report import DEFAULT_OUTPUT_ROOT, REPO_ROOT


SCHEMA_VERSION = 2
MODE_PLAN = "plan"
STATUS_PLANNED = "planned"
_STIMULUS_ENDPOINT_CASES = _registry_stimulus_endpoint_cases()


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tools/probe/run",
        description=(
            "Generate deterministic libcrafter probe plans. This command never "
            "selects infrastructure or sends packets."
        ),
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
        help="deterministic selection seed (default: %(default)s)",
    )
    parser.add_argument(
        "--count",
        type=_positive_int,
        default=None,
        help="number of cases to plan (default: profile default)",
    )
    parser.add_argument(
        "--case",
        dest="case_names",
        action="append",
        help="case name to include; may be repeated or comma-separated",
    )
    parser.add_argument(
        "--out",
        default=str(DEFAULT_OUTPUT_ROOT / "plan"),
        help="report directory or report.json path (default: %(default)s)",
    )
    return parser


def _request_from_args(args: argparse.Namespace) -> ProbeRunRequest:
    case_names = _case_name_filters(args.case_names)
    count = (
        args.count if args.count is not None else _profile_default_count(args.profile)
    )
    return ProbeRunRequest(
        profile=args.profile,
        seed=args.seed,
        count=count,
        case_names=list(case_names),
        out=args.out,
        metadata={
            "count_explicit": args.count is not None,
            "requested_cases": list(case_names),
        },
    )


def _report_path(out: str) -> Path:
    path = Path(out)
    if not path.is_absolute():
        path = REPO_ROOT / path
    return path if path.suffix == ".json" else path / "report.json"


def _role_models() -> list[EndpointRole]:
    return list(_ENDPOINT_ROLES)


def _primary_role(case) -> str:
    return case.endpoint_roles[0] if case.endpoint_roles else "stimulus"


def _required_capabilities(cases) -> list[str]:
    return sorted(
        {capability for case in cases for capability in case.required_capabilities}
    )


def _run(args: argparse.Namespace) -> int:
    try:
        request = _request_from_args(args)
        selected = _profile_selected_cases(request.profile, request.case_names)
        planned = _planned_cases(selected, seed=request.seed, count=request.count)
        plans = _probe_plans_for_cases(request, planned)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    results = [
        ProbeResult(
            case=case.name,
            sequence=sequence,
            status=STATUS_PLANNED,
            endpoint_role=_primary_role(case),
            passed=None,
            metadata={"plan_index": sequence},
        )
        for sequence, case in enumerate(planned)
    ]
    report = ProbeReport(
        mode=MODE_PLAN,
        profile=request.profile,
        seed=request.seed,
        count=request.count,
        status=STATUS_PLANNED,
        request=request,
        cases=list(planned),
        endpoint_roles=_role_models(),
        results=results,
        plans=plans,
        metadata={
            "schema": "crafter-probe-plan-v2",
            "mutates_network": False,
            "selects_infrastructure": False,
            "required_capabilities": _required_capabilities(planned),
            "supported_local_executor_cases": sorted(_STIMULUS_ENDPOINT_CASES),
        },
        schema_version=SCHEMA_VERSION,
    )
    path = _report_path(request.out or str(DEFAULT_OUTPUT_ROOT / "plan"))
    write_json(path, report)
    print(
        f"probe: status={report.status} profile={report.profile} "
        f"planned={len(report.plans)} report={path}"
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    return _run(args)


if __name__ == "__main__":
    raise SystemExit(main())
