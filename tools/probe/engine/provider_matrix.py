"""Provider dry-run matrix for behavioral probe planning."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

_REPO_ROOT_FOR_IMPORTS = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT_FOR_IMPORTS) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT_FOR_IMPORTS))

from tools.probe.engine import cases, cli, planning
from tools.probe.engine.lab import probe_provider_names
from tools.probe.engine.model import JSONObject, JSONValue, ProbeReport, ProbeRunRequest
from tools.probe.engine.model import write_json


MATRIX_REPORT_NAME = "provider-matrix.json"


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def _provider_list(value: str) -> list[str]:
    providers = [provider.strip() for provider in value.split(",") if provider.strip()]
    if not providers:
        raise argparse.ArgumentTypeError("at least one provider is required")
    known = set(probe_provider_names())
    unknown = [provider for provider in providers if provider not in known]
    if unknown:
        known_text = ", ".join(probe_provider_names())
        unknown_text = ", ".join(unknown)
        raise argparse.ArgumentTypeError(
            f"unsupported provider(s): {unknown_text}; known providers: {known_text}"
        )
    return providers


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tools/probe/engine/provider_matrix.py",
        description="Run provider dry-run planning matrix for probe cases.",
    )
    parser.add_argument(
        "--providers",
        type=_provider_list,
        required=True,
        help="comma-separated provider list",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="required; provider matrix never performs live execution",
    )
    parser.add_argument(
        "--profile",
        default=cases.BEHAVIOR_PROFILE,
        help="probe profile to plan (default: %(default)s)",
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
        help="number of cases to plan (default: profile default)",
    )
    parser.add_argument(
        "--out",
        default=str(Path("target") / "probe" / "provider-matrix"),
        help="matrix output directory or provider-matrix JSON path",
    )
    return parser


def build_provider_matrix(
    *,
    providers: Sequence[str],
    dry_run: bool,
    profile: str,
    seed: int,
    count: int | None,
    out: str | Path,
) -> JSONObject:
    """Run the selected probe cases through each provider's dry-run planner."""

    if not dry_run:
        raise ValueError("provider matrix supports dry-run planning only")

    output_path = _matrix_report_path(out)
    output_dir = output_path.parent
    selected_cases = cases.profile_selected_cases(profile, [])
    resolved_count = count if count is not None else cases.profile_default_count(profile)
    planned_cases = planning.planned_cases(
        selected_cases,
        seed=seed,
        count=resolved_count,
    )
    selected_case_names = [case.name for case in selected_cases]
    planned_case_names = [case.name for case in planned_cases]

    provider_reports: list[JSONObject] = []
    provider_capabilities: JSONObject = {}
    target_service_setup_plans: JSONObject = {}
    stimulus_request_paths: JSONObject = {}
    planned_cases_by_provider: JSONObject = {}
    skipped_cases_by_provider: JSONObject = {}

    for provider in providers:
        report_path = output_dir / "providers" / provider / "report.json"
        report = _provider_dry_run_report(
            provider=provider,
            profile=profile,
            seed=seed,
            count=resolved_count,
            selected_cases=selected_cases,
            planned_cases=planned_cases,
            report_path=report_path,
        )
        write_json(report_path, report)

        entry = _provider_matrix_entry(report=report, report_path=report_path)
        provider_reports.append(entry)
        provider_capabilities[provider] = _json_value(entry["provider_capabilities"])
        target_service_setup_plans[provider] = _json_value(entry["target_service_setup"])
        stimulus_request_paths[provider] = _json_value(
            entry["stimulus_request_artifact_path"]
        )
        planned_cases_by_provider[provider] = _json_value(entry["planned_cases"])
        skipped_cases_by_provider[provider] = _json_value(entry["skipped_cases"])

    summary = _matrix_summary(provider_reports)
    matrix: JSONObject = {
        "schema_version": 1,
        "mode": "probe-provider-matrix",
        "status": "dry-run",
        "dry_run": True,
        "profile": profile,
        "seed": seed,
        "count": resolved_count,
        "provider_count": len(provider_reports),
        "providers": list(providers),
        "selected_cases": selected_case_names,
        "selected_count": len(selected_case_names),
        "planned_cases": planned_case_names,
        "planned_count": len(planned_case_names),
        "provider_reports": provider_reports,
        "provider_capabilities": provider_capabilities,
        "planned_cases_by_provider": planned_cases_by_provider,
        "skipped_cases_by_provider": skipped_cases_by_provider,
        "target_service_setup_plans": target_service_setup_plans,
        "stimulus_request_artifact_paths": stimulus_request_paths,
        "summary": summary,
        "artifact_paths": [str(output_path)]
        + [str(entry["report_path"]) for entry in provider_reports],
    }
    write_json(output_path, matrix)
    return matrix


def _provider_dry_run_report(
    *,
    provider: str,
    profile: str,
    seed: int,
    count: int,
    selected_cases: Sequence[cases.ProbeCase],
    planned_cases: Sequence[cases.ProbeCase],
    report_path: Path,
) -> ProbeReport:
    request = ProbeRunRequest(
        provider=provider,
        profile=profile,
        seed=seed,
        count=count,
        case_names=[],
        dry_run=True,
        metadata={
            "requested_count": count,
            "count_explicit": True,
            "profile_default_count": cases.profile_default_count(profile),
            "requested_cases": [],
            "selected_specs": list(cli.PROBE_SELECTED_SPECS),
            "command": "provider_matrix",
        },
    )
    probe_plans = planning.probe_plans_for_cases(request, planned_cases)
    return cli._dry_run_report(
        request=request,
        selected_cases=selected_cases,
        planned_cases=planned_cases,
        probe_plans=probe_plans,
        report_path=report_path,
    )


def _provider_matrix_entry(
    *,
    report: ProbeReport,
    report_path: Path,
) -> JSONObject:
    metadata = report.metadata
    skipped_cases = [
        {
            "case": skip.case,
            "sequence": skip.sequence,
            "reason": skip.reason,
            "capability": skip.capability,
            "missing_capabilities": list(
                _json_list(skip.metadata.get("missing_capabilities", []))
            ),
        }
        for skip in report.skips
    ]
    skipped_sequences = {skip.sequence for skip in report.skips}
    planned_cases = list(_json_list(metadata.get("planned_case_names", [])))
    executable_cases = [
        case
        for sequence, case in enumerate(planned_cases)
        if sequence not in skipped_sequences
    ]
    stimulus_request_path = _stimulus_request_artifact_path(report)
    return {
        "provider": report.provider,
        "status": report.status,
        "dry_run": True,
        "report_path": str(report_path),
        "stimulus_request_artifact_path": stimulus_request_path,
        "artifact_paths": list(report.artifact_paths),
        "provider_capabilities": dict(
            _json_object(metadata.get("provider_capabilities", {}))
        ),
        "planned_cases": planned_cases,
        "planned_count": int(metadata.get("planned_count", len(planned_cases))),
        "executable_cases": executable_cases,
        "executable_count": len(executable_cases),
        "skipped_cases": skipped_cases,
        "skipped_count": len(skipped_cases),
        "skipped_by_capability": int(metadata.get("skipped_by_capability", 0)),
        "skipped_by_confirmation": int(metadata.get("skipped_by_confirmation", 0)),
        "skip_reasons": list(_json_list(metadata.get("skip_reasons", []))),
        "skip_counts_by_reason": dict(
            _json_object(metadata.get("skip_counts_by_reason", {}))
        ),
        "target_service_setup": dict(
            _json_object(metadata.get("target_service_setup", {}))
        ),
    }


def _matrix_summary(provider_reports: Sequence[JSONObject]) -> JSONObject:
    return {
        "providers": [str(report["provider"]) for report in provider_reports],
        "skipped_count_by_provider": {
            str(report["provider"]): int(report["skipped_count"])
            for report in provider_reports
        },
        "executable_count_by_provider": {
            str(report["provider"]): int(report["executable_count"])
            for report in provider_reports
        },
        "skip_counts_by_provider": {
            str(report["provider"]): dict(
                _json_object(report.get("skip_counts_by_reason", {}))
            )
            for report in provider_reports
        },
    }


def _matrix_report_path(out: str | Path) -> Path:
    output = Path(out)
    if output.suffix == ".json":
        return output
    return output / MATRIX_REPORT_NAME


def _stimulus_request_artifact_path(report: ProbeReport) -> str | None:
    for path in report.artifact_paths:
        if path.endswith("/stimulus.request.json"):
            return path
    return None


def _json_object(value: object) -> JSONObject:
    if not isinstance(value, dict):
        return {}
    return {str(key): _json_value(item) for key, item in value.items()}


def _json_list(value: object) -> list[JSONValue]:
    if not isinstance(value, list):
        return []
    return [_json_value(item) for item in value]


def _json_value(value: object) -> JSONValue:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    return str(value)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not args.dry_run:
        parser.error("--dry-run is required; provider matrix does not run live probes")

    try:
        matrix = build_provider_matrix(
            providers=args.providers,
            dry_run=args.dry_run,
            profile=args.profile,
            seed=args.seed,
            count=args.count,
            out=args.out,
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    report_path = _matrix_report_path(args.out)
    print(
        "probe-provider-matrix: "
        f"status={matrix['status']} providers={','.join(args.providers)} "
        f"planned={matrix['planned_count']} report={report_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
