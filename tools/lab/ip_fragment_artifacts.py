#!/usr/bin/env python3
"""Audit lab IP fragmentation artifacts without running live traffic."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any


_SCRIPT_PATH = Path(__file__).resolve()
_REPO_ROOT = _SCRIPT_PATH.parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tools.oracle.engine.model import JSONValue, read_json, write_json


TOOL_NAME = "ip_fragment_artifacts"
DEFAULT_OUTPUT_ROOT = "target/lab/ip-fragment-artifact-audit"
IP_FRAGMENT_PROFILE = "ip-fragment-smoke"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Read lab/oracle IP fragmentation JSON artifacts and write a "
            "provider pass/fail/skipped audit report."
        ),
    )
    parser.add_argument(
        "--input",
        action="append",
        default=[],
        help="artifact root or JSON file to audit (repeatable)",
    )
    parser.add_argument(
        "--out",
        default=DEFAULT_OUTPUT_ROOT,
        help="directory for report.json (default: %(default)s)",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="write and audit deterministic synthetic artifacts",
    )
    args = parser.parse_args(argv)

    out_dir = _absolute_path(Path(args.out))
    report_path = out_dir / "report.json"
    input_paths = [_absolute_path(Path(path)) for path in args.input]

    if args.self_test:
        fixture_root = out_dir / "self-test-input"
        _write_self_test_fixture(fixture_root)
        input_paths = [fixture_root]
    elif not input_paths:
        parser.error("--input is required unless --self-test is used")

    report = audit_artifacts(input_paths, output_report_path=report_path)
    report["self_test"] = bool(args.self_test)
    write_json(report_path, report)

    print(
        "ip fragment artifact audit: "
        f"status={report['status']} "
        f"providers={report['summary']['provider_count']} "
        f"report={report_path}"
    )
    return 1 if report["status"] == "failed" else 0


def audit_artifacts(
    input_paths: Sequence[Path],
    *,
    output_report_path: Path | None = None,
) -> dict[str, Any]:
    scan = _scan_inputs(input_paths, output_report_path=output_report_path)
    entries: dict[str, dict[str, Any]] = scan["entries"]

    for provider in _providers_from_standalone_artifacts(scan):
        entries.setdefault(provider, _new_entry(provider))

    provider_reports = [
        _evaluate_provider(provider, entry, scan)
        for provider, entry in sorted(entries.items())
    ]
    summary = {
        "provider_count": len(provider_reports),
        "passed": sum(1 for provider in provider_reports if provider["status"] == "passed"),
        "failed": sum(1 for provider in provider_reports if provider["status"] == "failed"),
        "skipped": sum(1 for provider in provider_reports if provider["status"] == "skipped"),
    }
    if summary["failed"]:
        status = "failed"
    elif summary["passed"]:
        status = "passed"
    else:
        status = "skipped"

    return {
        "tool": TOOL_NAME,
        "status": status,
        "inputs": [str(path) for path in input_paths],
        "summary": summary,
        "providers": provider_reports,
        "scan_errors": scan["errors"],
    }


def _scan_inputs(
    input_paths: Sequence[Path],
    *,
    output_report_path: Path | None,
) -> dict[str, Any]:
    scan: dict[str, Any] = {
        "entries": {},
        "pcap_summaries": [],
        "payload_hashes": [],
        "workload_plans": [],
        "errors": [],
    }
    for input_path in input_paths:
        for path, document in _iter_json_documents(input_path, output_report_path):
            if not isinstance(document, Mapping):
                continue
            doc = dict(document)
            if _is_matrix_summary(doc):
                _scan_matrix_summary(scan, path, doc)
            if _is_live_report(doc):
                provider = _provider_name(doc, path) or "unknown"
                _entry(scan, provider)["_live_reports"].append((path, doc))
                workload_plan = _workload_plan_from_live_report(doc)
                if isinstance(workload_plan, Mapping):
                    _entry(scan, provider)["_workload_plans"].append((path, dict(workload_plan)))
            if _is_lab_summary(doc):
                provider = _provider_name(doc, path) or "unknown"
                _entry(scan, provider)["_lab_summaries"].append((path, doc))
            if _is_workload_plan(doc):
                scan["workload_plans"].append((path, doc, _provider_name(doc, path)))
            if _is_pcap_summary(doc):
                scan["pcap_summaries"].append((path, doc, _provider_name(doc, path)))
            if _is_payload_hash_artifact(path, doc):
                scan["payload_hashes"].append((path, doc, _provider_name(doc, path)))
    return scan


def _iter_json_documents(
    input_path: Path,
    output_report_path: Path | None,
) -> Iterable[tuple[Path, JSONValue]]:
    paths: list[Path]
    if input_path.is_file():
        paths = [input_path]
    elif input_path.is_dir():
        paths = sorted(input_path.rglob("*.json"))
    else:
        return

    output_path = _absolute_path(output_report_path) if output_report_path else None
    for path in paths:
        resolved = _absolute_path(path)
        if output_path is not None and resolved == output_path:
            continue
        try:
            yield resolved, read_json(resolved)
        except (OSError, ValueError, json.JSONDecodeError):
            continue


def _scan_matrix_summary(scan: dict[str, Any], path: Path, document: Mapping[str, Any]) -> None:
    providers = document.get("providers")
    if not isinstance(providers, Sequence) or isinstance(providers, (str, bytes, bytearray)):
        return
    for provider_summary in providers:
        if not isinstance(provider_summary, Mapping):
            continue
        provider = _provider_name(provider_summary, path) or "unknown"
        entry = _entry(scan, provider)
        entry["_matrix_summaries"].append((path, dict(document)))
        entry["_provider_summaries"].append((path, dict(provider_summary)))
        workload_plan = provider_summary.get("workload_plan")
        if isinstance(workload_plan, Mapping):
            entry["_workload_plans"].append((path, dict(workload_plan)))


def _evaluate_provider(
    provider: str,
    entry: Mapping[str, Any],
    scan: Mapping[str, Any],
) -> dict[str, Any]:
    base = _provider_base(entry)
    workload_plans = _provider_workload_plans(provider, entry, scan)
    pcap_docs = _provider_docs(
        provider,
        scan["pcap_summaries"],
        artifact_paths=_artifact_path_candidates(workload_plans, "summary"),
    )
    payload_docs = _provider_docs(
        provider,
        scan["payload_hashes"],
        artifact_paths=_artifact_path_candidates(workload_plans, "payload_hashes"),
    )
    transform_hashes = _unique_hash_records(
        record
        for _path, document in pcap_docs
        for record in _transform_payload_hashes(document)
    )
    kernel_hashes = _unique_hash_records(
        record
        for _path, document in payload_docs
        for record in _kernel_payload_hashes(document)
    )

    reasons: list[dict[str, Any]] = []
    hash_comparison = _compare_hashes(transform_hashes, kernel_hashes)
    if base["oracle_status"] in {"failed", "fail", "error"}:
        status = "failed"
        reasons.append(
            _reason(
                "oracle_report_failed",
                "oracle or lab summary reported failure",
                oracle_status=base["oracle_status"],
            )
        )
    elif base["oracle_status"] == "skipped":
        status = "skipped"
        reasons.append(
            _reason(
                str(base["skip_reason"] or "provider_skipped"),
                "provider was skipped by the source summary",
            )
        )
    elif hash_comparison["status"] == "passed":
        status = "passed"
        reasons.append(_reason("payload_hashes_match", "kernel and transform payload hashes match"))
    elif hash_comparison["status"] == "failed":
        status = "failed"
        reasons.append(_reason("payload_hash_mismatch", "kernel and transform payload hashes differ"))
    elif base["oracle_status"] == "passed":
        status = "passed"
        reasons.append(
            _reason(
                "oracle_live_report_passed",
                "provider live report passed without separate payload hash artifacts",
            )
        )
    elif base["dry_run"] or base["oracle_status"] == "dry-run":
        status = "skipped"
        reasons.append(
            _reason(
                "dry_run_no_payload_hash_comparison",
                "dry-run artifacts do not include live kernel payload hashes",
            )
        )
    elif _expects_hash_artifacts(workload_plans):
        status = "failed"
        reasons.append(
            _reason(
                "missing_payload_hash_artifacts",
                "workload plan expected pcap summary and kernel payload hash artifacts",
            )
        )
    else:
        status = "skipped"
        reasons.append(
            _reason(
                "no_payload_hash_artifacts",
                "no pcap summary and kernel payload hash artifacts were available to compare",
            )
        )

    return {
        "provider": provider,
        "status": status,
        "oracle_status": base["oracle_status"],
        "dry_run": base["dry_run"],
        "reasons": reasons,
        "artifacts": {
            "matrix_summaries": _source_paths(entry.get("_matrix_summaries", [])),
            "provider_summaries": _source_paths(entry.get("_provider_summaries", [])),
            "live_reports": _source_paths(entry.get("_live_reports", [])),
            "lab_summaries": _source_paths(entry.get("_lab_summaries", [])),
            "workload_plans": _workload_plan_paths(entry, scan, provider),
            "pcap_summaries": [str(path) for path, _document in pcap_docs],
            "payload_hashes": [str(path) for path, _document in payload_docs],
        },
        "hash_comparison": hash_comparison,
    }


def _provider_base(entry: Mapping[str, Any]) -> dict[str, Any]:
    oracle_status: str | None = None
    dry_run: bool | None = None
    skip_reason: str | None = None

    for _path, summary in entry.get("_provider_summaries", []):
        if not isinstance(summary, Mapping):
            continue
        oracle_status = _string(summary.get("status")) or oracle_status
        dry_run = _bool_or_none(summary.get("dry_run"), dry_run)
        skip_reason = _string(summary.get("skip_reason")) or skip_reason

    for _path, report in entry.get("_live_reports", []):
        if not isinstance(report, Mapping):
            continue
        metadata = _mapping(report.get("metadata"))
        oracle_status = _string(report.get("status")) or oracle_status
        dry_run = _bool_or_none(metadata.get("dry_run"), dry_run)
        skip_reason = _string(metadata.get("skip_reason")) or skip_reason

    for _path, summary in entry.get("_lab_summaries", []):
        if not isinstance(summary, Mapping):
            continue
        oracle_status = _string(summary.get("status")) or oracle_status
        dry_run = _bool_or_none(summary.get("dry_run"), dry_run)

    return {
        "oracle_status": oracle_status,
        "dry_run": bool(dry_run),
        "skip_reason": skip_reason,
    }


def _provider_workload_plans(
    provider: str,
    entry: Mapping[str, Any],
    scan: Mapping[str, Any],
) -> list[tuple[Path, Mapping[str, Any]]]:
    plans: list[tuple[Path, Mapping[str, Any]]] = []
    seen: set[tuple[str, str]] = set()

    def add(path: Path, plan: Mapping[str, Any]) -> None:
        fingerprint = (str(path), json.dumps(plan, sort_keys=True, default=str))
        if fingerprint in seen:
            return
        seen.add(fingerprint)
        plans.append((path, plan))

    for path, plan in entry.get("_workload_plans", []):
        if isinstance(plan, Mapping):
            add(path, plan)
    for path, plan, plan_provider in scan["workload_plans"]:
        if plan_provider == provider and isinstance(plan, Mapping):
            add(path, plan)
    return plans


def _provider_docs(
    provider: str,
    docs: Sequence[tuple[Path, Mapping[str, Any], str | None]],
    *,
    artifact_paths: Sequence[Path],
) -> list[tuple[Path, Mapping[str, Any]]]:
    output: list[tuple[Path, Mapping[str, Any]]] = []
    seen: set[Path] = set()
    candidates = {_absolute_path(path) for path in artifact_paths}

    def add(path: Path, document: Mapping[str, Any]) -> None:
        resolved = _absolute_path(path)
        if resolved in seen:
            return
        seen.add(resolved)
        output.append((resolved, document))

    for path, document, doc_provider in docs:
        resolved = _absolute_path(path)
        if (
            doc_provider == provider
            or (provider == "standalone" and doc_provider is None)
            or resolved in candidates
        ):
            add(resolved, document)

    for path in candidates:
        if path in seen or not path.exists():
            continue
        try:
            document = read_json(path)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        if isinstance(document, Mapping):
            add(path, dict(document))
    return output


def _artifact_path_candidates(
    workload_plans: Sequence[tuple[Path, Mapping[str, Any]]],
    artifact_name: str,
) -> list[Path]:
    paths: list[Path] = []
    for plan_path, plan in workload_plans:
        artifacts = _mapping(plan.get("artifacts"))
        raw_path = _string(artifacts.get(artifact_name))
        if raw_path is None:
            continue
        path = Path(raw_path)
        if not path.is_absolute():
            path = plan_path.parent / path
        paths.append(_absolute_path(path))
    return paths


def _transform_payload_hashes(document: Mapping[str, Any]) -> list[dict[str, Any]]:
    outputs = document.get("outputs")
    if not isinstance(outputs, Sequence) or isinstance(outputs, (str, bytes, bytearray)):
        return []
    records: list[dict[str, Any]] = []
    for output in outputs:
        if not isinstance(output, Mapping):
            continue
        payload_hash = _string(output.get("payload_hash"))
        if payload_hash:
            records.append(
                {
                    "hash": payload_hash.lower(),
                    "index": output.get("index"),
                    "source": "ip_defrag_pcap_summary.outputs",
                }
            )
    return records


def _kernel_payload_hashes(document: Mapping[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for key in ("kernel_payload_hashes", "kernel_delivered_payload_hashes", "payload_hashes"):
        records.extend(_hash_records_from_value(document.get(key), source=key))
    for key in ("records", "outputs"):
        value = document.get(key)
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
            continue
        for index, item in enumerate(value):
            if not isinstance(item, Mapping):
                continue
            payload_hash = (
                _string(item.get("kernel_payload_hash"))
                or _string(item.get("kernel_delivered_payload_hash"))
                or _string(item.get("payload_hash"))
            )
            if payload_hash:
                records.append(
                    {
                        "hash": payload_hash.lower(),
                        "index": item.get("index", index),
                        "source": key,
                    }
                )
    payload_hash = _string(document.get("kernel_payload_hash")) or _string(
        document.get("payload_hash")
    )
    if payload_hash:
        records.append({"hash": payload_hash.lower(), "index": None, "source": "root"})
    return records


def _hash_records_from_value(value: Any, *, source: str) -> list[dict[str, Any]]:
    if isinstance(value, str):
        return [{"hash": value.lower(), "index": None, "source": source}]
    if not isinstance(value, Sequence) or isinstance(value, (bytes, bytearray)):
        return []
    records: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        if isinstance(item, str):
            records.append({"hash": item.lower(), "index": index, "source": source})
        elif isinstance(item, Mapping):
            payload_hash = (
                _string(item.get("hash"))
                or _string(item.get("payload_hash"))
                or _string(item.get("kernel_payload_hash"))
                or _string(item.get("kernel_delivered_payload_hash"))
            )
            if payload_hash:
                records.append(
                    {
                        "hash": payload_hash.lower(),
                        "index": item.get("index", index),
                        "source": source,
                    }
                )
    return records


def _compare_hashes(
    transform_hashes: Sequence[Mapping[str, Any]],
    kernel_hashes: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    transform_counter = Counter(_string(record.get("hash")) for record in transform_hashes)
    kernel_counter = Counter(_string(record.get("hash")) for record in kernel_hashes)
    transform_counter.pop(None, None)
    kernel_counter.pop(None, None)

    if not transform_counter and not kernel_counter:
        return {
            "status": "skipped",
            "reason": "no_hashes",
            "transform_count": 0,
            "kernel_count": 0,
            "missing_from_kernel": [],
            "unexpected_from_kernel": [],
        }
    if not transform_counter or not kernel_counter:
        return {
            "status": "failed",
            "reason": "one_sided_hash_artifacts",
            "transform_count": sum(transform_counter.values()),
            "kernel_count": sum(kernel_counter.values()),
            "missing_from_kernel": sorted((transform_counter - kernel_counter).elements()),
            "unexpected_from_kernel": sorted((kernel_counter - transform_counter).elements()),
        }

    missing = sorted((transform_counter - kernel_counter).elements())
    unexpected = sorted((kernel_counter - transform_counter).elements())
    return {
        "status": "passed" if not missing and not unexpected else "failed",
        "reason": "matched" if not missing and not unexpected else "mismatch",
        "transform_count": sum(transform_counter.values()),
        "kernel_count": sum(kernel_counter.values()),
        "missing_from_kernel": missing,
        "unexpected_from_kernel": unexpected,
    }


def _unique_hash_records(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    seen: set[tuple[str | None, str | None, str]] = set()
    for record in records:
        payload_hash = _string(record.get("hash"))
        if payload_hash is None:
            continue
        key = (_string(record.get("source")), _string(record.get("index")), payload_hash)
        if key in seen:
            continue
        seen.add(key)
        output.append(
            {
                "hash": payload_hash,
                "index": record.get("index"),
                "source": _string(record.get("source")),
            }
        )
    return output


def _providers_from_standalone_artifacts(scan: Mapping[str, Any]) -> list[str]:
    if scan["entries"]:
        return []
    if scan["pcap_summaries"] or scan["payload_hashes"]:
        return ["standalone"]
    return []


def _workload_plan_paths(
    entry: Mapping[str, Any],
    scan: Mapping[str, Any],
    provider: str,
) -> list[str]:
    paths = _source_paths(entry.get("_workload_plans", []))
    for path, _plan, plan_provider in scan["workload_plans"]:
        if plan_provider == provider:
            paths.append(str(path))
    return sorted(dict.fromkeys(paths))


def _expects_hash_artifacts(workload_plans: Sequence[tuple[Path, Mapping[str, Any]]]) -> bool:
    for _path, plan in workload_plans:
        artifacts = _mapping(plan.get("artifacts"))
        if artifacts.get("summary") or artifacts.get("payload_hashes"):
            return True
    return False


def _source_paths(records: Any) -> list[str]:
    paths: list[str] = []
    if not isinstance(records, Sequence):
        return paths
    for record in records:
        if isinstance(record, Sequence) and record and isinstance(record[0], Path):
            paths.append(str(record[0]))
    return sorted(dict.fromkeys(paths))


def _entry(scan: dict[str, Any], provider: str) -> dict[str, Any]:
    entries = scan["entries"]
    if provider not in entries:
        entries[provider] = _new_entry(provider)
    return entries[provider]


def _new_entry(provider: str) -> dict[str, Any]:
    return {
        "provider": provider,
        "_matrix_summaries": [],
        "_provider_summaries": [],
        "_live_reports": [],
        "_lab_summaries": [],
        "_workload_plans": [],
    }


def _is_matrix_summary(document: Mapping[str, Any]) -> bool:
    return isinstance(document.get("providers"), Sequence) and isinstance(
        document.get("baseline"),
        Mapping,
    )


def _is_live_report(document: Mapping[str, Any]) -> bool:
    return document.get("mode") == "live"


def _is_lab_summary(document: Mapping[str, Any]) -> bool:
    return (
        isinstance(document.get("provider"), str)
        and isinstance(document.get("roles"), Sequence)
        and (
            isinstance(document.get("session_id"), str)
            or isinstance(document.get("wire_provider"), str)
        )
    )


def _is_workload_plan(document: Mapping[str, Any]) -> bool:
    return document.get("profile") == IP_FRAGMENT_PROFILE and isinstance(
        document.get("artifacts"),
        Mapping,
    )


def _is_pcap_summary(document: Mapping[str, Any]) -> bool:
    return document.get("tool") == "ip_defrag_pcap_summary" or (
        document.get("transform") == "IpDefrag"
        and isinstance(document.get("outputs"), Sequence)
    )


def _is_payload_hash_artifact(path: Path, document: Mapping[str, Any]) -> bool:
    if path.name == "payload-hashes.json":
        return True
    return any(
        key in document
        for key in (
            "kernel_payload_hashes",
            "kernel_delivered_payload_hashes",
            "payload_hashes",
            "kernel_payload_hash",
        )
    )


def _provider_name(document: Mapping[str, Any], path: Path) -> str | None:
    provider = _string(document.get("provider"))
    if provider:
        return provider
    metadata = _mapping(document.get("metadata"))
    provider = _string(metadata.get("provider"))
    if provider:
        return provider
    workload_plan = _mapping(metadata.get("workload_plan"))
    provider = _string(workload_plan.get("provider"))
    if provider:
        return provider
    parts = list(path.parts)
    if "providers" in parts:
        index = parts.index("providers")
        if index + 1 < len(parts):
            return parts[index + 1]
    return None


def _workload_plan_from_live_report(document: Mapping[str, Any]) -> Mapping[str, Any] | None:
    metadata = _mapping(document.get("metadata"))
    workload_plan = metadata.get("workload_plan")
    return workload_plan if isinstance(workload_plan, Mapping) else None


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _string(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return str(value)


def _bool_or_none(value: Any, current: bool | None = None) -> bool | None:
    if isinstance(value, bool):
        return value
    return current


def _reason(code: str, message: str, **details: Any) -> dict[str, Any]:
    output: dict[str, Any] = {"code": code, "message": message}
    if details:
        output["details"] = details
    return output


def _absolute_path(path: Path | None) -> Path:
    if path is None:
        return Path.cwd().resolve(strict=False)
    expanded = path.expanduser()
    if not expanded.is_absolute():
        expanded = Path.cwd() / expanded
    return expanded.resolve(strict=False)


def _write_self_test_fixture(root: Path) -> None:
    qemu_artifact_root = root / "providers" / "qemu" / "live" / "artifacts" / IP_FRAGMENT_PROFILE
    qemu_report_path = root / "providers" / "qemu" / "live" / "report.json"
    summary_path = qemu_artifact_root / "ip-defrag-summary.json"
    payload_hash_path = qemu_artifact_root / "payload-hashes.json"
    workload_plan = {
        "name": IP_FRAGMENT_PROFILE,
        "profile": IP_FRAGMENT_PROFILE,
        "provider": "qemu",
        "dry_run": False,
        "artifacts": {
            "root": str(qemu_artifact_root),
            "summary": str(summary_path),
            "payload_hashes": str(payload_hash_path),
        },
    }
    write_json(
        root / "matrix-summary.json",
        {
            "status": "passed",
            "dry_run": False,
            "baseline": {},
            "providers": [
                {
                    "provider": "qemu",
                    "status": "passed",
                    "dry_run": False,
                    "report_path": str(qemu_report_path),
                    "workload_plan": workload_plan,
                },
                {
                    "provider": "hetzner",
                    "status": "skipped",
                    "dry_run": True,
                    "skip_reason": "provider_unavailable",
                },
            ],
        },
    )
    write_json(
        qemu_report_path,
        {
            "mode": "live",
            "status": "passed",
            "profile": IP_FRAGMENT_PROFILE,
            "metadata": {
                "provider": "qemu",
                "dry_run": False,
                "workload_plan": workload_plan,
            },
        },
    )
    write_json(qemu_artifact_root / "workload-plan.json", workload_plan)
    write_json(
        summary_path,
        {
            "tool": "ip_defrag_pcap_summary",
            "transform": "IpDefrag",
            "outputs": [
                {"index": 0, "payload_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                {"index": 1, "payload_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
            ],
        },
    )
    write_json(
        payload_hash_path,
        {
            "tool": "kernel_payload_hashes",
            "payload_hash_algorithm": "sha1",
            "records": [
                {"index": 0, "payload_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                {"index": 1, "payload_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
            ],
        },
    )


if __name__ == "__main__":
    raise SystemExit(main())
