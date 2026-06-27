#!/usr/bin/env python3
"""Audit DHCPv6 oracle/probe live artifacts without running live traffic."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any


_SCRIPT_PATH = Path(__file__).resolve()
_REPO_ROOT = _SCRIPT_PATH.parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tools.oracle.engine.model import JSONValue, read_json, write_json


TOOL_NAME = "dhcpv6_artifacts"
DEFAULT_OUTPUT_ROOT = "target/oracle/dhcpv6-artifact-audit"
DHCPV6_PROFILE = "dhcpv6-smoke"

REQUIRED_LIVE_CLASSES = (
    "provider_session_metadata",
    "provider_manifest",
    "planned_topology",
    "stimulus_bytes",
    "reply_bytes",
    "pcaps",
    "decoded_summary_show",
    "normalized_comparison_json",
    "command_logs",
    "teardown_records",
    "reports",
)

CLASS_DESCRIPTIONS = {
    "provider_session_metadata": "lab session id, provider, role, and endpoint metadata",
    "provider_manifest": "provider capability or endpoint manifest metadata",
    "planned_topology": "planned DHCPv6 topology, packet plan, or probe plan",
    "stimulus_bytes": "sent DHCPv6 stimulus bytes",
    "reply_bytes": "captured or observed DHCPv6 reply bytes",
    "pcaps": "pcap or pcapng capture artifact",
    "decoded_summary_show": "decoded packet summary() and show() text",
    "normalized_comparison_json": "normalized decode or comparison JSON",
    "command_logs": "command stdout/stderr log artifact references",
    "teardown_records": "cleanup or teardown records",
    "reports": "oracle or probe report.json",
}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Read DHCPv6 oracle/probe artifact roots and write an audit report "
            "for live-run evidence requirements."
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
        help="write and audit deterministic synthetic DHCPv6 artifacts",
    )
    args = parser.parse_args(argv)

    out_dir = _absolute_path(Path(args.out))
    report_path = out_dir / "report.json"
    input_paths = [_absolute_path(Path(path)) for path in args.input]

    if args.self_test:
        fixture_root = out_dir / "self-test-input"
        _write_self_test_fixture(fixture_root, include_pcap=True, dry_run=False)
        input_paths = [fixture_root]
    elif not input_paths:
        parser.error("--input is required unless --self-test is used")

    report = audit_artifacts(input_paths, output_report_path=report_path)
    report["self_test"] = bool(args.self_test)
    write_json(report_path, report)

    print(
        "dhcpv6 artifact audit: "
        f"status={report['status']} "
        f"present={report['summary']['present_count']} "
        f"missing={report['summary']['missing_count']} "
        f"report={report_path}"
    )
    return 1 if report["status"] == "failed" else 0


def audit_artifacts(
    input_paths: Sequence[Path],
    *,
    output_report_path: Path | None = None,
) -> dict[str, Any]:
    scan = _scan_inputs(input_paths, output_report_path=output_report_path)
    evidence: dict[str, list[str]] = {
        name: sorted({str(path) for path in paths})
        for name, paths in scan["evidence"].items()
    }
    missing = [name for name in REQUIRED_LIVE_CLASSES if not evidence.get(name)]

    if not scan["dhcpv6_paths"]:
        status = "failed"
        reasons = [
            _reason("no_dhcpv6_artifacts", "no DHCPv6 oracle or probe artifacts were found")
        ]
    elif scan["live_run"]:
        if missing:
            status = "failed"
            reasons = [
                _reason(
                    "missing_live_artifacts",
                    "non-dry-run DHCPv6 artifacts are missing required evidence",
                    missing=missing,
                )
            ]
        else:
            status = "passed"
            reasons = [
                _reason("live_artifacts_complete", "required DHCPv6 live evidence is present")
            ]
    else:
        status = "skipped"
        reasons = [
            _reason(
                "dry_run_no_live_artifacts",
                "DHCPv6 artifacts are dry-run or skipped, so live-only evidence is not required",
            )
        ]

    return {
        "tool": TOOL_NAME,
        "status": status,
        "inputs": [str(path) for path in input_paths],
        "summary": {
            "present_count": sum(1 for name in REQUIRED_LIVE_CLASSES if evidence.get(name)),
            "missing_count": len(missing),
            "dhcpv6_document_count": len(scan["dhcpv6_paths"]),
            "pcap_count": len(evidence.get("pcaps", [])),
            "dry_run": scan["dry_run"],
            "live_run": scan["live_run"],
        },
        "required_live_classes": [
            {
                "name": name,
                "description": CLASS_DESCRIPTIONS[name],
                "present": bool(evidence.get(name)),
            }
            for name in REQUIRED_LIVE_CLASSES
        ],
        "missing": missing,
        "evidence": evidence,
        "reasons": reasons,
        "scan_errors": scan["errors"],
    }


def _scan_inputs(
    input_paths: Sequence[Path],
    *,
    output_report_path: Path | None,
) -> dict[str, Any]:
    scan: dict[str, Any] = {
        "evidence": {name: [] for name in REQUIRED_LIVE_CLASSES},
        "dhcpv6_paths": set(),
        "dry_run": False,
        "live_run": False,
        "errors": [],
    }
    output_path = _absolute_path(output_report_path) if output_report_path else None

    for input_path in input_paths:
        for path in _iter_paths(input_path, output_path):
            if path.suffix.lower() in {".pcap", ".pcapng"} and _path_mentions_dhcpv6(path):
                scan["dhcpv6_paths"].add(str(path))
                scan["evidence"]["pcaps"].append(path)
                continue
            if path.suffix.lower() != ".json":
                continue
            try:
                document = read_json(path)
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                scan["errors"].append({"path": str(path), "error": str(exc)})
                continue
            if not isinstance(document, Mapping):
                continue
            if not (_path_mentions_dhcpv6(path) or _value_mentions_dhcpv6(document)):
                continue
            scan["dhcpv6_paths"].add(str(path))
            _classify_document(scan, path, document)
    return scan


def _classify_document(scan: dict[str, Any], path: Path, document: Mapping[str, Any]) -> None:
    evidence = scan["evidence"]
    values = list(_walk(document))
    mappings = [value for value in values if isinstance(value, Mapping)]
    strings = [value for value in values if isinstance(value, str)]

    if _document_is_dry_run(document, values):
        scan["dry_run"] = True
    if _document_is_live_run(document, values):
        scan["live_run"] = True

    if path.name == "report.json" or _has_any_key(mappings, {"results", "failures", "observed_responses"}):
        evidence["reports"].append(path)
    if _has_session_metadata(mappings):
        evidence["provider_session_metadata"].append(path)
    if _has_provider_manifest(mappings):
        evidence["provider_manifest"].append(path)
    if _has_any_key(mappings, {"topology", "roles", "endpoints", "wire_endpoint_plan", "probe_plans", "packet_plan"}):
        evidence["planned_topology"].append(path)
    if _has_hex_key(mappings, {"sent_raw_hex", "stimulus_raw_hex"}):
        evidence["stimulus_bytes"].append(path)
    if _has_hex_key(mappings, {"raw_hex", "reply_raw_hex", "received_raw_hex", "captured_raw_hex"}):
        evidence["reply_bytes"].append(path)
    if _has_summary_and_show(mappings):
        evidence["decoded_summary_show"].append(path)
    if _has_any_key(mappings, {"comparison", "comparisons", "decoded_model", "normalized", "decoded", "observed_response"}):
        evidence["normalized_comparison_json"].append(path)
    if _has_any_key(mappings, {"stdout_path", "stderr_path", "command_records"}) or _strings_contain_suffix(strings, (".stdout", ".stderr", ".stdout.txt", ".stderr.txt", ".log")):
        evidence["command_logs"].append(path)
    if _has_any_key(mappings, {"teardown", "cleanup_state", "destroyed", "teardown_attempted"}):
        evidence["teardown_records"].append(path)
    if _strings_contain_suffix(strings, (".pcap", ".pcapng")):
        evidence["pcaps"].append(path)


def _iter_paths(input_path: Path, output_path: Path | None) -> Iterable[Path]:
    resolved = _absolute_path(input_path)
    if resolved.is_file():
        paths = [resolved]
    elif resolved.is_dir():
        paths = sorted(path.resolve(strict=False) for path in resolved.rglob("*") if path.is_file())
    else:
        return
    for path in paths:
        if output_path is not None and path == output_path:
            continue
        yield path


def _walk(value: Any) -> Iterable[Any]:
    yield value
    if isinstance(value, Mapping):
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for child in value:
            yield from _walk(child)


def _document_is_dry_run(document: Mapping[str, Any], values: Sequence[Any]) -> bool:
    if document.get("dry_run") is True or document.get("mode") == "dry-run":
        return True
    if document.get("status") in {"dry-run", "skipped"}:
        return True
    return any(isinstance(value, Mapping) and value.get("dry_run") is True for value in values)


def _document_is_live_run(document: Mapping[str, Any], values: Sequence[Any]) -> bool:
    if document.get("mode") == "live" and document.get("dry_run") is not True:
        return True
    if document.get("dry_run") is False and document.get("status") in {"passed", "failed", "error"}:
        return True
    return any(
        isinstance(value, Mapping)
        and value.get("dry_run") is False
        and value.get("status") in {"passed", "failed", "error"}
        for value in values
    )


def _has_session_metadata(mappings: Sequence[Mapping[str, Any]]) -> bool:
    for value in mappings:
        if "session_id" in value and (
            "provider" in value or "providers" in value or "roles" in value or "endpoints" in value
        ):
            return True
        if "lab_session" in value or "lab_session_metadata" in value:
            return True
    return False


def _has_provider_manifest(mappings: Sequence[Mapping[str, Any]]) -> bool:
    for value in mappings:
        if "wire_manifest" in value or "endpoint_manifest" in value or "provider_capabilities" in value:
            return True
        if "provider" in value and ("capabilities" in value or "endpoint_id" in value or "artifact_dir" in value):
            return True
    return False


def _has_any_key(mappings: Sequence[Mapping[str, Any]], keys: set[str]) -> bool:
    return any(any(key in value for key in keys) for value in mappings)


def _has_hex_key(mappings: Sequence[Mapping[str, Any]], keys: set[str]) -> bool:
    for value in mappings:
        for key in keys:
            if key in value and isinstance(value[key], str) and _looks_like_hex(value[key]):
                return True
    return False


def _has_summary_and_show(mappings: Sequence[Mapping[str, Any]]) -> bool:
    return any(
        isinstance(value.get("summary"), str) and isinstance(value.get("show"), str)
        for value in mappings
    )


def _strings_contain_suffix(strings: Sequence[str], suffixes: tuple[str, ...]) -> bool:
    return any(string.endswith(suffixes) for string in strings)


def _path_mentions_dhcpv6(path: Path) -> bool:
    return "dhcpv6" in str(path).lower()


def _value_mentions_dhcpv6(value: Any) -> bool:
    if isinstance(value, str):
        return "dhcpv6" in value.lower()
    if isinstance(value, Mapping):
        return any(_value_mentions_dhcpv6(child) for child in value.values())
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return any(_value_mentions_dhcpv6(child) for child in value)
    return False


def _looks_like_hex(value: str) -> bool:
    return bool(value) and len(value) % 2 == 0 and all(
        char in "0123456789abcdefABCDEF" for char in value
    )


def _reason(code: str, message: str, **extra: Any) -> dict[str, Any]:
    reason = {"code": code, "message": message}
    reason.update(extra)
    return reason


def _absolute_path(path: Path) -> Path:
    return path if path.is_absolute() else (_REPO_ROOT / path).resolve(strict=False)


def _write_self_test_fixture(root: Path, *, include_pcap: bool, dry_run: bool) -> None:
    root.mkdir(parents=True, exist_ok=True)
    pcap_path = root / "captures" / "dhcpv6-reply.pcap"
    if include_pcap:
        pcap_path.parent.mkdir(parents=True, exist_ok=True)
        pcap_path.write_bytes(b"\xd4\xc3\xb2\xa1")

    write_json(
        root / "report.json",
        {
            "mode": "live" if not dry_run else "dry-run",
            "status": "passed" if not dry_run else "dry-run",
            "profile": DHCPV6_PROFILE,
            "provider": "qemu",
            "dry_run": dry_run,
            "results": [
                {
                    "case": "dhcpv6-information-request-reply",
                    "status": "passed" if not dry_run else "planned",
                    "observed_response": {
                        "raw_hex": "07010203",
                        "decoded": {
                            "summary": "Dhcpv6(type=reply)",
                            "show": "Dhcpv6\n  message_type: reply",
                        },
                    },
                }
            ],
            "artifacts": [str(pcap_path)] if include_pcap else [],
            "metadata": {
                "provider": "qemu",
                "dry_run": dry_run,
                "lab_session_metadata": {
                    "session_id": "dhcpv6-self-test",
                    "provider": "qemu",
                },
            },
        },
    )
    write_json(
        root / "session.json",
        {
            "session_id": "dhcpv6-self-test",
            "provider": "qemu",
            "roles": ["stimulus", "target"],
            "endpoints": {"stimulus": {"endpoint_id": "stimulus"}},
            "cleanup_state": {"teardown_attempted": True, "teardown_succeeded": True},
            "wire_manifest": {"endpoint_id": "stimulus", "provider": "qemu"},
            "provider_capabilities": {"ipv6": True, "multicast": True},
        },
    )
    write_json(
        root / "planned-topology.json",
        {
            "profile": DHCPV6_PROFILE,
            "topology": {"roles": ["stimulus", "target"]},
            "probe_plans": [{"case": "dhcpv6-information-request-reply"}],
            "packet_plan": {"family": "dhcpv6", "stack": ["ipv6", "udp", "dhcpv6"]},
        },
    )
    write_json(
        root / "stimulus-reply.json",
        {
            "sent_raw_hex": "0b010203",
            "raw_hex": "07010203",
            "decoded": {
                "summary": "Ipv6 / Udp / Dhcpv6(type=reply)",
                "show": "Packet\n  Dhcpv6\n    message_type: reply",
            },
        },
    )
    write_json(
        root / "normalized-comparison.json",
        {
            "comparison": {"passed": True},
            "normalized": {"layers": ["ipv6", "udp", "dhcpv6"]},
            "decoded_model": {"fields": {"dhcpv6": {"message_type": "reply"}}},
        },
    )
    write_json(
        root / "commands.json",
        {
            "profile": DHCPV6_PROFILE,
            "command_records": [
                {
                    "label": "stimulus",
                    "stdout_path": "stimulus.stdout.txt",
                    "stderr_path": "stimulus.stderr.txt",
                }
            ]
        },
    )


if __name__ == "__main__":
    raise SystemExit(main())
