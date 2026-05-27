#!/usr/bin/env python3
"""Run one corpus through offline, pcap, and provider-backed live dry-runs."""

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
) -> JSONObject:
    """Return compact provider summary after validating live dry-run metadata."""

    metadata = _object(report.get("metadata"), "report.metadata")
    errors: list[str] = []

    _expect(report.get("mode") == "live", "mode must be 'live'", errors)
    _expect(report.get("status") == "dry-run", "status must be 'dry-run'", errors)
    _expect(metadata.get("provider") == provider, "metadata.provider mismatch", errors)
    _expect(metadata.get("dry_run") is True, "metadata.dry_run must be true", errors)
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
        isinstance(metadata.get("artifact_collection"), dict),
        "metadata.artifact_collection must be present",
        errors,
    )
    _expect(
        isinstance(metadata.get("teardown"), dict),
        "metadata.teardown must be present",
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

    return {
        "provider": provider,
        "wire_provider": adapter.wire_provider,
        "wire_exposure": adapter.wire_exposure,
        "endpoint_roles": list(adapter.endpoint_roles),
        "status": str(report["status"]),
        "report_path": str(report_path),
        "corpus_id": corpus_id,
        "wire_eligible_count": int(metadata["wire_eligible_count"]),
        "wire_skipped_count": int(metadata["wire_skipped_count"]),
        "wire_skip_reasons": dict(metadata["wire_skip_reasons"]),
        "exchange_count": int(report.get("count", 0)),
        "no_live_packets_sent": True,
        "lifecycle": {
            "provider_workflow_count": len(metadata["provider_workflow"]),
            "endpoint_bootstrap_count": len(metadata["endpoint_bootstrap"]),
            "artifact_collection": True,
            "teardown": True,
        },
    }


def build_matrix_summary(
    *,
    backend: str,
    profile: str,
    seed: int,
    count: int,
    dry_run: bool,
    corpus_path: Path,
    corpus_report: Mapping[str, Any],
    offline_report_path: Path,
    pcap_report_path: Path,
    providers: Sequence[JSONObject],
    commands: Sequence[JSONObject],
) -> JSONObject:
    return {
        "status": "passed",
        "dry_run": dry_run,
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
        description="Run one oracle corpus through provider-backed live dry-runs.",
    )
    parser.add_argument(
        "--providers",
        type=parse_provider_list,
        default=list(registered_provider_names()),
        help="comma-separated provider-backed oracle live providers",
    )
    parser.add_argument("--backend", default="scapy")
    parser.add_argument("--profile", default="smoke")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--count", type=_positive_int, default=10)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="run provider-backed live validations in dry-run mode",
    )
    parser.add_argument(
        "--out",
        default="target/oracle/provider-matrix-dry-run",
        help="matrix output directory",
    )
    args = parser.parse_args(argv)

    if not args.dry_run:
        print("error: live provider matrix currently requires --dry-run", file=sys.stderr)
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
        for provider in args.providers:
            adapter = resolve_live_provider(provider)
            provider_out = out_dir / "providers" / provider
            live_command = [
                *_oracle_command(
                    "live",
                    args=args,
                    corpus_path=corpus_path,
                    out_dir=provider_out,
                ),
                "--provider",
                provider,
                "--dry-run",
            ]
            commands.append(
                _run_command(
                    live_command,
                    cwd=repo_root,
                    out_dir=out_dir,
                    label=f"live-{provider}",
                )
            )
            report_path = provider_out / "live" / "report.json"
            report = _object(read_json(report_path), f"{provider} live report")
            provider_summaries.append(
                validate_live_report(
                    report,
                    provider=provider,
                    adapter=adapter,
                    corpus_id=corpus_id,
                    corpus_path=corpus_path,
                    report_path=report_path,
                )
            )

        summary_path = out_dir / "matrix-summary.json"
        summary = build_matrix_summary(
            backend=args.backend,
            profile=args.profile,
            seed=args.seed,
            count=args.count,
            dry_run=True,
            corpus_path=corpus_path,
            corpus_report=corpus_report,
            offline_report_path=offline_report_path,
            pcap_report_path=pcap_report_path,
            providers=provider_summaries,
            commands=commands,
        )
        write_json(summary_path, summary)
        print(
            "provider matrix: status=passed "
            f"providers={','.join(args.providers)} summary={summary_path}"
        )
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
    if process.returncode != 0:
        raise MatrixValidationError(
            f"{label} command exited {process.returncode}; "
            f"stdout={stdout_path} stderr={stderr_path}"
        )
    return record


def _object(value: Any, name: str) -> JSONObject:
    if not isinstance(value, dict):
        raise MatrixValidationError(f"{name} must be a JSON object")
    output: JSONObject = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise MatrixValidationError(f"{name} keys must be strings")
        output[key] = item
    return output


def _roles_from_commands(value: Any) -> set[str]:
    if not isinstance(value, list):
        return set()
    roles: set[str] = set()
    for item in value:
        if isinstance(item, dict) and isinstance(item.get("role"), str):
            roles.add(item["role"])
    return roles


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


if __name__ == "__main__":
    raise SystemExit(main())
