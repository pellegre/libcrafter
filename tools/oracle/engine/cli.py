"""Command-line interface for oracle packet validation."""

from __future__ import annotations

import argparse
import json
import shlex
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

from .compare import compare_decoded_models, failure_indexes
from .model import ComparisonResult, JSONObject, RunReport, dumps_json, write_json
from .report import DEFAULT_OUTPUT_ROOT, REPO_ROOT


def _add_common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--out",
        default=str(DEFAULT_OUTPUT_ROOT),
        help="artifact output root (default: %(default)s)",
    )


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def _non_negative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be non-negative")
    return parsed


def _add_generation_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--backend",
        choices=("scapy",),
        default="scapy",
        help="reference backend to target (default: %(default)s)",
    )
    parser.add_argument(
        "--profile",
        choices=("smoke", "ci", "wild", "boundary", "fuzz"),
        default="smoke",
        help="sampling profile (default: %(default)s)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=1,
        help="deterministic generator seed (default: %(default)s)",
    )
    parser.add_argument(
        "--count",
        type=_positive_int,
        default=10,
        help="number of generated packet plans (default: %(default)s)",
    )
    parser.add_argument(
        "--case",
        dest="case_name",
        help="case name filter or reproduction coordinate",
    )
    parser.add_argument(
        "--feature",
        help="feature name filter or reproduction coordinate",
    )
    parser.add_argument(
        "--family",
        choices=("ipv4", "ipv6"),
        help="protocol family filter",
    )
    parser.add_argument(
        "--index",
        type=_non_negative_int,
        help="generate one packet plan at the selected index",
    )


def _not_implemented(args: argparse.Namespace) -> int:
    print(
        f"oracle {args.mode} mode is not implemented yet; parsed output root: {args.out}",
        file=sys.stderr,
    )
    return 2


def _offline(args: argparse.Namespace) -> int:
    if not args.dry_plan and not args.emit_vectors and not args.emit_decoded:
        return _offline_reference_to_libcrafter(args)

    from .generator import generate_plans

    plans = generate_plans(
        seed=args.seed,
        profile=args.profile,
        count=args.count,
        family=args.family,
        case=args.case_name,
        feature=args.feature,
        index=args.index,
    )
    if args.emit_vectors or args.emit_decoded:
        if args.backend == "scapy":
            from .backends.scapy.packets import encode_packet_plans

            vectors = encode_packet_plans(plans)
        else:
            print(f"unsupported backend: {args.backend}", file=sys.stderr)
            return 2

        if args.emit_decoded:
            from .backends.scapy.normalize import decode_vectors, validate_smoke_decodes

            decoded = decode_vectors(vectors)
            if args.profile == "smoke":
                validate_smoke_decodes(vectors, decoded)

            metadata = {
                "emit_decoded": True,
                "requested_count": args.count,
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
                selected_specs=["builtin-stack-grammar"],
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
            selected_specs=["builtin-stack-grammar"],
            metadata={
                "emit_vectors": True,
                "requested_count": args.count,
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
        selected_specs=["builtin-stack-grammar"],
        metadata={
            "dry_plan": True,
            "requested_count": args.count,
            "plans": [plan.to_dict() for plan in plans],
        },
    )
    sys.stdout.write(dumps_json(report))
    return 0


def _offline_reference_to_libcrafter(args: argparse.Namespace) -> int:
    if args.direction != "reference_to_libcrafter":
        print(f"unsupported offline direction: {args.direction}", file=sys.stderr)
        return 2

    from .backends.scapy.normalize import decode_vectors
    from .backends.scapy.packets import encode_packet_plans
    from .generator import generate_plans

    if args.backend != "scapy":
        print(f"unsupported backend: {args.backend}", file=sys.stderr)
        return 2

    output_dir = _offline_output_dir(args.out)
    artifacts_root = output_dir / "artifacts"
    artifacts_root.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "report.json"
    run_dir = Path(
        tempfile.mkdtemp(
            prefix=f"{args.direction}.",
            dir=artifacts_root,
        )
    )

    plans = generate_plans(
        seed=args.seed,
        profile=args.profile,
        count=args.count,
        family=args.family,
        case=args.case_name,
        feature=args.feature,
        index=args.index,
    )
    vectors = encode_packet_plans(plans)
    expected_decoded = decode_vectors(vectors)

    vector_report = RunReport(
        mode="offline",
        backend=args.backend,
        profile=args.profile,
        seed=args.seed,
        count=len(vectors),
        status="vectors",
        selected_specs=["builtin-stack-grammar"],
        metadata={
            "direction": args.direction,
            "requested_count": args.count,
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
            selected_specs=["builtin-stack-grammar"],
            metadata={
                "direction": args.direction,
                "decoded": [model.to_dict() for model in expected_decoded],
            },
        ),
    )

    bridge = _run_libcrafter_decode_bridge(vector_path, run_dir)
    actual_decoded = _decoded_models(bridge["report"])
    actual_path = run_dir / "libcrafter-decoded.json"
    write_json(actual_path, bridge["report"])

    results = _compare_offline_results(
        args=args,
        expected=expected_decoded,
        actual=actual_decoded,
        plans=plans,
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

    report = RunReport(
        mode="offline",
        backend=args.backend,
        profile=args.profile,
        seed=args.seed,
        count=len(results),
        status=status,
        selected_specs=["builtin-stack-grammar"],
        artifacts=artifacts,
        results=results,
        failures=failures,
        reproduction_commands=[
            command
            for command in (result.reproduction_command for result in failures)
            if command is not None
        ],
        metadata={
            "direction": args.direction,
            "requested_count": args.count,
            "generated_count": len(plans),
            "artifact_dir": str(run_dir) if preserve_artifacts else None,
            "libcrafter_bridge": {
                "argv": bridge["argv"],
                "exit_code": bridge["exit_code"],
            },
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


def _compare_offline_results(
    *,
    args: argparse.Namespace,
    expected: list[object],
    actual: list[JSONObject],
    plans: list[object],
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
                expected=expected[item].to_dict() if item < len(expected) else {},
                actual=actual[item] if item < len(actual) else {},
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


def _run_libcrafter_decode_bridge(vector_path: Path, run_dir: Path) -> JSONObject:
    argv = [
        "cargo",
        "run",
        "-q",
        "-p",
        "crafter",
        "--example",
        "oracle_decode_vectors",
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
        raise RuntimeError(
            "libcrafter decode bridge failed with exit "
            f"{process.returncode}; stderr={stderr_path}"
        )

    try:
        report = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"libcrafter decode bridge emitted invalid JSON: {exc}") from exc
    if not isinstance(report, dict):
        raise RuntimeError("libcrafter decode bridge report must be a JSON object")

    return {
        "argv": argv,
        "exit_code": process.returncode,
        "report": report,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
    }


def _decoded_models(report: object) -> list[JSONObject]:
    report_object = _json_object(report, "libcrafter report")
    metadata = _json_object(report_object.get("metadata", {}), "libcrafter report metadata")
    decoded = metadata.get("decoded")
    if not isinstance(decoded, list):
        raise RuntimeError("libcrafter report metadata.decoded must be a list")

    output: list[JSONObject] = []
    for index, item in enumerate(decoded):
        output.append(_json_object(item, f"decoded[{index}]"))
    return output


def _offline_output_dir(out: str) -> Path:
    output_root = Path(out)
    if not output_root.is_absolute():
        output_root = REPO_ROOT / output_root
    return output_root / "offline"


def _reproduction_command(args: argparse.Namespace, index: int) -> str:
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
    return shlex.join(argv)


def _json_object(value: object, name: str) -> JSONObject:
    if not isinstance(value, dict):
        raise RuntimeError(f"{name} must be a JSON object")
    output: JSONObject = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise RuntimeError(f"{name} keys must be strings")
        output[key] = item  # type: ignore[assignment]
    return output

def _backend_info(args: argparse.Namespace) -> int:
    if args.backend == "scapy":
        from .backends.scapy.bootstrap import backend_info

        sys.stdout.write(dumps_json(backend_info()))
        return 0

    print(f"unsupported backend: {args.backend}", file=sys.stderr)
    return 2


def _self_check(args: argparse.Namespace) -> int:
    from .generator import run_self_checks

    run_self_checks()
    sys.stdout.write(dumps_json({"status": "ok", "checks": ["generator"]}))
    return 0


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

    offline_parser = subparsers.add_parser(
        "offline",
        help="run offline validation",
        description="Run offline oracle validation.",
    )
    _add_common_options(offline_parser)
    _add_generation_options(offline_parser)
    offline_parser.add_argument(
        "--direction",
        choices=("reference_to_libcrafter",),
        default="reference_to_libcrafter",
        help="offline validation direction (default: %(default)s)",
    )
    offline_parser.add_argument(
        "--keep-artifacts",
        action="store_true",
        help="keep intermediate vector and decoded artifacts for successful runs",
    )
    offline_parser.add_argument(
        "--dry-plan",
        action="store_true",
        help="print generated packet plans without invoking a backend",
    )
    offline_parser.add_argument(
        "--emit-vectors",
        action="store_true",
        help="print Scapy-materialized packet vectors without invoking libcrafter",
    )
    offline_parser.add_argument(
        "--emit-decoded",
        action="store_true",
        help="print normalized Scapy-decoded packet models without invoking libcrafter",
    )
    offline_parser.set_defaults(func=_offline)

    for mode in ("pcap", "live"):
        mode_parser = subparsers.add_parser(
            mode,
            help=f"run {mode} validation",
            description=f"Run {mode} oracle validation.",
        )
        _add_common_options(mode_parser)
        mode_parser.set_defaults(func=_not_implemented)

    backend_info_parser = subparsers.add_parser(
        "backend-info",
        help="print backend dependency and version metadata",
        description="Print oracle backend dependency and version metadata.",
    )
    backend_info_parser.add_argument(
        "--backend",
        choices=("scapy",),
        default="scapy",
        help="backend to inspect (default: %(default)s)",
    )
    backend_info_parser.set_defaults(func=_backend_info)

    self_check_parser = subparsers.add_parser(
        "self-check",
        help="run oracle engine self checks",
        description="Run lightweight oracle engine self checks.",
    )
    self_check_parser.set_defaults(func=_self_check)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
