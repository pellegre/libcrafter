"""Command-line interface for oracle packet validation."""

from __future__ import annotations

import argparse
import json
import shlex
import shutil
import subprocess
import sys
import tempfile
import tomllib
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

from .compare import compare_decoded_models, failure_indexes
from .model import (
    ComparisonResult,
    DecodedModel,
    EncodedVector,
    JSONObject,
    PacketPlan,
    RunReport,
    dumps_json,
    write_json,
)
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
        if args.direction == "reference_to_libcrafter":
            return _offline_reference_to_libcrafter(args)
        if args.direction == "libcrafter_to_reference":
            return _offline_libcrafter_to_reference(args)
        print(f"unsupported offline direction: {args.direction}", file=sys.stderr)
        return 2

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
                backend_versions=_backend_versions(args.backend),
                libcrafter=_libcrafter_info(),
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
            backend_versions=_backend_versions(args.backend),
            libcrafter=_libcrafter_info(),
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
    backend_versions = _backend_versions(args.backend)
    libcrafter_info = _libcrafter_info()

    vector_report = RunReport(
        mode="offline",
        backend=args.backend,
        profile=args.profile,
        seed=args.seed,
        count=len(vectors),
        status="vectors",
        selected_specs=["builtin-stack-grammar"],
        backend_versions=backend_versions,
        libcrafter=libcrafter_info,
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
            backend_versions=backend_versions,
            libcrafter=libcrafter_info,
            metadata={
                "direction": args.direction,
                "decoded": [model.to_dict() for model in expected_decoded],
            },
        ),
    )

    bridge = _run_libcrafter_decode_bridge(vector_path, run_dir)
    actual_decoded = _decoded_models(bridge["report"]) if bridge["exit_code"] == 0 else []
    actual_path = run_dir / "libcrafter-decoded.json"
    write_json(actual_path, bridge["report"])

    results = _compare_offline_results(
        args=args,
        expected=expected_decoded,
        actual=actual_decoded,
        plans=plans,
    )
    results = _with_failure_artifacts(
        run_dir=run_dir,
        results=results,
        vectors=vectors,
        backend_decoded=expected_decoded,
        libcrafter_decoded=actual_decoded,
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
    artifacts.extend(_comparison_artifact_paths(failures))
    artifacts = _dedupe_paths(artifacts)

    report = RunReport(
        mode="offline",
        backend=args.backend,
        profile=args.profile,
        seed=args.seed,
        count=len(results),
        status=status,
        selected_specs=["builtin-stack-grammar"],
        artifacts=artifacts,
        artifact_paths=artifacts,
        results=results,
        failures=failures,
        reproduction_commands=[
            command
            for command in (result.reproduction_command for result in failures)
            if command is not None
        ],
        backend_versions=backend_versions,
        libcrafter=libcrafter_info,
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


def _offline_libcrafter_to_reference(args: argparse.Namespace) -> int:
    if args.backend != "scapy":
        print(f"unsupported backend: {args.backend}", file=sys.stderr)
        return 2

    from .backends.scapy.normalize import decode_vectors

    output_dir = _offline_output_dir(args.out)
    artifacts_root = output_dir / "artifacts"
    artifacts_root.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "report.json"
    scapy_decoded_path = output_dir / "scapy-decoded.json"
    run_dir = Path(
        tempfile.mkdtemp(
            prefix=f"{args.direction}.",
            dir=artifacts_root,
        )
    )

    emitter = _run_libcrafter_vector_emitter(run_dir)
    entries = _select_libcrafter_cases(emitter["manifest"], args)
    plans: list[PacketPlan] = []
    vectors: list[EncodedVector] = []
    expected_decoded: list[JSONObject] = []
    for index, case in entries:
        plan = _libcrafter_case_plan(case, args, index)
        plans.append(plan)
        vectors.append(_libcrafter_case_vector(case, plan))
        expected_decoded.append(
            _json_object(case.get("expected_decoded", {}), f"case[{index}].expected_decoded")
        )
    backend_versions = _backend_versions(args.backend)
    libcrafter_info = _libcrafter_info()

    vector_report = RunReport(
        mode="offline",
        backend=args.backend,
        profile=args.profile,
        seed=args.seed,
        count=len(vectors),
        status="vectors",
        selected_specs=["libcrafter-oracle-vectors"],
        backend_versions=backend_versions,
        libcrafter=libcrafter_info,
        metadata={
            "direction": args.direction,
            "requested_count": args.count,
            "generated_count": len(entries),
            "vector_backend": "libcrafter",
            "vectors": [vector.to_dict() for vector in vectors],
        },
    )
    vector_path = run_dir / "libcrafter-vectors.json"
    write_json(vector_path, vector_report)

    expected_path = run_dir / "libcrafter-expected-decoded.json"
    write_json(
        expected_path,
        RunReport(
            mode="offline",
            backend="libcrafter",
            profile=args.profile,
            seed=args.seed,
            count=len(expected_decoded),
            status="decoded",
            selected_specs=["libcrafter-oracle-vectors"],
            backend_versions=backend_versions,
            libcrafter=libcrafter_info,
            metadata={
                "direction": args.direction,
                "decoded": expected_decoded,
            },
        ),
    )

    actual_decoded = decode_vectors(vectors)
    scapy_report = RunReport(
        mode="offline",
        backend=args.backend,
        profile=args.profile,
        seed=args.seed,
        count=len(actual_decoded),
        status="decoded",
        selected_specs=["libcrafter-oracle-vectors"],
        metadata={
            "direction": args.direction,
            "decoded": [model.to_dict() for model in actual_decoded],
        },
    )
    actual_path = run_dir / "scapy-decoded.json"
    write_json(actual_path, scapy_report)
    write_json(scapy_decoded_path, scapy_report)

    results = _compare_offline_results(
        args=args,
        expected=expected_decoded,
        actual=actual_decoded,
        plans=plans,
        partial_expected=True,
    )
    results = _with_failure_artifacts(
        run_dir=run_dir,
        results=results,
        vectors=vectors,
        backend_decoded=actual_decoded,
        libcrafter_decoded=expected_decoded,
    )
    failures = [result for result in results if not result.passed]
    status = "passed" if not failures and emitter["exit_code"] == 0 else "failed"
    preserve_artifacts = args.keep_artifacts or status != "passed"

    artifacts = [str(report_path), str(scapy_decoded_path)]
    if preserve_artifacts:
        artifacts.extend(
            [
                str(run_dir),
                str(vector_path),
                str(expected_path),
                str(actual_path),
                str(emitter["stdout_path"]),
                str(emitter["stderr_path"]),
            ]
        )
    artifacts.extend(_comparison_artifact_paths(failures))
    artifacts = _dedupe_paths(artifacts)

    report = RunReport(
        mode="offline",
        backend=args.backend,
        profile=args.profile,
        seed=args.seed,
        count=len(results),
        status=status,
        selected_specs=["libcrafter-oracle-vectors"],
        artifacts=artifacts,
        artifact_paths=artifacts,
        results=results,
        failures=failures,
        reproduction_commands=[
            command
            for command in (result.reproduction_command for result in failures)
            if command is not None
        ],
        backend_versions=backend_versions,
        libcrafter=libcrafter_info,
        metadata={
            "direction": args.direction,
            "requested_count": args.count,
            "generated_count": len(entries),
            "artifact_dir": str(run_dir) if preserve_artifacts else None,
            "libcrafter_emitter": {
                "argv": emitter["argv"],
                "exit_code": emitter["exit_code"],
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
    actual: list[object],
    plans: list[PacketPlan],
    partial_expected: bool = False,
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
                partial_expected=partial_expected,
                actual_strict_bytes_hex=_strict_bytes_hex(actual[item]),
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
                expected=_model_to_object(expected[item]) if item < len(expected) else {},
                actual=_model_to_object(actual[item]) if item < len(actual) else {},
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


def _with_failure_artifacts(
    *,
    run_dir: Path,
    results: list[ComparisonResult],
    vectors: list[EncodedVector],
    backend_decoded: list[object],
    libcrafter_decoded: list[object],
) -> list[ComparisonResult]:
    """Write exact per-packet reproduction artifacts for failed comparisons."""

    updated: list[ComparisonResult] = []
    for position, result in enumerate(results):
        if result.passed:
            updated.append(result)
            continue

        index = result.plan.index if result.plan is not None else position
        failure_dir = run_dir / "failures" / f"index-{index:06d}"
        failure_dir.mkdir(parents=True, exist_ok=True)

        plan_path = failure_dir / "packet-plan.json"
        raw_path = failure_dir / "raw.hex"
        backend_path = failure_dir / "backend-decoded.json"
        libcrafter_path = failure_dir / "libcrafter-decoded.json"
        diff_path = failure_dir / "comparison-diff.json"

        write_json(plan_path, result.plan if result.plan is not None else {})
        raw_hex = vectors[position].raw_hex if position < len(vectors) else ""
        raw_path.write_text(f"{raw_hex}\n", encoding="utf-8")
        write_json(
            backend_path,
            _model_to_object(backend_decoded[position]) if position < len(backend_decoded) else {},
        )
        write_json(
            libcrafter_path,
            (
                _model_to_object(libcrafter_decoded[position])
                if position < len(libcrafter_decoded)
                else {}
            ),
        )

        artifact_paths = [
            str(plan_path),
            str(raw_path),
            str(backend_path),
            str(libcrafter_path),
            str(diff_path),
        ]
        result_with_artifacts = replace(result, artifacts=artifact_paths)
        write_json(diff_path, result_with_artifacts)
        updated.append(result_with_artifacts)

    return updated


def _comparison_artifact_paths(results: Sequence[ComparisonResult]) -> list[str]:
    paths: list[str] = []
    for result in results:
        paths.extend(result.artifacts)
    return paths


def _dedupe_paths(paths: Sequence[str]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for path in paths:
        if path in seen:
            continue
        seen.add(path)
        output.append(path)
    return output


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
        report = RunReport(
            mode="offline",
            backend="libcrafter",
            profile="unknown",
            seed=0,
            count=0,
            status="failed",
            artifact_paths=[str(stdout_path), str(stderr_path)],
            artifacts=[str(stdout_path), str(stderr_path)],
            libcrafter=_libcrafter_info(),
            metadata={
                "decoded": [],
                "error": "libcrafter decode bridge failed",
                "exit_code": process.returncode,
            },
        )
        return {
            "argv": argv,
            "exit_code": process.returncode,
            "report": report.to_dict(),
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
        }

    try:
        report = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        report = RunReport(
            mode="offline",
            backend="libcrafter",
            profile="unknown",
            seed=0,
            count=0,
            status="failed",
            artifact_paths=[str(stdout_path), str(stderr_path)],
            artifacts=[str(stdout_path), str(stderr_path)],
            libcrafter=_libcrafter_info(),
            metadata={
                "decoded": [],
                "error": f"libcrafter decode bridge emitted invalid JSON: {exc}",
                "exit_code": process.returncode,
            },
        )
        return {
            "argv": argv,
            "exit_code": 1,
            "report": report.to_dict(),
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
        }
    if not isinstance(report, dict):
        report = RunReport(
            mode="offline",
            backend="libcrafter",
            profile="unknown",
            seed=0,
            count=0,
            status="failed",
            artifact_paths=[str(stdout_path), str(stderr_path)],
            artifacts=[str(stdout_path), str(stderr_path)],
            libcrafter=_libcrafter_info(),
            metadata={
                "decoded": [],
                "error": "libcrafter decode bridge report must be a JSON object",
                "exit_code": process.returncode,
            },
        ).to_dict()
        return {
            "argv": argv,
            "exit_code": 1,
            "report": report,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
        }

    return {
        "argv": argv,
        "exit_code": process.returncode,
        "report": report,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
    }


def _run_libcrafter_vector_emitter(run_dir: Path) -> JSONObject:
    argv = [
        "cargo",
        "run",
        "-q",
        "-p",
        "crafter",
        "--example",
        "oracle_vectors",
        "--",
        "--json",
    ]
    process = subprocess.run(
        argv,
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    stdout_path = run_dir / "libcrafter-vectors.stdout.json"
    stderr_path = run_dir / "libcrafter-vectors.stderr.txt"
    stdout_path.write_text(process.stdout, encoding="utf-8")
    stderr_path.write_text(process.stderr, encoding="utf-8")

    if process.returncode != 0:
        raise RuntimeError(
            "libcrafter vector emitter failed with exit "
            f"{process.returncode}; stderr={stderr_path}"
        )

    try:
        manifest = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"libcrafter vector emitter emitted invalid JSON: {exc}") from exc
    if not isinstance(manifest, dict):
        raise RuntimeError("libcrafter vector emitter manifest must be a JSON object")

    return {
        "argv": argv,
        "exit_code": process.returncode,
        "manifest": manifest,
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


def _select_libcrafter_cases(
    manifest: object,
    args: argparse.Namespace,
) -> list[tuple[int, JSONObject]]:
    manifest_object = _json_object(manifest, "libcrafter vector manifest")
    cases = manifest_object.get("cases")
    if not isinstance(cases, list):
        raise RuntimeError("libcrafter vector manifest cases must be a list")

    entries: list[tuple[int, JSONObject]] = []
    for index, case in enumerate(cases):
        case_object = _json_object(case, f"cases[{index}]")
        if not _case_supports_direction(case_object, args.direction):
            continue
        entries.append((index, case_object))

    if args.case_name is not None:
        entries = [
            (index, case)
            for index, case in entries
            if case.get("name") == args.case_name
        ]
    if args.family is not None:
        entries = [
            (index, case)
            for index, case in entries
            if case.get("family") == args.family
        ]
    if args.feature is not None:
        entries = [
            (index, case)
            for index, case in entries
            if args.feature in _string_values(case.get("features", []))
            or args.feature in _string_values(case.get("feature_tags", []))
        ]
    if args.index is not None:
        entries = [
            (index, case)
            for index, case in entries
            if index == args.index
        ]
    else:
        entries = entries[: args.count]

    if not entries:
        raise RuntimeError("no libcrafter oracle vector cases selected")
    return entries


def _case_supports_direction(case: JSONObject, direction: str) -> bool:
    directions = case.get("directions")
    if isinstance(directions, list) and direction in directions:
        return True
    return case.get("direction") == direction


def _libcrafter_case_plan(
    case: JSONObject,
    args: argparse.Namespace,
    index: int,
) -> PacketPlan:
    expected = _json_object(case.get("expected_decoded", {}), f"case[{index}].expected_decoded")
    stack = _string_values(expected.get("layers", []))
    fields = _json_object(expected.get("fields", {}), f"case[{index}].expected_decoded.fields")
    name = _optional_string(case.get("name"))
    family = _optional_string(case.get("family"))
    strict_bytes = case.get("strict_bytes")
    return PacketPlan(
        stack=stack,
        fields=fields,
        profile=args.profile,
        seed=args.seed,
        index=index,
        direction=args.direction,
        family=family,
        feature_tags=_string_values(case.get("feature_tags", [])),
        case=name,
        strict_bytes=strict_bytes is not False,
        metadata={
            "plan_id": f"libcrafter:{index}",
            "case": name,
            "generator": "cargo run -q -p crafter --example oracle_vectors -- --json",
            "source": "libcrafter oracle vector emitter",
        },
    )


def _libcrafter_case_vector(case: JSONObject, plan: PacketPlan) -> EncodedVector:
    raw_hex = _optional_string(case.get("raw_hex")) or _optional_string(case.get("hex"))
    if raw_hex is None:
        raise RuntimeError(f"libcrafter case {plan.index} is missing raw_hex")
    root = _optional_string(case.get("root_decoder")) or _optional_string(case.get("root"))
    if root is None:
        raise RuntimeError(f"libcrafter case {plan.index} is missing root/root_decoder")
    return EncodedVector(
        plan=plan,
        backend="libcrafter",
        raw_hex=raw_hex,
        root=root,
        decoder=root,
        metadata={
            "case": plan.case,
            "length": len(bytes.fromhex(raw_hex)),
            "strict_bytes": plan.strict_bytes,
            "summary": case.get("summary"),
        },
    )


def _strict_bytes_hex(model: object) -> str | None:
    model_object = model.to_dict() if isinstance(model, DecodedModel) else model
    if not isinstance(model_object, dict):
        return None
    metadata = model_object.get("metadata")
    if not isinstance(metadata, dict):
        return None
    value = metadata.get("reencoded_hex")
    if isinstance(value, str):
        return value
    error = metadata.get("reencoded_error")
    if isinstance(error, str):
        return f"<scapy re-encode failed: {error}>"
    return None


def _model_to_object(model: object) -> JSONObject:
    value = model.to_dict() if hasattr(model, "to_dict") else model
    return _json_object(value, "oracle model")


def _backend_versions(backend: str) -> JSONObject:
    if backend == "scapy":
        from .backends.scapy.bootstrap import backend_info

        return {"scapy": backend_info()}
    return {}


def _libcrafter_info() -> JSONObject:
    info: JSONObject = {}
    version = _workspace_package_version()
    if version is not None:
        info["version"] = version
    commit = _git_head_commit()
    if commit is not None:
        info["commit"] = commit
    return info


def _workspace_package_version() -> str | None:
    try:
        document = tomllib.loads((REPO_ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return None

    workspace = document.get("workspace")
    if not isinstance(workspace, dict):
        return None
    package = workspace.get("package")
    if not isinstance(package, dict):
        return None
    version = package.get("version")
    return version if isinstance(version, str) else None


def _git_head_commit() -> str | None:
    git_dir = REPO_ROOT / ".git"
    try:
        if git_dir.is_file():
            content = git_dir.read_text(encoding="utf-8").strip()
            if not content.startswith("gitdir:"):
                return None
            raw_path = Path(content.split(":", 1)[1].strip())
            git_dir = raw_path if raw_path.is_absolute() else (REPO_ROOT / raw_path).resolve()

        head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
        if not head:
            return None
        if not head.startswith("ref:"):
            return head

        ref_name = head.removeprefix("ref:").strip()
        common_dir = _git_common_dir(git_dir)
        ref_path = git_dir / ref_name
        if ref_path.exists():
            return ref_path.read_text(encoding="utf-8").strip() or None
        ref_path = common_dir / ref_name
        if ref_path.exists():
            return ref_path.read_text(encoding="utf-8").strip() or None

        for packed_refs in (git_dir / "packed-refs", common_dir / "packed-refs"):
            if not packed_refs.exists():
                continue
            for line in packed_refs.read_text(encoding="utf-8").splitlines():
                if not line or line.startswith(("#", "^")):
                    continue
                commit, _, packed_ref = line.partition(" ")
                if packed_ref == ref_name:
                    return commit
    except OSError:
        return None
    return None


def _git_common_dir(git_dir: Path) -> Path:
    common_dir_file = git_dir / "commondir"
    if not common_dir_file.exists():
        return git_dir
    try:
        raw_path = Path(common_dir_file.read_text(encoding="utf-8").strip())
    except OSError:
        return git_dir
    return raw_path if raw_path.is_absolute() else (git_dir / raw_path).resolve()


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


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return str(value)


def _string_values(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


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


def _fixtures(args: argparse.Namespace) -> int:
    if args.backend != "scapy":
        print(f"unsupported backend: {args.backend}", file=sys.stderr)
        return 2

    from .backends.scapy.fixtures import FixtureGenerationOptions, generate_fixtures

    output_dir = Path(args.out)
    if not output_dir.is_absolute():
        output_dir = REPO_ROOT / output_dir

    names = list(args.only)
    if args.case_name is not None:
        names.append(args.case_name)

    return generate_fixtures(
        FixtureGenerationOptions(
            out_dir=output_dir,
            profile=args.profile,
            seed=args.seed,
            names=names,
            families=list(args.fixture_family),
            directions=list(args.fixture_direction),
            check_drift=args.check_drift,
            list_only=args.list_cases,
        )
    )


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
        choices=("reference_to_libcrafter", "libcrafter_to_reference"),
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

    fixtures_parser = subparsers.add_parser(
        "fixtures",
        help="generate deterministic oracle fixture artifacts",
        description="Generate deterministic oracle fixture artifacts.",
    )
    fixtures_parser.add_argument(
        "--backend",
        choices=("scapy",),
        default="scapy",
        help="reference backend to target (default: %(default)s)",
    )
    fixtures_parser.add_argument(
        "--profile",
        choices=("smoke", "ci", "wild", "boundary", "fuzz"),
        default="smoke",
        help="fixture generation profile metadata (default: %(default)s)",
    )
    fixtures_parser.add_argument(
        "--seed",
        type=int,
        default=1,
        help="fixture generation seed metadata (default: %(default)s)",
    )
    fixtures_parser.add_argument(
        "--out",
        default=str(DEFAULT_OUTPUT_ROOT / "fixtures"),
        help="fixture output directory (default: %(default)s)",
    )
    fixtures_parser.add_argument(
        "--case",
        dest="case_name",
        help="fixture case name to generate",
    )
    fixtures_parser.add_argument(
        "--only",
        action="append",
        default=[],
        metavar="NAME",
        help="legacy fixture name filter; can be passed multiple times or comma-separated",
    )
    fixtures_parser.add_argument(
        "--family",
        dest="fixture_family",
        action="append",
        default=[],
        metavar="FAMILY",
        help="legacy fixture family filter; can be passed multiple times or comma-separated",
    )
    fixtures_parser.add_argument(
        "--direction",
        dest="fixture_direction",
        action="append",
        default=[],
        metavar="DIRECTION",
        help="legacy fixture direction filter; can be passed multiple times or comma-separated",
    )
    fixtures_parser.add_argument(
        "--check-drift",
        action="store_true",
        help="compare generated fixture bytes and legacy metadata with checked-in fixtures",
    )
    fixtures_parser.add_argument(
        "--list",
        dest="list_cases",
        action="store_true",
        help="list available fixture cases and exit",
    )
    fixtures_parser.set_defaults(func=_fixtures)

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
