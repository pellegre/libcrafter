"""Reusable focused-acceptance harness for a single probe behavioral case.

This harness drives one focused probe case end to end through both halves of the
probe stack so each behavioral case step can prove its work without duplicating
fragile subprocess plumbing in forty separate tests:

1. Run ``tools/probe/run --dry-run`` for the case and read the deterministic
   report.
2. Locate the ``artifacts/stimulus-endpoint/stimulus.request.json`` request the
   dry-run emits.
3. Run the Rust ``stimulus_endpoint`` binary in ``--dry-run`` against that
   request (``cargo run -q -p probe-adapters --bin stimulus_endpoint``).
4. Assert the endpoint response JSON has the stable stimulus-endpoint shape.

The harness asserts *shape*, not a passing validation status: a behavioral case
whose Rust protocol wiring has not landed yet still routes through the
endpoint's structured ``decode_failed`` outcome, which is a well-formed response.
Per-case steps that add real packet construction can additionally assert their
case-specific result status on top of the shape contract here.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Repo root: tools/probe/testing/probe_acceptance.py -> parents[3] is the root.
REPO_ROOT = Path(__file__).resolve().parents[3]
PROBE_RUN = REPO_ROOT / "tools" / "probe" / "run"

DEFAULT_PROVIDER = "qemu"
DEFAULT_PROFILE = "behavior"
DEFAULT_SEED = 8

# Stable top-level keys the stimulus-endpoint response always carries.
_RESPONSE_TOP_KEYS = (
    "provider",
    "backend",
    "endpoint_role",
    "profile",
    "seed",
    "mode",
    "sent_count",
    "received_count",
    "results",
    "observed_responses",
    "errors",
    "artifacts",
    "artifact_paths",
    "metadata",
)

_RESULT_KEYS = ("case", "sequence", "status", "endpoint_role", "metadata")
_OBSERVED_KEYS = (
    "case",
    "sequence",
    "endpoint_role",
    "observed",
    "response_type",
)


@dataclass(frozen=True)
class HarnessOutcome:
    """Artifacts and parsed outputs from one focused-case harness run."""

    case: str
    report_path: Path
    report: dict[str, Any]
    request_path: Path
    request: dict[str, Any]
    response_path: Path
    response: dict[str, Any]


def cargo_available() -> bool:
    """Return whether the ``cargo`` toolchain is on PATH."""

    return shutil.which("cargo") is not None


def probe_run_available() -> bool:
    """Return whether the probe runner wrapper exists and ``uv`` is on PATH."""

    return PROBE_RUN.exists() and shutil.which("uv") is not None


def run_case_through_harness(
    case_name: str,
    *,
    out_dir: Path,
    provider: str = DEFAULT_PROVIDER,
    profile: str = DEFAULT_PROFILE,
    seed: int = DEFAULT_SEED,
    count: int = 1,
    timeout_seconds: int = 600,
) -> HarnessOutcome:
    """Drive one focused probe case through planner and stimulus-endpoint dry-run.

    Returns a :class:`HarnessOutcome` with the probe report, the emitted
    stimulus-endpoint request, and the endpoint dry-run response. Raises
    :class:`AssertionError` (via the subprocess/JSON failures it surfaces) when
    any stage cannot complete, so callers get a precise, inspectable failure
    rather than a silent skip.
    """

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    report_path = _run_probe_dry_run(
        case_name,
        out_dir=out_dir,
        provider=provider,
        profile=profile,
        seed=seed,
        count=count,
        timeout_seconds=timeout_seconds,
    )
    report = _load_json(report_path)

    request_path = (
        report_path.parent / "artifacts" / "stimulus-endpoint" / "stimulus.request.json"
    )
    if not request_path.is_file():
        raise AssertionError(
            f"probe dry-run for {case_name!r} did not emit {request_path}"
        )
    request = _load_json(request_path)

    response_path = _run_stimulus_endpoint(
        request_path,
        out_dir=out_dir / "endpoint",
        timeout_seconds=timeout_seconds,
    )
    response = _load_json(response_path)

    return HarnessOutcome(
        case=case_name,
        report_path=report_path,
        report=report,
        request_path=request_path,
        request=request,
        response_path=response_path,
        response=response,
    )


def assert_request_shape(
    test: unittest.TestCase,
    outcome: HarnessOutcome,
) -> None:
    """Assert the emitted stimulus-endpoint request targets the focused case."""

    request = outcome.request
    test.assertEqual(request.get("endpoint_role"), "stimulus")
    test.assertTrue(request.get("dry_run"))
    plans = request.get("probe_plans")
    test.assertIsInstance(plans, list)
    test.assertTrue(plans, "request carries at least one probe plan")
    cases = [plan.get("case") for plan in plans]
    test.assertIn(outcome.case, cases)


def assert_response_shape(
    test: unittest.TestCase,
    outcome: HarnessOutcome,
) -> None:
    """Assert the stimulus-endpoint response has the stable dry-run shape."""

    response = outcome.response
    for key in _RESPONSE_TOP_KEYS:
        test.assertIn(key, response, f"response missing top-level key {key!r}")

    test.assertEqual(response["endpoint_role"], "stimulus")
    test.assertEqual(response["mode"], "dry-run")
    test.assertEqual(response["backend"], "libcrafter")
    test.assertTrue(response["metadata"].get("dry_run"))

    results = response["results"]
    observed = response["observed_responses"]
    test.assertIsInstance(results, list)
    test.assertIsInstance(observed, list)

    request_plans = outcome.request.get("probe_plans", [])
    test.assertEqual(len(results), len(request_plans))
    test.assertEqual(len(observed), len(request_plans))

    case_results = [result for result in results if result.get("case") == outcome.case]
    test.assertTrue(
        case_results,
        f"response carries no result for case {outcome.case!r}",
    )
    for result in case_results:
        for key in _RESULT_KEYS:
            test.assertIn(key, result, f"result missing key {key!r}")
        test.assertEqual(result["endpoint_role"], "stimulus")

    case_observed = [
        item for item in observed if item.get("case") == outcome.case
    ]
    test.assertTrue(case_observed)
    for item in case_observed:
        for key in _OBSERVED_KEYS:
            test.assertIn(key, item, f"observed response missing key {key!r}")


def assert_focused_case(
    test: unittest.TestCase,
    case_name: str,
    *,
    out_dir: Path,
    provider: str = DEFAULT_PROVIDER,
    profile: str = DEFAULT_PROFILE,
    seed: int = DEFAULT_SEED,
) -> HarnessOutcome:
    """Run a focused case through the harness and assert request/response shape.

    This is the one-call entry point a per-case step's unit test uses. It skips
    (rather than fails) when the ``cargo`` or ``uv`` toolchains required to drive
    both halves of the stack are unavailable, so the offline-only environments
    do not report a spurious failure.
    """

    if not probe_run_available():
        test.skipTest("probe runner requires uv on PATH")
    if not cargo_available():
        test.skipTest("stimulus endpoint requires cargo on PATH")

    outcome = run_case_through_harness(
        case_name,
        out_dir=out_dir,
        provider=provider,
        profile=profile,
        seed=seed,
    )
    assert_request_shape(test, outcome)
    assert_response_shape(test, outcome)
    return outcome


def _run_probe_dry_run(
    case_name: str,
    *,
    out_dir: Path,
    provider: str,
    profile: str,
    seed: int,
    count: int,
    timeout_seconds: int,
) -> Path:
    argv = [
        str(PROBE_RUN),
        "--provider",
        provider,
        "--dry-run",
        "--profile",
        profile,
        "--seed",
        str(seed),
        "--count",
        str(count),
        "--case",
        case_name,
        "--out",
        str(out_dir),
    ]
    _run_checked(argv, label=f"probe dry-run {case_name}", timeout_seconds=timeout_seconds)
    report_path = out_dir / "report.json"
    if not report_path.is_file():
        raise AssertionError(f"probe dry-run did not write {report_path}")
    return report_path


def _run_stimulus_endpoint(
    request_path: Path,
    *,
    out_dir: Path,
    timeout_seconds: int,
) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    argv = [
        "cargo",
        "run",
        "-q",
        "-p",
        "probe-adapters",
        "--bin",
        "stimulus_endpoint",
        "--",
        "--dry-run",
        "--input",
        str(request_path),
        "--out",
        str(out_dir),
    ]
    _run_checked(argv, label="stimulus endpoint", timeout_seconds=timeout_seconds)
    response_path = out_dir / "response.json"
    if not response_path.is_file():
        raise AssertionError(f"stimulus endpoint did not write {response_path}")
    return response_path


def _run_checked(argv: list[str], *, label: str, timeout_seconds: int) -> None:
    process = subprocess.run(
        argv,
        cwd=REPO_ROOT,
        env={**os.environ},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )
    if process.returncode != 0:
        raise AssertionError(
            f"{label} exited {process.returncode}\n"
            f"argv: {argv}\n"
            f"stdout:\n{process.stdout}\n"
            f"stderr:\n{process.stderr}"
        )


def _load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise AssertionError(f"{path} did not contain a JSON object")
    return data
