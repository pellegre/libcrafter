"""Output, report-path, and command-IO helpers for the probe CLI.

These are pure orchestration-only concerns lifted out of :mod:`engine.cli.main`
without any behavior change. None of them are mock-patched or read as ``cli``
attributes by the test suite, so they can live in a focused module; the names a
function still referenced from the CLI body (``_report_path``) are re-imported
back into the body's namespace so its call sites resolve identically.

Contents:

* ``_report_path`` / ``_run_name`` / ``_slug`` — derive the report.json output
  path from the request and run status; and
* ``_run_command`` / ``_redacted_argv`` — run a subprocess, persist its
  stdout/stderr artifacts, and redact secrets from the recorded argv.
"""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from pathlib import Path

from ..live import parse_json_stdout as _parse_json_stdout
from ..model import JSONObject, ProbeRunRequest
from ..report import DEFAULT_OUTPUT_ROOT, REPO_ROOT


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
