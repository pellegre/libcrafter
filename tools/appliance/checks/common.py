"""Shared helpers for appliance readiness check scripts."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import TextIO


CommandRunner = Callable[[Sequence[str]], object]


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Small normalized command result used by mocked and real runners."""

    returncode: int
    stdout: str = ""
    stderr: str = ""


def environment(environ: Mapping[str, str] | None) -> Mapping[str, str]:
    """Return the supplied environment or the process environment."""

    return os.environ if environ is None else environ


def resolve_value(
    *,
    explicit: str,
    env_name: str,
    environ: Mapping[str, str],
) -> tuple[str, str]:
    """Resolve an explicit CLI value or an environment-backed value."""

    if explicit:
        return explicit, ""
    return environ.get(env_name, ""), env_name


def run_command(
    argv: Sequence[str],
    *,
    runner: CommandRunner | None = None,
    timeout_seconds: float = 5.0,
) -> CommandResult:
    """Run a non-interactive command and normalize real or mocked results."""

    command = list(argv)
    try:
        if runner is None:
            result = subprocess.run(
                command,
                capture_output=True,
                check=False,
                text=True,
                timeout=timeout_seconds,
            )
        else:
            result = runner(command)
    except FileNotFoundError as exc:
        return CommandResult(returncode=127, stderr=str(exc))
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        if stderr:
            stderr = f"{stderr}\ncommand timed out"
        else:
            stderr = "command timed out"
        return CommandResult(returncode=124, stdout=stdout, stderr=stderr)

    return normalize_command_result(result)


def normalize_command_result(result: object) -> CommandResult:
    """Convert subprocess.CompletedProcess-like objects to CommandResult."""

    return CommandResult(
        returncode=int(getattr(result, "returncode", 0)),
        stdout=_text(getattr(result, "stdout", "")),
        stderr=_text(getattr(result, "stderr", "")),
    )


def command_fields(result: CommandResult) -> dict[str, object]:
    """Return stable JSON fields for a completed command."""

    fields: dict[str, object] = {"returncode": result.returncode}
    if result.stdout:
        fields["stdout"] = result.stdout.strip()
    if result.stderr:
        fields["stderr"] = result.stderr.strip()
    return fields


def failure(check: str, error: str, message: str, **fields: object) -> dict[str, object]:
    """Build a structured failure payload."""

    payload: dict[str, object] = {
        "ok": False,
        "check": check,
        "error": error,
        "message": message,
    }
    payload.update(fields)
    return payload


def write_json(payload: Mapping[str, object], stdout: TextIO = sys.stdout) -> None:
    """Write deterministic JSON to stdout."""

    stdout.write(json.dumps(payload, indent=2, sort_keys=True))
    stdout.write("\n")


def _text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)
