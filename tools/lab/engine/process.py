"""Portable process execution helpers for lab integrations."""

from __future__ import annotations

import os
import shlex
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path


REDACTION = "<redacted>"

_SECRET_OPTION_NAMES = frozenset(
    {
        "-p",
        "--password",
        "--passphrase",
        "--secret",
        "--token",
        "--api-token",
        "--access-token",
        "--auth-token",
        "--bearer-token",
        "--private-key",
        "--identity-file",
    }
)
_SECRET_NAME_PARTS = ("password", "passwd", "passphrase", "secret", "token", "credential")


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Captured result from one command invocation."""

    argv: tuple[str, ...]
    redacted_argv: tuple[str, ...]
    cwd: str | None
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    timeout: float | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        """Return whether the command exited successfully."""

        return self.exit_code == 0 and not self.timed_out

    @property
    def command(self) -> str:
        """Return a shell-quoted, redacted command string for reports."""

        return render_argv(self.redacted_argv)


def run_command(
    argv: Sequence[object],
    *,
    env: Mapping[str, object] | None = None,
    cwd: str | Path | None = None,
    timeout: float | None = None,
    capture_stdout: bool = True,
    capture_stderr: bool = True,
    merge_env: bool = True,
) -> CommandResult:
    """Run a command without a shell and return captured process details.

    By default, custom environment values are overlaid on ``os.environ``. Pass
    ``merge_env=False`` to run with exactly the supplied environment mapping.
    """

    normalized_argv = _normalize_argv(argv)
    normalized_cwd = _normalize_cwd(cwd)
    process_env = _build_env(env, merge_env=merge_env)
    stdout_target = subprocess.PIPE if capture_stdout else subprocess.DEVNULL
    stderr_target = subprocess.PIPE if capture_stderr else subprocess.DEVNULL

    try:
        completed = subprocess.run(
            normalized_argv,
            cwd=normalized_cwd,
            env=process_env,
            timeout=timeout,
            stdout=stdout_target,
            stderr=stderr_target,
            text=True,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            argv=normalized_argv,
            redacted_argv=tuple(redact_argv(normalized_argv)),
            cwd=normalized_cwd,
            exit_code=124,
            stdout=_output_to_text(exc.stdout),
            stderr=_output_to_text(exc.stderr),
            timed_out=True,
            timeout=timeout,
            error=f"command timed out after {timeout} seconds",
        )
    except OSError as exc:
        return CommandResult(
            argv=normalized_argv,
            redacted_argv=tuple(redact_argv(normalized_argv)),
            cwd=normalized_cwd,
            exit_code=127,
            stdout="",
            stderr="",
            timeout=timeout,
            error=str(exc),
        )

    return CommandResult(
        argv=normalized_argv,
        redacted_argv=tuple(redact_argv(normalized_argv)),
        cwd=normalized_cwd,
        exit_code=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
        timeout=timeout,
    )


def redact_argv(argv: Sequence[object]) -> list[str]:
    """Return argv with likely secret values replaced for report output."""

    parts = [str(part) for part in argv]
    redacted: list[str] = []
    redact_next = False

    for part in parts:
        if redact_next:
            redacted.append(REDACTION)
            redact_next = False
            continue

        option_name, separator, _ = part.partition("=")
        if separator and _is_secret_name(option_name):
            redacted.append(f"{option_name}={REDACTION}")
            continue

        redacted.append(part)
        if _is_secret_name(part):
            redact_next = True

    return redacted


def render_argv(argv: Sequence[object]) -> str:
    """Return a shell-quoted command string suitable for logs and reports."""

    return " ".join(shlex.quote(str(part)) for part in argv)


def _normalize_argv(argv: Sequence[object]) -> tuple[str, ...]:
    parts = tuple(str(part) for part in argv)
    if not parts:
        raise ValueError("argv must contain at least one command argument")
    if parts[0] == "":
        raise ValueError("argv command must not be an empty string")
    return parts


def _normalize_cwd(cwd: str | Path | None) -> str | None:
    if cwd is None:
        return None
    return str(Path(cwd).expanduser())


def _build_env(
    env: Mapping[str, object] | None,
    *,
    merge_env: bool,
) -> dict[str, str] | None:
    if env is None:
        return None
    normalized = {str(key): str(value) for key, value in env.items()}
    if not merge_env:
        return normalized
    merged = dict(os.environ)
    merged.update(normalized)
    return merged


def _is_secret_name(value: str) -> bool:
    normalized = value.strip().lower().replace("_", "-")
    if normalized in _SECRET_OPTION_NAMES:
        return True
    return any(part in normalized for part in _SECRET_NAME_PARTS)


def _output_to_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value
