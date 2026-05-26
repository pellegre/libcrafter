"""Small wrappers around the hcloud command line."""

from __future__ import annotations

import json
from collections.abc import Mapping

from ...process import CommandResult, run_command
from .constants import HCLOUD_COMMAND, HcloudRunner
from .utils import _command_error, _json_object



def _hcloud_json(
    argv: list[str],
    *,
    env: Mapping[str, str],
    command_runner: HcloudRunner = run_command,
) -> dict[str, object]:
    result = command_runner(argv, env=env, timeout=180)
    if not result.ok:
        raise RuntimeError(_command_error("hcloud command failed", result))
    return _parse_hcloud_json(result)


def _hcloud_json_optional(
    argv: list[str],
    *,
    env: Mapping[str, str],
    command_runner: HcloudRunner,
) -> dict[str, object] | None:
    result = command_runner(argv, env=env, timeout=180)
    if not result.ok:
        if _is_missing_resource_result(result):
            return None
        raise RuntimeError(_command_error("hcloud command failed", result))
    return _parse_hcloud_json(result)


def _hcloud_ok(
    argv: list[str],
    *,
    env: Mapping[str, str],
    command_runner: HcloudRunner,
) -> CommandResult:
    result = command_runner(argv, env=env, timeout=180)
    if not result.ok:
        raise RuntimeError(_command_error("hcloud command failed", result))
    return result


def _parse_hcloud_json(result: CommandResult) -> dict[str, object]:
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"hcloud command did not emit valid JSON: {result.command}") from exc
    return _json_object(value, "hcloud output")


def _is_missing_resource_result(result: CommandResult) -> bool:
    text = " ".join(
        part.strip().lower() for part in (result.stderr, result.stdout, result.error or "")
    )
    missing_markers = (
        "not found",
        "not_found",
        "404",
        "does not exist",
        "no such",
        "could not find",
        "was not found",
        "already deleted",
        "not attached",
        "already detached",
    )
    return any(marker in text for marker in missing_markers)


def _hcloud_cleanup(argv: list[str], *, env: Mapping[str, str]) -> None:
    run_command(argv, env=env, timeout=120)
