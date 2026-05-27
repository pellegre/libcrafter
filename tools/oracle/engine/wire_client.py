"""Oracle-side client for the shared wire endpoint CLI."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TypeAlias

from tools.wire.engine.model import EndpointManifest, JSONObject, JSONValue
from tools.wire.engine.model import read_json as read_wire_json
from tools.wire.engine.process import CommandResult, render_argv, run_command


CommandRunner: TypeAlias = Callable[..., CommandResult]


class WireClientError(RuntimeError):
    """Raised when a wire command cannot be parsed as expected."""


@dataclass(frozen=True, slots=True)
class WireCommandRecord:
    """Captured metadata for one wire CLI invocation."""

    operation: str
    wire_path: str
    argv: tuple[str, ...]
    redacted_argv: tuple[str, ...]
    command: str
    cwd: str | None
    exit_code: int
    ok: bool
    timed_out: bool
    timeout: float | None
    error: str | None
    stdout_bytes: int
    stderr_bytes: int

    def to_dict(self) -> JSONObject:
        return {
            "operation": self.operation,
            "wire_path": self.wire_path,
            "argv": list(self.argv),
            "redacted_argv": list(self.redacted_argv),
            "command": self.command,
            "cwd": self.cwd,
            "exit_code": self.exit_code,
            "ok": self.ok,
            "timed_out": self.timed_out,
            "timeout": self.timeout,
            "error": self.error,
            "stdout_bytes": self.stdout_bytes,
            "stderr_bytes": self.stderr_bytes,
        }


@dataclass(frozen=True, slots=True)
class WireCommandResponse:
    """Result of one wire CLI request plus parsed JSON when available."""

    result: CommandResult
    record: WireCommandRecord
    json_data: JSONObject | None = None
    manifest: EndpointManifest | None = None

    @property
    def ok(self) -> bool:
        return self.result.ok

    @property
    def exit_code(self) -> int:
        return self.result.exit_code

    def metadata(self) -> JSONObject:
        data = self.record.to_dict()
        if self.json_data is not None:
            data["json"] = self.json_data
        if self.manifest is not None:
            data["endpoint_id"] = self.manifest.endpoint_id
            data["manifest"] = self.manifest.to_dict()
        return data


class WireClient:
    """Small process boundary around ``tools/wire/run`` for oracle callers."""

    def __init__(
        self,
        *,
        wire_path: str | Path | None = None,
        runner: CommandRunner = run_command,
        cwd: str | Path | None = None,
        timeout: float | None = None,
    ) -> None:
        self.wire_path = str(Path(wire_path).resolve() if wire_path else default_wire_path())
        self.runner = runner
        self.cwd = str(Path(cwd).resolve()) if cwd is not None else str(repo_root())
        self.timeout = timeout

    def create(
        self,
        *,
        provider: str,
        exposure: str,
        role: str = "libcrafter",
        private_group: str | None = None,
        private_ip: str | None = None,
        dry_run: bool = False,
        write_manifest: bool = True,
        confirm_live_run: bool = False,
    ) -> WireCommandResponse:
        argv: list[str] = [
            "create-endpoint",
            "--provider",
            provider,
            "--exposure",
            exposure,
            "--role",
            role,
            "--json",
        ]
        if private_group is not None:
            argv.extend(["--private-group", private_group])
        if private_ip is not None:
            argv.extend(["--private-ip", private_ip])
        if dry_run:
            argv.append("--dry-run")
        if write_manifest:
            argv.append("--write-manifest")
        if confirm_live_run:
            argv.append("--confirm-live-run")

        response = self._run("create-endpoint", argv, parse_json=True)
        if response.json_data is None:
            raise WireClientError("wire create-endpoint did not emit JSON")
        if not response.ok:
            error = response.json_data.get("error")
            detail = error if isinstance(error, str) and error else f"exit {response.exit_code}"
            raise WireClientError(f"wire create-endpoint failed: {detail}")
        manifest = _create_endpoint_manifest(response.json_data)
        return WireCommandResponse(
            result=response.result,
            record=response.record,
            json_data=response.json_data,
            manifest=manifest,
        )

    def doctor(
        self,
        *,
        provider: str,
        exposure: str,
        dry_run: bool = False,
    ) -> WireCommandResponse:
        argv: list[str] = [
            "doctor",
            "--provider",
            provider,
            "--exposure",
            exposure,
            "--json",
        ]
        if dry_run:
            argv.append("--dry-run")
        return self._run("doctor", argv, parse_json=True)

    def destroy(self, endpoint_id: str) -> WireCommandResponse:
        return self._run(
            "destroy-endpoint",
            ["destroy-endpoint", endpoint_id, "--json"],
            parse_json=True,
        )

    def exec(
        self,
        endpoint_id: str,
        command: Sequence[str],
        *,
        timeout: float | None = None,
    ) -> WireCommandResponse:
        if not command:
            raise ValueError("wire exec requires at least one command argument")
        return self._run(
            "exec",
            ["exec", endpoint_id, "--", *command],
            parse_json=False,
            timeout=timeout,
        )

    def upload(
        self,
        endpoint_id: str,
        local_path: str | Path,
        remote_path: str,
    ) -> WireCommandResponse:
        return self._run(
            "upload",
            ["upload", endpoint_id, str(Path(local_path).resolve()), remote_path],
            parse_json=False,
        )

    def download(
        self,
        endpoint_id: str,
        remote_path: str,
        local_path: str | Path,
    ) -> WireCommandResponse:
        return self._run(
            "download",
            ["download", endpoint_id, remote_path, str(Path(local_path).resolve())],
            parse_json=False,
        )

    def ssh_info(self, endpoint_id: str) -> WireCommandResponse:
        return self._run("ssh-info", ["ssh-info", endpoint_id, "--json"], parse_json=True)

    def collect_artifacts(
        self,
        endpoint_id: str,
        remote_path: str | None = None,
    ) -> WireCommandResponse:
        argv = ["collect-artifacts", endpoint_id]
        if remote_path is not None:
            argv.extend(["--remote", remote_path])
        return self._run("collect-artifacts", argv, parse_json=False)

    def _run(
        self,
        operation: str,
        args: Sequence[str],
        *,
        parse_json: bool,
        timeout: float | None = None,
    ) -> WireCommandResponse:
        argv = [self.wire_path, *args]
        result = self.runner(
            argv,
            cwd=self.cwd,
            timeout=self.timeout if timeout is None else timeout,
        )
        parsed = _parse_json_stdout(result.stdout, operation) if parse_json else None
        record = _record_command(operation, self.wire_path, result)
        return WireCommandResponse(result=result, record=record, json_data=parsed)


def default_wire_path() -> Path:
    """Return the absolute repository-local wire CLI path."""

    return repo_root() / "tools" / "wire" / "run"


def repo_root() -> Path:
    """Return the repository root derived from this module location."""

    return Path(__file__).resolve().parents[3]


def create(
    *,
    provider: str,
    exposure: str,
    role: str = "libcrafter",
    private_group: str | None = None,
    private_ip: str | None = None,
    dry_run: bool = False,
    write_manifest: bool = True,
    confirm_live_run: bool = False,
    client: WireClient | None = None,
) -> WireCommandResponse:
    return (client or WireClient()).create(
        provider=provider,
        exposure=exposure,
        role=role,
        private_group=private_group,
        private_ip=private_ip,
        dry_run=dry_run,
        write_manifest=write_manifest,
        confirm_live_run=confirm_live_run,
    )


def doctor(
    *,
    provider: str,
    exposure: str,
    dry_run: bool = False,
    client: WireClient | None = None,
) -> WireCommandResponse:
    return (client or WireClient()).doctor(
        provider=provider,
        exposure=exposure,
        dry_run=dry_run,
    )


def destroy(endpoint_id: str, *, client: WireClient | None = None) -> WireCommandResponse:
    return (client or WireClient()).destroy(endpoint_id)


def exec(
    endpoint_id: str,
    command: Sequence[str],
    *,
    timeout: float | None = None,
    client: WireClient | None = None,
) -> WireCommandResponse:
    return (client or WireClient()).exec(endpoint_id, command, timeout=timeout)


def upload(
    endpoint_id: str,
    local_path: str | Path,
    remote_path: str,
    *,
    client: WireClient | None = None,
) -> WireCommandResponse:
    return (client or WireClient()).upload(endpoint_id, local_path, remote_path)


def download(
    endpoint_id: str,
    remote_path: str,
    local_path: str | Path,
    *,
    client: WireClient | None = None,
) -> WireCommandResponse:
    return (client or WireClient()).download(endpoint_id, remote_path, local_path)


def ssh_info(endpoint_id: str, *, client: WireClient | None = None) -> WireCommandResponse:
    return (client or WireClient()).ssh_info(endpoint_id)


def collect_artifacts(
    endpoint_id: str,
    remote_path: str | None = None,
    *,
    client: WireClient | None = None,
) -> WireCommandResponse:
    return (client or WireClient()).collect_artifacts(endpoint_id, remote_path)


def _record_command(
    operation: str,
    wire_path: str,
    result: CommandResult,
) -> WireCommandRecord:
    return WireCommandRecord(
        operation=operation,
        wire_path=wire_path,
        argv=result.argv,
        redacted_argv=result.redacted_argv,
        command=render_argv(result.redacted_argv),
        cwd=result.cwd,
        exit_code=result.exit_code,
        ok=result.ok,
        timed_out=result.timed_out,
        timeout=result.timeout,
        error=result.error,
        stdout_bytes=len(result.stdout.encode("utf-8")),
        stderr_bytes=len(result.stderr.encode("utf-8")),
    )


def _parse_json_stdout(stdout: str, operation: str) -> JSONObject:
    try:
        parsed = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise WireClientError(f"wire {operation} emitted invalid JSON: {exc}") from exc
    if not isinstance(parsed, Mapping):
        raise WireClientError(f"wire {operation} emitted non-object JSON")
    return _json_object(parsed)


def _json_object(value: Mapping[str, object]) -> JSONObject:
    output: JSONObject = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise WireClientError("wire JSON object keys must be strings")
        output[key] = _json_value(item)
    return output


def _endpoint_manifest_json(value: JSONObject) -> JSONObject:
    """Return a typed-manifest view of the wire CLI compatibility JSON."""

    manifest = dict(value)
    provider_resources = manifest.get("provider_resources")
    if isinstance(provider_resources, list):
        manifest["provider_resources"] = {
            "resources": provider_resources,
            "cleanup_order": [],
            "metadata": {},
        }
    return manifest


def _create_endpoint_manifest(value: JSONObject) -> EndpointManifest:
    """Parse create-endpoint output, falling back to the stored manifest path."""

    try:
        return EndpointManifest.from_dict(_endpoint_manifest_json(value))
    except (TypeError, ValueError) as exc:
        manifest_path = value.get("manifest_path")
        if isinstance(manifest_path, str) and manifest_path:
            try:
                stored = read_wire_json(manifest_path)
            except (OSError, ValueError) as stored_exc:
                raise WireClientError(
                    "wire create-endpoint JSON is not an endpoint manifest "
                    f"and stored manifest could not be read: {stored_exc}"
                ) from exc
            if isinstance(stored, Mapping):
                return EndpointManifest.from_dict(_endpoint_manifest_json(_json_object(stored)))
        raise WireClientError(
            f"wire create-endpoint JSON is not an endpoint manifest: {exc}"
        ) from exc


def _json_value(value: object) -> JSONValue:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        return _json_object(value)
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    raise WireClientError(f"wire JSON value is not JSON-compatible: {value!r}")
