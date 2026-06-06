"""Lab-side client for the shared endpoint CLI."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TypeAlias

from tools.endpoint.engine.model import EndpointManifest
from tools.endpoint.engine.model import read_json as read_endpoint_json

from .model import JSONValue, JSONObject, LabCommandPlan
from .process import CommandResult, render_argv, run_command


CommandRunner: TypeAlias = Callable[..., CommandResult]


class EndpointClientError(RuntimeError):
    """Raised when an endpoint command cannot be parsed as expected."""


@dataclass(frozen=True, slots=True)
class EndpointCommandRecord:
    """Redacted metadata for one endpoint CLI invocation."""

    operation: str
    endpoint_command: str
    endpoint_path: str
    argv: tuple[str, ...]
    command: str
    cwd: str | None
    exit_code: int
    ok: bool
    timed_out: bool
    timeout: float | None
    error: str | None
    stdout_bytes: int
    stderr_bytes: int
    dry_run: bool
    live_mutation: bool

    def to_dict(self) -> JSONObject:
        return {
            "operation": self.operation,
            "endpoint_command": self.endpoint_command,
            "endpoint_path": self.endpoint_path,
            "argv": list(self.argv),
            "redacted_argv": list(self.argv),
            "command": self.command,
            "cwd": self.cwd,
            "exit_code": self.exit_code,
            "ok": self.ok,
            "timed_out": self.timed_out,
            "timeout": self.timeout,
            "error": self.error,
            "stdout_bytes": self.stdout_bytes,
            "stderr_bytes": self.stderr_bytes,
            "dry_run": self.dry_run,
            "live_mutation": self.live_mutation,
        }

    def to_command_plan(
        self,
        *,
        purpose: str | None = None,
        role: str | None = None,
        artifacts: Sequence[str] = (),
    ) -> LabCommandPlan:
        """Return this record in the lab command-record shape."""

        return LabCommandPlan(
            purpose=purpose or f"endpoint {self.operation}",
            role=role,
            argv=list(self.argv),
            operation=f"endpoint.{self.operation}",
            dry_run=self.dry_run,
            live_mutation=self.live_mutation,
            artifacts=list(artifacts),
            metadata=self.to_dict(),
        )


@dataclass(frozen=True, slots=True)
class EndpointCommandResponse:
    """Result of one endpoint CLI request plus parsed JSON when available."""

    result: CommandResult
    record: EndpointCommandRecord
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

    def command_plan(
        self,
        *,
        purpose: str | None = None,
        role: str | None = None,
        artifacts: Sequence[str] = (),
    ) -> LabCommandPlan:
        return self.record.to_command_plan(
            purpose=purpose,
            role=role,
            artifacts=artifacts,
        )


class EndpointClient:
    """Small process boundary around ``tools/endpoint/run`` for lab callers."""

    def __init__(
        self,
        *,
        endpoint_path: str | Path | None = None,
        runner: CommandRunner = run_command,
        cwd: str | Path | None = None,
        timeout: float | None = None,
    ) -> None:
        self.endpoint_path = str(
            Path(endpoint_path).resolve() if endpoint_path else default_endpoint_path()
        )
        self.runner = runner
        self.cwd = str(Path(cwd).resolve()) if cwd is not None else str(repo_root())
        self.timeout = timeout

    def doctor(
        self,
        *,
        provider: str,
        exposure: str,
        dry_run: bool = False,
    ) -> EndpointCommandResponse:
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
        return self._run(
            "doctor",
            argv,
            parse_json=True,
            dry_run=dry_run,
            live_mutation=False,
        )

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
    ) -> EndpointCommandResponse:
        argv: list[str] = [
            "create",
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

        response = self._run(
            "create",
            argv,
            parse_json=True,
            dry_run=dry_run,
            live_mutation=not dry_run,
        )
        if response.json_data is None:
            raise EndpointClientError("endpoint create did not emit JSON")
        if not response.ok:
            error = response.json_data.get("error")
            detail = error if isinstance(error, str) and error else f"exit {response.exit_code}"
            raise EndpointClientError(f"endpoint create failed: {detail}")
        manifest = _create_endpoint_manifest(response.json_data)
        return EndpointCommandResponse(
            result=response.result,
            record=response.record,
            json_data=response.json_data,
            manifest=manifest,
        )

    def destroy(self, endpoint_id: str) -> EndpointCommandResponse:
        return self._run(
            "destroy",
            ["destroy", endpoint_id, "--json"],
            parse_json=True,
            dry_run=False,
            live_mutation=True,
        )

    def exec(
        self,
        endpoint_id: str,
        command: Sequence[str],
        *,
        timeout: float | None = None,
    ) -> EndpointCommandResponse:
        if not command:
            raise ValueError("endpoint exec requires at least one command argument")
        return self._run(
            "exec",
            ["exec", endpoint_id, "--", *command],
            parse_json=False,
            timeout=timeout,
            dry_run=False,
            live_mutation=True,
        )

    def upload(
        self,
        endpoint_id: str,
        local_path: str | Path,
        remote_path: str,
    ) -> EndpointCommandResponse:
        return self._run(
            "upload",
            ["upload", endpoint_id, str(Path(local_path).resolve()), remote_path],
            parse_json=False,
            dry_run=False,
            live_mutation=True,
        )

    def download(
        self,
        endpoint_id: str,
        remote_path: str,
        local_path: str | Path,
    ) -> EndpointCommandResponse:
        return self._run(
            "download",
            ["download", endpoint_id, remote_path, str(Path(local_path).resolve())],
            parse_json=False,
            dry_run=False,
            live_mutation=False,
        )

    def ssh_info(self, endpoint_id: str) -> EndpointCommandResponse:
        return self._run(
            "ssh_info",
            ["ssh-info", endpoint_id, "--json"],
            parse_json=True,
            dry_run=False,
            live_mutation=False,
        )

    def collect_artifacts(
        self,
        endpoint_id: str,
        remote_path: str | None = None,
    ) -> EndpointCommandResponse:
        argv = ["collect-artifacts", endpoint_id]
        if remote_path is not None:
            argv.extend(["--remote", remote_path])
        return self._run(
            "collect_artifacts",
            argv,
            parse_json=False,
            dry_run=False,
            live_mutation=False,
        )

    def _run(
        self,
        operation: str,
        args: Sequence[str],
        *,
        parse_json: bool,
        dry_run: bool,
        live_mutation: bool,
        timeout: float | None = None,
    ) -> EndpointCommandResponse:
        argv = [self.endpoint_path, *args]
        result = self.runner(
            argv,
            cwd=self.cwd,
            timeout=self.timeout if timeout is None else timeout,
        )
        parsed = _parse_json_stdout(result.stdout, operation) if parse_json else None
        record = _record_command(
            operation,
            endpoint_command=args[0],
            endpoint_path=self.endpoint_path,
            result=result,
            dry_run=dry_run,
            live_mutation=live_mutation,
        )
        return EndpointCommandResponse(result=result, record=record, json_data=parsed)


def default_endpoint_path() -> Path:
    """Return the absolute repository-local endpoint CLI path."""

    return repo_root() / "tools" / "endpoint" / "run"


def repo_root() -> Path:
    """Return the repository root derived from this module location."""

    return Path(__file__).resolve().parents[3]


def doctor(
    *,
    provider: str,
    exposure: str,
    dry_run: bool = False,
    client: EndpointClient | None = None,
) -> EndpointCommandResponse:
    return (client or EndpointClient()).doctor(
        provider=provider,
        exposure=exposure,
        dry_run=dry_run,
    )


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
    client: EndpointClient | None = None,
) -> EndpointCommandResponse:
    return (client or EndpointClient()).create(
        provider=provider,
        exposure=exposure,
        role=role,
        private_group=private_group,
        private_ip=private_ip,
        dry_run=dry_run,
        write_manifest=write_manifest,
        confirm_live_run=confirm_live_run,
    )


def destroy(endpoint_id: str, *, client: EndpointClient | None = None) -> EndpointCommandResponse:
    return (client or EndpointClient()).destroy(endpoint_id)


def exec(
    endpoint_id: str,
    command: Sequence[str],
    *,
    timeout: float | None = None,
    client: EndpointClient | None = None,
) -> EndpointCommandResponse:
    return (client or EndpointClient()).exec(endpoint_id, command, timeout=timeout)


def upload(
    endpoint_id: str,
    local_path: str | Path,
    remote_path: str,
    *,
    client: EndpointClient | None = None,
) -> EndpointCommandResponse:
    return (client or EndpointClient()).upload(endpoint_id, local_path, remote_path)


def download(
    endpoint_id: str,
    remote_path: str,
    local_path: str | Path,
    *,
    client: EndpointClient | None = None,
) -> EndpointCommandResponse:
    return (client or EndpointClient()).download(endpoint_id, remote_path, local_path)


def ssh_info(endpoint_id: str, *, client: EndpointClient | None = None) -> EndpointCommandResponse:
    return (client or EndpointClient()).ssh_info(endpoint_id)


def collect_artifacts(
    endpoint_id: str,
    remote_path: str | None = None,
    *,
    client: EndpointClient | None = None,
) -> EndpointCommandResponse:
    return (client or EndpointClient()).collect_artifacts(endpoint_id, remote_path)


def _record_command(
    operation: str,
    *,
    endpoint_command: str,
    endpoint_path: str,
    result: CommandResult,
    dry_run: bool,
    live_mutation: bool,
) -> EndpointCommandRecord:
    redacted_argv = result.redacted_argv
    return EndpointCommandRecord(
        operation=operation,
        endpoint_command=endpoint_command,
        endpoint_path=endpoint_path,
        argv=redacted_argv,
        command=render_argv(redacted_argv),
        cwd=result.cwd,
        exit_code=result.exit_code,
        ok=result.ok,
        timed_out=result.timed_out,
        timeout=result.timeout,
        error=result.error,
        stdout_bytes=len(result.stdout.encode("utf-8")),
        stderr_bytes=len(result.stderr.encode("utf-8")),
        dry_run=dry_run,
        live_mutation=live_mutation,
    )


def _parse_json_stdout(stdout: str, operation: str) -> JSONObject:
    try:
        parsed = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise EndpointClientError(f"endpoint {operation} emitted invalid JSON: {exc}") from exc
    if not isinstance(parsed, Mapping):
        raise EndpointClientError(f"endpoint {operation} emitted non-object JSON")
    return _json_object(parsed)


def _json_object(value: Mapping[str, object]) -> JSONObject:
    output: JSONObject = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise EndpointClientError("endpoint JSON object keys must be strings")
        output[key] = _json_value(item)
    return output


def _endpoint_manifest_json(value: JSONObject) -> JSONObject:
    """Return a typed-manifest view of the endpoint CLI JSON."""

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
    """Parse create output, falling back to the stored manifest path."""

    try:
        return EndpointManifest.from_dict(_endpoint_manifest_json(value))
    except (TypeError, ValueError) as exc:
        manifest_path = value.get("manifest_path")
        if isinstance(manifest_path, str) and manifest_path:
            try:
                stored = read_endpoint_json(manifest_path)
            except (OSError, ValueError) as stored_exc:
                raise EndpointClientError(
                    "endpoint create JSON is not an endpoint manifest "
                    f"and stored manifest could not be read: {stored_exc}"
                ) from exc
            if isinstance(stored, Mapping):
                return EndpointManifest.from_dict(_endpoint_manifest_json(_json_object(stored)))
        raise EndpointClientError(
            f"endpoint create JSON is not an endpoint manifest: {exc}"
        ) from exc


def _json_value(value: object) -> JSONValue:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        return _json_object(value)
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    raise EndpointClientError(f"endpoint JSON value is not JSON-compatible: {value!r}")
