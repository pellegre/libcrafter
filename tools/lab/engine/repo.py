"""Repository archive and endpoint bootstrap helpers for lab sessions."""

from __future__ import annotations

import posixpath
import shlex
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TypeAlias

from .model import (
    JSONObject,
    LabCommandPlan,
    LabEndpoint,
    LabRole,
    LabSession,
    json_object,
    write_json,
)
from .process import CommandResult, render_argv, run_command
from .providers.common import validate_remote_dir
from .wire_client import WireClient, repo_root


DEFAULT_REPO_ARCHIVE_NAME = "libcrafter-repo.tar.gz"
DEFAULT_ARCHIVE_EXCLUDES = (
    ".git",
    "target",
    ".scratch",
    ".libcrafter-live",
    "artifacts",
    "generated",
    "tools/endpoint/.state",
    "tools/endpoint/artifacts",
    "tools/lab/.state",
    "tools/lab/artifacts",
)
DEFAULT_BOOTSTRAP_TIMEOUT_SECONDS = 1800.0
DEFAULT_REMOTE_COMMAND_TIMEOUT_SECONDS = 900.0
WIRE_ENTRYPOINT = "tools/endpoint/run"


class RepoArchiveError(RuntimeError):
    """Raised when the repository archive cannot be created."""


class RepoPushError(RuntimeError):
    """Raised when a repository push request is structurally invalid."""


@dataclass(frozen=True, slots=True)
class RepoArchiveResult:
    """Local repository archive path and command metadata."""

    archive_path: Path
    stdout_path: Path
    stderr_path: Path
    command_record: LabCommandPlan

    def to_dict(self) -> JSONObject:
        return {
            "archive_path": str(self.archive_path),
            "stdout_path": str(self.stdout_path),
            "stderr_path": str(self.stderr_path),
            "command_record": self.command_record.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class RepoBootstrapCommand:
    """Workload-supplied command to run after lab unpacks the repository."""

    argv: list[str]
    timeout: float | None = DEFAULT_BOOTSTRAP_TIMEOUT_SECONDS
    metadata: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.argv, Sequence) or isinstance(
            self.argv,
            (str, bytes, bytearray),
        ):
            raise ValueError("bootstrap argv must be a non-empty sequence")
        argv = [str(part) for part in self.argv]
        if not argv or any(part == "" for part in argv):
            raise ValueError("bootstrap argv must be a non-empty sequence")
        object.__setattr__(self, "argv", argv)
        if self.timeout is not None:
            if isinstance(self.timeout, bool) or float(self.timeout) <= 0:
                raise ValueError("bootstrap timeout must be positive")
            object.__setattr__(self, "timeout", float(self.timeout))
        object.__setattr__(
            self,
            "metadata",
            json_object(self.metadata, "bootstrap.metadata"),
        )


@dataclass(frozen=True, slots=True)
class RepoBootstrapContext:
    """Context passed to workload-owned bootstrap command hooks."""

    session: LabSession
    endpoint: LabEndpoint
    role: LabRole
    remote_archive: str
    remote_dir: str
    remote_artifact_root: str
    endpoints_by_role: Mapping[str, LabEndpoint]

    @property
    def peer_endpoints(self) -> tuple[LabEndpoint, ...]:
        peer_roles = self.role.peer_roles
        if peer_roles:
            return tuple(
                endpoint
                for role, endpoint in self.endpoints_by_role.items()
                if role in peer_roles
            )
        return tuple(
            endpoint
            for role, endpoint in self.endpoints_by_role.items()
            if role != self.endpoint.role
        )

    def to_dict(self) -> JSONObject:
        return {
            "session_id": self.session.session_id,
            "provider": self.session.provider,
            "role": self.role.name,
            "endpoint_id": self.endpoint.endpoint_id,
            "remote_archive": self.remote_archive,
            "remote_dir": self.remote_dir,
            "remote_artifact_root": self.remote_artifact_root,
            "peer_roles": [endpoint.role for endpoint in self.peer_endpoints],
        }


BootstrapHook: TypeAlias = Callable[[RepoBootstrapContext], object]
BootstrapCommandSpec: TypeAlias = RepoBootstrapCommand | Sequence[object] | BootstrapHook | None


@dataclass(frozen=True, slots=True)
class RepoPushResult:
    """Result of pushing one archive to all endpoints in a lab session."""

    archive_path: Path
    remote_archive: str
    remote_dir: str
    command_records: list[LabCommandPlan]
    endpoint_results: list[JSONObject]
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors and all(
            bool(endpoint.get("ok", False)) for endpoint in self.endpoint_results
        )

    def to_dict(self) -> JSONObject:
        return {
            "ok": self.ok,
            "archive_path": str(self.archive_path),
            "remote_archive": self.remote_archive,
            "remote_dir": self.remote_dir,
            "command_records": [record.to_dict() for record in self.command_records],
            "endpoint_results": list(self.endpoint_results),
            "errors": list(self.errors),
        }


@dataclass(frozen=True, slots=True)
class LabBootstrapResult:
    """Provider-neutral result of repository upload and workload bootstrap."""

    archive_path: Path
    output_dir: Path
    remote_archive: str
    remote_dir: str
    remote_artifact_root: str
    command_records: list[LabCommandPlan]
    endpoint_results: list[JSONObject]
    artifacts: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors and all(
            bool(endpoint.get("ok", False)) for endpoint in self.endpoint_results
        )

    def to_dict(self) -> JSONObject:
        return {
            "ok": self.ok,
            "archive_path": str(self.archive_path),
            "output_dir": str(self.output_dir),
            "remote_archive": self.remote_archive,
            "remote_dir": self.remote_dir,
            "remote_artifact_root": self.remote_artifact_root,
            "command_records": [record.to_dict() for record in self.command_records],
            "endpoint_results": list(self.endpoint_results),
            "artifacts": list(self.artifacts),
            "errors": list(self.errors),
        }


def create_repository_archive(
    output_dir: str | Path,
    *,
    source_root: str | Path | None = None,
    archive_name: str = DEFAULT_REPO_ARCHIVE_NAME,
    extra_excludes: Sequence[str] = (),
    runner: Callable[..., CommandResult] = run_command,
) -> RepoArchiveResult:
    """Create a compressed repository archive for upload to lab endpoints."""

    source = _absolute_existing_dir(source_root or repo_root(), "source_root")
    artifact_dir = Path(output_dir).expanduser()
    if not artifact_dir.is_absolute():
        artifact_dir = Path.cwd() / artifact_dir
    artifact_dir = artifact_dir.resolve(strict=False)
    artifact_dir.mkdir(parents=True, exist_ok=True)

    archive_path = artifact_dir / _archive_name(archive_name)
    stdout_path = artifact_dir / "repo-archive.stdout.txt"
    stderr_path = artifact_dir / "repo-archive.stderr.txt"
    excludes = _archive_excludes(
        source_root=source,
        archive_path=archive_path,
        artifact_dir=artifact_dir,
        extra_excludes=extra_excludes,
    )
    argv = [
        "tar",
        "-C",
        str(source),
        *[f"--exclude={exclude}" for exclude in excludes],
        "-czf",
        str(archive_path),
        ".",
    ]
    result = runner(argv, cwd=source)
    stdout_path.write_text(result.stdout, encoding="utf-8")
    stderr_path.write_text(result.stderr, encoding="utf-8")

    command_record = _local_command_plan(
        result,
        purpose="create repository archive",
        operation="lab.repo_archive",
        artifacts=[archive_path, stdout_path, stderr_path],
        metadata={
            "archive_path": str(archive_path),
            "source_root": str(source),
            "exclude_patterns": list(excludes),
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
        },
    )
    if not result.ok:
        detail = result.error or result.stderr.strip() or f"exit {result.exit_code}"
        raise RepoArchiveError(f"failed to create repository archive: {detail}")
    return RepoArchiveResult(
        archive_path=archive_path,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        command_record=command_record,
    )


def push_repository_to_session(
    session: LabSession,
    archive: str | Path | RepoArchiveResult,
    *,
    client: WireClient | None = None,
    remote_dir: str | None = None,
    archive_name: str = DEFAULT_REPO_ARCHIVE_NAME,
    bootstrap_commands: Mapping[str, BootstrapCommandSpec] | None = None,
    remote_command_timeout: float | None = DEFAULT_REMOTE_COMMAND_TIMEOUT_SECONDS,
    output_dir: str | Path | None = None,
) -> RepoPushResult:
    """Upload and unpack a repository archive on each endpoint in ``session``."""

    if not isinstance(session, LabSession):
        raise TypeError("session must be a LabSession")
    if session.dry_run:
        raise RepoPushError("repository push requires a live lab session")
    if not session.endpoints:
        raise RepoPushError("repository push requires at least one endpoint")

    archive_path = _archive_path(archive)
    if not archive_path.is_file():
        raise RepoPushError(f"repository archive does not exist: {archive_path}")
    target_dir = _repo_remote_dir(remote_dir or session.remote_dir)
    target_artifact_root = (
        posixpath.join(target_dir, "artifacts")
        if remote_dir is not None
        else _remote_artifact_root(session, target_dir)
    )
    remote_archive = _remote_archive_path(target_dir, archive_name)
    wire = client or WireClient()
    hooks = dict(bootstrap_commands or {})
    roles_by_name = {role.name: role for role in session.roles}
    endpoints_by_role = {endpoint.role: endpoint for endpoint in session.endpoints}
    artifact_root = _optional_output_dir(output_dir)
    command_records: list[LabCommandPlan] = []
    endpoint_results: list[JSONObject] = []
    errors: list[str] = []

    for endpoint in session.endpoints:
        endpoint_artifact_dir = _endpoint_artifact_dir(artifact_root, endpoint)
        role = roles_by_name.get(endpoint.role, LabRole(name=endpoint.role))
        context = RepoBootstrapContext(
            session=session,
            endpoint=endpoint,
            role=role,
            remote_archive=remote_archive,
            remote_dir=target_dir,
            remote_artifact_root=target_artifact_root,
            endpoints_by_role=endpoints_by_role,
        )
        endpoint_commands: list[LabCommandPlan] = []
        endpoint_errors: list[str] = []

        _run_endpoint_step(
            wire.exec,
            endpoint.endpoint_id,
            _ensure_remote_parent_command(remote_archive),
            purpose="prepare remote repository archive directory",
            role=endpoint.role,
            operation="wire.exec",
            fallback_argv=[
                WIRE_ENTRYPOINT,
                "exec",
                endpoint.endpoint_id,
                "--",
                *_ensure_remote_parent_command(remote_archive),
            ],
            timeout=remote_command_timeout,
            metadata={
                "endpoint_id": endpoint.endpoint_id,
                "remote_archive": remote_archive,
                "remote_parent": posixpath.dirname(remote_archive.rstrip("/")) or "/",
                "phase": "prepare-archive-directory",
            },
            command_records=command_records,
            endpoint_commands=endpoint_commands,
            endpoint_errors=endpoint_errors,
            artifact_dir=endpoint_artifact_dir,
            artifact_label="01-prepare-archive-directory",
        )
        if endpoint_errors:
            endpoint_results.append(_endpoint_result(endpoint, endpoint_commands, endpoint_errors))
            errors.extend(endpoint_errors)
            continue

        _run_upload_step(
            wire,
            endpoint,
            archive_path,
            remote_archive,
            command_records=command_records,
            endpoint_commands=endpoint_commands,
            endpoint_errors=endpoint_errors,
            artifact_dir=endpoint_artifact_dir,
            artifact_label="02-upload-repository",
        )
        if endpoint_errors:
            endpoint_results.append(_endpoint_result(endpoint, endpoint_commands, endpoint_errors))
            errors.extend(endpoint_errors)
            continue

        _run_endpoint_step(
            wire.exec,
            endpoint.endpoint_id,
            _unpack_repository_command(
                remote_archive=remote_archive,
                remote_dir=target_dir,
                remote_artifact_root=target_artifact_root,
            ),
            purpose="unpack repository archive",
            role=endpoint.role,
            operation="wire.exec",
            fallback_argv=[
                WIRE_ENTRYPOINT,
                "exec",
                endpoint.endpoint_id,
                "--",
                *_unpack_repository_command(
                    remote_archive=remote_archive,
                    remote_dir=target_dir,
                    remote_artifact_root=target_artifact_root,
                ),
            ],
            timeout=remote_command_timeout,
            metadata={
                "endpoint_id": endpoint.endpoint_id,
                "remote_archive": remote_archive,
                "remote_dir": target_dir,
                "remote_artifact_root": target_artifact_root,
                "phase": "unpack-repository",
            },
            command_records=command_records,
            endpoint_commands=endpoint_commands,
            endpoint_errors=endpoint_errors,
            artifact_dir=endpoint_artifact_dir,
            artifact_label="03-unpack-repository",
        )
        if endpoint_errors:
            endpoint_results.append(_endpoint_result(endpoint, endpoint_commands, endpoint_errors))
            errors.extend(endpoint_errors)
            continue

        bootstrap = _bootstrap_command_for(hooks, context)
        if bootstrap is not None:
            _run_endpoint_step(
                wire.exec,
                endpoint.endpoint_id,
                bootstrap.argv,
                purpose="run workload bootstrap",
                role=endpoint.role,
                operation="wire.exec",
                fallback_argv=[
                    WIRE_ENTRYPOINT,
                    "exec",
                    endpoint.endpoint_id,
                    "--",
                    *bootstrap.argv,
                ],
                timeout=bootstrap.timeout,
                metadata={
                    "endpoint_id": endpoint.endpoint_id,
                    "remote_archive": remote_archive,
                    "remote_dir": target_dir,
                    "remote_artifact_root": target_artifact_root,
                    "phase": "workload-bootstrap",
                    "bootstrap": bootstrap.metadata,
                    "context": context.to_dict(),
                },
                command_records=command_records,
                endpoint_commands=endpoint_commands,
                endpoint_errors=endpoint_errors,
                artifact_dir=endpoint_artifact_dir,
                artifact_label="04-workload-bootstrap",
            )

        endpoint_results.append(_endpoint_result(endpoint, endpoint_commands, endpoint_errors))
        errors.extend(endpoint_errors)

    return RepoPushResult(
        archive_path=archive_path,
        remote_archive=remote_archive,
        remote_dir=target_dir,
        command_records=command_records,
        endpoint_results=endpoint_results,
        errors=errors,
    )


def bootstrap_lab_session(
    session: LabSession,
    bootstrap_commands: Mapping[str, BootstrapCommandSpec],
    *,
    remote_dir: str,
    archive: str | Path | RepoArchiveResult,
    output_dir: str | Path,
    client: WireClient | None = None,
    archive_name: str | None = None,
    remote_command_timeout: float | None = DEFAULT_REMOTE_COMMAND_TIMEOUT_SECONDS,
) -> LabBootstrapResult:
    """Upload a repository archive and run workload bootstrap on lab endpoints."""

    if not isinstance(bootstrap_commands, Mapping):
        raise ValueError("bootstrap_commands must be a role-to-command mapping")
    archive_path = _archive_path(archive)
    artifact_root = _output_dir(output_dir)
    push_result = push_repository_to_session(
        session,
        archive,
        client=client,
        remote_dir=remote_dir,
        archive_name=archive_name or archive_path.name,
        bootstrap_commands=bootstrap_commands,
        remote_command_timeout=remote_command_timeout,
        output_dir=artifact_root,
    )
    result = LabBootstrapResult(
        archive_path=push_result.archive_path,
        output_dir=artifact_root,
        remote_archive=push_result.remote_archive,
        remote_dir=push_result.remote_dir,
        remote_artifact_root=_bootstrap_remote_artifact_root(
            session=session,
            remote_dir=push_result.remote_dir,
            requested_remote_dir=remote_dir,
        ),
        command_records=push_result.command_records,
        endpoint_results=push_result.endpoint_results,
        artifacts=_command_artifacts(push_result.command_records),
        errors=push_result.errors,
    )
    summary_path = artifact_root / "lab-bootstrap-result.json"
    result = replace(
        result,
        artifacts=_dedupe([*result.artifacts, str(summary_path)]),
    )
    write_json(summary_path, result)
    return result


def push_repository(
    session: LabSession,
    output_dir: str | Path,
    *,
    source_root: str | Path | None = None,
    client: WireClient | None = None,
    remote_dir: str | None = None,
    bootstrap_commands: Mapping[str, BootstrapCommandSpec] | None = None,
    archive_runner: Callable[..., CommandResult] = run_command,
) -> tuple[LabSession, RepoPushResult]:
    """Create an archive, push it, and return a session with command records."""

    archive = create_repository_archive(
        output_dir,
        source_root=source_root,
        runner=archive_runner,
    )
    push_result = push_repository_to_session(
        session,
        archive,
        client=client,
        remote_dir=remote_dir,
        bootstrap_commands=bootstrap_commands,
    )
    return session_with_repo_push_records(session, archive, push_result), push_result


def session_with_bootstrap_records(
    session: LabSession,
    bootstrap_result: LabBootstrapResult,
) -> LabSession:
    """Return ``session`` with lab bootstrap metadata and records appended."""

    metadata = dict(session.metadata)
    metadata["lab_bootstrap"] = bootstrap_result.to_dict()
    return replace(
        session,
        command_records=[
            *session.command_records,
            *bootstrap_result.command_records,
        ],
        metadata=json_object(metadata, "session.metadata"),
    )


def session_with_repo_push_records(
    session: LabSession,
    archive: RepoArchiveResult,
    push_result: RepoPushResult,
) -> LabSession:
    """Return ``session`` with archive and push command metadata appended."""

    metadata = dict(session.metadata)
    metadata["repository_push"] = push_result.to_dict()
    return replace(
        session,
        command_records=[
            *session.command_records,
            archive.command_record,
            *push_result.command_records,
        ],
        metadata=json_object(metadata, "session.metadata"),
    )


def _archive_excludes(
    *,
    source_root: Path,
    archive_path: Path,
    artifact_dir: Path,
    extra_excludes: Sequence[str],
) -> tuple[str, ...]:
    excludes: list[str] = list(DEFAULT_ARCHIVE_EXCLUDES)
    excludes.extend(_safe_exclude_pattern(item) for item in extra_excludes)
    excludes.extend(_relative_excludes(source_root, archive_path, artifact_dir))
    return tuple(_dedupe(excludes))


def _relative_excludes(source_root: Path, *paths: Path) -> list[str]:
    output: list[str] = []
    for path in paths:
        try:
            relative = path.resolve(strict=False).relative_to(source_root)
        except ValueError:
            continue
        if str(relative) == ".":
            continue
        output.append(relative.as_posix())
    return output


def _safe_exclude_pattern(value: object) -> str:
    if not isinstance(value, str) or value == "":
        raise ValueError("archive exclude patterns must be non-empty strings")
    if "\x00" in value:
        raise ValueError("archive exclude patterns must not contain NUL bytes")
    return value


def _archive_name(value: object) -> str:
    if not isinstance(value, str) or value == "":
        raise ValueError("archive_name must be a non-empty string")
    if value in {".", ".."} or "/" in value or "\x00" in value:
        raise ValueError("archive_name must be a single filename")
    return value


def _archive_path(archive: str | Path | RepoArchiveResult) -> Path:
    if isinstance(archive, RepoArchiveResult):
        return archive.archive_path.resolve(strict=False)
    return Path(archive).expanduser().resolve(strict=False)


def _absolute_existing_dir(value: str | Path, name: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    path = path.resolve(strict=False)
    if not path.is_dir():
        raise ValueError(f"{name} must be an existing directory: {path}")
    return path


def _repo_remote_dir(remote_dir: str | None) -> str:
    target_dir = validate_remote_dir(remote_dir)
    if target_dir == "/":
        raise RepoPushError("repository remote_dir must not be /")
    return target_dir


def _optional_output_dir(output_dir: str | Path | None) -> Path | None:
    if output_dir is None:
        return None
    return _output_dir(output_dir)


def _output_dir(output_dir: str | Path) -> Path:
    artifact_dir = Path(output_dir).expanduser()
    if not artifact_dir.is_absolute():
        artifact_dir = Path.cwd() / artifact_dir
    artifact_dir = artifact_dir.resolve(strict=False)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    return artifact_dir


def _endpoint_artifact_dir(
    artifact_root: Path | None,
    endpoint: LabEndpoint,
) -> Path | None:
    if artifact_root is None:
        return None
    return artifact_root / endpoint.role


def _remote_artifact_root(session: LabSession, remote_dir: str) -> str:
    if session.remote_artifact_root is not None:
        return validate_remote_dir(session.remote_artifact_root)
    return posixpath.join(remote_dir, "artifacts")


def _bootstrap_remote_artifact_root(
    *,
    session: LabSession,
    remote_dir: str,
    requested_remote_dir: str | None,
) -> str:
    if requested_remote_dir is not None:
        return posixpath.join(remote_dir, "artifacts")
    return _remote_artifact_root(session, remote_dir)


def _remote_archive_path(remote_dir: str, archive_name: str) -> str:
    remote_parent = posixpath.dirname(remote_dir.rstrip("/")) or "/"
    return posixpath.join(remote_parent, _archive_name(archive_name))


def _ensure_remote_parent_command(remote_archive: str) -> list[str]:
    remote_parent = posixpath.dirname(remote_archive.rstrip("/")) or "/"
    return ["bash", "-lc", f"mkdir -p {shlex.quote(remote_parent)}"]


def _unpack_repository_command(
    *,
    remote_archive: str,
    remote_dir: str,
    remote_artifact_root: str,
) -> list[str]:
    quoted_archive = shlex.quote(remote_archive)
    quoted_remote_dir = shlex.quote(remote_dir)
    quoted_artifacts = shlex.quote(remote_artifact_root)
    script = "\n".join(
        [
            "set -euo pipefail",
            f"rm -rf {quoted_remote_dir}",
            f"mkdir -p {quoted_remote_dir}",
            f"tar -xzf {quoted_archive} -C {quoted_remote_dir}",
            f"mkdir -p {quoted_artifacts}",
        ]
    )
    return ["bash", "-lc", script]


def _bootstrap_command_for(
    bootstrap_commands: Mapping[str, BootstrapCommandSpec],
    context: RepoBootstrapContext,
) -> RepoBootstrapCommand | None:
    value = bootstrap_commands.get(context.role.name)
    if value is None:
        return None
    if callable(value):
        value = value(context)
    if value is None:
        return None
    if isinstance(value, RepoBootstrapCommand):
        return value
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return RepoBootstrapCommand(argv=[str(part) for part in value])
    raise ValueError(f"bootstrap command for role {context.role.name!r} is invalid")


def _run_upload_step(
    wire: object,
    endpoint: LabEndpoint,
    archive_path: Path,
    remote_archive: str,
    *,
    command_records: list[LabCommandPlan],
    endpoint_commands: list[LabCommandPlan],
    endpoint_errors: list[str],
    artifact_dir: Path | None = None,
    artifact_label: str | None = None,
) -> None:
    try:
        response = wire.upload(endpoint.endpoint_id, archive_path, remote_archive)
    except Exception as exc:  # pragma: no cover - concrete clients vary.
        metadata = {
            "endpoint_id": endpoint.endpoint_id,
            "archive_path": str(archive_path),
            "remote_archive": remote_archive,
            "phase": "upload-repository",
        }
        artifacts = _write_exception_artifacts(
            artifact_dir,
            artifact_label,
            exc,
            metadata=metadata,
        )
        plan = _exception_command_plan(
            purpose="upload repository archive",
            role=endpoint.role,
            operation="wire.upload",
            argv=[
                WIRE_ENTRYPOINT,
                "upload",
                endpoint.endpoint_id,
                str(archive_path),
                remote_archive,
            ],
            exc=exc,
            metadata=metadata,
            artifacts=artifacts,
        )
        command_records.append(plan)
        endpoint_commands.append(plan)
        endpoint_errors.append(str(exc))
        return

    metadata = {
        "endpoint_id": endpoint.endpoint_id,
        "archive_path": str(archive_path),
        "remote_archive": remote_archive,
        "phase": "upload-repository",
    }
    artifacts = _write_response_artifacts(
        response,
        artifact_dir,
        artifact_label,
        metadata=metadata,
    )
    plan = _response_command_plan(
        response,
        purpose="upload repository archive",
        role=endpoint.role,
        fallback_operation="wire.upload",
        fallback_argv=[
            WIRE_ENTRYPOINT,
            "upload",
            endpoint.endpoint_id,
            str(archive_path),
            remote_archive,
        ],
        metadata=metadata,
        artifacts=artifacts,
    )
    command_records.append(plan)
    endpoint_commands.append(plan)
    if not _response_ok(response):
        endpoint_errors.append(_response_error(endpoint.endpoint_id, "repository upload", response))


def _run_endpoint_step(
    fn: Callable[..., object],
    endpoint_id: str,
    command: Sequence[str],
    *,
    purpose: str,
    role: str,
    operation: str,
    fallback_argv: Sequence[str],
    timeout: float | None,
    metadata: Mapping[str, object],
    command_records: list[LabCommandPlan],
    endpoint_commands: list[LabCommandPlan],
    endpoint_errors: list[str],
    artifact_dir: Path | None = None,
    artifact_label: str | None = None,
) -> None:
    try:
        response = fn(endpoint_id, command, timeout=timeout)
    except Exception as exc:  # pragma: no cover - concrete clients vary.
        artifacts = _write_exception_artifacts(
            artifact_dir,
            artifact_label,
            exc,
            metadata=metadata,
        )
        plan = _exception_command_plan(
            purpose=purpose,
            role=role,
            operation=operation,
            argv=list(fallback_argv),
            exc=exc,
            metadata=metadata,
            artifacts=artifacts,
        )
        command_records.append(plan)
        endpoint_commands.append(plan)
        endpoint_errors.append(str(exc))
        return

    artifacts = _write_response_artifacts(
        response,
        artifact_dir,
        artifact_label,
        metadata=metadata,
    )
    plan = _response_command_plan(
        response,
        purpose=purpose,
        role=role,
        fallback_operation=operation,
        fallback_argv=list(fallback_argv),
        metadata=metadata,
        artifacts=artifacts,
    )
    command_records.append(plan)
    endpoint_commands.append(plan)
    if not _response_ok(response):
        endpoint_errors.append(_response_error(endpoint_id, purpose, response))


def _response_command_plan(
    response: object,
    *,
    purpose: str,
    role: str | None,
    fallback_operation: str,
    fallback_argv: Sequence[str],
    metadata: Mapping[str, object],
    artifacts: Sequence[str | Path] = (),
) -> LabCommandPlan:
    artifact_paths = [str(path) for path in artifacts]
    command_plan = getattr(response, "command_plan", None)
    if callable(command_plan):
        try:
            plan = command_plan(
                purpose=purpose,
                role=role,
                artifacts=artifact_paths,
            )
        except TypeError:
            plan = command_plan(purpose=purpose, role=role)
        if isinstance(plan, Mapping):
            plan = LabCommandPlan.from_dict(plan)
        if isinstance(plan, LabCommandPlan):
            if artifact_paths:
                plan = replace(
                    plan,
                    artifacts=_dedupe([*plan.artifacts, *artifact_paths]),
                )
            return _merge_command_metadata(plan, metadata)

    plan = LabCommandPlan(
        purpose=purpose,
        role=role,
        argv=[str(part) for part in fallback_argv],
        operation=fallback_operation,
        dry_run=False,
        live_mutation=True,
        artifacts=artifact_paths,
        metadata={
            "ok": _response_ok(response),
            "exit_code": getattr(response, "exit_code", 0),
            "error": _optional_response_error(response),
        },
    )
    return _merge_command_metadata(plan, metadata)


def _local_command_plan(
    result: CommandResult,
    *,
    purpose: str,
    operation: str,
    artifacts: Sequence[Path],
    metadata: Mapping[str, object],
) -> LabCommandPlan:
    return LabCommandPlan(
        purpose=purpose,
        role=None,
        argv=list(result.redacted_argv),
        operation=operation,
        dry_run=False,
        live_mutation=False,
        artifacts=[str(path) for path in artifacts],
        metadata={
            **dict(metadata),
            "ok": result.ok,
            "exit_code": result.exit_code,
            "command": render_argv(result.redacted_argv),
            "cwd": result.cwd,
            "timed_out": result.timed_out,
            "timeout": result.timeout,
            "error": result.error,
            "stdout_bytes": len(result.stdout.encode("utf-8")),
            "stderr_bytes": len(result.stderr.encode("utf-8")),
        },
    )


def _exception_command_plan(
    *,
    purpose: str,
    role: str | None,
    operation: str,
    argv: Sequence[str],
    exc: Exception,
    metadata: Mapping[str, object],
    artifacts: Sequence[str | Path] = (),
) -> LabCommandPlan:
    return LabCommandPlan(
        purpose=purpose,
        role=role,
        argv=[str(part) for part in argv],
        operation=operation,
        dry_run=False,
        live_mutation=True,
        artifacts=[str(path) for path in artifacts],
        metadata={
            **dict(metadata),
            "ok": False,
            "exit_code": 1,
            "error": str(exc),
        },
    )


def _write_response_artifacts(
    response: object,
    artifact_dir: Path | None,
    artifact_label: str | None,
    *,
    metadata: Mapping[str, object],
) -> list[Path]:
    if artifact_dir is None or artifact_label is None:
        return []
    artifact_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = artifact_dir / f"{artifact_label}.stdout.txt"
    stderr_path = artifact_dir / f"{artifact_label}.stderr.txt"
    report_path = artifact_dir / f"{artifact_label}.json"
    result = getattr(response, "result", None)
    stdout_path.write_text(str(getattr(result, "stdout", "")), encoding="utf-8")
    stderr_path.write_text(str(getattr(result, "stderr", "")), encoding="utf-8")
    write_json(
        report_path,
        {
            **dict(metadata),
            "ok": _response_ok(response),
            "exit_code": getattr(response, "exit_code", 0),
            "error": _optional_response_error(response),
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
        },
    )
    return [stdout_path, stderr_path, report_path]


def _write_exception_artifacts(
    artifact_dir: Path | None,
    artifact_label: str | None,
    exc: Exception,
    *,
    metadata: Mapping[str, object],
) -> list[Path]:
    if artifact_dir is None or artifact_label is None:
        return []
    artifact_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = artifact_dir / f"{artifact_label}.stdout.txt"
    stderr_path = artifact_dir / f"{artifact_label}.stderr.txt"
    report_path = artifact_dir / f"{artifact_label}.json"
    stdout_path.write_text("", encoding="utf-8")
    stderr_path.write_text(str(exc), encoding="utf-8")
    write_json(
        report_path,
        {
            **dict(metadata),
            "ok": False,
            "exit_code": 1,
            "error": str(exc),
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
        },
    )
    return [stdout_path, stderr_path, report_path]


def _command_artifacts(command_records: Sequence[LabCommandPlan]) -> list[str]:
    return _dedupe(
        [
            artifact
            for record in command_records
            for artifact in record.artifacts
        ]
    )


def _merge_command_metadata(
    plan: LabCommandPlan,
    metadata: Mapping[str, object],
) -> LabCommandPlan:
    merged = dict(plan.metadata)
    merged.update(metadata)
    return replace(plan, metadata=json_object(merged, "command.metadata"))


def _endpoint_result(
    endpoint: LabEndpoint,
    commands: Sequence[LabCommandPlan],
    errors: Sequence[str],
) -> JSONObject:
    return json_object(
        {
            "endpoint_id": endpoint.endpoint_id,
            "role": endpoint.role,
            "ok": not errors,
            "commands": [command.to_dict() for command in commands],
            "errors": list(errors),
        },
        "repo_push.endpoint_result",
    )


def _response_ok(response: object) -> bool:
    return bool(getattr(response, "ok", False))


def _response_error(endpoint_id: str, operation: str, response: object) -> str:
    detail = _optional_response_error(response)
    if detail:
        return f"{operation} failed for {endpoint_id}: {detail}"
    return f"{operation} failed for {endpoint_id}: exit {getattr(response, 'exit_code', 1)}"


def _optional_response_error(response: object) -> str | None:
    result = getattr(response, "result", None)
    error = getattr(result, "error", None)
    if isinstance(error, str) and error:
        return error
    record = getattr(response, "record", None)
    error = getattr(record, "error", None)
    if isinstance(error, str) and error:
        return error
    json_data = getattr(response, "json_data", None)
    if isinstance(json_data, Mapping):
        error = json_data.get("error")
        if isinstance(error, str) and error:
            return error
    return None


def _dedupe(values: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output
