"""SSH-accessible Docker host plans for appliance workloads."""

from __future__ import annotations

import posixpath
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from tools.appliance.engine.image import DOCKER_COMMAND
from tools.appliance.engine.model import (
    JSONObject,
    JsonModel,
    absolute_path,
    json_object,
    require_non_empty_string,
    string_list,
)
from tools.appliance.engine.profile import ApplianceProfile
from tools.appliance.engine.runtime import DockerRunPlan, render_docker_run_plan
from tools.endpoint.engine.process import CommandResult
from tools.endpoint.engine.ssh import (
    DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_SSH_PORT,
    remote_host,
    scp_argv,
    ssh_argv,
)


DEFAULT_REMOTE_WORK_ROOT = "/var/tmp/libcrafter-appliance/work"
DEFAULT_REMOTE_ARTIFACT_ROOT = "/var/tmp/libcrafter-appliance/artifacts"
DOCKER_CHECK_COMMAND = ("info", "--format", "{{json .ServerVersion}}")

CommandRunner = Callable[..., CommandResult]


@dataclass(frozen=True, slots=True)
class SSHDockerHostTarget(JsonModel):
    """Connection and remote path metadata for one SSH-accessible Docker host."""

    host: str
    user: str
    identity_file: str | Path
    known_hosts_file: str | Path
    port: int = DEFAULT_SSH_PORT
    remote_work_root: str = DEFAULT_REMOTE_WORK_ROOT
    remote_artifact_root: str = DEFAULT_REMOTE_ARTIFACT_ROOT
    docker_command: str = DOCKER_COMMAND
    metadata: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "host", require_non_empty_string(self.host, "host"))
        object.__setattr__(self, "user", require_non_empty_string(self.user, "user"))
        object.__setattr__(
            self,
            "identity_file",
            absolute_path(self.identity_file, "identity_file"),
        )
        object.__setattr__(
            self,
            "known_hosts_file",
            absolute_path(self.known_hosts_file, "known_hosts_file"),
        )
        object.__setattr__(self, "port", _positive_int(self.port, "port"))
        object.__setattr__(
            self,
            "remote_work_root",
            _remote_absolute_path(self.remote_work_root, "remote_work_root"),
        )
        object.__setattr__(
            self,
            "remote_artifact_root",
            _remote_absolute_path(self.remote_artifact_root, "remote_artifact_root"),
        )
        object.__setattr__(
            self,
            "docker_command",
            require_non_empty_string(self.docker_command, "docker_command"),
        )
        object.__setattr__(self, "metadata", json_object(self.metadata, "metadata"))

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "SSHDockerHostTarget":
        """Build a target from JSON-style connection metadata."""

        data = _mapping(value, "ssh_docker_host")
        _reject_unknown_keys(
            data,
            {
                "host",
                "user",
                "identity_file",
                "known_hosts_file",
                "port",
                "remote_work_root",
                "remote_artifact_root",
                "docker_command",
                "metadata",
            },
            "ssh_docker_host",
        )
        return cls(
            host=_string(data.get("host"), "host"),
            user=_string(data.get("user"), "user"),
            identity_file=_string(data.get("identity_file"), "identity_file"),
            known_hosts_file=_string(data.get("known_hosts_file"), "known_hosts_file"),
            port=_int(data.get("port", DEFAULT_SSH_PORT), "port"),
            remote_work_root=_string(
                data.get("remote_work_root", DEFAULT_REMOTE_WORK_ROOT),
                "remote_work_root",
            ),
            remote_artifact_root=_string(
                data.get("remote_artifact_root", DEFAULT_REMOTE_ARTIFACT_ROOT),
                "remote_artifact_root",
            ),
            docker_command=_string(data.get("docker_command", DOCKER_COMMAND), "docker_command"),
            metadata=json_object(data.get("metadata", {}), "metadata"),
        )


@dataclass(frozen=True, slots=True)
class RemoteArtifact(JsonModel):
    """One declared artifact path relative to an SSH Docker host artifact root."""

    path: str
    local_path: str | None = None
    recursive: bool = False
    metadata: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        path = _relative_artifact_path(self.path, "artifact.path")
        object.__setattr__(self, "path", path)
        if self.local_path is not None:
            object.__setattr__(
                self,
                "local_path",
                _relative_artifact_path(self.local_path, "artifact.local_path"),
            )
        object.__setattr__(self, "recursive", _bool(self.recursive, "artifact.recursive"))
        object.__setattr__(self, "metadata", json_object(self.metadata, "artifact.metadata"))

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "RemoteArtifact":
        """Build an artifact declaration from JSON-style data."""

        data = _mapping(value, "artifact")
        _reject_unknown_keys(
            data,
            {"path", "local_path", "recursive", "metadata"},
            "artifact",
        )
        return cls(
            path=_string(data.get("path"), "artifact.path"),
            local_path=_optional_string(data.get("local_path"), "artifact.local_path"),
            recursive=_bool(data.get("recursive", False), "artifact.recursive"),
            metadata=json_object(data.get("metadata", {}), "artifact.metadata"),
        )


@dataclass(frozen=True, slots=True)
class SSHCommandPlan(JsonModel):
    """A JSON-serializable SSH command plan that does not execute by itself."""

    kind: str
    target: SSHDockerHostTarget
    remote_command_argv: list[str]
    command_argv: list[str]
    executes: bool = False
    metadata: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", require_non_empty_string(self.kind, "kind"))
        if not isinstance(self.target, SSHDockerHostTarget):
            object.__setattr__(
                self,
                "target",
                SSHDockerHostTarget.from_dict(_mapping(self.target, "target")),
            )
        object.__setattr__(
            self,
            "remote_command_argv",
            _non_empty_string_list(self.remote_command_argv, "remote_command_argv"),
        )
        object.__setattr__(
            self,
            "command_argv",
            _non_empty_string_list(self.command_argv, "command_argv"),
        )
        object.__setattr__(self, "executes", _bool(self.executes, "executes"))
        object.__setattr__(self, "metadata", json_object(self.metadata, "metadata"))


@dataclass(frozen=True, slots=True)
class RemoteDockerRunPlan(JsonModel):
    """A JSON-serializable SSH-wrapped Docker run plan."""

    kind: str
    target: SSHDockerHostTarget
    run: DockerRunPlan
    command_argv: list[str]
    executes: bool = False
    metadata: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", require_non_empty_string(self.kind, "kind"))
        if not isinstance(self.target, SSHDockerHostTarget):
            object.__setattr__(
                self,
                "target",
                SSHDockerHostTarget.from_dict(_mapping(self.target, "target")),
            )
        if not isinstance(self.run, DockerRunPlan):
            raise ValueError("run must be a DockerRunPlan")
        object.__setattr__(
            self,
            "command_argv",
            _non_empty_string_list(self.command_argv, "command_argv"),
        )
        object.__setattr__(self, "executes", _bool(self.executes, "executes"))
        object.__setattr__(self, "metadata", json_object(self.metadata, "metadata"))


@dataclass(frozen=True, slots=True)
class ArtifactCollectionPlan(JsonModel):
    """A JSON-serializable SCP plan for collecting one remote artifact."""

    kind: str
    target: SSHDockerHostTarget
    artifact: RemoteArtifact
    remote_path: str
    local_path: str
    command_argv: list[str]
    recursive: bool = False
    executes: bool = False
    metadata: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", require_non_empty_string(self.kind, "kind"))
        if not isinstance(self.target, SSHDockerHostTarget):
            object.__setattr__(
                self,
                "target",
                SSHDockerHostTarget.from_dict(_mapping(self.target, "target")),
            )
        if not isinstance(self.artifact, RemoteArtifact):
            object.__setattr__(
                self,
                "artifact",
                RemoteArtifact.from_dict(_mapping(self.artifact, "artifact")),
            )
        object.__setattr__(
            self,
            "remote_path",
            _remote_absolute_path(self.remote_path, "remote_path"),
        )
        object.__setattr__(self, "local_path", absolute_path(self.local_path, "local_path"))
        object.__setattr__(
            self,
            "command_argv",
            _non_empty_string_list(self.command_argv, "command_argv"),
        )
        object.__setattr__(self, "recursive", _bool(self.recursive, "recursive"))
        object.__setattr__(self, "executes", _bool(self.executes, "executes"))
        object.__setattr__(self, "metadata", json_object(self.metadata, "metadata"))


def render_docker_check_plan(
    target: SSHDockerHostTarget | Mapping[str, object],
    *,
    connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
) -> SSHCommandPlan:
    """Return a deterministic SSH plan for checking Docker daemon access."""

    ssh_target = _target(target)
    remote_command = [ssh_target.docker_command, *DOCKER_CHECK_COMMAND]
    return SSHCommandPlan(
        kind="ssh-docker-check",
        target=ssh_target,
        remote_command_argv=remote_command,
        command_argv=_ssh_command_argv(
            ssh_target,
            remote_command,
            connect_timeout=connect_timeout,
        ),
        metadata={"docker_command": ssh_target.docker_command},
    )


def render_mkdir_plan(
    target: SSHDockerHostTarget | Mapping[str, object],
    *,
    paths: Sequence[str] | None = None,
    connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
) -> SSHCommandPlan:
    """Return a deterministic SSH plan for creating remote work and artifact roots."""

    ssh_target = _target(target)
    selected_paths = paths if paths is not None else [
        ssh_target.remote_work_root,
        ssh_target.remote_artifact_root,
    ]
    remote_paths = [
        _remote_absolute_path(path, "paths[]")
        for path in selected_paths
    ]
    if not remote_paths:
        raise ValueError("paths must not be empty")
    remote_command = ["mkdir", "-p", *remote_paths]
    return SSHCommandPlan(
        kind="ssh-docker-mkdir",
        target=ssh_target,
        remote_command_argv=remote_command,
        command_argv=_ssh_command_argv(
            ssh_target,
            remote_command,
            connect_timeout=connect_timeout,
        ),
        metadata={"paths": list(remote_paths)},
    )


def render_remote_docker_run_plan(
    target: SSHDockerHostTarget | Mapping[str, object],
    profile: ApplianceProfile | Mapping[str, object],
    *,
    command_argv: Sequence[str],
    image_tag: str | None = None,
    environment: Mapping[str, str] | None = None,
    env: Mapping[str, str] | None = None,
    network_mode: str | None = None,
    cap_add: Sequence[str] = (),
    capabilities: Sequence[str] = (),
    connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
) -> RemoteDockerRunPlan:
    """Return a deterministic SSH plan for running an appliance container remotely."""

    ssh_target = _target(target)
    run = render_docker_run_plan(
        profile,
        image_tag=image_tag,
        work_dir=ssh_target.remote_work_root,
        artifact_dir=ssh_target.remote_artifact_root,
        command_argv=command_argv,
        environment=environment,
        env=env,
        network_mode=network_mode,
        cap_add=cap_add,
        capabilities=capabilities,
        docker_command=ssh_target.docker_command,
    )
    return RemoteDockerRunPlan(
        kind="ssh-docker-run",
        target=ssh_target,
        run=run,
        command_argv=_ssh_command_argv(
            ssh_target,
            run.docker_argv,
            connect_timeout=connect_timeout,
        ),
        metadata={
            "remote_work_root": ssh_target.remote_work_root,
            "remote_artifact_root": ssh_target.remote_artifact_root,
        },
    )


def render_artifact_collection_plans(
    target: SSHDockerHostTarget | Mapping[str, object],
    artifacts: Sequence[RemoteArtifact | Mapping[str, object] | str],
    *,
    local_root: str | Path,
    connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
) -> list[ArtifactCollectionPlan]:
    """Return deterministic SCP plans for declared artifacts."""

    ssh_target = _target(target)
    local_root_path = Path(absolute_path(local_root, "local_root"))
    declarations = [_artifact(item) for item in _sequence(artifacts, "artifacts")]
    return [
        _artifact_collection_plan(
            ssh_target,
            artifact,
            local_root=local_root_path,
            connect_timeout=connect_timeout,
        )
        for artifact in declarations
    ]


def execute_command_plan(
    plan: SSHCommandPlan | RemoteDockerRunPlan | ArtifactCollectionPlan,
    *,
    runner: CommandRunner,
    timeout: float | None = None,
) -> CommandResult:
    """Execute an explicit plan with an injected runner.

    Rendering helpers remain plan-only. This wrapper is for callers and tests
    that deliberately provide a command runner.
    """

    if runner is None:
        raise ValueError("runner is required")
    return runner(plan.command_argv, timeout=timeout)


def _artifact_collection_plan(
    target: SSHDockerHostTarget,
    artifact: RemoteArtifact,
    *,
    local_root: Path,
    connect_timeout: int,
) -> ArtifactCollectionPlan:
    remote_path = _join_remote(target.remote_artifact_root, artifact.path)
    relative_local = artifact.local_path or artifact.path
    local_path = local_root.joinpath(*relative_local.split("/")).resolve(strict=False)
    source = f"{remote_host(host=target.host, user=target.user)}:{remote_path}"
    argv = scp_argv(
        source=source,
        destination=str(local_path),
        identity_file=target.identity_file,
        known_hosts=target.known_hosts_file,
        port=target.port,
        connect_timeout=connect_timeout,
        recursive=artifact.recursive,
    )
    return ArtifactCollectionPlan(
        kind="ssh-docker-artifact-collection",
        target=target,
        artifact=artifact,
        remote_path=remote_path,
        local_path=str(local_path),
        command_argv=argv,
        recursive=artifact.recursive,
        metadata={"remote_artifact_root": target.remote_artifact_root},
    )


def _ssh_command_argv(
    target: SSHDockerHostTarget,
    remote_command_argv: Sequence[str],
    *,
    connect_timeout: int,
) -> list[str]:
    return ssh_argv(
        host=target.host,
        user=target.user,
        identity_file=target.identity_file,
        known_hosts=target.known_hosts_file,
        command=remote_command_argv,
        port=target.port,
        connect_timeout=connect_timeout,
    )


def _target(value: SSHDockerHostTarget | Mapping[str, object]) -> SSHDockerHostTarget:
    if isinstance(value, SSHDockerHostTarget):
        return value
    return SSHDockerHostTarget.from_dict(value)


def _artifact(value: RemoteArtifact | Mapping[str, object] | str) -> RemoteArtifact:
    if isinstance(value, RemoteArtifact):
        return value
    if isinstance(value, str):
        return RemoteArtifact(path=value)
    return RemoteArtifact.from_dict(value)


def _remote_absolute_path(value: str | Path, name: str) -> str:
    path = require_non_empty_string(str(value), name)
    if not path.startswith("/"):
        raise ValueError(f"{name} must be an absolute remote path")
    normalized = posixpath.normpath(path)
    if normalized == ".":
        raise ValueError(f"{name} must be an absolute remote path")
    return normalized


def _relative_artifact_path(value: str, name: str) -> str:
    path = require_non_empty_string(value, name)
    if path.startswith("/"):
        raise ValueError(f"{name} must be relative to the remote artifact root")
    normalized = posixpath.normpath(path)
    if normalized in {".", ".."} or normalized.startswith("../"):
        raise ValueError(f"{name} must stay within the remote artifact root")
    return normalized


def _join_remote(root: str, relative: str) -> str:
    return posixpath.normpath(posixpath.join(root, relative))


def _non_empty_string_list(value: Sequence[str], name: str) -> list[str]:
    output = string_list(value, name)
    if not output:
        raise ValueError(f"{name} must not be empty")
    for item in output:
        if item == "":
            raise ValueError(f"{name} entries must be non-empty strings")
    return output


def _mapping(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    for key in value:
        if not isinstance(key, str):
            raise ValueError(f"{name} keys must be strings")
    return value


def _sequence(value: object, name: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError(f"{name} must be a list")
    return value


def _string(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    return value


def _optional_string(value: object, name: str) -> str | None:
    if value is None:
        return None
    return _string(value, name)


def _int(value: object, name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc


def _positive_int(value: object, name: str) -> int:
    output = _int(value, name)
    if output <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return output


def _bool(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be a boolean")
    return value


def _reject_unknown_keys(data: Mapping[str, object], allowed: set[str], name: str) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        joined = ", ".join(unknown)
        raise ValueError(f"{name} contains unknown field(s): {joined}")


__all__ = [
    "ArtifactCollectionPlan",
    "DEFAULT_REMOTE_ARTIFACT_ROOT",
    "DEFAULT_REMOTE_WORK_ROOT",
    "DOCKER_CHECK_COMMAND",
    "RemoteArtifact",
    "RemoteDockerRunPlan",
    "SSHCommandPlan",
    "SSHDockerHostTarget",
    "execute_command_plan",
    "render_artifact_collection_plans",
    "render_docker_check_plan",
    "render_mkdir_plan",
    "render_remote_docker_run_plan",
]
