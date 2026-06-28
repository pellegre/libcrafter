"""Resolve endpoint manifests into appliance execution targets."""

from __future__ import annotations

import json
import posixpath
import shlex
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from tools.appliance.engine.image import (
    APPLIANCE_IMAGE_CONTEXT_LABEL,
    LIBCRAFTER_APPLIANCE_IMAGE,
    appliance_image_context_digest,
    appliance_image_metadata,
    requested_appliance_image,
)
from tools.appliance.engine.profile import ApplianceProfile
from tools.appliance.engine.profiles import resolve_profile
from tools.appliance.engine.runtime import DockerRunPlan, render_docker_run_plan
from tools.appliance.engine.ssh_docker import (
    CommandRunner,
    SSHCommandPlan,
    SSHDockerHostTarget,
    execute_command_plan,
    render_docker_check_plan,
    render_mkdir_plan,
)

from .config import WireConfig
from .model import EndpointManifest, JSONObject, JsonModel, NetworkInterface, json_object
from .process import CommandResult
from .state import read_endpoint_manifest
from .ssh import DEFAULT_CONNECT_TIMEOUT, remote_host, scp_argv, ssh_argv


DEFAULT_APPLIANCE_REMOTE_BASE = "/var/lib/libcrafter/appliance"
DOCKER_ENDPOINT_TRANSPORT = "docker-localhost-port-forward"
DEFAULT_APPLIANCE_DEPLOY_ARTIFACT_DIRNAME = "appliance-deploy"
DEFAULT_APPLIANCE_SYNC_ARTIFACT_DIRNAME = "appliance-sync"
DEFAULT_APPLIANCE_RUN_ARTIFACT_DIRNAME = "appliance-run"
DEFAULT_APPLIANCE_SYNC_ARCHIVE_NAME = "workspace.tar.gz"
DEFAULT_APPLIANCE_SYNC_RUN_ID = "default"
DEFAULT_APPLIANCE_RUN_ID = DEFAULT_APPLIANCE_SYNC_RUN_ID
DEFAULT_APPLIANCE_SYNC_ARCHIVE_EXCLUDES = (
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
DEFAULT_DOCKER_INSTALL_SCRIPT = """
set -eu
if command -v docker >/dev/null 2>&1; then
  exit 0
fi
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y docker.io
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y docker
elif command -v yum >/dev/null 2>&1; then
  yum install -y docker
else
  echo 'no supported Docker package manager found' >&2
  exit 127
fi
""".strip()


@dataclass(frozen=True, slots=True)
class EndpointApplianceTarget(JsonModel):
    """Endpoint manifest data resolved for appliance profile rendering."""

    endpoint_id: str
    provider: str
    exposure: str
    role: str
    target: SSHDockerHostTarget
    interfaces: list[NetworkInterface] = field(default_factory=list)
    metadata: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_non_empty_string(self.endpoint_id, "endpoint_id")
        _require_non_empty_string(self.provider, "provider")
        _require_non_empty_string(self.exposure, "exposure")
        _require_non_empty_string(self.role, "role")
        if not isinstance(self.target, SSHDockerHostTarget):
            raise TypeError("target must be an SSHDockerHostTarget")
        object.__setattr__(
            self,
            "interfaces",
            [
                item
                if isinstance(item, NetworkInterface)
                else NetworkInterface.from_dict(_mapping(item, "interfaces[]"))
                for item in self.interfaces
            ],
        )
        object.__setattr__(self, "metadata", json_object(self.metadata, "metadata"))


@dataclass(frozen=True, slots=True)
class EndpointApplianceDeployPlan(JsonModel):
    """Dry-run plan for preparing one endpoint target to run the appliance image."""

    kind: str
    endpoint_id: str
    target: EndpointApplianceTarget
    commands: list[SSHCommandPlan]
    image: JSONObject
    install_docker: bool = False
    executes: bool = False
    metadata: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", _require_non_empty_string(self.kind, "kind"))
        object.__setattr__(
            self,
            "endpoint_id",
            _require_non_empty_string(self.endpoint_id, "endpoint_id"),
        )
        if not isinstance(self.target, EndpointApplianceTarget):
            raise TypeError("target must be an EndpointApplianceTarget")
        object.__setattr__(
            self,
            "commands",
            [
                command
                if isinstance(command, SSHCommandPlan)
                else SSHCommandPlan(**dict(_mapping(command, "commands[]")))
                for command in self.commands
            ],
        )
        if not self.commands:
            raise ValueError("commands must not be empty")
        object.__setattr__(self, "image", json_object(self.image, "image"))
        object.__setattr__(self, "install_docker", _bool(self.install_docker, "install_docker"))
        object.__setattr__(self, "executes", _bool(self.executes, "executes"))
        object.__setattr__(self, "metadata", json_object(self.metadata, "metadata"))


@dataclass(frozen=True, slots=True)
class EndpointApplianceDeployCommandResult(JsonModel):
    """Recorded result and stdout/stderr artifact paths for one deploy command."""

    name: str
    kind: str
    command_argv: list[str]
    exit_code: int
    ok: bool
    stdout_path: str
    stderr_path: str
    timed_out: bool = False
    error: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _require_non_empty_string(self.name, "name"))
        object.__setattr__(self, "kind", _require_non_empty_string(self.kind, "kind"))
        object.__setattr__(
            self,
            "command_argv",
            _non_empty_string_list(self.command_argv, "command_argv"),
        )
        object.__setattr__(self, "exit_code", _int(self.exit_code, "exit_code"))
        object.__setattr__(self, "ok", _bool(self.ok, "ok"))
        object.__setattr__(self, "stdout_path", _absolute_path(self.stdout_path, "stdout_path"))
        object.__setattr__(self, "stderr_path", _absolute_path(self.stderr_path, "stderr_path"))
        object.__setattr__(self, "timed_out", _bool(self.timed_out, "timed_out"))
        if self.error is not None:
            object.__setattr__(self, "error", _require_non_empty_string(self.error, "error"))


@dataclass(frozen=True, slots=True)
class EndpointApplianceDeployResult(JsonModel):
    """Live deploy outcome for one endpoint appliance target."""

    kind: str
    endpoint_id: str
    ok: bool
    plan: EndpointApplianceDeployPlan
    artifact_dir: str
    command_results: list[EndpointApplianceDeployCommandResult] = field(default_factory=list)
    metadata: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", _require_non_empty_string(self.kind, "kind"))
        object.__setattr__(
            self,
            "endpoint_id",
            _require_non_empty_string(self.endpoint_id, "endpoint_id"),
        )
        object.__setattr__(self, "ok", _bool(self.ok, "ok"))
        if not isinstance(self.plan, EndpointApplianceDeployPlan):
            raise TypeError("plan must be an EndpointApplianceDeployPlan")
        object.__setattr__(self, "artifact_dir", _absolute_path(self.artifact_dir, "artifact_dir"))
        object.__setattr__(
            self,
            "command_results",
            [
                result
                if isinstance(result, EndpointApplianceDeployCommandResult)
                else EndpointApplianceDeployCommandResult(
                    **dict(_mapping(result, "command_results[]"))
                )
                for result in self.command_results
            ],
        )
        object.__setattr__(self, "metadata", json_object(self.metadata, "metadata"))


@dataclass(frozen=True, slots=True)
class EndpointApplianceSyncTransferPlan(JsonModel):
    """Dry-run SCP upload plan for one endpoint appliance workspace archive."""

    kind: str
    target: SSHDockerHostTarget
    local_path: str
    remote_path: str
    command_argv: list[str]
    recursive: bool = False
    executes: bool = False
    metadata: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", _require_non_empty_string(self.kind, "kind"))
        if not isinstance(self.target, SSHDockerHostTarget):
            object.__setattr__(
                self,
                "target",
                SSHDockerHostTarget.from_dict(_mapping(self.target, "target")),
            )
        object.__setattr__(self, "local_path", _absolute_path(self.local_path, "local_path"))
        object.__setattr__(
            self,
            "remote_path",
            _remote_absolute_path(self.remote_path, "remote_path"),
        )
        object.__setattr__(
            self,
            "command_argv",
            _non_empty_string_list(self.command_argv, "command_argv"),
        )
        object.__setattr__(self, "recursive", _bool(self.recursive, "recursive"))
        object.__setattr__(self, "executes", _bool(self.executes, "executes"))
        object.__setattr__(self, "metadata", json_object(self.metadata, "metadata"))


@dataclass(frozen=True, slots=True)
class EndpointApplianceSyncPlan(JsonModel):
    """Dry-run plan for syncing a local workspace to one endpoint appliance target."""

    kind: str
    endpoint_id: str
    target: EndpointApplianceTarget
    source_root: str
    run_id: str
    local_archive_path: str
    remote_run_root: str
    remote_workspace_dir: str
    remote_artifact_dir: str
    remote_archive_path: str
    archive_excludes: list[str]
    archive_command_argv: list[str]
    commands: list[SSHCommandPlan | EndpointApplianceSyncTransferPlan]
    executes: bool = False
    metadata: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", _require_non_empty_string(self.kind, "kind"))
        object.__setattr__(
            self,
            "endpoint_id",
            _require_non_empty_string(self.endpoint_id, "endpoint_id"),
        )
        if not isinstance(self.target, EndpointApplianceTarget):
            raise TypeError("target must be an EndpointApplianceTarget")
        object.__setattr__(self, "source_root", _absolute_path(self.source_root, "source_root"))
        object.__setattr__(self, "run_id", _remote_component(self.run_id, "run_id"))
        object.__setattr__(
            self,
            "local_archive_path",
            _absolute_path(self.local_archive_path, "local_archive_path"),
        )
        object.__setattr__(
            self,
            "remote_run_root",
            _remote_absolute_path(self.remote_run_root, "remote_run_root"),
        )
        object.__setattr__(
            self,
            "remote_workspace_dir",
            _remote_absolute_path(self.remote_workspace_dir, "remote_workspace_dir"),
        )
        object.__setattr__(
            self,
            "remote_artifact_dir",
            _remote_absolute_path(self.remote_artifact_dir, "remote_artifact_dir"),
        )
        object.__setattr__(
            self,
            "remote_archive_path",
            _remote_absolute_path(self.remote_archive_path, "remote_archive_path"),
        )
        object.__setattr__(
            self,
            "archive_excludes",
            _string_list(self.archive_excludes, "archive_excludes"),
        )
        object.__setattr__(
            self,
            "archive_command_argv",
            _non_empty_string_list(self.archive_command_argv, "archive_command_argv"),
        )
        commands: list[SSHCommandPlan | EndpointApplianceSyncTransferPlan] = []
        for command in self.commands:
            if isinstance(command, (SSHCommandPlan, EndpointApplianceSyncTransferPlan)):
                commands.append(command)
                continue
            data = _mapping(command, "commands[]")
            kind = data.get("kind")
            if kind == "ssh-appliance-sync-upload":
                commands.append(EndpointApplianceSyncTransferPlan(**dict(data)))
            else:
                commands.append(SSHCommandPlan(**dict(data)))
        if not commands:
            raise ValueError("commands must not be empty")
        object.__setattr__(self, "commands", commands)
        object.__setattr__(self, "executes", _bool(self.executes, "executes"))
        object.__setattr__(self, "metadata", json_object(self.metadata, "metadata"))


@dataclass(frozen=True, slots=True)
class EndpointApplianceSyncCommandResult(JsonModel):
    """Recorded result and stdout/stderr artifact paths for one sync command."""

    name: str
    kind: str
    command_argv: list[str]
    exit_code: int
    ok: bool
    stdout_path: str
    stderr_path: str
    timed_out: bool = False
    error: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _require_non_empty_string(self.name, "name"))
        object.__setattr__(self, "kind", _require_non_empty_string(self.kind, "kind"))
        object.__setattr__(
            self,
            "command_argv",
            _non_empty_string_list(self.command_argv, "command_argv"),
        )
        object.__setattr__(self, "exit_code", _int(self.exit_code, "exit_code"))
        object.__setattr__(self, "ok", _bool(self.ok, "ok"))
        object.__setattr__(self, "stdout_path", _absolute_path(self.stdout_path, "stdout_path"))
        object.__setattr__(self, "stderr_path", _absolute_path(self.stderr_path, "stderr_path"))
        object.__setattr__(self, "timed_out", _bool(self.timed_out, "timed_out"))
        if self.error is not None:
            object.__setattr__(self, "error", _require_non_empty_string(self.error, "error"))


@dataclass(frozen=True, slots=True)
class EndpointApplianceSyncResult(JsonModel):
    """Live sync outcome for one endpoint appliance target."""

    kind: str
    endpoint_id: str
    ok: bool
    plan: EndpointApplianceSyncPlan
    artifact_dir: str
    command_results: list[EndpointApplianceSyncCommandResult] = field(default_factory=list)
    metadata: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", _require_non_empty_string(self.kind, "kind"))
        object.__setattr__(
            self,
            "endpoint_id",
            _require_non_empty_string(self.endpoint_id, "endpoint_id"),
        )
        object.__setattr__(self, "ok", _bool(self.ok, "ok"))
        if not isinstance(self.plan, EndpointApplianceSyncPlan):
            raise TypeError("plan must be an EndpointApplianceSyncPlan")
        object.__setattr__(self, "artifact_dir", _absolute_path(self.artifact_dir, "artifact_dir"))
        object.__setattr__(
            self,
            "command_results",
            [
                result
                if isinstance(result, EndpointApplianceSyncCommandResult)
                else EndpointApplianceSyncCommandResult(
                    **dict(_mapping(result, "command_results[]"))
                )
                for result in self.command_results
            ],
        )
        object.__setattr__(self, "metadata", json_object(self.metadata, "metadata"))


@dataclass(frozen=True, slots=True)
class EndpointApplianceRunPlan(JsonModel):
    """Dry-run plan for running one appliance profile command on an endpoint."""

    kind: str
    endpoint_id: str
    target: EndpointApplianceTarget
    profile: str
    image_tag: str
    command_argv: list[str]
    run_id: str
    remote_work_root: str
    remote_artifact_root: str
    local_artifact_dir: str
    local_stdout_path: str
    local_stderr_path: str
    local_metadata_path: str
    docker_run: DockerRunPlan
    commands: list[SSHCommandPlan]
    executes: bool = False
    metadata: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", _require_non_empty_string(self.kind, "kind"))
        object.__setattr__(
            self,
            "endpoint_id",
            _require_non_empty_string(self.endpoint_id, "endpoint_id"),
        )
        if not isinstance(self.target, EndpointApplianceTarget):
            raise TypeError("target must be an EndpointApplianceTarget")
        object.__setattr__(self, "profile", _require_non_empty_string(self.profile, "profile"))
        object.__setattr__(
            self,
            "image_tag",
            _require_non_empty_string(self.image_tag, "image_tag"),
        )
        object.__setattr__(
            self,
            "command_argv",
            _non_empty_string_list(self.command_argv, "command_argv"),
        )
        object.__setattr__(self, "run_id", _remote_component(self.run_id, "run_id"))
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
            "local_artifact_dir",
            _absolute_path(self.local_artifact_dir, "local_artifact_dir"),
        )
        object.__setattr__(
            self,
            "local_stdout_path",
            _absolute_path(self.local_stdout_path, "local_stdout_path"),
        )
        object.__setattr__(
            self,
            "local_stderr_path",
            _absolute_path(self.local_stderr_path, "local_stderr_path"),
        )
        object.__setattr__(
            self,
            "local_metadata_path",
            _absolute_path(self.local_metadata_path, "local_metadata_path"),
        )
        if not isinstance(self.docker_run, DockerRunPlan):
            object.__setattr__(
                self,
                "docker_run",
                DockerRunPlan(**dict(_mapping(self.docker_run, "docker_run"))),
            )
        commands = [
            command
            if isinstance(command, SSHCommandPlan)
            else SSHCommandPlan(**dict(_mapping(command, "commands[]")))
            for command in self.commands
        ]
        if not commands:
            raise ValueError("commands must not be empty")
        object.__setattr__(self, "commands", commands)
        object.__setattr__(self, "executes", _bool(self.executes, "executes"))
        object.__setattr__(self, "metadata", json_object(self.metadata, "metadata"))


@dataclass(frozen=True, slots=True)
class EndpointApplianceRunCommandResult(JsonModel):
    """Recorded result and stdout/stderr artifact paths for one run command."""

    name: str
    kind: str
    command_argv: list[str]
    exit_code: int
    ok: bool
    stdout_path: str
    stderr_path: str
    timed_out: bool = False
    error: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _require_non_empty_string(self.name, "name"))
        object.__setattr__(self, "kind", _require_non_empty_string(self.kind, "kind"))
        object.__setattr__(
            self,
            "command_argv",
            _non_empty_string_list(self.command_argv, "command_argv"),
        )
        object.__setattr__(self, "exit_code", _int(self.exit_code, "exit_code"))
        object.__setattr__(self, "ok", _bool(self.ok, "ok"))
        object.__setattr__(self, "stdout_path", _absolute_path(self.stdout_path, "stdout_path"))
        object.__setattr__(self, "stderr_path", _absolute_path(self.stderr_path, "stderr_path"))
        object.__setattr__(self, "timed_out", _bool(self.timed_out, "timed_out"))
        if self.error is not None:
            object.__setattr__(self, "error", _require_non_empty_string(self.error, "error"))


@dataclass(frozen=True, slots=True)
class EndpointApplianceRunResult(JsonModel):
    """Live appliance run outcome for one endpoint target."""

    kind: str
    endpoint_id: str
    ok: bool
    plan: EndpointApplianceRunPlan
    profile: str
    image_tag: str
    command_argv: list[str]
    exit_code: int
    remote_work_root: str
    remote_artifact_root: str
    local_artifact_dir: str
    local_stdout_path: str
    local_stderr_path: str
    local_metadata_path: str
    artifact_dir: str
    command_results: list[EndpointApplianceRunCommandResult] = field(default_factory=list)
    metadata: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", _require_non_empty_string(self.kind, "kind"))
        object.__setattr__(
            self,
            "endpoint_id",
            _require_non_empty_string(self.endpoint_id, "endpoint_id"),
        )
        object.__setattr__(self, "ok", _bool(self.ok, "ok"))
        if not isinstance(self.plan, EndpointApplianceRunPlan):
            raise TypeError("plan must be an EndpointApplianceRunPlan")
        object.__setattr__(self, "profile", _require_non_empty_string(self.profile, "profile"))
        object.__setattr__(
            self,
            "image_tag",
            _require_non_empty_string(self.image_tag, "image_tag"),
        )
        object.__setattr__(
            self,
            "command_argv",
            _non_empty_string_list(self.command_argv, "command_argv"),
        )
        object.__setattr__(self, "exit_code", _int(self.exit_code, "exit_code"))
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
            "local_artifact_dir",
            _absolute_path(self.local_artifact_dir, "local_artifact_dir"),
        )
        object.__setattr__(
            self,
            "local_stdout_path",
            _absolute_path(self.local_stdout_path, "local_stdout_path"),
        )
        object.__setattr__(
            self,
            "local_stderr_path",
            _absolute_path(self.local_stderr_path, "local_stderr_path"),
        )
        object.__setattr__(
            self,
            "local_metadata_path",
            _absolute_path(self.local_metadata_path, "local_metadata_path"),
        )
        object.__setattr__(self, "artifact_dir", _absolute_path(self.artifact_dir, "artifact_dir"))
        object.__setattr__(
            self,
            "command_results",
            [
                result
                if isinstance(result, EndpointApplianceRunCommandResult)
                else EndpointApplianceRunCommandResult(
                    **dict(_mapping(result, "command_results[]"))
                )
                for result in self.command_results
            ],
        )
        object.__setattr__(self, "metadata", json_object(self.metadata, "metadata"))


def resolve_endpoint_appliance_target(
    manifest: EndpointManifest | Mapping[str, object],
) -> EndpointApplianceTarget:
    """Return an appliance target derived from an endpoint manifest."""

    endpoint = _manifest(manifest)
    ssh = endpoint.ssh
    if ssh.identity_file is None:
        raise ValueError("endpoint ssh.identity_file is required for appliance targets")
    if ssh.known_hosts_file is None:
        raise ValueError("endpoint ssh.known_hosts_file is required for appliance targets")

    appliance_metadata = _optional_mapping(endpoint.metadata.get("appliance"), "metadata.appliance")
    docker_metadata = _optional_mapping(endpoint.metadata.get("docker"), "metadata.docker")
    docker_container = _optional_mapping(
        docker_metadata.get("container") if docker_metadata is not None else None,
        "metadata.docker.container",
    )
    docker_endpoint = _is_docker_endpoint(endpoint, docker_container)
    appliance_capable = _is_appliance_capable(appliance_metadata, docker_container)
    nested_docker = _nested_docker_supported(
        appliance_metadata,
        docker_endpoint=docker_endpoint,
        appliance_capable=appliance_capable,
    )

    remote_base = _remote_base(endpoint, appliance_metadata)
    remote_work_root = _remote_root(
        endpoint,
        appliance_metadata,
        field_name="remote_work_root",
        default_name="work",
        remote_base=remote_base,
    )
    remote_artifact_root = _remote_root(
        endpoint,
        appliance_metadata,
        field_name="remote_artifact_root",
        default_name="artifacts",
        remote_base=remote_base,
    )
    runtime_metadata = {
        "target_kind": _target_kind(
            docker_endpoint=docker_endpoint,
            appliance_capable=appliance_capable,
        ),
        "remote_base": remote_base,
        "remote_work_root": remote_work_root,
        "remote_artifact_root": remote_artifact_root,
        "docker_endpoint_container": docker_endpoint,
        "appliance_capable": appliance_capable,
        "nested_docker": nested_docker,
        "docker_execution_supported": nested_docker,
    }
    if docker_endpoint and not nested_docker:
        runtime_metadata["docker_execution_disabled_reason"] = (
            "endpoint is already a Docker container"
        )

    metadata = {
        "endpoint_id": endpoint.endpoint_id,
        "provider": endpoint.provider,
        "exposure": endpoint.exposure,
        "role": endpoint.role,
        "endpoint_status": endpoint.status,
        "artifact_dir": endpoint.artifact_dir,
        "interfaces": [interface.to_dict() for interface in endpoint.interfaces],
        "provider_resources": endpoint.provider_resources.to_dict(),
        "endpoint_metadata": endpoint.metadata,
        "ssh_metadata": ssh.metadata,
        "appliance": runtime_metadata,
    }
    if docker_container is not None:
        metadata["docker_container"] = dict(docker_container)

    target = SSHDockerHostTarget(
        host=ssh.host,
        user=ssh.user,
        port=ssh.port,
        identity_file=ssh.identity_file,
        known_hosts_file=ssh.known_hosts_file,
        remote_work_root=remote_work_root,
        remote_artifact_root=remote_artifact_root,
        docker_command=_docker_command(appliance_metadata),
        metadata=metadata,
    )
    return EndpointApplianceTarget(
        endpoint_id=endpoint.endpoint_id,
        provider=endpoint.provider,
        exposure=endpoint.exposure,
        role=endpoint.role,
        target=target,
        interfaces=endpoint.interfaces,
        metadata=metadata,
    )


def read_endpoint_appliance_target(
    endpoint_id: str,
    config: WireConfig | None = None,
) -> EndpointApplianceTarget:
    """Read an endpoint manifest from state and resolve its appliance target."""

    return resolve_endpoint_appliance_target(read_endpoint_manifest(endpoint_id, config))


def render_endpoint_appliance_deploy_plan(
    target: EndpointApplianceTarget,
    *,
    env: Mapping[str, str] | None = None,
    image_tag: str | None = None,
    install_docker: bool = False,
    docker_install_script: str = DEFAULT_DOCKER_INSTALL_SCRIPT,
    image_archive_remote_path: str | None = None,
    remote_context_dir: str | None = None,
    connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
) -> EndpointApplianceDeployPlan:
    """Return a dry-run plan for deploying the appliance image to an endpoint."""

    if not isinstance(target, EndpointApplianceTarget):
        raise TypeError("target must be an EndpointApplianceTarget")
    _require_docker_execution_supported(target)
    ssh_target = target.target
    metadata_env = {} if env is None else dict(env)
    tag = requested_appliance_image(metadata_env) if image_tag is None else _require_non_empty_string(
        image_tag,
        "image_tag",
    )
    metadata_env[LIBCRAFTER_APPLIANCE_IMAGE] = tag
    image = appliance_image_metadata(
        env=metadata_env,
        docker_command=ssh_target.docker_command,
    )
    image["inspect_argv"] = _remote_image_inspect_argv(ssh_target, tag)

    commands = [
        render_docker_check_plan(ssh_target, connect_timeout=connect_timeout),
    ]
    if install_docker:
        commands.append(
            _render_ssh_command_plan(
                ssh_target,
                kind="ssh-docker-install",
                remote_command_argv=["sh", "-lc", docker_install_script],
                connect_timeout=connect_timeout,
                metadata={"explicit": True},
            )
        )
    commands.extend(
        [
            render_mkdir_plan(ssh_target, connect_timeout=connect_timeout),
            _render_ssh_command_plan(
                ssh_target,
                kind="ssh-docker-image-inspect",
                remote_command_argv=_remote_image_inspect_argv(ssh_target, tag),
                connect_timeout=connect_timeout,
                metadata={"image_tag": tag},
            ),
            _render_image_prepare_plan(
                ssh_target,
                tag=tag,
                image_archive_remote_path=image_archive_remote_path,
                remote_context_dir=remote_context_dir,
                connect_timeout=connect_timeout,
            ),
        ]
    )
    image["deploy_argv"] = commands[-1].remote_command_argv
    return EndpointApplianceDeployPlan(
        kind="endpoint-appliance-deploy-plan",
        endpoint_id=target.endpoint_id,
        target=target,
        commands=commands,
        image=image,
        install_docker=install_docker,
        metadata={
            "image_action": commands[-1].metadata["image_action"],
            "remote_work_root": ssh_target.remote_work_root,
            "remote_artifact_root": ssh_target.remote_artifact_root,
        },
    )


def deploy_endpoint_appliance_target(
    target: EndpointApplianceTarget,
    *,
    runner: CommandRunner,
    artifact_dir: str | Path | None = None,
    env: Mapping[str, str] | None = None,
    image_tag: str | None = None,
    install_docker: bool = False,
    docker_install_script: str = DEFAULT_DOCKER_INSTALL_SCRIPT,
    image_archive_remote_path: str | None = None,
    remote_context_dir: str | None = None,
    connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
    timeout: float | None = None,
) -> EndpointApplianceDeployResult:
    """Explicitly execute an endpoint appliance deploy plan with an injected runner."""

    if runner is None:
        raise ValueError("runner is required")
    plan = render_endpoint_appliance_deploy_plan(
        target,
        env=env,
        image_tag=image_tag,
        install_docker=install_docker,
        docker_install_script=docker_install_script,
        image_archive_remote_path=image_archive_remote_path,
        remote_context_dir=remote_context_dir,
        connect_timeout=connect_timeout,
    )
    output_dir = _deploy_artifact_dir(target, artifact_dir)
    command_results: list[EndpointApplianceDeployCommandResult] = []
    commands = {command.kind: command for command in plan.commands}

    docker_check = _execute_deploy_command(
        commands["ssh-docker-check"],
        name="01-docker-check",
        artifact_dir=output_dir,
        runner=runner,
        timeout=timeout,
    )
    command_results.append(docker_check)
    if not docker_check.ok:
        if not install_docker:
            return _deploy_result(plan, output_dir, command_results, ok=False)
        install = _execute_deploy_command(
            commands["ssh-docker-install"],
            name="02-docker-install",
            artifact_dir=output_dir,
            runner=runner,
            timeout=timeout,
        )
        command_results.append(install)
        if not install.ok:
            return _deploy_result(plan, output_dir, command_results, ok=False)
        post_install_check = _execute_deploy_command(
            commands["ssh-docker-check"],
            name="03-docker-check-after-install",
            artifact_dir=output_dir,
            runner=runner,
            timeout=timeout,
        )
        command_results.append(post_install_check)
        if not post_install_check.ok:
            return _deploy_result(plan, output_dir, command_results, ok=False)

    mkdir = _execute_deploy_command(
        commands["ssh-docker-mkdir"],
        name=f"{len(command_results) + 1:02d}-remote-mkdir",
        artifact_dir=output_dir,
        runner=runner,
        timeout=timeout,
    )
    command_results.append(mkdir)
    if not mkdir.ok:
        return _deploy_result(plan, output_dir, command_results, ok=False)

    inspect = _execute_deploy_command(
        commands["ssh-docker-image-inspect"],
        name=f"{len(command_results) + 1:02d}-image-inspect",
        artifact_dir=output_dir,
        runner=runner,
        timeout=timeout,
    )
    command_results.append(inspect)
    if inspect.ok:
        return _deploy_result(plan, output_dir, command_results, ok=True)

    prepare = _execute_deploy_command(
        commands["ssh-docker-image-build"]
        if "ssh-docker-image-build" in commands
        else commands["ssh-docker-image-load"],
        name=f"{len(command_results) + 1:02d}-image-prepare",
        artifact_dir=output_dir,
        runner=runner,
        timeout=timeout,
    )
    command_results.append(prepare)
    return _deploy_result(plan, output_dir, command_results, ok=prepare.ok)


def render_endpoint_appliance_sync_plan(
    target: EndpointApplianceTarget,
    *,
    source_root: str | Path | None = None,
    artifact_dir: str | Path | None = None,
    run_id: str = DEFAULT_APPLIANCE_SYNC_RUN_ID,
    archive_name: str = DEFAULT_APPLIANCE_SYNC_ARCHIVE_NAME,
    extra_excludes: Sequence[str] = (),
    connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
) -> EndpointApplianceSyncPlan:
    """Return a dry-run plan for syncing a local workspace to an endpoint."""

    if not isinstance(target, EndpointApplianceTarget):
        raise TypeError("target must be an EndpointApplianceTarget")
    ssh_target = target.target
    source = _absolute_existing_dir(source_root or _repository_root(), "source_root")
    run_component = _remote_component(run_id, "run_id")
    archive_filename = _archive_name(archive_name)
    output_dir = _sync_artifact_dir(target, artifact_dir, run_component, create=False)
    local_archive = output_dir / archive_filename
    excludes = _archive_excludes(
        source_root=source,
        archive_path=local_archive,
        artifact_dir=output_dir,
        extra_excludes=extra_excludes,
    )
    archive_command = [
        "tar",
        "-C",
        str(source),
        *[f"--exclude={exclude}" for exclude in excludes],
        "-czf",
        str(local_archive),
        ".",
    ]
    remote_run_root = _remote_absolute_path(
        posixpath.join(ssh_target.remote_work_root, "runs", run_component),
        "remote_run_root",
    )
    remote_workspace_dir = posixpath.join(remote_run_root, "workspace")
    remote_artifact_dir = _remote_absolute_path(
        posixpath.join(ssh_target.remote_artifact_root, "runs", run_component),
        "remote_artifact_dir",
    )
    remote_archive_path = posixpath.join(remote_run_root, archive_filename)
    mkdir_plan = _render_ssh_command_plan(
        ssh_target,
        kind="ssh-appliance-sync-mkdir",
        remote_command_argv=[
            "mkdir",
            "-p",
            remote_run_root,
            remote_workspace_dir,
            remote_artifact_dir,
        ],
        connect_timeout=connect_timeout,
        metadata={
            "paths": [remote_run_root, remote_workspace_dir, remote_artifact_dir],
            "run_id": run_component,
        },
    )
    upload_plan = _render_sync_upload_plan(
        ssh_target,
        local_archive=local_archive,
        remote_archive=remote_archive_path,
        connect_timeout=connect_timeout,
        metadata={
            "run_id": run_component,
            "archive_name": archive_filename,
        },
    )
    unpack_plan = _render_ssh_command_plan(
        ssh_target,
        kind="ssh-appliance-sync-unpack",
        remote_command_argv=[
            "sh",
            "-lc",
            _sync_unpack_script(
                remote_archive=remote_archive_path,
                remote_workspace_dir=remote_workspace_dir,
                remote_artifact_dir=remote_artifact_dir,
            ),
        ],
        connect_timeout=connect_timeout,
        metadata={
            "run_id": run_component,
            "remote_archive_path": remote_archive_path,
            "remote_workspace_dir": remote_workspace_dir,
            "remote_artifact_dir": remote_artifact_dir,
        },
    )
    return EndpointApplianceSyncPlan(
        kind="endpoint-appliance-sync-plan",
        endpoint_id=target.endpoint_id,
        target=target,
        source_root=str(source),
        run_id=run_component,
        local_archive_path=str(local_archive),
        remote_run_root=remote_run_root,
        remote_workspace_dir=remote_workspace_dir,
        remote_artifact_dir=remote_artifact_dir,
        remote_archive_path=remote_archive_path,
        archive_excludes=list(excludes),
        archive_command_argv=archive_command,
        commands=[mkdir_plan, upload_plan, unpack_plan],
        metadata={
            "archive_name": archive_filename,
            "remote_work_root": ssh_target.remote_work_root,
            "remote_artifact_root": ssh_target.remote_artifact_root,
        },
    )


def sync_endpoint_appliance_workspace(
    target: EndpointApplianceTarget,
    *,
    runner: CommandRunner,
    source_root: str | Path | None = None,
    artifact_dir: str | Path | None = None,
    run_id: str = DEFAULT_APPLIANCE_SYNC_RUN_ID,
    archive_name: str = DEFAULT_APPLIANCE_SYNC_ARCHIVE_NAME,
    extra_excludes: Sequence[str] = (),
    connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
    timeout: float | None = None,
) -> EndpointApplianceSyncResult:
    """Explicitly execute an endpoint appliance workspace sync with an injected runner."""

    if runner is None:
        raise ValueError("runner is required")
    plan = render_endpoint_appliance_sync_plan(
        target,
        source_root=source_root,
        artifact_dir=artifact_dir,
        run_id=run_id,
        archive_name=archive_name,
        extra_excludes=extra_excludes,
        connect_timeout=connect_timeout,
    )
    output_dir = Path(plan.local_archive_path).parent
    output_dir.mkdir(parents=True, exist_ok=True)
    command_results: list[EndpointApplianceSyncCommandResult] = []

    archive = runner(plan.archive_command_argv, cwd=plan.source_root, timeout=timeout)
    command_results.append(
        _record_sync_command_result(
            name="01-create-archive",
            kind="local-appliance-sync-archive",
            command_argv=plan.archive_command_argv,
            result=archive,
            artifact_dir=output_dir,
        )
    )
    if not archive.ok:
        return _sync_result(plan, output_dir, command_results, ok=False)

    for index, command in enumerate(plan.commands, start=2):
        result = _execute_sync_command(
            command,
            name=_sync_command_name(index, command.kind),
            artifact_dir=output_dir,
            runner=runner,
            timeout=timeout,
        )
        command_results.append(result)
        if not result.ok:
            return _sync_result(plan, output_dir, command_results, ok=False)

    return _sync_result(plan, output_dir, command_results, ok=True)


def render_endpoint_appliance_run_plan(
    target: EndpointApplianceTarget,
    profile: str | ApplianceProfile | Mapping[str, object],
    command_argv: Sequence[str],
    *,
    sync_context: (
        EndpointApplianceSyncPlan | EndpointApplianceSyncResult | Mapping[str, object] | None
    ) = None,
    artifact_dir: str | Path | None = None,
    run_id: str = DEFAULT_APPLIANCE_RUN_ID,
    image_tag: str | None = None,
    env: Mapping[str, str] | None = None,
    remote_work_root: str | None = None,
    remote_artifact_root: str | None = None,
    connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
    profile_dir: str | Path | None = None,
) -> EndpointApplianceRunPlan:
    """Return a dry-run plan for running an appliance command on an endpoint."""

    if not isinstance(target, EndpointApplianceTarget):
        raise TypeError("target must be an EndpointApplianceTarget")
    _require_docker_execution_supported(target)
    appliance_profile = _appliance_profile(profile, profile_dir=profile_dir)
    command = _command_sequence(command_argv, "command_argv")
    run_component, remote_work, remote_artifacts = _run_remote_paths(
        target,
        run_id=run_id,
        sync_context=sync_context,
        remote_work_root=remote_work_root,
        remote_artifact_root=remote_artifact_root,
    )
    local_artifacts = _run_artifact_dir(target, artifact_dir, run_component, create=False)
    stdout_path = local_artifacts / "run.stdout.txt"
    stderr_path = local_artifacts / "run.stderr.txt"
    metadata_path = local_artifacts / "run.metadata.json"
    docker_run = render_docker_run_plan(
        appliance_profile,
        image_tag=image_tag,
        work_dir=remote_work,
        artifact_dir=remote_artifacts,
        command_argv=command,
        env=env,
        docker_command=target.target.docker_command,
    )
    mkdir_plan = _render_ssh_command_plan(
        target.target,
        kind="ssh-appliance-run-mkdir",
        remote_command_argv=["mkdir", "-p", remote_work, remote_artifacts],
        connect_timeout=connect_timeout,
        metadata={
            "paths": [remote_work, remote_artifacts],
            "run_id": run_component,
        },
    )
    run_plan = _render_ssh_command_plan(
        target.target,
        kind="ssh-appliance-run-docker",
        remote_command_argv=docker_run.docker_argv,
        connect_timeout=connect_timeout,
        metadata={
            "run_id": run_component,
            "profile": appliance_profile.name,
            "image_tag": docker_run.image_tag,
            "remote_work_root": remote_work,
            "remote_artifact_root": remote_artifacts,
        },
    )
    return EndpointApplianceRunPlan(
        kind="endpoint-appliance-run-plan",
        endpoint_id=target.endpoint_id,
        target=target,
        profile=appliance_profile.name,
        image_tag=docker_run.image_tag,
        command_argv=command,
        run_id=run_component,
        remote_work_root=remote_work,
        remote_artifact_root=remote_artifacts,
        local_artifact_dir=str(local_artifacts),
        local_stdout_path=str(stdout_path),
        local_stderr_path=str(stderr_path),
        local_metadata_path=str(metadata_path),
        docker_run=docker_run,
        commands=[mkdir_plan, run_plan],
        metadata={
            "local_artifact_paths": {
                "stdout": str(stdout_path),
                "stderr": str(stderr_path),
                "metadata": str(metadata_path),
            },
            "remote_path_source": _run_remote_path_source(
                sync_context=sync_context,
                remote_work_root=remote_work_root,
                remote_artifact_root=remote_artifact_root,
            ),
        },
    )


def run_endpoint_appliance_command(
    target: EndpointApplianceTarget,
    profile: str | ApplianceProfile | Mapping[str, object],
    command_argv: Sequence[str],
    *,
    runner: CommandRunner,
    sync_context: (
        EndpointApplianceSyncPlan | EndpointApplianceSyncResult | Mapping[str, object] | None
    ) = None,
    artifact_dir: str | Path | None = None,
    run_id: str = DEFAULT_APPLIANCE_RUN_ID,
    image_tag: str | None = None,
    env: Mapping[str, str] | None = None,
    remote_work_root: str | None = None,
    remote_artifact_root: str | None = None,
    connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
    profile_dir: str | Path | None = None,
    timeout: float | None = None,
) -> EndpointApplianceRunResult:
    """Explicitly execute an endpoint appliance run plan with an injected runner."""

    if runner is None:
        raise ValueError("runner is required")
    plan = render_endpoint_appliance_run_plan(
        target,
        profile,
        command_argv,
        sync_context=sync_context,
        artifact_dir=artifact_dir,
        run_id=run_id,
        image_tag=image_tag,
        env=env,
        remote_work_root=remote_work_root,
        remote_artifact_root=remote_artifact_root,
        connect_timeout=connect_timeout,
        profile_dir=profile_dir,
    )
    output_dir = Path(plan.local_artifact_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    command_results: list[EndpointApplianceRunCommandResult] = []

    mkdir = _execute_run_command(
        plan.commands[0],
        name="01-remote-mkdir",
        artifact_dir=output_dir,
        runner=runner,
        timeout=timeout,
    )
    command_results.append(mkdir)
    if not mkdir.ok:
        result = _run_result(plan, command_results, ok=False, exit_code=mkdir.exit_code)
        _write_run_metadata(result)
        return result

    run = _execute_run_command(
        plan.commands[1],
        name="02-docker-run",
        artifact_dir=output_dir,
        runner=runner,
        timeout=timeout,
    )
    command_results.append(run)
    Path(plan.local_stdout_path).write_text(
        Path(run.stdout_path).read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    Path(plan.local_stderr_path).write_text(
        Path(run.stderr_path).read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    result = _run_result(plan, command_results, ok=run.ok, exit_code=run.exit_code)
    _write_run_metadata(result)
    return result


def _appliance_profile(
    value: str | ApplianceProfile | Mapping[str, object],
    *,
    profile_dir: str | Path | None,
) -> ApplianceProfile:
    if isinstance(value, ApplianceProfile):
        return value
    if isinstance(value, str):
        return resolve_profile(value, profile_dir=profile_dir)
    return ApplianceProfile.from_dict(value)


def _command_sequence(value: Sequence[str], name: str) -> list[str]:
    if isinstance(value, (str, bytes, bytearray)):
        raise ValueError(f"{name} must be a list")
    return _non_empty_string_list([str(item) for item in value], name)


def _run_remote_paths(
    target: EndpointApplianceTarget,
    *,
    run_id: str,
    sync_context: (
        EndpointApplianceSyncPlan | EndpointApplianceSyncResult | Mapping[str, object] | None
    ),
    remote_work_root: str | None,
    remote_artifact_root: str | None,
) -> tuple[str, str, str]:
    if (remote_work_root is None) != (remote_artifact_root is None):
        raise ValueError("remote_work_root and remote_artifact_root must be provided together")
    if remote_work_root is not None and remote_artifact_root is not None:
        return (
            _remote_component(run_id, "run_id"),
            _remote_absolute_path(remote_work_root, "remote_work_root"),
            _remote_absolute_path(remote_artifact_root, "remote_artifact_root"),
        )
    if sync_context is not None:
        context = _sync_context_run_paths(sync_context)
        return context

    run_component = _remote_component(run_id, "run_id")
    return (
        run_component,
        _remote_absolute_path(
            posixpath.join(target.target.remote_work_root, "runs", run_component, "workspace"),
            "remote_work_root",
        ),
        _remote_absolute_path(
            posixpath.join(target.target.remote_artifact_root, "runs", run_component),
            "remote_artifact_root",
        ),
    )


def _sync_context_run_paths(
    context: EndpointApplianceSyncPlan | EndpointApplianceSyncResult | Mapping[str, object],
) -> tuple[str, str, str]:
    if isinstance(context, EndpointApplianceSyncResult):
        return (
            context.plan.run_id,
            context.plan.remote_workspace_dir,
            context.plan.remote_artifact_dir,
        )
    if isinstance(context, EndpointApplianceSyncPlan):
        return (context.run_id, context.remote_workspace_dir, context.remote_artifact_dir)

    data = _mapping(context, "sync_context")
    plan_data = data.get("plan")
    if isinstance(plan_data, Mapping):
        data = _mapping(plan_data, "sync_context.plan")
    run_id = _require_non_empty_string(data.get("run_id"), "sync_context.run_id")
    work = data.get("remote_workspace_dir", data.get("remote_work_root"))
    artifacts = data.get("remote_artifact_dir", data.get("remote_artifact_root"))
    return (
        _remote_component(run_id, "sync_context.run_id"),
        _remote_absolute_path(
            _require_non_empty_string(work, "sync_context.remote_workspace_dir"),
            "sync_context.remote_workspace_dir",
        ),
        _remote_absolute_path(
            _require_non_empty_string(artifacts, "sync_context.remote_artifact_dir"),
            "sync_context.remote_artifact_dir",
        ),
    )


def _run_remote_path_source(
    *,
    sync_context: object,
    remote_work_root: str | None,
    remote_artifact_root: str | None,
) -> str:
    if remote_work_root is not None or remote_artifact_root is not None:
        return "explicit"
    if sync_context is not None:
        return "sync-context"
    return "default-run-id"


def _run_artifact_dir(
    target: EndpointApplianceTarget,
    artifact_dir: str | Path | None,
    run_id: str,
    *,
    create: bool,
) -> Path:
    if artifact_dir is not None:
        output = Path(_absolute_path(artifact_dir, "artifact_dir"))
    else:
        endpoint_artifact_dir = _optional_string(
            target.metadata.get("artifact_dir"),
            "metadata.artifact_dir",
        )
        if endpoint_artifact_dir is None:
            raise ValueError("artifact_dir is required when target metadata has no artifact_dir")
        output = (
            Path(_absolute_path(endpoint_artifact_dir, "metadata.artifact_dir"))
            / DEFAULT_APPLIANCE_RUN_ARTIFACT_DIRNAME
            / run_id
        )
    if create:
        output.mkdir(parents=True, exist_ok=True)
    return output.resolve(strict=False)


def _execute_run_command(
    plan: SSHCommandPlan,
    *,
    name: str,
    artifact_dir: Path,
    runner: CommandRunner,
    timeout: float | None,
) -> EndpointApplianceRunCommandResult:
    result = execute_command_plan(plan, runner=runner, timeout=timeout)
    return _record_run_command_result(
        name=name,
        kind=plan.kind,
        command_argv=plan.command_argv,
        result=result,
        artifact_dir=artifact_dir,
    )


def _record_run_command_result(
    *,
    name: str,
    kind: str,
    command_argv: list[str],
    result: CommandResult,
    artifact_dir: Path,
) -> EndpointApplianceRunCommandResult:
    stdout_path = artifact_dir / f"{name}.stdout.txt"
    stderr_path = artifact_dir / f"{name}.stderr.txt"
    stdout_path.write_text(result.stdout, encoding="utf-8")
    stderr_path.write_text(result.stderr, encoding="utf-8")
    return EndpointApplianceRunCommandResult(
        name=name,
        kind=kind,
        command_argv=command_argv,
        exit_code=result.exit_code,
        ok=result.ok,
        stdout_path=str(stdout_path),
        stderr_path=str(stderr_path),
        timed_out=result.timed_out,
        error=result.error,
    )


def _run_result(
    plan: EndpointApplianceRunPlan,
    command_results: list[EndpointApplianceRunCommandResult],
    *,
    ok: bool,
    exit_code: int,
) -> EndpointApplianceRunResult:
    return EndpointApplianceRunResult(
        kind="endpoint-appliance-run",
        endpoint_id=plan.endpoint_id,
        ok=ok,
        plan=plan,
        profile=plan.profile,
        image_tag=plan.image_tag,
        command_argv=plan.command_argv,
        exit_code=exit_code,
        remote_work_root=plan.remote_work_root,
        remote_artifact_root=plan.remote_artifact_root,
        local_artifact_dir=plan.local_artifact_dir,
        local_stdout_path=plan.local_stdout_path,
        local_stderr_path=plan.local_stderr_path,
        local_metadata_path=plan.local_metadata_path,
        artifact_dir=plan.local_artifact_dir,
        command_results=command_results,
        metadata={
            "commands_executed": len(command_results),
            "local_artifact_paths": {
                "stdout": plan.local_stdout_path,
                "stderr": plan.local_stderr_path,
                "metadata": plan.local_metadata_path,
            },
        },
    )


def _write_run_metadata(result: EndpointApplianceRunResult) -> None:
    path = Path(result.local_metadata_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _manifest(value: EndpointManifest | Mapping[str, object]) -> EndpointManifest:
    if isinstance(value, EndpointManifest):
        return value
    return EndpointManifest.from_dict(value)


def _remote_base(
    manifest: EndpointManifest,
    appliance_metadata: Mapping[str, object] | None,
) -> str:
    value = _optional_string(
        appliance_metadata.get("remote_base") if appliance_metadata is not None else None,
        "metadata.appliance.remote_base",
    )
    base = value if value is not None else DEFAULT_APPLIANCE_REMOTE_BASE
    return _remote_absolute_path(base, "metadata.appliance.remote_base")


def _remote_root(
    manifest: EndpointManifest,
    appliance_metadata: Mapping[str, object] | None,
    *,
    field_name: str,
    default_name: str,
    remote_base: str,
) -> str:
    value = _optional_string(
        appliance_metadata.get(field_name) if appliance_metadata is not None else None,
        f"metadata.appliance.{field_name}",
    )
    if value is not None:
        return _remote_absolute_path(value, f"metadata.appliance.{field_name}")
    endpoint_component = _remote_component(manifest.endpoint_id, "endpoint_id")
    return _remote_absolute_path(
        posixpath.join(remote_base, endpoint_component, default_name),
        f"metadata.appliance.{field_name}",
    )


def _docker_command(appliance_metadata: Mapping[str, object] | None) -> str:
    value = _optional_string(
        appliance_metadata.get("docker_command") if appliance_metadata is not None else None,
        "metadata.appliance.docker_command",
    )
    return "docker" if value is None else value


def _is_docker_endpoint(
    manifest: EndpointManifest,
    docker_container: Mapping[str, object] | None,
) -> bool:
    if manifest.provider == "docker":
        return True
    if manifest.ssh.metadata.get("transport") == DOCKER_ENDPOINT_TRANSPORT:
        return True
    container_type = (
        _optional_string(docker_container.get("type"), "metadata.docker.container.type")
        if docker_container is not None
        else None
    )
    return container_type == "docker-container"


def _is_appliance_capable(
    appliance_metadata: Mapping[str, object] | None,
    docker_container: Mapping[str, object] | None,
) -> bool:
    for value, name in (
        (
            appliance_metadata.get("appliance_capable")
            if appliance_metadata is not None
            else None,
            "metadata.appliance.appliance_capable",
        ),
        (
            docker_container.get("appliance_capable") if docker_container is not None else None,
            "metadata.docker.container.appliance_capable",
        ),
        (
            docker_container.get("is_appliance") if docker_container is not None else None,
            "metadata.docker.container.is_appliance",
        ),
    ):
        if value is None:
            continue
        return _bool(value, name)
    return False


def _nested_docker_supported(
    appliance_metadata: Mapping[str, object] | None,
    *,
    docker_endpoint: bool,
    appliance_capable: bool,
) -> bool:
    value = (
        appliance_metadata.get("nested_docker")
        if appliance_metadata is not None and "nested_docker" in appliance_metadata
        else None
    )
    if value is not None:
        return _bool(value, "metadata.appliance.nested_docker")
    if docker_endpoint:
        return False
    return True


def _target_kind(*, docker_endpoint: bool, appliance_capable: bool) -> str:
    if docker_endpoint and appliance_capable:
        return "docker-endpoint-appliance-container"
    if docker_endpoint:
        return "docker-endpoint-container"
    return "ssh-docker-host"


def _remote_absolute_path(value: str, name: str) -> str:
    path = _require_non_empty_string(value, name)
    if not path.startswith("/"):
        raise ValueError(f"{name} must be an absolute remote path")
    normalized = posixpath.normpath(path)
    if normalized == ".":
        raise ValueError(f"{name} must be an absolute remote path")
    return normalized


def _remote_component(value: str, name: str) -> str:
    component = _require_non_empty_string(value, name)
    if "/" in component or component in {".", ".."}:
        raise ValueError(f"{name} must be a single remote path component")
    return component


def _optional_mapping(value: object, name: str) -> Mapping[str, object] | None:
    if value is None:
        return None
    return _mapping(value, name)


def _mapping(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    for key in value:
        if not isinstance(key, str):
            raise ValueError(f"{name} keys must be strings")
    return value


def _optional_string(value: object, name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    return value


def _bool(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be a boolean")
    return value


def _require_non_empty_string(value: object, name: str) -> str:
    if not isinstance(value, str) or value == "":
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _int(value: object, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    return value


def _absolute_path(value: str | Path, name: str) -> str:
    path = Path(value)
    if not path.is_absolute():
        raise ValueError(f"{name} must be an absolute path")
    return str(path)


def _non_empty_string_list(value: object, name: str) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"{name} must be a list")
    output: list[str] = []
    for item in value:
        output.append(_require_non_empty_string(item, f"{name}[]"))
    if not output:
        raise ValueError(f"{name} must not be empty")
    return output


def _string_list(value: object, name: str) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"{name} must be a list")
    output: list[str] = []
    for item in value:
        output.append(_require_non_empty_string(item, f"{name}[]"))
    return output


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _absolute_existing_dir(path: str | Path, name: str) -> Path:
    output = Path(path).expanduser()
    if not output.is_absolute():
        output = Path.cwd() / output
    output = output.resolve(strict=False)
    if not output.exists():
        raise ValueError(f"{name} does not exist: {output}")
    if not output.is_dir():
        raise ValueError(f"{name} must be a directory: {output}")
    return output


def _sync_artifact_dir(
    target: EndpointApplianceTarget,
    artifact_dir: str | Path | None,
    run_id: str,
    *,
    create: bool,
) -> Path:
    if artifact_dir is not None:
        output = Path(_absolute_path(artifact_dir, "artifact_dir"))
    else:
        endpoint_artifact_dir = _optional_string(
            target.metadata.get("artifact_dir"),
            "metadata.artifact_dir",
        )
        if endpoint_artifact_dir is None:
            raise ValueError("artifact_dir is required when target metadata has no artifact_dir")
        output = Path(_absolute_path(endpoint_artifact_dir, "metadata.artifact_dir"))
        output = output / DEFAULT_APPLIANCE_SYNC_ARTIFACT_DIRNAME / run_id
    if create:
        output.mkdir(parents=True, exist_ok=True)
    return output.resolve(strict=False)


def _archive_excludes(
    *,
    source_root: Path,
    archive_path: Path,
    artifact_dir: Path,
    extra_excludes: Sequence[str],
) -> tuple[str, ...]:
    excludes: list[str] = list(DEFAULT_APPLIANCE_SYNC_ARCHIVE_EXCLUDES)
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


def _dedupe(values: list[str]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output


def _require_docker_execution_supported(target: EndpointApplianceTarget) -> None:
    appliance = _optional_mapping(target.metadata.get("appliance"), "metadata.appliance")
    if appliance is None:
        return
    supported = appliance.get("docker_execution_supported")
    if supported is None or _bool(supported, "metadata.appliance.docker_execution_supported"):
        return
    reason = appliance.get("docker_execution_disabled_reason")
    if isinstance(reason, str) and reason:
        raise ValueError(f"endpoint appliance target does not support Docker execution: {reason}")
    raise ValueError("endpoint appliance target does not support Docker execution")


def _remote_image_inspect_argv(target: SSHDockerHostTarget, tag: str) -> list[str]:
    return [target.docker_command, "image", "inspect", tag]


def _render_image_prepare_plan(
    target: SSHDockerHostTarget,
    *,
    tag: str,
    image_archive_remote_path: str | None,
    remote_context_dir: str | None,
    connect_timeout: int,
) -> SSHCommandPlan:
    if image_archive_remote_path is not None:
        archive_path = _remote_absolute_path(image_archive_remote_path, "image_archive_remote_path")
        return _render_ssh_command_plan(
            target,
            kind="ssh-docker-image-load",
            remote_command_argv=[target.docker_command, "load", "-i", archive_path],
            connect_timeout=connect_timeout,
            metadata={"image_action": "load", "image_archive_remote_path": archive_path},
        )
    context_dir = _remote_absolute_path(
        remote_context_dir or posixpath.join(target.remote_work_root, "tools", "appliance"),
        "remote_context_dir",
    )
    dockerfile_path = posixpath.join(context_dir, "Dockerfile")
    digest = appliance_image_context_digest()
    return _render_ssh_command_plan(
        target,
        kind="ssh-docker-image-build",
        remote_command_argv=[
            target.docker_command,
            "build",
            "-t",
            tag,
            "--label",
            f"{APPLIANCE_IMAGE_CONTEXT_LABEL}={digest}",
            "-f",
            dockerfile_path,
            context_dir,
        ],
        connect_timeout=connect_timeout,
        metadata={
            "image_action": "build",
            "image_tag": tag,
            "context_digest": digest,
            "context_label": APPLIANCE_IMAGE_CONTEXT_LABEL,
            "remote_context_dir": context_dir,
            "remote_dockerfile_path": dockerfile_path,
        },
    )


def _render_ssh_command_plan(
    target: SSHDockerHostTarget,
    *,
    kind: str,
    remote_command_argv: list[str],
    connect_timeout: int,
    metadata: Mapping[str, object] | None = None,
) -> SSHCommandPlan:
    remote_command = _non_empty_string_list(remote_command_argv, "remote_command_argv")
    return SSHCommandPlan(
        kind=kind,
        target=target,
        remote_command_argv=remote_command,
        command_argv=ssh_argv(
            host=target.host,
            user=target.user,
            identity_file=target.identity_file,
            known_hosts=target.known_hosts_file,
            command=remote_command,
            port=target.port,
            connect_timeout=connect_timeout,
        ),
        metadata={} if metadata is None else json_object(metadata, "metadata"),
    )


def _render_sync_upload_plan(
    target: SSHDockerHostTarget,
    *,
    local_archive: Path,
    remote_archive: str,
    connect_timeout: int,
    metadata: Mapping[str, object] | None = None,
) -> EndpointApplianceSyncTransferPlan:
    local_path = str(Path(_absolute_path(local_archive, "local_archive")))
    remote_path = _remote_absolute_path(remote_archive, "remote_archive")
    destination = f"{remote_host(host=target.host, user=target.user)}:{remote_path}"
    return EndpointApplianceSyncTransferPlan(
        kind="ssh-appliance-sync-upload",
        target=target,
        local_path=local_path,
        remote_path=remote_path,
        command_argv=scp_argv(
            source=local_path,
            destination=destination,
            identity_file=target.identity_file,
            known_hosts=target.known_hosts_file,
            port=target.port,
            connect_timeout=connect_timeout,
        ),
        metadata={} if metadata is None else json_object(metadata, "metadata"),
    )


def _sync_unpack_script(
    *,
    remote_archive: str,
    remote_workspace_dir: str,
    remote_artifact_dir: str,
) -> str:
    archive = shlex.quote(_remote_absolute_path(remote_archive, "remote_archive"))
    workspace = shlex.quote(_remote_absolute_path(remote_workspace_dir, "remote_workspace_dir"))
    artifacts = shlex.quote(_remote_absolute_path(remote_artifact_dir, "remote_artifact_dir"))
    return (
        "set -eu\n"
        f"rm -rf {workspace}\n"
        f"mkdir -p {workspace} {artifacts}\n"
        f"tar -xzf {archive} -C {workspace}"
    )


def _deploy_artifact_dir(
    target: EndpointApplianceTarget,
    artifact_dir: str | Path | None,
) -> Path:
    if artifact_dir is not None:
        output = Path(_absolute_path(artifact_dir, "artifact_dir"))
    else:
        endpoint_artifact_dir = _optional_string(
            target.metadata.get("artifact_dir"),
            "metadata.artifact_dir",
        )
        if endpoint_artifact_dir is None:
            raise ValueError("artifact_dir is required when target metadata has no artifact_dir")
        output = Path(_absolute_path(endpoint_artifact_dir, "metadata.artifact_dir"))
        output = output / DEFAULT_APPLIANCE_DEPLOY_ARTIFACT_DIRNAME
    output.mkdir(parents=True, exist_ok=True)
    return output


def _execute_deploy_command(
    plan: SSHCommandPlan,
    *,
    name: str,
    artifact_dir: Path,
    runner: CommandRunner,
    timeout: float | None,
) -> EndpointApplianceDeployCommandResult:
    result = execute_command_plan(plan, runner=runner, timeout=timeout)
    return _record_deploy_command_result(
        name=name,
        kind=plan.kind,
        command_argv=plan.command_argv,
        result=result,
        artifact_dir=artifact_dir,
    )


def _record_deploy_command_result(
    *,
    name: str,
    kind: str,
    command_argv: list[str],
    result: CommandResult,
    artifact_dir: Path,
) -> EndpointApplianceDeployCommandResult:
    stdout_path = artifact_dir / f"{name}.stdout.txt"
    stderr_path = artifact_dir / f"{name}.stderr.txt"
    stdout_path.write_text(result.stdout, encoding="utf-8")
    stderr_path.write_text(result.stderr, encoding="utf-8")
    return EndpointApplianceDeployCommandResult(
        name=name,
        kind=kind,
        command_argv=command_argv,
        exit_code=result.exit_code,
        ok=result.ok,
        stdout_path=str(stdout_path),
        stderr_path=str(stderr_path),
        timed_out=result.timed_out,
        error=result.error,
    )


def _execute_sync_command(
    plan: SSHCommandPlan | EndpointApplianceSyncTransferPlan,
    *,
    name: str,
    artifact_dir: Path,
    runner: CommandRunner,
    timeout: float | None,
) -> EndpointApplianceSyncCommandResult:
    result = runner(plan.command_argv, timeout=timeout)
    return _record_sync_command_result(
        name=name,
        kind=plan.kind,
        command_argv=plan.command_argv,
        result=result,
        artifact_dir=artifact_dir,
    )


def _record_sync_command_result(
    *,
    name: str,
    kind: str,
    command_argv: list[str],
    result: CommandResult,
    artifact_dir: Path,
) -> EndpointApplianceSyncCommandResult:
    stdout_path = artifact_dir / f"{name}.stdout.txt"
    stderr_path = artifact_dir / f"{name}.stderr.txt"
    stdout_path.write_text(result.stdout, encoding="utf-8")
    stderr_path.write_text(result.stderr, encoding="utf-8")
    return EndpointApplianceSyncCommandResult(
        name=name,
        kind=kind,
        command_argv=command_argv,
        exit_code=result.exit_code,
        ok=result.ok,
        stdout_path=str(stdout_path),
        stderr_path=str(stderr_path),
        timed_out=result.timed_out,
        error=result.error,
    )


def _sync_command_name(index: int, kind: str) -> str:
    suffixes = {
        "ssh-appliance-sync-mkdir": "remote-mkdir",
        "ssh-appliance-sync-upload": "upload-workspace",
        "ssh-appliance-sync-unpack": "unpack-workspace",
    }
    return f"{index:02d}-{suffixes.get(kind, kind)}"


def _sync_result(
    plan: EndpointApplianceSyncPlan,
    artifact_dir: Path,
    command_results: list[EndpointApplianceSyncCommandResult],
    *,
    ok: bool,
) -> EndpointApplianceSyncResult:
    return EndpointApplianceSyncResult(
        kind="endpoint-appliance-sync",
        endpoint_id=plan.endpoint_id,
        ok=ok,
        plan=plan,
        artifact_dir=str(artifact_dir),
        command_results=command_results,
        metadata={
            "commands_executed": len(command_results),
            "remote_workspace_dir": plan.remote_workspace_dir,
            "remote_artifact_dir": plan.remote_artifact_dir,
        },
    )


def _deploy_result(
    plan: EndpointApplianceDeployPlan,
    artifact_dir: Path,
    command_results: list[EndpointApplianceDeployCommandResult],
    *,
    ok: bool,
) -> EndpointApplianceDeployResult:
    return EndpointApplianceDeployResult(
        kind="endpoint-appliance-deploy",
        endpoint_id=plan.endpoint_id,
        ok=ok,
        plan=plan,
        artifact_dir=str(artifact_dir),
        command_results=command_results,
        metadata={"commands_executed": len(command_results)},
    )


__all__ = [
    "DEFAULT_APPLIANCE_REMOTE_BASE",
    "DEFAULT_APPLIANCE_DEPLOY_ARTIFACT_DIRNAME",
    "DEFAULT_APPLIANCE_RUN_ARTIFACT_DIRNAME",
    "DEFAULT_APPLIANCE_RUN_ID",
    "DEFAULT_APPLIANCE_SYNC_ARCHIVE_EXCLUDES",
    "DEFAULT_APPLIANCE_SYNC_ARCHIVE_NAME",
    "DEFAULT_APPLIANCE_SYNC_ARTIFACT_DIRNAME",
    "DEFAULT_APPLIANCE_SYNC_RUN_ID",
    "DEFAULT_DOCKER_INSTALL_SCRIPT",
    "DOCKER_ENDPOINT_TRANSPORT",
    "EndpointApplianceDeployCommandResult",
    "EndpointApplianceDeployPlan",
    "EndpointApplianceDeployResult",
    "EndpointApplianceRunCommandResult",
    "EndpointApplianceRunPlan",
    "EndpointApplianceRunResult",
    "EndpointApplianceSyncCommandResult",
    "EndpointApplianceSyncPlan",
    "EndpointApplianceSyncResult",
    "EndpointApplianceSyncTransferPlan",
    "EndpointApplianceTarget",
    "deploy_endpoint_appliance_target",
    "read_endpoint_appliance_target",
    "render_endpoint_appliance_deploy_plan",
    "render_endpoint_appliance_run_plan",
    "render_endpoint_appliance_sync_plan",
    "resolve_endpoint_appliance_target",
    "run_endpoint_appliance_command",
    "sync_endpoint_appliance_workspace",
]
