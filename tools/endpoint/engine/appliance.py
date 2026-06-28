"""Resolve endpoint manifests into appliance execution targets."""

from __future__ import annotations

import posixpath
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from tools.appliance.engine.image import (
    APPLIANCE_IMAGE_CONTEXT_LABEL,
    LIBCRAFTER_APPLIANCE_IMAGE,
    appliance_image_context_digest,
    appliance_image_metadata,
    requested_appliance_image,
)
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
from .ssh import DEFAULT_CONNECT_TIMEOUT, ssh_argv


DEFAULT_APPLIANCE_REMOTE_BASE = "/var/lib/libcrafter/appliance"
DOCKER_ENDPOINT_TRANSPORT = "docker-localhost-port-forward"
DEFAULT_APPLIANCE_DEPLOY_ARTIFACT_DIRNAME = "appliance-deploy"
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
    "DEFAULT_DOCKER_INSTALL_SCRIPT",
    "DOCKER_ENDPOINT_TRANSPORT",
    "EndpointApplianceDeployCommandResult",
    "EndpointApplianceDeployPlan",
    "EndpointApplianceDeployResult",
    "EndpointApplianceTarget",
    "deploy_endpoint_appliance_target",
    "read_endpoint_appliance_target",
    "render_endpoint_appliance_deploy_plan",
    "resolve_endpoint_appliance_target",
]
