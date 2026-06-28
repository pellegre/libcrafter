"""Deterministic Docker run plan rendering for appliance workloads."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from tools.appliance.engine.image import DOCKER_COMMAND
from tools.appliance.engine.model import JsonModel, absolute_path, require_non_empty_string
from tools.appliance.engine.profile import ApplianceProfile, ProfileDevice, ProfileMount


CONTAINER_WORK_DIR = "/work"
CONTAINER_ARTIFACT_DIR = "/artifacts"


@dataclass(frozen=True, slots=True)
class DockerRunPlan(JsonModel):
    """A JSON-serializable Docker run command plan that does not execute Docker."""

    profile: str
    image_tag: str
    work_dir: str
    artifact_dir: str
    command_argv: list[str]
    network_mode: str = "bridge"
    cap_add: list[str] = field(default_factory=list)
    devices: list[ProfileDevice] = field(default_factory=list)
    mounts: list[ProfileMount] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    docker_command: str = DOCKER_COMMAND
    container_work_dir: str = CONTAINER_WORK_DIR
    container_artifact_dir: str = CONTAINER_ARTIFACT_DIR
    docker_argv: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        profile = require_non_empty_string(self.profile, "profile")
        image_tag = require_non_empty_string(self.image_tag, "image_tag")
        work_dir = absolute_path(self.work_dir, "work_dir")
        artifact_dir = absolute_path(self.artifact_dir, "artifact_dir")
        command_argv = _command_argv(self.command_argv)
        network_mode = require_non_empty_string(self.network_mode, "network_mode")
        cap_add = _capabilities(self.cap_add)
        devices = _devices(self.devices)
        mounts = _mounts(self.mounts)
        env = _environment(self.env, "env")
        docker_command = require_non_empty_string(self.docker_command, "docker_command")
        container_work_dir = require_non_empty_string(
            self.container_work_dir,
            "container_work_dir",
        )
        container_artifact_dir = require_non_empty_string(
            self.container_artifact_dir,
            "container_artifact_dir",
        )

        object.__setattr__(self, "profile", profile)
        object.__setattr__(self, "image_tag", image_tag)
        object.__setattr__(self, "work_dir", work_dir)
        object.__setattr__(self, "artifact_dir", artifact_dir)
        object.__setattr__(self, "command_argv", command_argv)
        object.__setattr__(self, "network_mode", network_mode)
        object.__setattr__(self, "cap_add", cap_add)
        object.__setattr__(self, "devices", devices)
        object.__setattr__(self, "mounts", mounts)
        object.__setattr__(self, "env", env)
        object.__setattr__(self, "docker_command", docker_command)
        object.__setattr__(self, "container_work_dir", container_work_dir)
        object.__setattr__(self, "container_artifact_dir", container_artifact_dir)

        docker_argv = self.docker_argv or docker_run_argv(
            docker_command=docker_command,
            image_tag=image_tag,
            work_dir=work_dir,
            artifact_dir=artifact_dir,
            container_work_dir=container_work_dir,
            container_artifact_dir=container_artifact_dir,
            command_argv=command_argv,
            network_mode=network_mode,
            cap_add=cap_add,
            devices=devices,
            mounts=mounts,
            env=env,
        )
        object.__setattr__(self, "docker_argv", _string_list(docker_argv, "docker_argv"))


def render_docker_run_plan(
    profile: ApplianceProfile | Mapping[str, object],
    image_tag: str | None = None,
    work_dir: str | Path | None = None,
    artifact_dir: str | Path | None = None,
    command_argv: Sequence[str] | None = None,
    *,
    command: Sequence[str] | None = None,
    devices: Sequence[ProfileDevice | Mapping[str, object]] = (),
    mounts: Sequence[ProfileMount | Mapping[str, object]] = (),
    environment: Mapping[str, str] | None = None,
    env: Mapping[str, str] | None = None,
    network_mode: str | None = None,
    cap_add: Sequence[str] = (),
    capabilities: Sequence[str] = (),
    docker_command: str = DOCKER_COMMAND,
) -> DockerRunPlan:
    """Return a deterministic Docker run plan for an appliance profile."""

    appliance_profile = _profile(profile)
    selected_command = command_argv if command_argv is not None else command
    if work_dir is None:
        raise ValueError("work_dir must be an absolute path")
    if artifact_dir is None:
        raise ValueError("artifact_dir must be an absolute path")
    if selected_command is None:
        raise ValueError("command_argv must not be empty")

    merged_env = dict(appliance_profile.env)
    if environment is not None:
        merged_env.update(_environment(environment, "environment"))
    if env is not None:
        merged_env.update(_environment(env, "env"))

    return DockerRunPlan(
        profile=appliance_profile.name,
        image_tag=image_tag or appliance_profile.image,
        work_dir=absolute_path(work_dir, "work_dir"),
        artifact_dir=absolute_path(artifact_dir, "artifact_dir"),
        command_argv=_command_argv(selected_command),
        network_mode=network_mode or appliance_profile.network_mode,
        cap_add=_dedupe(
            [
                *appliance_profile.cap_add,
                *_string_list(cap_add, "cap_add"),
                *_string_list(capabilities, "capabilities"),
            ]
        ),
        devices=[*appliance_profile.devices, *_devices(devices)],
        mounts=[*appliance_profile.mounts, *_mounts(mounts)],
        env=merged_env,
        docker_command=docker_command,
    )


def docker_run_plan(*args: object, **kwargs: object) -> DockerRunPlan:
    """Compatibility wrapper for callers that use the shorter plan name."""

    return render_docker_run_plan(*args, **kwargs)


def docker_run_argv(
    *,
    docker_command: str,
    image_tag: str,
    work_dir: str,
    artifact_dir: str,
    container_work_dir: str,
    container_artifact_dir: str,
    command_argv: Sequence[str],
    network_mode: str,
    cap_add: Sequence[str],
    devices: Sequence[ProfileDevice],
    mounts: Sequence[ProfileMount],
    env: Mapping[str, str],
) -> list[str]:
    """Render the shell-safe Docker argv for a validated run plan."""

    argv = [
        require_non_empty_string(docker_command, "docker_command"),
        "run",
        "--rm",
        "--network",
        require_non_empty_string(network_mode, "network_mode"),
        "--workdir",
        require_non_empty_string(container_work_dir, "container_work_dir"),
        "--mount",
        _mount_arg(work_dir, container_work_dir, read_only=False),
        "--mount",
        _mount_arg(artifact_dir, container_artifact_dir, read_only=False),
    ]

    for mount in _mounts(mounts):
        argv.extend(["--mount", _mount_arg(mount.source, mount.target, mount.read_only)])
    for device in _devices(devices):
        argv.extend(["--device", _device_arg(device)])
    for capability in _capabilities(cap_add):
        argv.extend(["--cap-add", capability])
    for key, value in sorted(_environment(env, "env").items()):
        argv.extend(["--env", f"{key}={value}"])
    argv.append(require_non_empty_string(image_tag, "image_tag"))
    argv.extend(_command_argv(command_argv))
    _reject_privileged(argv)
    return argv


def _profile(value: ApplianceProfile | Mapping[str, object]) -> ApplianceProfile:
    if isinstance(value, ApplianceProfile):
        return value
    return ApplianceProfile.from_dict(value)


def _command_argv(value: Sequence[str]) -> list[str]:
    command = _string_list(value, "command_argv")
    if not command:
        raise ValueError("command_argv must not be empty")
    if command[0] == "":
        raise ValueError("command_argv[0] must be a non-empty string")
    _reject_privileged(command)
    return command


def _capabilities(value: Sequence[str]) -> list[str]:
    capabilities = _string_list(value, "cap_add")
    for capability in capabilities:
        if capability == "":
            raise ValueError("cap_add entries must be non-empty strings")
        if capability.startswith("-"):
            raise ValueError("cap_add entries must be Linux capability names")
    _reject_privileged(capabilities)
    return capabilities


def _devices(value: Sequence[ProfileDevice | Mapping[str, object]]) -> list[ProfileDevice]:
    devices: list[ProfileDevice] = []
    for item in _sequence(value, "devices"):
        device = item if isinstance(item, ProfileDevice) else ProfileDevice.from_dict(item)
        _reject_docker_socket_path(device.host_path, "device.host_path")
        _reject_docker_socket_path(device.container_path, "device.container_path")
        devices.append(device)
    return devices


def _mounts(value: Sequence[ProfileMount | Mapping[str, object]]) -> list[ProfileMount]:
    mounts: list[ProfileMount] = []
    for item in _sequence(value, "mounts"):
        mount = item if isinstance(item, ProfileMount) else ProfileMount.from_dict(item)
        _reject_docker_socket_path(mount.source, "mount.source")
        _reject_docker_socket_path(mount.target, "mount.target")
        mounts.append(mount)
    return mounts


def _environment(value: Mapping[str, str], name: str) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    output: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or key == "":
            raise ValueError(f"{name} keys must be non-empty strings")
        if "=" in key:
            raise ValueError(f"{name} keys must not contain '='")
        if not isinstance(item, str):
            raise ValueError(f"{name}.{key} must be a string")
        output[key] = item
    return output


def _mount_arg(source: str, target: str, read_only: bool) -> str:
    _reject_docker_socket_path(source, "mount.source")
    _reject_docker_socket_path(target, "mount.target")
    source_text = absolute_path(source, "mount.source")
    target_text = require_non_empty_string(target, "mount.target")
    parts = [f"type=bind", f"source={source_text}", f"target={target_text}"]
    if read_only:
        parts.append("readonly")
    return ",".join(parts)


def _device_arg(device: ProfileDevice) -> str:
    return f"{device.host_path}:{device.container_path}:{device.permissions}"


def _dedupe(values: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            output.append(value)
    return output


def _reject_privileged(values: Sequence[str]) -> None:
    if "--privileged" in values:
        raise ValueError("--privileged is not allowed in appliance Docker run plans")


def _reject_docker_socket_path(value: str, name: str) -> None:
    path = require_non_empty_string(value, name).replace("\\", "/")
    leaf = path.rstrip("/").rsplit("/", maxsplit=1)[-1]
    if leaf == "docker.sock":
        raise ValueError("Docker socket mounts are not allowed")


def _string_list(value: Sequence[str], name: str) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError(f"{name} must be a list of strings")
    output: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"{name} must be a list of strings")
        output.append(item)
    return output


def _sequence(value: object, name: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError(f"{name} must be a list")
    return value


__all__ = [
    "CONTAINER_ARTIFACT_DIR",
    "CONTAINER_WORK_DIR",
    "DockerRunPlan",
    "docker_run_plan",
    "docker_run_argv",
    "render_docker_run_plan",
]
