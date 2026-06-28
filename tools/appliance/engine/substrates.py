"""Appliance execution substrates for local plan rendering."""

from __future__ import annotations

import os
import platform
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from tools.appliance.engine import image
from tools.appliance.engine.checks import CheckPlan, render_profile_check_plans
from tools.appliance.engine.model import JSONObject, JsonModel, absolute_path, json_object
from tools.appliance.engine.profile import ALLOWED_PROFILE_NAMES, ApplianceProfile
from tools.appliance.engine.runtime import DockerRunPlan, render_docker_run_plan


LOCAL_SUBSTRATE = "local"
LOCAL_SUPPORTED_PROFILES = ALLOWED_PROFILE_NAMES
DEFAULT_ARTIFACT_SUBDIR = ".scratch/appliance-artifacts"


class UnknownApplianceSubstrateError(ValueError):
    """Raised when a substrate name is not available in this command surface."""

    def __init__(self, name: str, known: tuple[str, ...]) -> None:
        known_text = ", ".join(known) or "<none>"
        super().__init__(f"unknown appliance substrate {name!r}; known substrates: {known_text}")
        self.name = name
        self.known = known


class UnsupportedSubstrateProfileError(ValueError):
    """Raised when a substrate cannot render a requested profile."""

    def __init__(self, substrate: str, profile: str, supported: tuple[str, ...]) -> None:
        supported_text = ", ".join(supported) or "<none>"
        super().__init__(
            f"appliance substrate {substrate!r} does not support profile {profile!r}; "
            f"supported profiles: {supported_text}"
        )
        self.substrate = substrate
        self.profile = profile
        self.supported = supported


@dataclass(frozen=True, slots=True)
class LocalRunPlan(JsonModel):
    """A JSON-serializable local Docker-host appliance run plan."""

    ok: bool
    substrate: str
    mode: str
    profile: str
    work_dir: str
    artifact_dir: str
    environment: dict[str, str]
    checks: list[CheckPlan]
    run: DockerRunPlan
    safety: JSONObject = field(default_factory=dict)
    metadata: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "substrate", _non_empty_string(self.substrate, "substrate"))
        object.__setattr__(self, "mode", _non_empty_string(self.mode, "mode"))
        object.__setattr__(self, "profile", _non_empty_string(self.profile, "profile"))
        object.__setattr__(self, "work_dir", absolute_path(self.work_dir, "work_dir"))
        object.__setattr__(
            self,
            "artifact_dir",
            absolute_path(self.artifact_dir, "artifact_dir"),
        )
        object.__setattr__(self, "environment", _environment(self.environment, "environment"))
        object.__setattr__(self, "checks", _check_plans(self.checks))
        if not isinstance(self.run, DockerRunPlan):
            raise ValueError("run must be a DockerRunPlan")
        object.__setattr__(self, "safety", json_object(self.safety, "safety"))
        object.__setattr__(self, "metadata", json_object(self.metadata, "metadata"))


@dataclass(frozen=True, slots=True)
class LocalDockerHostSubstrate:
    """Plan appliance checks and Docker runs for the current local host."""

    name: str = LOCAL_SUBSTRATE
    supported_profiles: tuple[str, ...] = LOCAL_SUPPORTED_PROFILES

    def render_check_plans(
        self,
        profile: ApplianceProfile,
        *,
        environment: Mapping[str, str] | None = None,
        host_environment: Mapping[str, str] | None = None,
        docker_command: str | None = None,
        image_tag: str | None = None,
    ) -> list[CheckPlan]:
        self._require_supported(profile)
        resolved_env = local_profile_environment(
            profile,
            environment=environment,
            host_environment=host_environment,
        )
        env_source = _merged_env_source(host_environment, environment)
        return render_profile_check_plans(
            profile,
            environment=resolved_env,
            docker_command=docker_command or image.requested_docker_command(env_source),
            image_tag=image_tag or image.requested_appliance_image(env_source),
        )

    def render_run_plan(
        self,
        profile: ApplianceProfile,
        *,
        command_argv: Sequence[str],
        work_dir: str | Path | None = None,
        artifact_dir: str | Path | None = None,
        environment: Mapping[str, str] | None = None,
        host_environment: Mapping[str, str] | None = None,
        repo_root: str | Path | None = None,
        docker_command: str | None = None,
        image_tag: str | None = None,
    ) -> LocalRunPlan:
        self._require_supported(profile)
        root = _repo_root(repo_root)
        resolved_work_dir = _absolute_or_default(work_dir, root)
        resolved_artifact_dir = _absolute_or_default(
            artifact_dir,
            root / DEFAULT_ARTIFACT_SUBDIR,
        )
        resolved_env = local_profile_environment(
            profile,
            environment=environment,
            host_environment=host_environment,
        )
        env_source = _merged_env_source(host_environment, environment)
        resolved_docker_command = docker_command or image.requested_docker_command(env_source)
        resolved_image_tag = image_tag or image.requested_appliance_image(env_source)
        checks = render_profile_check_plans(
            profile,
            environment=resolved_env,
            docker_command=resolved_docker_command,
            image_tag=resolved_image_tag,
        )
        run = render_docker_run_plan(
            profile,
            image_tag=resolved_image_tag,
            work_dir=resolved_work_dir,
            artifact_dir=resolved_artifact_dir,
            command_argv=command_argv,
            environment=resolved_env,
            docker_command=resolved_docker_command,
        )
        return LocalRunPlan(
            ok=True,
            substrate=self.name,
            mode="plan-only",
            profile=profile.name,
            work_dir=str(resolved_work_dir),
            artifact_dir=str(resolved_artifact_dir),
            environment=resolved_env,
            checks=checks,
            run=run,
            safety=_local_safety(profile),
            metadata={
                "host": {
                    "system": platform.system().lower(),
                },
                "default_artifact_subdir": DEFAULT_ARTIFACT_SUBDIR,
            },
        )

    def _require_supported(self, profile: ApplianceProfile) -> None:
        if profile.name not in self.supported_profiles:
            raise UnsupportedSubstrateProfileError(
                self.name,
                profile.name,
                tuple(self.supported_profiles),
            )


def resolve_substrate(name: str = LOCAL_SUBSTRATE) -> LocalDockerHostSubstrate:
    """Return a substrate implementation by stable name."""

    if name == LOCAL_SUBSTRATE:
        return LocalDockerHostSubstrate()
    raise UnknownApplianceSubstrateError(name, (LOCAL_SUBSTRATE,))


def list_substrate_names() -> tuple[str, ...]:
    """Return available appliance substrate names in deterministic order."""

    return (LOCAL_SUBSTRATE,)


def render_local_check_plans(
    profile: ApplianceProfile,
    *,
    environment: Mapping[str, str] | None = None,
    host_environment: Mapping[str, str] | None = None,
    docker_command: str | None = None,
    image_tag: str | None = None,
) -> list[CheckPlan]:
    """Render local readiness check plans without executing them."""

    return LocalDockerHostSubstrate().render_check_plans(
        profile,
        environment=environment,
        host_environment=host_environment,
        docker_command=docker_command,
        image_tag=image_tag,
    )


def render_local_run_plan(
    profile: ApplianceProfile,
    *,
    command_argv: Sequence[str],
    work_dir: str | Path | None = None,
    artifact_dir: str | Path | None = None,
    environment: Mapping[str, str] | None = None,
    host_environment: Mapping[str, str] | None = None,
    repo_root: str | Path | None = None,
    docker_command: str | None = None,
    image_tag: str | None = None,
) -> LocalRunPlan:
    """Render a local Docker-host run plan without executing Docker."""

    return LocalDockerHostSubstrate().render_run_plan(
        profile,
        command_argv=command_argv,
        work_dir=work_dir,
        artifact_dir=artifact_dir,
        environment=environment,
        host_environment=host_environment,
        repo_root=repo_root,
        docker_command=docker_command,
        image_tag=image_tag,
    )


def local_profile_environment(
    profile: ApplianceProfile,
    *,
    environment: Mapping[str, str] | None = None,
    host_environment: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return profile-scoped env values from host env plus explicit overrides."""

    host = os.environ if host_environment is None else host_environment
    explicit = _environment(environment or {}, "environment")
    output: dict[str, str] = {}
    for key, default in profile.env.items():
        output[key] = explicit.get(key, host.get(key, default))
    output.update(explicit)
    return output


def _local_safety(profile: ApplianceProfile) -> JSONObject:
    live_gate_required = profile.name in {"wan-raw", "lan-raw", "dot11-monitor"}
    return {
        "executes": False,
        "docker_executes": False,
        "plan_only": True,
        "live_raw_packet_work_requires_endpoint_or_lab_gate": live_gate_required,
        "notes": [
            "run-plan renders check and Docker argv only",
            "local substrate planning does not authorize live raw packet work",
        ],
    }


def _repo_root(repo_root: str | Path | None) -> Path:
    if repo_root is not None:
        return Path(repo_root).expanduser().resolve(strict=False)
    configured = os.environ.get("LIBCRAFTER_REPO_ROOT")
    if configured:
        return Path(configured).expanduser().resolve(strict=False)
    return Path.cwd().resolve(strict=False)


def _absolute_or_default(value: str | Path | None, default: Path) -> Path:
    if value is None:
        return default.resolve(strict=False)
    return Path(value).expanduser().resolve(strict=False)


def _merged_env_source(
    host_environment: Mapping[str, str] | None,
    environment: Mapping[str, str] | None,
) -> dict[str, str]:
    host = os.environ if host_environment is None else host_environment
    output = _environment(host, "host_environment")
    output.update(_environment(environment or {}, "environment"))
    return output


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


def _check_plans(value: Sequence[CheckPlan]) -> list[CheckPlan]:
    if not isinstance(value, Sequence):
        raise ValueError("checks must be a list of CheckPlan values")
    output: list[CheckPlan] = []
    for item in value:
        if not isinstance(item, CheckPlan):
            raise ValueError("checks must be a list of CheckPlan values")
        output.append(item)
    return output


def _non_empty_string(value: object, name: str) -> str:
    if not isinstance(value, str) or value == "":
        raise ValueError(f"{name} must be a non-empty string")
    return value


__all__ = [
    "DEFAULT_ARTIFACT_SUBDIR",
    "LOCAL_SUBSTRATE",
    "LOCAL_SUPPORTED_PROFILES",
    "LocalDockerHostSubstrate",
    "LocalRunPlan",
    "UnknownApplianceSubstrateError",
    "UnsupportedSubstrateProfileError",
    "local_profile_environment",
    "list_substrate_names",
    "render_local_check_plans",
    "render_local_run_plan",
    "resolve_substrate",
]
