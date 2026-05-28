"""Probe-owned endpoint bootstrap plans and lab bootstrap hooks."""

from __future__ import annotations

from collections.abc import Callable

from tools.lab.engine import bootstrap as lab_bootstrap
from tools.lab.engine.repo import RepoBootstrapCommand, RepoBootstrapContext

from .lab import STIMULUS_ROLE, TARGET_ROLE


BOOTSTRAP_ROLES = (STIMULUS_ROLE, TARGET_ROLE)
STIMULUS_BOOTSTRAP_PACKAGES = (
    "build-essential",
    "ca-certificates",
    "clang",
    "curl",
    "git",
    "iproute2",
    "iptables",
    "iputils-ping",
    "libpcap-dev",
    "pkg-config",
    "python3",
)
TARGET_BOOTSTRAP_PACKAGES = (
    "ca-certificates",
    "curl",
    "git",
    "iproute2",
    "iputils-ping",
    "python3",
)
STIMULUS_BUILD_COMMAND = "cargo build -p probe-adapters --bin stimulus_endpoint"


def bootstrap_commands() -> dict[str, Callable[[RepoBootstrapContext], RepoBootstrapCommand]]:
    """Return role-to-hook mappings for probe lab repository bootstrap."""

    return {
        STIMULUS_ROLE: repo_bootstrap_command,
        TARGET_ROLE: repo_bootstrap_command,
    }


def repo_bootstrap_command(context: RepoBootstrapContext) -> RepoBootstrapCommand:
    """Render a probe workload bootstrap command from lab repository context."""

    role = context.role.name
    if role not in BOOTSTRAP_ROLES:
        raise ValueError(f"unsupported probe bootstrap role: {role}")
    return RepoBootstrapCommand(
        argv=["bash", "-lc", _bootstrap_script(context)],
        timeout=1800,
        metadata={
            "workload": "probe",
            "role": role,
            "builds_stimulus_endpoint": role == STIMULUS_ROLE,
        },
    )


def _bootstrap_script(context: RepoBootstrapContext) -> str:
    role = context.role.name
    if role == STIMULUS_ROLE:
        return lab_bootstrap.render_workload_bootstrap_script(
            context,
            artifact_subdir=("probe", "bootstrap"),
            packages=STIMULUS_BOOTSTRAP_PACKAGES,
            install_rust=True,
            cargo_build_commands=[STIMULUS_BUILD_COMMAND],
            env_artifacts=[_stimulus_env_artifact()],
        )
    if role == TARGET_ROLE:
        return lab_bootstrap.render_workload_bootstrap_script(
            context,
            artifact_subdir=("probe", "bootstrap"),
            packages=TARGET_BOOTSTRAP_PACKAGES,
            load_rust_env=False,
            env_artifacts=[_target_env_artifact()],
        )
    raise ValueError(f"unsupported probe bootstrap role: {role}")


def _stimulus_env_artifact() -> lab_bootstrap.BootstrapEnvArtifact:
    return lab_bootstrap.BootstrapEnvArtifact(
        values={
            "repository_synced": "true",
            "libcrafter_probe_bin": "stimulus_endpoint",
            "libcrafter_probe_bin_build": "ok",
        },
        shell_values={
            "role": "$LIBCRAFTER_ENDPOINT_ROLE",
            "private_ipv4": "$LIBCRAFTER_PRIVATE_IPV4",
            "peer_private_ipv4": "$LIBCRAFTER_PEER_PRIVATE_IPV4",
            "private_interface": "$LIBCRAFTER_PRIVATE_INTERFACE",
            "finished_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
        },
    )


def _target_env_artifact() -> lab_bootstrap.BootstrapEnvArtifact:
    return lab_bootstrap.BootstrapEnvArtifact(
        values={
            "repository_synced": "true",
            "target_service_runtime": "python3",
        },
        shell_values={
            "role": "$LIBCRAFTER_ENDPOINT_ROLE",
            "private_ipv4": "$LIBCRAFTER_PRIVATE_IPV4",
            "peer_private_ipv4": "$LIBCRAFTER_PEER_PRIVATE_IPV4",
            "private_interface": "$LIBCRAFTER_PRIVATE_INTERFACE",
            "finished_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
        },
    )
