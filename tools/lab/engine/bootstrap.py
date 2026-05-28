"""Provider-neutral shell helpers for lab workload bootstrap scripts."""

from __future__ import annotations

import posixpath
import re
import shlex
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from .repo import RepoBootstrapContext


CLOUD_INIT_WAIT_LINE = (
    "if command -v cloud-init >/dev/null 2>&1; then "
    "cloud-init status --wait >/dev/null 2>&1 || true; fi"
)
DEBIAN_FRONTEND_LINE = "export DEBIAN_FRONTEND=noninteractive"
BOOTSTRAP_ARTIFACT_DIR_ENV = "LIBCRAFTER_BOOTSTRAP_ARTIFACT_DIR"
_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass(frozen=True, slots=True)
class BootstrapEnvArtifact:
    """A simple ``key=value`` environment artifact emitted by bootstrap shell."""

    filename: str = "bootstrap.env"
    values: Mapping[str, str] = field(default_factory=dict)
    shell_values: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "filename",
            "/".join(_relative_artifact_parts(self.filename, name="filename")),
        )
        object.__setattr__(
            self,
            "values",
            _env_mapping(self.values, "values"),
        )
        object.__setattr__(
            self,
            "shell_values",
            _env_mapping(self.shell_values, "shell_values"),
        )


def render_workload_bootstrap_script(
    context: RepoBootstrapContext,
    *,
    artifact_subdir: str | Sequence[str] = "bootstrap",
    wait_for_cloud_init: bool = True,
    export_debian_frontend: bool = True,
    packages: Sequence[str] = (),
    install_rust: bool = False,
    load_rust_env: bool = True,
    rust_profile: str = "minimal",
    cargo_build_commands: Sequence[str] = (),
    extra_lines: Sequence[str] = (),
    env_artifacts: Sequence[BootstrapEnvArtifact] = (),
    require_peer: bool = True,
) -> str:
    """Render a generic workload bootstrap shell script for one lab endpoint."""

    artifact_dir = role_artifact_dir(context, artifact_subdir)
    lines: list[str] = ["set -euo pipefail"]
    if wait_for_cloud_init:
        lines.append(CLOUD_INIT_WAIT_LINE)
    lines.append(cd_remote_dir_line(context))
    lines.extend(context_export_lines(context, require_peer=require_peer))
    if export_debian_frontend:
        lines.append(DEBIAN_FRONTEND_LINE)
    lines.extend(role_artifact_dir_lines(artifact_dir))
    lines.extend(package_install_lines(packages))
    if install_rust or load_rust_env:
        lines.extend(
            rust_toolchain_lines(
                install=install_rust,
                load_env=load_rust_env,
                profile=rust_profile,
            )
        )
    lines.extend(cargo_build_lines(cargo_build_commands))
    lines.extend(_shell_lines(extra_lines, "extra_lines"))
    for artifact in _env_artifacts(env_artifacts):
        lines.extend(environment_artifact_lines(artifact_dir, artifact))
    return "\n".join(lines)


def cd_remote_dir_line(context: RepoBootstrapContext) -> str:
    """Return the command that enters the already-unpacked repository."""

    return f"cd {shlex.quote(context.remote_dir)}"


def context_export_lines(
    context: RepoBootstrapContext,
    *,
    require_peer: bool = True,
) -> list[str]:
    """Return standard lab endpoint context exports."""

    peer_ipv4 = peer_private_ipv4(context, required=require_peer)
    return [
        f"export LIBCRAFTER_ENDPOINT_ROLE={shlex.quote(context.role.name)}",
        f"export LIBCRAFTER_PRIVATE_IPV4={shlex.quote(context.endpoint.ipv4)}",
        f"export LIBCRAFTER_PEER_PRIVATE_IPV4={shlex.quote(peer_ipv4)}",
        f"export LIBCRAFTER_PRIVATE_INTERFACE={shlex.quote(context.endpoint.interface)}",
    ]


def peer_private_ipv4(
    context: RepoBootstrapContext,
    *,
    required: bool = True,
) -> str:
    """Return the first peer endpoint IPv4 address from the lab context."""

    peers = context.peer_endpoints
    if peers:
        return peers[0].ipv4
    if required:
        raise ValueError(f"bootstrap role {context.role.name!r} requires a peer endpoint")
    return ""


def role_artifact_dir(
    context: RepoBootstrapContext,
    artifact_subdir: str | Sequence[str] = "bootstrap",
) -> str:
    """Return a role-specific artifact directory under the lab artifact root."""

    parts = _relative_artifact_parts(artifact_subdir, name="artifact_subdir")
    return posixpath.join(context.remote_artifact_root, *parts, context.role.name)


def role_artifact_dir_lines(artifact_dir: str) -> list[str]:
    """Return shell lines that export and create a bootstrap artifact directory."""

    quoted_dir = shlex.quote(artifact_dir)
    return [
        f"export {BOOTSTRAP_ARTIFACT_DIR_ENV}={quoted_dir}",
        f"mkdir -p \"${BOOTSTRAP_ARTIFACT_DIR_ENV}\"",
    ]


def package_install_lines(packages: Sequence[str]) -> list[str]:
    """Return apt update/install lines for caller-supplied packages."""

    package_names = _strings(packages, "packages")
    if not package_names:
        return []
    return [
        "apt-get update",
        "apt-get install -y --no-install-recommends "
        + " ".join(shlex.quote(package) for package in package_names),
    ]


def rust_toolchain_lines(
    *,
    install: bool = False,
    load_env: bool = True,
    profile: str = "minimal",
) -> list[str]:
    """Return optional rustup install and cargo environment loading lines."""

    lines: list[str] = []
    if install:
        rust_profile = _shell_token(profile, "profile")
        lines.append(
            "if ! command -v cargo >/dev/null 2>&1; then "
            "curl -fsS https://sh.rustup.rs | sh -s -- -y --profile "
            f"{shlex.quote(rust_profile)}; "
            "fi"
        )
    if load_env:
        lines.append('if [ -f "$HOME/.cargo/env" ]; then . "$HOME/.cargo/env"; fi')
    return lines


def cargo_build_lines(commands: Sequence[str]) -> list[str]:
    """Return caller-supplied cargo build command lines."""

    return _shell_lines(commands, "cargo_build_commands")


def environment_artifact_lines(
    artifact_dir: str,
    artifact: BootstrapEnvArtifact,
) -> list[str]:
    """Return shell lines that write one environment artifact file."""

    artifact_path = posixpath.join(
        artifact_dir,
        *_relative_artifact_parts(artifact.filename, name="filename"),
    )
    quoted_path = shlex.quote(artifact_path)
    if not artifact.values and not artifact.shell_values:
        return [f": > {quoted_path}"]

    lines = ["{"]
    for key, value in artifact.values.items():
        lines.append(f"  printf '%s\\n' {shlex.quote(f'{key}={value}')}")
    for key, value in artifact.shell_values.items():
        lines.append(f"  printf '%s\\n' \"{key}={value}\"")
    lines.append(f"}} > {quoted_path}")
    return lines


def _env_artifacts(
    artifacts: Sequence[BootstrapEnvArtifact],
) -> tuple[BootstrapEnvArtifact, ...]:
    if isinstance(artifacts, (str, bytes, bytearray)):
        raise ValueError("env_artifacts must be a sequence of BootstrapEnvArtifact")
    result: list[BootstrapEnvArtifact] = []
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, BootstrapEnvArtifact):
            raise ValueError(
                f"env_artifacts[{index}] must be a BootstrapEnvArtifact"
            )
        result.append(artifact)
    return tuple(result)


def _env_mapping(value: Mapping[str, str], name: str) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be a mapping")
    output: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or _ENV_KEY_RE.fullmatch(key) is None:
            raise ValueError(f"{name} keys must be shell environment names")
        output[key] = _shell_token(item, f"{name}[{key!r}]")
    return output


def _relative_artifact_parts(
    value: str | Sequence[str],
    *,
    name: str,
) -> tuple[str, ...]:
    if isinstance(value, str):
        raw_parts: Sequence[str] = value.split("/")
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        raw_parts_list: list[str] = []
        for index, item in enumerate(value):
            if not isinstance(item, str):
                raise ValueError(f"{name}[{index}] must be a string")
            raw_parts_list.extend(item.split("/"))
        raw_parts = raw_parts_list
    else:
        raise ValueError(f"{name} must be a relative path or path parts")

    parts: list[str] = []
    for part in raw_parts:
        if part in {"", ".", ".."} or "/" in part or "\x00" in part:
            raise ValueError(f"{name} must stay under the bootstrap artifact root")
        parts.append(part)
    if not parts:
        raise ValueError(f"{name} must not be empty")
    return tuple(parts)


def _strings(values: Sequence[str], name: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes, bytearray)):
        raise ValueError(f"{name} must be a sequence of strings")
    result: list[str] = []
    for index, value in enumerate(values):
        result.append(_shell_token(value, f"{name}[{index}]"))
    return tuple(result)


def _shell_lines(values: Sequence[str], name: str) -> list[str]:
    return list(_strings(values, name))


def _shell_token(value: object, name: str) -> str:
    if not isinstance(value, str) or value == "" or "\x00" in value or "\n" in value:
        raise ValueError(f"{name} must be a non-empty single-line string")
    return value
