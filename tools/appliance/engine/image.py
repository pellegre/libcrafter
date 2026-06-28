"""Appliance Docker image metadata and command rendering helpers."""

from __future__ import annotations

import os
from collections.abc import Mapping
from hashlib import sha256
from pathlib import Path
from typing import Final


LIBCRAFTER_APPLIANCE_IMAGE: Final = "LIBCRAFTER_APPLIANCE_IMAGE"
LIBCRAFTER_APPLIANCE_DEFAULT_IMAGE: Final = "libcrafter/appliance:local"
LIBCRAFTER_DOCKER_COMMAND: Final = "LIBCRAFTER_DOCKER_COMMAND"

APPLIANCE_IMAGE_ENV: Final = LIBCRAFTER_APPLIANCE_IMAGE
APPLIANCE_DEFAULT_IMAGE: Final = LIBCRAFTER_APPLIANCE_DEFAULT_IMAGE
DEFAULT_APPLIANCE_IMAGE: Final = LIBCRAFTER_APPLIANCE_DEFAULT_IMAGE
DOCKER_COMMAND: Final = "docker"
APPLIANCE_IMAGE_CONTEXT_LABEL: Final = "org.libcrafter.appliance.image-context-sha256"


def appliance_root() -> Path:
    """Return the tracked appliance directory."""

    return Path(__file__).resolve(strict=False).parents[1]


def appliance_image_context_dir(root: str | Path | None = None) -> Path:
    """Return the Docker build context directory for the appliance image."""

    if root is None:
        return appliance_root()
    return Path(root).expanduser().resolve(strict=False)


def appliance_image_dockerfile_path(root: str | Path | None = None) -> Path:
    """Return the appliance image Dockerfile path."""

    return appliance_image_context_dir(root) / "Dockerfile"


def appliance_image_context_paths(root: str | Path | None = None) -> tuple[Path, ...]:
    """Return tracked files that define the appliance image context digest."""

    context_dir = appliance_image_context_dir(root)
    paths = [context_dir / "Dockerfile"]
    image_dir = context_dir / "image"
    if image_dir.is_dir():
        paths.extend(path for path in image_dir.rglob("*") if path.is_file())
    return tuple(sorted(paths, key=lambda path: path.relative_to(context_dir).as_posix()))


def appliance_image_context_digest(root: str | Path | None = None) -> str:
    """Return a deterministic sha256 digest of the appliance image context."""

    context_dir = appliance_image_context_dir(root)
    digest = sha256()
    for path in appliance_image_context_paths(context_dir):
        relative = path.relative_to(context_dir).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def requested_docker_command(env: Mapping[str, str] | None = None) -> str:
    """Return the Docker-compatible CLI command from env or the default."""

    environ = _env_source(env)
    command = (environ.get(LIBCRAFTER_DOCKER_COMMAND) or DOCKER_COMMAND).strip()
    return command or DOCKER_COMMAND


def requested_appliance_image(env: Mapping[str, str] | None = None) -> str:
    """Return the requested appliance image tag from env or the default."""

    environ = _env_source(env)
    tag = (environ.get(LIBCRAFTER_APPLIANCE_IMAGE) or DEFAULT_APPLIANCE_IMAGE).strip()
    return tag or DEFAULT_APPLIANCE_IMAGE


def appliance_image_inspect_argv(
    image_tag: str | None = None,
    *,
    env: Mapping[str, str] | None = None,
    docker_command: str | None = None,
) -> list[str]:
    """Return argv for inspecting the appliance Docker image."""

    tag = _image_tag(image_tag, env)
    return _docker_argv(
        "image",
        "inspect",
        tag,
        env=env,
        docker_command=docker_command,
    )


def appliance_image_build_argv(
    image_tag: str | None = None,
    *,
    env: Mapping[str, str] | None = None,
    docker_command: str | None = None,
    root: str | Path | None = None,
) -> list[str]:
    """Return argv for building the appliance Docker image."""

    tag = _image_tag(image_tag, env)
    context_dir = appliance_image_context_dir(root)
    return _docker_argv(
        "build",
        "-t",
        tag,
        "--label",
        f"{APPLIANCE_IMAGE_CONTEXT_LABEL}={appliance_image_context_digest(context_dir)}",
        "-f",
        appliance_image_dockerfile_path(context_dir),
        context_dir,
        env=env,
        docker_command=docker_command,
    )


def appliance_image_metadata(
    env: Mapping[str, str] | None = None,
    *,
    docker_command: str | None = None,
    root: str | Path | None = None,
) -> dict[str, object]:
    """Return JSON-compatible appliance image metadata."""

    context_dir = appliance_image_context_dir(root)
    tag = requested_appliance_image(env)
    digest = appliance_image_context_digest(context_dir)
    return {
        "tag": tag,
        "env": LIBCRAFTER_APPLIANCE_IMAGE,
        "default": DEFAULT_APPLIANCE_IMAGE,
        "uses_default": tag == DEFAULT_APPLIANCE_IMAGE,
        "context_digest": digest,
        "context_label": APPLIANCE_IMAGE_CONTEXT_LABEL,
        "dockerfile_path": str(appliance_image_dockerfile_path(context_dir)),
        "context_dir": str(context_dir),
        "context_files": [
            path.relative_to(context_dir).as_posix()
            for path in appliance_image_context_paths(context_dir)
        ],
        "inspect_argv": appliance_image_inspect_argv(
            tag,
            env=env,
            docker_command=docker_command,
        ),
        "build_argv": appliance_image_build_argv(
            tag,
            env=env,
            docker_command=docker_command,
            root=context_dir,
        ),
    }


def _docker_argv(
    *args: object,
    env: Mapping[str, str] | None = None,
    docker_command: str | None = None,
) -> list[str]:
    command = docker_command or requested_docker_command(env)
    return [_non_empty_string(command, "docker_command"), *(str(arg) for arg in args)]


def _env_source(env: Mapping[str, str] | None) -> Mapping[str, str]:
    return os.environ if env is None else env


def _image_tag(image_tag: str | None, env: Mapping[str, str] | None) -> str:
    if image_tag is None:
        return requested_appliance_image(env)
    return _non_empty_string(image_tag, "image_tag")


def _non_empty_string(value: str, name: str) -> str:
    if not isinstance(value, str) or value == "":
        raise ValueError(f"{name} must be a non-empty string")
    return value


__all__ = [
    "APPLIANCE_DEFAULT_IMAGE",
    "APPLIANCE_IMAGE_CONTEXT_LABEL",
    "APPLIANCE_IMAGE_ENV",
    "DEFAULT_APPLIANCE_IMAGE",
    "DOCKER_COMMAND",
    "LIBCRAFTER_APPLIANCE_DEFAULT_IMAGE",
    "LIBCRAFTER_APPLIANCE_IMAGE",
    "LIBCRAFTER_DOCKER_COMMAND",
    "appliance_image_build_argv",
    "appliance_image_context_digest",
    "appliance_image_context_dir",
    "appliance_image_context_paths",
    "appliance_image_dockerfile_path",
    "appliance_image_inspect_argv",
    "appliance_image_metadata",
    "appliance_root",
    "requested_appliance_image",
    "requested_docker_command",
]
