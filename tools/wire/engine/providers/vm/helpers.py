"""Provider-neutral helpers for local VM endpoint providers."""

from __future__ import annotations

import secrets
import socket
import string
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path

from ...config import absolute_path
from ...model import ProviderResource, ProviderResources
from ...process import CommandResult, run_command
from ...ssh import CommandRunner, create_key_pair


DEFAULT_RESOURCE_NAME_LIMIT = 63
DEFAULT_KEYGEN_TIMEOUT = 30

_PATH_SAFE_CHARS = frozenset(string.ascii_lowercase + string.digits)


def path_component(value: str, *, fallback: str = "value") -> str:
    """Return an ASCII path-safe component for endpoint IDs and local names."""

    if not isinstance(value, str):
        raise ValueError("path component value must be a string")
    if not isinstance(fallback, str) or fallback == "":
        raise ValueError("fallback must be a non-empty string")

    normalized = value.strip().lower()
    output = "".join(
        character if character in _PATH_SAFE_CHARS else "-" for character in normalized
    )
    output = "-".join(part for part in output.split("-") if part)
    return output or fallback


def utc_now(moment: datetime | None = None) -> str:
    """Return a UTC timestamp suitable for endpoint manifests."""

    current = _utc_datetime(moment)
    return current.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def id_timestamp(moment: datetime | None = None) -> str:
    """Return a compact UTC timestamp suitable for endpoint IDs."""

    return _utc_datetime(moment).strftime("%Y%m%d%H%M%S")


def endpoint_id(
    *,
    provider: str,
    exposure: str,
    role: str,
    timestamp: str | None = None,
    suffix: str | None = None,
) -> str:
    """Return a unique, single-component endpoint ID for a local VM."""

    return "-".join(
        path_component(part)
        for part in (
            provider,
            exposure,
            role,
            timestamp or id_timestamp(),
            suffix or secrets.token_hex(3),
        )
    )


def short_provider_resource_name(
    *parts: str,
    max_length: int = DEFAULT_RESOURCE_NAME_LIMIT,
    fallback: str = "wire-resource",
) -> str:
    """Return a bounded provider resource name from path-safe parts."""

    if isinstance(max_length, bool) or int(max_length) <= 0:
        raise ValueError("max_length must be a positive integer")
    limit = int(max_length)
    name = "-".join(path_component(part) for part in parts)
    if name == "":
        name = path_component(fallback)
    if len(name) <= limit:
        return name
    return name[:limit].rstrip("-") or path_component(fallback)[:limit]


def free_localhost_tcp_port(host: str = "127.0.0.1") -> int:
    """Return an currently free localhost TCP port."""

    if not isinstance(host, str) or host == "":
        raise ValueError("host must be a non-empty string")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])


def public_key_path(private_key_path: str | Path) -> Path:
    """Return the public key path for an endpoint private key path."""

    key_path = absolute_path(_non_empty_path(private_key_path, "private_key_path"))
    return key_path.with_name(f"{key_path.name}.pub")


def ensure_endpoint_ssh_key(
    private_key_path: str | Path,
    endpoint_id_value: str,
    *,
    runner: CommandRunner = run_command,
    force: bool = False,
    timeout: float | None = DEFAULT_KEYGEN_TIMEOUT,
) -> tuple[Path, Path]:
    """Ensure an endpoint SSH key pair exists and return private/public paths."""

    key_path = absolute_path(_non_empty_path(private_key_path, "private_key_path"))
    pub_path = public_key_path(key_path)
    _non_empty_string(endpoint_id_value, "endpoint_id")

    if not force and key_path.exists() and pub_path.exists():
        return key_path, pub_path
    if not force and key_path.exists() != pub_path.exists():
        raise FileExistsError(f"endpoint SSH key is incomplete: {key_path} and {pub_path}")

    result = create_key_pair(
        key_path,
        comment=f"libcrafter-wire {endpoint_id_value}",
        force=force,
        runner=runner,
        timeout=timeout,
    )
    if not result.ok:
        raise RuntimeError(command_error("ssh-keygen failed", result))
    return key_path, pub_path


def command_error(message: str, result: CommandResult) -> str:
    """Render a command failure with the redacted command and useful output."""

    _non_empty_string(message, "message")
    if not isinstance(result, CommandResult):
        raise TypeError("result must be a CommandResult")
    details = result.stderr.strip() or result.stdout.strip() or result.error or "no output"
    return f"{message}: {result.command}: {details}"


def file_resource(
    path: str | Path,
    *,
    name: str | None = None,
    cleanup: bool = True,
    metadata: Mapping[str, object] | None = None,
) -> ProviderResource:
    """Return a provider resource for a local file or directory."""

    file_path = absolute_path(_non_empty_path(path, "path"))
    return ProviderResource(
        kind="local-file",
        provider_id=str(file_path),
        name=name or file_path.name,
        cleanup=cleanup,
        metadata=_metadata(
            {"type": "local-file", "path": str(file_path)},
            metadata,
        ),
    )


def process_resource(
    pid: int,
    *,
    name: str | None = None,
    cleanup: bool = True,
    metadata: Mapping[str, object] | None = None,
) -> ProviderResource:
    """Return a provider resource for a local process."""

    if isinstance(pid, bool) or int(pid) <= 0:
        raise ValueError("pid must be a positive integer")
    process_id = int(pid)
    return ProviderResource(
        kind="process",
        provider_id=str(process_id),
        name=name,
        cleanup=cleanup,
        metadata=_metadata({"type": "process", "pid": process_id}, metadata),
    )


def vm_resource(
    vm_name: str,
    *,
    provider_id: str | None = None,
    kind: str = "vm",
    cleanup: bool = True,
    metadata: Mapping[str, object] | None = None,
) -> ProviderResource:
    """Return a provider resource for a local VM name."""

    name = _non_empty_string(vm_name, "vm_name")
    resource_kind = _non_empty_string(kind, "kind")
    return ProviderResource(
        kind=resource_kind,
        provider_id=provider_id or name,
        name=name,
        cleanup=cleanup,
        metadata=_metadata({"type": resource_kind, "vm_name": name}, metadata),
    )


def provider_resources(
    resources: Iterable[ProviderResource],
    *,
    cleanup_order: Sequence[str] | None = None,
    metadata: Mapping[str, object] | None = None,
) -> ProviderResources:
    """Return a provider resource collection with a deterministic cleanup order."""

    resource_list = list(resources)
    order = list(cleanup_order) if cleanup_order is not None else _default_cleanup_order(resource_list)
    return ProviderResources(
        resources=resource_list,
        cleanup_order=order,
        metadata=_metadata({"created_by": "tools/wire"}, metadata),
    )


def _utc_datetime(moment: datetime | None) -> datetime:
    current = datetime.now(UTC) if moment is None else moment
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    return current.astimezone(UTC)


def _metadata(
    base: Mapping[str, object],
    extra: Mapping[str, object] | None,
) -> dict[str, object]:
    output = dict(base)
    if extra is not None:
        output.update(dict(extra))
    return output


def _default_cleanup_order(resources: Sequence[ProviderResource]) -> list[str]:
    order: list[str] = []
    for resource in resources:
        if resource.cleanup and resource.kind not in order:
            order.append(resource.kind)
    return order


def _non_empty_string(value: str, name: str) -> str:
    if not isinstance(value, str) or value == "":
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _non_empty_path(path: str | Path, name: str) -> Path:
    if isinstance(path, str) and path == "":
        raise ValueError(f"{name} must be a non-empty path")
    output = Path(path).expanduser()
    if str(output) == "":
        raise ValueError(f"{name} must be a non-empty path")
    return output
