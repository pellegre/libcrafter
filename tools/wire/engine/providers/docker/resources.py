"""Docker provider resource and command helpers."""

from __future__ import annotations

import json
import os
from collections.abc import Iterable, Mapping, Sequence
from hashlib import sha256
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from pathlib import Path
from typing import Any

from ...model import ProviderResource, ProviderResources, write_json
from ...process import CommandResult, render_argv, run_command
from ..vm import (
    command_error,
    endpoint_id as local_endpoint_id,
    file_resource,
    free_localhost_tcp_port,
    path_component,
    provider_resources,
    short_provider_resource_name,
    utc_now,
)
from .constants import (
    DOCKER_COMMAND,
    DOCKER_COMMAND_ENV,
    DOCKER_DEFAULT_IMAGE,
    DOCKER_DEFAULT_PRIVATE_CIDR,
    DOCKER_IMAGE_ENV,
    DOCKER_PRIVATE_CIDR_ENV,
    DOCKER_REBUILD_ENV,
    PROVIDER_NAME,
    DockerRunner,
)


DOCKER_RESOURCE_NAME_LIMIT = 63
DOCKER_LABEL_PREFIX = "org.libcrafter.wire"
DOCKER_LABEL_PROVIDER = f"{DOCKER_LABEL_PREFIX}.provider"
DOCKER_LABEL_ENDPOINT_ID = f"{DOCKER_LABEL_PREFIX}.endpoint-id"
DOCKER_LABEL_PRIVATE_GROUP = f"{DOCKER_LABEL_PREFIX}.private-group"
DOCKER_LABEL_EXPOSURE = f"{DOCKER_LABEL_PREFIX}.exposure"
DOCKER_LABEL_ROLE = f"{DOCKER_LABEL_PREFIX}.role"
DOCKER_LABEL_CREATED_AT = f"{DOCKER_LABEL_PREFIX}.created-at"
DOCKER_LABEL_MANAGED = f"{DOCKER_LABEL_PREFIX}.managed"

DOCKER_MANAGED_LABEL_VALUE = "true"
DOCKER_CONTAINER_KIND = "docker-container"
DOCKER_NETWORK_KIND = "docker-network"
DOCKER_IMAGE_KIND = "docker-image"
DOCKER_PRIVATE_GATEWAY_HOST_INDEX = 1
DOCKER_IMAGE_COMMAND_LOG_NAME = "docker-image-commands.json"
DOCKER_IMAGE_INSPECT_TIMEOUT_SECONDS = 30
DOCKER_IMAGE_BUILD_TIMEOUT_SECONDS = 600


def docker_endpoint_id(
    *,
    exposure: str,
    role: str,
    provider: str = PROVIDER_NAME,
    timestamp: str | None = None,
    suffix: str | None = None,
) -> str:
    """Return a path-safe endpoint id for a live Docker endpoint."""

    return local_endpoint_id(
        provider=provider,
        exposure=exposure,
        role=role,
        timestamp=timestamp,
        suffix=suffix,
    )


def planned_docker_endpoint_id(
    *,
    exposure: str,
    role: str,
    private_group: str | None = None,
    provider: str = PROVIDER_NAME,
) -> str:
    """Return the deterministic endpoint id used by Docker dry-run manifests."""

    parts = ["planned", provider, exposure, role]
    if private_group is not None:
        parts.append(private_group)
    return "-".join(path_component(part) for part in parts)


def docker_resource_name(
    *parts: str,
    prefix: str = "wire",
    max_length: int = DOCKER_RESOURCE_NAME_LIMIT,
    fallback: str = "wire-docker-resource",
) -> str:
    """Return a bounded Docker resource name from path-safe components."""

    name_parts = (prefix, *parts) if prefix else parts
    return short_provider_resource_name(
        *name_parts,
        max_length=max_length,
        fallback=fallback,
    )


def docker_container_name(endpoint_id: str) -> str:
    """Return the provider-owned Docker container name for an endpoint."""

    return docker_resource_name("container", endpoint_id, fallback="wire-docker-container")


def docker_private_network_name(private_group: str) -> str:
    """Return the provider-owned Docker network name for a private group."""

    return docker_resource_name("private", private_group, fallback="wire-docker-network")


def docker_labels(
    *,
    endpoint_id: str | None = None,
    exposure: str | None = None,
    role: str | None = None,
    private_group: str | None = None,
    created_at: str | None = None,
    provider: str = PROVIDER_NAME,
    extra: Mapping[str, object] | None = None,
) -> dict[str, str]:
    """Return common Docker labels for provider-owned resources."""

    labels = {
        DOCKER_LABEL_PROVIDER: _non_empty_string(provider, "provider"),
        DOCKER_LABEL_MANAGED: DOCKER_MANAGED_LABEL_VALUE,
    }
    optional = {
        DOCKER_LABEL_ENDPOINT_ID: endpoint_id,
        DOCKER_LABEL_EXPOSURE: exposure,
        DOCKER_LABEL_ROLE: role,
        DOCKER_LABEL_PRIVATE_GROUP: private_group,
        DOCKER_LABEL_CREATED_AT: created_at,
    }
    for key, value in optional.items():
        if value is not None:
            labels[key] = _non_empty_string(value, key)
    if extra is not None:
        for key, value in extra.items():
            label_key = _non_empty_string(str(key), "label key")
            if value is None:
                continue
            labels[label_key] = str(value)
    return labels


def docker_label_args(labels: Mapping[str, object]) -> list[str]:
    """Return Docker CLI --label argv parts for the supplied labels."""

    args: list[str] = []
    for key, value in _sorted_string_mapping(labels).items():
        args.extend(["--label", f"{key}={value}"])
    return args


def docker_label_filter_args(labels: Mapping[str, object]) -> list[str]:
    """Return Docker CLI --filter label=... argv parts for the supplied labels."""

    args: list[str] = []
    for key, value in _sorted_string_mapping(labels).items():
        args.extend(["--filter", f"label={key}={value}"])
    return args


def docker_provider_resources(
    resources: Iterable[ProviderResource],
    *,
    cleanup_order: Sequence[str] | None = None,
    metadata: Mapping[str, object] | None = None,
) -> ProviderResources:
    """Return Docker provider resources with a deterministic cleanup order."""

    return provider_resources(
        resources,
        cleanup_order=cleanup_order
        or [DOCKER_CONTAINER_KIND, DOCKER_NETWORK_KIND, "local-file"],
        metadata={"provider": PROVIDER_NAME, **dict(metadata or {})},
    )


def docker_container_resource(
    container_id: str | None,
    *,
    name: str,
    endpoint_id: str | None = None,
    cleanup: bool = True,
    metadata: Mapping[str, object] | None = None,
) -> ProviderResource:
    """Return a provider resource for a Docker container."""

    container_name = _non_empty_string(name, "name")
    provider_id = container_id or container_name
    return ProviderResource(
        kind=DOCKER_CONTAINER_KIND,
        provider_id=_non_empty_string(provider_id, "container_id"),
        name=container_name,
        cleanup=cleanup,
        metadata=_metadata(
            {
                "type": "container",
                "provider": PROVIDER_NAME,
                "container_id": container_id,
                "container_name": container_name,
                "endpoint_id": endpoint_id,
            },
            metadata,
        ),
    )


def docker_network_resource(
    network_id: str | None,
    *,
    name: str,
    private_group: str | None = None,
    cidr: str | None = None,
    cleanup: bool = True,
    metadata: Mapping[str, object] | None = None,
) -> ProviderResource:
    """Return a provider resource for a Docker network."""

    network_name = _non_empty_string(name, "name")
    provider_id = network_id or network_name
    return ProviderResource(
        kind=DOCKER_NETWORK_KIND,
        provider_id=_non_empty_string(provider_id, "network_id"),
        name=network_name,
        cleanup=cleanup,
        metadata=_metadata(
            {
                "type": "network",
                "provider": PROVIDER_NAME,
                "network_id": network_id,
                "network_name": network_name,
                "private_group": private_group,
                "cidr": cidr,
            },
            metadata,
        ),
    )


def docker_image_resource(
    image_tag: str,
    *,
    cleanup: bool = False,
    metadata: Mapping[str, object] | None = None,
) -> ProviderResource:
    """Return a provider resource for the Docker endpoint image."""

    tag = _non_empty_string(image_tag, "image_tag")
    return ProviderResource(
        kind=DOCKER_IMAGE_KIND,
        provider_id=tag,
        name=tag,
        cleanup=cleanup,
        metadata=_metadata(
            {
                "type": "image",
                "provider": PROVIDER_NAME,
                "image": tag,
            },
            metadata,
        ),
    )


def docker_local_file_resource(
    path: str | Path,
    *,
    name: str | None = None,
    cleanup: bool = True,
    metadata: Mapping[str, object] | None = None,
) -> ProviderResource:
    """Return a provider resource for a Docker endpoint local file path."""

    return file_resource(
        path,
        name=name,
        cleanup=cleanup,
        metadata={"provider": PROVIDER_NAME, **dict(metadata or {})},
    )


def requested_private_cidr(env: Mapping[str, str] | None = None) -> str:
    """Return the requested Docker private CIDR from env or the default."""

    environ = {} if env is None else env
    raw_value = (environ.get(DOCKER_PRIVATE_CIDR_ENV) or DOCKER_DEFAULT_PRIVATE_CIDR).strip()
    if not raw_value:
        raw_value = DOCKER_DEFAULT_PRIVATE_CIDR
    return str(parse_private_cidr(raw_value, DOCKER_PRIVATE_CIDR_ENV))


def parse_private_cidr(value: str, name: str = "private_cidr") -> IPv4Network:
    """Parse and validate a Docker private IPv4 network."""

    try:
        network = ip_network(value, strict=False)
    except ValueError as exc:
        raise ValueError(f"{name}={value!r} must be an IPv4 CIDR") from exc
    if not isinstance(network, IPv4Network):
        raise ValueError(f"{name}={value!r} must be an IPv4 CIDR")
    if network.num_addresses < 4:
        raise ValueError(f"{name}={value!r} must provide at least two usable IPv4 hosts")
    return network


def validate_requested_private_ipv4(
    requested_private_ip: str | None,
    private_cidr: str | IPv4Network,
    *,
    allocated_private_ipv4s: Iterable[str] = (),
) -> str | None:
    """Validate a requested Docker private IPv4 address against a private CIDR."""

    if requested_private_ip is None:
        return None
    if requested_private_ip == "":
        raise ValueError("private_ip must be a non-empty string when supplied")

    network = _private_network(private_cidr)
    address = parse_ipv4_address(requested_private_ip, "private_ip")
    if address not in network:
        raise ValueError(f"private_ip {requested_private_ip} is outside {network}")
    if is_reserved_private_ipv4(address, network):
        raise ValueError(f"private_ip {requested_private_ip} is reserved in {network}")
    allocated = {str(value) for value in allocated_private_ipv4s}
    if str(address) in allocated:
        raise ValueError(f"private_ip {requested_private_ip} is already allocated")
    return str(address)


def allocate_private_ipv4(
    private_cidr: str | IPv4Network,
    *,
    allocated_private_ipv4s: Iterable[str] = (),
    requested_private_ip: str | None = None,
) -> str:
    """Return a requested or first available Docker private IPv4 address."""

    requested = validate_requested_private_ipv4(
        requested_private_ip,
        private_cidr,
        allocated_private_ipv4s=allocated_private_ipv4s,
    )
    if requested is not None:
        return requested

    network = _private_network(private_cidr)
    allocated = {str(value) for value in allocated_private_ipv4s}
    for address in network.hosts():
        if is_reserved_private_ipv4(address, network):
            continue
        private_ipv4 = str(address)
        if private_ipv4 not in allocated:
            return private_ipv4
    raise RuntimeError(f"no private IPv4 addresses are available in {network}")


def parse_ipv4_address(value: str, name: str = "ipv4") -> IPv4Address:
    """Parse and validate an IPv4 address string."""

    try:
        address = ip_address(value)
    except ValueError as exc:
        raise ValueError(f"{name}={value!r} must be an IPv4 address") from exc
    if not isinstance(address, IPv4Address):
        raise ValueError(f"{name}={value!r} must be an IPv4 address")
    return address


def is_reserved_private_ipv4(address: IPv4Address, network: IPv4Network) -> bool:
    """Return whether Docker should not assign this address to an endpoint."""

    if address == network.network_address or address == network.broadcast_address:
        return True
    return address == private_gateway_ipv4(network)


def private_gateway_ipv4(private_cidr: str | IPv4Network) -> IPv4Address:
    """Return Docker's planned private bridge gateway address."""

    network = _private_network(private_cidr)
    return IPv4Address(int(network.network_address) + DOCKER_PRIVATE_GATEWAY_HOST_INDEX)


def deterministic_private_mac(
    *,
    private_group: str,
    endpoint_id: str,
    namespace: str = "docker-private",
) -> str:
    """Return a stable locally administered MAC for a Docker private endpoint."""

    group = path_component(_non_empty_string(private_group, "private_group"))
    endpoint = path_component(_non_empty_string(endpoint_id, "endpoint_id"))
    digest = sha256(":".join((namespace, group, endpoint)).encode("utf-8")).digest()
    return "02:42:" + ":".join(f"{byte:02x}" for byte in digest[:4])


def requested_docker_command(env: Mapping[str, str] | None = None) -> str:
    """Return the requested Docker CLI command from env or the default."""

    environ = {} if env is None else env
    command = (environ.get(DOCKER_COMMAND_ENV) or DOCKER_COMMAND).strip()
    return command or DOCKER_COMMAND


def docker_argv(
    *args: object,
    env: Mapping[str, str] | None = None,
    docker_command: str | None = None,
) -> list[str]:
    """Return a Docker CLI argv with normalized string arguments."""

    command = docker_command or requested_docker_command(env)
    return [_non_empty_string(command, "docker_command"), *(str(arg) for arg in args)]


def requested_docker_image(env: Mapping[str, str] | None = None) -> str:
    """Return the requested Docker endpoint image tag from env or the default."""

    environ = _env_source(env)
    image = (environ.get(DOCKER_IMAGE_ENV) or DOCKER_DEFAULT_IMAGE).strip()
    return image or DOCKER_DEFAULT_IMAGE


def docker_rebuild_requested(env: Mapping[str, str] | None = None) -> bool:
    """Return whether the provider image should be rebuilt."""

    environ = _env_source(env)
    return (environ.get(DOCKER_REBUILD_ENV) or "").strip() == "1"


def docker_image_context_dir() -> Path:
    """Return the provider-owned Docker image build context directory."""

    return Path(__file__).resolve(strict=False).parent / "image"


def docker_image_dockerfile_path() -> Path:
    """Return the provider-owned endpoint image Dockerfile path."""

    return docker_image_context_dir() / "Dockerfile"


def docker_image_command_log_path(
    artifact_dir: str | Path,
    *,
    name: str = DOCKER_IMAGE_COMMAND_LOG_NAME,
) -> Path:
    """Return the command artifact path for Docker image operations."""

    return Path(artifact_dir).expanduser().resolve(strict=False) / _non_empty_string(
        name,
        "name",
    )


def docker_image_inspect_argv(
    image_tag: str,
    *,
    env: Mapping[str, str] | None = None,
    docker_command: str | None = None,
) -> list[str]:
    """Return argv for a Docker image existence check."""

    return docker_argv(
        "image",
        "inspect",
        _non_empty_string(image_tag, "image_tag"),
        env=env,
        docker_command=docker_command,
    )


def docker_image_build_argv(
    image_tag: str,
    *,
    env: Mapping[str, str] | None = None,
    docker_command: str | None = None,
) -> list[str]:
    """Return argv for building the provider-owned Docker endpoint image."""

    return docker_argv(
        "build",
        "-t",
        _non_empty_string(image_tag, "image_tag"),
        "-f",
        docker_image_dockerfile_path(),
        docker_image_context_dir(),
        env=env,
        docker_command=docker_command,
    )


def docker_image_metadata(
    env: Mapping[str, str] | None = None,
    *,
    artifact_dir: str | Path | None = None,
    image_exists: bool | None = None,
    built: bool | None = None,
    docker_command: str | None = None,
) -> dict[str, object]:
    """Return manifest-ready Docker image metadata for dry-run or live output."""

    environ = _env_source(env)
    image_tag = requested_docker_image(environ)
    metadata: dict[str, object] = {
        "tag": image_tag,
        "env": DOCKER_IMAGE_ENV,
        "default": DOCKER_DEFAULT_IMAGE,
        "uses_default": image_tag == DOCKER_DEFAULT_IMAGE,
        "rebuild_env": DOCKER_REBUILD_ENV,
        "rebuild_requested": docker_rebuild_requested(environ),
        "dockerfile_path": str(docker_image_dockerfile_path()),
        "context_dir": str(docker_image_context_dir()),
        "inspect_argv": docker_image_inspect_argv(
            image_tag,
            env=environ,
            docker_command=docker_command,
        ),
        "build_argv": docker_image_build_argv(
            image_tag,
            env=environ,
            docker_command=docker_command,
        ),
    }
    if artifact_dir is not None:
        metadata["command_log_path"] = str(docker_image_command_log_path(artifact_dir))
    if image_exists is not None:
        metadata["image_exists"] = bool(image_exists)
    if built is not None:
        metadata["built"] = bool(built)
    return metadata


def plan_docker_image(
    env: Mapping[str, str] | None = None,
    *,
    artifact_dir: str | Path | None = None,
    docker_command: str | None = None,
) -> dict[str, object]:
    """Return dry-run metadata for the provider-owned Docker endpoint image."""

    return {
        "docker_image": docker_image_metadata(
            env,
            artifact_dir=artifact_dir,
            docker_command=docker_command,
        )
    }


def docker_image_exists(
    image_tag: str,
    *,
    env: Mapping[str, str] | None = None,
    docker_command: str | None = None,
    command_runner: DockerRunner | None = None,
    artifact_dir: str | Path | None = None,
    timeout: float | None = DOCKER_IMAGE_INSPECT_TIMEOUT_SECONDS,
) -> bool:
    """Return whether the requested Docker image exists locally."""

    environ = _env_source(env)
    runner = _recording_docker_runner(
        command_runner,
        artifact_dir,
        command_log_name=DOCKER_IMAGE_COMMAND_LOG_NAME,
    )
    result = _inspect_docker_image(
        image_tag,
        env=environ,
        docker_command=docker_command,
        runner=runner,
        timeout=timeout,
    )
    return result.ok


def ensure_docker_image(
    *,
    env: Mapping[str, str] | None = None,
    artifact_dir: str | Path,
    docker_command: str | None = None,
    command_runner: DockerRunner | None = None,
    inspect_timeout: float | None = DOCKER_IMAGE_INSPECT_TIMEOUT_SECONDS,
    build_timeout: float | None = DOCKER_IMAGE_BUILD_TIMEOUT_SECONDS,
) -> dict[str, object]:
    """Ensure the configured Docker image is available and return image metadata."""

    environ = _env_source(env)
    image_tag = requested_docker_image(environ)
    command_log_path = docker_image_command_log_path(artifact_dir)
    runner = _recording_docker_runner(
        command_runner,
        artifact_dir,
        command_log_name=DOCKER_IMAGE_COMMAND_LOG_NAME,
    )

    inspect_result = _inspect_docker_image(
        image_tag,
        env=environ,
        docker_command=docker_command,
        runner=runner,
        timeout=inspect_timeout,
    )
    exists_before = inspect_result.ok
    should_build = docker_rebuild_requested(environ) or (
        image_tag == DOCKER_DEFAULT_IMAGE and not exists_before
    )

    built = False
    if should_build:
        build_result = _build_docker_image(
            image_tag,
            env=environ,
            docker_command=docker_command,
            runner=runner,
            timeout=build_timeout,
        )
        if not build_result.ok:
            raise RuntimeError(command_error("Docker image build failed", build_result))
        built = True
        inspect_result = _inspect_docker_image(
            image_tag,
            env=environ,
            docker_command=docker_command,
            runner=runner,
            timeout=inspect_timeout,
        )

    if not inspect_result.ok:
        raise RuntimeError(command_error("Docker image is not available", inspect_result))

    return {
        "docker_image": docker_image_metadata(
            environ,
            artifact_dir=artifact_dir,
            image_exists=True,
            built=built,
            docker_command=docker_command,
        )
        | {
            "exists_before": exists_before,
            "command_log_path": str(command_log_path),
        }
    }


def docker_publish_arg(
    *,
    host_port: int,
    guest_port: int,
    host: str = "127.0.0.1",
) -> str:
    """Return a Docker publish specification for localhost port forwarding."""

    normalized_host = _non_empty_string(host, "host")
    normalized_host_port = _positive_int(host_port, "host_port")
    normalized_guest_port = _positive_int(guest_port, "guest_port")
    return f"{normalized_host}:{normalized_host_port}:{normalized_guest_port}"


def docker_inspect_argv(
    *resource_ids: str,
    env: Mapping[str, str] | None = None,
    docker_command: str | None = None,
) -> list[str]:
    """Return argv for a Docker inspect command."""

    if not resource_ids:
        raise ValueError("at least one Docker resource id is required")
    return docker_argv("inspect", *resource_ids, env=env, docker_command=docker_command)


def render_docker_argv(argv: Sequence[object]) -> str:
    """Return a shell-quoted Docker command string for logs and manifests."""

    return render_argv(argv)


def parse_docker_json_output(output: str | CommandResult, *, context: str = "docker output") -> Any:
    """Parse Docker JSON output from stdout text or a CommandResult."""

    text = output.stdout if isinstance(output, CommandResult) else output
    if not isinstance(text, str):
        raise TypeError(f"{context} must be a string or CommandResult")
    stripped = text.strip()
    if not stripped:
        raise ValueError(f"{context} was empty")
    try:
        return json.loads(stripped)
    except json.JSONDecodeError as array_exc:
        items: list[object] = []
        for line in stripped.splitlines():
            raw_line = line.strip()
            if not raw_line:
                continue
            try:
                items.append(json.loads(raw_line))
            except json.JSONDecodeError as line_exc:
                raise ValueError(f"{context} was not valid JSON") from line_exc
        if items:
            return items
        raise ValueError(f"{context} was not valid JSON") from array_exc


def parse_docker_inspect_output(
    output: str | CommandResult,
    *,
    context: str = "docker inspect output",
) -> list[dict[str, object]]:
    """Parse Docker inspect JSON output into a list of objects."""

    parsed = parse_docker_json_output(output, context=context)
    if isinstance(parsed, Mapping):
        parsed_items: Sequence[object] = [parsed]
    elif isinstance(parsed, list):
        parsed_items = parsed
    else:
        raise ValueError(f"{context} must be a JSON object or list of objects")

    records: list[dict[str, object]] = []
    for index, item in enumerate(parsed_items):
        if not isinstance(item, Mapping):
            raise ValueError(f"{context}[{index}] must be a JSON object")
        records.append(dict(item))
    return records


def parse_single_docker_inspect_output(
    output: str | CommandResult,
    *,
    context: str = "docker inspect output",
) -> dict[str, object]:
    """Parse Docker inspect output that must contain exactly one object."""

    records = parse_docker_inspect_output(output, context=context)
    if len(records) != 1:
        raise ValueError(f"{context} must contain exactly one object, got {len(records)}")
    return records[0]


def docker_inspect_labels(record: Mapping[str, object]) -> dict[str, str]:
    """Return a Docker inspect object's labels as a string mapping."""

    config = record.get("Config")
    labels: object | None = None
    if isinstance(config, Mapping):
        labels = config.get("Labels")
    if labels is None:
        labels = record.get("Labels")
    if labels is None:
        return {}
    if not isinstance(labels, Mapping):
        raise ValueError("Docker inspect labels must be an object")
    return {str(key): str(value) for key, value in labels.items() if value is not None}


def docker_inspect_id(record: Mapping[str, object]) -> str | None:
    """Return a Docker inspect object's id if present."""

    value = record.get("Id") or record.get("ID")
    return str(value) if value is not None and str(value) else None


def docker_inspect_name(record: Mapping[str, object]) -> str | None:
    """Return a Docker inspect object's name without Docker's leading slash."""

    value = record.get("Name") or record.get("Name".lower())
    if value is None:
        return None
    name = str(value).strip()
    if name.startswith("/"):
        name = name[1:]
    return name or None


def _env_source(env: Mapping[str, str] | None) -> Mapping[str, str]:
    return os.environ if env is None else env


def _recording_docker_runner(
    command_runner: DockerRunner | None,
    artifact_dir: str | Path | None,
    *,
    command_log_name: str,
) -> DockerRunner:
    runner = run_command if command_runner is None else command_runner
    if artifact_dir is None:
        return runner
    return _DockerCommandRecorder(
        runner,
        docker_image_command_log_path(artifact_dir, name=command_log_name),
    )


def _inspect_docker_image(
    image_tag: str,
    *,
    env: Mapping[str, str],
    docker_command: str | None,
    runner: DockerRunner,
    timeout: float | None,
) -> CommandResult:
    return runner(
        docker_image_inspect_argv(
            image_tag,
            env=env,
            docker_command=docker_command,
        ),
        env=env,
        timeout=timeout,
    )


def _build_docker_image(
    image_tag: str,
    *,
    env: Mapping[str, str],
    docker_command: str | None,
    runner: DockerRunner,
    timeout: float | None,
) -> CommandResult:
    return runner(
        docker_image_build_argv(
            image_tag,
            env=env,
            docker_command=docker_command,
        ),
        env=env,
        timeout=timeout,
    )


class _DockerCommandRecorder:
    def __init__(self, runner: DockerRunner, log_path: Path) -> None:
        self._runner = runner
        self.path = log_path.resolve(strict=False)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._records: list[dict[str, object]] = []
        self._write()

    def __call__(self, argv: Sequence[object], **kwargs: object) -> CommandResult:
        result = self._runner(argv, **kwargs)
        self._records.append(_command_result_record(result))
        self._write()
        return result

    def _write(self) -> None:
        write_json(self.path, {"commands": self._records})


def _command_result_record(result: CommandResult) -> dict[str, object]:
    return {
        "argv": list(result.redacted_argv),
        "cwd": result.cwd,
        "exit_code": result.exit_code,
        "ok": result.ok,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "timed_out": result.timed_out,
        "timeout": result.timeout,
        "error": result.error,
    }


def _private_network(private_cidr: str | IPv4Network) -> IPv4Network:
    if isinstance(private_cidr, IPv4Network):
        return private_cidr
    return parse_private_cidr(private_cidr)


def _metadata(
    base: Mapping[str, object],
    extra: Mapping[str, object] | None,
) -> dict[str, object]:
    output = {key: value for key, value in base.items() if value is not None}
    if extra is not None:
        output.update(dict(extra))
    return output


def _sorted_string_mapping(values: Mapping[str, object]) -> dict[str, str]:
    output: dict[str, str] = {}
    for key, value in values.items():
        if value is None:
            continue
        output[_non_empty_string(str(key), "mapping key")] = str(value)
    return dict(sorted(output.items()))


def _non_empty_string(value: str, name: str) -> str:
    if not isinstance(value, str) or value == "":
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _positive_int(value: int, name: str) -> int:
    if isinstance(value, bool) or int(value) <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return int(value)


__all__ = [
    "DOCKER_CONTAINER_KIND",
    "DOCKER_IMAGE_BUILD_TIMEOUT_SECONDS",
    "DOCKER_IMAGE_COMMAND_LOG_NAME",
    "DOCKER_IMAGE_KIND",
    "DOCKER_IMAGE_INSPECT_TIMEOUT_SECONDS",
    "DOCKER_LABEL_CREATED_AT",
    "DOCKER_LABEL_ENDPOINT_ID",
    "DOCKER_LABEL_EXPOSURE",
    "DOCKER_LABEL_MANAGED",
    "DOCKER_LABEL_PREFIX",
    "DOCKER_LABEL_PRIVATE_GROUP",
    "DOCKER_LABEL_PROVIDER",
    "DOCKER_LABEL_ROLE",
    "DOCKER_MANAGED_LABEL_VALUE",
    "DOCKER_NETWORK_KIND",
    "DOCKER_PRIVATE_GATEWAY_HOST_INDEX",
    "DOCKER_RESOURCE_NAME_LIMIT",
    "allocate_private_ipv4",
    "deterministic_private_mac",
    "docker_image_build_argv",
    "docker_image_command_log_path",
    "docker_image_context_dir",
    "docker_image_dockerfile_path",
    "docker_image_exists",
    "docker_image_inspect_argv",
    "docker_image_metadata",
    "docker_argv",
    "docker_container_name",
    "docker_container_resource",
    "docker_endpoint_id",
    "docker_image_resource",
    "docker_inspect_argv",
    "docker_inspect_id",
    "docker_inspect_labels",
    "docker_inspect_name",
    "docker_label_args",
    "docker_label_filter_args",
    "docker_labels",
    "docker_local_file_resource",
    "docker_network_resource",
    "docker_private_network_name",
    "docker_provider_resources",
    "docker_publish_arg",
    "docker_rebuild_requested",
    "docker_resource_name",
    "ensure_docker_image",
    "free_localhost_tcp_port",
    "parse_docker_inspect_output",
    "parse_docker_json_output",
    "parse_ipv4_address",
    "parse_private_cidr",
    "parse_single_docker_inspect_output",
    "plan_docker_image",
    "planned_docker_endpoint_id",
    "private_gateway_ipv4",
    "render_docker_argv",
    "requested_docker_command",
    "requested_docker_image",
    "requested_private_cidr",
    "utc_now",
    "validate_requested_private_ipv4",
]
