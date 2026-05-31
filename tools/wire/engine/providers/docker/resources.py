"""Docker provider resource and command helpers."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from hashlib import sha256
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from pathlib import Path
from typing import Any

from ...model import ProviderResource, ProviderResources
from ...process import CommandResult, render_argv
from ..vm import (
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
    DOCKER_DEFAULT_PRIVATE_CIDR,
    DOCKER_PRIVATE_CIDR_ENV,
    PROVIDER_NAME,
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
    "DOCKER_IMAGE_KIND",
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
    "docker_resource_name",
    "free_localhost_tcp_port",
    "parse_docker_inspect_output",
    "parse_docker_json_output",
    "parse_ipv4_address",
    "parse_private_cidr",
    "parse_single_docker_inspect_output",
    "planned_docker_endpoint_id",
    "private_gateway_ipv4",
    "render_docker_argv",
    "requested_docker_command",
    "requested_private_cidr",
    "utc_now",
    "validate_requested_private_ipv4",
]
