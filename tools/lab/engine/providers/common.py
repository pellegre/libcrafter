"""Shared provider helpers for lab endpoint planning."""

from __future__ import annotations

import posixpath
import re
from collections.abc import Mapping, Sequence
from pathlib import PurePosixPath

from tools.appliance.engine.image import requested_appliance_image
from tools.appliance.engine.profiles import resolve_profile
from tools.endpoint.engine.appliance import DEFAULT_APPLIANCE_REMOTE_BASE
from tools.endpoint.engine.model import EndpointManifest, NetworkInterface

from ..model import (
    JSONObject,
    LabApplianceRuntime,
    LabCommandPlan,
    LabEndpoint,
    LabRequest,
    LabRole,
    json_object,
)


COMMON_PROVIDER_CAPABILITY_NAMES = (
    "ipv4_unicast",
    "ipv6_unicast",
    "link_layer_send",
    "link_layer_capture",
    "broadcast",
    "multicast",
    "provider_mac_known",
    "controlled_services",
    "controlled_router",
)

DEFAULT_REMOTE_DIR = "/root/libcrafter"

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def slug_label(value: object, *, fallback: str = "label", max_length: int = 63) -> str:
    """Return a lower-case provider-safe label component."""

    if not isinstance(fallback, str) or fallback == "":
        raise ValueError("fallback must be a non-empty string")
    if isinstance(max_length, bool) or max_length <= 0:
        raise ValueError("max_length must be a positive integer")

    normalized = str(value).strip().lower()
    label = "-".join(part for part in _SLUG_RE.sub("-", normalized).split("-") if part)
    if label == "":
        label = slug_label(fallback, fallback="label", max_length=max_length)
    if len(label) > max_length:
        label = label[:max_length].rstrip("-")
    return label or "label"


def profile_seed_label(profile: object, seed: object, *, max_length: int = 63) -> str:
    """Return a deterministic label for a profile and seed pair."""

    return slug_label(
        f"{slug_label(profile, fallback='profile')}-seed-{seed}",
        fallback="profile-seed",
        max_length=max_length,
    )


def request_session_label(
    request: LabRequest,
    *,
    session_label: object | None = None,
    prefix: str = "lab",
    max_length: int = 63,
) -> str:
    """Return a deterministic label for request-scoped provider resources."""

    parts = [
        slug_label(prefix, fallback="lab"),
        slug_label(request.workload_label or request.provider, fallback="workload"),
        profile_seed_label(request.profile, request.seed),
    ]
    if session_label is not None:
        parts.append(slug_label(session_label, fallback="session"))
    return slug_label("-".join(parts), fallback="lab-session", max_length=max_length)


def validate_remote_dir(remote_dir: str | None, *, default: str = DEFAULT_REMOTE_DIR) -> str:
    """Return a normalized absolute POSIX remote directory."""

    value = default if remote_dir is None else remote_dir
    if not isinstance(value, str) or value == "":
        raise ValueError("remote_dir must be a non-empty string")
    if "\x00" in value:
        raise ValueError("remote_dir must not contain NUL bytes")
    if "'" in value:
        raise ValueError("remote_dir must not contain single quotes")

    path = PurePosixPath(value)
    if not path.is_absolute():
        raise ValueError("remote_dir must be an absolute path")
    normalized = str(path)
    return normalized.rstrip("/") or "/"


def build_command_plan(
    *,
    purpose: str,
    argv: Sequence[str],
    operation: str,
    dry_run: bool,
    role: str | None = None,
    live_mutation: bool = False,
    artifacts: Sequence[str] = (),
    provider: str | None = None,
    exposure: str | None = None,
    metadata: Mapping[str, object] | None = None,
) -> LabCommandPlan:
    """Build a lab command record with common provider metadata."""

    command_metadata: dict[str, object] = dict(metadata or {})
    command_metadata["dry_run"] = dry_run
    command_metadata["operation"] = operation
    if provider is not None:
        command_metadata["provider"] = provider
    if exposure is not None:
        command_metadata["exposure"] = exposure
    if live_mutation:
        command_metadata["live_mutation"] = True

    return LabCommandPlan(
        purpose=purpose,
        role=role,
        argv=list(argv),
        operation=operation,
        dry_run=dry_run,
        live_mutation=live_mutation,
        artifacts=list(artifacts),
        metadata=json_object(command_metadata, "command.metadata"),
    )


def select_manifest_interface(
    manifest: EndpointManifest | Mapping[str, object],
    exposure: str,
    *,
    fallback_to_first: bool = False,
) -> NetworkInterface:
    """Return the manifest interface for a packet-exchange exposure."""

    endpoint_manifest = coerce_endpoint_manifest(manifest)
    for interface in endpoint_manifest.interfaces:
        if interface.exposure == exposure:
            return interface
    if fallback_to_first and endpoint_manifest.interfaces:
        return endpoint_manifest.interfaces[0]
    raise ValueError(
        f"endpoint manifest {endpoint_manifest.endpoint_id!r} lacks an {exposure!r} interface"
    )


def lab_endpoint_from_manifest(
    manifest: EndpointManifest | Mapping[str, object],
    *,
    role: LabRole | str,
    exposure: str,
    peer_roles: Sequence[LabRole] = (),
    dry_run: bool,
    fallback_to_first_interface: bool = False,
    appliance_runtime: LabApplianceRuntime | None = None,
    metadata: Mapping[str, object] | None = None,
) -> LabEndpoint:
    """Convert an endpoint manifest into the lab endpoint shape."""

    endpoint_manifest = coerce_endpoint_manifest(manifest)
    lab_role = role if isinstance(role, LabRole) else LabRole(name=role)
    interface = select_manifest_interface(
        endpoint_manifest,
        exposure,
        fallback_to_first=fallback_to_first_interface,
    )
    ipv4 = interface.ipv4 or lab_role.planned_ipv4 or lab_role.requested_private_ipv4
    if ipv4 is None:
        raise ValueError(
            f"endpoint manifest {endpoint_manifest.endpoint_id!r} lacks an IPv4 address "
            f"for role {lab_role.name!r}"
        )

    interface_metadata = json_object(interface.metadata, "interface.metadata")
    endpoint_metadata: dict[str, object] = {
        "provider": endpoint_manifest.provider,
        "wire_provider": endpoint_manifest.provider,
        "wire_exposure": endpoint_manifest.exposure,
        "selected_exposure": exposure,
        "dry_run": dry_run,
        "creates_infrastructure": not dry_run,
        "would_create_infrastructure": dry_run,
        "resource_type": "wire-endpoint",
        "artifact_dir": endpoint_manifest.artifact_dir,
        "provider_network_id": interface.provider_network_id,
        "address_source": "manifest-interface" if interface.ipv4 else "role-planned-ipv4",
        "planned_address": interface.ipv4 is None,
        "interface_metadata": interface_metadata,
    }
    endpoint_metadata.update(_selected_manifest_metadata(endpoint_manifest.metadata))
    endpoint_metadata.update(_selected_interface_metadata(interface_metadata))
    endpoint_metadata.update(json_object(metadata or {}, "endpoint.metadata"))

    return LabEndpoint(
        endpoint_id=endpoint_manifest.endpoint_id,
        role=lab_role.name,
        interface=interface.name,
        ipv4=ipv4,
        ipv6=interface.ipv6,
        mac=interface.mac,
        peer_addresses=peer_address_map(peer_roles),
        wire_manifest=endpoint_manifest.to_dict(),
        appliance_runtime=appliance_runtime,
        metadata=json_object(endpoint_metadata, "endpoint.metadata"),
    )


def lab_appliance_runtime_from_manifest(
    manifest: EndpointManifest | Mapping[str, object],
    *,
    default_profile: str,
    default_substrate: str,
    default_execution_mode: str,
    default_remote_work_root: str | None = None,
    default_remote_artifact_root: str | None = None,
    default_remote_base: str = DEFAULT_APPLIANCE_REMOTE_BASE,
    default_docker_command: str = "docker",
    default_image_tag: str | None = None,
    metadata: Mapping[str, object] | None = None,
) -> LabApplianceRuntime:
    """Return provider-neutral appliance runtime metadata for one endpoint.

    Endpoint manifests may carry a provider-specific ``metadata.appliance``
    block. Lab providers mirror those substrate fields into the neutral runtime
    model and only use explicit provider defaults when the manifest is older or
    produced by a substrate without an appliance block.
    """

    endpoint_manifest = coerce_endpoint_manifest(manifest)
    manifest_metadata = json_object(endpoint_manifest.metadata, "manifest.metadata")
    appliance = _optional_json_object(
        manifest_metadata.get("appliance"),
        "manifest.metadata.appliance",
    )
    docker = _optional_json_object(
        manifest_metadata.get("docker"),
        "manifest.metadata.docker",
    )
    docker_container = _optional_json_object(
        docker.get("container") if docker is not None else None,
        "manifest.metadata.docker.container",
    )
    docker_image = _optional_json_object(
        manifest_metadata.get("docker_image")
        or (docker.get("image") if docker is not None else None),
        "manifest.metadata.docker_image",
    )

    supported_profiles = _supported_profiles(appliance)
    profile = (
        _string_metadata(appliance, "profile")
        or _string_metadata(appliance, "raw_profile")
        or (supported_profiles[0] if supported_profiles else None)
        or default_profile
    )
    docker_command = (
        _string_metadata(appliance, "docker_command")
        or _string_metadata(docker, "command")
        or default_docker_command
    )
    image_tag = (
        _string_metadata(appliance, "image_tag")
        or _string_metadata(docker_container, "image")
        or _string_metadata(docker_image, "tag")
        or default_image_tag
        or requested_appliance_image({})
    )

    remote_work_root = (
        _string_metadata(appliance, "remote_work_root")
        or default_remote_work_root
        or _remote_root(
            endpoint_manifest.endpoint_id,
            appliance=appliance,
            default_remote_base=default_remote_base,
            leaf="work",
        )
    )
    remote_artifact_root = (
        _string_metadata(appliance, "remote_artifact_root")
        or default_remote_artifact_root
        or _remote_root(
            endpoint_manifest.endpoint_id,
            appliance=appliance,
            default_remote_base=default_remote_base,
            leaf="artifacts",
        )
    )

    substrate = _string_metadata(appliance, "substrate") or default_substrate
    execution_mode = (
        _string_metadata(appliance, "execution_mode")
        or _string_metadata(appliance, "target_kind")
        or default_execution_mode
    )
    nested_docker = _bool_metadata(appliance, "nested_docker")
    if nested_docker is None:
        nested_docker = default_execution_mode == "ssh-docker-host"
    docker_execution_supported = _bool_metadata(appliance, "docker_execution_supported")
    if docker_execution_supported is None:
        docker_execution_supported = nested_docker

    container_policy = _runtime_container_policy(
        profile,
        appliance=appliance,
        docker_command=docker_command,
        execution_mode=execution_mode,
        nested_docker=nested_docker,
        docker_execution_supported=docker_execution_supported,
    )
    check_metadata = _runtime_check_metadata(profile, appliance=appliance)
    runtime_metadata: dict[str, object] = {
        "provider": endpoint_manifest.provider,
        "wire_provider": endpoint_manifest.provider,
        "wire_exposure": endpoint_manifest.exposure,
        "endpoint_id": endpoint_manifest.endpoint_id,
        "role": endpoint_manifest.role,
        "status": endpoint_manifest.status,
        "source": "endpoint-manifest" if appliance is not None else "provider-defaults",
        "substrate": substrate,
        "execution_mode": execution_mode,
        "docker_command": docker_command,
        "nested_docker": nested_docker,
        "docker_execution_supported": docker_execution_supported,
        "appliance_capable": _bool_metadata(appliance, "appliance_capable", default=True),
        "supported_profiles": supported_profiles or [profile],
    }
    if docker_container is not None:
        runtime_metadata["docker_endpoint_container"] = True
        runtime_metadata["docker_container"] = docker_container
    if appliance is not None:
        runtime_metadata["endpoint_appliance"] = appliance
    runtime_metadata.update(json_object(metadata or {}, "appliance_runtime.metadata"))

    return LabApplianceRuntime(
        profile=profile,
        image_tag=image_tag,
        remote_work_root=remote_work_root,
        remote_artifact_root=remote_artifact_root,
        container_policy=container_policy,
        check_metadata=check_metadata,
        metadata=json_object(runtime_metadata, "appliance_runtime.metadata"),
    )


def session_appliance_runtime_from_endpoints(
    endpoints: Sequence[LabEndpoint],
    *,
    remote_work_root: str,
    remote_artifact_root: str,
) -> LabApplianceRuntime | None:
    """Return a session-level appliance runtime when endpoint runtimes agree."""

    if not endpoints:
        return None

    runtimes: list[LabApplianceRuntime] = []
    for endpoint in endpoints:
        if endpoint.appliance_runtime is None:
            return None
        runtimes.append(endpoint.appliance_runtime)

    if not runtimes:
        return None

    first = runtimes[0]
    if not all(
        runtime.profile == first.profile
        and runtime.image_tag == first.image_tag
        and runtime.container_policy == first.container_policy
        and runtime.check_metadata == first.check_metadata
        for runtime in runtimes
    ):
        return None

    metadata = dict(first.metadata)
    for endpoint_key in (
        "endpoint_id",
        "role",
        "status",
        "endpoint_appliance",
        "docker_container",
    ):
        metadata.pop(endpoint_key, None)
    metadata.update(
        {
            "scope": "session",
            "source": "endpoint-runtimes",
            "endpoint_runtime_count": len(runtimes),
            "endpoint_ids": [endpoint.endpoint_id for endpoint in endpoints],
        }
    )
    return LabApplianceRuntime(
        profile=first.profile,
        image_tag=first.image_tag,
        remote_work_root=remote_work_root,
        remote_artifact_root=remote_artifact_root,
        container_policy=first.container_policy,
        check_metadata=first.check_metadata,
        metadata=json_object(metadata, "session.appliance_runtime.metadata"),
    )


def normalize_provider_capabilities(
    raw: Mapping[str, object],
    *,
    provider: str,
    dry_run: bool | None = None,
    source: str | None = None,
    live_packet_exchange: bool = True,
    capability_names: Sequence[str] = COMMON_PROVIDER_CAPABILITY_NAMES,
    defaults: Mapping[str, object] | None = None,
) -> JSONObject:
    """Normalize common substrate capability keys and legacy aliases."""

    base: dict[str, object] = dict(defaults or {})
    raw_capabilities = raw.get("capabilities")
    if isinstance(raw_capabilities, Mapping):
        base.update({key: value for key, value in raw.items() if key != "capabilities"})
        base.update(
            {
                key: value
                for key, value in raw_capabilities.items()
                if isinstance(key, str)
            }
        )
    else:
        base.update(raw)

    base["provider"] = provider
    if dry_run is not None:
        base["dry_run"] = dry_run
    if source is not None:
        base["source"] = source
    base.setdefault("live_packet_exchange", live_packet_exchange)

    normalized_names = [str(name) for name in capability_names]
    for name in normalized_names:
        base[name] = bool(base.get(name, False))

    base["ipv4"] = bool(base.get("ipv4_unicast", False))
    base["ipv6"] = bool(base.get("ipv6_unicast", False))
    base["l2"] = bool(
        base.get("link_layer_send", False) and base.get("link_layer_capture", False)
    )
    base["provider_mac"] = bool(base.get("provider_mac_known", False))
    base["controlled_service"] = bool(base.get("controlled_services", False))
    base["capability_names"] = normalized_names
    return json_object(base, "provider_capabilities")


def coerce_endpoint_manifest(
    manifest: EndpointManifest | Mapping[str, object],
) -> EndpointManifest:
    """Return a typed endpoint manifest from model or JSON-compatible data."""

    if isinstance(manifest, EndpointManifest):
        return manifest
    if not isinstance(manifest, Mapping):
        raise ValueError("endpoint manifest must be an object")
    return EndpointManifest.from_dict(_wire_manifest_object(manifest))


def peer_address_map(peer_roles: Sequence[LabRole]) -> JSONObject:
    """Return peer role addresses for endpoint metadata."""

    peers: JSONObject = {}
    for peer in peer_roles:
        ipv4 = peer.planned_ipv4 or peer.requested_private_ipv4
        if ipv4 is None:
            continue
        peers[peer.name] = {"ipv4": ipv4}
    return peers


def _selected_manifest_metadata(manifest_metadata: JSONObject) -> JSONObject:
    output: JSONObject = {}
    private_group = manifest_metadata.get("private_group")
    if isinstance(private_group, str) and private_group:
        output["private_group"] = private_group
    return output


def _selected_interface_metadata(interface_metadata: JSONObject) -> JSONObject:
    output: JSONObject = {}
    for key in (
        "private_group",
        "bridge_interface",
        "bridge_selection",
        "bridge_env",
        "backend",
        "type",
    ):
        value = interface_metadata.get(key)
        if value is not None:
            output[key] = value
    network = interface_metadata.get("network")
    if isinstance(network, Mapping):
        private_group = network.get("private_group")
        if isinstance(private_group, str) and private_group:
            output.setdefault("private_group", private_group)
    return output


def _runtime_container_policy(
    profile: str,
    *,
    appliance: JSONObject | None,
    docker_command: str,
    execution_mode: str,
    nested_docker: bool,
    docker_execution_supported: bool,
) -> JSONObject:
    explicit = _optional_json_object(
        appliance.get("container_policy") if appliance is not None else None,
        "manifest.metadata.appliance.container_policy",
    )
    if explicit is not None:
        policy = dict(explicit)
    else:
        appliance_profile = resolve_profile(profile)
        if execution_mode == "endpoint-container":
            policy = {
                "runtime": "endpoint-container",
                "environment": dict(appliance_profile.env),
            }
        else:
            policy = {
                "runtime": "docker",
                "network_mode": appliance_profile.network_mode,
                "capabilities": list(appliance_profile.cap_add),
                "devices": [device.to_dict() for device in appliance_profile.devices],
                "mounts": [mount.to_dict() for mount in appliance_profile.mounts],
                "environment": dict(appliance_profile.env),
            }

    policy.setdefault(
        "runtime",
        "endpoint-container" if execution_mode == "endpoint-container" else "docker",
    )
    if execution_mode != "endpoint-container":
        policy["docker_command"] = docker_command
    policy["execution_mode"] = execution_mode
    policy["nested_docker"] = nested_docker
    policy["docker_execution_supported"] = docker_execution_supported
    if execution_mode == "endpoint-container":
        policy["already_inside_appliance"] = True
    return json_object(policy, "appliance_runtime.container_policy")


def _runtime_check_metadata(profile: str, *, appliance: JSONObject | None) -> JSONObject:
    explicit = _optional_json_object(
        appliance.get("check_metadata") if appliance is not None else None,
        "manifest.metadata.appliance.check_metadata",
    )
    if explicit is not None:
        return explicit

    appliance_profile = resolve_profile(profile)
    checks = [
        check.to_dict() if hasattr(check, "to_dict") else json_object(check, "profile.checks[]")
        for check in appliance_profile.checks
    ]
    metadata: dict[str, object] = {
        "profile": profile,
        "profile_checks": checks,
        "host_requirements": list(appliance_profile.host_requirements),
    }
    if appliance is not None:
        for key in ("docker_setup", "docker_host_readiness", "profile_hints"):
            value = appliance.get(key)
            if value is not None:
                metadata[key] = value
    return json_object(metadata, "appliance_runtime.check_metadata")


def _remote_root(
    endpoint_id: str,
    *,
    appliance: JSONObject | None,
    default_remote_base: str,
    leaf: str,
) -> str:
    remote_base = (
        _string_metadata(appliance, "remote_base")
        or default_remote_base
    )
    return posixpath.join(
        validate_remote_dir(remote_base),
        slug_label(endpoint_id, fallback="endpoint", max_length=127),
        leaf,
    )


def _supported_profiles(appliance: JSONObject | None) -> list[str]:
    value = appliance.get("supported_profiles") if appliance is not None else None
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _optional_json_object(value: object, name: str) -> JSONObject | None:
    if value is None:
        return None
    return json_object(value, name)


def _string_metadata(metadata: JSONObject | None, key: str) -> str | None:
    if metadata is None:
        return None
    value = metadata.get(key)
    return value if isinstance(value, str) and value else None


def _bool_metadata(
    metadata: JSONObject | None,
    key: str,
    *,
    default: bool | None = None,
) -> bool | None:
    if metadata is None:
        return default
    value = metadata.get(key)
    return value if isinstance(value, bool) else default


def _wire_manifest_object(value: Mapping[str, object]) -> JSONObject:
    output = json_object(value, "wire_manifest")
    provider_resources = output.get("provider_resources")
    if isinstance(provider_resources, list):
        output["provider_resources"] = {
            "resources": provider_resources,
            "cleanup_order": [],
            "metadata": {},
        }
    return output


__all__ = [
    "COMMON_PROVIDER_CAPABILITY_NAMES",
    "DEFAULT_REMOTE_DIR",
    "build_command_plan",
    "coerce_endpoint_manifest",
    "lab_appliance_runtime_from_manifest",
    "lab_endpoint_from_manifest",
    "normalize_provider_capabilities",
    "peer_address_map",
    "profile_seed_label",
    "request_session_label",
    "select_manifest_interface",
    "session_appliance_runtime_from_endpoints",
    "slug_label",
    "validate_remote_dir",
]
