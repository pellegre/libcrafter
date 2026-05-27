"""Shared provider helpers for lab endpoint planning."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from pathlib import PurePosixPath

from tools.wire.engine.model import EndpointManifest, NetworkInterface

from ..model import (
    JSONObject,
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
        f"wire manifest {endpoint_manifest.endpoint_id!r} lacks an {exposure!r} interface"
    )


def lab_endpoint_from_manifest(
    manifest: EndpointManifest | Mapping[str, object],
    *,
    role: LabRole | str,
    exposure: str,
    peer_roles: Sequence[LabRole] = (),
    dry_run: bool,
    fallback_to_first_interface: bool = False,
    metadata: Mapping[str, object] | None = None,
) -> LabEndpoint:
    """Convert a wire endpoint manifest into the lab endpoint shape."""

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
            f"wire manifest {endpoint_manifest.endpoint_id!r} lacks an IPv4 address "
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
        metadata=json_object(endpoint_metadata, "endpoint.metadata"),
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
    """Return a typed wire endpoint manifest from model or JSON-compatible data."""

    if isinstance(manifest, EndpointManifest):
        return manifest
    if not isinstance(manifest, Mapping):
        raise ValueError("wire manifest must be an object")
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
    "lab_endpoint_from_manifest",
    "normalize_provider_capabilities",
    "peer_address_map",
    "profile_seed_label",
    "request_session_label",
    "select_manifest_interface",
    "slug_label",
    "validate_remote_dir",
]
