"""Probe-owned boundary over lab provider sessions."""

from __future__ import annotations

from collections.abc import Mapping

from tools.lab.engine.model import LabEndpoint, LabSession
from tools.lab.engine.providers import (
    LabProviderAdapter,
    UnknownLabProviderError,
    registered_provider_names as registered_lab_provider_names,
    resolve_lab_provider,
)

from .model import JSONObject, JSONValue, json_object


LOCAL_DRY_RUN_PROVIDER = "local-dry-run"
STIMULUS_ROLE = "stimulus"
TARGET_ROLE = "target"
PROBE_LAB_ROLES = (STIMULUS_ROLE, TARGET_ROLE)
PROBE_CAPABILITY_NAMES = (
    "icmp_echo",
    "tcp_open_port",
    "tcp_closed_port",
    "dns_service",
    "dhcp_service",
    "udp_service",
    "privileged_udp_port",
    "controlled_router",
    "arp_resolution",
    "link_layer_arp",
    "link_layer_send",
    "link_layer_capture",
    "broadcast",
    "provider_mac",
    "repeated_response",
)


class UnknownProbeLabProviderError(ValueError):
    """Raised when probe asks for an unknown lab-backed provider."""


def probe_provider_names() -> tuple[str, ...]:
    """Return provider names accepted by probe CLI choices."""

    return tuple(sorted((*registered_lab_provider_names(), LOCAL_DRY_RUN_PROVIDER)))


def probe_lab_provider_names() -> tuple[str, ...]:
    """Return lab-backed provider names available to probe."""

    return registered_lab_provider_names()


def is_probe_lab_provider(provider: str) -> bool:
    """Return whether the provider is backed by the standalone lab tool."""

    return provider in registered_lab_provider_names()


def resolve_probe_lab_provider(provider: str) -> LabProviderAdapter:
    """Resolve a lab provider adapter for a probe provider name."""

    if provider == LOCAL_DRY_RUN_PROVIDER:
        raise UnknownProbeLabProviderError(
            f"{LOCAL_DRY_RUN_PROVIDER!r} is probe-local and has no lab provider"
        )
    try:
        return resolve_lab_provider(provider)
    except UnknownLabProviderError as exc:
        known = ", ".join(probe_lab_provider_names()) or "<none>"
        raise UnknownProbeLabProviderError(
            f"unsupported probe lab provider {provider!r}; known providers: {known}"
        ) from exc


def probe_capabilities_for_provider(
    provider: str,
    *,
    dry_run: bool,
) -> JSONObject:
    """Return probe capabilities derived from the provider substrate."""

    if provider == LOCAL_DRY_RUN_PROVIDER:
        return local_dry_run_probe_capabilities()

    adapter = resolve_probe_lab_provider(provider)
    lab_capabilities = adapter.default_provider_capabilities(dry_run=dry_run)
    return probe_capabilities_from_lab_capabilities(
        provider,
        lab_capabilities,
        dry_run=dry_run,
    )


def local_dry_run_probe_capabilities() -> JSONObject:
    """Return local dry-run probe capabilities through the same derivation path."""

    lab_capabilities: JSONObject = {
        "provider": LOCAL_DRY_RUN_PROVIDER,
        "dry_run": True,
        "source": "probe-local-dry-run",
        "live_packet_exchange": False,
        "ipv4_unicast": True,
        "ipv6_unicast": False,
        "link_layer_send": False,
        "link_layer_capture": False,
        "broadcast": False,
        "provider_mac_known": False,
        "controlled_services": True,
        "controlled_router": False,
    }
    return probe_capabilities_from_lab_capabilities(
        LOCAL_DRY_RUN_PROVIDER,
        lab_capabilities,
        dry_run=True,
    )


def probe_capabilities_from_lab_capabilities(
    provider: str,
    lab_capabilities: Mapping[str, object],
    *,
    dry_run: bool | None = None,
) -> JSONObject:
    """Derive probe case capabilities from lab substrate capabilities."""

    substrate = json_object(lab_capabilities, "lab_capabilities")
    ipv4_unicast = _capability(substrate, "ipv4_unicast", "ipv4")
    controlled_services = _capability(
        substrate,
        "controlled_services",
        "controlled_service",
    )
    controlled_router = _capability(substrate, "controlled_router")
    link_layer_send = _capability(substrate, "link_layer_send")
    link_layer_capture = _capability(substrate, "link_layer_capture")
    broadcast = _capability(substrate, "broadcast")
    provider_mac = _capability(substrate, "provider_mac_known", "provider_mac")
    arp_resolution = link_layer_send and link_layer_capture and broadcast
    link_layer_arp = arp_resolution and provider_mac
    dhcp_service = (
        ipv4_unicast
        and controlled_services
        and link_layer_send
        and link_layer_capture
        and broadcast
    )
    udp_service = ipv4_unicast and controlled_services
    privileged_udp_port = ipv4_unicast and controlled_services
    repeated_response = ipv4_unicast and controlled_services
    derived_dry_run = (
        dry_run
        if dry_run is not None
        else substrate.get("dry_run")
        if isinstance(substrate.get("dry_run"), bool)
        else None
    )

    capabilities: JSONObject = {
        "provider": provider,
        "lab_provider": str(substrate.get("provider") or provider),
        "source": "lab_provider_capabilities",
        "live_packet_exchange": _capability(substrate, "live_packet_exchange"),
        "ipv4_unicast": ipv4_unicast,
        "controlled_services": controlled_services,
        "icmp_echo": ipv4_unicast,
        "tcp_open_port": ipv4_unicast and controlled_services,
        "tcp_closed_port": ipv4_unicast,
        "dns_service": ipv4_unicast and controlled_services,
        "dhcp_service": dhcp_service,
        "udp_service": udp_service,
        "privileged_udp_port": privileged_udp_port,
        "controlled_router": controlled_router,
        "link_layer_send": link_layer_send,
        "link_layer_capture": link_layer_capture,
        "broadcast": broadcast,
        "provider_mac": provider_mac,
        "arp_resolution": arp_resolution,
        "link_layer_arp": link_layer_arp,
        "repeated_response": repeated_response,
        "capability_names": list(PROBE_CAPABILITY_NAMES),
        "capability_sources": {
            "icmp_echo": ["ipv4_unicast"],
            "tcp_open_port": ["ipv4_unicast", "controlled_services"],
            "tcp_closed_port": ["ipv4_unicast"],
            "dns_service": ["ipv4_unicast", "controlled_services"],
            "dhcp_service": [
                "ipv4_unicast",
                "controlled_services",
                "link_layer_send",
                "link_layer_capture",
                "broadcast",
            ],
            "udp_service": ["ipv4_unicast", "controlled_services"],
            "privileged_udp_port": ["ipv4_unicast", "controlled_services"],
            "controlled_router": ["controlled_router"],
            "link_layer_send": ["link_layer_send"],
            "link_layer_capture": ["link_layer_capture"],
            "broadcast": ["broadcast"],
            "provider_mac": ["provider_mac_known"],
            "arp_resolution": [
                "link_layer_send",
                "link_layer_capture",
                "broadcast",
            ],
            "link_layer_arp": [
                "link_layer_send",
                "link_layer_capture",
                "broadcast",
                "provider_mac_known",
            ],
            "repeated_response": ["ipv4_unicast", "controlled_services"],
        },
        "lab_capabilities": substrate,
    }
    if derived_dry_run is not None:
        capabilities["dry_run"] = derived_dry_run
    artifact = substrate.get("capability_report_artifact")
    if isinstance(artifact, str) and artifact:
        capabilities["capability_report_artifact"] = artifact
    return capabilities


def probe_address_context_from_lab_session(
    session: LabSession,
    *,
    stimulus_role: str = STIMULUS_ROLE,
    target_role: str = TARGET_ROLE,
) -> JSONObject:
    """Return probe endpoint address context from a lab session."""

    if not isinstance(session, LabSession):
        raise TypeError("session must be a LabSession")

    endpoints_by_role = _endpoints_by_role(session)
    stimulus = _required_endpoint(endpoints_by_role, stimulus_role)
    target = _required_endpoint(endpoints_by_role, target_role)

    endpoints: dict[str, JSONValue] = {}
    for role, endpoint in endpoints_by_role.items():
        peer_role, peer_address = _default_peer(
            role,
            endpoints_by_role,
            stimulus_role=stimulus_role,
            target_role=target_role,
        )
        endpoints[role] = _probe_endpoint_address(
            endpoint,
            session=session,
            peer_role=peer_role,
            peer_address=peer_address,
            endpoints_by_role=endpoints_by_role,
        )

    return {
        "provider": session.provider,
        "wire_provider": session.wire_provider,
        "wire_exposure": session.wire_exposure,
        "session_id": session.session_id,
        "dry_run": session.dry_run,
        "stimulus_role": stimulus_role,
        "target_role": target_role,
        "stimulus_ipv4": stimulus.ipv4,
        "target_ipv4": target.ipv4,
        "endpoint_count": len(endpoints),
        "endpoints": endpoints,
    }


def _capability(capabilities: Mapping[str, JSONValue], *names: str) -> bool:
    return any(capabilities.get(name) is True for name in names)


def _endpoints_by_role(session: LabSession) -> dict[str, LabEndpoint]:
    endpoints: dict[str, LabEndpoint] = {}
    for endpoint in session.endpoints:
        if endpoint.role in endpoints:
            raise ValueError(f"duplicate lab endpoint role {endpoint.role!r}")
        endpoints[endpoint.role] = endpoint
    return endpoints


def _required_endpoint(
    endpoints_by_role: Mapping[str, LabEndpoint],
    role: str,
) -> LabEndpoint:
    try:
        return endpoints_by_role[role]
    except KeyError as exc:
        raise ValueError(f"missing lab endpoint role {role!r}") from exc


def _default_peer(
    role: str,
    endpoints_by_role: Mapping[str, LabEndpoint],
    *,
    stimulus_role: str,
    target_role: str,
) -> tuple[str | None, str | None]:
    if role == stimulus_role and target_role in endpoints_by_role:
        peer = endpoints_by_role[target_role]
        return peer.role, peer.ipv4
    if role == target_role and stimulus_role in endpoints_by_role:
        peer = endpoints_by_role[stimulus_role]
        return peer.role, peer.ipv4
    for peer_role in sorted(endpoints_by_role):
        if peer_role != role:
            peer = endpoints_by_role[peer_role]
            return peer.role, peer.ipv4
    return None, None


def _probe_endpoint_address(
    endpoint: LabEndpoint,
    *,
    session: LabSession,
    peer_role: str | None,
    peer_address: str | None,
    endpoints_by_role: Mapping[str, LabEndpoint],
) -> JSONObject:
    peer_addresses = _peer_addresses(endpoint, endpoints_by_role)
    metadata = json_object(endpoint.metadata, "endpoint.metadata")
    metadata.update(
        {
            "provider": session.provider,
            "wire_provider": session.wire_provider,
            "wire_exposure": session.wire_exposure,
            "lab_session_id": session.session_id,
            "peer_role": peer_role,
            "peer_address": peer_address,
            "wire_endpoint_plan": endpoint.wire_manifest,
        }
    )

    output: JSONObject = {
        "endpoint_id": endpoint.endpoint_id,
        "role": endpoint.role,
        "interface": endpoint.interface,
        "address": endpoint.ipv4,
        "ipv4": endpoint.ipv4,
        "peer_address": peer_address,
        "peer_addresses": peer_addresses,
        "metadata": metadata,
    }
    if endpoint.ipv6 is not None:
        output["ipv6"] = endpoint.ipv6
    if endpoint.mac is not None:
        output["mac"] = endpoint.mac
    return output


def _peer_addresses(
    endpoint: LabEndpoint,
    endpoints_by_role: Mapping[str, LabEndpoint],
) -> JSONObject:
    peers = json_object(endpoint.peer_addresses, "endpoint.peer_addresses")
    for role, peer in endpoints_by_role.items():
        if role == endpoint.role:
            continue
        peers.setdefault(role, {"ipv4": peer.ipv4})
    return peers


__all__ = [
    "LOCAL_DRY_RUN_PROVIDER",
    "PROBE_CAPABILITY_NAMES",
    "PROBE_LAB_ROLES",
    "STIMULUS_ROLE",
    "TARGET_ROLE",
    "UnknownProbeLabProviderError",
    "is_probe_lab_provider",
    "local_dry_run_probe_capabilities",
    "probe_address_context_from_lab_session",
    "probe_capabilities_for_provider",
    "probe_capabilities_from_lab_capabilities",
    "probe_lab_provider_names",
    "probe_provider_names",
    "resolve_probe_lab_provider",
]
