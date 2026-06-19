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

from .cases import UDP_ECHO_LARGE_PAYLOAD_LENGTH
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
    "udp_large_payload",
    "udp_ipv4_zero_checksum",
    "udp_options_surplus",
    "privileged_udp_port",
    "controlled_router",
    "arp_resolution",
    "link_layer_arp",
    "link_layer_send",
    "link_layer_capture",
    "broadcast",
    "ipv6_multicast",
    "provider_mac",
    "repeated_response",
    "bgp_peer",
    "rip_peer",
    # IPSec behavioral capabilities. An IPSec-capable peer holds the matching
    # Security Association (ESP/AH) or runs an IKEv2 responder. The peer is the
    # Linux kernel xfrm / strongSwan stack or an oracle reference peer
    # configured on the controlled target endpoint; none of this is required for
    # a dry-run, which plans the exchange without provisioning the peer.
    "ipsec_esp",
    "ipsec_ah",
    "ikev2",
    # OSPF behavioral capability. An OSPF-capable peer runs an OSPFv2 speaker
    # (FRR/Quagga ospfd or the oracle reference peer) on the same area and
    # segment as the controlled target endpoint. Like the BGP/IPSec peers it
    # rides the IPv4-unicast + controlled-services substrate and is not required
    # for a dry-run, which plans the OSPF exchange without provisioning the peer.
    "ospf_neighbor_peer",
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
    # IPv6 Neighbor Discovery (the IPv6 analog of ARP) addresses solicitations to
    # the solicited-node / all-routers / all-nodes multicast groups rather than
    # the broadcast address, but it rides the same same-segment link-layer
    # substrate ARP uses: a segment that carries broadcast frames carries IPv6
    # multicast frames too. Derive ``ipv6_multicast`` from link-layer send/capture
    # plus broadcast so NDP cases plan on providers that carry same-segment L2
    # traffic (QEMU, VirtualBox) and skip cleanly on providers without an L2
    # segment (Hetzner) with the stable link-layer reason.
    ipv6_multicast = link_layer_send and link_layer_capture and broadcast
    dhcp_service = (
        ipv4_unicast
        and controlled_services
        and link_layer_send
        and link_layer_capture
        and broadcast
    )
    udp_service = ipv4_unicast and controlled_services
    advertised_udp_safe_payload = _optional_positive_int(
        substrate,
        "udp_safe_payload_size",
        "safe_udp_payload_size",
        "max_udp_payload_size",
        "private_network_safe_udp_payload_size",
    )
    udp_large_payload = udp_service and (
        advertised_udp_safe_payload is None
        or advertised_udp_safe_payload >= UDP_ECHO_LARGE_PAYLOAD_LENGTH
    )
    udp_ipv4_zero_checksum = udp_service and _capability_default_true(
        substrate,
        "udp_ipv4_zero_checksum",
        "ipv4_udp_zero_checksum",
    )
    udp_options_surplus = udp_service and _capability_default_true(
        substrate,
        "udp_options_surplus",
        "udp_surplus_options",
    )
    privileged_udp_port = ipv4_unicast and controlled_services
    repeated_response = ipv4_unicast and controlled_services
    # BGP smoke drives a controlled FRR peer on the target endpoint. It needs the
    # same IPv4-unicast + controlled-service substrate as DNS/UDP target
    # services, with an optional provider flag to deny BGP peer provisioning.
    bgp_peer = (
        ipv4_unicast
        and controlled_services
        and _capability_default_true(substrate, "bgp_peer")
    )
    # RIP smoke drives a controlled FRR ripd peer on the target endpoint. Like
    # BGP, it needs the IPv4-unicast + controlled-service substrate, with an
    # optional provider flag to deny RIP peer provisioning.
    rip_peer = (
        ipv4_unicast
        and controlled_services
        and _capability_default_true(substrate, "rip_peer")
    )
    # IPSec behavioral capabilities. The ESP/AH cases need a peer on the
    # controlled target endpoint that holds the matching Security Association
    # (the same SPI, mode, algorithms, and keys libcrafter seals/verifies with);
    # the IKEv2 case needs that peer to run an IKE responder on UDP/500. The peer
    # is realized as the Linux kernel xfrm / strongSwan stack or an oracle
    # reference peer configured on the target VM, so the capabilities derive from
    # the same IPv4-unicast + controlled-services substrate the DNS/UDP services
    # use: a substrate that can carry IPv4 unicast and host a controlled service
    # can host the IPSec peer too. Providers without a controlled service (a
    # bare L3 transit with no configurable peer) skip the IPSec cases cleanly
    # with the stable requires-IPSec-peer / requires-IKEv2-responder reasons.
    # An explicit ``ipsec_peer`` substrate flag, when present, can deny the peer
    # even where controlled services exist (e.g. a peer the lab cannot configure
    # with an xfrm/strongSwan SA). Tunnel-mode ESP additionally needs a
    # tunnel-mode SA on the peer; the ``requires_tunnel`` case metadata records
    # that so a transport-only peer skips the tunnel case while transport cases
    # still plan -- the capability itself is shared (``ipsec_esp``).
    ipsec_peer = (
        ipv4_unicast
        and controlled_services
        and _capability_default_true(substrate, "ipsec_peer")
    )
    ikev2_responder = (
        ipv4_unicast
        and controlled_services
        and _capability_default_true(
            substrate,
            "ikev2_responder",
            "ike_responder",
        )
    )
    ipsec_esp = ipsec_peer
    ipsec_ah = ipsec_peer
    ikev2 = ikev2_responder
    # OSPF smoke drives a controlled OSPFv2 neighbor on the target endpoint. OSPF
    # runs directly over IPv4 (protocol 89, no ports), so the peer needs the same
    # IPv4-unicast + controlled-services substrate the DNS/UDP/BGP target services
    # use: a substrate that can carry IPv4 unicast and host a controlled service
    # can host the OSPF speaker too. An explicit ``ospf_peer`` substrate flag,
    # when present, can deny the peer even where controlled services exist (e.g. a
    # peer the lab cannot configure with an ospfd in the documentation area).
    # Providers without a controlled service skip the OSPF cases cleanly with the
    # stable capability-unavailable reason; the offline dry-run path plans the
    # exchange regardless of whether the peer would be provisioned.
    ospf_neighbor_peer = (
        ipv4_unicast
        and controlled_services
        and _capability_default_true(substrate, "ospf_peer")
    )
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
        "udp_large_payload": udp_large_payload,
        "udp_ipv4_zero_checksum": udp_ipv4_zero_checksum,
        "udp_options_surplus": udp_options_surplus,
        "privileged_udp_port": privileged_udp_port,
        "controlled_router": controlled_router,
        "link_layer_send": link_layer_send,
        "link_layer_capture": link_layer_capture,
        "broadcast": broadcast,
        "ipv6_multicast": ipv6_multicast,
        "provider_mac": provider_mac,
        "arp_resolution": arp_resolution,
        "link_layer_arp": link_layer_arp,
        "repeated_response": repeated_response,
        "bgp_peer": bgp_peer,
        "rip_peer": rip_peer,
        "ipsec_esp": ipsec_esp,
        "ipsec_ah": ipsec_ah,
        "ikev2": ikev2,
        "ospf_neighbor_peer": ospf_neighbor_peer,
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
            "udp_large_payload": [
                "ipv4_unicast",
                "controlled_services",
                "udp_safe_payload_size",
            ],
            "udp_ipv4_zero_checksum": [
                "ipv4_unicast",
                "controlled_services",
                "udp_ipv4_zero_checksum",
            ],
            "udp_options_surplus": [
                "ipv4_unicast",
                "controlled_services",
                "udp_options_surplus",
            ],
            "privileged_udp_port": ["ipv4_unicast", "controlled_services"],
            "controlled_router": ["controlled_router"],
            "link_layer_send": ["link_layer_send"],
            "link_layer_capture": ["link_layer_capture"],
            "broadcast": ["broadcast"],
            "ipv6_multicast": [
                "link_layer_send",
                "link_layer_capture",
                "broadcast",
            ],
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
            "bgp_peer": ["ipv4_unicast", "controlled_services", "bgp_peer"],
            "rip_peer": ["ipv4_unicast", "controlled_services", "rip_peer"],
            "ipsec_esp": ["ipv4_unicast", "controlled_services", "ipsec_peer"],
            "ipsec_ah": ["ipv4_unicast", "controlled_services", "ipsec_peer"],
            "ikev2": [
                "ipv4_unicast",
                "controlled_services",
                "ikev2_responder",
            ],
            "ospf_neighbor_peer": [
                "ipv4_unicast",
                "controlled_services",
                "ospf_peer",
            ],
        },
        "lab_capabilities": substrate,
    }
    wire_policy = substrate.get("wire_policy")
    if isinstance(wire_policy, Mapping):
        capabilities["wire_policy"] = json_object(
            wire_policy,
            "lab_capabilities.wire_policy",
        )
    if derived_dry_run is not None:
        capabilities["dry_run"] = derived_dry_run
    if advertised_udp_safe_payload is not None:
        capabilities["udp_safe_payload_size"] = advertised_udp_safe_payload
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


def _optional_positive_int(
    capabilities: Mapping[str, JSONValue],
    *names: str,
) -> int | None:
    for name in names:
        value = capabilities.get(name)
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            return value
    return None


def _capability_default_true(
    capabilities: Mapping[str, JSONValue],
    *names: str,
) -> bool:
    for name in names:
        if name in capabilities:
            return capabilities.get(name) is True
    return True


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
    "UDP_ECHO_LARGE_PAYLOAD_LENGTH",
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
