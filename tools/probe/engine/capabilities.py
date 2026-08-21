"""Runtime capability requirements declared by deterministic probe cases."""

from __future__ import annotations

from collections.abc import Mapping

from .model import JSONValue, ProbeCase


SKIP_CAPABILITY_UNAVAILABLE = "runtime_capability_unavailable"
SKIP_CONFIRMATION_REQUIRED = "explicit_execution_required"
SKIP_REQUIRES_CONTROLLED_ROUTER = "requires_controlled_router"
SKIP_REQUIRES_LINK_LAYER = "requires_link_layer"
SKIP_REQUIRES_BROADCAST = "requires_broadcast"
SKIP_REQUIRES_PEER_MAC = "requires_peer_mac"
SKIP_REQUIRES_PRIVILEGED_PORT = "requires_privileged_port"
SKIP_REQUIRES_CONTROLLED_SERVICE = "requires_controlled_service"
SKIP_REQUIRES_BGP_PEER = "requires_bgp_peer"
SKIP_REQUIRES_RIP_PEER = "requires_rip_peer"
SKIP_REQUIRES_MQTT_BROKER = "requires_mqtt_broker"
SKIP_REQUIRES_DHCPV6_SERVICE = "requires_dhcpv6_service"
SKIP_REQUIRES_DHCPV6_RELAY_TOPOLOGY = "requires_dhcpv6_relay_topology"
SKIP_REQUIRES_MULTICAST = "requires_multicast"
SKIP_OFFLINE_PLAN_UNAVAILABLE = "offline_plan_unavailable"
SKIP_REQUIRES_IPV6_LINK_LOCAL_SCOPE_METADATA = "requires_ipv6_link_local_scope_metadata"
SKIP_REQUIRES_IPV4_MULTICAST = "requires_ipv4_multicast"
SKIP_REQUIRES_IGMP_PEER = "requires_igmp_peer"
SKIP_REQUIRES_IPSEC_PEER = "requires_ipsec_peer"
SKIP_REQUIRES_IKEV2_RESPONDER = "requires_ikev2_responder"
SKIP_REQUIRES_SNMP_PEER = "requires_snmp_peer"
SKIP_REQUIRES_SCTP_CONTROLLED_PEER = "requires_sctp_controlled_peer"


_LINK_LAYER_CAPABILITIES = frozenset(
    {"arp_resolution", "link_layer_arp", "link_layer_send", "link_layer_capture"}
)

_CAPABILITY_REASONS = {
    "controlled_router": SKIP_REQUIRES_CONTROLLED_ROUTER,
    "broadcast": SKIP_REQUIRES_BROADCAST,
    "peer_mac": SKIP_REQUIRES_PEER_MAC,
    "privileged_udp_port": SKIP_REQUIRES_PRIVILEGED_PORT,
    "controlled_services": SKIP_REQUIRES_CONTROLLED_SERVICE,
    "bgp_peer": SKIP_REQUIRES_BGP_PEER,
    "rip_peer": SKIP_REQUIRES_RIP_PEER,
    "mqtt_broker": SKIP_REQUIRES_MQTT_BROKER,
    "dhcpv6_service": SKIP_REQUIRES_DHCPV6_SERVICE,
    "dhcpv6_relay_topology": SKIP_REQUIRES_DHCPV6_RELAY_TOPOLOGY,
    "ssdp_ipv4_multicast": SKIP_REQUIRES_MULTICAST,
    "ssdp_ipv6_multicast": SKIP_REQUIRES_MULTICAST,
    "ssdp_ipv6_link_local_scope": SKIP_REQUIRES_IPV6_LINK_LOCAL_SCOPE_METADATA,
    "ssdp_controlled_responder": SKIP_REQUIRES_CONTROLLED_SERVICE,
    "ssdp_offline_plan": SKIP_OFFLINE_PLAN_UNAVAILABLE,
    "mdns_ipv4_multicast": SKIP_REQUIRES_MULTICAST,
    "mdns_ipv6_multicast": SKIP_REQUIRES_MULTICAST,
    "mdns_ipv6_link_local_scope": SKIP_REQUIRES_IPV6_LINK_LOCAL_SCOPE_METADATA,
    "mdns_controlled_responder": SKIP_REQUIRES_CONTROLLED_SERVICE,
    "mdns_unicast_response": SKIP_REQUIRES_CONTROLLED_SERVICE,
    "ipv4_multicast": SKIP_REQUIRES_IPV4_MULTICAST,
    "igmp_peer": SKIP_REQUIRES_IGMP_PEER,
    "ipsec_esp": SKIP_REQUIRES_IPSEC_PEER,
    "ipsec_ah": SKIP_REQUIRES_IPSEC_PEER,
    "ikev2": SKIP_REQUIRES_IKEV2_RESPONDER,
    "snmp_peer": SKIP_REQUIRES_SNMP_PEER,
    "sctp_controlled_peer": SKIP_REQUIRES_SCTP_CONTROLLED_PEER,
}


def missing_capabilities(
    case: ProbeCase,
    available_capabilities: Mapping[str, JSONValue],
) -> list[str]:
    """Return required runtime capabilities not present in ``available``."""

    return [
        capability
        for capability in case.required_capabilities
        if available_capabilities.get(capability) is not True
    ]


def skip_reason_for_missing_capability(case: ProbeCase, capability: str) -> str:
    """Return a stable reason for an unmet runtime requirement."""

    if capability in _LINK_LAYER_CAPABILITIES or capability == "ipv6_multicast":
        return SKIP_REQUIRES_LINK_LAYER
    return _CAPABILITY_REASONS.get(capability, SKIP_CAPABILITY_UNAVAILABLE)


def primary_endpoint_role(case: ProbeCase) -> str:
    """Return the primary execution role for a case."""

    return case.endpoint_roles[0] if case.endpoint_roles else "stimulus"


__all__ = [name for name in globals() if name.startswith("SKIP_")] + [
    "missing_capabilities",
    "primary_endpoint_role",
    "skip_reason_for_missing_capability",
]
