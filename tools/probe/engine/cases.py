"""Probe behavioral case catalog and lookup helpers.

This module owns the canonical :class:`ProbeCase` catalog, the endpoint role
definitions, and the helpers that turn requested case-name filters into a stable
ordered selection of cases. Keeping the catalog here gives the behavioral suite
a single place to grow without enlarging the CLI orchestration module.
"""

from __future__ import annotations

from collections.abc import Sequence

from .model import EndpointRole, JSONObject, ProbeCase


# Capabilities required by each behavioral protocol group. DNS and UDP need only
# IPv4 unicast plus a controlled service; DHCP and ARP additionally need a
# link-layer (Ethernet/broadcast) substrate; NDP needs an IPv6 link-layer
# multicast substrate (solicited-node / all-routers multicast, not broadcast).
# The capability names match the probe capability derivation in
# :mod:`tools.probe.engine.lab`, so the behavior-suite cases skip with stable
# reasons on providers that cannot support them. Full per-case stimulus/
# validation wiring lands in the later per-case steps; here the cases route
# through the planned-only dispatcher fallback.
UDP_ECHO_LARGE_PAYLOAD_LENGTH = 1200
_DNS_CAPABILITIES = ["dns_service"]
_DHCP_CAPABILITIES = ["dhcp_service"]
_UDP_CAPABILITIES = ["udp_service"]
_UDP_LARGE_CAPABILITIES = [*_UDP_CAPABILITIES, "udp_large_payload"]
_UDP_ZERO_CHECKSUM_IPV4_CAPABILITIES = [
    *_UDP_CAPABILITIES,
    "udp_ipv4_zero_checksum",
]
_UDP_OPTIONS_SURPLUS_CAPABILITIES = [
    *_UDP_CAPABILITIES,
    "udp_options_surplus",
]
_ARP_CAPABILITIES = [
    "arp_resolution",
    "link_layer_send",
    "link_layer_capture",
    "broadcast",
]
# IPv6 Neighbor Discovery is the IPv6 analog of ARP. Unlike ARP (which rides
# Ethernet broadcast), NDP rides ICMPv6 over IPv6 and addresses solicitations to
# the solicited-node multicast group (and router solicitations to the
# all-routers multicast group), so it needs an IPv6 link-layer multicast
# substrate rather than broadcast. ``ipv6_multicast`` is derived in
# :mod:`tools.probe.engine.lab` from the same link-layer send/capture substrate
# ARP uses, so providers that carry same-segment multicast (QEMU, VirtualBox)
# plan the cases while providers without an L2 segment (Hetzner) skip cleanly
# with the stable ``requires_link_layer`` reason.
_NDP_CAPABILITIES = [
    "link_layer_send",
    "link_layer_capture",
    "ipv6_multicast",
]
# Some ARP cases need the *target MAC* (provider metadata): a unicast request is
# addressed to it rather than the broadcast address, and the MAC-validation case
# ties the decoded reply to it. Either way the case can only run once the
# target's MAC is known, so it adds ``provider_mac`` to the base ARP
# capabilities. A provider that cannot supply target-MAC metadata must skip with
# the stable ``requires_provider_mac`` reason.
_ARP_PROVIDER_MAC_CAPABILITIES = [
    *_ARP_CAPABILITIES,
    "provider_mac",
]
# Backwards-compatible alias: the unicast case introduced this list.
_ARP_UNICAST_CAPABILITIES = _ARP_PROVIDER_MAC_CAPABILITIES


def _behavior_case(
    *,
    name: str,
    description: str,
    stimulus: str,
    expected_response: str,
    required_capabilities: list[str],
    protocol: str,
    metadata: JSONObject | None = None,
) -> ProbeCase:
    case_metadata: JSONObject = {
        "protocol": protocol,
        "suite": "behavior",
    }
    if metadata:
        case_metadata.update(metadata)
    return ProbeCase(
        name=name,
        description=description,
        stimulus=stimulus,
        expected_response=expected_response,
        required_capabilities=list(required_capabilities),
        endpoint_roles=["stimulus", "target"],
        metadata=case_metadata,
    )


# Ten DNS behavioral cases (RFC-correct query/response shapes against a
# controlled DNS responder bound to the target address).
BEHAVIOR_DNS_CASES: tuple[ProbeCase, ...] = (
    _behavior_case(
        name="dns-a-success",
        description="Send an A query and validate a matching A answer.",
        stimulus="dns_query",
        expected_response="dns_response",
        required_capabilities=_DNS_CAPABILITIES,
        protocol="dns",
    ),
    _behavior_case(
        name="dns-aaaa-success",
        description="Send an AAAA query and validate a matching AAAA answer.",
        stimulus="dns_query",
        expected_response="dns_response",
        required_capabilities=_DNS_CAPABILITIES,
        protocol="dns",
    ),
    _behavior_case(
        name="dns-cname-chain",
        description="Query a CNAME that chains to an A record and validate the chain.",
        stimulus="dns_query",
        expected_response="dns_response",
        required_capabilities=_DNS_CAPABILITIES,
        protocol="dns",
    ),
    _behavior_case(
        name="dns-nxdomain",
        description="Query an absent name and validate an NXDOMAIN response.",
        stimulus="dns_query",
        expected_response="dns_response",
        required_capabilities=_DNS_CAPABILITIES,
        protocol="dns",
    ),
    _behavior_case(
        name="dns-nodata",
        description="Query an existing name for an absent type and validate NOERROR/NODATA.",
        stimulus="dns_query",
        expected_response="dns_response",
        required_capabilities=_DNS_CAPABILITIES,
        protocol="dns",
    ),
    _behavior_case(
        name="dns-txt-answer",
        description="Send a TXT query and validate the TXT answer.",
        stimulus="dns_query",
        expected_response="dns_response",
        required_capabilities=_DNS_CAPABILITIES,
        protocol="dns",
    ),
    _behavior_case(
        name="dns-mx-answer",
        description="Send an MX query and validate the MX answer.",
        stimulus="dns_query",
        expected_response="dns_response",
        required_capabilities=_DNS_CAPABILITIES,
        protocol="dns",
    ),
    _behavior_case(
        name="dns-srv-answer",
        description="Send an SRV query and validate the SRV answer.",
        stimulus="dns_query",
        expected_response="dns_response",
        required_capabilities=_DNS_CAPABILITIES,
        protocol="dns",
    ),
    _behavior_case(
        name="dns-edns-opt",
        description="Send an EDNS query with an OPT record and validate the OPT metadata.",
        stimulus="dns_query",
        expected_response="dns_response",
        required_capabilities=_DNS_CAPABILITIES,
        protocol="dns",
    ),
    _behavior_case(
        name="dns-repeat-transaction",
        description=(
            "Reuse a transaction id over separate source ports and validate each "
            "independently decoded response."
        ),
        stimulus="dns_query",
        expected_response="dns_response",
        required_capabilities=_DNS_CAPABILITIES,
        protocol="dns",
    ),
)


# Ten DHCP behavioral cases (DHCP/BOOTP client messages against a controlled
# DHCP responder on a private L2 segment).
BEHAVIOR_DHCP_CASES: tuple[ProbeCase, ...] = (
    _behavior_case(
        name="dhcp-discover-offer",
        description="Send a DHCP Discover and validate the Offer.",
        stimulus="dhcp_discover",
        expected_response="dhcp_offer",
        required_capabilities=_DHCP_CAPABILITIES,
        protocol="dhcp",
    ),
    _behavior_case(
        name="dhcp-request-ack",
        description="Send a DHCP Request and validate the Ack.",
        stimulus="dhcp_request",
        expected_response="dhcp_ack",
        required_capabilities=_DHCP_CAPABILITIES,
        protocol="dhcp",
    ),
    _behavior_case(
        name="dhcp-client-identifier",
        description=(
            "Send a Discover carrying a client identifier (option 61) and validate "
            "the matching Offer that records the client identity."
        ),
        stimulus="dhcp_discover",
        expected_response="dhcp_offer",
        required_capabilities=_DHCP_CAPABILITIES,
        protocol="dhcp",
    ),
    _behavior_case(
        name="dhcp-hostname",
        description="Send a Discover with a hostname option and validate the Offer.",
        stimulus="dhcp_discover",
        expected_response="dhcp_offer",
        required_capabilities=_DHCP_CAPABILITIES,
        protocol="dhcp",
    ),
    _behavior_case(
        name="dhcp-parameter-request-list",
        description=(
            "Send a Discover with a parameter request list and validate the "
            "requested options in the Offer."
        ),
        stimulus="dhcp_discover",
        expected_response="dhcp_offer",
        required_capabilities=_DHCP_CAPABILITIES,
        protocol="dhcp",
    ),
    _behavior_case(
        name="dhcp-lease-time",
        description=(
            "Send a Discover and validate the lease time (51), renewal T1 (58), "
            "and rebinding T2 (59) timing options in the Offer."
        ),
        stimulus="dhcp_discover",
        expected_response="dhcp_offer",
        required_capabilities=_DHCP_CAPABILITIES,
        protocol="dhcp",
    ),
    _behavior_case(
        name="dhcp-renewal-unicast-ack",
        description="Send a unicast renewal Request and validate the unicast Ack.",
        stimulus="dhcp_request",
        expected_response="dhcp_ack",
        required_capabilities=_DHCP_CAPABILITIES,
        protocol="dhcp",
    ),
    _behavior_case(
        name="dhcp-inform-ack",
        description="Send a DHCP Inform and validate the Ack with config options.",
        stimulus="dhcp_inform",
        expected_response="dhcp_ack",
        required_capabilities=_DHCP_CAPABILITIES,
        protocol="dhcp",
    ),
    _behavior_case(
        name="dhcp-request-nak",
        description="Request an invalid address and validate the Nak.",
        stimulus="dhcp_request",
        expected_response="dhcp_nak",
        required_capabilities=_DHCP_CAPABILITIES,
        protocol="dhcp",
    ),
    _behavior_case(
        name="dhcp-rapid-repeat",
        description=(
            "Send repeated Discovers and validate each independently decoded Offer."
        ),
        stimulus="dhcp_discover",
        expected_response="dhcp_offer",
        required_capabilities=_DHCP_CAPABILITIES,
        protocol="dhcp",
    ),
)


# Ten ARP behavioral cases (Ethernet/ARP who-has and is-at exchanges on a
# private L2 segment with provider MAC knowledge).
BEHAVIOR_ARP_CASES: tuple[ProbeCase, ...] = (
    _behavior_case(
        name="arp-basic-who-has",
        description="Broadcast a who-has request and validate the is-at reply.",
        stimulus="arp_who_has",
        expected_response="arp_is_at",
        required_capabilities=_ARP_CAPABILITIES,
        protocol="arp",
        metadata={"layer": "link"},
    ),
    _behavior_case(
        name="arp-repeat-two-replies",
        description="Repeat a who-has request and validate two parseable replies.",
        stimulus="arp_who_has",
        expected_response="arp_is_at",
        required_capabilities=_ARP_CAPABILITIES,
        protocol="arp",
        metadata={"layer": "link"},
    ),
    _behavior_case(
        name="arp-source-address-preserved",
        description=(
            "Validate that the reply is addressed to the request's sender "
            "hardware/protocol address."
        ),
        stimulus="arp_who_has",
        expected_response="arp_is_at",
        required_capabilities=_ARP_CAPABILITIES,
        protocol="arp",
        metadata={"layer": "link"},
    ),
    _behavior_case(
        name="arp-alias-address-reply",
        description="Query a target alias address and validate the reply.",
        stimulus="arp_who_has",
        expected_response="arp_is_at",
        required_capabilities=_ARP_CAPABILITIES,
        protocol="arp",
        metadata={"layer": "link"},
    ),
    _behavior_case(
        name="arp-unicast-request-reply",
        description=(
            "Send the ARP request to the known target MAC (not broadcast) and "
            "validate the reply."
        ),
        stimulus="arp_who_has",
        expected_response="arp_is_at",
        required_capabilities=_ARP_UNICAST_CAPABILITIES,
        protocol="arp",
        metadata={"layer": "link"},
    ),
    _behavior_case(
        name="arp-padding-reply",
        description="Send a request with Ethernet padding and validate the reply.",
        stimulus="arp_who_has",
        expected_response="arp_is_at",
        required_capabilities=_ARP_CAPABILITIES,
        protocol="arp",
        metadata={"layer": "link"},
    ),
    _behavior_case(
        name="arp-cache-flush-reply",
        description="Flush the neighbor cache, then validate a fresh who-has reply.",
        stimulus="arp_who_has",
        expected_response="arp_is_at",
        required_capabilities=_ARP_CAPABILITIES,
        protocol="arp",
        metadata={"layer": "link"},
    ),
    _behavior_case(
        name="arp-mac-validation",
        description=(
            "Validate that the reply Ethernet source and ARP sender hardware "
            "address both equal the target endpoint MAC."
        ),
        stimulus="arp_who_has",
        expected_response="arp_is_at",
        # The reply is validated against the target endpoint's MAC (provider
        # metadata), so the case requires provider_mac: MAC-less providers skip
        # with the stable requires_provider_mac reason.
        required_capabilities=_ARP_PROVIDER_MAC_CAPABILITIES,
        protocol="arp",
        metadata={"layer": "link"},
    ),
    _behavior_case(
        name="arp-spa-variation",
        description="Send a request from an alternate sender protocol address and validate the reply.",
        stimulus="arp_who_has",
        expected_response="arp_is_at",
        required_capabilities=_ARP_CAPABILITIES,
        protocol="arp",
        metadata={"layer": "link"},
    ),
    _behavior_case(
        name="arp-broadcast-filtered-capture",
        description=(
            "Capture ARP replies on a noisy segment and validate only the "
            "matching target reply."
        ),
        stimulus="arp_who_has",
        expected_response="arp_is_at",
        required_capabilities=_ARP_CAPABILITIES,
        protocol="arp",
        metadata={"layer": "link"},
    ),
)


# NDP (IPv6 Neighbor Discovery, RFC 4861) behavioral cases. NDP is the IPv6
# analog of ARP: a Neighbor Solicitation resolves an IPv6 address the way an ARP
# who-has resolves an IPv4 address, and the target kernel answers a solicited
# Neighbor Advertisement the way it answers an ARP is-at. The cases mirror the
# ARP set's stimulus/expected_response/required_capabilities shape; the
# ``layer`` metadata is ``network`` because NDP rides ICMPv6 over IPv6 (rather
# than directly over Ethernet like ARP). Providers that lack an IPv6 multicast
# link-layer substrate skip cleanly on ``_NDP_CAPABILITIES``.
BEHAVIOR_NDP_CASES: tuple[ProbeCase, ...] = (
    _behavior_case(
        name="ndp-neighbor-solicitation",
        description=(
            "Send a Neighbor Solicitation (ICMPv6 type 135) to the target's "
            "solicited-node multicast group and validate the kernel's solicited "
            "Neighbor Advertisement (type 136)."
        ),
        # The kernel NA-for-NS exchange is the direct analog of ARP who-has/is-at
        # and the single most reliable NDP behavior on a bare kernel: the target
        # kernel auto-answers a solicitation for an address it owns. This is the
        # PRIMARY reliable NDP case.
        stimulus="ndp_neighbor_solicitation",
        expected_response="ndp_neighbor_advertisement",
        required_capabilities=_NDP_CAPABILITIES,
        protocol="ndp",
        metadata={"layer": "network"},
    ),
    _behavior_case(
        name="ndp-router-solicitation",
        description=(
            "Send a Router Solicitation (ICMPv6 type 133) to the all-routers "
            "multicast group and validate a Router Advertisement (type 134)."
        ),
        # A Router Advertisement only arrives when the target acts as a router and
        # sends RAs (e.g. radvd / net.ipv6.conf.*.forwarding with RA emission). A
        # bare kernel that is not configured as a router does not answer a Router
        # Solicitation, so the live runners must configure the target as an
        # RA-emitting router for this case or skip it; the plan/notes record that
        # requirement. The dry-run plan is well-formed regardless.
        stimulus="ndp_router_solicitation",
        expected_response="ndp_router_advertisement",
        required_capabilities=_NDP_CAPABILITIES,
        protocol="ndp",
        metadata={
            "layer": "network",
            "requires_router_target": True,
            "notes": (
                "Needs the target to act as a router and emit Router "
                "Advertisements; a bare kernel does not answer a Router "
                "Solicitation. Live runners configure an RA-emitting router or "
                "skip this case."
            ),
        },
    ),
    _behavior_case(
        name="ndp-duplicate-address-detection",
        description=(
            "Send a Duplicate Address Detection Neighbor Solicitation from the "
            "unspecified source (::) for an address the target owns and validate "
            "the target's defending Neighbor Advertisement."
        ),
        # DAD probe: RFC 4861 section 4.3 / RFC 4862 — the solicitation source is
        # the unspecified address (::) and carries no Source Link-Layer Address
        # option; the target, which owns the tentative address, defends it with a
        # Neighbor Advertisement to the all-nodes multicast group.
        stimulus="ndp_duplicate_address_detection",
        expected_response="ndp_neighbor_advertisement",
        required_capabilities=_NDP_CAPABILITIES,
        protocol="ndp",
        metadata={
            "layer": "network",
            "dad": True,
            "notes": (
                "Unspecified-source (::) DAD solicitation with no SLLA option; "
                "the target defends an owned address with a Neighbor "
                "Advertisement (RFC 4861 section 4.3 / RFC 4862)."
            ),
        },
    ),
)


# Ten UDP behavioral cases (datagram echo/transform and kernel ICMP behavior
# against controlled UDP services bound to the target address).
BEHAVIOR_UDP_CASES: tuple[ProbeCase, ...] = (
    _behavior_case(
        name="udp-echo-empty",
        description="Echo an empty payload and validate the echoed response.",
        stimulus="udp_datagram",
        expected_response="udp_response",
        required_capabilities=_UDP_CAPABILITIES,
        protocol="udp",
    ),
    _behavior_case(
        name="udp-echo-short",
        description="Echo a short ASCII payload and validate the echoed response.",
        stimulus="udp_datagram",
        expected_response="udp_response",
        required_capabilities=_UDP_CAPABILITIES,
        protocol="udp",
    ),
    _behavior_case(
        name="udp-echo-binary",
        description="Echo a binary payload and validate the echoed response.",
        stimulus="udp_datagram",
        expected_response="udp_response",
        required_capabilities=_UDP_CAPABILITIES,
        protocol="udp",
    ),
    _behavior_case(
        name="udp-echo-large",
        description="Echo a large non-fragmenting payload and validate the response.",
        stimulus="udp_datagram",
        expected_response="udp_response",
        required_capabilities=_UDP_LARGE_CAPABILITIES,
        protocol="udp",
    ),
    _behavior_case(
        name="udp-source-port-reflection",
        description="Validate that the response reflects the source port.",
        stimulus="udp_datagram",
        expected_response="udp_response",
        required_capabilities=_UDP_CAPABILITIES,
        protocol="udp",
    ),
    _behavior_case(
        name="udp-multi-shot-order",
        description="Send multiple datagrams and validate ordered echoed responses.",
        stimulus="udp_datagram",
        expected_response="udp_response",
        required_capabilities=_UDP_CAPABILITIES,
        protocol="udp",
    ),
    _behavior_case(
        name="udp-closed-port-icmp",
        description="Send to a closed port and validate an ICMP port unreachable.",
        stimulus="udp_datagram",
        expected_response="icmp_port_unreachable",
        required_capabilities=_UDP_CAPABILITIES,
        protocol="udp",
    ),
    _behavior_case(
        name="udp-zero-checksum-ipv4",
        description=(
            "Send an IPv4 zero-checksum datagram and validate the response where the "
            "kernel accepts it."
        ),
        stimulus="udp_datagram",
        expected_response="udp_response",
        required_capabilities=_UDP_ZERO_CHECKSUM_IPV4_CAPABILITIES,
        protocol="udp",
    ),
    _behavior_case(
        name="udp-options-surplus-echo",
        description=(
            "Send a UDP options surplus datagram and validate the response where the "
            "kernel accepts it."
        ),
        stimulus="udp_datagram",
        expected_response="udp_response",
        required_capabilities=_UDP_OPTIONS_SURPLUS_CAPABILITIES,
        protocol="udp",
    ),
    _behavior_case(
        name="udp-length-boundary-echo",
        description="Echo a near-length-boundary payload and validate the response.",
        stimulus="udp_datagram",
        expected_response="udp_response",
        required_capabilities=_UDP_LARGE_CAPABILITIES,
        protocol="udp",
    ),
)


PROBE_CASES: tuple[ProbeCase, ...] = (
    ProbeCase(
        name="icmp-echo",
        description="Send ICMP echo request and validate echo reply from peer kernel.",
        stimulus="icmp_echo_request",
        expected_response="icmp_echo_reply",
        required_capabilities=["icmp_echo"],
        endpoint_roles=["stimulus", "target"],
        metadata={"protocol": "icmp", "service": "kernel"},
    ),
    ProbeCase(
        name="tcp-syn-open",
        description="Send TCP SYN to controlled listener and validate SYN/ACK.",
        stimulus="tcp_syn",
        expected_response="tcp_syn_ack",
        required_capabilities=["tcp_open_port"],
        endpoint_roles=["stimulus", "target"],
        metadata={"protocol": "tcp", "service": "controlled_listener"},
    ),
    ProbeCase(
        name="tcp-syn-closed",
        description="Send TCP SYN to closed port and validate RST response.",
        stimulus="tcp_syn",
        expected_response="tcp_rst",
        required_capabilities=["tcp_closed_port"],
        endpoint_roles=["stimulus", "target"],
        metadata={"protocol": "tcp", "service": "kernel"},
    ),
    ProbeCase(
        name="tcp-syn-options",
        description=(
            "Send a TCP SYN carrying a representative option set (MSS, Window "
            "Scale, SACK-Permitted, Timestamp, User Timeout) to a controlled "
            "listener and validate the SYN/ACK."
        ),
        stimulus="tcp_syn",
        expected_response="tcp_syn_ack",
        required_capabilities=["tcp_open_port"],
        endpoint_roles=["stimulus", "target"],
        metadata={"protocol": "tcp", "service": "controlled_listener"},
    ),
    ProbeCase(
        name="dns-query",
        description="Send DNS query to controlled DNS service and validate matching reply.",
        stimulus="dns_query",
        expected_response="dns_response",
        required_capabilities=["dns_service"],
        endpoint_roles=["stimulus", "target"],
        metadata={"protocol": "dns", "service": "controlled_dns"},
    ),
    ProbeCase(
        name="ttl-expired",
        description="Send low-TTL packet and validate ICMP TTL-expired from controlled hop.",
        stimulus="low_ttl_probe",
        expected_response="icmp_ttl_expired",
        required_capabilities=["controlled_router"],
        endpoint_roles=["stimulus", "router"],
        metadata={"protocol": "icmp", "service": "controlled_router"},
    ),
    ProbeCase(
        name="arp-resolution",
        description=(
            "Broadcast an ARP who-has request on the lab segment and validate the "
            "target's unicast is-at reply."
        ),
        stimulus="arp_who_has",
        expected_response="arp_is_at",
        required_capabilities=[
            "arp_resolution",
            "link_layer_send",
            "link_layer_capture",
            "broadcast",
        ],
        endpoint_roles=["stimulus", "target"],
        metadata={"protocol": "arp", "service": "kernel", "layer": "link"},
    ),
    *BEHAVIOR_DNS_CASES,
    *BEHAVIOR_DHCP_CASES,
    *BEHAVIOR_ARP_CASES,
    *BEHAVIOR_NDP_CASES,
    *BEHAVIOR_UDP_CASES,
)

PROBE_CASE_BY_NAME: dict[str, ProbeCase] = {case.name: case for case in PROBE_CASES}

ENDPOINT_ROLES: tuple[EndpointRole, ...] = (
    EndpointRole(
        role="stimulus",
        responsibilities=["send_probe", "capture_response", "validate_response"],
        capabilities=["raw_send", "packet_capture"],
    ),
    EndpointRole(
        role="target",
        responsibilities=["expose_kernel_behavior", "run_controlled_services"],
        capabilities=["kernel_reply", "tcp_listener", "dns_service"],
    ),
    EndpointRole(
        role="router",
        responsibilities=["emit_ttl_expired"],
        capabilities=["controlled_router"],
    ),
)


def known_case_names() -> tuple[str, ...]:
    """Return the sorted tuple of every case name in the catalog."""

    return tuple(sorted(PROBE_CASE_BY_NAME))


def case_by_name(name: str) -> ProbeCase:
    """Look up a single probe case by name.

    Raises ``ValueError`` with the stable available-case listing when the name
    is not part of the catalog.
    """

    try:
        return PROBE_CASE_BY_NAME[name]
    except KeyError:
        available = ", ".join(known_case_names())
        raise ValueError(
            f"unknown probe case {name!r}; available cases: {available}"
        ) from None


def case_name_filters(values: Sequence[str] | None) -> list[str]:
    """Normalize raw ``--case`` values into a de-duplicated, ordered list.

    Each value may be comma-separated; surrounding whitespace is stripped and
    empty fragments are dropped. Insertion order is preserved while removing
    duplicates so the resulting selection is deterministic.
    """

    if not values:
        return []
    names: list[str] = []
    for value in values:
        for raw_name in value.split(","):
            name = raw_name.strip()
            if name:
                names.append(name)
    return list(dict.fromkeys(names))


def selected_cases(case_names: Sequence[str]) -> list[ProbeCase]:
    """Resolve requested case names to catalog cases in requested order.

    With no requested names the full catalog is returned in declaration order.
    Any unknown name raises ``ValueError`` listing the available cases.
    """

    if not case_names:
        return list(PROBE_CASES)
    unknown = [name for name in case_names if name not in PROBE_CASE_BY_NAME]
    if unknown:
        available = ", ".join(known_case_names())
        raise ValueError(
            f"unknown probe case {unknown[0]!r}; available cases: {available}"
        )
    return [PROBE_CASE_BY_NAME[name] for name in case_names]


# Default profile. It samples the legacy ICMP/TCP/DNS/TTL/ARP catalog and keeps
# the historical default count, so existing smoke commands are unchanged.
DEFAULT_PROFILE = "smoke"
SMOKE_PROFILE = "smoke"
BEHAVIOR_PROFILE = "behavior"
TCP_SMOKE_PROFILE = "tcp-smoke"

# Legacy default count used by the smoke profile and any profile without an
# explicit default; preserves the pre-behavior-suite CLI behavior.
_LEGACY_DEFAULT_COUNT = 5

# The legacy ICMP/TCP/DNS/TTL/ARP cases the smoke profile samples. Pinning smoke
# to this set keeps its selection unchanged now that the catalog also carries the
# full behavioral case suite.
SMOKE_PROFILE_CASE_NAMES: tuple[str, ...] = (
    "icmp-echo",
    "tcp-syn-open",
    "tcp-syn-closed",
    "dns-query",
    "ttl-expired",
    "arp-resolution",
)

# The tcp-smoke profile samples a focused TCP-only set: a SYN carrying a
# representative option set (MSS/Window Scale/SACK-Permitted/Timestamp/User
# Timeout), plus the open- and closed-port SYN cases. It lets an agent inspect
# the intended TCP traffic -- including the materialized options -- before any
# provider-backed run, without pulling in the DNS/TTL/ARP smoke cases.
TCP_SMOKE_PROFILE_CASE_NAMES: tuple[str, ...] = (
    "tcp-syn-options",
    "tcp-syn-open",
    "tcp-syn-closed",
)

# The behavior profile selects the full DNS/DHCP/ARP/NDP/UDP behavioral catalog
# in a stable deterministic order: each protocol group in declaration order,
# grouped DNS -> DHCP -> ARP -> NDP -> UDP. The default count covers every case
# so a bare ``--profile behavior`` plans the complete suite.
BEHAVIOR_PROFILE_CASE_NAMES: tuple[str, ...] = tuple(
    case.name
    for group in (
        BEHAVIOR_DNS_CASES,
        BEHAVIOR_DHCP_CASES,
        BEHAVIOR_ARP_CASES,
        BEHAVIOR_NDP_CASES,
        BEHAVIOR_UDP_CASES,
    )
    for case in group
)


# Profiles that select an explicit ordered case subset. A profile not listed
# here selects the full catalog. ``smoke`` is pinned to the legacy case set so
# adding the behavioral catalog does not change what smoke samples.
_PROFILE_CASE_NAMES: dict[str, tuple[str, ...]] = {
    SMOKE_PROFILE: SMOKE_PROFILE_CASE_NAMES,
    BEHAVIOR_PROFILE: BEHAVIOR_PROFILE_CASE_NAMES,
    TCP_SMOKE_PROFILE: TCP_SMOKE_PROFILE_CASE_NAMES,
}

# Per-profile default counts used when no explicit ``--count`` is supplied. The
# behavior profile defaults to its full case suite; every other profile keeps the
# legacy default.
_PROFILE_DEFAULT_COUNTS: dict[str, int] = {
    BEHAVIOR_PROFILE: len(BEHAVIOR_PROFILE_CASE_NAMES),
}


def known_profiles() -> tuple[str, ...]:
    """Return the profiles that define an explicit case selection, sorted."""

    return tuple(sorted(_PROFILE_CASE_NAMES))


def profile_case_names(profile: str) -> tuple[str, ...] | None:
    """Return the ordered case names a profile selects, or ``None``.

    ``None`` means the profile does not constrain the selection and the full
    catalog is used (the smoke/legacy behavior).
    """

    return _PROFILE_CASE_NAMES.get(profile)


def profile_default_count(profile: str) -> int:
    """Return the default planned count for a profile.

    Profiles without an explicit default fall back to the legacy default count.
    """

    return _PROFILE_DEFAULT_COUNTS.get(profile, _LEGACY_DEFAULT_COUNT)


def profile_selected_cases(
    profile: str,
    case_names: Sequence[str],
) -> list[ProbeCase]:
    """Resolve the cases for a run from its profile and explicit case filters.

    Explicit ``--case`` filters always win so focused runs work under any
    profile. With no filters, a profile that defines a case subset selects it in
    declaration order; otherwise the full catalog is returned (smoke/legacy).
    """

    if case_names:
        return selected_cases(case_names)
    profile_names = profile_case_names(profile)
    if profile_names is None:
        return selected_cases([])
    return selected_cases(list(profile_names))
