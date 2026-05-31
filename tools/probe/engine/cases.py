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
# link-layer (Ethernet/broadcast) substrate. The capability names match the
# probe capability derivation in :mod:`tools.probe.engine.lab`, so the
# behavior-suite cases skip with stable reasons on providers that cannot support
# them. Full per-case stimulus/validation wiring lands in the later per-case
# steps; here the cases route through the planned-only dispatcher fallback.
_DNS_CAPABILITIES = ["dns_service"]
_DHCP_CAPABILITIES = ["dhcp_service"]
_UDP_CAPABILITIES = ["udp_service"]
_ARP_CAPABILITIES = [
    "arp_resolution",
    "link_layer_send",
    "link_layer_capture",
    "broadcast",
]


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
        name="dhcp-clientid-offer",
        description="Send a Discover with a client id and validate the matching Offer.",
        stimulus="dhcp_discover",
        expected_response="dhcp_offer",
        required_capabilities=_DHCP_CAPABILITIES,
        protocol="dhcp",
    ),
    _behavior_case(
        name="dhcp-hostname-offer",
        description="Send a Discover with a hostname option and validate the Offer.",
        stimulus="dhcp_discover",
        expected_response="dhcp_offer",
        required_capabilities=_DHCP_CAPABILITIES,
        protocol="dhcp",
    ),
    _behavior_case(
        name="dhcp-paramreq-options",
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
        name="dhcp-lease-timing",
        description="Send a Discover and validate lease and renewal timing options.",
        stimulus="dhcp_discover",
        expected_response="dhcp_offer",
        required_capabilities=_DHCP_CAPABILITIES,
        protocol="dhcp",
    ),
    _behavior_case(
        name="dhcp-renew-unicast-ack",
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
        name="dhcp-invalid-addr-nak",
        description="Request an invalid address and validate the Nak.",
        stimulus="dhcp_request",
        expected_response="dhcp_nak",
        required_capabilities=_DHCP_CAPABILITIES,
        protocol="dhcp",
    ),
    _behavior_case(
        name="dhcp-repeated-discover",
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
        name="arp-who-has-is-at",
        description="Broadcast a who-has request and validate the is-at reply.",
        stimulus="arp_who_has",
        expected_response="arp_is_at",
        required_capabilities=_ARP_CAPABILITIES,
        protocol="arp",
        metadata={"layer": "link"},
    ),
    _behavior_case(
        name="arp-repeated-who-has",
        description="Repeat a who-has request and validate two parseable replies.",
        stimulus="arp_who_has",
        expected_response="arp_is_at",
        required_capabilities=_ARP_CAPABILITIES,
        protocol="arp",
        metadata={"layer": "link"},
    ),
    _behavior_case(
        name="arp-preserve-sender-pa",
        description="Validate that the reply preserves the sender protocol address.",
        stimulus="arp_who_has",
        expected_response="arp_is_at",
        required_capabilities=_ARP_CAPABILITIES,
        protocol="arp",
        metadata={"layer": "link"},
    ),
    _behavior_case(
        name="arp-target-alias",
        description="Query a target alias address and validate the reply.",
        stimulus="arp_who_has",
        expected_response="arp_is_at",
        required_capabilities=_ARP_CAPABILITIES,
        protocol="arp",
        metadata={"layer": "link"},
    ),
    _behavior_case(
        name="arp-unicast-request",
        description="Send a unicast ARP request and validate the reply.",
        stimulus="arp_who_has",
        expected_response="arp_is_at",
        required_capabilities=_ARP_CAPABILITIES,
        protocol="arp",
        metadata={"layer": "link"},
    ),
    _behavior_case(
        name="arp-padded-request",
        description="Send a request with Ethernet padding and validate the reply.",
        stimulus="arp_who_has",
        expected_response="arp_is_at",
        required_capabilities=_ARP_CAPABILITIES,
        protocol="arp",
        metadata={"layer": "link"},
    ),
    _behavior_case(
        name="arp-after-cache-flush",
        description="Validate a reply after a neighbor cache flush.",
        stimulus="arp_who_has",
        expected_response="arp_is_at",
        required_capabilities=_ARP_CAPABILITIES,
        protocol="arp",
        metadata={"layer": "link"},
    ),
    _behavior_case(
        name="arp-reply-mac-matches",
        description="Validate that the reply sender MAC matches the target MAC.",
        stimulus="arp_who_has",
        expected_response="arp_is_at",
        required_capabilities=_ARP_CAPABILITIES,
        protocol="arp",
        metadata={"layer": "link"},
    ),
    _behavior_case(
        name="arp-alt-sender-pa",
        description="Send a request from an alternate sender protocol address and validate the reply.",
        stimulus="arp_who_has",
        expected_response="arp_is_at",
        required_capabilities=_ARP_CAPABILITIES,
        protocol="arp",
        metadata={"layer": "link"},
    ),
    _behavior_case(
        name="arp-capture-filter-match",
        description="Validate that capture filtering accepts only the matching target reply.",
        stimulus="arp_who_has",
        expected_response="arp_is_at",
        required_capabilities=_ARP_CAPABILITIES,
        protocol="arp",
        metadata={"layer": "link"},
    ),
)


# Ten UDP behavioral cases (datagram echo/transform and kernel ICMP behavior
# against controlled UDP services bound to the target address).
BEHAVIOR_UDP_CASES: tuple[ProbeCase, ...] = (
    _behavior_case(
        name="udp-empty-echo",
        description="Echo an empty payload and validate the echoed response.",
        stimulus="udp_datagram",
        expected_response="udp_response",
        required_capabilities=_UDP_CAPABILITIES,
        protocol="udp",
    ),
    _behavior_case(
        name="udp-short-ascii-echo",
        description="Echo a short ASCII payload and validate the echoed response.",
        stimulus="udp_datagram",
        expected_response="udp_response",
        required_capabilities=_UDP_CAPABILITIES,
        protocol="udp",
    ),
    _behavior_case(
        name="udp-binary-echo",
        description="Echo a binary payload and validate the echoed response.",
        stimulus="udp_datagram",
        expected_response="udp_response",
        required_capabilities=_UDP_CAPABILITIES,
        protocol="udp",
    ),
    _behavior_case(
        name="udp-large-nofragment-echo",
        description="Echo a large non-fragmenting payload and validate the response.",
        stimulus="udp_datagram",
        expected_response="udp_response",
        required_capabilities=_UDP_CAPABILITIES,
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
        name="udp-multishot-ordered-echo",
        description="Send multiple datagrams and validate ordered echoed responses.",
        stimulus="udp_datagram",
        expected_response="udp_response",
        required_capabilities=_UDP_CAPABILITIES,
        protocol="udp",
    ),
    _behavior_case(
        name="udp-closed-port-unreachable",
        description="Send to a closed port and validate an ICMP port unreachable.",
        stimulus="udp_datagram",
        expected_response="icmp_port_unreachable",
        required_capabilities=_UDP_CAPABILITIES,
        protocol="udp",
    ),
    _behavior_case(
        name="udp-zero-checksum",
        description=(
            "Send an IPv4 zero-checksum datagram and validate the response where the "
            "kernel accepts it."
        ),
        stimulus="udp_datagram",
        expected_response="udp_response",
        required_capabilities=_UDP_CAPABILITIES,
        protocol="udp",
    ),
    _behavior_case(
        name="udp-options-surplus",
        description=(
            "Send a UDP options surplus datagram and validate the response where the "
            "kernel accepts it."
        ),
        stimulus="udp_datagram",
        expected_response="udp_response",
        required_capabilities=_UDP_CAPABILITIES,
        protocol="udp",
    ),
    _behavior_case(
        name="udp-length-boundary-echo",
        description="Echo a near-length-boundary payload and validate the response.",
        stimulus="udp_datagram",
        expected_response="udp_response",
        required_capabilities=_UDP_CAPABILITIES,
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

# Legacy default count used by the smoke profile and any profile without an
# explicit default; preserves the pre-behavior-suite CLI behavior.
_LEGACY_DEFAULT_COUNT = 5

# The legacy ICMP/TCP/DNS/TTL/ARP cases the smoke profile samples. Pinning smoke
# to this set keeps its selection unchanged now that the catalog also carries the
# forty behavioral cases.
SMOKE_PROFILE_CASE_NAMES: tuple[str, ...] = (
    "icmp-echo",
    "tcp-syn-open",
    "tcp-syn-closed",
    "dns-query",
    "ttl-expired",
    "arp-resolution",
)

# The behavior profile selects the full DNS/DHCP/ARP/UDP behavioral catalog in a
# stable deterministic order: each protocol group in declaration order, grouped
# DNS -> DHCP -> ARP -> UDP. The default count covers all forty cases so a bare
# ``--profile behavior`` plans the complete suite.
BEHAVIOR_PROFILE_CASE_NAMES: tuple[str, ...] = tuple(
    case.name
    for group in (
        BEHAVIOR_DNS_CASES,
        BEHAVIOR_DHCP_CASES,
        BEHAVIOR_ARP_CASES,
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
}

# Per-profile default counts used when no explicit ``--count`` is supplied. The
# behavior profile defaults to its full forty-case suite; every other profile
# keeps the legacy default.
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
