"""Probe behavioral case catalog and lookup helpers.

This module owns the canonical :class:`ProbeCase` catalog, the endpoint role
definitions, and the helpers that turn requested case-name filters into a stable
ordered selection of cases. Keeping the catalog here gives the behavioral suite
a single place to grow without enlarging the CLI orchestration module.
"""

from __future__ import annotations

from collections.abc import Sequence

from .model import EndpointRole, ProbeCase


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
