"""Probe behavioral case catalog and lookup helpers.

This module owns the canonical :class:`ProbeCase` catalog, the endpoint role
definitions, and the helpers that turn requested case-name filters into a stable
ordered selection of cases. Keeping the catalog here gives the behavioral suite
a single place to grow without enlarging the CLI orchestration module.
"""

from __future__ import annotations

from collections.abc import Sequence

from .case_helpers import _behavior_case, case_name_filters
from .model import EndpointRole, ProbeCase
# Importing from the ``protocols`` package runs its auto-discovery so every
# migrated protocol module self-registers into ``PROTOCOL_REGISTRY`` before the
# case catalog and profile tables are assembled below. No protocol is migrated
# yet, so the registry contribution is empty and the merged catalog/profiles are
# byte-identical to the legacy aggregation. Imports stay relative; the package
# autodiscovers ``__name__``-relatively, so this does not cycle back through
# ``cases``.
from .protocols import (
    all_cases as _registry_cases,
    all_profile_counts as _registry_profile_counts,
)
# Re-import the IGMP case tuple from the IGMP plugin so ``cases.IGMP_PROBE_CASES``
# stays resolvable for the catalog tests (the cases themselves reach the merged
# catalog through the registry; this is a back-compat re-export only).
from .protocols.igmp import (  # noqa: F401  (re-exported for back-compat)
    IGMP_PROBE_CASES,
)


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
# DNS's, DHCP's, and UDP's capability constants and case tuples now live in their
# plugin modules (``protocols/dns.py``, ``protocols/dhcp.py``,
# ``protocols/udp.py``); the merged catalog/profile tables below pick those cases
# up from the registry. ``UDP_ECHO_LARGE_PAYLOAD_LENGTH`` stays here because
# :mod:`tools.probe.engine.lab` also reads it; the UDP plugin imports it lazily.
# BGP's capability constant (``_BGP_CAPABILITIES``) and case tuple now live in
# the BGP plugin module (``protocols/bgp.py``); the merged catalog/profile tables
# below pick the BGP case up from the registry.
# RIP's capability constant (``_RIP_CAPABILITIES``) and case tuple now live in
# the RIP plugin module (``protocols/rip.py``); the merged catalog/profile tables
# below pick the RIP/RIPng cases up from the registry.
# IGMP's capability constant (``_IGMP_CAPABILITIES``) and case tuple now live in
# the IGMP plugin module (``protocols/igmp.py``); the merged catalog/profile
# tables below pick the IGMP cases up from the registry. ``IGMP_PROBE_CASES`` is
# re-imported below so ``cases.IGMP_PROBE_CASES`` stays resolvable for the catalog
# tests.
# ARP's capability constants and case tuple now live in the ARP plugin module
# (``protocols/arp.py``); NDP's capability constant and case tuple now live in
# the NDP plugin module (``protocols/ndp.py``); the merged catalog/profile tables
# below pick those cases up from the registry.

# IPSec's capability constants (``_IPSEC_ESP_CAPABILITIES`` /
# ``_IPSEC_AH_CAPABILITIES`` / ``_IKEV2_CAPABILITIES`` and the aggregate
# ``_IPSEC_CAPABILITIES`` alias) and the four IPSec behavioral cases now live in
# the IPSec plugin module (``protocols/ipsec.py``); the merged catalog/profile
# tables below pick those cases up from the registry.

# OSPF's capability constant (``_OSPF_CAPABILITIES``) and the two OSPF behavioral
# cases now live in the OSPF plugin module (``protocols/ospf.py``); the merged
# catalog/profile tables source the OSPF cases from the registry.


# NDP's capability constant and the three NDP behavioral cases now live in the
# NDP plugin module (``protocols/ndp.py``); the merged catalog/profile tables
# below pick the NDP cases up from the registry.


# The BGP smoke case (``bgp-session-smoke``) now lives in the BGP plugin module
# (``protocols/bgp.py``); the merged catalog/profile tables below pick it up from
# the registry.


# The RIP smoke cases (``rip-update-v2`` / ``ripng-update``) now live in the RIP
# plugin module (``protocols/rip.py``); the merged catalog/profile tables below
# pick them up from the registry.


# The IGMP behavior cases (``igmp-membership-query-observation`` /
# ``igmp-v2-membership-report-emission`` / ``igmp-v2-leave-group-emission`` /
# ``igmp-v3-source-list-report``) now live in the IGMP plugin module
# (``protocols/igmp.py``); the merged catalog/profile tables below pick them up
# from the registry, and ``IGMP_PROBE_CASES`` is re-imported above for back-compat.


# The four IPSec behavioral cases (``esp-transport-echo`` / ``esp-tunnel-echo`` /
# ``ah-transport-verify`` / ``ikev2-sa-init``) now live in the IPSec plugin module
# (``protocols/ipsec.py``); the merged catalog/profile tables below pick them up
# from the registry.


# OSPFv2's behavioral cases (RFC 2328) -- the live-capable ``ospf-hello-exchange``
# and the planned-only ``ospf-dd-exchange`` -- and their ``_OSPF_CAPABILITIES``
# constant now live in the OSPF plugin module (``protocols/ospf.py``); the merged
# catalog below contributes them through the registry.


# The legacy per-protocol case aggregation: the seven inline ICMP/TCP/DNS/TTL/ARP
# cases followed by the behavioral ``BEHAVIOR_*``/smoke case tuples in declaration
# order. The registry-aware ``PROBE_CASES`` below merges this with the registry's
# contributed cases; until a protocol migrates the registry is empty and the
# merged catalog is byte-identical to this tuple.
_LEGACY_PROBE_CASES: tuple[ProbeCase, ...] = (
    # The inline ``icmp-echo`` smoke case (and the ``ttl-expired`` case) are now
    # contributed by the ICMP plugin (``protocols/icmp.py``) and merged in ahead
    # of this legacy aggregation by ``_merge_probe_cases``.
    # The inline ``tcp-syn-open`` / ``tcp-syn-closed`` smoke cases and the
    # ``tcp-syn-options`` case are now contributed by the TCP plugin
    # (``protocols/tcp.py``) and merged in ahead of this legacy aggregation by
    # ``_merge_probe_cases``.
    # The inline ``dns-query`` smoke case is contributed by the DNS plugin
    # (``protocols/dns.py``) and merged in ahead of this legacy aggregation by
    # ``_merge_probe_cases``.
    # The inline ``icmp-echo`` and ``ttl-expired`` cases are contributed by the
    # ICMP plugin (``protocols/icmp.py``) and merged in ahead of this legacy
    # aggregation by ``_merge_probe_cases``.
    # The inline ``arp-resolution`` smoke case and the ten ARP behavioral cases
    # are contributed by the ARP plugin (``protocols/arp.py``); the inline
    # ``dns-query`` smoke case and the ten DNS behavioral cases are contributed
    # by the DNS plugin (``protocols/dns.py``); the ten DHCP behavioral cases are
    # contributed by the DHCP plugin (``protocols/dhcp.py``); the three NDP
    # behavioral cases are contributed by the NDP plugin (``protocols/ndp.py``);
    # the ten UDP behavioral cases are contributed by the UDP plugin
    # (``protocols/udp.py``). All are merged in ahead of this legacy aggregation
    # by ``_merge_probe_cases``.
    # The ``ospf-hello-exchange`` / ``ospf-dd-exchange`` cases are contributed by
    # the OSPF plugin (``protocols/ospf.py``) and merged in ahead of this legacy
    # aggregation by ``_merge_probe_cases``.
    # The ``bgp-session-smoke`` case is contributed by the BGP plugin
    # (``protocols/bgp.py``); the ``rip-update-v2`` / ``ripng-update`` cases are
    # contributed by the RIP plugin (``protocols/rip.py``). Both are merged in
    # ahead of this legacy aggregation by ``_merge_probe_cases``.
    # The four IGMP cases are contributed by the IGMP plugin
    # (``protocols/igmp.py``) and merged in ahead of this legacy aggregation by
    # ``_merge_probe_cases``.
    # The four IPSec cases are contributed by the IPSec plugin
    # (``protocols/ipsec.py``) and merged in ahead of this legacy aggregation by
    # ``_merge_probe_cases``. Every protocol's cases now come from the registry,
    # so this legacy aggregation is empty.
)


def _merge_probe_cases() -> tuple[ProbeCase, ...]:
    """Merge the registry's contributed cases ahead of the legacy aggregation.

    Registry-contributed cases come first (in sorted-plugin / declaration
    order), then the legacy per-protocol and inline cases, deduped by case name
    with the registry taking precedence. Until a protocol migrates the registry
    is empty, so the merge yields ``_LEGACY_PROBE_CASES`` byte-identically and
    the snapshot-pinned generated plans (and profile selection order) are
    unchanged.
    """

    merged: list[ProbeCase] = []
    seen: set[str] = set()
    for case in (*_registry_cases(), *_LEGACY_PROBE_CASES):
        if case.name in seen:
            continue
        seen.add(case.name)
        merged.append(case)
    return tuple(merged)


# Registry-first case catalog. The registry contribution (empty until a protocol
# migrates) takes precedence; the legacy aggregation fills every case no plugin
# owns yet, preserving declaration order where ordering is observable.
PROBE_CASES: tuple[ProbeCase, ...] = _merge_probe_cases()

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
BGP_SESSION_PROFILE = "bgp-smoke"
RIP_SMOKE_PROFILE = "rip-smoke"
OSPF_SMOKE_PROFILE = "ospf-smoke"
IGMP_PROFILE = "igmp"
IPSEC_PROFILE = "ipsec"

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

# The ten DNS behavioral case names, in declaration order, sourced from the DNS
# plugin's registered cases (the ``dns-query`` smoke case is excluded -- it
# rides the smoke profile, not the behavior profile). DNS's profile membership
# stays in these legacy ordered tables (rather than the plugin's
# ``profile_counts``) so the behavior/smoke selection order is byte-identical:
# the registry-first profile merge would otherwise move DNS to the front of
# those profiles.
_DNS_BEHAVIOR_CASE_NAMES: tuple[str, ...] = tuple(
    case.name
    for case in _registry_cases()
    if case.metadata.get("protocol") == "dns" and case.name != "dns-query"
)

# The ten DHCP behavioral case names, in declaration order, sourced from the
# DHCP plugin's registered cases. DHCP's profile membership stays in these legacy
# ordered tables (rather than the plugin's ``profile_counts``) so the behavior
# selection order is byte-identical: the registry-first profile merge would
# otherwise move DHCP to the front of the behavior profile.
_DHCP_BEHAVIOR_CASE_NAMES: tuple[str, ...] = tuple(
    case.name
    for case in _registry_cases()
    if case.metadata.get("protocol") == "dhcp"
)

# The ten ARP behavioral case names, in declaration order, sourced from the ARP
# plugin's registered cases (the ``arp-resolution`` smoke case is excluded -- it
# rides the smoke profile, not the behavior profile). ARP's profile membership
# stays in these legacy ordered tables (rather than the plugin's
# ``profile_counts``) so the behavior/smoke selection order is byte-identical:
# the registry-first profile merge would otherwise move ARP to the front of
# those profiles.
_ARP_BEHAVIOR_CASE_NAMES: tuple[str, ...] = tuple(
    case.name
    for case in _registry_cases()
    if case.metadata.get("protocol") == "arp" and case.name != "arp-resolution"
)

# The three NDP behavioral case names, in declaration order, sourced from the NDP
# plugin's registered cases. NDP's profile membership stays in these legacy
# ordered tables (rather than the plugin's ``profile_counts``) so the behavior
# selection order is byte-identical: the registry-first profile merge would
# otherwise move NDP to the front of the behavior profile.
_NDP_BEHAVIOR_CASE_NAMES: tuple[str, ...] = tuple(
    case.name
    for case in _registry_cases()
    if case.metadata.get("protocol") == "ndp"
)

# The ten UDP behavioral case names, in declaration order, sourced from the UDP
# plugin's registered cases. UDP's profile membership stays in these legacy
# ordered tables (rather than the plugin's ``profile_counts``) so the behavior
# selection order is byte-identical: the registry-first profile merge would
# otherwise move UDP to the front of the behavior profile.
_UDP_BEHAVIOR_CASE_NAMES: tuple[str, ...] = tuple(
    case.name
    for case in _registry_cases()
    if case.metadata.get("protocol") == "udp"
)

# The single live-capable OSPF case name (``ospf-hello-exchange``), sourced from
# the OSPF plugin's registered cases. Only the OSPF case that is *not*
# ``planned_only`` rides the live ``behavior`` profile; the planned-only
# ``ospf-dd-exchange`` is excluded here (it lives in the dry-run ``ospf-smoke``
# profile below). OSPF's profile membership stays in these legacy ordered tables
# (rather than the plugin's ``profile_counts``) so the behavior selection order
# is byte-identical: the registry-first profile merge would otherwise move OSPF
# to the front of the behavior profile.
_OSPF_BEHAVIOR_CASE_NAMES: tuple[str, ...] = tuple(
    case.name
    for case in _registry_cases()
    if case.metadata.get("protocol") == "ospf"
    and not case.metadata.get("planned_only")
)

# The planned-only OSPF case names (currently ``ospf-dd-exchange``), sourced from
# the OSPF plugin's registered cases. These ride the dry-run ``ospf-smoke``
# profile, never the live ``behavior`` profile.
_OSPF_SMOKE_CASE_NAMES: tuple[str, ...] = tuple(
    case.name
    for case in _registry_cases()
    if case.metadata.get("protocol") == "ospf"
    and case.metadata.get("planned_only")
)

# The behavior profile selects the full DNS/DHCP/ARP/NDP/UDP behavioral catalog
# plus the live-capable OSPF case in a stable deterministic order: each protocol
# group in declaration order, grouped DNS -> DHCP -> ARP -> NDP -> UDP -> OSPF.
# Only the live-routable OSPF case (``ospf-hello-exchange``, sourced into
# ``_OSPF_BEHAVIOR_CASE_NAMES``) is included; the planned-only ``ospf-dd-exchange``
# sits in the dry-run ``ospf-smoke`` profile so the behavior profile stays fully
# live-routable. The default count covers every case so a bare
# ``--profile behavior`` plans the complete suite.
BEHAVIOR_PROFILE_CASE_NAMES: tuple[str, ...] = (
    *_DNS_BEHAVIOR_CASE_NAMES,
    *_DHCP_BEHAVIOR_CASE_NAMES,
    *_ARP_BEHAVIOR_CASE_NAMES,
    *_NDP_BEHAVIOR_CASE_NAMES,
    *_UDP_BEHAVIOR_CASE_NAMES,
    *_OSPF_BEHAVIOR_CASE_NAMES,
)

# The ipsec profile selects the IPSec behavioral catalog (ESP transport/tunnel,
# AH transport, IKE_SA_INIT) in declaration order. It is kept out of the general
# ``behavior`` profile because the cases need an IPSec-capable peer that holds
# the matching Security Association (or an IKE responder), so an agent inspects
# the planned IPSec exchange in isolation before any provider-backed run. The
# default count covers every case so a bare ``--profile ipsec`` plans the whole
# IPSec suite. The case names are sourced from the IPSec plugin's registered
# cases; IPSec's profile membership stays in this legacy ordered table (rather
# than the plugin's ``profile_counts``) so the selection order is byte-identical
# -- the registry-first profile merge would otherwise move IPSec to the front of
# the profile.
IPSEC_PROFILE_CASE_NAMES: tuple[str, ...] = tuple(
    case.name
    for case in _registry_cases()
    if case.metadata.get("protocol") == "ipsec"
)

# The BGP smoke profile plans the probe-owned FRR peer target service and the
# bgp_session stimulus driver intent without asking lab to infer workload
# metadata from the profile label. The BGP case name is sourced from the BGP
# plugin's registered case; BGP's profile membership stays in this legacy ordered
# table (rather than the plugin's ``profile_counts``) so the selection order is
# byte-identical -- the registry-first profile merge would otherwise move BGP to
# the front of the profile.
BGP_SESSION_PROFILE_CASE_NAMES: tuple[str, ...] = tuple(
    case.name
    for case in _registry_cases()
    if case.metadata.get("protocol") == "bgp"
)

# The RIP smoke profile plans the probe-owned FRR ripd target service and the
# RIP stimulus driver intent without asking lab to infer workload metadata from
# the profile label. The RIP/RIPng case names are sourced from the RIP plugin's
# registered cases in declaration order (``rip-update-v2`` then ``ripng-update``);
# RIP's profile membership stays in this legacy ordered table (rather than the
# plugin's ``profile_counts``) so the selection order is byte-identical -- the
# registry-first profile merge would otherwise move RIP to the front of the
# profile.
RIP_SMOKE_PROFILE_CASE_NAMES: tuple[str, ...] = tuple(
    case.name
    for case in _registry_cases()
    if case.metadata.get("protocol") in ("rip", "ripng")
)

# The OSPF smoke profile carries the planned-only OSPF cases (currently the
# Database Description exchange). They plan in dry-run but have no live adapter
# arm yet, so they are kept out of the live ``behavior`` profile -- the way
# ``bgp-session-smoke`` lives in ``bgp-smoke`` -- and selected here for an
# isolated dry-run plan until their adapter dispatch arm lands. The case names
# are sourced from the OSPF plugin's registered planned-only cases; OSPF's
# profile membership stays in this legacy ordered table (rather than the plugin's
# ``profile_counts``) so the selection order is byte-identical.
OSPF_SMOKE_PROFILE_CASE_NAMES: tuple[str, ...] = _OSPF_SMOKE_CASE_NAMES

# The focused ``igmp`` profile selects the four IGMP cases in declaration order.
# The case names are sourced from the IGMP plugin's registered cases; IGMP's
# profile membership stays in this legacy ordered table (rather than the plugin's
# ``profile_counts``) so the selection order is byte-identical -- the
# registry-first profile merge would otherwise move IGMP to the front of the
# profile.
IGMP_PROFILE_CASE_NAMES: tuple[str, ...] = tuple(
    case.name
    for case in _registry_cases()
    if case.metadata.get("protocol") == "igmp"
)


# Legacy profiles that select an explicit ordered case subset. A profile not
# listed here selects the full catalog. ``smoke`` is pinned to the legacy case
# set so adding the behavioral catalog does not change what smoke samples. The
# registry-aware tables below merge this with each plugin's ``profile_counts``
# contribution; until a protocol migrates the registry is empty and the merged
# tables are byte-identical to these.
_LEGACY_PROFILE_CASE_NAMES: dict[str, tuple[str, ...]] = {
    SMOKE_PROFILE: SMOKE_PROFILE_CASE_NAMES,
    BEHAVIOR_PROFILE: BEHAVIOR_PROFILE_CASE_NAMES,
    TCP_SMOKE_PROFILE: TCP_SMOKE_PROFILE_CASE_NAMES,
    BGP_SESSION_PROFILE: BGP_SESSION_PROFILE_CASE_NAMES,
    RIP_SMOKE_PROFILE: RIP_SMOKE_PROFILE_CASE_NAMES,
    OSPF_SMOKE_PROFILE: OSPF_SMOKE_PROFILE_CASE_NAMES,
    IGMP_PROFILE: IGMP_PROFILE_CASE_NAMES,
    IPSEC_PROFILE: IPSEC_PROFILE_CASE_NAMES,
}

# Per-profile default counts used when no explicit ``--count`` is supplied. The
# behavior and ipsec profiles default to their full case suites; every other
# profile keeps the legacy default.
_LEGACY_PROFILE_DEFAULT_COUNTS: dict[str, int] = {
    BEHAVIOR_PROFILE: len(BEHAVIOR_PROFILE_CASE_NAMES),
    BGP_SESSION_PROFILE: len(BGP_SESSION_PROFILE_CASE_NAMES),
    RIP_SMOKE_PROFILE: len(RIP_SMOKE_PROFILE_CASE_NAMES),
    OSPF_SMOKE_PROFILE: len(OSPF_SMOKE_PROFILE_CASE_NAMES),
    IGMP_PROFILE: len(IGMP_PROFILE_CASE_NAMES),
    IPSEC_PROFILE: len(IPSEC_PROFILE_CASE_NAMES),
}


def _merge_profile_case_names() -> dict[str, tuple[str, ...]]:
    """Union the registry's profile membership with the legacy profile tables.

    Each plugin contributes ``profile_counts`` as ``{profile: {case_name:
    count}}``; the registry's case names for a profile come first (registry
    precedence), then the legacy ordered case names, deduped. Until a protocol
    migrates the registry is empty, so the merge reproduces
    ``_LEGACY_PROFILE_CASE_NAMES`` byte-identically and the profile selection
    order is unchanged.
    """

    registry_counts = _registry_profile_counts()
    profiles = [*_LEGACY_PROFILE_CASE_NAMES]
    for profile in registry_counts:
        if profile not in _LEGACY_PROFILE_CASE_NAMES:
            profiles.append(profile)

    merged: dict[str, tuple[str, ...]] = {}
    for profile in profiles:
        ordered: list[str] = []
        seen: set[str] = set()
        for case_name in (
            *registry_counts.get(profile, {}),
            *_LEGACY_PROFILE_CASE_NAMES.get(profile, ()),
        ):
            if case_name in seen:
                continue
            seen.add(case_name)
            ordered.append(case_name)
        merged[profile] = tuple(ordered)
    return merged


def _merge_profile_default_counts() -> dict[str, int]:
    """Union the registry's default counts with the legacy default counts.

    A plugin's ``profile_counts`` per-case entries sum into the profile's
    registry-contributed default; that sum is added to the legacy default count
    so several protocols can grow one profile's default. Until a protocol
    migrates the registry is empty and this reproduces
    ``_LEGACY_PROFILE_DEFAULT_COUNTS`` byte-identically.
    """

    registry_counts = _registry_profile_counts()
    merged: dict[str, int] = dict(_LEGACY_PROFILE_DEFAULT_COUNTS)
    for profile, contribution in registry_counts.items():
        merged[profile] = merged.get(profile, 0) + sum(contribution.values())
    return merged


# Registry-first profile tables. The registry contribution (empty until a
# protocol migrates) is unioned with the legacy profile membership and default
# counts, preserving selection order and counts where they are observable.
_PROFILE_CASE_NAMES: dict[str, tuple[str, ...]] = _merge_profile_case_names()
_PROFILE_DEFAULT_COUNTS: dict[str, int] = _merge_profile_default_counts()


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
