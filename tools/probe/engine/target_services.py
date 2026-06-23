"""Probe target service planning, setup scripts, and cleanup.

The probe target endpoint exposes controlled, disposable services and kernel
behavior the stimulus endpoint exercises. This module owns:

- the dry-run/live ``target_service_setup`` plan,
- typed service descriptors for the DNS responder, DHCP responder, UDP
  responder, FRR BGP peer, ARP alias/sysctl setup, and closed UDP port
  validation,
- the deterministic, artifact-producing setup script for the live target,
- the cleanup script invocation that tears those services down.

Keeping the target-service surface here lets the behavior suite grow DNS, DHCP,
UDP, and ARP target setup in one place without enlarging the CLI orchestration
module. The lab-wire transport helpers stay in :mod:`cli`; the wire setup and
cleanup entry points accept them so this module has no import cycle with the
CLI.

The service descriptors are pure, deterministic data: each describes one
controlled service the live setup script must stand up (or one piece of kernel
state it must verify) and the cleanup commands that dispose of it. They make the
target contract inspectable from agent code and from dry-run reports without
running anything.
"""

from __future__ import annotations

import json
import posixpath
import shlex
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from .capabilities import (
    SKIP_REQUIRES_CONTROLLED_ROUTER,
    SKIP_REQUIRES_CONTROLLED_SERVICE,
    SKIP_REQUIRES_LINK_LAYER,
)
from .lab import TARGET_ROLE
from .model import JSONObject, JSONValue, json_object

# Importing from the ``protocols`` package runs its auto-discovery so every
# migrated protocol module self-registers into ``PROTOCOL_REGISTRY`` before the
# target-service setup plan and setup script consult it below. Imports stay
# relative; the package autodiscovers ``__name__``-relatively, so this does not
# cycle back through ``target_services``.
from .protocols import PROTOCOL_REGISTRY, registered_plugins

# ARP's target-service descriptors, kernel case set, plan/script helpers, and the
# setup-script block were migrated into the ARP plugin
# (:mod:`tools.probe.engine.protocols.arp`). They are re-imported here so
# ``target_services.arp_*`` / ``target_services._ARP_KERNEL_CASES`` keep
# resolving (the behavior/script tests and ``__all__`` reference them), and so
# ``target_service_setup_script`` can render the ARP setup block. The ARP plugin
# module does not import ``target_services``, so this does not cycle.
from .protocols.arp import (
    _ARP_KERNEL_CASES,
    arp_alias_descriptor,
    arp_decoy_events,
    arp_extra_addresses,
    arp_kernel_state_plan,
    arp_probe_plans,
    arp_sysctl_descriptor,
    arp_target_setup_lines,
)

# DNS's target-service descriptor, responder case set, plan selector, and the
# setup-script blocks were migrated into the DNS plugin
# (:mod:`tools.probe.engine.protocols.dns`). They are re-imported here so
# ``target_services.dns_responder_descriptor`` / ``target_services._DNS_RESPONDER_CASES``
# / ``target_services.dns_probe_plans`` keep resolving (the behavior/script tests,
# ``prepare_wire_probe_target``, and ``__all__`` reference them), and so
# ``target_service_setup_script`` can render the DNS setup blocks. The DNS plugin
# module does not import ``target_services``, so this does not cycle.
from .protocols.dns import (
    _DNS_RESPONDER_CASES,
    dns_port_check_lines,
    dns_probe_plans,
    dns_responder_descriptor,
    dns_responder_setup_lines,
)
from .target_service_helpers import (
    KernelStateDescriptor,
    TargetServiceDescriptor,
    dedupe_ints,
    plans_by_destination_port,
    probe_plan_send_count,
    target_service_address_fields,
)
from .target_service_helpers import json_mapping as _json_mapping
from .target_service_helpers import string_or as _string_or


# A lab-wire helper that resolves an endpoint mapping to its endpoint ID.
EndpointIdResolver = Callable[..., str]
# A lab-wire helper that resolves an endpoint mapping to its bind IPv4 address.
EndpointIpv4Resolver = Callable[..., str]
# A lab-wire helper that resolves an endpoint mapping to its packet interface.
EndpointInterfaceResolver = Callable[..., str]
# A lab-wire helper that runs a wire command response and records its artifacts.
WireCommandRunner = Callable[..., JSONObject]

BGP_SERVICE_KIND = "frr-bgp-peer"
BGP_SERVICE_PORT = 179
BGP_RUNTIME = "frr"
BGP_DRIVER_AS = 65000
BGP_PEER_AS = 65001
BGP_DOCUMENTATION_IPV4_PREFIX = "198.51.100.0/24"
BGP_DOCUMENTATION_IPV6_PREFIX = "2001:db8::/32"
BGP_PROVISION_SCRIPT = "tools/probe/target_services/bgp/provision-peer.sh"
BGP_FRR_TEMPLATE = "tools/probe/target_services/bgp/frr.conf.template"
BGP_RIB_COMMAND = "vtysh -c 'show bgp ipv4 unicast'"

RIP_SERVICE_KIND = "frr-ripd"
RIP_SERVICE_PORTS = [520]
RIP_RUNTIME = "frr"
RIP_MULTICAST_GROUP = "224.0.0.9"
RIP_DOCUMENTATION_IPV4_PREFIX = "198.51.100.0/24"
RIP_PROVISION_SCRIPT = "tools/probe/target_services/rip/provision-daemon.sh"
RIP_CONFIG_TEMPLATE = "tools/probe/target_services/rip/ripd.conf.template"
RIP_RIB_COMMAND = "vtysh -c 'show ip rip'"


# --------------------------------------------------------------------------- #
# Typed service descriptors
# --------------------------------------------------------------------------- #
#
# Each descriptor is a deterministic, inspectable plan for one controlled
# target service or one piece of verified kernel state. The descriptor
# dataclasses (:class:`TargetServiceDescriptor`, :class:`KernelStateDescriptor`)
# live in :mod:`target_service_helpers`; the per-protocol builders below render
# the typed contract the live setup script renders and the dry-run report
# advertises.


# The DNS target-service descriptor (``dns_responder_descriptor``) now lives in
# :mod:`tools.probe.engine.protocols.dns` and is re-imported above so
# ``target_services.dns_responder_descriptor`` keeps resolving for the
# behavior/script tests.


def dhcp_responder_descriptor(
    *,
    bind_ipv4: str,
    source_ipv4: str,
    port: int,
    artifact_root: str,
) -> TargetServiceDescriptor:
    """Describe the controlled DHCP/BOOTP responder on a private L2 segment.

    DHCP requires link-layer broadcast on a private lab network, so the
    descriptor records the link-layer requirement that gates it.
    """

    return TargetServiceDescriptor(
        name="dhcp-responder",
        protocol="udp",
        purpose="dhcp",
        bind_ipv4=bind_ipv4,
        source_ipv4=source_ipv4,
        port=port,
        requires=["python3", SKIP_REQUIRES_LINK_LAYER, SKIP_REQUIRES_CONTROLLED_SERVICE],
        setup_commands=[
            f"check udp port {bind_ipv4}:{port} is free",
            f"start dhcp-responder.py on {bind_ipv4}:{port}",
        ],
        cleanup_commands=[
            f"kill dhcp-responder on {bind_ipv4}:{port}",
        ],
        artifacts=[
            posixpath.join(artifact_root, f"dhcp-responder-{port}.stdout.txt"),
            posixpath.join(artifact_root, f"dhcp-responder-{port}.stderr.txt"),
            posixpath.join(artifact_root, f"dhcp-responder-{port}.pid"),
        ],
        metadata={"runtime": "python3", "deterministic": True, "layer": "link"},
    )


def udp_responder_descriptor(
    *,
    bind_ipv4: str,
    source_ipv4: str,
    port: int,
    artifact_root: str,
) -> TargetServiceDescriptor:
    """Describe the controlled UDP echo/transform responder."""

    return TargetServiceDescriptor(
        name="udp-responder",
        protocol="udp",
        purpose="udp-echo",
        bind_ipv4=bind_ipv4,
        source_ipv4=source_ipv4,
        port=port,
        requires=["python3", SKIP_REQUIRES_CONTROLLED_SERVICE],
        setup_commands=[
            f"check udp port {bind_ipv4}:{port} is free",
            f"start udp-responder.py on {bind_ipv4}:{port}",
        ],
        cleanup_commands=[
            f"kill udp-responder on {bind_ipv4}:{port}",
        ],
        artifacts=[
            posixpath.join(artifact_root, f"udp-responder-{port}.stdout.txt"),
            posixpath.join(artifact_root, f"udp-responder-{port}.stderr.txt"),
            posixpath.join(artifact_root, f"udp-responder-{port}.pid"),
        ],
        metadata={"runtime": "python3", "deterministic": True},
    )


def frr_bgp_peer_descriptor(
    *,
    bind_ipv4: str,
    source_ipv4: str,
) -> TargetServiceDescriptor:
    """Describe the probe-owned FRR BGP peer target service."""

    return TargetServiceDescriptor(
        name=BGP_SERVICE_KIND,
        protocol="tcp",
        purpose="bgp-peer",
        bind_ipv4=bind_ipv4,
        source_ipv4=source_ipv4,
        port=BGP_SERVICE_PORT,
        requires=[BGP_RUNTIME, SKIP_REQUIRES_CONTROLLED_SERVICE],
        setup_commands=[
            f"run {BGP_PROVISION_SCRIPT} with DRIVER_IP={source_ipv4}",
            f"inspect RIB with {BGP_RIB_COMMAND}",
        ],
        cleanup_commands=[
            "stop FRR BGP peer service through provider cleanup",
        ],
        artifacts=[
            "live-artifacts/probe/target-services/bgp-provision.stdout.txt",
            "live-artifacts/probe/target-services/bgp-provision.stderr.txt",
        ],
        metadata={
            "kind": BGP_SERVICE_KIND,
            "runtime": BGP_RUNTIME,
            "deterministic": True,
            "driver_as": BGP_DRIVER_AS,
            "peer_as": BGP_PEER_AS,
            "documentation_prefixes": [
                BGP_DOCUMENTATION_IPV4_PREFIX,
                BGP_DOCUMENTATION_IPV6_PREFIX,
            ],
            "provision_script": BGP_PROVISION_SCRIPT,
            "frr_template": BGP_FRR_TEMPLATE,
            "rib_command": BGP_RIB_COMMAND,
        },
    )


def rip_peer_service_descriptor(
    *,
    bind_ipv4: str,
    source_ipv4: str,
) -> TargetServiceDescriptor:
    """Describe the probe-owned FRR ``ripd`` target service.

    Mirrors :func:`frr_bgp_peer_descriptor` for the RIP smoke profile: an FRR
    runtime serving RIPv2 on UDP/520, advertising documentation-range prefixes
    to the all-RIP-routers multicast group, provisioned from probe-owned assets
    and inspected through ``vtysh``.
    """

    return TargetServiceDescriptor(
        name=RIP_SERVICE_KIND,
        protocol="udp",
        purpose="rip-peer",
        bind_ipv4=bind_ipv4,
        source_ipv4=source_ipv4,
        port=RIP_SERVICE_PORTS[0],
        requires=[RIP_RUNTIME, SKIP_REQUIRES_CONTROLLED_SERVICE],
        setup_commands=[
            f"run {RIP_PROVISION_SCRIPT} with DRIVER_IP={source_ipv4}",
            f"inspect RIB with {RIP_RIB_COMMAND}",
        ],
        cleanup_commands=[
            "stop FRR ripd peer service through provider cleanup",
        ],
        artifacts=[
            "live-artifacts/probe/target-services/rip-provision.stdout.txt",
            "live-artifacts/probe/target-services/rip-provision.stderr.txt",
        ],
        metadata={
            "kind": RIP_SERVICE_KIND,
            "runtime": RIP_RUNTIME,
            "deterministic": True,
            "ports": list(RIP_SERVICE_PORTS),
            "multicast_group": RIP_MULTICAST_GROUP,
            "documentation_prefixes": [
                RIP_DOCUMENTATION_IPV4_PREFIX,
            ],
            "provision_script": RIP_PROVISION_SCRIPT,
            "config_template": RIP_CONFIG_TEMPLATE,
            "rib_command": RIP_RIB_COMMAND,
        },
    )


def closed_udp_port_descriptor(
    *,
    bind_ipv4: str,
    source_ipv4: str,
    port: int,
) -> KernelStateDescriptor:
    """Describe a closed UDP port whose kernel emits ICMP port-unreachable."""

    return KernelStateDescriptor(
        name="closed-udp-port",
        purpose="udp-port-unreachable",
        bind_ipv4=bind_ipv4,
        source_ipv4=source_ipv4,
        port=port,
        verify_commands=[
            f"check udp port {bind_ipv4}:{port} is free",
        ],
        metadata={"expects": "icmp_port_unreachable", "deterministic": True},
    )


# The ARP target-service descriptors (``arp_alias_descriptor`` /
# ``arp_sysctl_descriptor``) now live in :mod:`tools.probe.engine.protocols.arp`
# and are re-imported below so ``target_services.arp_*`` keeps resolving for the
# behavior/script tests.


# --------------------------------------------------------------------------- #
# Registry-first folding helpers
# --------------------------------------------------------------------------- #
#
# The target-service setup plan and setup script are assembled registry-first:
# every registered protocol plugin contributes its own target-service plan
# fragment and setup-script block, and only the cases no plugin owns flow
# through the legacy per-protocol construction below. With an empty registry
# (no protocol migrated yet) the owned-case set is empty, so the legacy path
# sees every plan and the emitted bytes are byte-identical to the pre-registry
# behavior. A protocol served by a plugin is therefore never double-built.


def _registry_owned_case_names() -> frozenset[str]:
    """Return the case names whose target-service plan a plugin owns.

    Only plugins that provide a ``target_service`` hook divert their cases to the
    registry path: a plan is removed from the legacy per-protocol construction
    (so a plugin-served protocol is never built twice) *only* when its owning
    plugin actually contributes a target-service fragment. A plugin that has
    migrated its planning surface but not yet its target-service concern (its
    ``target_service`` hook is still ``None``) keeps its cases on the legacy path
    so their target-service plan stays byte-identical until that hook lands.
    Empty until a protocol migrates its target-service hook.
    """

    names: set[str] = set()
    for plugin in registered_plugins():
        if plugin.target_service is None:
            continue
        names.update(case.name for case in plugin.cases)
    return frozenset(names)


def _split_registry_plans(
    probe_plans: Sequence[JSONObject],
) -> tuple[list[JSONObject], list[JSONObject]]:
    """Partition probe plans into registry-owned and legacy-owned lists.

    The first list holds plans whose case is served by a registered plugin (to
    be built from the plugin's ``target_service`` contribution); the second
    holds the plans the legacy per-protocol code still owns. With an empty
    registry the first list is empty and the second is the full input, in order.
    """

    owned = _registry_owned_case_names()
    if not owned:
        return [], list(probe_plans)
    registry_plans = [plan for plan in probe_plans if plan.get("case") in owned]
    legacy_plans = [plan for plan in probe_plans if plan.get("case") not in owned]
    return registry_plans, legacy_plans


def _merge_target_service_contribution(
    plan: JSONObject,
    contribution: Mapping[str, JSONValue],
) -> None:
    """Fold one plugin's target-service contribution into the central plan.

    Plugin-contributed ``services``/``closed_tcp_ports``/``closed_udp_ports``
    entries are appended to the central lists, and ``starts_services`` is OR-ed
    so a live run that any plugin needs to stand up a service still flips the
    flag. Other contributed keys overwrite the central value (the legacy path
    leaves them at their defaults for plugin-owned protocols). With an empty
    registry this helper is never called.
    """

    for key in ("services", "closed_tcp_ports", "closed_udp_ports"):
        extra = contribution.get(key)
        if isinstance(extra, Sequence) and not isinstance(extra, (str, bytes)):
            existing = plan.get(key)
            if isinstance(existing, list):
                existing.extend(extra)
            else:
                plan[key] = list(extra)
    if contribution.get("starts_services"):
        plan["starts_services"] = bool(plan.get("starts_services")) or True
    for key, value in contribution.items():
        if key in ("services", "closed_tcp_ports", "closed_udp_ports", "starts_services"):
            continue
        plan[key] = value


# --------------------------------------------------------------------------- #
# Target service setup plan (dry-run + live shape)
# --------------------------------------------------------------------------- #


def target_service_setup_plan(
    *,
    probe_plans: Sequence[JSONObject],
    dry_run: bool,
) -> JSONObject:
    """Return the ``target_service_setup`` plan for a probe run.

    The shape is the stable contract consumed by the dry-run report and the
    live target setup. ``starts_services`` is only true on a live run that has
    at least one service to stand up; dry-run never starts services.

    The plan is assembled registry-first: every registered protocol plugin
    contributes its own ``target_service(probe_plans)`` fragment, and only the
    plans no plugin owns flow through the legacy per-protocol construction below
    (so a plugin-served protocol is never double-built). With an empty registry
    the legacy path sees every plan and the result is byte-identical.
    """

    registry_plans, legacy_plans = _split_registry_plans(probe_plans)
    plan = _legacy_target_service_setup_plan(
        probe_plans=legacy_plans,
        dry_run=dry_run,
    )
    if registry_plans:
        for plugin in registered_plugins():
            if plugin.target_service is None:
                continue
            owned = frozenset(case.name for case in plugin.cases)
            plugin_plans = [p for p in registry_plans if p.get("case") in owned]
            if not plugin_plans:
                continue
            contribution = plugin.target_service(plugin_plans, dry_run=dry_run)
            if isinstance(contribution, Mapping):
                _merge_target_service_contribution(plan, contribution)
    return plan


def _legacy_target_service_setup_plan(
    *,
    probe_plans: Sequence[JSONObject],
    dry_run: bool,
) -> JSONObject:
    """Build the per-protocol target-service plan for legacy-owned cases.

    This is the historical ``target_service_setup_plan`` body, unchanged; the
    registry-first wrapper above feeds it only the plans no plugin owns. With an
    empty registry that is every plan, so the output is byte-identical.
    """

    tcp_open_plans = plans_by_destination_port(
        plan for plan in probe_plans if plan.get("case") == "tcp-syn-open"
    )
    tcp_closed_plans = plans_by_destination_port(
        plan for plan in probe_plans if plan.get("case") == "tcp-syn-closed"
    )
    dhcp_plans = dhcp_probe_plans(probe_plans)
    dhcp_plans_by_port = plans_by_destination_port(dhcp_plans)
    udp_plans = udp_probe_plans(probe_plans)
    udp_plans_by_port = plans_by_destination_port(udp_plans)
    closed_udp_plans = closed_udp_probe_plans(probe_plans)
    closed_udp_plans_by_port = plans_by_destination_port(closed_udp_plans)
    bgp_plans = bgp_peer_probe_plans(probe_plans)
    arp_plans = arp_probe_plans(probe_plans)
    return {
        "role": "target",
        "planned": True,
        "starts_services": not dry_run
        and bool(
            tcp_open_plans
            or dhcp_plans_by_port
            or udp_plans_by_port
            or bgp_plans
        ),
        "dry_run_starts_services": False,
        "services": [
            *[
                {
                    "name": "tcp-open-listener",
                    "protocol": "tcp",
                    "port": port,
                    "purpose": "tcp-syn-open",
                    "deterministic": True,
                    **target_service_address_fields(plan),
                }
                for port, plan in tcp_open_plans.items()
            ],
            *[
                {
                    "name": "dhcp-responder",
                    "protocol": "udp",
                    "port": port,
                    "purpose": "dhcp",
                    "deterministic": True,
                    "request_count": sum(
                        probe_plan_send_count(plan)
                        for plan in dhcp_plans
                        if int(plan.get("destination_port", 0)) == port
                    ),
                    **target_service_address_fields(plan),
                    "log_paths": [
                        f"live-artifacts/probe/target-services/dhcp-responder-{port}.stdout.txt",
                        f"live-artifacts/probe/target-services/dhcp-responder-{port}.stderr.txt",
                    ],
                }
                for port, plan in dhcp_plans_by_port.items()
            ],
            *[
                {
                    "name": "udp-responder",
                    "protocol": "udp",
                    "port": port,
                    "purpose": "udp-echo",
                    "deterministic": True,
                    "echo": True,
                    "payload_count": sum(
                        int(plan.get("send_count") or 1)
                        for plan in udp_plans
                        if int(plan.get("destination_port", 0)) == port
                    ),
                    **target_service_address_fields(plan),
                    "log_paths": [
                        f"live-artifacts/probe/target-services/udp-responder-{port}.stdout.txt",
                        f"live-artifacts/probe/target-services/udp-responder-{port}.stderr.txt",
                    ],
                }
                for port, plan in udp_plans_by_port.items()
            ],
            *bgp_peer_service_plans(bgp_plans),
        ],
        "closed_tcp_ports": [
            {
                "port": port,
                "state": "verified-unbound" if not dry_run else "planned-unbound",
                "purpose": "tcp-syn-closed",
                "deterministic": True,
                **target_service_address_fields(plan),
            }
            for port, plan in tcp_closed_plans.items()
        ],
        "closed_udp_ports": [
            {
                "port": port,
                "state": "verified-unbound" if not dry_run else "planned-unbound",
                "purpose": "udp-closed-port-icmp",
                "expects": "icmp_port_unreachable",
                "deterministic": True,
                **target_service_address_fields(plan),
            }
            for port, plan in closed_udp_plans_by_port.items()
        ],
        "controlled_router": {
            "available": False,
            "skip_reason": SKIP_REQUIRES_CONTROLLED_ROUTER,
        },
        "arp_kernel_state": arp_kernel_state_plan(
            probe_plans=arp_plans,
            dry_run=dry_run,
        ),
    }


def bgp_peer_service_plans(probe_plans: Sequence[JSONObject]) -> list[JSONObject]:
    """Return the FRR BGP peer service plan, if any probe plan requests it."""

    if not probe_plans:
        return []
    plan = probe_plans[0]
    addresses = target_service_address_fields(plan)
    descriptor = frr_bgp_peer_descriptor(
        bind_ipv4=_string_or(addresses.get("bind_ipv4"), ""),
        source_ipv4=_string_or(addresses.get("source_ipv4"), ""),
    )
    service: JSONObject = {
        "name": descriptor.name,
        "kind": descriptor.name,
        "protocol": descriptor.protocol,
        "port": descriptor.port,
        "purpose": descriptor.purpose,
        "deterministic": True,
        "requires": list(descriptor.requires),
        **addresses,
        **descriptor.metadata,
    }
    return [service]


# The ARP kernel-state plan (``arp_kernel_state_plan``) now lives in
# :mod:`tools.probe.engine.protocols.arp`; the ARP plugin's ``target_service``
# hook contributes the ``arp_kernel_state`` key to the central setup plan. It is
# re-imported below so ``target_services.arp_kernel_state_plan`` keeps resolving.


# --------------------------------------------------------------------------- #
# Plan filters and small helpers
# --------------------------------------------------------------------------- #


def tcp_probe_plans(probe_plans: Sequence[JSONObject]) -> list[JSONObject]:
    """Return the TCP-SYN probe plans (open and closed) in order."""

    return [
        plan
        for plan in probe_plans
        if str(plan.get("case", "")).startswith("tcp-syn-")
    ]


# The DNS responder case set (``_DNS_RESPONDER_CASES``) and the ``dns_probe_plans``
# selector now live in :mod:`tools.probe.engine.protocols.dns`; they are
# re-imported above so ``target_services._DNS_RESPONDER_CASES`` /
# ``target_services.dns_probe_plans`` keep resolving for the legacy plan body
# (the partition reroutes DNS plans to the plugin's ``target_service`` hook) and
# for ``prepare_wire_probe_target`` / the tests.


def bgp_peer_probe_plans(probe_plans: Sequence[JSONObject]) -> list[JSONObject]:
    """Return probe plans that require the probe-owned FRR BGP peer."""

    return [plan for plan in probe_plans if probe_plan_requires_bgp_peer(plan)]


def probe_plan_requires_bgp_peer(plan: Mapping[str, JSONValue]) -> bool:
    """Return whether a probe plan requests FRR BGP peer target setup."""

    target_service = _json_mapping(
        plan.get("target_service", {}),
        "probe_plan.target_service",
    )
    if target_service.get("kind") == BGP_SERVICE_KIND:
        return True
    case_name = plan.get("case")
    return isinstance(case_name, str) and case_name.startswith("bgp-")


# Probe cases that drive the controlled DHCP/BOOTP responder on a private L2
# segment. ``dhcp-discover-offer`` is the baseline Discover->Offer case; the
# later DHCP behavioral cases reuse the same responder descriptor and target
# setup. Providers without link-layer/broadcast capability skip these cases (the
# descriptor records the link-layer requirement that gates them).
_DHCP_RESPONDER_CASES: frozenset[str] = frozenset(
    {
        "dhcp-discover-offer",
        "dhcp-request-ack",
        "dhcp-client-identifier",
        "dhcp-hostname",
        "dhcp-parameter-request-list",
        "dhcp-lease-time",
        "dhcp-renewal-unicast-ack",
        "dhcp-inform-ack",
        "dhcp-request-nak",
        "dhcp-rapid-repeat",
    }
)


def dhcp_probe_plans(probe_plans: Sequence[JSONObject]) -> list[JSONObject]:
    """Return the DHCP probe plans in order."""

    return [plan for plan in probe_plans if plan.get("case") in _DHCP_RESPONDER_CASES]


# Probe cases that drive the controlled UDP echo/transform responder. The empty
# echo case is the zero-payload baseline; the short and binary echo cases cover
# application bytes over the same service-response path. Source-port reflection
# reuses the same echo responder and tightens the stimulus-side port contract.
# Multi-shot order drives the same responder with an ordered per-send payload
# sequence. The IPv4 zero-checksum case uses the same responder, while the
# provider/kernel acceptance is surfaced through a case capability. The options
# surplus case also reuses the responder; only the stimulus datagram carries the
# surplus area, while the service echoes the conventional application payload.
_UDP_RESPONDER_CASES: frozenset[str] = frozenset(
    {
        "udp-echo-empty",
        "udp-echo-short",
        "udp-echo-binary",
        "udp-echo-large",
        "udp-length-boundary-echo",
        "udp-source-port-reflection",
        "udp-multi-shot-order",
        "udp-zero-checksum-ipv4",
        "udp-options-surplus-echo",
    }
)


_UDP_CLOSED_PORT_CASES: frozenset[str] = frozenset({"udp-closed-port-icmp"})


def udp_probe_plans(probe_plans: Sequence[JSONObject]) -> list[JSONObject]:
    """Return the UDP responder probe plans in order."""

    return [plan for plan in probe_plans if plan.get("case") in _UDP_RESPONDER_CASES]


def closed_udp_probe_plans(probe_plans: Sequence[JSONObject]) -> list[JSONObject]:
    """Return UDP plans that require the target kernel's closed-port behavior."""

    return [
        plan for plan in probe_plans if plan.get("case") in _UDP_CLOSED_PORT_CASES
    ]


# The ARP kernel case set (``_ARP_KERNEL_CASES``) and the ``arp_probe_plans``
# selector now live in :mod:`tools.probe.engine.protocols.arp`; they are
# re-imported below so ``target_services._ARP_KERNEL_CASES`` /
# ``target_services.arp_probe_plans`` keep resolving for the legacy plan body
# (which now sees no ARP plans) and the behavior/script tests.


# Probe cases whose target is primarily the kernel answering IPv6 Neighbor
# Discovery on a private L2 segment. ``ndp-neighbor-solicitation`` and
# ``ndp-duplicate-address-detection`` rely on a bare kernel auto-answering /
# defending a Neighbor Solicitation for an address it owns; the setup only needs
# to make sure IPv6 is enabled on the private interface and the neighbor cache is
# clean (no listening daemon). ``ndp-router-solicitation`` additionally needs the
# target to act as an RA-emitting router (kernel RA via forwarding + accept_ra),
# which the setup enables best-effort.
_NDP_KERNEL_CASES: frozenset[str] = frozenset(
    {
        "ndp-neighbor-solicitation",
        "ndp-router-solicitation",
        "ndp-duplicate-address-detection",
    }
)
_NDP_ROUTER_CASES: frozenset[str] = frozenset({"ndp-router-solicitation"})


def ndp_probe_plans(probe_plans: Sequence[JSONObject]) -> list[JSONObject]:
    """Return the NDP probe plans in order."""

    return [plan for plan in probe_plans if plan.get("case") in _NDP_KERNEL_CASES]


# The ARP live-setup helpers (``arp_extra_addresses`` / ``arp_decoy_events``)
# now live in :mod:`tools.probe.engine.protocols.arp` and are re-imported below;
# the ARP setup-script block also moved there (``arp_target_setup_lines``).


# --------------------------------------------------------------------------- #
# Live target setup / cleanup over the lab-wire transport
# --------------------------------------------------------------------------- #


def prepare_wire_probe_target(
    *,
    wire: object,
    target_endpoint: Mapping[str, JSONValue],
    artifact_root: str,
    probe_plans: Sequence[JSONObject],
    output_dir: Path,
    endpoint_id_resolver: EndpointIdResolver,
    endpoint_ipv4_resolver: EndpointIpv4Resolver,
    endpoint_interface_resolver: EndpointInterfaceResolver,
    run_wire_command: WireCommandRunner,
) -> JSONObject | None:
    """Stand up controlled target services for a live probe run.

    Returns ``None`` when no target service is required. The lab-wire transport
    helpers are injected so this module stays free of an import cycle with the
    CLI orchestration module.
    """

    tcp_plans = tcp_probe_plans(probe_plans)
    dns_plans = dns_probe_plans(probe_plans)
    dhcp_plans = dhcp_probe_plans(probe_plans)
    arp_plans = arp_probe_plans(probe_plans)
    ndp_plans = ndp_probe_plans(probe_plans)
    udp_plans = udp_probe_plans(probe_plans)
    closed_udp_plans = closed_udp_probe_plans(probe_plans)
    if (
        not tcp_plans
        and not dns_plans
        and not dhcp_plans
        and not arp_plans
        and not ndp_plans
        and not udp_plans
        and not closed_udp_plans
    ):
        return None
    endpoint_id = endpoint_id_resolver(target_endpoint, role=TARGET_ROLE)
    bind_ipv4 = endpoint_ipv4_resolver(target_endpoint, role=TARGET_ROLE)
    target_interface = endpoint_interface_resolver(target_endpoint, role=TARGET_ROLE)
    open_ports = dedupe_ints(
        int(plan["destination_port"])
        for plan in tcp_plans
        if plan.get("case") == "tcp-syn-open"
    )
    closed_ports = dedupe_ints(
        int(plan["destination_port"])
        for plan in tcp_plans
        if plan.get("case") == "tcp-syn-closed"
    )
    closed_udp_ports = dedupe_ints(
        int(plan["destination_port"]) for plan in closed_udp_plans
    )
    script = target_service_setup_script(
        artifact_root=artifact_root,
        bind_ipv4=bind_ipv4,
        open_ports=open_ports,
        closed_ports=closed_ports,
        dns_plans=dns_plans,
        dhcp_plans=dhcp_plans,
        arp_plans=arp_plans,
        ndp_plans=ndp_plans,
        udp_plans=udp_plans,
        closed_udp_ports=closed_udp_ports,
        target_interface=target_interface,
    )
    return run_wire_command(
        wire.exec(endpoint_id, ["bash", "-lc", script], timeout=60),
        output_dir=output_dir,
        label="probe-target-setup",
    )


def cleanup_wire_probe_target(
    *,
    wire: object,
    target_endpoint: Mapping[str, JSONValue],
    artifact_root: str,
    output_dir: Path,
    endpoint_id_resolver: EndpointIdResolver,
    run_wire_command: WireCommandRunner,
) -> JSONObject:
    """Run the disposable target cleanup script over the lab-wire transport."""

    endpoint_id = endpoint_id_resolver(target_endpoint, role=TARGET_ROLE)
    cleanup_script = posixpath.join(artifact_root, "cleanup.sh")
    script = "\n".join(
        [
            "set -euo pipefail",
            f"if [ -x {shlex.quote(cleanup_script)} ]; then {shlex.quote(cleanup_script)}; fi",
        ]
    )
    return run_wire_command(
        wire.exec(endpoint_id, ["bash", "-lc", script], timeout=60),
        output_dir=output_dir,
        label="probe-target-cleanup",
    )


# --------------------------------------------------------------------------- #
# Deterministic, artifact-producing setup script
# --------------------------------------------------------------------------- #


def target_service_setup_script(
    *,
    artifact_root: str,
    bind_ipv4: str,
    open_ports: Sequence[int],
    closed_ports: Sequence[int],
    dns_plans: Sequence[JSONObject],
    dhcp_plans: Sequence[JSONObject] = (),
    arp_plans: Sequence[JSONObject] = (),
    ndp_plans: Sequence[JSONObject] = (),
    udp_plans: Sequence[JSONObject] = (),
    closed_udp_ports: Sequence[int] = (),
    target_interface: str = "",
) -> str:
    """Render the deterministic target setup script.

    The script verifies closed ports, starts TCP listeners and the DNS
    responder, records a cleanup script, and writes per-service artifacts so
    the live run is inspectable.
    """

    dhcp_plan_json = json.dumps(list(dhcp_plans), sort_keys=True)
    dhcp_ports = dedupe_ints(
        int(plan["destination_port"])
        for plan in dhcp_plans
        if isinstance(plan.get("destination_port"), int)
    )
    udp_ports = dedupe_ints(
        int(plan["destination_port"])
        for plan in udp_plans
        if isinstance(plan.get("destination_port"), int)
    )
    lines = [
        "set -euo pipefail",
        f"artifact_root={shlex.quote(artifact_root)}",
        f"tcp_bind_ipv4={shlex.quote(bind_ipv4)}",
        f"dns_bind_ipv4={shlex.quote(bind_ipv4)}",
        f"dhcp_bind_ipv4={shlex.quote(bind_ipv4)}",
        f"udp_bind_ipv4={shlex.quote(bind_ipv4)}",
        f"target_interface={shlex.quote(target_interface)}",
        'mkdir -p "$artifact_root"',
        'cleanup="$artifact_root/cleanup.sh"',
        ': > "$cleanup"',
        'chmod 700 "$cleanup"',
        "check_port_free() {",
        "  python3 - \"$1\" \"$2\" <<'PY'",
        "import socket",
        "import sys",
        "bind_ip = sys.argv[1]",
        "port = int(sys.argv[2])",
        "sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)",
        "try:",
        "    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)",
        "    sock.bind((bind_ip, port))",
        "except OSError as exc:",
        "    print(f'tcp port {bind_ip}:{port} is not free: {exc}', file=sys.stderr)",
        "    sys.exit(1)",
        "finally:",
        "    sock.close()",
        "PY",
        "}",
        "check_udp_port_free() {",
        "  python3 - \"$1\" \"$2\" <<'PY'",
        "import socket",
        "import sys",
        "bind_ip = sys.argv[1]",
        "port = int(sys.argv[2])",
        "sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)",
        "try:",
        "    sock.bind((bind_ip, port))",
        "except OSError as exc:",
        "    print(f'udp port {bind_ip}:{port} is not free: {exc}', file=sys.stderr)",
        "    sys.exit(1)",
        "finally:",
        "    sock.close()",
        "PY",
        "}",
    ]
    # The DNS per-port UDP port-free check moved to
    # ``protocols.dns.dns_port_check_lines``; render it here so the script bytes
    # stay byte-identical to the legacy inline ``for port in dns_ports:`` loop.
    lines.extend(dns_port_check_lines(dns_plans))
    for port in dhcp_ports:
        lines.extend(
            [
                "python3 - \"$dhcp_bind_ipv4\" \"$1\" <<'PY'".replace("$1", str(port)),
                "import socket",
                "import sys",
                "bind_ip = sys.argv[1]",
                "port = int(sys.argv[2])",
                "sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)",
                "try:",
                "    sock.bind((bind_ip, port))",
                "except OSError as exc:",
                "    print(f'udp port {bind_ip}:{port} is not free: {exc}', file=sys.stderr)",
                "    sys.exit(1)",
                "finally:",
                "    sock.close()",
                "PY",
            ]
        )
    for port in closed_ports:
        lines.append(f"check_port_free \"$tcp_bind_ipv4\" {port}")
        lines.append(f"echo closed_port_{port}=free")
    for port in closed_udp_ports:
        lines.append(f"check_udp_port_free \"$udp_bind_ipv4\" {port}")
        lines.append(f"echo closed_udp_port_{port}=free")
    for port in open_ports:
        listener_path = posixpath.join(artifact_root, f"tcp-listener-{port}.py")
        stdout_path = posixpath.join(artifact_root, f"tcp-listener-{port}.stdout.txt")
        stderr_path = posixpath.join(artifact_root, f"tcp-listener-{port}.stderr.txt")
        pid_path = posixpath.join(artifact_root, f"tcp-listener-{port}.pid")
        lines.extend(
            [
                f"check_port_free \"$tcp_bind_ipv4\" {port}",
                f"cat > {shlex.quote(listener_path)} <<'PY'",
                "import signal",
                "import socket",
                "import sys",
                "",
                "stop = False",
                "",
                "def handle_stop(_signum, _frame):",
                "    global stop",
                "    stop = True",
                "",
                "signal.signal(signal.SIGTERM, handle_stop)",
                "signal.signal(signal.SIGINT, handle_stop)",
                "bind_ip = sys.argv[1]",
                "port = int(sys.argv[2])",
                "sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)",
                "sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)",
                "sock.bind((bind_ip, port))",
                "sock.listen(128)",
                "sock.settimeout(1.0)",
                "print(f'listening on {bind_ip}:{port}', flush=True)",
                "while not stop:",
                "    try:",
                "        conn, _addr = sock.accept()",
                "    except socket.timeout:",
                "        continue",
                "    conn.close()",
                "sock.close()",
                "PY",
                (
                    f"python3 {shlex.quote(listener_path)} \"$tcp_bind_ipv4\" {port} "
                    f">{shlex.quote(stdout_path)} 2>{shlex.quote(stderr_path)} &"
                ),
                "pid=$!",
                f"echo \"$pid\" > {shlex.quote(pid_path)}",
                "printf '%s\\n' \"kill $pid 2>/dev/null || true\" >> \"$cleanup\"",
                f"printf '%s\\n' \"rm -f {shlex.quote(pid_path)}\" >> \"$cleanup\"",
                "sleep 0.5",
                "if ! kill -0 \"$pid\" 2>/dev/null; then",
                f"  cat {shlex.quote(stderr_path)} >&2 || true",
                f"  echo listener_{port}=failed >&2",
                "  exit 73",
                "fi",
                f"echo listener_{port}=running",
            ]
        )
    # The DNS responder heredoc + launch block moved to
    # ``protocols.dns.dns_responder_setup_lines``; render it here so the
    # script bytes stay byte-identical to the legacy inline blocks.
    lines.extend(
        dns_responder_setup_lines(
            artifact_root=artifact_root,
            dns_plans=dns_plans,
        )
    )
    if dhcp_ports:
        plan_path = posixpath.join(artifact_root, "dhcp-plans.json")
        service_path = posixpath.join(artifact_root, "dhcp-responder.py")
        lines.extend(
            [
                f"cat > {shlex.quote(plan_path)} <<'JSON'",
                dhcp_plan_json,
                "JSON",
                f"cat > {shlex.quote(service_path)} <<'PY'",
                "import ipaddress",
                "import json",
                "import signal",
                "import socket",
                "import struct",
                "import sys",
                "import time",
                "",
                "stop = False",
                "",
                "def handle_stop(_signum, _frame):",
                "    global stop",
                "    stop = True",
                "",
                "signal.signal(signal.SIGTERM, handle_stop)",
                "signal.signal(signal.SIGINT, handle_stop)",
                "",
                "plan_path, bind_ip, port_text = sys.argv[1:4]",
                "port = int(port_text)",
                "plans = json.load(open(plan_path, encoding='utf-8'))",
                "entries = {}",
                "entries_by_xid = {}",
                "",
                "def mac_normal(value):",
                "    return str(value or '').lower()",
                "",
                "def mac_bytes(value):",
                "    return bytes(int(part, 16) for part in mac_normal(value).split(':'))",
                "",
                "def ip_bytes(value):",
                "    return ipaddress.IPv4Address(str(value)).packed",
                "",
                "def opt_u8(code, value):",
                "    return bytes([code, 1, int(value) & 0xff])",
                "",
                "def opt_u32(code, value):",
                "    return bytes([code, 4]) + struct.pack('!I', int(value) & 0xffffffff)",
                "",
                "def opt_ip(code, value):",
                "    return bytes([code, 4]) + ip_bytes(value)",
                "",
                "def opt_bytes(code, data):",
                "    return bytes([code, len(data)]) + data",
                "",
                "def opt_text(code, value):",
                "    raw = str(value).encode('utf-8')",
                "    if len(raw) > 255:",
                "        raise ValueError(f'dhcp option {code} text is too long')",
                "    return opt_bytes(code, raw)",
                "",
                "def entry_from(raw, parent=None):",
                "    parent = parent or {}",
                "    xid = int(raw.get('transaction_id') or parent.get('transaction_id'))",
                "    client_mac = mac_normal(raw.get('client_mac') or parent.get('client_mac'))",
                "    message_type = int(",
                "        raw.get('expected_message_type_value')",
                "        or parent.get('expected_message_type_value')",
                "        or (6 if raw.get('expected_message') or raw.get('message') else 2)",
                "    )",
                "    yiaddr = '0.0.0.0' if (raw.get('expected_yiaddr_zero') or raw.get('yiaddr_zero')) else str(",
                "        raw.get('expected_yiaddr') or raw.get('yiaddr') or parent.get('expected_yiaddr') or '0.0.0.0'",
                "    )",
                "    return {",
                "        'transaction_id': xid,",
                "        'client_mac': client_mac,",
                "        'message_type': message_type,",
                "        'yiaddr': yiaddr,",
                "        'server_identifier': str(",
                "            raw.get('expected_server_identifier')",
                "            or raw.get('server_identifier')",
                "            or parent.get('expected_server_identifier')",
                "            or bind_ip",
                "        ),",
                "        'subnet_mask': raw.get('expected_subnet_mask') or raw.get('subnet_mask') or parent.get('expected_subnet_mask'),",
                "        'router_ipv4': raw.get('expected_router_ipv4') or raw.get('router_ipv4') or parent.get('expected_router_ipv4'),",
                "        'dns_ipv4': raw.get('expected_dns_ipv4') or raw.get('dns_ipv4') or parent.get('expected_dns_ipv4'),",
                "        'lease_time': raw.get('expected_lease_time') or raw.get('lease_time') or parent.get('expected_lease_time'),",
                "        'renewal_time': raw.get('expected_renewal_time') or raw.get('renewal_time') or parent.get('expected_renewal_time'),",
                "        'rebinding_time': raw.get('expected_rebinding_time') or raw.get('rebinding_time') or parent.get('expected_rebinding_time'),",
                "        'no_lease_time': bool(raw.get('expected_no_lease_time') or raw.get('no_lease_time')),",
                "        'client_identifier_hex': raw.get('expected_client_identifier_hex') or raw.get('client_identifier_hex') or parent.get('expected_client_identifier_hex'),",
                "        'hostname': raw.get('expected_hostname') or raw.get('hostname') or parent.get('expected_hostname'),",
                "        'message': raw.get('expected_message') or raw.get('message') or parent.get('expected_message'),",
                "    }",
                "",
                "def register(raw, parent=None):",
                "    entry = entry_from(raw, parent)",
                "    key = (entry['transaction_id'], entry['client_mac'])",
                "    entries[key] = entry",
                "    entries_by_xid.setdefault(entry['transaction_id'], entry)",
                "",
                "for plan in plans:",
                "    register(plan)",
                "    sends = plan.get('dhcp_sends')",
                "    if isinstance(sends, list):",
                "        for send in sends:",
                "            register(send, plan)",
                "",
                "def response_for(request):",
                "    if len(request) < 240:",
                "        raise ValueError('dhcp request shorter than bootp header')",
                "    xid = struct.unpack('!I', request[4:8])[0]",
                "    chaddr = request[28:44]",
                "    client_mac = ':'.join(f'{octet:02x}' for octet in chaddr[:6])",
                "    entry = entries.get((xid, client_mac)) or entries_by_xid.get(xid)",
                "    if entry is None:",
                "        raise ValueError(f'no planned dhcp response for xid {xid} client {client_mac}')",
                "    server_ip = ip_bytes(entry['server_identifier'])",
                "    yiaddr = ip_bytes(entry['yiaddr'])",
                "    ciaddr = request[12:16]",
                "    header = struct.pack(",
                "        '!BBBBIHH4s4s4s4s16s64s128s',",
                "        2,",
                "        1,",
                "        6,",
                "        0,",
                "        xid,",
                "        0,",
                "        0,",
                "        ciaddr,",
                "        yiaddr,",
                "        server_ip,",
                "        b'\\x00' * 4,",
                "        chaddr,",
                "        b'\\x00' * 64,",
                "        b'\\x00' * 128,",
                "    )",
                "    options = bytearray(b'\\x63\\x82\\x53\\x63')",
                "    options.extend(opt_u8(53, entry['message_type']))",
                "    options.extend(opt_ip(54, entry['server_identifier']))",
                "    if entry.get('subnet_mask'):",
                "        options.extend(opt_ip(1, entry['subnet_mask']))",
                "    if entry.get('router_ipv4'):",
                "        options.extend(opt_ip(3, entry['router_ipv4']))",
                "    if entry.get('dns_ipv4'):",
                "        options.extend(opt_ip(6, entry['dns_ipv4']))",
                "    if entry.get('lease_time') is not None and not entry.get('no_lease_time'):",
                "        options.extend(opt_u32(51, entry['lease_time']))",
                "    if entry.get('renewal_time') is not None:",
                "        options.extend(opt_u32(58, entry['renewal_time']))",
                "    if entry.get('rebinding_time') is not None:",
                "        options.extend(opt_u32(59, entry['rebinding_time']))",
                "    if entry.get('client_identifier_hex'):",
                "        options.extend(opt_bytes(61, bytes.fromhex(str(entry['client_identifier_hex']))))",
                "    if entry.get('hostname'):",
                "        options.extend(opt_text(12, entry['hostname']))",
                "    if entry.get('message'):",
                "        options.extend(opt_text(56, entry['message']))",
                "    options.append(255)",
                "    return header + bytes(options), entry",
                "",
                "sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)",
                "sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)",
                "sock.bind((bind_ip, port))",
                "sock.settimeout(1.0)",
                "print(json.dumps({'event': 'listening', 'bind_ip': bind_ip, 'port': port, 'planned_responses': len(entries)}), flush=True)",
                "while not stop:",
                "    try:",
                "        data, addr = sock.recvfrom(4096)",
                "    except socket.timeout:",
                "        continue",
                "    try:",
                "        response, entry = response_for(data)",
                "        sock.sendto(response, (addr[0], 68))",
                "        print(json.dumps({'event': 'answered', 'client': addr[0], 'client_port': addr[1], 'transaction_id': entry['transaction_id'], 'message_type': entry['message_type']}, sort_keys=True), flush=True)",
                "    except Exception as exc:",
                "        print(json.dumps({'event': 'error', 'client': addr[0], 'error': str(exc)}), file=sys.stderr, flush=True)",
                "sock.close()",
                "print(json.dumps({'event': 'stopped', 'ts': time.time()}), flush=True)",
                "PY",
            ]
        )
    for port in dhcp_ports:
        stdout_path = posixpath.join(artifact_root, f"dhcp-responder-{port}.stdout.txt")
        stderr_path = posixpath.join(artifact_root, f"dhcp-responder-{port}.stderr.txt")
        pid_path = posixpath.join(artifact_root, f"dhcp-responder-{port}.pid")
        lines.extend(
            [
                f"check_udp_port_free \"$dhcp_bind_ipv4\" {port}",
                (
                    f"python3 {shlex.quote(posixpath.join(artifact_root, 'dhcp-responder.py'))} "
                    f"{shlex.quote(posixpath.join(artifact_root, 'dhcp-plans.json'))} "
                    f"\"$dhcp_bind_ipv4\" {port} "
                    f">{shlex.quote(stdout_path)} 2>{shlex.quote(stderr_path)} &"
                ),
                "pid=$!",
                f"echo \"$pid\" > {shlex.quote(pid_path)}",
                "printf '%s\\n' \"kill $pid 2>/dev/null || true\" >> \"$cleanup\"",
                f"printf '%s\\n' \"rm -f {shlex.quote(pid_path)}\" >> \"$cleanup\"",
                "sleep 0.5",
                "if ! kill -0 \"$pid\" 2>/dev/null; then",
                f"  cat {shlex.quote(stderr_path)} >&2 || true",
                f"  echo dhcp_responder_{port}=failed >&2",
                "  exit 73",
                "fi",
                f"echo dhcp_responder_{port}=running",
            ]
        )
    if udp_ports:
        service_path = posixpath.join(artifact_root, "udp-responder.py")
        lines.extend(
            [
                f"cat > {shlex.quote(service_path)} <<'PY'",
                "import json",
                "import signal",
                "import socket",
                "import sys",
                "import time",
                "",
                "stop = False",
                "",
                "def handle_stop(_signum, _frame):",
                "    global stop",
                "    stop = True",
                "",
                "signal.signal(signal.SIGTERM, handle_stop)",
                "signal.signal(signal.SIGINT, handle_stop)",
                "",
                "bind_ip, port_text = sys.argv[1:3]",
                "port = int(port_text)",
                "sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)",
                "sock.bind((bind_ip, port))",
                "sock.settimeout(1.0)",
                "print(json.dumps({'event': 'listening', 'bind_ip': bind_ip, 'port': port}), flush=True)",
                "while not stop:",
                "    try:",
                "        data, addr = sock.recvfrom(65535)",
                "    except socket.timeout:",
                "        continue",
                "    sock.sendto(data, addr)",
                "    print(json.dumps({'event': 'echoed', 'client': addr[0], 'client_port': addr[1], 'bytes': len(data)}, sort_keys=True), flush=True)",
                "sock.close()",
                "print(json.dumps({'event': 'stopped', 'ts': time.time()}), flush=True)",
                "PY",
            ]
        )
    for port in udp_ports:
        stdout_path = posixpath.join(artifact_root, f"udp-responder-{port}.stdout.txt")
        stderr_path = posixpath.join(artifact_root, f"udp-responder-{port}.stderr.txt")
        pid_path = posixpath.join(artifact_root, f"udp-responder-{port}.pid")
        lines.extend(
            [
                f"check_udp_port_free \"$udp_bind_ipv4\" {port}",
                (
                    f"python3 {shlex.quote(posixpath.join(artifact_root, 'udp-responder.py'))} "
                    f"\"$udp_bind_ipv4\" {port} "
                    f">{shlex.quote(stdout_path)} 2>{shlex.quote(stderr_path)} &"
                ),
                "pid=$!",
                f"echo \"$pid\" > {shlex.quote(pid_path)}",
                "printf '%s\\n' \"kill $pid 2>/dev/null || true\" >> \"$cleanup\"",
                f"printf '%s\\n' \"rm -f {shlex.quote(pid_path)}\" >> \"$cleanup\"",
                "sleep 0.5",
                "if ! kill -0 \"$pid\" 2>/dev/null; then",
                f"  cat {shlex.quote(stderr_path)} >&2 || true",
                f"  echo udp_responder_{port}=failed >&2",
                "  exit 73",
                "fi",
                f"echo udp_responder_{port}=running",
            ]
        )
    if arp_plans:
        # The ARP kernel-state setup block moved to
        # ``protocols.arp.arp_target_setup_lines``; render it here so the
        # script bytes stay byte-identical to the legacy inline block.
        lines.extend(
            arp_target_setup_lines(
                artifact_root=artifact_root,
                arp_plans=arp_plans,
            )
        )
    if ndp_plans:
        wants_router = any(
            str(plan.get("case", "")) in _NDP_ROUTER_CASES for plan in ndp_plans
        )
        lines.extend(_ndp_target_setup_lines(wants_router=wants_router))
    # Fold in each registered plugin's setup-script block after the legacy
    # per-protocol blocks, preserving block ordering. Migrated protocols emit
    # their own responder heredocs here; with an empty registry no plugin
    # contributes, so the script bytes are byte-identical to the legacy output.
    lines.extend(
        _registry_setup_script_lines(
            artifact_root=artifact_root,
            bind_ipv4=bind_ipv4,
            target_interface=target_interface,
        )
    )
    lines.append("echo target_service_setup=ok")
    return "\n".join(lines)


def _registry_setup_script_lines(
    *,
    artifact_root: str,
    bind_ipv4: str,
    target_interface: str,
) -> list[str]:
    """Return the setup-script lines contributed by registered plugins.

    Each registered plugin's optional ``setup_script(ctx)`` hook returns the
    block of script lines for that protocol's responder/provisioning. The blocks
    are concatenated in sorted-plugin order. Empty until a protocol migrates, so
    this returns ``[]`` and the assembled script is byte-identical to the legacy
    output.
    """

    lines: list[str] = []
    for plugin in registered_plugins():
        if plugin.setup_script is None:
            continue
        block = plugin.setup_script(
            artifact_root=artifact_root,
            bind_ipv4=bind_ipv4,
            target_interface=target_interface,
        )
        if isinstance(block, Sequence) and not isinstance(block, (str, bytes)):
            lines.extend(str(line) for line in block)
    return lines


def _ndp_target_setup_lines(*, wants_router: bool) -> list[str]:
    """Render the NDP/IPv6 kernel setup block for the target setup script.

    A bare Linux kernel already owns a modified-EUI-64 link-local address on
    every IPv6-enabled interface and auto-answers a Neighbor Solicitation for it
    (and defends it on Duplicate Address Detection), so the Neighbor Solicitation
    and DAD cases need only that IPv6 is enabled on the private interface, that
    the link-local has finished Duplicate Address Detection, and that the IPv6
    neighbor cache is clean so the kernel re-answers. The Router Solicitation
    case additionally needs the target to act as an RA-emitting router; the block
    enables IPv6 forwarding and per-interface RA emission best-effort (a bare
    kernel without forwarding does not answer a Router Solicitation). Every
    sysctl change records its restore command into the cleanup script so the
    disposable endpoint is returned to its prior state on teardown.
    """

    lines = [
        'if [ -z "$target_interface" ]; then',
        "  echo ndp_target_interface=missing >&2",
        "  exit 73",
        "fi",
        'ip link show dev "$target_interface" >/dev/null',
        # Enable IPv6 on the private interface and accept the kernel's link-local.
        'for key in disable_ipv6 accept_dad; do',
        '  sysctl_name="net.ipv6.conf.${target_interface}.${key}"',
        '  before_path="$artifact_root/ndp-${key}.before"',
        '  sysctl -n "$sysctl_name" > "$before_path" 2>/dev/null || true',
        '  before_value=""',
        '  if [ -s "$before_path" ]; then before_value="$(cat "$before_path")"; fi',
        '  if [ -n "$before_value" ]; then',
        '    printf \'%s\\n\' "sysctl -w ${sysctl_name}=${before_value} >/dev/null 2>&1 || true" >> "$cleanup"',
        "  fi",
        "done",
        # disable_ipv6=0 keeps IPv6 on; accept_dad=1 lets the link-local finish DAD.
        'sysctl -w "net.ipv6.conf.${target_interface}.disable_ipv6=0" >/dev/null 2>&1 || true',
        'sysctl -w "net.ipv6.conf.${target_interface}.accept_dad=1" >/dev/null 2>&1 || true',
        'ip link set dev "$target_interface" up || true',
        # Give the kernel a moment to assign the link-local and finish DAD so it
        # answers a solicitation for the address it owns.
        'for _ in 1 2 3 4 5 6 7 8 9 10; do',
        '  if ip -6 addr show dev "$target_interface" scope link | grep -q "inet6 fe80:"; then break; fi',
        "  sleep 1",
        "done",
        'link_local="$(ip -6 addr show dev "$target_interface" scope link 2>/dev/null '
        "| awk '/inet6 fe80:/ {print $2}' | head -1)\"",
        'printf \'%s\\n\' "ip -6 neigh flush dev $target_interface || true" >> "$cleanup"',
        'ip -6 neigh flush dev "$target_interface" 2>/dev/null || true',
        'echo "ndp_link_local=${link_local:-none}"',
        "echo ndp_kernel_state=configured",
    ]
    if wants_router:
        lines.extend(
            [
                # Router Solicitation needs the target to emit Router
                # Advertisements. Enable IPv6 forwarding so the kernel acts as a
                # router; per-interface RA emission still depends on the kernel
                # build, so this is best-effort and the case skips cleanly if no
                # RA arrives.
                'for key in forwarding; do',
                '  sysctl_name="net.ipv6.conf.${target_interface}.${key}"',
                '  before_path="$artifact_root/ndp-router-${key}.before"',
                '  sysctl -n "$sysctl_name" > "$before_path" 2>/dev/null || true',
                '  before_value=""',
                '  if [ -s "$before_path" ]; then before_value="$(cat "$before_path")"; fi',
                '  if [ -n "$before_value" ]; then',
                '    printf \'%s\\n\' "sysctl -w ${sysctl_name}=${before_value} >/dev/null 2>&1 || true" >> "$cleanup"',
                "  fi",
                "done",
                'sysctl -w "net.ipv6.conf.${target_interface}.forwarding=1" >/dev/null 2>&1 || true',
                "echo ndp_router_state=configured",
            ]
        )
    return lines


__all__ = [
    "KernelStateDescriptor",
    "TargetServiceDescriptor",
    "arp_alias_descriptor",
    "arp_decoy_events",
    "arp_extra_addresses",
    "arp_kernel_state_plan",
    "arp_probe_plans",
    "arp_sysctl_descriptor",
    "cleanup_wire_probe_target",
    "closed_udp_probe_plans",
    "closed_udp_port_descriptor",
    "dedupe_ints",
    "dhcp_probe_plans",
    "dhcp_responder_descriptor",
    "dns_probe_plans",
    "dns_responder_descriptor",
    "plans_by_destination_port",
    "prepare_wire_probe_target",
    "target_service_address_fields",
    "target_service_setup_plan",
    "target_service_setup_script",
    "tcp_probe_plans",
    "udp_probe_plans",
    "udp_responder_descriptor",
]
