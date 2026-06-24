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

# DHCP's target-service descriptor, responder case set, plan selector, and the
# setup-script blocks were migrated into the DHCP plugin
# (:mod:`tools.probe.engine.protocols.dhcp`). They are re-imported here so
# ``target_services.dhcp_responder_descriptor`` / ``target_services._DHCP_RESPONDER_CASES``
# / ``target_services.dhcp_probe_plans`` keep resolving (the behavior/script tests,
# ``prepare_wire_probe_target``, and ``__all__`` reference them), and so
# ``target_service_setup_script`` can render the DHCP setup blocks. The DHCP plugin
# module does not import ``target_services``, so this does not cycle.
from .protocols.dhcp import (
    _DHCP_RESPONDER_CASES,
    dhcp_port_check_lines,
    dhcp_probe_plans,
    dhcp_responder_descriptor,
    dhcp_responder_setup_lines,
)

# UDP's target-service descriptors (responder + closed-port), responder /
# closed-port case sets, plan selectors, and the setup-script blocks (the
# closed-UDP-port free check and the responder heredoc + launch) were migrated
# into the UDP plugin (:mod:`tools.probe.engine.protocols.udp`). They are
# re-imported here so ``target_services.udp_responder_descriptor`` /
# ``target_services.closed_udp_port_descriptor`` /
# ``target_services._UDP_RESPONDER_CASES`` / ``target_services._UDP_CLOSED_PORT_CASES``
# / ``target_services.udp_probe_plans`` / ``target_services.closed_udp_probe_plans``
# keep resolving (the behavior/script tests, ``prepare_wire_probe_target``, and
# ``__all__`` reference them), and so ``target_service_setup_script`` can render
# the UDP setup blocks. The UDP plugin module does not import ``target_services``,
# so this does not cycle.
from .protocols.udp import (
    _UDP_CLOSED_PORT_CASES,
    _UDP_RESPONDER_CASES,
    closed_udp_port_descriptor,
    closed_udp_probe_plans,
    udp_closed_port_check_lines,
    udp_probe_plans,
    udp_responder_descriptor,
    udp_responder_setup_lines,
)

# NDP's kernel case set, plan selector, and the IPv6/kernel setup-script block
# were migrated into the NDP plugin (:mod:`tools.probe.engine.protocols.ndp`).
# They are re-imported here so ``target_services.ndp_probe_plans`` keeps
# resolving (``prepare_wire_probe_target`` uses it, the partition reroutes NDP
# cases to the plugin's ``target_service`` hook), and so
# ``target_service_setup_script`` can render the NDP setup block. The NDP plugin
# module does not import ``target_services``, so this does not cycle.
from .protocols.ndp import (
    ndp_probe_plans,
    ndp_target_setup_lines,
)
from .target_service_helpers import (
    KernelStateDescriptor,
    TargetServiceDescriptor,
    dedupe_ints,
    plans_by_destination_port,
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


# The UDP target-service descriptor (``udp_responder_descriptor``) now lives in
# :mod:`tools.probe.engine.protocols.udp` and is re-imported above so
# ``target_services.udp_responder_descriptor`` keeps resolving for the
# behavior/script tests.


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


# The closed-UDP-port descriptor (``closed_udp_port_descriptor``) now lives in
# :mod:`tools.probe.engine.protocols.udp` and is re-imported above so
# ``target_services.closed_udp_port_descriptor`` keeps resolving for the
# behavior/script tests.


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
    bgp_plans = bgp_peer_probe_plans(probe_plans)
    arp_plans = arp_probe_plans(probe_plans)
    return {
        "role": "target",
        "planned": True,
        # The ``udp-responder`` services and ``closed_udp_ports`` entries (and
        # their ``starts_services`` contribution) moved to the UDP plugin's
        # ``target_service`` hook; the registry partition diverts the UDP cases off
        # this legacy path, so this body sees no UDP plans.
        "starts_services": not dry_run
        and bool(
            tcp_open_plans
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
        "closed_udp_ports": [],
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


# The DHCP responder case set (``_DHCP_RESPONDER_CASES``) and the
# ``dhcp_probe_plans`` selector now live in
# :mod:`tools.probe.engine.protocols.dhcp`; they are re-imported above so
# ``target_services._DHCP_RESPONDER_CASES`` / ``target_services.dhcp_probe_plans``
# keep resolving for ``prepare_wire_probe_target`` / the tests (the partition
# reroutes DHCP plans to the plugin's ``target_service`` hook).


# The UDP responder / closed-port case sets (``_UDP_RESPONDER_CASES`` /
# ``_UDP_CLOSED_PORT_CASES``) and the ``udp_probe_plans`` / ``closed_udp_probe_plans``
# selectors now live in :mod:`tools.probe.engine.protocols.udp`; they are
# re-imported above so ``target_services._UDP_RESPONDER_CASES`` /
# ``target_services._UDP_CLOSED_PORT_CASES`` / ``target_services.udp_probe_plans``
# / ``target_services.closed_udp_probe_plans`` keep resolving for the legacy plan
# body (the partition reroutes UDP plans to the plugin's ``target_service`` hook),
# for ``prepare_wire_probe_target`` / ``target_service_setup_script``, and for the
# behavior/script tests.


# The ARP kernel case set (``_ARP_KERNEL_CASES``) and the ``arp_probe_plans``
# selector now live in :mod:`tools.probe.engine.protocols.arp`; they are
# re-imported below so ``target_services._ARP_KERNEL_CASES`` /
# ``target_services.arp_probe_plans`` keep resolving for the legacy plan body
# (which now sees no ARP plans) and the behavior/script tests.


# The NDP kernel case set (``_NDP_KERNEL_CASES`` / ``_NDP_ROUTER_CASES``), the
# ``ndp_probe_plans`` selector, and the IPv6/kernel setup-script block
# (``ndp_target_setup_lines``) now live in
# :mod:`tools.probe.engine.protocols.ndp`; ``ndp_probe_plans`` /
# ``ndp_target_setup_lines`` are re-imported above so
# ``target_services.ndp_probe_plans`` keeps resolving for
# ``prepare_wire_probe_target`` (the partition reroutes NDP cases to the plugin's
# ``target_service`` hook) and ``target_service_setup_script`` can render the NDP
# setup block.


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
    # The DHCP per-port UDP port-free check moved to
    # ``protocols.dhcp.dhcp_port_check_lines``; render it here so the script bytes
    # stay byte-identical to the legacy inline ``for port in dhcp_ports:`` loop.
    lines.extend(dhcp_port_check_lines(dhcp_plans))
    for port in closed_ports:
        lines.append(f"check_port_free \"$tcp_bind_ipv4\" {port}")
        lines.append(f"echo closed_port_{port}=free")
    # The closed-UDP-port free-check moved to
    # ``protocols.udp.udp_closed_port_check_lines``; render it here so the script
    # bytes stay byte-identical to the legacy inline ``for port in closed_udp_ports:``
    # loop.
    lines.extend(udp_closed_port_check_lines(closed_udp_ports))
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
    # The DHCP responder heredoc + launch block moved to
    # ``protocols.dhcp.dhcp_responder_setup_lines``; render it here so the
    # script bytes stay byte-identical to the legacy inline blocks.
    lines.extend(
        dhcp_responder_setup_lines(
            artifact_root=artifact_root,
            dhcp_plans=dhcp_plans,
        )
    )
    # The UDP responder heredoc + launch block moved to
    # ``protocols.udp.udp_responder_setup_lines``; render it here so the script
    # bytes stay byte-identical to the legacy inline blocks.
    lines.extend(
        udp_responder_setup_lines(
            artifact_root=artifact_root,
            udp_plans=udp_plans,
        )
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
        # The NDP/IPv6 kernel-state setup block moved to
        # ``protocols.ndp.ndp_target_setup_lines``; render it here so the script
        # bytes stay byte-identical to the legacy inline block.
        lines.extend(ndp_target_setup_lines(ndp_plans=ndp_plans))
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
