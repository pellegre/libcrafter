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

import posixpath
import shlex
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from .capabilities import (
    SKIP_REQUIRES_CONTROLLED_ROUTER,
    SKIP_REQUIRES_LINK_LAYER,
)
from .lab import TARGET_ROLE
from .model import JSONObject, JSONValue

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

# DNS's target-service descriptor, plan selector, and the setup-script blocks
# were migrated into the DNS plugin (:mod:`tools.probe.engine.protocols.dns`).
# They are re-imported here so ``target_services.dns_responder_descriptor`` /
# ``target_services.dns_probe_plans`` keep resolving (the behavior/script tests,
# ``prepare_wire_probe_target``, and ``__all__`` reference them), and so
# ``target_service_setup_script`` can render the DNS setup blocks. The DNS
# responder case set (``_DNS_RESPONDER_CASES``) is no longer re-imported: the
# registry partition diverts the DNS cases to the plugin's ``target_service``
# hook, so the legacy plan body no longer selects them and no caller references
# ``target_services._DNS_RESPONDER_CASES``. The DNS plugin module does not import
# ``target_services``, so this does not cycle.
from .protocols.dns import (
    dns_port_check_lines,
    dns_probe_plans,
    dns_responder_descriptor,
    dns_responder_setup_lines,
)

# DHCP's target-service descriptor, plan selector, and the setup-script blocks
# were migrated into the DHCP plugin (:mod:`tools.probe.engine.protocols.dhcp`).
# They are re-imported here so ``target_services.dhcp_responder_descriptor`` /
# ``target_services.dhcp_probe_plans`` keep resolving (the behavior/script tests,
# ``prepare_wire_probe_target``, and ``__all__`` reference them), and so
# ``target_service_setup_script`` can render the DHCP setup blocks. The DHCP
# responder case set (``_DHCP_RESPONDER_CASES``) is no longer re-imported: the
# registry partition diverts the DHCP cases to the plugin's ``target_service``
# hook, so the legacy plan body no longer selects them and no caller references
# ``target_services._DHCP_RESPONDER_CASES``. The DHCP plugin module does not
# import ``target_services``, so this does not cycle.
from .protocols.dhcp import (
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

# TCP's plan selector (``tcp_probe_plans``) and the setup-script blocks (the
# closed-TCP-port free check and the open-listener heredoc + launch) were
# migrated into the TCP plugin (:mod:`tools.probe.engine.protocols.tcp`). They are
# re-imported here so ``target_services.tcp_probe_plans`` keeps resolving (``live.py``
# / ``prepare_wire_probe_target`` use it, and the partition reroutes the TCP cases
# to the plugin's ``target_service`` hook), and so ``target_service_setup_script``
# can render the TCP setup blocks. The TCP plugin module does not import
# ``target_services``, so this does not cycle.
from .protocols.tcp import (
    tcp_closed_port_check_lines,
    tcp_open_listener_setup_lines,
    tcp_probe_plans,
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

# QUIC's live-capable initial observation uses the same controlled UDP echo
# responder as the UDP behavioral cases. The QUIC plugin contributes the
# target-service metadata; this selector lets live target setup render the
# existing UDP responder script for QUIC plans without a second service
# implementation.
from .protocols.quic import quic_udp_probe_plans

# BGP's target-service constants, the ``frr_bgp_peer_descriptor``, the FRR BGP
# peer service-plan builder, the ``bgp-`` name-prefix plan selector
# (``probe_plan_requires_bgp_peer``), and the ``bgp_peer_probe_plans`` selector
# were migrated into the BGP plugin
# (:mod:`tools.probe.engine.protocols.bgp`). They are re-imported here so
# ``target_services.frr_bgp_peer_descriptor`` (and the ``BGP_*`` constants) keep
# resolving (the script test and any caller reference them). The BGP plugin's
# ``target_service`` hook now contributes the FRR BGP peer service entry, so the
# partition reroutes the BGP case to the plugin and the legacy setup-plan body no
# longer builds it. The BGP plugin module does not import ``target_services``, so
# this does not cycle.
from .protocols.bgp import (  # noqa: F401  (re-exported for resolvability)
    BGP_DOCUMENTATION_IPV4_PREFIX,
    BGP_DOCUMENTATION_IPV6_PREFIX,
    BGP_DRIVER_AS,
    BGP_FRR_TEMPLATE,
    BGP_PEER_AS,
    BGP_PROVISION_SCRIPT,
    BGP_RIB_COMMAND,
    BGP_RUNTIME,
    BGP_SERVICE_KIND,
    BGP_SERVICE_PORT,
    bgp_peer_probe_plans,
    bgp_peer_service_plans,
    frr_bgp_peer_descriptor,
    probe_plan_requires_bgp_peer,
)
from .protocols.mqtt import (  # noqa: F401  (re-exported for resolvability)
    MQTT_CONFIG_TEMPLATE,
    MQTT_PROVISION_SCRIPT,
    MQTT_RUNTIME,
    MQTT_SERVICE_KIND,
    MQTT_SERVICE_PORT,
    mqtt_broker_descriptor,
    mqtt_broker_probe_plans,
    mqtt_broker_service_plans,
    probe_plan_requires_mqtt_broker,
)
from .target_service_helpers import (
    KernelStateDescriptor,
    TargetServiceDescriptor,
    dedupe_ints,
    plans_by_destination_port,
    target_service_address_fields,
)


# A lab-wire helper that resolves an endpoint mapping to its endpoint ID.
EndpointIdResolver = Callable[..., str]
# A lab-wire helper that resolves an endpoint mapping to its bind IPv4 address.
EndpointIpv4Resolver = Callable[..., str]
# A lab-wire helper that resolves an endpoint mapping to its packet interface.
EndpointInterfaceResolver = Callable[..., str]
# A lab-wire helper that runs a wire command response and records its artifacts.
WireCommandRunner = Callable[..., JSONObject]

# The BGP target-service constants (``BGP_SERVICE_KIND`` / ``BGP_SERVICE_PORT`` /
# ``BGP_RUNTIME`` / ``BGP_DRIVER_AS`` / ``BGP_PEER_AS`` / the documentation
# prefixes / ``BGP_PROVISION_SCRIPT`` / ``BGP_FRR_TEMPLATE`` / ``BGP_RIB_COMMAND``)
# now live in the BGP plugin module (``protocols/bgp.py``) and are re-imported
# above so ``target_services.BGP_*`` keeps resolving.

# The MQTT target-service constants, descriptor, and broker service-plan selectors
# now live in the MQTT plugin module (``protocols/mqtt.py``) and are re-imported
# above so ``target_services.MQTT_*`` and ``target_services.mqtt_*`` keep resolving.

# The RIP target-service constants (``RIP_SERVICE_KIND`` / ``RIP_SERVICE_PORTS`` /
# ``RIP_RUNTIME`` / ``RIP_MULTICAST_GROUP`` / ``RIP_DOCUMENTATION_IPV4_PREFIX`` /
# ``RIP_PROVISION_SCRIPT`` / ``RIP_CONFIG_TEMPLATE`` / ``RIP_RIB_COMMAND``) and the
# ``rip_peer_service_descriptor`` now live in the RIP plugin module
# (``protocols/rip.py``). RIP/RIPng never produced a ``target_service_setup_plan``
# service entry (the legacy setup plan only builds the BGP peer via the
# ``bgp-`` / ``frr-bgp-peer`` selector), so nothing in this module references
# them: the descriptor is a plan-building input the RIP plan builder calls
# directly.


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


# The FRR BGP peer descriptor (``frr_bgp_peer_descriptor``) now lives in the BGP
# plugin module (``protocols/bgp.py``) and is re-imported above so
# ``target_services.frr_bgp_peer_descriptor`` keeps resolving for the script test.


# The FRR ``ripd`` peer descriptor (``rip_peer_service_descriptor``) now lives in
# the RIP plugin module (``protocols/rip.py``); the RIP plan builder calls it to
# render the IPv4 RIP plan's target-service block. Nothing in this module
# references it.


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

    bgp_plans = bgp_peer_probe_plans(probe_plans)
    mqtt_plans = mqtt_broker_probe_plans(probe_plans)
    arp_plans = arp_probe_plans(probe_plans)
    return {
        "role": "target",
        "planned": True,
        # The ``tcp-open-listener`` services and ``closed_tcp_ports`` entries (and
        # their ``starts_services`` contribution) moved to the TCP plugin's
        # ``target_service`` hook; the ``udp-responder`` services and
        # ``closed_udp_ports`` entries (and their ``starts_services`` contribution)
        # moved to the UDP plugin's ``target_service`` hook. The registry partition
        # diverts the TCP and UDP cases off this legacy path, so this body sees no
        # TCP or UDP plans.
        #
        # The BGP plugin's ``target_service`` hook owns the FRR BGP peer service
        # entry for the ``bgp-session-smoke`` case (the only real BGP case); the
        # partition diverts that case to the plugin. This legacy body keeps the BGP
        # build for any *other* plan that requests the peer through the ``bgp-``
        # name-prefix or the ``frr-bgp-peer`` ``target_service.kind`` (which the
        # partition does not divert because such a plan's case is not in the plugin's
        # case set). In a real run those plans never occur -- the only BGP case is
        # ``bgp-session-smoke``, served by the plugin -- so this legacy build is
        # exercised only by the kind/prefix coverage tests and stays byte-identical
        # to the pre-migration behavior for them.
        "starts_services": not dry_run and bool(bgp_plans or mqtt_plans),
        "dry_run_starts_services": False,
        "services": [
            *bgp_peer_service_plans(bgp_plans),
            *mqtt_broker_service_plans(mqtt_plans),
        ],
        "closed_tcp_ports": [],
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


# The FRR BGP peer service-plan builder (``bgp_peer_service_plans``) now lives in
# the BGP plugin module (``protocols/bgp.py``) and is re-imported above so
# ``target_services.bgp_peer_service_plans`` keeps resolving; the BGP plugin's
# ``target_service`` hook calls it to contribute the FRR BGP peer service entry.


# The ARP kernel-state plan (``arp_kernel_state_plan``) now lives in
# :mod:`tools.probe.engine.protocols.arp`; the ARP plugin's ``target_service``
# hook contributes the ``arp_kernel_state`` key to the central setup plan. It is
# re-imported below so ``target_services.arp_kernel_state_plan`` keeps resolving.


# --------------------------------------------------------------------------- #
# Plan filters and small helpers
# --------------------------------------------------------------------------- #


# The TCP plan selector (``tcp_probe_plans``) now lives in
# :mod:`tools.probe.engine.protocols.tcp` and is re-imported above so
# ``target_services.tcp_probe_plans`` keeps resolving (``live.py`` /
# ``prepare_wire_probe_target`` use it; the partition reroutes the TCP plans to
# the plugin's ``target_service`` hook).


# The DNS responder case set (``_DNS_RESPONDER_CASES``) and the ``dns_probe_plans``
# selector now live in :mod:`tools.probe.engine.protocols.dns`. ``dns_probe_plans``
# is re-imported above so ``target_services.dns_probe_plans`` keeps resolving for
# ``prepare_wire_probe_target`` / the tests (the partition reroutes DNS plans to
# the plugin's ``target_service`` hook). ``_DNS_RESPONDER_CASES`` is no longer
# re-imported: the legacy plan body no longer selects DNS cases and no caller
# references it.


# The ``bgp_peer_probe_plans`` selector and the ``bgp-`` name-prefix dispatch
# (``probe_plan_requires_bgp_peer``) now live in the BGP plugin module
# (``protocols/bgp.py``) and are re-imported above so
# ``target_services.bgp_peer_probe_plans`` / ``target_services.probe_plan_requires_bgp_peer``
# keep resolving; the BGP plugin's ``target_service`` hook uses them to gate the
# FRR BGP peer service entry.


# The ``mqtt_broker_probe_plans`` selector and the ``mqtt-`` name-prefix dispatch
# (``probe_plan_requires_mqtt_broker``) now live in the MQTT plugin module
# (``protocols/mqtt.py``) and are re-imported above so
# ``target_services.mqtt_broker_probe_plans`` /
# ``target_services.probe_plan_requires_mqtt_broker`` keep resolving.


# The DHCP responder case set (``_DHCP_RESPONDER_CASES``) and the
# ``dhcp_probe_plans`` selector now live in
# :mod:`tools.probe.engine.protocols.dhcp`. ``dhcp_probe_plans`` is re-imported
# above so ``target_services.dhcp_probe_plans`` keeps resolving for
# ``prepare_wire_probe_target`` / the tests (the partition reroutes DHCP plans to
# the plugin's ``target_service`` hook). ``_DHCP_RESPONDER_CASES`` is no longer
# re-imported: the legacy plan body no longer selects DHCP cases and no caller
# references it.


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
    udp_plans = [*udp_probe_plans(probe_plans), *quic_udp_probe_plans(probe_plans)]
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
    # The closed-TCP-port free-check moved to
    # ``protocols.tcp.tcp_closed_port_check_lines``; render it here so the script
    # bytes stay byte-identical to the legacy inline ``for port in closed_ports:``
    # loop.
    lines.extend(tcp_closed_port_check_lines(closed_ports))
    # The closed-UDP-port free-check moved to
    # ``protocols.udp.udp_closed_port_check_lines``; render it here so the script
    # bytes stay byte-identical to the legacy inline ``for port in closed_udp_ports:``
    # loop.
    lines.extend(udp_closed_port_check_lines(closed_udp_ports))
    # The TCP open-listener heredoc + launch block moved to
    # ``protocols.tcp.tcp_open_listener_setup_lines``; render it here so the script
    # bytes stay byte-identical to the legacy inline ``for port in open_ports:``
    # loop.
    lines.extend(
        tcp_open_listener_setup_lines(
            artifact_root=artifact_root,
            open_ports=open_ports,
        )
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
    "mqtt_broker_descriptor",
    "mqtt_broker_probe_plans",
    "mqtt_broker_service_plans",
    "MQTT_CONFIG_TEMPLATE",
    "MQTT_PROVISION_SCRIPT",
    "MQTT_RUNTIME",
    "MQTT_SERVICE_KIND",
    "MQTT_SERVICE_PORT",
    "plans_by_destination_port",
    "prepare_wire_probe_target",
    "probe_plan_requires_mqtt_broker",
    "target_service_address_fields",
    "target_service_setup_plan",
    "target_service_setup_script",
    "tcp_closed_port_check_lines",
    "tcp_open_listener_setup_lines",
    "tcp_probe_plans",
    "udp_probe_plans",
    "udp_responder_descriptor",
]
