"""The per-protocol plugin contract and registry for the probe engine.

A :class:`ProtocolPlugin` bundles a single protocol's entire surface so the six
central case-name dispatchers can be fed from one place per protocol instead of
the historical 5-7-way duplication:

* the plan builders (``planning.PLAN_BUILDERS`` + planned-only set),
* the cases and their profile membership / default-count contribution
  (``cases.PROBE_CASES`` / ``cases._PROFILE_*``),
* the target-service setup-plan and setup-script contributions
  (``target_services.target_service_setup_plan`` / ``..._script``),
* the stimulus-endpoint routing set (``cli._STIMULUS_ENDPOINT_CASES``),
* the live-path address rewrite + failure-reason taxonomy
  (``cli._probe_plan_with_endpoint_addresses`` / ``_failure_reasons_for_case``),
* and the lab-capability derivation
  (``lab.probe_capabilities_from_lab_capabilities``).

This step only introduces the contract, an empty registry, and the
auto-discovery entrypoint; no protocol is migrated, so the registry is empty and
every dispatcher still flows through the existing legacy code. The field shapes
are chosen to reproduce each legacy dispatcher byte-identically when protocols
do migrate.

Imports are relative only: the engine is imported both as ``engine.*`` (the CLI,
``python -m engine.cli``) and as ``tools.probe.engine.*`` (the tests), so this
module must not assume either import root.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from ..model import JSONObject, ProbeCase
from ..planning_helpers import PlanBuilder
from ..plugin_registry import PluginRegistry


# Optional per-protocol callables. Each mirrors the signature of the legacy
# dispatcher branch it replaces so a migrated plugin reproduces it byte-for-byte.
#
# ``target_service``: given the probe plans selected for this protocol, return
#   the protocol's contribution to ``target_service_setup_plan`` (services,
#   closed-port entries, kernel-state contracts, ...).
# ``setup_script``: given the setup context, return the protocol's contribution
#   to ``target_service_setup_script`` (responder heredocs, provisioning steps).
# ``rewrite_endpoint_addresses``: given a single plan plus the rewrite context,
#   return the live-path address-rewritten plan for this protocol's cases.
# ``failure_reasons``: given a case name owned by this protocol, return its
#   ordered failure-reason taxonomy, or ``None`` to fall through.
# ``lab_capabilities``: given the substrate capability mapping, return this
#   protocol's contribution to the derived probe capability mapping.
# ``live_plan_candidates``: given the full batched live probe-plan sequence,
#   return a transformed plan sequence (e.g. ARP's batched sender-protocol
#   candidate annotation). The hook receives every plan so it can read cross-plan
#   context (sibling target-service addresses) and must return the full sequence;
#   ``live.plans_with_live_plan_candidates`` folds each plugin's transform in
#   registry order so the live path stays protocol-agnostic.
# ``ipsec_interop``: the IPSec-only cross-crypto interop dry-run hook.
TargetServiceHook = Callable[..., object]
SetupScriptHook = Callable[..., object]
RewriteEndpointAddressesHook = Callable[..., JSONObject]
FailureReasonsHook = Callable[[str], "list[str] | None"]
LabCapabilitiesHook = Callable[..., Mapping[str, object]]
LivePlanCandidatesHook = Callable[..., "list[JSONObject]"]
IpsecInteropHook = Callable[..., object]


@dataclass(frozen=True, slots=True)
class ProtocolPlugin:
    """One protocol's full probe surface, declared in a single place.

    ``name`` is the registry key (the protocol label, e.g. ``"arp"``). The
    remaining fields are the per-concern contributions the six central
    dispatchers fold over; the optional callables default to ``None`` when a
    protocol does not participate in that concern.
    """

    name: str
    cases: tuple[ProbeCase, ...] = ()
    plan_builders: Mapping[str, PlanBuilder] = field(default_factory=dict)
    planned_only_cases: frozenset[str] = frozenset()
    profile_counts: Mapping[str, Mapping[str, int]] = field(default_factory=dict)
    stimulus_endpoint_cases: frozenset[str] = frozenset()
    target_service: TargetServiceHook | None = None
    setup_script: SetupScriptHook | None = None
    rewrite_endpoint_addresses: RewriteEndpointAddressesHook | None = None
    failure_reasons: FailureReasonsHook | None = None
    lab_capabilities: LabCapabilitiesHook | None = None
    live_plan_candidates: LivePlanCandidatesHook | None = None
    ipsec_interop: IpsecInteropHook | None = None


# The single registry every probe protocol plugin registers into. It is empty
# until a protocol module calls :func:`register`; the auto-discovery in
# ``protocols/__init__`` imports each protocol module so its ``register(...)``
# call runs at import time.
PROTOCOL_REGISTRY: PluginRegistry[ProtocolPlugin] = PluginRegistry("probe-protocol")


def register(plugin: ProtocolPlugin) -> None:
    """Register ``plugin`` under its ``name``; raise on a duplicate name."""

    PROTOCOL_REGISTRY.register(plugin.name, plugin)


def registered_plugins() -> tuple[ProtocolPlugin, ...]:
    """Return every registered plugin in sorted-name order."""

    return PROTOCOL_REGISTRY.values()


def all_cases() -> tuple[ProbeCase, ...]:
    """Return every plugin's cases, concatenated in sorted-name order.

    Empty while no protocol is migrated. Wirings merge this with the legacy
    ``cases.PROBE_CASES`` aggregation.
    """

    cases: list[ProbeCase] = []
    for plugin in registered_plugins():
        cases.extend(plugin.cases)
    return tuple(cases)


def all_plan_builders() -> dict[str, PlanBuilder]:
    """Return the merged ``case_name -> builder`` map across plugins.

    Empty while no protocol is migrated. Wirings merge this with the legacy
    ``planning.PLAN_BUILDERS`` dict.
    """

    builders: dict[str, PlanBuilder] = {}
    for plugin in registered_plugins():
        for case_name, builder in plugin.plan_builders.items():
            builders[case_name] = builder
    return builders


def all_planned_only_cases() -> frozenset[str]:
    """Return the union of every plugin's planned-only case names."""

    names: set[str] = set()
    for plugin in registered_plugins():
        names.update(plugin.planned_only_cases)
    return frozenset(names)


def all_profile_counts() -> dict[str, dict[str, int]]:
    """Return the merged per-profile case-count contributions across plugins.

    Profiles are keyed to ``case_name -> count`` mappings, accumulated across
    plugins so several protocols can contribute to the same profile.
    """

    counts: dict[str, dict[str, int]] = {}
    for plugin in registered_plugins():
        for profile, contribution in plugin.profile_counts.items():
            profile_counts = counts.setdefault(profile, {})
            for case_name, count in contribution.items():
                profile_counts[case_name] = count
    return counts


def all_stimulus_endpoint_cases() -> frozenset[str]:
    """Return the union of every plugin's stimulus-endpoint case names."""

    names: set[str] = set()
    for plugin in registered_plugins():
        names.update(plugin.stimulus_endpoint_cases)
    return frozenset(names)


def ipsec_interop_plugin() -> ProtocolPlugin | None:
    """Return the registered plugin that owns the ``ipsec_interop`` hook.

    The cross-crypto IPSec interop dry-run check is a single-protocol concern
    (only the IPSec plugin sets ``ipsec_interop``), so this returns the first
    registered plugin whose ``ipsec_interop`` hook is non-``None``, or ``None``
    when no plugin participates. ``cli._dry_run_report`` routes the IPSec dry-run
    interop metadata through this accessor instead of an inline branch.
    """

    for plugin in registered_plugins():
        if plugin.ipsec_interop is not None:
            return plugin
    return None
