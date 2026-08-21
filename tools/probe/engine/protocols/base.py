"""Per-protocol deterministic probe-plan registry.

Plugins describe packet cases, deterministic builders, profile membership, and
which cases the bounded local stimulus executable understands. Machine
selection, capability translation, target provisioning, and execution topology
are deliberately outside this repository.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from ..model import JSONObject, ProbeCase
from ..planning_helpers import PlanBuilder
from ..plugin_registry import PluginRegistry


# Optional validation hooks stay local and deterministic.
FailureReasonsHook = Callable[[str], "list[str] | None"]
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
    failure_reasons: FailureReasonsHook | None = None
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
