"""BGP probe protocol plugin: case, plan builder, and full live surface.

This is the BGP full migration (a single step). BGP has a small surface -- one
planned-only ``bgp-session-smoke`` case driving a probe-owned FRR peer target
service -- so its entire surface fits in one step:

* the ``bgp-session-smoke`` case (built through the ``_behavior_case`` factory)
  and its ``_BGP_CAPABILITIES`` constant (the catalog contribution),
* the ``_bgp_session_smoke_probe_plan`` plan builder, the planned-only set, and
  the BGP service constants the plan and descriptor reference,
* the ``target_service`` hook (the probe-owned FRR BGP peer service entry and the
  ``starts_services`` flip on a live run), backed by the ``frr_bgp_peer_descriptor``
  + the ``bgp-`` name-prefix plan selector (``probe_plan_requires_bgp_peer``),
* the ``rewrite_endpoint_addresses`` hook (``None``: ``bgp-session-smoke`` is
  planned-only and was never stimulus-routed, so the live-path rewrite never
  reached BGP -- there is no legacy BGP rewrite branch to reproduce),
* the ``failure_reasons`` hook (``None``: BGP had no failure-reason branch in
  ``cli._failure_reasons_for_case`` and fell through to the shared default), and
* the ``lab_capabilities`` hook (the ``bgp_peer`` derived capability).

The plan builder is moved verbatim from :mod:`tools.probe.engine.planning`;
:mod:`planning` re-imports it so ``planning._bgp_session_smoke_probe_plan`` /
``planning.PLAN_BUILDERS["bgp-session-smoke"]`` keep identical object identity for
any pin. The ``frr_bgp_peer_descriptor`` + ``probe_plan_requires_bgp_peer`` +
``bgp_peer_service_plans`` + ``bgp_peer_probe_plans`` selectors are moved verbatim
from :mod:`tools.probe.engine.target_services`; that module re-imports them so
``target_services.frr_bgp_peer_descriptor`` (and the constants) keep resolving for
the script tests, and so the legacy setup-plan / partition code stays byte-identical.

BGP's ``profile_counts`` is intentionally empty: ``bgp-session-smoke`` rides the
``bgp-smoke`` profile in a fixed position, and the registry-first profile merge
would move the registry contribution to the front of that profile, so the legacy
ordered profile name table in :mod:`tools.probe.engine.cases`
(``BGP_SESSION_PROFILE_CASE_NAMES``, now sourced from the registered BGP case)
keeps owning BGP's profile membership to preserve byte-identical selection order.

The ``bgp-`` *name-prefix* dispatch in ``probe_plan_requires_bgp_peer`` is
preserved exactly: a probe plan requests the FRR BGP peer when its
``target_service.kind`` is ``frr-bgp-peer`` or its case name starts with
``bgp-``.

Imports are relative only so the module loads under both engine import roots
(``engine.protocols.bgp`` for the CLI and ``tools.probe.engine.protocols.bgp``
for the tests).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..capability_derivation import capability, capability_default_true
from ..case_helpers import _behavior_case
from ..model import JSONObject, JSONValue, ProbeCase
from ..planning_helpers import (
    deterministic_bytes,
    deterministic_ipv4_pair,
)
from ..target_service_helpers import (
    TargetServiceDescriptor,
    json_mapping,
    string_or,
    target_service_address_fields,
)
from .base import ProtocolPlugin, register


# BGP target-service constants (moved verbatim from
# :mod:`tools.probe.engine.target_services`). The probe-owned FRR BGP peer rides
# TCP/179 (the BGP well-known port) with a deterministic driver/peer AS pair in
# the private-use range and advertises documentation-range prefixes. The
# provision script and FRR config template live under
# ``tools/probe/target_services/bgp/`` (out of scope; referenced, not changed).
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


# BGP smoke capability constant (moved verbatim from
# :mod:`tools.probe.engine.cases`). A controlled FRR peer needs the same
# IPv4-unicast + controlled-service substrate as the DNS/UDP target services,
# with an optional provider flag to deny BGP peer provisioning.
_BGP_CAPABILITIES = ["bgp_peer"]


# BGP smoke case. Probe owns controlled target-service setup for the FRR peer;
# the current stimulus is planned-only until the endpoint driver executes the
# bgp_session example. Built through the ``_behavior_case`` factory (the legacy
# ``cases.BGP_SMOKE_CASES`` tuple carried exactly this case).
BGP_SESSION_SMOKE_CASE: ProbeCase = _behavior_case(
    name="bgp-session-smoke",
    description=(
        "Plan a BGP session exchange against a probe-owned FRR peer target "
        "service."
    ),
    stimulus="bgp_session",
    expected_response="bgp_peer_session",
    required_capabilities=_BGP_CAPABILITIES,
    protocol="bgp",
    metadata={
        "service": "frr-bgp-peer",
        "stateful": True,
        "planned_only": True,
    },
)


def _bgp_session_smoke_probe_plan(
    *,
    case_name: str = "bgp-session-smoke",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan a probe-owned BGP smoke exchange against an FRR peer service."""

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    source_port = 42000 + int.from_bytes(digest[0:2], "big") % 10000
    documentation_prefixes = [
        BGP_DOCUMENTATION_IPV4_PREFIX,
        BGP_DOCUMENTATION_IPV6_PREFIX,
    ]
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "bgp_session",
        "expected_response": "bgp_peer_session",
        "planned_only": True,
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": BGP_SERVICE_PORT,
        "driver_as": BGP_DRIVER_AS,
        "peer_as": BGP_PEER_AS,
        "documentation_prefixes": documentation_prefixes,
        "stimulus_driver": {
            "name": "bgp_session",
            "cargo_example": "bgp_session",
            "driver_source": "crafter/examples/bgp_session.rs",
            "state": "planned-only",
            "planned_only": True,
        },
        "target_service": {
            "required": True,
            "kind": BGP_SERVICE_KIND,
            "protocol": "tcp",
            "port": BGP_SERVICE_PORT,
            "bind_ipv4": target_ipv4,
            "source_ipv4": stimulus_ipv4,
            "runtime": BGP_RUNTIME,
            "driver_as": BGP_DRIVER_AS,
            "peer_as": BGP_PEER_AS,
            "documentation_prefixes": documentation_prefixes,
            "provision_script": BGP_PROVISION_SCRIPT,
            "frr_template": BGP_FRR_TEMPLATE,
            "rib_command": BGP_RIB_COMMAND,
            "deterministic": True,
        },
        "capture_filter": (
            f"tcp and src host {target_ipv4} and dst host {stimulus_ipv4} "
            f"and src port {BGP_SERVICE_PORT} and dst port {source_port}"
        ),
        "validation": {
            "planned_only": True,
            "driver": "bgp_session",
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "source_port": BGP_SERVICE_PORT,
            "destination_port": source_port,
            "driver_as": BGP_DRIVER_AS,
            "peer_as": BGP_PEER_AS,
            "rib_command": BGP_RIB_COMMAND,
        },
        "wire_requirements": {
            "requires_ipv4_unicast": True,
            "requires_controlled_service": True,
            "requires_bgp_peer": True,
            "note": (
                "BGP smoke dry-run exposes the bgp_session stimulus intent and "
                "probe-owned FRR target-service setup without opening TCP "
                "sessions or installing FRR."
            ),
        },
        "digest_hex": digest.hex()[:16],
    }


# Per-case plan-builder dispatch entry for the single BGP case. The registry
# merge in :mod:`tools.probe.engine.planning` exposes this through
# ``PLAN_BUILDERS`` (registry-first), and ``planning`` re-imports the function so
# ``planning._bgp_session_smoke_probe_plan`` keeps identical object identity for
# any pin.
_BGP_PLAN_BUILDERS: dict[str, object] = {
    "bgp-session-smoke": _bgp_session_smoke_probe_plan,
}


# ``bgp-session-smoke`` is planned-only: the builder records the exchange shape
# without building packet bytes.
_BGP_PLANNED_ONLY_CASES: frozenset[str] = frozenset({"bgp-session-smoke"})


# --------------------------------------------------------------------------- #
# Target-service descriptor + plan selectors (moved from target_services.py)
# --------------------------------------------------------------------------- #


def frr_bgp_peer_descriptor(
    *,
    bind_ipv4: str,
    source_ipv4: str,
) -> TargetServiceDescriptor:
    """Describe the probe-owned FRR BGP peer target service."""

    # Imported lazily so the plugin module loads during ``protocols`` package
    # auto-discovery without cycling through ``capabilities`` -> ``lab`` ->
    # ``protocols``. The constant is a plain skip-reason string.
    from ..capabilities import SKIP_REQUIRES_CONTROLLED_SERVICE

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


def bgp_peer_service_plans(probe_plans: Sequence[JSONObject]) -> list[JSONObject]:
    """Return the FRR BGP peer service plan, if any probe plan requests it."""

    if not probe_plans:
        return []
    plan = probe_plans[0]
    addresses = target_service_address_fields(plan)
    descriptor = frr_bgp_peer_descriptor(
        bind_ipv4=string_or(addresses.get("bind_ipv4"), ""),
        source_ipv4=string_or(addresses.get("source_ipv4"), ""),
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


def bgp_peer_probe_plans(probe_plans: Sequence[JSONObject]) -> list[JSONObject]:
    """Return probe plans that require the probe-owned FRR BGP peer."""

    return [plan for plan in probe_plans if probe_plan_requires_bgp_peer(plan)]


def probe_plan_requires_bgp_peer(plan: Mapping[str, JSONValue]) -> bool:
    """Return whether a probe plan requests FRR BGP peer target setup.

    The ``bgp-`` *name-prefix* dispatch is preserved exactly: a plan requests the
    peer when its ``target_service.kind`` is ``frr-bgp-peer`` or its case name
    starts with ``bgp-``.
    """

    target_service = json_mapping(
        plan.get("target_service", {}),
        "probe_plan.target_service",
    )
    if target_service.get("kind") == BGP_SERVICE_KIND:
        return True
    case_name = plan.get("case")
    return isinstance(case_name, str) and case_name.startswith("bgp-")


def bgp_target_service_contribution(
    probe_plans: Sequence[JSONObject],
    *,
    dry_run: bool,
) -> JSONObject:
    """Return the BGP plugin's ``target_service_setup_plan`` contribution.

    Moved verbatim from the BGP entries of the central ``target_service_setup_plan``
    legacy body: the FRR BGP peer service entry (when any plan requests it) plus
    the ``starts_services`` flip on a live run that has at least one BGP plan to
    stand up. The registry merge appends these ``services`` to the central list
    and OR-s ``starts_services``, byte-identical to the legacy per-protocol path
    (which built ``bgp_peer_service_plans(bgp_plans)`` and set ``starts_services``
    to ``not dry_run and bool(bgp_plans)``).
    """

    bgp_plans = bgp_peer_probe_plans(probe_plans)
    return {
        "services": bgp_peer_service_plans(bgp_plans),
        "starts_services": not dry_run and bool(bgp_plans),
    }


# --------------------------------------------------------------------------- #
# Lab-capability derivation (moved from lab.probe_capabilities_from_lab_capabilities)
# --------------------------------------------------------------------------- #


def bgp_lab_capabilities(substrate: Mapping[str, JSONValue]) -> Mapping[str, object]:
    """Return the BGP plugin's derived probe-capability contribution.

    Moved verbatim from the ``bgp_peer`` derivation in
    ``lab.probe_capabilities_from_lab_capabilities``: BGP smoke drives a
    controlled FRR peer on the target endpoint, so it needs the same
    IPv4-unicast + controlled-service substrate as the DNS/UDP target services,
    with an optional provider flag to deny BGP peer provisioning. The shared
    ``capability_names`` / ``capability_sources`` tables stay in ``lab``; this
    hook contributes only the derived ``bgp_peer`` value, merged byte-identically
    over the legacy value.
    """

    ipv4_unicast = capability(substrate, "ipv4_unicast", "ipv4")
    controlled_services = capability(
        substrate,
        "controlled_services",
        "controlled_service",
    )
    return {
        "bgp_peer": (
            ipv4_unicast
            and controlled_services
            and capability_default_true(substrate, "bgp_peer")
        ),
    }


register(
    ProtocolPlugin(
        name="bgp",
        cases=(BGP_SESSION_SMOKE_CASE,),
        plan_builders=_BGP_PLAN_BUILDERS,
        planned_only_cases=_BGP_PLANNED_ONLY_CASES,
        # BGP's profile membership stays in the legacy ordered profile table in
        # ``cases.py`` (``BGP_SESSION_PROFILE_CASE_NAMES``, sourced from the
        # registered BGP case) to preserve byte-identical selection order.
        profile_counts={},
        # ``bgp-session-smoke`` is planned-only and was never stimulus-routed.
        stimulus_endpoint_cases=frozenset(),
        # The ``target_service`` hook contributes the FRR BGP peer service entry
        # and the ``starts_services`` flip, and diverts the BGP case off the
        # legacy target path. ``setup_script`` stays ``None``: BGP is
        # provision-script driven, with no inline setup-script block to render.
        # ``rewrite_endpoint_addresses`` / ``failure_reasons`` stay ``None``: BGP
        # has no live-path rewrite branch (it is not stimulus-routed) and no
        # failure-reason branch (it fell through to the shared default).
        # ``lab_capabilities`` contributes the ``bgp_peer`` derived capability.
        target_service=bgp_target_service_contribution,
        setup_script=None,
        rewrite_endpoint_addresses=None,
        failure_reasons=None,
        lab_capabilities=bgp_lab_capabilities,
    )
)
