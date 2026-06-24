"""IGMP probe protocol plugin: cases, plan builders, and live surface.

IGMP (IPv4 protocol number 2, RFC 2236 / RFC 3376) rides link-local IPv4
multicast with TTL 1 and the Router Alert option, driving a controlled
listener/router peer on a same-segment multicast substrate. This is a
single-step full migration. The surface this module bundles:

* the four IGMP cases (``igmp-membership-query-observation`` /
  ``igmp-v2-membership-report-emission`` / ``igmp-v2-leave-group-emission`` /
  ``igmp-v3-source-list-report``), built through the ``_behavior_case`` factory,
  and their shared ``_IGMP_CAPABILITIES`` constant (the catalog contribution),
* the ``_igmp_probe_plan`` plan builder (one builder serving all four cases),
  the ``_igmp_target_service`` plan-building helper, the
  ``deterministic_igmp_group`` / ``deterministic_igmp_source_list`` deterministic
  helpers, the IGMP wire constants the plans reference, and the planned-only set
  (all four cases are planned-only),
* the ``target_service`` / ``setup_script`` hooks (``None``: IGMP produced no
  ``target_service_setup_plan`` service entry and no inline setup-script block --
  there was no IGMP descriptor, frozenset, or responder heredoc in
  :mod:`tools.probe.engine.target_services`. The IGMP target service is embedded
  *inside the plan* by ``_igmp_target_service`` -- a plan-building input called by
  the builder, not a setup-plan contribution; the provision/cleanup scripts live
  under ``tools/probe/target_services/igmp/`` (out of scope; referenced, not
  changed)),
* the ``rewrite_endpoint_addresses`` hook (``None``: the four IGMP cases are
  planned-only and were never stimulus-routed -- they are absent from
  ``cli._LEGACY_STIMULUS_ENDPOINT_CASES`` -- so the live-path rewrite never
  reached IGMP and there is no legacy IGMP rewrite branch to reproduce),
* the ``failure_reasons`` hook (the IGMP failure-reason taxonomy moved verbatim
  from the ``cli._failure_reasons_for_case`` IGMP branch), and
* the ``lab_capabilities`` hook (the ``ipv4_multicast`` and ``igmp_peer`` derived
  capabilities, moved verbatim from
  ``lab.probe_capabilities_from_lab_capabilities``).

The plan builder, target-service helper, and deterministic helpers are moved
verbatim from :mod:`tools.probe.engine.planning`; ``planning`` re-imports them so
``planning._igmp_probe_plan`` / ``planning.deterministic_igmp_group`` /
``planning.deterministic_igmp_source_list`` and ``PLAN_BUILDERS[name] is
_igmp_probe_plan`` keep identical object identity for the pinning tests. The case
tuple is re-imported into :mod:`tools.probe.engine.cases` so
``cases.IGMP_PROBE_CASES`` stays resolvable for the catalog tests.

IGMP's ``profile_counts`` is intentionally empty: the focused ``igmp`` profile
rides the four cases in a fixed declaration order, and the registry-first profile
merge would move the registry contribution to the front of that profile, so the
legacy ordered profile name table in :mod:`tools.probe.engine.cases`
(``IGMP_PROFILE_CASE_NAMES``, now sourced from the registered IGMP cases) keeps
owning IGMP's profile membership to preserve byte-identical selection order.

Imports are relative only so the module loads under both engine import roots
(``engine.protocols.igmp`` for the CLI and ``tools.probe.engine.protocols.igmp``
for the tests).
"""

from __future__ import annotations

from collections.abc import Mapping

from ..capability_derivation import capability, capability_default_true
from ..case_helpers import _behavior_case
from ..endpoint_addressing import (
    FAILURE_DECODE_FAILED,
    FAILURE_TARGET_SETUP_FAILED,
    FAILURE_TIMEOUT,
    FAILURE_WRONG_PAYLOAD,
    FAILURE_WRONG_PEER,
)
from ..model import JSONObject, JSONValue, ProbeCase
from ..planning_helpers import deterministic_bytes, deterministic_ipv4_pair
from .base import ProtocolPlugin, register


# IGMP shared capability constant (moved verbatim from
# :mod:`tools.probe.engine.cases`). IGMP is IPv4-only and needs a same-segment
# IPv4 multicast substrate plus a controlled IGMP peer (listener/router).
_IGMP_CAPABILITIES = ["ipv4_multicast", "igmp_peer"]


# IGMP behavior cases (moved verbatim from ``cases.IGMP_PROBE_CASES``). IGMP is
# IPv4-only and rides link-local IPv4 multicast groups, so every case is kept out
# of the broad behavior profile and selected through the focused ``igmp``
# profile. The cases are planned dry-run first: live execution remains
# provider-backed and confirmation-gated, with unsupported substrates skipping on
# the multicast / IGMP-peer capabilities.
IGMP_PROBE_CASES: tuple[ProbeCase, ...] = (
    _behavior_case(
        name="igmp-membership-query-observation",
        description=(
            "Observe a controlled peer's IGMP Membership Query on the lab "
            "multicast segment."
        ),
        stimulus="igmp_query_observation",
        expected_response="igmp_membership_query",
        required_capabilities=_IGMP_CAPABILITIES,
        protocol="igmp",
        metadata={
            "service": "igmp-router",
            "layer": "network",
            "ipv4_only": True,
            "planned_only": True,
        },
    ),
    _behavior_case(
        name="igmp-v2-membership-report-emission",
        description=(
            "Emit an IGMPv2 Membership Report to a documentation multicast "
            "group and plan peer observation."
        ),
        stimulus="igmp_v2_membership_report",
        expected_response="igmp_membership_report_observed",
        required_capabilities=_IGMP_CAPABILITIES,
        protocol="igmp",
        metadata={
            "service": "igmp-listener",
            "layer": "network",
            "ipv4_only": True,
            "planned_only": True,
        },
    ),
    _behavior_case(
        name="igmp-v2-leave-group-emission",
        description=(
            "Emit an IGMPv2 Leave Group message toward the all-routers group and "
            "plan peer observation."
        ),
        stimulus="igmp_v2_leave_group",
        expected_response="igmp_leave_group_observed",
        required_capabilities=_IGMP_CAPABILITIES,
        protocol="igmp",
        metadata={
            "service": "igmp-listener",
            "layer": "network",
            "ipv4_only": True,
            "planned_only": True,
        },
    ),
    _behavior_case(
        name="igmp-v3-source-list-report",
        description=(
            "Emit an IGMPv3 Membership Report carrying a deterministic "
            "MODE_IS_INCLUDE source list."
        ),
        stimulus="igmp_v3_source_list_report",
        expected_response="igmp_v3_report_observed",
        required_capabilities=_IGMP_CAPABILITIES,
        protocol="igmp",
        metadata={
            "service": "igmp-listener",
            "layer": "network",
            "ipv4_only": True,
            "planned_only": True,
            "record_type": "mode_is_include",
        },
    ),
)


# IGMP wire constants (moved verbatim from :mod:`tools.probe.engine.planning`).
# IGMP (IPv4 protocol number 2) rides link-local IPv4 multicast with TTL 1 and
# Router Alert on real networks. The probe plans below are dry-run-only and
# provider-backed for live execution; they expose the exact message shapes an
# agent should expect before any protected live run is confirmed.
_IGMP_IP_PROTOCOL = 2
_IGMP_DEFAULT_TTL = 1
_IGMP_ALL_SYSTEMS_GROUP = "224.0.0.1"
_IGMP_ALL_ROUTERS_GROUP = "224.0.0.2"
_IGMPV3_REPORT_DESTINATION = "224.0.0.22"
_IGMP_DOCUMENTATION_MULTICAST_PREFIX = "233.252.0.0/24"
_IGMP_DOCUMENTATION_SOURCE_PREFIXES = ["192.0.2.0/24", "198.51.100.0/24"]
_IGMP_TARGET_SERVICE_DIR = "tools/probe/target_services/igmp"
_IGMP_LISTENER_SCRIPT = f"{_IGMP_TARGET_SERVICE_DIR}/provision-listener.sh"
_IGMP_ROUTER_SCRIPT = f"{_IGMP_TARGET_SERVICE_DIR}/provision-router.sh"
_IGMP_CLEANUP_SCRIPT = f"{_IGMP_TARGET_SERVICE_DIR}/cleanup.sh"


def _igmp_probe_plan(
    *,
    case_name: str,
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan a dry-run IGMP peer-behavior case.

    IGMP probes need a provider-backed multicast segment and a controlled peer
    (listener/router) before any live traffic is useful. This builder therefore
    records packet shapes, capture filters, target-service scripts, and stable
    validation expectations while emitting no packet bytes and sending nothing.
    """

    # Imported lazily so the plugin module loads during ``protocols`` package
    # auto-discovery without cycling through ``cases`` -> ``protocols`` ->
    # ``igmp``. ``PROBE_CASE_BY_NAME`` is the assembled catalog index.
    from ..cases import PROBE_CASE_BY_NAME

    case = PROBE_CASE_BY_NAME[case_name]
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    group_address = deterministic_igmp_group(profile, seed, sequence)
    source_list = deterministic_igmp_source_list(profile, seed, sequence)

    if case_name == "igmp-membership-query-observation":
        destination_ipv4 = _IGMP_ALL_SYSTEMS_GROUP
        sender_ipv4 = target_ipv4
        target_service = _igmp_target_service(
            kind="igmp-router",
            role="router",
            bind_ipv4=target_ipv4,
            source_ipv4=stimulus_ipv4,
            multicast_group=destination_ipv4,
            provision_script=_IGMP_ROUTER_SCRIPT,
        )
        stimulus_shape: JSONObject = {
            "direction": "observe",
            "sender_role": "router",
            "igmp_type": 0x11,
            "message": "membership_query",
            "max_response_time_tenths": 10,
            "group_address": "0.0.0.0",
        }
        expected_shape = dict(stimulus_shape)
        expected_shape["source_ipv4"] = sender_ipv4
        expected_shape["destination_ipv4"] = destination_ipv4
        validation: JSONObject = {
            "planned_only": True,
            "driver": "igmp_query_observation",
            "source_ipv4": sender_ipv4,
            "destination_ipv4": destination_ipv4,
            "igmp_type": 0x11,
            "group_address": "0.0.0.0",
            "max_response_time_tenths": 10,
        }
        capture_filter = (
            f"igmp and src host {sender_ipv4} and dst host {destination_ipv4}"
        )
        adapter_case = "igmp-v2-membership-query"
    elif case_name == "igmp-v2-membership-report-emission":
        destination_ipv4 = group_address
        target_service = _igmp_target_service(
            kind="igmp-listener",
            role="target",
            bind_ipv4=target_ipv4,
            source_ipv4=stimulus_ipv4,
            multicast_group=group_address,
            provision_script=_IGMP_LISTENER_SCRIPT,
        )
        stimulus_shape = {
            "direction": "emit",
            "igmp_type": 0x16,
            "message": "v2_membership_report",
            "group_address": group_address,
        }
        expected_shape = {
            "observer_role": "target",
            "expected_response": case.expected_response,
            "source_ipv4": stimulus_ipv4,
            "destination_ipv4": destination_ipv4,
            "igmp_type": 0x16,
            "group_address": group_address,
        }
        validation = {
            "planned_only": True,
            "driver": "igmp_v2_membership_report",
            "source_ipv4": stimulus_ipv4,
            "destination_ipv4": destination_ipv4,
            "igmp_type": 0x16,
            "group_address": group_address,
        }
        capture_filter = (
            f"igmp and src host {stimulus_ipv4} and dst host {destination_ipv4}"
        )
        adapter_case = "igmp-v2-membership-report"
    elif case_name == "igmp-v2-leave-group-emission":
        destination_ipv4 = _IGMP_ALL_ROUTERS_GROUP
        target_service = _igmp_target_service(
            kind="igmp-listener",
            role="target",
            bind_ipv4=target_ipv4,
            source_ipv4=stimulus_ipv4,
            multicast_group=group_address,
            provision_script=_IGMP_LISTENER_SCRIPT,
        )
        stimulus_shape = {
            "direction": "emit",
            "igmp_type": 0x17,
            "message": "v2_leave_group",
            "group_address": group_address,
        }
        expected_shape = {
            "observer_role": "target",
            "expected_response": case.expected_response,
            "source_ipv4": stimulus_ipv4,
            "destination_ipv4": destination_ipv4,
            "igmp_type": 0x17,
            "group_address": group_address,
        }
        validation = {
            "planned_only": True,
            "driver": "igmp_v2_leave_group",
            "source_ipv4": stimulus_ipv4,
            "destination_ipv4": destination_ipv4,
            "igmp_type": 0x17,
            "group_address": group_address,
        }
        capture_filter = (
            f"igmp and src host {stimulus_ipv4} and dst host {destination_ipv4}"
        )
        adapter_case = "igmp-v2-leave-group"
    elif case_name == "igmp-v3-source-list-report":
        destination_ipv4 = _IGMPV3_REPORT_DESTINATION
        target_service = _igmp_target_service(
            kind="igmp-listener",
            role="target",
            bind_ipv4=target_ipv4,
            source_ipv4=stimulus_ipv4,
            multicast_group=group_address,
            provision_script=_IGMP_LISTENER_SCRIPT,
        )
        stimulus_shape = {
            "direction": "emit",
            "igmp_type": 0x22,
            "message": "v3_membership_report",
            "record_type": "mode_is_include",
            "group_address": group_address,
            "source_addresses": source_list,
            "record_count": 1,
        }
        expected_shape = {
            "observer_role": "target",
            "expected_response": case.expected_response,
            "source_ipv4": stimulus_ipv4,
            "destination_ipv4": destination_ipv4,
            "igmp_type": 0x22,
            "group_address": group_address,
            "source_addresses": source_list,
            "record_type": "mode_is_include",
        }
        validation = {
            "planned_only": True,
            "driver": "igmp_v3_source_list_report",
            "source_ipv4": stimulus_ipv4,
            "destination_ipv4": destination_ipv4,
            "igmp_type": 0x22,
            "group_address": group_address,
            "source_addresses": source_list,
            "record_type": "mode_is_include",
            "record_count": 1,
        }
        capture_filter = (
            f"igmp and src host {stimulus_ipv4} and dst host {destination_ipv4}"
        )
        adapter_case = "igmp-v3-source-list-report"
    else:
        raise ValueError(f"unsupported IGMP probe case {case_name!r}")

    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": case.stimulus,
        "expected_response": case.expected_response,
        "planned_only": True,
        "protocol": "igmp",
        "ip_protocol": _IGMP_IP_PROTOCOL,
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": destination_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "group_address": group_address,
        "multicast_group": group_address,
        "ttl": _IGMP_DEFAULT_TTL,
        "router_alert_required": True,
        "documentation_prefixes": [
            _IGMP_DOCUMENTATION_MULTICAST_PREFIX,
            *_IGMP_DOCUMENTATION_SOURCE_PREFIXES,
        ],
        "stimulus_driver": {
            "name": case.stimulus,
            "adapter_module": "tools/probe/adapters/src/igmp.rs",
            "adapter_case": adapter_case,
            "state": "planned-only",
            "planned_only": True,
        },
        "stimulus_packet_shape": {
            "ipv4": {
                "source": stimulus_ipv4,
                "destination": destination_ipv4,
                "ttl": _IGMP_DEFAULT_TTL,
                "protocol": _IGMP_IP_PROTOCOL,
                "router_alert_required": True,
            },
            "igmp": stimulus_shape,
        },
        "expected_response_packet_shape": expected_shape,
        "target_service": target_service,
        "capture_filter": capture_filter,
        "validation": validation,
        "wire_requirements": {
            "requires_ipv4_multicast": True,
            "requires_igmp_peer": True,
            "requires_provider_backing": True,
            "requires_confirm_live_run": True,
            "note": (
                "IGMP dry-run records the packet and peer-observation contract. "
                "Any live traffic must run from a provider-backed lab endpoint "
                "with explicit confirmation, never from the developer host."
            ),
        },
        "live_path": (
            "Opt-in via lab-session / providers: provision the IGMP target "
            "listener/router, run the stimulus from the provider endpoint with "
            "--confirm-live-run, collect artifacts, and tear the endpoint down."
        ),
        "digest_hex": digest.hex()[:16],
    }


def _igmp_target_service(
    *,
    kind: str,
    role: str,
    bind_ipv4: str,
    source_ipv4: str,
    multicast_group: str,
    provision_script: str,
) -> JSONObject:
    return {
        "required": True,
        "kind": kind,
        "protocol": "igmp",
        "role": role,
        "bind_ipv4": bind_ipv4,
        "source_ipv4": source_ipv4,
        "multicast_group": multicast_group,
        "runtime": "probe-target-service",
        "provision_script": provision_script,
        "cleanup_script": _IGMP_CLEANUP_SCRIPT,
        "artifact_root": "target/probe/target-services/igmp",
        "deterministic": True,
        "dry_run_safe": True,
        "live_guard": "LIBCRAFTER_PROBE_LAB_TARGET=1",
    }


def deterministic_igmp_group(profile: str, seed: int, sequence: int) -> str:
    digest = deterministic_bytes("igmp-group", profile, seed, sequence)
    host = 1 + digest[0] % 254
    return f"233.252.0.{host}"


def deterministic_igmp_source_list(profile: str, seed: int, sequence: int) -> list[str]:
    digest = deterministic_bytes("igmp-source-list", profile, seed, sequence)
    first = 1 + digest[0] % 254
    second = 1 + digest[1] % 254
    return [f"192.0.2.{first}", f"198.51.100.{second}"]


# Per-case plan-builder dispatch entries for the four IGMP cases (one builder
# serves them all). The registry merge in :mod:`tools.probe.engine.planning`
# exposes these through ``PLAN_BUILDERS`` (registry-first), and ``planning``
# re-imports ``_igmp_probe_plan`` so ``planning._igmp_probe_plan`` keeps identical
# object identity for the pinning tests.
_IGMP_PLAN_BUILDERS: dict[str, object] = {
    "igmp-membership-query-observation": _igmp_probe_plan,
    "igmp-v2-membership-report-emission": _igmp_probe_plan,
    "igmp-v2-leave-group-emission": _igmp_probe_plan,
    "igmp-v3-source-list-report": _igmp_probe_plan,
}


# All four IGMP cases are planned-only: the builder records the exchange shape
# without building packet bytes. Moved verbatim from
# ``planning._LEGACY_PLANNED_ONLY_REGISTERED_CASES``.
_IGMP_PLANNED_ONLY_CASES: frozenset[str] = frozenset(
    {
        "igmp-membership-query-observation",
        "igmp-v2-membership-report-emission",
        "igmp-v2-leave-group-emission",
        "igmp-v3-source-list-report",
    }
)


def igmp_failure_reasons(case_name: str) -> list[str] | None:
    """Return the IGMP failure-reason taxonomy for ``case_name``.

    Moved verbatim from the IGMP branch of ``cli._failure_reasons_for_case``: the
    four IGMP cases share a stable failure taxonomy (timeout / wrong peer / wrong
    payload / decode failed / target setup failed). Cases this plugin does not
    own return ``None`` so the central dispatcher falls through to the shared
    default taxonomy.
    """

    if case_name in _IGMP_PLANNED_ONLY_CASES:
        return [
            FAILURE_TIMEOUT,
            FAILURE_WRONG_PEER,
            FAILURE_WRONG_PAYLOAD,
            FAILURE_DECODE_FAILED,
            FAILURE_TARGET_SETUP_FAILED,
        ]
    return None


def igmp_lab_capabilities(substrate: Mapping[str, JSONValue]) -> Mapping[str, object]:
    """Return the IGMP plugin's derived probe-capability contribution.

    Moved verbatim from the ``ipv4_multicast`` / ``igmp_peer`` derivation in
    ``lab.probe_capabilities_from_lab_capabilities``: IGMP peer behavior needs a
    same-segment IPv4 multicast substrate (IPv4 unicast plus link-layer
    send/capture/broadcast and an explicit multicast flag) plus a controlled
    peer/listener/router service on the target endpoint. Providers may explicitly
    deny either multicast delivery or the controlled IGMP peer; unsupported
    substrates then skip with stable IGMP-specific reasons. The shared
    ``capability_names`` / ``capability_sources`` tables stay in ``lab``; this
    hook contributes the derived ``ipv4_multicast`` and ``igmp_peer`` values,
    merged byte-identically over the legacy values.
    """

    ipv4_unicast = capability(substrate, "ipv4_unicast", "ipv4")
    controlled_services = capability(
        substrate,
        "controlled_services",
        "controlled_service",
    )
    link_layer_send = capability(substrate, "link_layer_send")
    link_layer_capture = capability(substrate, "link_layer_capture")
    broadcast = capability(substrate, "broadcast")
    ipv4_multicast = (
        ipv4_unicast
        and link_layer_send
        and link_layer_capture
        and broadcast
        and capability_default_true(substrate, "ipv4_multicast", "multicast")
    )
    igmp_peer = (
        ipv4_multicast
        and controlled_services
        and capability_default_true(
            substrate,
            "igmp_peer",
            "igmp_listener",
            "igmp_router",
        )
    )
    return {
        "ipv4_multicast": ipv4_multicast,
        "igmp_peer": igmp_peer,
    }


register(
    ProtocolPlugin(
        name="igmp",
        cases=IGMP_PROBE_CASES,
        plan_builders=_IGMP_PLAN_BUILDERS,
        planned_only_cases=_IGMP_PLANNED_ONLY_CASES,
        # IGMP's profile membership stays in the legacy ordered profile table in
        # ``cases.py`` (``IGMP_PROFILE_CASE_NAMES``, sourced from the registered
        # IGMP cases) to preserve byte-identical selection order.
        profile_counts={},
        # All four IGMP cases are planned-only and were never stimulus-routed.
        stimulus_endpoint_cases=frozenset(),
        # ``target_service`` / ``setup_script`` stay ``None``: IGMP produced no
        # ``target_service_setup_plan`` service entry and no inline setup-script
        # block (the IGMP target service is embedded inside the plan by
        # ``_igmp_target_service``, a plan-building input called by the builder,
        # not a setup-plan contribution). ``rewrite_endpoint_addresses`` stays
        # ``None``: the four IGMP cases are planned-only and were never
        # stimulus-routed, so the live-path rewrite never reached IGMP and there
        # is no legacy rewrite branch to reproduce. ``failure_reasons`` contributes
        # the IGMP failure taxonomy; ``lab_capabilities`` contributes the
        # ``ipv4_multicast`` and ``igmp_peer`` derived capabilities.
        target_service=None,
        setup_script=None,
        rewrite_endpoint_addresses=None,
        failure_reasons=igmp_failure_reasons,
        lab_capabilities=igmp_lab_capabilities,
    )
)
