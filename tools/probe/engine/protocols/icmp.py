"""ICMP probe protocol plugin: cases, plan builders, and full live surface.

This is the ICMP full migration (a single step, after the ARP vertical slice and
the DNS / DHCPv4 / UDP / NDP migrations). ICMP has a small surface and no responder
target service -- both of its cases ride a bare kernel -- so its entire surface
fits in one step:

* the two inline ICMP cases (``icmp-echo`` and ``ttl-expired``), carried directly
  in the legacy per-protocol aggregation rather than through the ``_behavior_case``
  factory (the catalog contribution),
* the ``_icmp_echo_probe_plan`` and ``_ttl_expired_probe_plan`` plan builders (the
  plan-builder contribution),
* the ICMP stimulus-endpoint routing set,
* the ``rewrite_endpoint_addresses`` hook (the ``icmp-echo`` + ``ttl-expired``
  live-path address rewrite),
* the ``failure_reasons`` hook (the ``icmp-echo`` + ``ttl-expired`` taxonomy), and
* the ``lab_capabilities`` hook (the ``icmp_echo`` derived capability).

``icmp-echo`` validates the peer kernel's echo reply; ``ttl-expired`` validates an
ICMP Time Exceeded from a controlled hop. Both ride IPv4 and need no listening
daemon (the kernel answers an echo and a controlled router emits the
TTL-exceeded), so ICMP contributes no ``target_service`` hook: its cases stay on
the legacy target path, which produces no per-case ICMP service entry (the static
``controlled_router`` skip-key in the legacy setup plan is unconditional and is
not ICMP-owned data, so it stays in :mod:`tools.probe.engine.target_services`).

The plan builders are moved verbatim from :mod:`tools.probe.engine.planning`;
:mod:`planning` re-imports both so ``planning._<builder>`` /
``planning.PLAN_BUILDERS[name]`` keep identical object identity for any pin.

ICMP carries no ``planned_only`` cases (both builders materialize a plan), and its
``profile_counts`` is intentionally empty: ``icmp-echo`` and ``ttl-expired`` sit
in the ``smoke`` profile in a fixed, order-sensitive position, and the
registry-first profile merge would move the registry contribution to the front of
that profile, so the legacy ordered profile name tables in
:mod:`tools.probe.engine.cases` keep owning ICMP's profile membership to preserve
byte-identical selection order.

The ``rewrite_endpoint_addresses`` hook reproduces ICMP's two branches of
``cli._probe_plan_with_endpoint_addresses`` verbatim, *including the shared
transport-IPv4 pre-sets that ran before the per-protocol if/elif* and the shared
IPv4-layer validation/live-rewrite tail that ran after it. ICMP rides IPv4 (no
early-return like NDP), so the hook applies the shared head, the ICMP-specific
overrides (the ``icmp-echo`` capture filter; the ``ttl-expired`` controlled-router
addressing and capture filter), then the shared tail. The ``failure_reasons`` hook
reproduces the ICMP branch (``icmp-echo`` and ``ttl-expired`` share a taxonomy),
returning ``None`` for non-ICMP cases. The ``lab_capabilities`` hook contributes
the ``icmp_echo`` derived capability (``ipv4_unicast``), the way ``ttl-expired``'s
``controlled_router`` capability is derived in
:mod:`tools.probe.engine.lab`'s shared body.

Imports are relative only so the module loads under both engine import roots
(``engine.protocols.icmp`` for the CLI and ``tools.probe.engine.protocols.icmp``
for the tests).
"""

from __future__ import annotations

from collections.abc import Mapping

from ..capability_derivation import capability
from ..endpoint_addressing import (
    FAILURE_DECODE_FAILED,
    FAILURE_TIMEOUT,
    FAILURE_WRONG_PAYLOAD,
    FAILURE_WRONG_PEER,
    apply_shared_ipv4_rewrite_tail,
)
from ..model import JSONObject, JSONValue, ProbeCase
from ..planning_helpers import (
    deterministic_bytes,
    deterministic_ipv4_pair,
    deterministic_router_ipv4,
)
from .base import ProtocolPlugin, register


# The two inline ICMP cases (the legacy per-protocol aggregation carried these
# directly rather than through the ``_behavior_case`` factory). ``icmp-echo``
# validates the peer kernel's echo reply; ``ttl-expired`` validates an ICMP Time
# Exceeded from a controlled hop. Both ride IPv4 and need no listening daemon.
ICMP_ECHO_CASE: ProbeCase = ProbeCase(
    name="icmp-echo",
    description="Send ICMP echo request and validate echo reply from peer kernel.",
    stimulus="icmp_echo_request",
    expected_response="icmp_echo_reply",
    required_capabilities=["icmp_echo"],
    endpoint_roles=["stimulus", "target"],
    metadata={"protocol": "icmp", "service": "kernel"},
)

TTL_EXPIRED_CASE: ProbeCase = ProbeCase(
    name="ttl-expired",
    description="Send low-TTL packet and validate ICMP TTL-expired from controlled hop.",
    stimulus="low_ttl_probe",
    expected_response="icmp_ttl_expired",
    required_capabilities=["controlled_router"],
    endpoint_roles=["stimulus", "router"],
    metadata={"protocol": "icmp", "service": "controlled_router"},
)


def _icmp_echo_probe_plan(
    *,
    case_name: str = "icmp-echo",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    digest = deterministic_bytes("icmp-echo", profile, seed, sequence)
    identifier = int.from_bytes(digest[0:2], "big") or 1
    sequence_number = int.from_bytes(digest[2:4], "big")
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    payload = (
        f"libcrafter-probe:icmp-echo:{profile}:{seed}:{sequence}:"
        f"{digest.hex()[:16]}"
    ).encode("ascii")
    return {
        "schema_version": 1,
        "case": "icmp-echo",
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "icmp_echo_request",
        "expected_response": "icmp_echo_reply",
        "identifier": identifier,
        "sequence_number": sequence_number,
        "payload_hex": payload.hex(),
        "payload_length": len(payload),
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "capture_filter": (
            f"icmp and src host {target_ipv4} and dst host {stimulus_ipv4}"
        ),
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "icmp_type": 0,
            "icmp_code": 0,
            "identifier": identifier,
            "sequence_number": sequence_number,
            "payload_hex": payload.hex(),
        },
    }


def _ttl_expired_probe_plan(
    *,
    case_name: str = "ttl-expired",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    digest = deterministic_bytes("ttl-expired", profile, seed, sequence)
    stimulus_ipv4, destination_ipv4 = deterministic_ipv4_pair(
        profile,
        seed,
        sequence,
    )
    router_ipv4 = deterministic_router_ipv4(profile, seed, sequence)
    identifier = int.from_bytes(digest[0:2], "big") or 1
    sequence_number = int.from_bytes(digest[2:4], "big")
    payload = (
        f"libcrafter-probe:ttl-expired:{profile}:{seed}:{sequence}:"
        f"{digest.hex()[:16]}"
    ).encode("ascii")
    embedded_prefix_length = 28
    return {
        "schema_version": 1,
        "case": "ttl-expired",
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "low_ttl_probe",
        "expected_response": "icmp_ttl_expired",
        "ttl": 1,
        "identifier": identifier,
        "sequence_number": sequence_number,
        "payload_hex": payload.hex(),
        "payload_length": len(payload),
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": destination_ipv4,
        "controlled_router_ipv4": router_ipv4,
        "expected_reply_source_ipv4": router_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "expected_icmp_type": 11,
        "expected_icmp_code": 0,
        "expected_embedded_prefix_length": embedded_prefix_length,
        "capture_filter": (
            f"icmp and src host {router_ipv4} and dst host {stimulus_ipv4}"
        ),
        "validation": {
            "source_ipv4": router_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "icmp_type": 11,
            "icmp_code": 0,
            "embedded_prefix": {
                "source": "stimulus_sent_bytes",
                "length": embedded_prefix_length,
                "meaning": "original IPv4 header plus first eight bytes of payload",
            },
        },
    }


# Per-case plan-builder dispatch entries for the two ICMP cases. The registry
# merge in :mod:`tools.probe.engine.planning` exposes these through
# ``PLAN_BUILDERS`` (registry-first), and ``planning`` re-imports each function so
# ``planning._<builder>`` keeps identical object identity for any pin.
_ICMP_PLAN_BUILDERS: dict[str, object] = {
    "icmp-echo": _icmp_echo_probe_plan,
    "ttl-expired": _ttl_expired_probe_plan,
}


# Both ICMP cases route through the stimulus endpoint adapter.
_ICMP_STIMULUS_ENDPOINT_CASES: frozenset[str] = frozenset(
    {
        "icmp-echo",
        "ttl-expired",
    }
)


# --------------------------------------------------------------------------- #
# Live-path address rewrite (moved from cli._probe_plan_with_endpoint_addresses)
# --------------------------------------------------------------------------- #
#
# ICMP rides IPv4 (no early-return like NDP): the legacy dispatcher applied the
# shared transport-IPv4 pre-sets, then the ICMP-specific if/elif overrides, then
# the shared IPv4-layer validation/live-rewrite tail. The hook reproduces that
# exact sequence. ``source_mac`` / ``target_mac`` / ``target_interface`` are
# accepted (the central dispatcher passes them to every hook) and discarded: ICMP
# is purely IPv4-transport.


def icmp_rewrite_endpoint_addresses(
    plan: JSONObject,
    *,
    source_ipv4: str,
    target_ipv4: str,
    source_mac: str | None = None,
    target_mac: str | None = None,
    target_interface: str | None = None,
    rewrite_source: str = "wire_endpoint_plan",
) -> JSONObject:
    """Rewrite an ICMP probe plan onto the live lab-segment addresses.

    Moved verbatim from the ``icmp-echo`` and ``ttl-expired`` branches of
    ``cli._probe_plan_with_endpoint_addresses`` (including the shared
    transport-IPv4 pre-sets that ran before the per-protocol if/elif and the
    shared IPv4-layer validation/live-rewrite tail that ran after it). ``icmp-echo``
    rewrites the source/destination IPv4 and the capture filter to watch the echo
    reply from the target; ``ttl-expired`` keeps the controlled-router IPv4 as the
    expected reply source and watches the Time Exceeded from that hop. ICMP rides
    IPv4 with no link-layer rewrite, so the MAC / interface arguments are accepted
    and discarded.
    """

    original_destination_ipv4 = str(plan.get("destination_ipv4", ""))
    updated = dict(plan)
    updated["source_ipv4"] = source_ipv4
    updated["destination_ipv4"] = target_ipv4
    updated["expected_reply_source_ipv4"] = target_ipv4
    updated["expected_reply_destination_ipv4"] = source_ipv4
    case_name = str(updated.get("case", ""))
    if case_name == "icmp-echo":
        updated["capture_filter"] = (
            f"icmp and src host {target_ipv4} and dst host {source_ipv4}"
        )
    elif case_name == "ttl-expired":
        router_ipv4 = (
            target_ipv4
            if rewrite_source == "lab_session"
            else str(updated.get("controlled_router_ipv4") or target_ipv4)
        )
        updated["source_ipv4"] = source_ipv4
        updated["destination_ipv4"] = (
            original_destination_ipv4
            if rewrite_source == "lab_session"
            else target_ipv4
        )
        updated["controlled_router_ipv4"] = router_ipv4
        updated["expected_reply_source_ipv4"] = router_ipv4
        updated["expected_reply_destination_ipv4"] = source_ipv4
        updated["capture_filter"] = (
            f"icmp and src host {router_ipv4} and dst host {source_ipv4}"
        )
    return apply_shared_ipv4_rewrite_tail(
        updated,
        case_name=case_name,
        source_ipv4=source_ipv4,
        target_ipv4=target_ipv4,
        rewrite_source=rewrite_source,
    )


# --------------------------------------------------------------------------- #
# Failure-reason taxonomy (moved from cli._failure_reasons_for_case)
# --------------------------------------------------------------------------- #


def icmp_failure_reasons(case_name: str) -> list[str] | None:
    """Return the ordered ICMP failure-reason taxonomy for ``case_name``.

    Moved verbatim from the ``icmp-echo`` and ``ttl-expired`` branches of
    ``cli._failure_reasons_for_case`` (both shared an identical taxonomy).
    Returns ``None`` for a non-ICMP case so the central dispatcher falls through
    to the next branch.
    """

    if case_name in _ICMP_STIMULUS_ENDPOINT_CASES:
        return [
            FAILURE_TIMEOUT,
            FAILURE_WRONG_PEER,
            FAILURE_WRONG_PAYLOAD,
            FAILURE_DECODE_FAILED,
        ]
    return None


# --------------------------------------------------------------------------- #
# Lab-capability derivation (moved from lab.probe_capabilities_from_lab_capabilities)
# --------------------------------------------------------------------------- #


def icmp_lab_capabilities(substrate: Mapping[str, JSONValue]) -> Mapping[str, object]:
    """Return the ICMP plugin's derived probe-capability contribution.

    Moved verbatim from the ``icmp_echo`` derivation in
    ``lab.probe_capabilities_from_lab_capabilities``: an ICMP echo exchange needs
    only IPv4 unicast reachability to a peer kernel (the kernel answers an echo
    request out of the box), so ``icmp_echo`` derives directly from
    ``ipv4_unicast``. The shared ``capability_names`` / ``capability_sources``
    tables stay in ``lab``; this hook contributes only the derived ``icmp_echo``
    value, merged byte-identically over the legacy value. (``ttl-expired``'s
    ``controlled_router`` capability is a distinct, separately derived bit that
    stays in the shared ``lab`` body.)
    """

    ipv4_unicast = capability(substrate, "ipv4_unicast", "ipv4")
    return {"icmp_echo": ipv4_unicast}


register(
    ProtocolPlugin(
        name="icmp",
        # The two inline ICMP cases in declaration order (``icmp-echo`` first, to
        # match the legacy aggregation where it led the catalog).
        cases=(ICMP_ECHO_CASE, TTL_EXPIRED_CASE),
        plan_builders=_ICMP_PLAN_BUILDERS,
        # ICMP carries no planned-only cases (both builders materialize a plan).
        planned_only_cases=frozenset(),
        # ICMP's profile membership stays in the legacy ordered profile tables in
        # ``cases.py`` to preserve byte-identical selection order (the registry-
        # first profile merge would otherwise move ICMP to the front of the smoke
        # profile). Contribute nothing here.
        profile_counts={},
        stimulus_endpoint_cases=_ICMP_STIMULUS_ENDPOINT_CASES,
        # ICMP needs no responder target service (both cases ride a bare kernel),
        # so ``target_service`` / ``setup_script`` stay ``None`` and ICMP's cases
        # stay on the legacy target path, which produces no per-case ICMP service
        # entry. ``rewrite_endpoint_addresses`` reproduces the ICMP IPv4 rewrite
        # (shared head, ICMP overrides, shared tail); ``failure_reasons`` returns
        # the ICMP taxonomy for its two cases (``None`` otherwise);
        # ``lab_capabilities`` contributes ``icmp_echo``.
        target_service=None,
        setup_script=None,
        rewrite_endpoint_addresses=icmp_rewrite_endpoint_addresses,
        failure_reasons=icmp_failure_reasons,
        lab_capabilities=icmp_lab_capabilities,
    )
)
