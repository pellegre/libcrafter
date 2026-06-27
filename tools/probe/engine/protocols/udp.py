"""UDP probe protocol plugin: cases, plan builders, and planning surface.

This is the UDP *planning half* migration (after the ARP vertical slice and the
DNS / DHCPv4 migrations). It bundles UDP's planning surface in one place:

* the ten UDP behavioral cases plus the UDP capability constants (the catalog
  contribution),
* the ``_udp_*_probe_plan`` plan builders, the multi-send
  ``_udp_multi_shot_order_send`` helper, the shared ``_udp_echo_probe_plan``
  scaffolding, the deterministic payload helper, and the UDP MTU/length-boundary
  constants (the plan-builder contribution),
* and the UDP stimulus-endpoint routing set.

The plan builders and the deterministic helpers are moved verbatim from
:mod:`tools.probe.engine.planning`; :mod:`planning` re-imports the builders, the
multi-send helper, and the UDP MTU/length-boundary constants so
``planning._<builder>`` / ``planning.PLAN_BUILDERS[name]`` (the UDP behavior
tests' ``assertIs`` pins) and the ``planning.UDP_ECHO_LARGE_*`` /
``planning.UDP_LENGTH_BOUNDARY_*`` constants the tests read keep identical object
identity / value. UDP carries no ``planned_only`` cases, and its
``profile_counts`` is intentionally empty: the ten UDP behavioral cases sit
between NDP and OSPF in the ``behavior`` profile in a fixed, order-sensitive
position, and the registry-first profile merge would move the registry
contribution to the front of that profile, so the legacy ordered profile name
tables in :mod:`tools.probe.engine.cases` keep owning UDP's profile membership to
preserve byte-identical selection order.

The UDP target-service / address-rewrite / failure-reason / lab-capability hooks
complete the migration here (step 24): the ``target_service`` hook contributes
the ``udp-responder`` service entries *and* the ``closed_udp_ports`` entries for
the closed-port case (and diverts all ten UDP cases off the legacy target path);
the co-located setup-script blocks (the closed-UDP-port free check and the UDP
responder heredoc + launch) are called directly by
``target_services.target_service_setup_script`` because they need the planned
UDP plans the ``setup_script`` hook is not handed; the
``rewrite_endpoint_addresses`` hook reproduces the UDP live-path rewrite (all
ten UDP cases carry a UDP-specific rewrite, so none falls through); the
``failure_reasons`` hook reproduces the UDP failure taxonomy; and the
``lab_capabilities`` hook contributes the ``udp_*`` derived capabilities
(``udp_service`` / ``udp_large_payload`` / ``udp_ipv4_zero_checksum`` /
``udp_options_surplus`` / ``privileged_udp_port``, plus the advertised
``udp_safe_payload_size`` echo when present).

Imports are relative only so the module loads under both engine import roots
(``engine.protocols.udp`` for the CLI and ``tools.probe.engine.protocols.udp``
for the tests).
"""

from __future__ import annotations

import json
import posixpath
import shlex
from collections.abc import Mapping, Sequence

from ..capability_derivation import (
    capability,
    capability_default_true,
    optional_positive_int,
)
from ..case_helpers import _behavior_case
from ..endpoint_addressing import (
    FAILURE_DECODE_FAILED,
    FAILURE_TARGET_SETUP_FAILED,
    FAILURE_TIMEOUT,
    FAILURE_WRONG_PAYLOAD,
    FAILURE_WRONG_PEER,
    apply_shared_ipv4_rewrite_tail,
)
from ..model import JSONObject, JSONValue, ProbeCase, json_object
from ..planning_helpers import (
    deterministic_bytes,
    deterministic_ipv4_pair,
)
from ..target_service_helpers import (
    KernelStateDescriptor,
    TargetServiceDescriptor,
    dedupe_ints,
    plans_by_destination_port,
    target_service_address_fields,
)
from .base import ProtocolPlugin, register


# Capabilities required by each UDP behavioral case. UDP needs only IPv4 unicast
# plus a controlled UDP service; the large/zero-checksum/options variants add a
# wire-level capability gate so providers that cannot carry those datagrams skip
# the case with a stable reason. The capability names match the probe capability
# derivation in :mod:`tools.probe.engine.lab`.
_UDP_CAPABILITIES = ["udp_service"]
_UDP_LARGE_CAPABILITIES = [*_UDP_CAPABILITIES, "udp_large_payload"]
_UDP_ZERO_CHECKSUM_IPV4_CAPABILITIES = [
    *_UDP_CAPABILITIES,
    "udp_ipv4_zero_checksum",
]
_UDP_OPTIONS_SURPLUS_CAPABILITIES = [
    *_UDP_CAPABILITIES,
    "udp_options_surplus",
]


# Ten UDP behavioral cases (datagram echo/transform and kernel ICMP behavior
# against controlled UDP services bound to the target address).
BEHAVIOR_UDP_CASES: tuple[ProbeCase, ...] = (
    _behavior_case(
        name="udp-echo-empty",
        description="Echo an empty payload and validate the echoed response.",
        stimulus="udp_datagram",
        expected_response="udp_response",
        required_capabilities=_UDP_CAPABILITIES,
        protocol="udp",
    ),
    _behavior_case(
        name="udp-echo-short",
        description="Echo a short ASCII payload and validate the echoed response.",
        stimulus="udp_datagram",
        expected_response="udp_response",
        required_capabilities=_UDP_CAPABILITIES,
        protocol="udp",
    ),
    _behavior_case(
        name="udp-echo-binary",
        description="Echo a binary payload and validate the echoed response.",
        stimulus="udp_datagram",
        expected_response="udp_response",
        required_capabilities=_UDP_CAPABILITIES,
        protocol="udp",
    ),
    _behavior_case(
        name="udp-echo-large",
        description="Echo a large non-fragmenting payload and validate the response.",
        stimulus="udp_datagram",
        expected_response="udp_response",
        required_capabilities=_UDP_LARGE_CAPABILITIES,
        protocol="udp",
    ),
    _behavior_case(
        name="udp-source-port-reflection",
        description="Validate that the response reflects the source port.",
        stimulus="udp_datagram",
        expected_response="udp_response",
        required_capabilities=_UDP_CAPABILITIES,
        protocol="udp",
    ),
    _behavior_case(
        name="udp-multi-shot-order",
        description="Send multiple datagrams and validate ordered echoed responses.",
        stimulus="udp_datagram",
        expected_response="udp_response",
        required_capabilities=_UDP_CAPABILITIES,
        protocol="udp",
    ),
    _behavior_case(
        name="udp-closed-port-icmp",
        description="Send to a closed port and validate an ICMP port unreachable.",
        stimulus="udp_datagram",
        expected_response="icmp_port_unreachable",
        required_capabilities=_UDP_CAPABILITIES,
        protocol="udp",
    ),
    _behavior_case(
        name="udp-zero-checksum-ipv4",
        description=(
            "Send an IPv4 zero-checksum datagram and validate the response where the "
            "kernel accepts it."
        ),
        stimulus="udp_datagram",
        expected_response="udp_response",
        required_capabilities=_UDP_ZERO_CHECKSUM_IPV4_CAPABILITIES,
        protocol="udp",
    ),
    _behavior_case(
        name="udp-options-surplus-echo",
        description=(
            "Send a UDP options surplus datagram and validate the response where the "
            "kernel accepts it."
        ),
        stimulus="udp_datagram",
        expected_response="udp_response",
        required_capabilities=_UDP_OPTIONS_SURPLUS_CAPABILITIES,
        protocol="udp",
    ),
    _behavior_case(
        name="udp-length-boundary-echo",
        description="Echo a near-length-boundary payload and validate the response.",
        stimulus="udp_datagram",
        expected_response="udp_response",
        required_capabilities=_UDP_LARGE_CAPABILITIES,
        protocol="udp",
    ),
)


UDP_ECHO_LARGE_IPV4_HEADER_LENGTH = 20
UDP_ECHO_LARGE_UDP_HEADER_LENGTH = 8
UDP_ECHO_LARGE_IPV4_PACKET_SAFETY_LIMIT = 1400
UDP_ECHO_LARGE_MAX_PAYLOAD_LENGTH = (
    UDP_ECHO_LARGE_IPV4_PACKET_SAFETY_LIMIT
    - UDP_ECHO_LARGE_IPV4_HEADER_LENGTH
    - UDP_ECHO_LARGE_UDP_HEADER_LENGTH
)
UDP_LENGTH_BOUNDARY_PAYLOAD_MARGIN = 1
UDP_LENGTH_BOUNDARY_PAYLOAD_LENGTH = (
    UDP_ECHO_LARGE_MAX_PAYLOAD_LENGTH - UDP_LENGTH_BOUNDARY_PAYLOAD_MARGIN
)


def _deterministic_udp_payload(
    *,
    label: str,
    profile: str,
    seed: int,
    sequence: int,
    length: int,
) -> bytes:
    payload = bytearray()
    counter = 0
    while len(payload) < length:
        payload.extend(
            deterministic_bytes(
                f"{label}:{counter}",
                profile,
                seed,
                sequence,
            )
        )
        counter += 1
    return bytes(payload[:length])


def _udp_echo_probe_plan(
    *,
    case_name: str,
    profile: str,
    seed: int,
    sequence: int,
    payload: bytes,
    payload_metadata: JSONObject | None = None,
    source_port: int | None = None,
) -> JSONObject:
    """Plan a UDP datagram echoed by a controlled UDP responder."""

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    planned_source_port = source_port
    if planned_source_port is None:
        planned_source_port = 46000 + int.from_bytes(digest[0:2], "big") % 8000
    destination_port = 30000 + int.from_bytes(digest[2:4], "big") % 8000
    payload_hex = payload.hex()
    payload_length = len(payload)
    expected_udp_length = 8 + payload_length
    checksum_statuses = ["valid", "ipv4_no_checksum"]
    extra_payload_metadata = dict(payload_metadata or {})
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "udp_datagram",
        "expected_response": "udp_response",
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": planned_source_port,
        "destination_port": destination_port,
        "payload_hex": payload_hex,
        "payload_length": payload_length,
        "expected_payload_hex": payload_hex,
        "expected_payload_length": payload_length,
        "expected_udp_length": expected_udp_length,
        "expected_udp_checksum_present": True,
        "expected_udp_checksum_statuses": checksum_statuses,
        **extra_payload_metadata,
        "target_service": {
            "required": True,
            "kind": "udp-responder",
            "mode": "echo",
            "port": destination_port,
            "bind_ipv4": target_ipv4,
            "source_ipv4": stimulus_ipv4,
            "payload_hex": payload_hex,
            "payload_length": payload_length,
            **extra_payload_metadata,
            "deterministic": True,
        },
        "capture_filter": (
            f"udp and src host {target_ipv4} and dst host {stimulus_ipv4} "
            f"and src port {destination_port} and dst port {planned_source_port}"
        ),
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "source_port": destination_port,
            "destination_port": planned_source_port,
            "payload_hex": payload_hex,
            "payload_length": payload_length,
            "udp_length": expected_udp_length,
            "checksum_present": True,
            "checksum_statuses": checksum_statuses,
            **extra_payload_metadata,
        },
        "wire_requirements": {
            "requires_udp_service": True,
            "requires_ipv4_unicast": True,
            "requires_controlled_service": True,
            "note": (
                "UDP echo behavior runs against a controlled responder on the "
                "target endpoint, never a public service."
            ),
        },
        "digest_hex": digest.hex()[:16],
    }


def _udp_echo_empty_probe_plan(
    *,
    case_name: str = "udp-echo-empty",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan an empty UDP datagram echoed by a controlled UDP responder."""

    return _udp_echo_probe_plan(
        case_name=case_name,
        profile=profile,
        seed=seed,
        sequence=sequence,
        payload=b"",
    )


def _udp_echo_short_probe_plan(
    *,
    case_name: str = "udp-echo-short",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan a short ASCII UDP payload echoed by a controlled UDP responder."""

    digest = deterministic_bytes("udp-echo-short-payload", profile, seed, sequence)
    payload = f"udp-echo:{digest.hex()[:8]}".encode("ascii")
    return _udp_echo_probe_plan(
        case_name=case_name,
        profile=profile,
        seed=seed,
        sequence=sequence,
        payload=payload,
    )


def _udp_echo_binary_probe_plan(
    *,
    case_name: str = "udp-echo-binary",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan a binary UDP payload echoed by a controlled UDP responder."""

    digest = deterministic_bytes("udp-echo-binary-payload", profile, seed, sequence)
    payload = bytes(
        [
            0x00,
            digest[0],
            0x7F,
            0x80,
            digest[1],
            0xFF,
            digest[2],
            0x00,
            digest[3],
            0xC3,
            digest[4],
            0xFE,
        ]
    )
    return _udp_echo_probe_plan(
        case_name=case_name,
        profile=profile,
        seed=seed,
        sequence=sequence,
        payload=payload,
    )


def _udp_echo_large_probe_plan(
    *,
    case_name: str = "udp-echo-large",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan a large UDP payload that stays below the private-network MTU limit."""

    # ``UDP_ECHO_LARGE_PAYLOAD_LENGTH`` lives in :mod:`tools.probe.engine.cases`
    # (it is also read by ``lab``). Import it lazily inside the builder to avoid a
    # module-init cycle: ``cases`` triggers ``protocols`` auto-discovery (which
    # imports this module) before its own module body finishes binding the
    # constant, so a top-level ``from ..cases import ...`` would fail.
    from ..cases import UDP_ECHO_LARGE_PAYLOAD_LENGTH

    if UDP_ECHO_LARGE_PAYLOAD_LENGTH > UDP_ECHO_LARGE_MAX_PAYLOAD_LENGTH:
        raise ValueError("large UDP echo payload exceeds the MTU safety limit")
    payload = _deterministic_udp_payload(
        label="udp-echo-large-payload",
        profile=profile,
        seed=seed,
        sequence=sequence,
        length=UDP_ECHO_LARGE_PAYLOAD_LENGTH,
    )
    payload_metadata: JSONObject = {
        "payload_size_policy": "large_non_fragmenting",
        "payload_mtu_safety_limit": UDP_ECHO_LARGE_IPV4_PACKET_SAFETY_LIMIT,
        "payload_mtu_header_overhead": (
            UDP_ECHO_LARGE_IPV4_HEADER_LENGTH + UDP_ECHO_LARGE_UDP_HEADER_LENGTH
        ),
        "max_non_fragmenting_payload_length": UDP_ECHO_LARGE_MAX_PAYLOAD_LENGTH,
    }
    return _udp_echo_probe_plan(
        case_name=case_name,
        profile=profile,
        seed=seed,
        sequence=sequence,
        payload=payload,
        payload_metadata=payload_metadata,
    )


def _udp_length_boundary_echo_probe_plan(
    *,
    case_name: str = "udp-length-boundary-echo",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan a UDP echo payload one byte below the IPv4 packet safety limit."""

    if UDP_LENGTH_BOUNDARY_PAYLOAD_LENGTH >= UDP_ECHO_LARGE_MAX_PAYLOAD_LENGTH:
        raise ValueError("boundary UDP echo payload must stay below the safety limit")
    payload = _deterministic_udp_payload(
        label="udp-length-boundary-echo-payload",
        profile=profile,
        seed=seed,
        sequence=sequence,
        length=UDP_LENGTH_BOUNDARY_PAYLOAD_LENGTH,
    )
    expected_ipv4_total_length = (
        UDP_ECHO_LARGE_IPV4_HEADER_LENGTH
        + UDP_ECHO_LARGE_UDP_HEADER_LENGTH
        + UDP_LENGTH_BOUNDARY_PAYLOAD_LENGTH
    )
    payload_metadata: JSONObject = {
        "payload_size_policy": "near_boundary_non_fragmenting",
        "payload_boundary_margin": UDP_LENGTH_BOUNDARY_PAYLOAD_MARGIN,
        "payload_mtu_safety_limit": UDP_ECHO_LARGE_IPV4_PACKET_SAFETY_LIMIT,
        "payload_mtu_header_overhead": (
            UDP_ECHO_LARGE_IPV4_HEADER_LENGTH + UDP_ECHO_LARGE_UDP_HEADER_LENGTH
        ),
        "max_non_fragmenting_payload_length": UDP_ECHO_LARGE_MAX_PAYLOAD_LENGTH,
        "expected_ipv4_total_length": expected_ipv4_total_length,
    }
    plan = _udp_echo_probe_plan(
        case_name=case_name,
        profile=profile,
        seed=seed,
        sequence=sequence,
        payload=payload,
        payload_metadata=payload_metadata,
    )
    wire_requirements = json_object(
        plan["wire_requirements"],
        "udp_length_boundary.wire_requirements",
    )
    wire_requirements.update(
        {
            "requires_udp_large_payload": True,
            "note": (
                "UDP length-boundary behavior sends one datagram just below "
                "the configured IPv4 no-fragment safety limit through a "
                "controlled echo responder."
            ),
        }
    )
    plan["wire_requirements"] = wire_requirements
    return plan


def _udp_source_port_reflection_probe_plan(
    *,
    case_name: str = "udp-source-port-reflection",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan a UDP echo response that must target the stimulus source port."""

    payload_digest = deterministic_bytes(
        "udp-source-port-reflection-payload",
        profile,
        seed,
        sequence,
    )
    port_digest = deterministic_bytes(
        "udp-source-port-reflection-source-port",
        profile,
        seed,
        sequence,
    )
    payload = f"udp-source-port:{payload_digest.hex()[:8]}".encode("ascii")
    source_port = 60000 + int.from_bytes(port_digest[0:2], "big") % 4000
    payload_metadata: JSONObject = {
        "source_port_policy": "deterministic_high",
        "source_port_reflection": True,
    }
    return _udp_echo_probe_plan(
        case_name=case_name,
        profile=profile,
        seed=seed,
        sequence=sequence,
        payload=payload,
        payload_metadata=payload_metadata,
        source_port=source_port,
    )


def _udp_multi_shot_order_send(
    *,
    index: int,
    source_ipv4: str,
    target_ipv4: str,
    source_port: int,
    destination_port: int,
    payload: bytes,
    sequence_marker: str,
    checksum_statuses: list[str],
) -> JSONObject:
    payload_hex = payload.hex()
    payload_length = len(payload)
    expected_udp_length = 8 + payload_length
    return {
        "index": index,
        "sequence_marker": sequence_marker,
        "source_ipv4": source_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": source_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "payload_hex": payload_hex,
        "payload_length": payload_length,
        "expected_payload_hex": payload_hex,
        "expected_payload_length": payload_length,
        "expected_udp_length": expected_udp_length,
        "expected_udp_checksum_present": True,
        "expected_udp_checksum_statuses": checksum_statuses,
        "capture_filter": (
            f"udp and src host {target_ipv4} and dst host {source_ipv4} "
            f"and src port {destination_port} and dst port {source_port}"
        ),
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": source_ipv4,
            "source_port": destination_port,
            "destination_port": source_port,
            "sequence_marker": sequence_marker,
            "payload_hex": payload_hex,
            "payload_length": payload_length,
            "udp_length": expected_udp_length,
            "checksum_present": True,
            "checksum_statuses": checksum_statuses,
        },
    }


def _udp_multi_shot_order_probe_plan(
    *,
    case_name: str = "udp-multi-shot-order",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan three ordered UDP datagrams echoed by one controlled responder."""

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    source_port = 50000 + int.from_bytes(digest[0:2], "big") % 6000
    destination_port = 32000 + int.from_bytes(digest[2:4], "big") % 6000
    checksum_statuses = ["valid", "ipv4_no_checksum"]
    sends = []
    for index in range(3):
        payload_digest = deterministic_bytes(
            f"{case_name}:payload:{index}",
            profile,
            seed,
            sequence,
        )
        sequence_marker = f"shot-{index:02d}"
        payload = (
            f"udp-multi-shot-order:{sequence_marker}:{payload_digest.hex()[:12]}"
        ).encode("ascii")
        sends.append(
            _udp_multi_shot_order_send(
                index=index,
                source_ipv4=stimulus_ipv4,
                target_ipv4=target_ipv4,
                source_port=source_port,
                destination_port=destination_port,
                payload=payload,
                sequence_marker=sequence_marker,
                checksum_statuses=checksum_statuses,
            )
        )

    first = sends[0]
    sequence_markers = [str(send["sequence_marker"]) for send in sends]
    ordered_payloads = [
        {
            "index": send["index"],
            "sequence_marker": send["sequence_marker"],
            "payload_hex": send["payload_hex"],
            "payload_length": send["payload_length"],
        }
        for send in sends
    ]
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "udp_datagram",
        "expected_response": "udp_response",
        # Conventional single-send top-level fields mirror the first datagram so
        # the generic plan echo, capture filter, and single-send consumers keep
        # working while the UDP dispatch detects `udp_sends` and drives all sends.
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "sequence_marker": first["sequence_marker"],
        "sequence_markers": sequence_markers,
        "payload_hex": first["payload_hex"],
        "payload_length": first["payload_length"],
        "expected_payload_hex": first["expected_payload_hex"],
        "expected_payload_length": first["expected_payload_length"],
        "expected_udp_length": first["expected_udp_length"],
        "expected_udp_checksum_present": True,
        "expected_udp_checksum_statuses": checksum_statuses,
        "multi_shot_order": True,
        "send_count": len(sends),
        "udp_sends": sends,
        "target_service": {
            "required": True,
            "kind": "udp-responder",
            "mode": "echo",
            "port": destination_port,
            "bind_ipv4": target_ipv4,
            "source_ipv4": stimulus_ipv4,
            "multi_shot_order": True,
            "send_count": len(sends),
            "sequence_markers": sequence_markers,
            "ordered_payloads": ordered_payloads,
            "deterministic": True,
        },
        "capture_filter": first["capture_filter"],
        "validation": first["validation"],
        "wire_requirements": {
            "requires_udp_service": True,
            "requires_ipv4_unicast": True,
            "requires_controlled_service": True,
            "note": (
                "UDP multi-shot order behavior runs against a controlled echo "
                "responder on the target endpoint, never a public service."
            ),
        },
        "digest_hex": digest.hex()[:16],
    }


def _udp_closed_port_icmp_probe_plan(
    *,
    case_name: str = "udp-closed-port-icmp",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan a UDP datagram whose closed target port triggers ICMP port-unreachable."""

    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    source_port = 47000 + int.from_bytes(digest[0:2], "big") % 7000
    destination_port = 38000 + int.from_bytes(digest[2:4], "big") % 7000
    payload = (
        f"udp-closed-port-icmp:{profile}:{seed}:{sequence}:"
        f"{digest.hex()[:16]}"
    ).encode("ascii")
    payload_hex = payload.hex()
    payload_length = len(payload)
    embedded_prefix_length = 28
    expected_udp_length = 8 + payload_length
    return {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": "udp_datagram",
        "expected_response": "icmp_port_unreachable",
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": destination_port,
        "payload_hex": payload_hex,
        "payload_length": payload_length,
        "expected_payload_hex": payload_hex,
        "expected_payload_length": payload_length,
        "expected_udp_length": expected_udp_length,
        "expected_icmp_type": 3,
        "expected_icmp_code": 3,
        "expected_embedded_prefix_length": embedded_prefix_length,
        "target_service": {
            "required": False,
            "kind": "closed-udp-port",
            "port": destination_port,
            "bind_ipv4": target_ipv4,
            "source_ipv4": stimulus_ipv4,
            "state": "planned-unbound",
            "expects": "icmp_port_unreachable",
            "deterministic": True,
        },
        "capture_filter": (
            f"icmp and src host {target_ipv4} and dst host {stimulus_ipv4}"
        ),
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "icmp_type": 3,
            "icmp_code": 3,
            "embedded_prefix": {
                "source": "stimulus_sent_bytes",
                "length": embedded_prefix_length,
                "meaning": "original IPv4 header plus first eight bytes of UDP datagram",
            },
            "embedded_udp": {
                "source_port": source_port,
                "destination_port": destination_port,
                "udp_length": expected_udp_length,
            },
        },
        "wire_requirements": {
            "requires_ipv4_unicast": True,
            "requires_closed_udp_port": True,
            "requires_no_udp_service": True,
            "note": (
                "UDP closed-port behavior is target kernel ICMP generation. "
                "Target setup verifies the UDP port is unbound and starts no "
                "responder."
            ),
        },
        "digest_hex": digest.hex()[:16],
    }


def _udp_zero_checksum_ipv4_probe_plan(
    *,
    case_name: str = "udp-zero-checksum-ipv4",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan an IPv4 UDP datagram with an explicit zero checksum override."""

    digest = deterministic_bytes("udp-zero-checksum-ipv4-payload", profile, seed, sequence)
    payload = f"udp-zero-checksum-ipv4:{digest.hex()[:12]}".encode("ascii")
    plan = _udp_echo_probe_plan(
        case_name=case_name,
        profile=profile,
        seed=seed,
        sequence=sequence,
        payload=payload,
    )
    checksum_metadata: JSONObject = {
        "stimulus_udp_checksum": 0,
        "stimulus_udp_checksum_override": True,
        "stimulus_udp_checksum_policy": "ipv4_zero_checksum_override",
    }
    plan.update(checksum_metadata)
    target_service = json_object(plan["target_service"], "udp_zero_checksum.target_service")
    target_service.update(
        {
            **checksum_metadata,
            "kernel_acceptance": "provider_dependent",
        }
    )
    plan["target_service"] = target_service
    validation = json_object(plan["validation"], "udp_zero_checksum.validation")
    validation.update(checksum_metadata)
    plan["validation"] = validation
    wire_requirements = json_object(
        plan["wire_requirements"],
        "udp_zero_checksum.wire_requirements",
    )
    wire_requirements.update(
        {
            "requires_udp_ipv4_zero_checksum": True,
            "note": (
                "IPv4 permits UDP checksum zero. The stimulus intentionally "
                "sets checksum 0; providers that drop such datagrams must "
                "skip via the udp_ipv4_zero_checksum capability."
            ),
        }
    )
    plan["wire_requirements"] = wire_requirements
    return plan


def _udp_options_surplus_echo_probe_plan(
    *,
    case_name: str = "udp-options-surplus-echo",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan a UDP echo stimulus with deterministic UDP surplus option bytes."""

    payload_digest = deterministic_bytes(
        "udp-options-surplus-echo-payload",
        profile,
        seed,
        sequence,
    )
    option_digest = deterministic_bytes(
        "udp-options-surplus-echo-options",
        profile,
        seed,
        sequence,
    )
    payload = f"udp-options-surplus-echo:{payload_digest.hex()[:12]}".encode("ascii")
    mds_size = 1200 + option_digest[4] % 48
    req_token = int.from_bytes(option_digest[0:4], "big")
    req_token_bytes = req_token.to_bytes(4, "big")
    # Option bytes after the UDP Option Checksum field. UdpOptions::from_bytes
    # preserves this exact option stream while compile() adds the RFC surplus
    # alignment and OCS envelope.
    option_bytes = bytes(
        [
            0x01,  # NOP
            0x04,  # MDS
            0x04,
            *mds_size.to_bytes(2, "big"),
            0x06,  # REQ
            0x06,
            *req_token_bytes,
            0x00,  # EOL
        ]
    )
    option_summary = [
        "NOP",
        f"MDS(size={mds_size})",
        f"REQ(token=0x{req_token:08x})",
        "EOL",
    ]
    plan = _udp_echo_probe_plan(
        case_name=case_name,
        profile=profile,
        seed=seed,
        sequence=sequence,
        payload=payload,
    )
    expected_udp_length = int(plan["expected_udp_length"])
    surplus_alignment_length = (UDP_ECHO_LARGE_IPV4_HEADER_LENGTH + expected_udp_length) & 1
    expected_surplus_length = surplus_alignment_length + 2 + len(option_bytes)
    surplus_metadata: JSONObject = {
        "udp_options_surplus": True,
        "stimulus_udp_options_hex": option_bytes.hex(),
        "stimulus_udp_options_policy": "deterministic_valid_surplus_options",
        "expected_udp_options_hex": option_bytes.hex(),
        "expected_udp_options_status": "valid",
        "expected_udp_options_summary": option_summary,
        "expected_udp_option_count": len(option_summary),
        "expected_udp_surplus_alignment_length": surplus_alignment_length,
        "expected_udp_surplus_length": expected_surplus_length,
        "expected_ipv4_total_length": (
            UDP_ECHO_LARGE_IPV4_HEADER_LENGTH
            + expected_udp_length
            + expected_surplus_length
        ),
    }
    plan.update(surplus_metadata)
    target_service = json_object(
        plan["target_service"],
        "udp_options_surplus.target_service",
    )
    target_service.update(
        {
            **surplus_metadata,
            "kernel_acceptance": "provider_dependent",
        }
    )
    plan["target_service"] = target_service
    validation = json_object(plan["validation"], "udp_options_surplus.validation")
    validation.update(surplus_metadata)
    plan["validation"] = validation
    wire_requirements = json_object(
        plan["wire_requirements"],
        "udp_options_surplus.wire_requirements",
    )
    wire_requirements.update(
        {
            "requires_udp_options_surplus": True,
            "note": (
                "UDP options are carried as surplus after the UDP payload length. "
                "Providers that drop such datagrams must skip via the "
                "udp_options_surplus capability."
            ),
        }
    )
    plan["wire_requirements"] = wire_requirements
    return plan


# Per-case plan-builder dispatch entries for the ten UDP behavioral cases. The
# registry merge in :mod:`tools.probe.engine.planning` exposes these through
# ``PLAN_BUILDERS`` (registry-first), and ``planning`` re-imports each function
# so ``planning._<builder>`` keeps identical object identity for the pinning
# tests.
_UDP_PLAN_BUILDERS: dict[str, object] = {
    "udp-echo-empty": _udp_echo_empty_probe_plan,
    "udp-echo-short": _udp_echo_short_probe_plan,
    "udp-echo-binary": _udp_echo_binary_probe_plan,
    "udp-echo-large": _udp_echo_large_probe_plan,
    "udp-length-boundary-echo": _udp_length_boundary_echo_probe_plan,
    "udp-source-port-reflection": _udp_source_port_reflection_probe_plan,
    "udp-multi-shot-order": _udp_multi_shot_order_probe_plan,
    "udp-closed-port-icmp": _udp_closed_port_icmp_probe_plan,
    "udp-zero-checksum-ipv4": _udp_zero_checksum_ipv4_probe_plan,
    "udp-options-surplus-echo": _udp_options_surplus_echo_probe_plan,
}


# The ten UDP behavioral cases route through the stimulus endpoint adapter.
_UDP_STIMULUS_ENDPOINT_CASES: frozenset[str] = frozenset(
    {
        "udp-echo-empty",
        "udp-echo-short",
        "udp-echo-binary",
        "udp-echo-large",
        "udp-length-boundary-echo",
        "udp-source-port-reflection",
        "udp-multi-shot-order",
        "udp-closed-port-icmp",
        "udp-zero-checksum-ipv4",
        "udp-options-surplus-echo",
    }
)


# --------------------------------------------------------------------------- #
# Target-service descriptors and case selectors (moved from target_services.py)
# --------------------------------------------------------------------------- #
#
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


def udp_responder_descriptor(
    *,
    bind_ipv4: str,
    source_ipv4: str,
    port: int,
    artifact_root: str,
) -> TargetServiceDescriptor:
    """Describe the controlled UDP echo/transform responder."""

    # Imported lazily so the plugin module loads during ``protocols`` package
    # auto-discovery without cycling through ``capabilities`` -> ``lab`` ->
    # ``protocols``. The constant is a plain skip-reason string.
    from ..capabilities import SKIP_REQUIRES_CONTROLLED_SERVICE

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


def udp_target_service_contribution(
    probe_plans: Sequence[JSONObject],
    *,
    dry_run: bool,
) -> JSONObject:
    """Return the UDP plugin's ``target_service_setup_plan`` contribution.

    Moved verbatim from the ``udp-responder`` ``services`` entries and the
    ``closed_udp_ports`` entries of the central ``target_service_setup_plan``:
    one controlled UDP responder service per distinct responder destination port,
    one closed-UDP-port verification entry per distinct closed-port destination,
    plus the ``starts_services`` flip on a live run that has at least one UDP
    responder to stand up. The registry merge appends these ``services`` /
    ``closed_udp_ports`` to the central lists and OR-s ``starts_services``,
    byte-identical to the legacy per-protocol path (which included
    ``udp_plans_by_port`` -- but not the closed-port plans -- in its
    ``starts_services`` OR).
    """

    udp_plans = udp_probe_plans(probe_plans)
    udp_plans_by_port = plans_by_destination_port(udp_plans)
    closed_udp_plans = closed_udp_probe_plans(probe_plans)
    closed_udp_plans_by_port = plans_by_destination_port(closed_udp_plans)
    services = [
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
    ]
    closed_udp_ports = [
        {
            "port": port,
            "state": "verified-unbound" if not dry_run else "planned-unbound",
            "purpose": "udp-closed-port-icmp",
            "expects": "icmp_port_unreachable",
            "deterministic": True,
            **target_service_address_fields(plan),
        }
        for port, plan in closed_udp_plans_by_port.items()
    ]
    return {
        "services": services,
        "closed_udp_ports": closed_udp_ports,
        "starts_services": not dry_run and bool(udp_plans_by_port),
    }


# --------------------------------------------------------------------------- #
# Target setup-script blocks (moved from target_services.target_service_setup_script)
# --------------------------------------------------------------------------- #
#
# The UDP setup-script contribution is split into two blocks that the legacy
# ``target_service_setup_script`` emitted at two distinct positions: a per-port
# closed-UDP-port free check (rendered after the closed TCP-port checks, before
# the open-port listeners) and the UDP responder heredoc + per-port launch loop
# (rendered after the DHCPv4 responder block, before the ARP block). They are
# co-located here and called *directly* by ``target_service_setup_script`` (the
# plugin ``setup_script`` hook receives no plan context), so the rendered bytes
# stay byte-identical to the legacy inline blocks.


def udp_closed_port_check_lines(closed_udp_ports: Sequence[int]) -> list[str]:
    """Render the closed-UDP-port free-check block for the setup script.

    Moved verbatim from the ``for port in closed_udp_ports:`` loop that ran after
    the closed TCP-port checks in ``target_service_setup_script``; binds
    ``$udp_bind_ipv4:port`` to confirm the port stays free so the target kernel
    emits ICMP port-unreachable.
    """

    lines: list[str] = []
    for port in closed_udp_ports:
        lines.append(f"check_udp_port_free \"$udp_bind_ipv4\" {port}")
        lines.append(f"echo closed_udp_port_{port}=free")
    return lines


def udp_responder_setup_lines(
    *,
    artifact_root: str,
    udp_plans: Sequence[JSONObject],
) -> list[str]:
    """Render the UDP responder heredoc + launch block for the setup script.

    Moved verbatim from the ``if udp_ports:`` responder heredoc and the
    subsequent ``for port in udp_ports:`` launch loop of
    ``target_service_setup_script``; the orchestrator calls this with the planned
    UDP plans so the rendered script bytes stay byte-identical.
    """

    udp_ports = dedupe_ints(
        int(plan["destination_port"])
        for plan in udp_plans
        if isinstance(plan.get("destination_port"), int)
    )
    lines: list[str] = []
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
    return lines


# --------------------------------------------------------------------------- #
# Live-path address rewrite (moved from cli._probe_plan_with_endpoint_addresses)
# --------------------------------------------------------------------------- #
#
# The legacy UDP rewrite branch matched all ten UDP cases, so the plugin set is
# the full UDP stimulus-endpoint case set: every UDP case carries the
# UDP-specific rewrite plus the shared transport-IPv4 pre-sets and the shared
# IPv4-layer tail.


def udp_rewrite_endpoint_addresses(
    plan: JSONObject,
    *,
    source_ipv4: str,
    target_ipv4: str,
    source_mac: str | None = None,
    target_mac: str | None = None,
    target_interface: str | None = None,
    rewrite_source: str = "wire_endpoint_plan",
) -> JSONObject:
    """Rewrite a UDP probe plan onto the live lab-segment addresses.

    Moved verbatim from the UDP branch of
    ``cli._probe_plan_with_endpoint_addresses`` (including the shared
    transport-IPv4 pre-sets that ran before the per-protocol if/elif). The
    closed-port case validates the target kernel's ICMP port-unreachable, so its
    capture filter watches ICMP from the target; every other UDP case watches the
    echoed datagram from the responder. The multi-shot case carries a per-send
    ``udp_sends`` array whose transport addresses, capture filters, and
    validation contracts are rewritten onto the lab segment while the ordered
    payload markers stay intact. The branch then falls into the shared
    IPv4-layer validation/live-rewrite tail, applied here.
    """

    updated = dict(plan)
    updated["source_ipv4"] = source_ipv4
    updated["destination_ipv4"] = target_ipv4
    updated["expected_reply_source_ipv4"] = target_ipv4
    updated["expected_reply_destination_ipv4"] = source_ipv4
    case_name = str(updated.get("case", ""))
    source_port = int(updated.get("source_port", 0))
    destination_port = int(updated.get("destination_port", 0))
    if case_name == "udp-closed-port-icmp":
        updated["capture_filter"] = (
            f"icmp and src host {target_ipv4} and dst host {source_ipv4}"
        )
    else:
        updated["capture_filter"] = (
            f"udp and src host {target_ipv4} and dst host {source_ipv4} "
            f"and src port {destination_port} and dst port {source_port}"
        )
    target_service = dict(
        json_object(updated.get("target_service", {}), "probe_plan.target_service")
    )
    target_service.update(
        {
            "bind_ipv4": target_ipv4,
            "port": destination_port,
            "source_ipv4": source_ipv4,
        }
    )
    updated["target_service"] = target_service
    udp_validation = dict(
        json_object(updated.get("validation", {}), "probe_plan.validation")
    )
    udp_validation["source_ipv4"] = target_ipv4
    udp_validation["destination_ipv4"] = source_ipv4
    updated["validation"] = udp_validation
    # udp-multi-shot-order carries a per-send array: rewrite each datagram's
    # transport addresses, capture filter, and validation contract onto the
    # lab segment while preserving the ordered payload markers.
    udp_sends = updated.get("udp_sends")
    if isinstance(udp_sends, list):
        rewritten_udp_sends: list[JSONObject] = []
        for raw_send in udp_sends:
            send = dict(json_object(raw_send, "probe_plan.udp_send"))
            send_source_port = int(send.get("source_port", source_port))
            send_destination_port = int(send.get("destination_port", destination_port))
            send["source_ipv4"] = source_ipv4
            send["destination_ipv4"] = target_ipv4
            send["expected_reply_source_ipv4"] = target_ipv4
            send["expected_reply_destination_ipv4"] = source_ipv4
            send["capture_filter"] = (
                f"udp and src host {target_ipv4} and dst host {source_ipv4} "
                f"and src port {send_destination_port} and dst port {send_source_port}"
            )
            send_validation = dict(
                json_object(send.get("validation", {}), "probe_plan.udp_send.validation")
            )
            send_validation["source_ipv4"] = target_ipv4
            send_validation["destination_ipv4"] = source_ipv4
            send["validation"] = send_validation
            rewritten_udp_sends.append(send)
        updated["udp_sends"] = rewritten_udp_sends
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


def udp_failure_reasons(case_name: str) -> list[str] | None:
    """Return the ordered UDP failure-reason taxonomy for ``case_name``.

    Moved verbatim from the UDP branch of ``cli._failure_reasons_for_case`` (all
    ten UDP cases). Returns ``None`` for a non-matching case so the central
    dispatcher falls through to the next branch.
    """

    if case_name in _UDP_STIMULUS_ENDPOINT_CASES:
        return [
            FAILURE_TIMEOUT,
            FAILURE_WRONG_PEER,
            FAILURE_WRONG_PAYLOAD,
            FAILURE_DECODE_FAILED,
            FAILURE_TARGET_SETUP_FAILED,
        ]
    return None


# --------------------------------------------------------------------------- #
# Lab-capability derivation (moved from lab.probe_capabilities_from_lab_capabilities)
# --------------------------------------------------------------------------- #


def udp_lab_capabilities(substrate: Mapping[str, JSONValue]) -> Mapping[str, object]:
    """Return the UDP plugin's derived probe-capability contribution.

    Moved verbatim from the ``udp_*`` boolean derivations in
    ``lab.probe_capabilities_from_lab_capabilities``: the controlled UDP
    responder needs an IPv4-unicast substrate that can host a controlled service
    (``udp_service``); the large/length-boundary echo additionally needs the
    advertised safe payload size to clear the large-echo length
    (``udp_large_payload``); the zero-checksum and options-surplus echoes can be
    explicitly denied per provider (``udp_ipv4_zero_checksum`` /
    ``udp_options_surplus``); and a privileged UDP port rides the same
    IPv4-unicast + controlled-service substrate (``privileged_udp_port``). When
    the substrate advertises a safe UDP payload size, the derived capabilities
    echo it back as ``udp_safe_payload_size`` (the legacy body added the same
    key). The shared ``capability_names`` / ``capability_sources`` tables stay in
    ``lab``; this hook contributes only the derived ``udp_*`` values, merged
    byte-identically over the legacy values.
    """

    # ``UDP_ECHO_LARGE_PAYLOAD_LENGTH`` lives in :mod:`tools.probe.engine.cases`.
    # Import it lazily to avoid a module-init cycle: ``cases`` triggers
    # ``protocols`` auto-discovery (which imports this module) before its own
    # module body finishes binding the constant.
    from ..cases import UDP_ECHO_LARGE_PAYLOAD_LENGTH

    ipv4_unicast = capability(substrate, "ipv4_unicast", "ipv4")
    controlled_services = capability(
        substrate,
        "controlled_services",
        "controlled_service",
    )
    udp_service = ipv4_unicast and controlled_services
    advertised_udp_safe_payload = optional_positive_int(
        substrate,
        "udp_safe_payload_size",
        "safe_udp_payload_size",
        "max_udp_payload_size",
        "private_network_safe_udp_payload_size",
    )
    udp_large_payload = udp_service and (
        advertised_udp_safe_payload is None
        or advertised_udp_safe_payload >= UDP_ECHO_LARGE_PAYLOAD_LENGTH
    )
    udp_ipv4_zero_checksum = udp_service and capability_default_true(
        substrate,
        "udp_ipv4_zero_checksum",
        "ipv4_udp_zero_checksum",
    )
    udp_options_surplus = udp_service and capability_default_true(
        substrate,
        "udp_options_surplus",
        "udp_surplus_options",
    )
    privileged_udp_port = ipv4_unicast and controlled_services
    contribution: dict[str, object] = {
        "udp_service": udp_service,
        "udp_large_payload": udp_large_payload,
        "udp_ipv4_zero_checksum": udp_ipv4_zero_checksum,
        "udp_options_surplus": udp_options_surplus,
        "privileged_udp_port": privileged_udp_port,
    }
    if advertised_udp_safe_payload is not None:
        contribution["udp_safe_payload_size"] = advertised_udp_safe_payload
    return contribution


register(
    ProtocolPlugin(
        name="udp",
        # The ten UDP behavioral cases in declaration order.
        cases=BEHAVIOR_UDP_CASES,
        plan_builders=_UDP_PLAN_BUILDERS,
        # UDP carries no planned-only cases (every builder materializes a plan).
        planned_only_cases=frozenset(),
        # UDP's profile membership stays in the legacy ordered profile tables in
        # ``cases.py`` to preserve byte-identical selection order (the registry-
        # first profile merge would otherwise move UDP to the front of the
        # behavior profile). Contribute nothing here.
        profile_counts={},
        stimulus_endpoint_cases=_UDP_STIMULUS_ENDPOINT_CASES,
        # UDP target-service / address-rewrite / failure-reason / lab-capability
        # hooks (step 24, completing UDP). ``target_service`` contributes the
        # ``udp-responder`` services entries and the ``closed_udp_ports`` entries
        # (and diverts all ten UDP cases off the legacy target path).
        # ``setup_script`` stays ``None``: UDP's setup-script blocks (the
        # closed-UDP-port free check and the responder heredoc + launch) need the
        # planned UDP plans, which the plugin ``setup_script`` hook does not
        # receive, so ``target_services.target_service_setup_script`` renders them
        # by calling :func:`udp_closed_port_check_lines` /
        # :func:`udp_responder_setup_lines` directly (byte-identically to the
        # legacy inline blocks).
        target_service=udp_target_service_contribution,
        setup_script=None,
        rewrite_endpoint_addresses=udp_rewrite_endpoint_addresses,
        failure_reasons=udp_failure_reasons,
        lab_capabilities=udp_lab_capabilities,
    )
)
