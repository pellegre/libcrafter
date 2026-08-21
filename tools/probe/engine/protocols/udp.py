"""Deterministic UDP probe cases and packet plans."""

from __future__ import annotations
from ..case_helpers import _behavior_case
from ..model import JSONObject, ProbeCase, json_object
from ..planning_helpers import deterministic_bytes, deterministic_ipv4_pair
from .base import ProtocolPlugin, register

_UDP_CAPABILITIES = ["udp_service"]
_UDP_LARGE_CAPABILITIES = [*_UDP_CAPABILITIES, "udp_large_payload"]
_UDP_ZERO_CHECKSUM_IPV4_CAPABILITIES = [*_UDP_CAPABILITIES, "udp_ipv4_zero_checksum"]
_UDP_OPTIONS_SURPLUS_CAPABILITIES = [*_UDP_CAPABILITIES, "udp_options_surplus"]
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
        description="Send an IPv4 zero-checksum datagram and validate the response where the kernel accepts it.",
        stimulus="udp_datagram",
        expected_response="udp_response",
        required_capabilities=_UDP_ZERO_CHECKSUM_IPV4_CAPABILITIES,
        protocol="udp",
    ),
    _behavior_case(
        name="udp-options-surplus-echo",
        description="Send a UDP options surplus datagram and validate the response where the kernel accepts it.",
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
    *, label: str, profile: str, seed: int, sequence: int, length: int
) -> bytes:
    payload = bytearray()
    counter = 0
    while len(payload) < length:
        payload.extend(
            deterministic_bytes(f"{label}:{counter}", profile, seed, sequence)
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
        "capture_filter": f"udp and src host {target_ipv4} and dst host {stimulus_ipv4} and src port {destination_port} and dst port {planned_source_port}",
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
            "note": "UDP echo behavior runs against a controlled responder on the target endpoint, never a public service.",
        },
        "digest_hex": digest.hex()[:16],
    }


def _udp_echo_empty_probe_plan(
    *, case_name: str = "udp-echo-empty", profile: str, seed: int, sequence: int
) -> JSONObject:
    return _udp_echo_probe_plan(
        case_name=case_name, profile=profile, seed=seed, sequence=sequence, payload=b""
    )


def _udp_echo_short_probe_plan(
    *, case_name: str = "udp-echo-short", profile: str, seed: int, sequence: int
) -> JSONObject:
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
    *, case_name: str = "udp-echo-binary", profile: str, seed: int, sequence: int
) -> JSONObject:
    digest = deterministic_bytes("udp-echo-binary-payload", profile, seed, sequence)
    payload = bytes(
        [
            0,
            digest[0],
            127,
            128,
            digest[1],
            255,
            digest[2],
            0,
            digest[3],
            195,
            digest[4],
            254,
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
    *, case_name: str = "udp-echo-large", profile: str, seed: int, sequence: int
) -> JSONObject:
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
        "payload_mtu_header_overhead": UDP_ECHO_LARGE_IPV4_HEADER_LENGTH
        + UDP_ECHO_LARGE_UDP_HEADER_LENGTH,
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
        "payload_mtu_header_overhead": UDP_ECHO_LARGE_IPV4_HEADER_LENGTH
        + UDP_ECHO_LARGE_UDP_HEADER_LENGTH,
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
        plan["wire_requirements"], "udp_length_boundary.wire_requirements"
    )
    wire_requirements.update(
        {
            "requires_udp_large_payload": True,
            "note": "UDP length-boundary behavior sends one datagram just below the configured IPv4 no-fragment safety limit through a controlled echo responder.",
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
    payload_digest = deterministic_bytes(
        "udp-source-port-reflection-payload", profile, seed, sequence
    )
    port_digest = deterministic_bytes(
        "udp-source-port-reflection-source-port", profile, seed, sequence
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
        "capture_filter": f"udp and src host {target_ipv4} and dst host {source_ipv4} and src port {destination_port} and dst port {source_port}",
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
    *, case_name: str = "udp-multi-shot-order", profile: str, seed: int, sequence: int
) -> JSONObject:
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    source_port = 50000 + int.from_bytes(digest[0:2], "big") % 6000
    destination_port = 32000 + int.from_bytes(digest[2:4], "big") % 6000
    checksum_statuses = ["valid", "ipv4_no_checksum"]
    sends = []
    for index in range(3):
        payload_digest = deterministic_bytes(
            f"{case_name}:payload:{index}", profile, seed, sequence
        )
        sequence_marker = f"shot-{index:02d}"
        payload = f"udp-multi-shot-order:{sequence_marker}:{payload_digest.hex()[:12]}".encode(
            "ascii"
        )
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
        "capture_filter": first["capture_filter"],
        "validation": first["validation"],
        "wire_requirements": {
            "requires_udp_service": True,
            "requires_ipv4_unicast": True,
            "requires_controlled_service": True,
            "note": "UDP multi-shot order behavior runs against a controlled echo responder on the target endpoint, never a public service.",
        },
        "digest_hex": digest.hex()[:16],
    }


def _udp_closed_port_icmp_probe_plan(
    *, case_name: str = "udp-closed-port-icmp", profile: str, seed: int, sequence: int
) -> JSONObject:
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    source_port = 47000 + int.from_bytes(digest[0:2], "big") % 7000
    destination_port = 38000 + int.from_bytes(digest[2:4], "big") % 7000
    payload = (
        f"udp-closed-port-icmp:{profile}:{seed}:{sequence}:{digest.hex()[:16]}".encode(
            "ascii"
        )
    )
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
        "capture_filter": f"icmp and src host {target_ipv4} and dst host {stimulus_ipv4}",
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
            "note": "UDP closed-port behavior is target kernel ICMP generation. Target precondition verifies the UDP port is unbound and starts no responder.",
        },
        "digest_hex": digest.hex()[:16],
    }


def _udp_zero_checksum_ipv4_probe_plan(
    *, case_name: str = "udp-zero-checksum-ipv4", profile: str, seed: int, sequence: int
) -> JSONObject:
    digest = deterministic_bytes(
        "udp-zero-checksum-ipv4-payload", profile, seed, sequence
    )
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
    validation = json_object(plan["validation"], "udp_zero_checksum.validation")
    validation.update(checksum_metadata)
    plan["validation"] = validation
    wire_requirements = json_object(
        plan["wire_requirements"], "udp_zero_checksum.wire_requirements"
    )
    wire_requirements.update(
        {
            "requires_udp_ipv4_zero_checksum": True,
            "note": "IPv4 permits UDP checksum zero. The stimulus intentionally sets checksum 0; execution environments that drop such datagrams must skip via the udp_ipv4_zero_checksum capability.",
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
    payload_digest = deterministic_bytes(
        "udp-options-surplus-echo-payload", profile, seed, sequence
    )
    option_digest = deterministic_bytes(
        "udp-options-surplus-echo-options", profile, seed, sequence
    )
    payload = f"udp-options-surplus-echo:{payload_digest.hex()[:12]}".encode("ascii")
    mds_size = 1200 + option_digest[4] % 48
    req_token = int.from_bytes(option_digest[0:4], "big")
    req_token_bytes = req_token.to_bytes(4, "big")
    option_bytes = bytes(
        [1, 4, 4, *mds_size.to_bytes(2, "big"), 6, 6, *req_token_bytes, 0]
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
    surplus_alignment_length = (
        UDP_ECHO_LARGE_IPV4_HEADER_LENGTH + expected_udp_length & 1
    )
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
        "expected_ipv4_total_length": UDP_ECHO_LARGE_IPV4_HEADER_LENGTH
        + expected_udp_length
        + expected_surplus_length,
    }
    plan.update(surplus_metadata)
    validation = json_object(plan["validation"], "udp_options_surplus.validation")
    validation.update(surplus_metadata)
    plan["validation"] = validation
    wire_requirements = json_object(
        plan["wire_requirements"], "udp_options_surplus.wire_requirements"
    )
    wire_requirements.update(
        {
            "requires_udp_options_surplus": True,
            "note": "UDP options are carried as surplus after the UDP payload length. Execution environments that drop such datagrams must skip via the udp_options_surplus capability.",
        }
    )
    plan["wire_requirements"] = wire_requirements
    return plan


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


def udp_failure_reasons(case_name: str) -> list[str] | None:
    return None


register(
    ProtocolPlugin(
        name="udp",
        cases=BEHAVIOR_UDP_CASES,
        plan_builders=_UDP_PLAN_BUILDERS,
        planned_only_cases=frozenset(),
        profile_counts={},
        stimulus_endpoint_cases=_UDP_STIMULUS_ENDPOINT_CASES,
        failure_reasons=udp_failure_reasons,
    )
)
