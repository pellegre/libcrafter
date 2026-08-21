"""Deterministic COAP probe cases and packet plans."""

from __future__ import annotations
from collections.abc import Sequence
from ..case_helpers import _behavior_case
from ..validation import FAILURE_DECODE_FAILED, FAILURE_WRONG_PAYLOAD
from ..model import JSONObject, ProbeCase
from ..planning_helpers import deterministic_bytes
from .base import ProtocolPlugin, register

COAP_SMOKE_PROFILE = "coap-smoke"
COAP_PORT = 5683
_COAP_LIVE_CAPABILITIES = ["udp_service"]
_COAP_OFFLINE_CAPABILITIES: list[str] = []


def _case(
    name: str,
    description: str,
    stimulus: str,
    expected_response: str,
    *,
    live_capable: bool,
    transport: str = "udp",
    message_kind: str,
) -> ProbeCase:
    metadata: JSONObject = {
        "transport": transport,
        "message_kind": message_kind,
        "planned_only": True,
        "live_capable": live_capable,
    }
    if not live_capable:
        metadata["offline_only"] = True
    return _behavior_case(
        name=name,
        description=description,
        stimulus=stimulus,
        expected_response=expected_response,
        required_capabilities=(
            _COAP_LIVE_CAPABILITIES if live_capable else _COAP_OFFLINE_CAPABILITIES
        ),
        protocol="coap",
        metadata=metadata,
    )


COAP_PROBE_CASES: tuple[ProbeCase, ...] = (
    _case(
        "coap-unicast-get-content",
        "Plan a confirmable unicast GET and piggybacked Content response.",
        "coap_confirmable_get",
        "coap_ack_content",
        live_capable=True,
        message_kind="unicast_get_content",
    ),
    _case(
        "coap-empty-ack-separate-response",
        "Plan an Empty ACK followed by a separate confirmable Content response.",
        "coap_confirmable_get",
        "coap_empty_ack_then_separate_content",
        live_capable=True,
        message_kind="empty_ack_separate_response",
    ),
    _case(
        "coap-reset",
        "Plan a confirmable message answered by an Empty Reset.",
        "coap_confirmable_get",
        "coap_empty_reset",
        live_capable=True,
        message_kind="reset",
    ),
    _case(
        "coap-observe-notification",
        "Plan Observe registration and one bounded notification.",
        "coap_observe_register",
        "coap_observe_notification",
        live_capable=True,
        message_kind="observe_notification",
    ),
    _case(
        "coap-block1-transfer",
        "Plan one bounded Block1 request and Continue response.",
        "coap_block1_request",
        "coap_continue_response",
        live_capable=True,
        message_kind="block1",
    ),
    _case(
        "coap-block2-transfer",
        "Plan one bounded Block2 request and Content response.",
        "coap_block2_request",
        "coap_block2_content",
        live_capable=True,
        message_kind="block2",
    ),
    _case(
        "coap-echo-request-tag",
        "Plan opaque Echo and Request-Tag correlation with a controlled peer.",
        "coap_echo_request_tag",
        "coap_echo_request_tag_content",
        live_capable=True,
        message_kind="echo_request_tag",
    ),
    _case(
        "coap-qblock-planning",
        "Plan Q-Block metadata without scheduling or burst execution.",
        "coap_qblock_request",
        "coap_qblock_plan",
        live_capable=False,
        message_kind="qblock",
    ),
    _case(
        "coap-reliable-csm",
        "Plan one complete reliable-transport CSM frame.",
        "coap_reliable_csm",
        "coap_reliable_csm_observed",
        live_capable=False,
        transport="tcp",
        message_kind="reliable_csm",
    ),
    _case(
        "coap-reliable-ping",
        "Plan one complete reliable-transport Ping/Pong exchange.",
        "coap_reliable_ping",
        "coap_reliable_pong",
        live_capable=False,
        transport="tcp",
        message_kind="reliable_ping",
    ),
    _case(
        "coap-malformed-raw-fallback",
        "Plan malformed service-port bytes that registry dispatch preserves as Raw.",
        "coap_malformed_candidate",
        "coap_raw_fallback",
        live_capable=False,
        message_kind="malformed_raw_fallback",
    ),
    _case(
        "coap-oscore-vector-exchange",
        "Plan RFC 8613 Appendix C protected bytes without preparation secrets.",
        "coap_oscore_request_vector",
        "coap_oscore_response_vector",
        live_capable=False,
        message_kind="oscore_vector",
    ),
)
_COAP_CASE_BY_NAME = {case.name: case for case in COAP_PROBE_CASES}
_COAP_LIVE_CAPABLE_CASES = frozenset(
    (
        case.name
        for case in COAP_PROBE_CASES
        if case.metadata.get("live_capable") is True
    )
)
_COAP_PLANNED_ONLY_CASES = frozenset(_COAP_CASE_BY_NAME) - _COAP_LIVE_CAPABLE_CASES


def _coap_probe_plan(
    *, case_name: str, profile: str, seed: int, sequence: int
) -> JSONObject:
    case = _COAP_CASE_BY_NAME[case_name]
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    source_ipv4, target_ipv4 = _documentation_ipv4_pair(digest)
    source_port = _ephemeral_port(digest)
    message_id = int.from_bytes(digest[4:6], "big")
    response_message_id = int.from_bytes(digest[6:8], "big")
    token = digest[8:10]
    request, responses, request_model, response_models = _exchange_bytes(
        case_name,
        message_id=message_id,
        response_message_id=response_message_id,
        token=token,
        digest=digest,
    )
    transport = str(case.metadata["transport"])
    live_capable = case_name in _COAP_LIVE_CAPABLE_CASES
    planned_only = not live_capable
    expected = responses[-1] if responses else request
    response_models = response_models or [{"layer": "Raw", "raw_hex": expected.hex()}]
    expected_model = response_models[-1]
    transport_layer = {"src_port": source_port, "dst_port": COAP_PORT}
    response_transport = {"src_port": COAP_PORT, "dst_port": source_port}
    stack_transport = "tcp" if transport == "tcp" else "udp"
    validation: JSONObject = {
        "expected_decode": str(expected_model.get("layer", "Coap")),
        "expected_typed_model": expected_model,
        "source_ipv4": target_ipv4,
        "destination_ipv4": source_ipv4,
        "source_port": COAP_PORT,
        "destination_port": source_port,
        "response_count": len(responses),
        **({"planned_only": True} if planned_only else {}),
    }
    if case_name == "coap-malformed-raw-fallback":
        validation.update(
            {
                "registry_layer": "Raw",
                "raw_hex": request.hex(),
                "shape_gate": "reject",
                "direct_decode_error": {
                    "context": "coap.fixed_header",
                    "required": 4,
                    "available": len(request),
                },
            }
        )
    return {
        "schema_version": 1,
        "case": case.name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": case.stimulus,
        "expected_response": case.expected_response,
        "planned_only": planned_only,
        "live_capable": live_capable,
        "protocol": "coap",
        "transport": transport,
        "source_ipv4": source_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": source_ipv4,
        "source_port": source_port,
        "destination_port": COAP_PORT,
        "payload_hex": request.hex(),
        "payload_length": len(request),
        "expected_payload_hex": expected.hex(),
        "expected_payloads_hex": [payload.hex() for payload in responses],
        "packet": {
            "stack": ["ipv4", stack_transport, "coap"],
            "root": "l3:ipv4",
            "ipv4": {"src": source_ipv4, "dst": target_ipv4},
            stack_transport: transport_layer,
            "coap": request_model,
        },
        "expected_response_packet": {
            "ipv4": {"src": target_ipv4, "dst": source_ipv4},
            stack_transport: response_transport,
            "coap": expected_model,
        },
        "capture_filter": (
            f"{stack_transport} and src host {target_ipv4} and dst host "
            f"{source_ipv4} and src port {COAP_PORT} and dst port {source_port}"
        ),
        "validation": validation,
        "required_capabilities": list(case.required_capabilities),
        "documentation_prefixes": ["198.51.100.0/24"],
        "digest_hex": digest.hex()[:16],
    }


def _exchange_bytes(
    case_name: str,
    *,
    message_id: int,
    response_message_id: int,
    token: bytes,
    digest: bytes,
) -> tuple[bytes, list[bytes], JSONObject, list[JSONObject]]:
    uri_options = [(11, b"status")]
    request_options = uri_options
    request_payload = b""
    response_options: list[tuple[int, bytes]] = [(12, b"")]
    response_payload = b"content"
    request_type, request_code = (0, 1)
    response_type, response_code = (2, 69)
    response_mid = message_id
    response_token = token
    if case_name == "coap-empty-ack-separate-response":
        request = _datagram(
            request_type, request_code, message_id, token, request_options
        )
        empty_ack = _datagram(2, 0, message_id, b"", [])
        separate = _datagram(
            0, 69, response_message_id, token, response_options, response_payload
        )
        return (
            request,
            [empty_ack, separate],
            _datagram_model(
                "confirmable", "0.01 GET", message_id, token, request_options, b""
            ),
            [
                _datagram_model(
                    "acknowledgement", "0.00 Empty", message_id, b"", [], b""
                ),
                _datagram_model(
                    "confirmable",
                    "2.05 Content",
                    response_message_id,
                    token,
                    response_options,
                    response_payload,
                ),
            ],
        )
    if case_name == "coap-reset":
        request = _datagram(
            request_type, request_code, message_id, token, request_options
        )
        reset = _datagram(3, 0, message_id, b"", [])
        return (
            request,
            [reset],
            _datagram_model(
                "confirmable", "0.01 GET", message_id, token, request_options, b""
            ),
            [_datagram_model("reset", "0.00 Empty", message_id, b"", [], b"")],
        )
    if case_name == "coap-observe-notification":
        request_options = [(6, b""), *uri_options]
        response_options = [(6, b"\x01"), (12, b"")]
        response_type = 1
    elif case_name == "coap-block1-transfer":
        request_code = 2
        request_options = [(11, b"upload"), (27, b"\n")]
        request_payload = digest[12:28]
        response_code = 95
        response_options = [(27, b"\n")]
        response_payload = b""
    elif case_name == "coap-block2-transfer":
        request_options = [(11, b"large"), (23, b"\x02")]
        response_options = [(12, b""), (23, b"\n")]
        response_payload = digest[12:28]
    elif case_name == "coap-echo-request-tag":
        echo = digest[12:20]
        request_tag = digest[20:24]
        request_options = [(11, b"fresh"), (252, echo), (292, request_tag)]
        response_options = [(12, b""), (252, echo), (292, request_tag)]
    elif case_name == "coap-qblock-planning":
        request_options = [(11, b"large"), (31, b"\x12")]
        response_options = [(12, b""), (31, b"\x12")]
    elif case_name == "coap-reliable-csm":
        request = bytes.fromhex("30e1220480")
        model = _reliable_model("7.01 CSM", b"", [(2, b"\x04\x80")])
        return (request, [], model, [])
    elif case_name == "coap-reliable-ping":
        request = bytes.fromhex("01e2")
        response = bytes.fromhex("01e3")
        return (
            request,
            [response],
            _reliable_model("7.02 Ping", b"", []),
            [_reliable_model("7.03 Pong", b"", [])],
        )
    elif case_name == "coap-malformed-raw-fallback":
        raw = bytes([64, 1, digest[0]])
        return (raw, [], {"layer": "Raw", "raw_hex": raw.hex()}, [])
    elif case_name == "coap-oscore-vector-exchange":
        request = bytes.fromhex(
            "44025d1f00003974396c6f63616c686f7374620914ff612f1092f1776f1c1668b3825e"
        )
        response = bytes.fromhex(
            "64445d1f0000397490ffdbaad1e9a7e7b2a813d3c31524378303cdafae119106"
        )
        request_model = {
            "layer": "Coap",
            "type": "confirmable",
            "code": "0.02 POST",
            "message_id": 23839,
            "token_hex": "00003974",
            "options": [
                {"number": 3, "value_hex": "6c6f63616c686f7374"},
                {"number": 9, "value_hex": "14"},
            ],
            "payload_hex": "612f1092f1776f1c1668b3825e",
            "security": "oscore-rfc8613-appendix-c4",
            "secrets_in_plan": False,
        }
        response_model = {
            "layer": "Coap",
            "type": "acknowledgement",
            "code": "2.04 Changed",
            "message_id": 23839,
            "token_hex": "00003974",
            "options": [{"number": 9, "value_hex": ""}],
            "payload_hex": "dbaad1e9a7e7b2a813d3c31524378303cdafae119106",
            "security": "oscore-rfc8613-appendix-c7",
            "secrets_in_plan": False,
        }
        return (request, [response], request_model, [response_model])
    request = _datagram(
        request_type, request_code, message_id, token, request_options, request_payload
    )
    response = _datagram(
        response_type,
        response_code,
        response_mid,
        response_token,
        response_options,
        response_payload,
    )
    return (
        request,
        [response],
        _datagram_model(
            "confirmable",
            _code_label(request_code),
            message_id,
            token,
            request_options,
            request_payload,
        ),
        [
            _datagram_model(
                _type_label(response_type),
                _code_label(response_code),
                response_mid,
                response_token,
                response_options,
                response_payload,
            )
        ],
    )


def _datagram(
    message_type: int,
    code: int,
    message_id: int,
    token: bytes,
    options: Sequence[tuple[int, bytes]],
    payload: bytes = b"",
) -> bytes:
    if len(token) > 8:
        raise ValueError("probe datagrams use base CoAP tokens only")
    out = bytearray([1 << 6 | (message_type & 3) << 4 | len(token), code])
    out.extend(message_id.to_bytes(2, "big"))
    out.extend(token)
    previous = 0
    for number, value in sorted(options, key=lambda item: item[0]):
        delta = number - previous
        delta_nibble, delta_extension = _option_component(delta)
        length_nibble, length_extension = _option_component(len(value))
        out.append(delta_nibble << 4 | length_nibble)
        out.extend(delta_extension)
        out.extend(length_extension)
        out.extend(value)
        previous = number
    if payload:
        out.append(255)
        out.extend(payload)
    return bytes(out)


def _option_component(value: int) -> tuple[int, bytes]:
    if value <= 12:
        return (value, b"")
    if value <= 268:
        return (13, bytes([value - 13]))
    if value <= 65804:
        return (14, (value - 269).to_bytes(2, "big"))
    raise ValueError("CoAP option delta or length exceeds the wire grammar")


def _datagram_model(
    message_type: str,
    code: str,
    message_id: int,
    token: bytes,
    options: Sequence[tuple[int, bytes]],
    payload: bytes,
) -> JSONObject:
    return {
        "layer": "Coap",
        "transport": "datagram",
        "version": 1,
        "type": message_type,
        "code": code,
        "message_id": message_id,
        "token_hex": token.hex(),
        "options": [
            {"number": number, "value_hex": value.hex()} for number, value in options
        ],
        "payload_marker": "present" if payload else "absent",
        "payload_hex": payload.hex(),
    }


def _reliable_model(
    code: str, token: bytes, options: Sequence[tuple[int, bytes]]
) -> JSONObject:
    return {
        "layer": "CoapReliable",
        "transport": "tcp",
        "code": code,
        "token_hex": token.hex(),
        "signaling_options": [
            {"number": number, "value_hex": value.hex()} for number, value in options
        ],
        "one_complete_frame": True,
    }


def _code_label(code: int) -> str:
    return {1: "0.01 GET", 2: "0.02 POST", 69: "2.05 Content", 95: "2.31 Continue"}.get(
        code, f"{code >> 5}.{code & 31:02d}"
    )


def _type_label(value: int) -> str:
    return ("confirmable", "non_confirmable", "acknowledgement", "reset")[value]


def _documentation_ipv4_pair(digest: bytes) -> tuple[str, str]:
    return (f"198.51.100.{1 + digest[0] % 120}", f"198.51.100.{121 + digest[1] % 120}")


def _ephemeral_port(digest: bytes) -> int:
    return 49152 + int.from_bytes(digest[2:4], "big") % 12000


def coap_failure_reasons(case_name: str) -> list[str] | None:
    if case_name in _COAP_CASE_BY_NAME:
        return [FAILURE_DECODE_FAILED, FAILURE_WRONG_PAYLOAD]
    return None


_COAP_PLAN_BUILDERS: dict[str, object] = {
    case.name: _coap_probe_plan for case in COAP_PROBE_CASES
}
register(
    ProtocolPlugin(
        name="coap",
        cases=COAP_PROBE_CASES,
        plan_builders=_COAP_PLAN_BUILDERS,
        planned_only_cases=_COAP_PLANNED_ONLY_CASES,
        profile_counts={
            COAP_SMOKE_PROFILE: {case.name: 1 for case in COAP_PROBE_CASES}
        },
        stimulus_endpoint_cases=_COAP_LIVE_CAPABLE_CASES,
        failure_reasons=coap_failure_reasons,
    )
)
