"""CoAP probe plugin: deterministic offline and provider-backed plans.

Seven bounded UDP cases route through the Rust stimulus adapter and a generated
controlled responder. Reliable transport, Q-Block scheduling, malformed-shape,
and OSCORE cases remain offline-only. Provider placement uses the coarse
``lan-raw`` appliance profile, while controlled-responder readiness remains a
target-service contract rather than a protocol-specific provider capability.
"""

from __future__ import annotations

import json
import os
import posixpath
import shlex
from collections.abc import Mapping, Sequence

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
from ..planning_helpers import deterministic_bytes
from ..target_service_helpers import plans_by_destination_port, target_service_address_fields
from .base import ProtocolPlugin, register


COAP_SMOKE_PROFILE = "coap-smoke"
COAP_SERVICE_KIND = "coap-controlled-responder"
COAP_RUNTIME = "probe-coap-reference"
COAP_STIMULUS_DRIVER = "coap_probe"
COAP_ADAPTER_MODULE = "tools/probe/adapters/src/coap.rs"
COAP_PORT = 5683
COAPS_PORT = 5684
COAP_APPLIANCE_PROFILE = "lan-raw"
COAP_DOCUMENTATION_IPV4_PREFIX = "198.51.100.0/24"
COAP_LIVE_CONFIRMATION_ENV = "LIBCRAFTER_COAP_LIVE_CONFIRM"

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
        "service": COAP_SERVICE_KIND,
        "transport": transport,
        "service_port": COAP_PORT,
        "planned_only": not live_capable,
        "live_capable": live_capable,
        "message_kind": message_kind,
        "appliance_runtime_profile": COAP_APPLIANCE_PROFILE,
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
        "Plan RFC 8613 Appendix C protected bytes without provisioning secrets.",
        "coap_oscore_request_vector",
        "coap_oscore_response_vector",
        live_capable=False,
        message_kind="oscore_vector",
    ),
)

_COAP_CASE_BY_NAME = {case.name: case for case in COAP_PROBE_CASES}
_COAP_LIVE_CAPABLE_CASES = frozenset(
    case.name for case in COAP_PROBE_CASES if case.metadata.get("live_capable") is True
)
_COAP_PLANNED_ONLY_CASES = frozenset(_COAP_CASE_BY_NAME) - _COAP_LIVE_CAPABLE_CASES


def _coap_probe_plan(
    *,
    case_name: str,
    profile: str,
    seed: int,
    sequence: int,
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
    target_service = _target_service(
        case=case,
        source_ipv4=source_ipv4,
        target_ipv4=target_ipv4,
        response_payloads=responses,
        live_capable=live_capable,
    )
    transport_layer = {
        "src_port": source_port,
        "dst_port": COAP_PORT,
    }
    response_transport = {
        "src_port": COAP_PORT,
        "dst_port": source_port,
    }
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
        **({"planned_only": True} if planned_only else {}),
        "live_capable": live_capable,
        "protocol": "coap",
        "transport": transport,
        "source_ipv4": source_ipv4,
        "destination_ipv4": target_ipv4,
        "target_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": source_ipv4,
        "source_port": source_port,
        "destination_port": COAP_PORT,
        "service_port": COAP_PORT,
        "payload_hex": request.hex(),
        "payload_length": len(request),
        "request_payload_hex": request.hex(),
        "response_payload_hex": expected.hex(),
        "response_payload_length": len(expected),
        f"{stack_transport}_payload_hex": request.hex(),
        f"{stack_transport}_payload_length": len(request),
        "expected_payload_hex": expected.hex(),
        "expected_payload_length": len(expected),
        "packet": {
            "stack": ["ipv4", stack_transport, "coap"],
            "root": "l3:ipv4",
            "ipv4": {"src": source_ipv4, "dst": target_ipv4, "protocol": stack_transport, "ttl": 64},
            stack_transport: transport_layer,
            "coap": request_model,
        },
        "expected_response_packet": {
            "stack": ["ipv4", stack_transport, "coap"],
            "root": "l3:ipv4",
            "ipv4": {"src": target_ipv4, "dst": source_ipv4, "protocol": stack_transport, "ttl": 64},
            stack_transport: response_transport,
            "coap": expected_model,
        },
        "coap": request_model,
        "expected_coap": expected_model,
        "exchange": {
            "bounded": True,
            "send_count": 1,
            "response_count": len(responses),
            "response_payloads_hex": [payload.hex() for payload in responses],
            "response_models": response_models,
            "response_window_ms": 2000,
            "workload_timeout_seconds": 30,
            "capture_timeout_seconds": 60,
            "capture_max_bytes": 16 * 1024 * 1024,
        },
        "target_service": target_service,
        "capture_filter": _capture_filter(
            transport=stack_transport,
            target_ipv4=target_ipv4,
            source_ipv4=source_ipv4,
            source_port=source_port,
        ),
        "validation": validation,
        "wire_requirements": {
            "requires_ipv4_unicast": live_capable,
            "requires_controlled_service": live_capable,
            "offline_only": not live_capable,
            "requires_live_network": live_capable,
            "live_requires_provider": live_capable,
            "live_requires_confirm_live_run": live_capable,
            "live_requires_coap_confirmation": live_capable,
            "coap_confirmation_environment": COAP_LIVE_CONFIRMATION_ENV,
            "coap_confirmation_value": "yes",
            "appliance_runtime_profile": COAP_APPLIANCE_PROFILE,
            "dry_run_only_until_adapter": planned_only,
            "stimulus_adapter_ready": live_capable,
        },
        "stimulus_driver": {
            "name": COAP_STIMULUS_DRIVER,
            "adapter_module": COAP_ADAPTER_MODULE,
            "state": "ready" if live_capable else "planned-only",
            "planned_only": planned_only,
        },
        "provider_capabilities": list(case.required_capabilities),
        "required_capabilities": list(case.required_capabilities),
        "skip_reasons": {
            "capability": _capability_skip_reasons(case, live_capable=live_capable),
            "failure": coap_failure_reasons(case.name) or [],
            "live_promotion": _live_promotion_skip_reasons(case.name),
        },
        "documentation_prefixes": [COAP_DOCUMENTATION_IPV4_PREFIX],
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
    request_type, request_code = 0, 0x01
    response_type, response_code = 2, 0x45
    response_mid = message_id
    response_token = token

    if case_name == "coap-empty-ack-separate-response":
        request = _datagram(request_type, request_code, message_id, token, request_options)
        empty_ack = _datagram(2, 0x00, message_id, b"", [])
        separate = _datagram(0, 0x45, response_message_id, token, response_options, response_payload)
        return (
            request,
            [empty_ack, separate],
            _datagram_model("confirmable", "0.01 GET", message_id, token, request_options, b""),
            [
                _datagram_model("acknowledgement", "0.00 Empty", message_id, b"", [], b""),
                _datagram_model("confirmable", "2.05 Content", response_message_id, token, response_options, response_payload),
            ],
        )
    if case_name == "coap-reset":
        request = _datagram(request_type, request_code, message_id, token, request_options)
        reset = _datagram(3, 0x00, message_id, b"", [])
        return (
            request,
            [reset],
            _datagram_model("confirmable", "0.01 GET", message_id, token, request_options, b""),
            [_datagram_model("reset", "0.00 Empty", message_id, b"", [], b"")],
        )
    if case_name == "coap-observe-notification":
        request_options = [(6, b""), *uri_options]
        response_options = [(6, b"\x01"), (12, b"")]
        response_type = 1
    elif case_name == "coap-block1-transfer":
        request_code = 0x02
        request_options = [(11, b"upload"), (27, b"\x0a")]
        request_payload = digest[12:28]
        response_code = 0x5F
        response_options = [(27, b"\x0a")]
        response_payload = b""
    elif case_name == "coap-block2-transfer":
        request_options = [(11, b"large"), (23, b"\x02")]
        response_options = [(12, b""), (23, b"\x0a")]
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
        return request, [], model, []
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
        raw = bytes([0x40, 0x01, digest[0]])
        return raw, [], {"layer": "Raw", "raw_hex": raw.hex()}, []
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
            "message_id": 0x5D1F,
            "token_hex": "00003974",
            "options": [{"number": 3, "value_hex": "6c6f63616c686f7374"}, {"number": 9, "value_hex": "14"}],
            "payload_hex": "612f1092f1776f1c1668b3825e",
            "security": "oscore-rfc8613-appendix-c4",
            "secrets_in_plan": False,
        }
        response_model = {
            "layer": "Coap",
            "type": "acknowledgement",
            "code": "2.04 Changed",
            "message_id": 0x5D1F,
            "token_hex": "00003974",
            "options": [{"number": 9, "value_hex": ""}],
            "payload_hex": "dbaad1e9a7e7b2a813d3c31524378303cdafae119106",
            "security": "oscore-rfc8613-appendix-c7",
            "secrets_in_plan": False,
        }
        return request, [response], request_model, [response_model]

    request = _datagram(request_type, request_code, message_id, token, request_options, request_payload)
    response = _datagram(response_type, response_code, response_mid, response_token, response_options, response_payload)
    return (
        request,
        [response],
        _datagram_model("confirmable", _code_label(request_code), message_id, token, request_options, request_payload),
        [_datagram_model(_type_label(response_type), _code_label(response_code), response_mid, response_token, response_options, response_payload)],
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
    out = bytearray([(1 << 6) | ((message_type & 0x03) << 4) | len(token), code])
    out.extend(message_id.to_bytes(2, "big"))
    out.extend(token)
    previous = 0
    for number, value in sorted(options, key=lambda item: item[0]):
        delta = number - previous
        delta_nibble, delta_extension = _option_component(delta)
        length_nibble, length_extension = _option_component(len(value))
        out.append((delta_nibble << 4) | length_nibble)
        out.extend(delta_extension)
        out.extend(length_extension)
        out.extend(value)
        previous = number
    if payload:
        out.append(0xFF)
        out.extend(payload)
    return bytes(out)


def _option_component(value: int) -> tuple[int, bytes]:
    if value <= 12:
        return value, b""
    if value <= 268:
        return 13, bytes([value - 13])
    if value <= 65_804:
        return 14, (value - 269).to_bytes(2, "big")
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
        "options": [{"number": number, "value_hex": value.hex()} for number, value in options],
        "payload_marker": "present" if payload else "absent",
        "payload_hex": payload.hex(),
    }


def _reliable_model(code: str, token: bytes, options: Sequence[tuple[int, bytes]]) -> JSONObject:
    return {
        "layer": "CoapReliable",
        "transport": "tcp",
        "code": code,
        "token_hex": token.hex(),
        "signaling_options": [{"number": number, "value_hex": value.hex()} for number, value in options],
        "one_complete_frame": True,
    }


def _code_label(code: int) -> str:
    return {
        0x01: "0.01 GET",
        0x02: "0.02 POST",
        0x45: "2.05 Content",
        0x5F: "2.31 Continue",
    }.get(code, f"{code >> 5}.{code & 0x1f:02d}")


def _type_label(value: int) -> str:
    return ("confirmable", "non_confirmable", "acknowledgement", "reset")[value]


def _documentation_ipv4_pair(digest: bytes) -> tuple[str, str]:
    return f"198.51.100.{1 + digest[0] % 120}", f"198.51.100.{121 + digest[1] % 120}"


def _ephemeral_port(digest: bytes) -> int:
    return 49152 + int.from_bytes(digest[2:4], "big") % 12000


def _capture_filter(*, transport: str, target_ipv4: str, source_ipv4: str, source_port: int) -> str:
    return (
        f"{transport} and src host {target_ipv4} and dst host {source_ipv4} "
        f"and src port {COAP_PORT} and dst port {source_port}"
    )


def _target_service(
    *,
    case: ProbeCase,
    source_ipv4: str,
    target_ipv4: str,
    response_payloads: Sequence[bytes],
    live_capable: bool,
) -> JSONObject:
    if not live_capable:
        return {
            "required": False,
            "kind": "none",
            "planned_case": case.metadata["message_kind"],
            "live_promotion": "unsupported_until_adapter_and_controlled_context",
        }
    return {
        "required": True,
        "kind": COAP_SERVICE_KIND,
        "protocol": "udp",
        "port": COAP_PORT,
        "bind_ipv4": target_ipv4,
        "source_ipv4": source_ipv4,
        "runtime": COAP_RUNTIME,
        "behavior": case.metadata["message_kind"],
        "response_payloads_hex": [payload.hex() for payload in response_payloads],
        "deterministic": True,
        "planned_only": False,
        "live_requires_provider": True,
        "controlled_responder": True,
        "workload_readiness": "required",
    }


def _capability_skip_reasons(case: ProbeCase, *, live_capable: bool) -> list[str]:
    if not live_capable:
        return []
    return [
        "requires_lan_raw_appliance",
        "requires_ipv4_unicast",
        "requires_controlled_service",
        "requires_controlled_coap_responder",
    ]


def _live_promotion_skip_reasons(case_name: str) -> list[str]:
    reasons: list[str] = []
    if case_name == "coap-malformed-raw-fallback":
        reasons.append("malformed_case_offline_only")
    elif case_name.startswith("coap-reliable-"):
        reasons.append("reliable_responder_not_configured")
    elif case_name == "coap-oscore-vector-exchange":
        reasons.extend(["controlled_oscore_context_not_configured", "secrets_excluded_from_plan"])
    elif case_name == "coap-qblock-planning":
        reasons.append("qblock_scheduler_out_of_scope")
    return reasons


def coap_probe_plans(probe_plans: Sequence[JSONObject]) -> list[JSONObject]:
    return [plan for plan in probe_plans if plan.get("case") in _COAP_CASE_BY_NAME]


def missing_live_environment_confirmation(plan: JSONObject) -> JSONObject | None:
    """Return one unsatisfied CoAP live-run environment gate."""

    requirements = plan.get("wire_requirements")
    if not isinstance(requirements, Mapping):
        return None
    environment = requirements.get("coap_confirmation_environment")
    expected = requirements.get("coap_confirmation_value")
    required = requirements.get("live_requires_coap_confirmation") is True
    if not required or not isinstance(environment, str) or not isinstance(expected, str):
        return None
    actual = os.environ.get(environment)
    if actual == expected:
        return None
    return {"environment": environment, "expected": expected, "present": actual is not None}


def missing_live_environment_confirmations(
    probe_plans: Sequence[JSONObject],
) -> list[JSONObject]:
    """Collect unsatisfied CoAP live gates before provider provisioning."""

    missing: list[JSONObject] = []
    for plan in probe_plans:
        requirement = missing_live_environment_confirmation(plan)
        if requirement is not None:
            missing.append({"case": str(plan.get("case", "")), **requirement})
    return missing


def coap_port_check_lines(probe_plans: Sequence[JSONObject]) -> list[str]:
    """Render deterministic UDP port-free checks for admitted responder plans."""

    ports = sorted(
        {
            int(plan.get("destination_port", COAP_PORT))
            for plan in coap_probe_plans(probe_plans)
            if (plan.get("target_service") or {}).get("kind") == COAP_SERVICE_KIND
        }
    )
    return [f'check_udp_port_free "$coap_bind_ipv4" {port}' for port in ports]


def coap_responder_setup_lines(
    *,
    artifact_root: str,
    coap_plans: Sequence[JSONObject],
) -> list[str]:
    """Render a bounded exact-request CoAP responder for disposable targets."""

    service_plans = [
        plan
        for plan in coap_probe_plans(coap_plans)
        if (plan.get("target_service") or {}).get("kind") == COAP_SERVICE_KIND
    ]
    if not service_plans:
        return []
    plans_json = json.dumps(service_plans, sort_keys=True, separators=(",", ":"))
    script_path = posixpath.join(artifact_root, "coap-responder.py")
    log_path = posixpath.join(artifact_root, "coap-responder.jsonl")
    stdout_path = posixpath.join(artifact_root, "coap-5683.stdout.txt")
    stderr_path = posixpath.join(artifact_root, "coap-5683.stderr.txt")
    pid_path = posixpath.join(artifact_root, "coap-5683.pid")
    return [
        f"cat > {shlex.quote(script_path)} <<'PY'",
        "import json",
        "import signal",
        "import socket",
        "import sys",
        "import time",
        "",
        f"plans = json.loads({plans_json!r})",
        "bind_ip = sys.argv[1]",
        "log_path = sys.argv[2]",
        f"port = {COAP_PORT}",
        "max_requests = min(10, max(1, sum(int((p.get('exchange') or {}).get('send_count', 1)) for p in plans)))",
        "deadline = time.monotonic() + 60.0",
        "stop = False",
        "",
        "def stop_now(_signum, _frame):",
        "    global stop",
        "    stop = True",
        "",
        "def log(event, **fields):",
        "    record = {'event': event, 'ts': time.time(), **fields}",
        "    with open(log_path, 'a', encoding='utf-8') as handle:",
        "        handle.write(json.dumps(record, sort_keys=True) + '\\n')",
        "",
        "signal.signal(signal.SIGTERM, stop_now)",
        "signal.signal(signal.SIGINT, stop_now)",
        "exchanges = {}",
        "for plan in plans:",
        "    request = bytes.fromhex(str(plan['request_payload_hex']))",
        "    responses = [bytes.fromhex(str(value)) for value in (plan.get('exchange') or {}).get('response_payloads_hex', [])]",
        "    exchanges[request] = (str(plan.get('case')), responses)",
        "sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)",
        "sock.bind((bind_ip, port))",
        "sock.settimeout(1.0)",
        "log('listening', bind_ipv4=bind_ip, port=port, max_requests=max_requests, timeout_seconds=60)",
        "request_count = 0",
        "while not stop and request_count < max_requests and time.monotonic() < deadline:",
        "    try:",
        "        data, peer = sock.recvfrom(65535)",
        "    except socket.timeout:",
        "        continue",
        "    request_count += 1",
        "    exchange = exchanges.get(data)",
        "    if exchange is None:",
        "        log('ignored', peer=str(peer), bytes=len(data), request_count=request_count)",
        "        continue",
        "    case_name, responses = exchange",
        "    for index, response in enumerate(responses):",
        "        sock.sendto(response, peer)",
        "        log('responded', case=case_name, peer=str(peer), response_index=index, bytes=len(response))",
        "sock.close()",
        "log('stopped', request_count=request_count)",
        "PY",
        f"python3 {shlex.quote(script_path)} \"$coap_bind_ipv4\" {shlex.quote(log_path)} >{shlex.quote(stdout_path)} 2>{shlex.quote(stderr_path)} &",
        f"coap_pid=$!; echo \"$coap_pid\" > {shlex.quote(pid_path)}",
        'printf \'kill %s 2>/dev/null || true\\n\' "$coap_pid" >> "$cleanup"',
    ]


def coap_target_service_contribution(
    probe_plans: Sequence[JSONObject],
    *,
    dry_run: bool,
) -> JSONObject:
    service_plans = [
        plan
        for plan in coap_probe_plans(probe_plans)
        if isinstance(plan.get("target_service"), Mapping)
        and plan.get("target_service", {}).get("kind") == COAP_SERVICE_KIND
    ]
    plans_by_port = plans_by_destination_port(service_plans)
    services = [
        {
            "name": COAP_SERVICE_KIND,
            "protocol": "udp",
            "port": port,
            "purpose": "bounded-controlled-coap-responder",
            "runtime": COAP_RUNTIME,
            "deterministic": True,
            "planned_only": False,
            "live_requires_provider": True,
            "workload_readiness": "required",
            "query_count": sum(1 for item in service_plans if int(item.get("destination_port", 0)) == port),
            "cases": [str(item.get("case")) for item in service_plans if int(item.get("destination_port", 0)) == port],
            "supports": {
                "unicast_get_content": True,
                "separate_response": True,
                "reset": True,
                "observe_single_notification": True,
                "single_block_exchange": True,
                "echo_request_tag": True,
                "qblock_burst": False,
                "reliable_transport": False,
                "oscore_context": False,
            },
            **target_service_address_fields(plan),
            "log_paths": [
                f"live-artifacts/probe/target-services/coap-{port}.stdout.txt",
                f"live-artifacts/probe/target-services/coap-{port}.stderr.txt",
            ],
        }
        for port, plan in plans_by_port.items()
    ]
    return {"services": services, "starts_services": not dry_run and bool(services)}


def coap_failure_reasons(case_name: str) -> list[str] | None:
    if case_name in _COAP_LIVE_CAPABLE_CASES:
        return [
            FAILURE_TIMEOUT,
            FAILURE_WRONG_PEER,
            FAILURE_WRONG_PAYLOAD,
            FAILURE_DECODE_FAILED,
            FAILURE_TARGET_SETUP_FAILED,
        ]
    if case_name in _COAP_CASE_BY_NAME:
        return [FAILURE_DECODE_FAILED, FAILURE_WRONG_PAYLOAD]
    return None


def coap_lab_capabilities(substrate: Mapping[str, JSONValue]) -> Mapping[str, object]:
    """Contribute no protocol-specific capability; placement stays coarse."""

    del substrate
    return {}


def coap_rewrite_endpoint_addresses(
    plan: JSONObject,
    *,
    source_ipv4: str,
    target_ipv4: str,
    source_mac: str | None = None,
    target_mac: str | None = None,
    target_interface: str | None = None,
    rewrite_source: str = "wire_endpoint_plan",
) -> JSONObject:
    del source_mac, target_mac, target_interface
    updated = dict(plan)
    case_name = str(updated.get("case", ""))
    if case_name not in _COAP_LIVE_CAPABLE_CASES:
        return _mark_rewrite_skipped(
            updated,
            source_ipv4=source_ipv4,
            target_ipv4=target_ipv4,
            rewrite_source=rewrite_source,
            reason="offline_or_planned_only",
        )

    source_port = int(updated.get("source_port", 0))
    transport = str(updated.get("transport", "udp"))
    updated.update(
        {
            "source_ipv4": source_ipv4,
            "destination_ipv4": target_ipv4,
            "target_ipv4": target_ipv4,
            "expected_reply_source_ipv4": target_ipv4,
            "expected_reply_destination_ipv4": source_ipv4,
            "capture_filter": _capture_filter(
                transport=transport,
                target_ipv4=target_ipv4,
                source_ipv4=source_ipv4,
                source_port=source_port,
            ),
        }
    )
    _rewrite_packet_models(updated, source_ipv4=source_ipv4, target_ipv4=target_ipv4)
    validation = dict(json_object(updated.get("validation", {}), "probe_plan.validation"))
    validation["source_ipv4"] = target_ipv4
    validation["destination_ipv4"] = source_ipv4
    updated["validation"] = validation
    target_service = dict(json_object(updated.get("target_service", {}), "probe_plan.target_service"))
    target_service["bind_ipv4"] = target_ipv4
    target_service["source_ipv4"] = source_ipv4
    updated["target_service"] = target_service
    return apply_shared_ipv4_rewrite_tail(
        updated,
        case_name=case_name,
        source_ipv4=source_ipv4,
        target_ipv4=target_ipv4,
        rewrite_source=rewrite_source,
    )


def _rewrite_packet_models(updated: JSONObject, *, source_ipv4: str, target_ipv4: str) -> None:
    packet = dict(json_object(updated.get("packet", {}), "probe_plan.packet"))
    ipv4 = dict(json_object(packet.get("ipv4", {}), "probe_plan.packet.ipv4"))
    ipv4.update({"src": source_ipv4, "dst": target_ipv4})
    packet["ipv4"] = ipv4
    updated["packet"] = packet
    response = dict(json_object(updated.get("expected_response_packet", {}), "probe_plan.expected_response_packet"))
    response_ipv4 = dict(json_object(response.get("ipv4", {}), "probe_plan.expected_response_packet.ipv4"))
    response_ipv4.update({"src": target_ipv4, "dst": source_ipv4})
    response["ipv4"] = response_ipv4
    updated["expected_response_packet"] = response


def _mark_rewrite_skipped(
    updated: JSONObject,
    *,
    source_ipv4: str,
    target_ipv4: str,
    rewrite_source: str,
    reason: str,
) -> JSONObject:
    skip_reasons = dict(updated.get("skip_reasons", {}) if isinstance(updated.get("skip_reasons"), Mapping) else {})
    address_rewrite = list(skip_reasons.get("address_rewrite", []) if isinstance(skip_reasons.get("address_rewrite"), list) else [])
    address_rewrite.append(reason)
    skip_reasons["address_rewrite"] = list(dict.fromkeys(str(item) for item in address_rewrite))
    updated["skip_reasons"] = skip_reasons
    updated["live_address_rewrite"] = {
        "source": rewrite_source,
        "status": "skipped",
        "reason": reason,
        "stimulus_ipv4": source_ipv4,
        "target_ipv4": target_ipv4,
    }
    return updated


_COAP_PLAN_BUILDERS: dict[str, object] = {case.name: _coap_probe_plan for case in COAP_PROBE_CASES}

register(
    ProtocolPlugin(
        name="coap",
        cases=COAP_PROBE_CASES,
        plan_builders=_COAP_PLAN_BUILDERS,
        planned_only_cases=_COAP_PLANNED_ONLY_CASES,
        profile_counts={},
        stimulus_endpoint_cases=_COAP_LIVE_CAPABLE_CASES,
        target_service=coap_target_service_contribution,
        setup_script=None,
        rewrite_endpoint_addresses=coap_rewrite_endpoint_addresses,
        failure_reasons=coap_failure_reasons,
        lab_capabilities=coap_lab_capabilities,
    )
)
