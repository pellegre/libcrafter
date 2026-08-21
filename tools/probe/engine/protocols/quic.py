"""Deterministic QUIC probe cases and packet plans."""

from __future__ import annotations
import hashlib
from ..case_helpers import _behavior_case
from ..model import JSONObject, ProbeCase
from ..planning_helpers import deterministic_bytes, deterministic_ipv4_pair
from .base import ProtocolPlugin, register

QUIC_SERVICE_KIND = "quic-controlled-udp"
QUIC_SERVICE_PORT = 4433
QUIC_ADAPTER_MODULE = "tools/probe/adapters/src/quic.rs"
_QUIC_CAPABILITIES = ["udp_service"]
_QUIC_STATEFUL_CAPABILITIES = [
    "two_endpoints",
    "controlled_service_startup",
    "udp_capture",
    "artifact_collection",
    "endpoint_teardown",
]
_QUIC_ALPN = "crafter-flow"
_QUIC_REFERENCE_IMPLEMENTATION = "aioquic"
_QUIC_REFERENCE_VERSION = "1.2.0"
_QUIC_V1_INITIAL_HEX = "c000000001048394c8f001aa000301beef"
_QUIC_VERSION_NEGOTIATION_HEX = "c000000000048394c8f001aa000000016b3343cf"
_QUIC_RETRY_HEX = "f000000001048394c8f001aa010203000102030405060708090a0b0c0d0e0f"
_QUIC_STATELESS_RESET_CANDIDATE_HEX = "409d7c5b3a190817263544638291a0bf"
_QUIC_PROTECTED_FLOW_HEX = "c000000001048394c8f001aa000501aabbccdd"
QUIC_SMOKE_CASES: tuple[ProbeCase, ...] = (
    _behavior_case(
        name="quic-initial-udp-observation",
        description="Send a QUIC v1 Initial-looking UDP datagram to a controlled UDP target and validate the observable UDP response path.",
        stimulus="quic_udp_datagram",
        expected_response="udp_response",
        required_capabilities=_QUIC_CAPABILITIES,
        protocol="quic",
        metadata={"service": QUIC_SERVICE_KIND, "packet_type": "initial"},
    ),
    _behavior_case(
        name="quic-version-negotiation-observation",
        description="Plan a QUIC Version Negotiation observation against a controlled peer when that service is provided.",
        stimulus="quic_version_negotiation_probe",
        expected_response="quic_version_negotiation_or_udp_response",
        required_capabilities=_QUIC_CAPABILITIES,
        protocol="quic",
        metadata={
            "service": QUIC_SERVICE_KIND,
            "packet_type": "version_negotiation",
            "planned_only": True,
        },
    ),
    _behavior_case(
        name="quic-retry-observation",
        description="Plan a QUIC Retry observation only for a controlled peer that can emit Retry packets.",
        stimulus="quic_retry_probe",
        expected_response="quic_retry",
        required_capabilities=_QUIC_CAPABILITIES,
        protocol="quic",
        metadata={
            "service": QUIC_SERVICE_KIND,
            "packet_type": "retry",
            "planned_only": True,
            "requires_controlled_quic_service": True,
        },
    ),
    _behavior_case(
        name="quic-stateless-reset-observation",
        description="Plan a stateless reset candidate observation only for a controlled peer that owns the reset token behavior.",
        stimulus="quic_stateless_reset_probe",
        expected_response="quic_stateless_reset_candidate",
        required_capabilities=_QUIC_CAPABILITIES,
        protocol="quic",
        metadata={
            "service": QUIC_SERVICE_KIND,
            "packet_type": "stateless_reset_candidate",
            "planned_only": True,
            "requires_controlled_quic_service": True,
        },
    ),
    _behavior_case(
        name="quic-protected-flow-plan",
        description="Plan a stateful QUIC v1 client/server exchange with authenticated endpoint state, one bidirectional stream, graceful close, capture, validation, artifact collection, and teardown.",
        stimulus="quic_authenticated_client_flow",
        expected_response="quic_authenticated_stream_response_and_close",
        required_capabilities=_QUIC_STATEFUL_CAPABILITIES,
        protocol="quic",
        metadata={
            "service": "quic-controlled-endpoint",
            "packet_type": "protected_initial",
            "planned_only": True,
            "encrypted": True,
            "stateful_endpoint_flow": True,
            "distinct_from_udp_echo": True,
            "requires_controlled_quic_service": True,
            "quic_version": 1,
            "alpn": _QUIC_ALPN,
        },
    ),
)
_QUIC_CASE_BY_NAME: dict[str, ProbeCase] = {
    case.name: case for case in QUIC_SMOKE_CASES
}
_QUIC_PLANNED_ONLY_CASES = frozenset(
    {
        "quic-version-negotiation-observation",
        "quic-retry-observation",
        "quic-stateless-reset-observation",
        "quic-protected-flow-plan",
    }
)
_QUIC_STIMULUS_ENDPOINT_CASES = frozenset({"quic-initial-udp-observation"})


def _quic_initial_udp_observation_probe_plan(
    *,
    case_name: str = "quic-initial-udp-observation",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    return _quic_probe_plan(
        case_name=case_name, profile=profile, seed=seed, sequence=sequence
    )


def _quic_version_negotiation_observation_probe_plan(
    *,
    case_name: str = "quic-version-negotiation-observation",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    return _quic_probe_plan(
        case_name=case_name, profile=profile, seed=seed, sequence=sequence
    )


def _quic_retry_observation_probe_plan(
    *, case_name: str = "quic-retry-observation", profile: str, seed: int, sequence: int
) -> JSONObject:
    return _quic_probe_plan(
        case_name=case_name, profile=profile, seed=seed, sequence=sequence
    )


def _quic_stateless_reset_observation_probe_plan(
    *,
    case_name: str = "quic-stateless-reset-observation",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    return _quic_probe_plan(
        case_name=case_name, profile=profile, seed=seed, sequence=sequence
    )


def _quic_protected_flow_plan_probe_plan(
    *,
    case_name: str = "quic-protected-flow-plan",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    return _quic_probe_plan(
        case_name=case_name, profile=profile, seed=seed, sequence=sequence
    )


def _quic_probe_plan(
    *, case_name: str, profile: str, seed: int, sequence: int
) -> JSONObject:
    case = _QUIC_CASE_BY_NAME[case_name]
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    source_port = 49152 + int.from_bytes(digest[0:2], "big") % 12000
    payload_hex = _payload_hex_for_case(case_name)
    payload_length = len(bytes.fromhex(payload_hex))
    packet_count = 1
    planned_only = case_name in _QUIC_PLANNED_ONLY_CASES
    target_behavior = _target_behavior_for_case(case_name)
    stateful_endpoint_flow = case_name == "quic-protected-flow-plan"
    capture_filter = (
        f"udp and host {stimulus_ipv4} and host {target_ipv4} and port {QUIC_SERVICE_PORT}"
        if stateful_endpoint_flow
        else f"udp and src host {target_ipv4} and dst host {stimulus_ipv4} and src port {QUIC_SERVICE_PORT} and dst port {source_port}"
    )
    plan: JSONObject = {
        "schema_version": 1,
        "case": case.name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": case.stimulus,
        "expected_response": case.expected_response,
        "protocol": "quic",
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": QUIC_SERVICE_PORT,
        "payload_hex": payload_hex,
        "payload_length": payload_length,
        "expected_payload_hex": payload_hex,
        "expected_payload_length": payload_length,
        "quic_payload_hex": payload_hex,
        "quic_payload_length": payload_length,
        "udp_payload_hex": payload_hex,
        "udp_payload_length": payload_length,
        "expected_udp_length": 8 + payload_length,
        "quic": {
            "packet_type": str(case.metadata.get("packet_type", "unknown")),
            "version": _version_for_case(case_name),
            "packet_count": packet_count,
            "encrypted_payload_opaque": bool(case.metadata.get("encrypted", False)),
            "raw_hex": payload_hex,
        },
        "stimulus_driver": {
            "name": case.stimulus,
            "adapter_module": QUIC_ADAPTER_MODULE,
            "state": "planned-only" if planned_only else "adapter-ready",
            "planned_only": planned_only,
        },
        "capture_filter": capture_filter,
        "validation": {
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "source_port": QUIC_SERVICE_PORT,
            "destination_port": source_port,
            "quic_packet_count": packet_count,
            "payload_hex": payload_hex,
            "payload_length": payload_length,
            "target_behavior": target_behavior,
            "planned_only": planned_only,
        },
        "wire_requirements": {
            "requires_ipv4_unicast": True,
            "requires_controlled_service": True,
            "requires_udp_service": True,
            "requires_controlled_quic_service": bool(
                case.metadata.get("requires_controlled_quic_service", False)
            ),
        },
        "digest_hex": digest.hex()[:16],
    }
    if planned_only:
        plan["planned_only"] = True
    if stateful_endpoint_flow:
        plan.update(_protected_flow_contract(digest, capture_filter))
    return plan


def _protected_flow_contract(digest: bytes, capture_filter: str) -> JSONObject:
    request = b"crafter-quic-request:" + digest[:8]
    response = b"crafter-quic-response:" + digest[8:16]
    request_bound = len(request)
    response_bound = len(response)
    artifacts = [
        "target/probe/artifacts/quic/protected-flow-plan.json",
        "target/probe/artifacts/quic/protected-flow-capture.pcap",
        "target/probe/artifacts/quic/protected-flow-report.json",
        "target/probe/artifacts/quic/protected-flow-teardown.json",
    ]
    reference_artifact_root = "target/probe/artifacts/quic/reference-interop"
    reference_artifacts = {
        "crafter_client_log": f"{reference_artifact_root}/crafter-client.log.json",
        "crafter_server_log": f"{reference_artifact_root}/crafter-server.log.json",
        "reference_client_log": f"{reference_artifact_root}/reference-client.log.json",
        "reference_server_log": f"{reference_artifact_root}/reference-server.log.json",
        "client_against_reference_pcap": f"{reference_artifact_root}/crafter-client-reference-server.pcap",
        "reference_against_server_pcap": f"{reference_artifact_root}/reference-client-crafter-server.pcap",
        "decoded_summaries": f"{reference_artifact_root}/decoded-summaries.json",
        "state_traces": f"{reference_artifact_root}/state-traces.json",
        "command_manifest": f"{reference_artifact_root}/commands.json",
        "teardown_status": f"{reference_artifact_root}/teardown.json",
        "structured_skip": f"{reference_artifact_root}/skip.json",
    }
    return {
        "conversation": {
            "kind": "stateful_authenticated_quic_endpoint_flow",
            "distinct_from": "quic-initial-udp-observation",
            "version": 1,
            "alpn": _QUIC_ALPN,
            "identity": {
                "kind": "synthetic_test_identity",
                "trust_installed_on": "stimulus_client",
                "secrets_in_plan": False,
            },
            "roles": {
                "stimulus": "authenticated_quic_client",
                "target": "controlled_quic_server",
            },
            "stream_exchange": {
                "bidirectional_streams": 1,
                "request_length": len(request),
                "max_request_bytes": request_bound,
                "request_sha256": hashlib.sha256(request).hexdigest(),
                "response_length": len(response),
                "max_response_bytes": response_bound,
                "response_sha256": hashlib.sha256(response).hexdigest(),
                "payload_bytes_in_artifacts": False,
            },
            "close": "graceful_application_close",
        },
        "capture": {
            "protocol": "udp",
            "points": ["stimulus", "target"],
            "filter": capture_filter,
            "artifacts": artifacts,
        },
        "artifact_outputs": artifacts,
        "flow_validation": {
            "client_state_trace": [
                "Initial",
                "Handshaking",
                "Established",
                "Closing",
                "Draining",
                "Closed",
            ],
            "server_state_trace": [
                "Listen",
                "Handshaking",
                "Established",
                "Closing",
                "Draining",
                "Closed",
            ],
            "stream_exchange": {
                "request_length": len(request),
                "request_sha256": hashlib.sha256(request).hexdigest(),
                "response_length": len(response),
                "response_sha256": hashlib.sha256(response).hexdigest(),
            },
            "required_packet_spaces": ["Initial", "Handshake", "Application"],
            "recovery_counters": [
                "timeout_events",
                "pto_firings",
                "declared_losses",
                "regenerated_transmits",
            ],
            "close_outcome": "graceful_application_close",
            "reject_secrets": True,
        },
        "reference_interoperability": {
            "schema_version": 1,
            "reference": {
                "implementation": _QUIC_REFERENCE_IMPLEMENTATION,
                "version": _QUIC_REFERENCE_VERSION,
                "package_pin": f"{_QUIC_REFERENCE_IMPLEMENTATION}=={_QUIC_REFERENCE_VERSION}",
            },
            "quic_version": 1,
            "alpn": _QUIC_ALPN,
            "cases": [
                {
                    "name": "crafter-client-reference-server",
                    "client": "crafter-flow",
                    "server": _QUIC_REFERENCE_IMPLEMENTATION,
                },
                {
                    "name": "reference-client-crafter-server",
                    "client": _QUIC_REFERENCE_IMPLEMENTATION,
                    "server": "crafter-flow",
                },
            ],
            "identity": {
                "kind": "synthetic_short_lived",
                "private_key_collected": False,
                "certificate_public_fields_redacted": True,
            },
            "stream_exchange": {
                "bidirectional_streams": 1,
                "request_length": len(request),
                "request_sha256": hashlib.sha256(request).hexdigest(),
                "response_length": len(response),
                "response_sha256": hashlib.sha256(response).hexdigest(),
                "payload_bytes_collected": False,
            },
            "adapter_contract": {
                "input": [
                    "endpoint_roles",
                    "synthetic_identity_paths",
                    "opaque_request_length_and_sha256",
                    "opaque_response_length_and_sha256",
                    "bounded_deadline",
                ],
                "output": [
                    "role_exit_statuses",
                    "safe_state_traces",
                    "bounded_capture_paths",
                    "decoded_summary_paths",
                    "teardown_status",
                ],
                "secret_output_forbidden": True,
            },
            "capture": {
                "format": "pcap",
                "bounded": True,
                "filter": capture_filter,
                "payloads_redacted_before_promotion": True,
            },
            "artifacts": reference_artifacts,
            "redaction": {
                "required_before_promotion": True,
                "fields": [
                    "credentials",
                    "public_addresses",
                    "endpoint_identifiers",
                    "hostnames",
                    "private_keys",
                    "sensitive_payloads",
                ],
                "retain_only_payload_lengths_and_sha256": True,
            },
            "skip": {
                "when": ["live_authorization_absent", "runtime_capability_unavailable"],
                "status": "skipped",
                "artifact": reference_artifacts["structured_skip"],
                "developer_host_fallback": False,
            },
        },
        "structured_skip_artifact": {
            "relative_path": "artifacts/quic/reference-interop/skip.json",
            "schema_version": 1,
            "redacted": True,
        },
        "safety": {
            "default_mode": "dry_run",
            "documentation_addresses": True,
            "deterministic_seed": True,
            "developer_host_raw_send": False,
        },
    }


def _payload_hex_for_case(case_name: str) -> str:
    return {
        "quic-initial-udp-observation": _QUIC_V1_INITIAL_HEX,
        "quic-version-negotiation-observation": _QUIC_VERSION_NEGOTIATION_HEX,
        "quic-retry-observation": _QUIC_RETRY_HEX,
        "quic-stateless-reset-observation": _QUIC_STATELESS_RESET_CANDIDATE_HEX,
        "quic-protected-flow-plan": _QUIC_PROTECTED_FLOW_HEX,
    }[case_name]


def _version_for_case(case_name: str) -> int | str:
    return {
        "quic-initial-udp-observation": 1,
        "quic-version-negotiation-observation": 0,
        "quic-retry-observation": 1,
        "quic-stateless-reset-observation": "not_applicable_short_header",
        "quic-protected-flow-plan": 1,
    }[case_name]


def _target_behavior_for_case(case_name: str) -> str:
    return {
        "quic-initial-udp-observation": "echo_udp_payload",
        "quic-version-negotiation-observation": "observe_version_negotiation",
        "quic-retry-observation": "emit_retry",
        "quic-stateless-reset-observation": "emit_stateless_reset_candidate",
        "quic-protected-flow-plan": "run_authenticated_client_server_flow",
    }[case_name]


def quic_failure_reasons(case_name: str) -> list[str] | None:
    if case_name in _QUIC_STIMULUS_ENDPOINT_CASES:
        return [
            "timeout",
            "wrong_peer",
            "wrong_payload",
            "decode_failed",
            "target_precondition_failed",
        ]
    return None


_QUIC_PLAN_BUILDERS: dict[str, object] = {
    "quic-initial-udp-observation": _quic_initial_udp_observation_probe_plan,
    "quic-version-negotiation-observation": _quic_version_negotiation_observation_probe_plan,
    "quic-retry-observation": _quic_retry_observation_probe_plan,
    "quic-stateless-reset-observation": _quic_stateless_reset_observation_probe_plan,
    "quic-protected-flow-plan": _quic_protected_flow_plan_probe_plan,
}
register(
    ProtocolPlugin(
        name="quic",
        cases=QUIC_SMOKE_CASES,
        plan_builders=_QUIC_PLAN_BUILDERS,
        planned_only_cases=_QUIC_PLANNED_ONLY_CASES,
        profile_counts={},
        stimulus_endpoint_cases=_QUIC_STIMULUS_ENDPOINT_CASES,
        failure_reasons=quic_failure_reasons,
    )
)
