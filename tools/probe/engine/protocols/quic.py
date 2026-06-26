"""QUIC probe protocol plugin: planned UDP/QUIC behavior cases."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..capability_derivation import capability
from ..case_helpers import _behavior_case
from ..endpoint_addressing import apply_shared_ipv4_rewrite_tail
from ..model import JSONObject, JSONValue, ProbeCase, json_object
from ..planning_helpers import deterministic_bytes, deterministic_ipv4_pair
from ..target_service_helpers import (
    plans_by_destination_port,
    target_service_address_fields,
)
from .base import ProtocolPlugin, register


QUIC_SERVICE_KIND = "quic-controlled-udp"
QUIC_SERVICE_PORT = 4433
QUIC_ADAPTER_MODULE = "tools/probe/adapters/src/quic.rs"
_QUIC_CAPABILITIES = ["udp_service"]
_QUIC_V1_INITIAL_HEX = "c000000001048394c8f001aa000301beef"
_QUIC_VERSION_NEGOTIATION_HEX = "c000000000048394c8f001aa000000016b3343cf"
_QUIC_RETRY_HEX = "f000000001048394c8f001aa010203000102030405060708090a0b0c0d0e0f"
_QUIC_STATELESS_RESET_CANDIDATE_HEX = "409d7c5b3a190817263544638291a0bf"
_QUIC_PROTECTED_FLOW_HEX = "c000000001048394c8f001aa000501aabbccdd"


QUIC_SMOKE_CASES: tuple[ProbeCase, ...] = (
    _behavior_case(
        name="quic-initial-udp-observation",
        description=(
            "Send a QUIC v1 Initial-looking UDP datagram to a controlled UDP "
            "target and validate the observable UDP response path."
        ),
        stimulus="quic_udp_datagram",
        expected_response="udp_response",
        required_capabilities=_QUIC_CAPABILITIES,
        protocol="quic",
        metadata={"service": QUIC_SERVICE_KIND, "packet_type": "initial"},
    ),
    _behavior_case(
        name="quic-version-negotiation-observation",
        description=(
            "Plan a QUIC Version Negotiation observation against a controlled "
            "target service when that service is provided."
        ),
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
        description=(
            "Plan a QUIC Retry observation only for a controlled target service "
            "that can emit Retry packets."
        ),
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
        description=(
            "Plan a stateless reset candidate observation only for a controlled "
            "target service that owns the reset token behavior."
        ),
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
        description=(
            "Plan an encrypted/protected QUIC flow shape while preserving the "
            "opaque payload bytes and avoiding endpoint state-machine claims."
        ),
        stimulus="quic_protected_flow",
        expected_response="quic_encrypted_flow_observation",
        required_capabilities=_QUIC_CAPABILITIES,
        protocol="quic",
        metadata={
            "service": QUIC_SERVICE_KIND,
            "packet_type": "protected_initial",
            "planned_only": True,
            "encrypted": True,
        },
    ),
)
_QUIC_CASE_BY_NAME: dict[str, ProbeCase] = {case.name: case for case in QUIC_SMOKE_CASES}
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
        case_name=case_name,
        profile=profile,
        seed=seed,
        sequence=sequence,
    )


def _quic_version_negotiation_observation_probe_plan(
    *,
    case_name: str = "quic-version-negotiation-observation",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    return _quic_probe_plan(
        case_name=case_name,
        profile=profile,
        seed=seed,
        sequence=sequence,
    )


def _quic_retry_observation_probe_plan(
    *,
    case_name: str = "quic-retry-observation",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    return _quic_probe_plan(
        case_name=case_name,
        profile=profile,
        seed=seed,
        sequence=sequence,
    )


def _quic_stateless_reset_observation_probe_plan(
    *,
    case_name: str = "quic-stateless-reset-observation",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    return _quic_probe_plan(
        case_name=case_name,
        profile=profile,
        seed=seed,
        sequence=sequence,
    )


def _quic_protected_flow_plan_probe_plan(
    *,
    case_name: str = "quic-protected-flow-plan",
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    return _quic_probe_plan(
        case_name=case_name,
        profile=profile,
        seed=seed,
        sequence=sequence,
    )


def _quic_probe_plan(
    *,
    case_name: str,
    profile: str,
    seed: int,
    sequence: int,
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
        "target_service": {
            "required": True,
            "kind": QUIC_SERVICE_KIND,
            "protocol": "udp",
            "port": QUIC_SERVICE_PORT,
            "bind_ipv4": target_ipv4,
            "source_ipv4": stimulus_ipv4,
            "behavior": target_behavior,
            "payload_hex": payload_hex,
            "payload_length": payload_length,
            "deterministic": True,
            "planned_only": planned_only,
        },
        "stimulus_driver": {
            "name": case.stimulus,
            "adapter_module": QUIC_ADAPTER_MODULE,
            "state": "planned-only" if planned_only else "adapter-ready",
            "planned_only": planned_only,
        },
        "capture_filter": (
            f"udp and src host {target_ipv4} and dst host {stimulus_ipv4} "
            f"and src port {QUIC_SERVICE_PORT} and dst port {source_port}"
        ),
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
    return plan


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
        "quic-protected-flow-plan": "observe_encrypted_flow",
    }[case_name]


def quic_udp_probe_plans(probe_plans: Sequence[JSONObject]) -> list[JSONObject]:
    """Return QUIC plans that can use the controlled UDP echo responder."""

    return [
        plan
        for plan in probe_plans
        if plan.get("case") in _QUIC_STIMULUS_ENDPOINT_CASES
    ]


def quic_target_service_contribution(
    probe_plans: Sequence[JSONObject],
    *,
    dry_run: bool,
) -> JSONObject:
    """Return target-service setup metadata for the QUIC UDP echo case."""

    quic_plans = quic_udp_probe_plans(probe_plans)
    plans_by_port = plans_by_destination_port(quic_plans)
    services = [
        {
            "name": "quic-controlled-udp",
            "protocol": "udp",
            "port": port,
            "purpose": "quic-initial-udp-observation",
            "deterministic": True,
            "echo": True,
            "payload_count": sum(
                1 for plan in quic_plans if int(plan.get("destination_port", 0)) == port
            ),
            **target_service_address_fields(plan),
            "log_paths": [
                f"live-artifacts/probe/target-services/udp-responder-{port}.stdout.txt",
                f"live-artifacts/probe/target-services/udp-responder-{port}.stderr.txt",
            ],
        }
        for port, plan in plans_by_port.items()
    ]
    return {
        "services": services,
        "starts_services": not dry_run and bool(plans_by_port),
    }


def quic_rewrite_endpoint_addresses(
    plan: JSONObject,
    *,
    source_ipv4: str,
    target_ipv4: str,
    source_mac: str | None = None,
    target_mac: str | None = None,
    target_interface: str | None = None,
    rewrite_source: str = "wire_endpoint_plan",
) -> JSONObject:
    """Rewrite the QUIC UDP probe plan onto lab-session endpoint addresses."""

    updated = dict(plan)
    updated["source_ipv4"] = source_ipv4
    updated["destination_ipv4"] = target_ipv4
    updated["expected_reply_source_ipv4"] = target_ipv4
    updated["expected_reply_destination_ipv4"] = source_ipv4
    case_name = str(updated.get("case", ""))
    source_port = int(updated.get("source_port", 0))
    destination_port = int(updated.get("destination_port", QUIC_SERVICE_PORT))
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
    validation = dict(json_object(updated.get("validation", {}), "probe_plan.validation"))
    validation.update(
        {
            "source_ipv4": target_ipv4,
            "destination_ipv4": source_ipv4,
            "source_port": destination_port,
            "destination_port": source_port,
        }
    )
    updated["validation"] = validation
    return apply_shared_ipv4_rewrite_tail(
        updated,
        case_name=case_name,
        source_ipv4=source_ipv4,
        target_ipv4=target_ipv4,
        rewrite_source=rewrite_source,
    )


def quic_failure_reasons(case_name: str) -> list[str] | None:
    if case_name in _QUIC_STIMULUS_ENDPOINT_CASES:
        return [
            "timeout",
            "wrong_peer",
            "wrong_payload",
            "decode_failed",
            "target_setup_failed",
        ]
    return None


def quic_lab_capabilities(substrate: Mapping[str, JSONValue]) -> Mapping[str, object]:
    ipv4_unicast = capability(substrate, "ipv4_unicast", "ipv4")
    controlled_services = capability(
        substrate,
        "controlled_services",
        "controlled_service",
    )
    return {"quic_udp_service": ipv4_unicast and controlled_services}


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
        target_service=quic_target_service_contribution,
        setup_script=None,
        rewrite_endpoint_addresses=quic_rewrite_endpoint_addresses,
        failure_reasons=quic_failure_reasons,
        lab_capabilities=quic_lab_capabilities,
    )
)
