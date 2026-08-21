"""Deterministic IPSEC probe cases and packet plans."""

from __future__ import annotations
from collections.abc import Sequence
from tools.oracle.engine import ipsec_interop as _ipsec_interop
from ..case_helpers import _behavior_case
from ..model import JSONObject, ProbeCase
from ..planning_helpers import deterministic_bytes, deterministic_ipv4_pair
from .base import ProtocolPlugin, register

_IPSEC_ESP_CAPABILITIES = ["ipsec_esp"]
_IPSEC_AH_CAPABILITIES = ["ipsec_ah"]
_IKEV2_CAPABILITIES = ["ikev2"]
BEHAVIOR_IPSEC_CASES: tuple[ProbeCase, ...] = (
    _behavior_case(
        name="esp-transport-echo",
        description="Send an ESP-protected (transport-mode) ICMP echo request to the peer and validate the peer's ESP-protected echo reply.",
        stimulus="esp_transport_echo_request",
        expected_response="esp_transport_echo_reply",
        required_capabilities=_IPSEC_ESP_CAPABILITIES,
        protocol="ipsec",
        metadata={"ipsec_protocol": "esp", "mode": "transport", "stateful": True},
    ),
    _behavior_case(
        name="esp-tunnel-echo",
        description="Send a tunnel-mode ESP-encapsulated ICMP echo request (inner IP inside ESP) to the peer and validate the tunnel-mode ESP echo reply.",
        stimulus="esp_tunnel_echo_request",
        expected_response="esp_tunnel_echo_reply",
        required_capabilities=_IPSEC_ESP_CAPABILITIES,
        protocol="ipsec",
        metadata={
            "ipsec_protocol": "esp",
            "mode": "tunnel",
            "stateful": True,
            "requires_tunnel": True,
            "notes": "Needs the peer to hold a tunnel-mode ESP SA (inner IP); a transport-only peer skips this case. Live runners configure a tunnel-mode SA or skip.",
        },
    ),
    _behavior_case(
        name="ah-transport-verify",
        description="Send an AH-protected (transport-mode) datagram to the peer and validate that the peer accepts it (the ICV verifies) and responds.",
        stimulus="ah_transport_request",
        expected_response="ah_transport_response",
        required_capabilities=_IPSEC_AH_CAPABILITIES,
        protocol="ipsec",
        metadata={"ipsec_protocol": "ah", "mode": "transport", "stateful": True},
    ),
    _behavior_case(
        name="ikev2-sa-init",
        description="Send an IKE_SA_INIT request (header + SA + KE + Ni) over UDP/500 and validate a well-formed IKE_SA_INIT response from the peer's IKE responder.",
        stimulus="ikev2_sa_init_request",
        expected_response="ikev2_sa_init_response",
        required_capabilities=_IKEV2_CAPABILITIES,
        protocol="ipsec",
        metadata={
            "ipsec_protocol": "ikev2",
            "exchange": "IKE_SA_INIT",
            "stateful": True,
        },
    ),
)
_IPSEC_ESP_PROTOCOL = 50
_IPSEC_AH_PROTOCOL = 51
_IKEV2_UDP_PORT = 500


def _ipsec_probe_plan(
    *, case_name: str, profile: str, seed: int, sequence: int
) -> JSONObject:
    from ..cases import PROBE_CASE_BY_NAME

    case = PROBE_CASE_BY_NAME[case_name]
    metadata = case.metadata or {}
    ipsec_protocol = str(metadata.get("ipsec_protocol", "ipsec"))
    mode = metadata.get("mode")
    exchange = metadata.get("exchange")
    requires_tunnel = bool(metadata.get("requires_tunnel", False))
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    spi = 4096 + int.from_bytes(digest[0:4], "big") % 4294901760
    stimulus_shape: JSONObject = {
        "ipsec_protocol": ipsec_protocol,
        "stimulus": case.stimulus,
    }
    response_shape: JSONObject = {
        "ipsec_protocol": ipsec_protocol,
        "expected_response": case.expected_response,
    }
    if ipsec_protocol == "esp":
        stimulus_shape["ip_protocol"] = _IPSEC_ESP_PROTOCOL
        response_shape["ip_protocol"] = _IPSEC_ESP_PROTOCOL
        stimulus_shape["spi"] = spi
        response_shape["spi"] = spi
        if mode is not None:
            stimulus_shape["mode"] = mode
            response_shape["mode"] = mode
    elif ipsec_protocol == "ah":
        stimulus_shape["ip_protocol"] = _IPSEC_AH_PROTOCOL
        response_shape["ip_protocol"] = _IPSEC_AH_PROTOCOL
        stimulus_shape["spi"] = spi
        response_shape["spi"] = spi
        if mode is not None:
            stimulus_shape["mode"] = mode
            response_shape["mode"] = mode
    elif ipsec_protocol == "ikev2":
        stimulus_shape["udp_port"] = _IKEV2_UDP_PORT
        response_shape["udp_port"] = _IKEV2_UDP_PORT
        if exchange is not None:
            stimulus_shape["exchange"] = exchange
            response_shape["exchange"] = exchange
    plan: JSONObject = {
        "schema_version": 1,
        "case": case_name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": case.stimulus,
        "expected_response": case.expected_response,
        "planned_only": True,
        "ipsec_protocol": ipsec_protocol,
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "stimulus_packet_shape": stimulus_shape,
        "expected_response_packet_shape": response_shape,
        "ipsec_peer": {
            "required": True,
            "role": "ipsec_peer" if ipsec_protocol != "ikev2" else "ikev2_responder",
            "kind": (
                "ikev2-responder"
                if ipsec_protocol == "ikev2"
                else f"ipsec-{ipsec_protocol}-{mode or 'transport'}-peer"
            ),
            "peer_options": ["linux-xfrm", "strongswan", "oracle-reference-peer"],
            "live_only": True,
        },
        "digest_hex": digest.hex()[:16],
    }
    if mode is not None:
        plan["mode"] = mode
    if exchange is not None:
        plan["exchange"] = exchange
    if requires_tunnel:
        plan["requires_tunnel"] = True
    return plan


_IPSEC_PLAN_BUILDERS: dict[str, object] = {
    "esp-transport-echo": _ipsec_probe_plan,
    "esp-tunnel-echo": _ipsec_probe_plan,
    "ah-transport-verify": _ipsec_probe_plan,
    "ikev2-sa-init": _ipsec_probe_plan,
}
_IPSEC_PLANNED_ONLY_CASES: frozenset[str] = frozenset(
    {"esp-transport-echo", "esp-tunnel-echo", "ah-transport-verify", "ikev2-sa-init"}
)
_IPSEC_PROBE_CASES: frozenset[str] = frozenset(
    {"esp-transport-echo", "esp-tunnel-echo", "ah-transport-verify", "ikev2-sa-init"}
)


def _ipsec_interop_dry_run_metadata(
    selected_cases: Sequence[ProbeCase],
) -> JSONObject | None:
    if not any((case.name in _IPSEC_PROBE_CASES for case in selected_cases)):
        return None
    try:
        report = _ipsec_interop.run_interop()
    except _ipsec_interop.IpsecInteropError as exc:
        return {
            "check": "ipsec-cross-crypto-interop",
            "available": False,
            "passed": None,
            "reason": str(exc),
        }
    report["available"] = True
    return report


register(
    ProtocolPlugin(
        name="ipsec",
        cases=BEHAVIOR_IPSEC_CASES,
        plan_builders=_IPSEC_PLAN_BUILDERS,
        planned_only_cases=_IPSEC_PLANNED_ONLY_CASES,
        profile_counts={},
        stimulus_endpoint_cases=frozenset(),
        failure_reasons=None,
        ipsec_interop=_ipsec_interop_dry_run_metadata,
    )
)
