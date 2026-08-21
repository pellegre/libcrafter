"""Deterministic MQTT probe cases and packet plans."""

from __future__ import annotations
from ..case_helpers import _behavior_case
from ..model import JSONObject, ProbeCase
from ..planning_helpers import deterministic_bytes, deterministic_ipv4_pair
from .base import ProtocolPlugin, register

MQTT_SERVICE_KIND = "mosquitto-mqtt-broker"
MQTT_SERVICE_PORT = 1883
_MQTT_CAPABILITIES = ["mqtt_broker"]
_MQTT_SOURCE_PORT_BASE = 49194
_MQTT_CLIENT_ID_PREFIX = "crafter-probe"
_MQTT_KEEP_ALIVE_SECONDS = 30
_MQTT_SUBSCRIBE_TOPIC = "crafter/probe/inbound"
_MQTT_PUBLISH_TOPIC = "crafter/probe/outbound"
_MQTT_PUBLISH_PAYLOAD = b"hello from crafter probe"
_MQTT_SUBSCRIBE_PACKET_ID = 1
_MQTT_PUBLISH_PACKET_ID = 2
_MQTT_QOS_1 = 1
_MQTT_CONNACK_ACCEPTED = 0
_MQTT_V5_PROTOCOL_LEVEL = 5
_MQTT_V5_CONNECT_PROPERTIES: tuple[JSONObject, ...] = (
    {"name": "session_expiry_interval", "value": 60},
    {"name": "receive_maximum", "value": 10},
)
MQTT_SMOKE_CASES: tuple[ProbeCase, ...] = (
    _behavior_case(
        name="mqtt-connect-connack",
        description="Plan an MQTT CONNECT exchange against a controlled Mosquitto broker and expect CONNACK.",
        stimulus="mqtt_connect",
        expected_response="mqtt_connack",
        required_capabilities=_MQTT_CAPABILITIES,
        protocol="mqtt",
        metadata={"service": "mosquitto", "stateful": True, "planned_only": True},
    ),
    _behavior_case(
        name="mqtt-v5-connect-connack",
        description="Plan an MQTT 5.0 CONNECT exchange with properties against a controlled Mosquitto broker and expect a reason-code CONNACK.",
        stimulus="mqtt_v5_connect",
        expected_response="mqtt_v5_connack",
        required_capabilities=_MQTT_CAPABILITIES,
        protocol="mqtt",
        metadata={"service": "mosquitto", "stateful": True, "planned_only": True},
    ),
    _behavior_case(
        name="mqtt-subscribe-suback",
        description="Plan an MQTT SUBSCRIBE exchange against a controlled Mosquitto broker and expect SUBACK.",
        stimulus="mqtt_subscribe",
        expected_response="mqtt_suback",
        required_capabilities=_MQTT_CAPABILITIES,
        protocol="mqtt",
        metadata={"service": "mosquitto", "stateful": True, "planned_only": True},
    ),
    _behavior_case(
        name="mqtt-publish-puback",
        description="Plan an MQTT QoS 1 PUBLISH exchange against a controlled Mosquitto broker and expect PUBACK.",
        stimulus="mqtt_publish",
        expected_response="mqtt_puback",
        required_capabilities=_MQTT_CAPABILITIES,
        protocol="mqtt",
        metadata={"service": "mosquitto", "stateful": True, "planned_only": True},
    ),
)
_MQTT_CASE_BY_NAME: dict[str, ProbeCase] = {
    case.name: case for case in MQTT_SMOKE_CASES
}
_MQTT_PLANNED_ONLY_CASES = frozenset(_MQTT_CASE_BY_NAME)


def _mqtt_probe_plan(
    *, case_name: str, profile: str, seed: int, sequence: int
) -> JSONObject:
    case = _MQTT_CASE_BY_NAME[case_name]
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    source_port = _MQTT_SOURCE_PORT_BASE + int.from_bytes(digest[0:2], "big") % 12000
    client_id = f"{_MQTT_CLIENT_ID_PREFIX}-{sequence}"
    connect_step: JSONObject = {
        "label": "CONNECT",
        "stimulus": "mqtt_connect",
        "expected_response": "mqtt_connack",
        "client_id": client_id,
        "keep_alive_seconds": _MQTT_KEEP_ALIVE_SECONDS,
        "clean_session": True,
    }
    subscribe_step: JSONObject = {
        "label": "SUBSCRIBE",
        "stimulus": "mqtt_subscribe",
        "expected_response": "mqtt_suback",
        "packet_id": _MQTT_SUBSCRIBE_PACKET_ID,
        "topic": _MQTT_SUBSCRIBE_TOPIC,
        "qos": _MQTT_QOS_1,
    }
    publish_step: JSONObject = {
        "label": "PUBLISH QoS1",
        "stimulus": "mqtt_publish",
        "expected_response": "mqtt_puback",
        "packet_id": _MQTT_PUBLISH_PACKET_ID,
        "topic": _MQTT_PUBLISH_TOPIC,
        "qos": _MQTT_QOS_1,
        "payload_hex": _MQTT_PUBLISH_PAYLOAD.hex(),
        "payload_length": len(_MQTT_PUBLISH_PAYLOAD),
    }
    if case_name == "mqtt-connect-connack":
        stimulus_shape: JSONObject = {
            "packet_type": "CONNECT",
            "client_id": client_id,
            "keep_alive_seconds": _MQTT_KEEP_ALIVE_SECONDS,
            "clean_session": True,
        }
        expected_shape: JSONObject = {
            "packet_type": "CONNACK",
            "return_code": _MQTT_CONNACK_ACCEPTED,
        }
        steps = [connect_step]
    elif case_name == "mqtt-v5-connect-connack":
        v5_connect_step: JSONObject = {
            **connect_step,
            "label": "CONNECT v5",
            "stimulus": "mqtt_v5_connect",
            "expected_response": "mqtt_v5_connack",
            "version": _MQTT_V5_PROTOCOL_LEVEL,
            "connect_properties": list(_MQTT_V5_CONNECT_PROPERTIES),
        }
        stimulus_shape = {
            "packet_type": "CONNECT",
            "version": _MQTT_V5_PROTOCOL_LEVEL,
            "client_id": client_id,
            "keep_alive_seconds": _MQTT_KEEP_ALIVE_SECONDS,
            "clean_session": True,
            "connect_properties": list(_MQTT_V5_CONNECT_PROPERTIES),
        }
        expected_shape = {
            "packet_type": "CONNACK",
            "version": _MQTT_V5_PROTOCOL_LEVEL,
            "reason_code": _MQTT_CONNACK_ACCEPTED,
        }
        steps = [v5_connect_step]
    elif case_name == "mqtt-subscribe-suback":
        stimulus_shape = {
            "packet_type": "SUBSCRIBE",
            "packet_id": _MQTT_SUBSCRIBE_PACKET_ID,
            "topic": _MQTT_SUBSCRIBE_TOPIC,
            "qos": _MQTT_QOS_1,
        }
        expected_shape = {
            "packet_type": "SUBACK",
            "packet_id": _MQTT_SUBSCRIBE_PACKET_ID,
            "suback_return_codes": "no_failure",
        }
        steps = [connect_step, subscribe_step]
    elif case_name == "mqtt-publish-puback":
        stimulus_shape = {
            "packet_type": "PUBLISH",
            "packet_id": _MQTT_PUBLISH_PACKET_ID,
            "topic": _MQTT_PUBLISH_TOPIC,
            "qos": _MQTT_QOS_1,
            "payload_hex": _MQTT_PUBLISH_PAYLOAD.hex(),
            "payload_length": len(_MQTT_PUBLISH_PAYLOAD),
        }
        expected_shape = {"packet_type": "PUBACK", "packet_id": _MQTT_PUBLISH_PACKET_ID}
        steps = [connect_step, publish_step]
    else:
        raise ValueError(f"unsupported MQTT probe case {case_name!r}")
    return {
        "schema_version": 1,
        "case": case.name,
        "sequence": sequence,
        "index": sequence,
        "profile": profile,
        "seed": seed,
        "stimulus": case.stimulus,
        "expected_response": case.expected_response,
        "planned_only": True,
        "protocol": "mqtt",
        "source_ipv4": stimulus_ipv4,
        "destination_ipv4": target_ipv4,
        "expected_reply_source_ipv4": target_ipv4,
        "expected_reply_destination_ipv4": stimulus_ipv4,
        "source_port": source_port,
        "destination_port": MQTT_SERVICE_PORT,
        "broker_exchange": {
            "transport": "tcp",
            "broker_ipv4": target_ipv4,
            "broker_port": MQTT_SERVICE_PORT,
            "client_ipv4": stimulus_ipv4,
            "client_port": source_port,
            "steps": steps,
        },
        "stimulus_driver": {
            "name": case.stimulus,
            "adapter_module": "tools/probe/adapters/src/mqtt.rs",
            "state": "planned-only",
            "planned_only": True,
        },
        "stimulus_packet_shape": {
            "ipv4": {
                "source": stimulus_ipv4,
                "destination": target_ipv4,
                "protocol": 6,
            },
            "tcp": {"source_port": source_port, "destination_port": MQTT_SERVICE_PORT},
            "mqtt": stimulus_shape,
        },
        "expected_response_packet_shape": {
            "ipv4": {
                "source": target_ipv4,
                "destination": stimulus_ipv4,
                "protocol": 6,
            },
            "tcp": {"source_port": MQTT_SERVICE_PORT, "destination_port": source_port},
            "mqtt": expected_shape,
        },
        "capture_filter": f"tcp and src host {target_ipv4} and dst host {stimulus_ipv4} and src port {MQTT_SERVICE_PORT} and dst port {source_port}",
        "validation": {
            "planned_only": True,
            "driver": case.stimulus,
            "source_ipv4": target_ipv4,
            "destination_ipv4": stimulus_ipv4,
            "source_port": MQTT_SERVICE_PORT,
            "destination_port": source_port,
            "expected_response": case.expected_response,
            "mqtt": expected_shape,
        },
        "wire_requirements": {
            "requires_ipv4_unicast": True,
            "requires_controlled_service": True,
            "requires_mqtt_broker": True,
            "note": "MQTT exchanges require a controlled broker and TCP session state.",
        },
        "digest_hex": digest.hex()[:16],
    }


_MQTT_PLAN_BUILDERS: dict[str, object] = {
    name: _mqtt_probe_plan for name in _MQTT_CASE_BY_NAME
}
register(
    ProtocolPlugin(
        name="mqtt",
        cases=MQTT_SMOKE_CASES,
        plan_builders=_MQTT_PLAN_BUILDERS,
        planned_only_cases=_MQTT_PLANNED_ONLY_CASES,
    )
)
