"""MQTT probe protocol plugin planning and target-service surface."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..capability_derivation import capability, capability_default_true
from ..case_helpers import _behavior_case
from ..endpoint_addressing import apply_shared_ipv4_rewrite_tail
from ..model import JSONObject, JSONValue, ProbeCase, json_object
from ..planning_helpers import deterministic_bytes, deterministic_ipv4_pair
from ..target_service_helpers import (
    TargetServiceDescriptor,
    json_mapping,
    string_or,
    target_service_address_fields,
)
from .base import ProtocolPlugin, register


MQTT_SERVICE_KIND = "mosquitto-mqtt-broker"
MQTT_SERVICE_PORT = 1883
MQTT_RUNTIME = "mosquitto"
MQTT_PROVISION_SCRIPT = "tools/probe/target_services/mqtt/provision-broker.sh"
MQTT_CONFIG_TEMPLATE = "tools/probe/target_services/mqtt/mosquitto.conf.template"
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
        description=(
            "Plan an MQTT CONNECT exchange against a probe-owned Mosquitto "
            "broker and expect CONNACK."
        ),
        stimulus="mqtt_connect",
        expected_response="mqtt_connack",
        required_capabilities=_MQTT_CAPABILITIES,
        protocol="mqtt",
        metadata={
            "service": "mosquitto",
            "stateful": True,
            "planned_only": True,
        },
    ),
    _behavior_case(
        name="mqtt-v5-connect-connack",
        description=(
            "Plan an MQTT 5.0 CONNECT exchange with properties against a "
            "probe-owned Mosquitto broker and expect a reason-code CONNACK."
        ),
        stimulus="mqtt_v5_connect",
        expected_response="mqtt_v5_connack",
        required_capabilities=_MQTT_CAPABILITIES,
        protocol="mqtt",
        metadata={
            "service": "mosquitto",
            "stateful": True,
            "planned_only": True,
        },
    ),
    _behavior_case(
        name="mqtt-subscribe-suback",
        description=(
            "Plan an MQTT SUBSCRIBE exchange against a probe-owned Mosquitto "
            "broker and expect SUBACK."
        ),
        stimulus="mqtt_subscribe",
        expected_response="mqtt_suback",
        required_capabilities=_MQTT_CAPABILITIES,
        protocol="mqtt",
        metadata={
            "service": "mosquitto",
            "stateful": True,
            "planned_only": True,
        },
    ),
    _behavior_case(
        name="mqtt-publish-puback",
        description=(
            "Plan an MQTT QoS 1 PUBLISH exchange against a probe-owned "
            "Mosquitto broker and expect PUBACK."
        ),
        stimulus="mqtt_publish",
        expected_response="mqtt_puback",
        required_capabilities=_MQTT_CAPABILITIES,
        protocol="mqtt",
        metadata={
            "service": "mosquitto",
            "stateful": True,
            "planned_only": True,
        },
    ),
)
_MQTT_CASE_BY_NAME: dict[str, ProbeCase] = {
    case.name: case for case in MQTT_SMOKE_CASES
}
_MQTT_PLANNED_ONLY_CASES = frozenset(_MQTT_CASE_BY_NAME)


def _mqtt_probe_plan(
    *,
    case_name: str,
    profile: str,
    seed: int,
    sequence: int,
) -> JSONObject:
    """Plan a deterministic MQTT broker exchange without materializing bytes."""

    case = _MQTT_CASE_BY_NAME[case_name]
    digest = deterministic_bytes(case_name, profile, seed, sequence)
    stimulus_ipv4, target_ipv4 = deterministic_ipv4_pair(profile, seed, sequence)
    source_port = _MQTT_SOURCE_PORT_BASE + int.from_bytes(digest[0:2], "big") % 12000
    client_id = f"{_MQTT_CLIENT_ID_PREFIX}-{sequence}"
    mqtt_service = mqtt_broker_descriptor(
        bind_ipv4=target_ipv4,
        source_ipv4=stimulus_ipv4,
    )
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
        expected_shape = {
            "packet_type": "PUBACK",
            "packet_id": _MQTT_PUBLISH_PACKET_ID,
        }
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
            "tcp": {
                "source_port": source_port,
                "destination_port": MQTT_SERVICE_PORT,
            },
            "mqtt": stimulus_shape,
        },
        "expected_response_packet_shape": {
            "ipv4": {
                "source": target_ipv4,
                "destination": stimulus_ipv4,
                "protocol": 6,
            },
            "tcp": {
                "source_port": MQTT_SERVICE_PORT,
                "destination_port": source_port,
            },
            "mqtt": expected_shape,
        },
        "target_service": {
            "required": True,
            "kind": mqtt_service.name,
            "protocol": mqtt_service.protocol,
            "port": mqtt_service.port,
            "bind_ipv4": mqtt_service.bind_ipv4,
            "source_ipv4": mqtt_service.source_ipv4,
            "runtime": MQTT_RUNTIME,
            "provision_script": MQTT_PROVISION_SCRIPT,
            "config_template": MQTT_CONFIG_TEMPLATE,
            "anonymous_access": bool(mqtt_service.metadata["anonymous_access"]),
            "persistence": bool(mqtt_service.metadata["persistence"]),
            "deterministic": True,
        },
        "capture_filter": (
            f"tcp and src host {target_ipv4} and dst host {stimulus_ipv4} "
            f"and src port {MQTT_SERVICE_PORT} and dst port {source_port}"
        ),
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
            "note": "MQTT exchanges require a probe-owned broker and TCP session state.",
        },
        "digest_hex": digest.hex()[:16],
    }


def mqtt_broker_descriptor(
    *,
    bind_ipv4: str,
    source_ipv4: str,
) -> TargetServiceDescriptor:
    """Describe the probe-owned Mosquitto MQTT broker target service."""

    from ..capabilities import SKIP_REQUIRES_CONTROLLED_SERVICE

    return TargetServiceDescriptor(
        name=MQTT_SERVICE_KIND,
        protocol="tcp",
        purpose="mqtt-broker",
        bind_ipv4=bind_ipv4,
        source_ipv4=source_ipv4,
        port=MQTT_SERVICE_PORT,
        requires=[MQTT_RUNTIME, SKIP_REQUIRES_CONTROLLED_SERVICE],
        setup_commands=[
            f"run {MQTT_PROVISION_SCRIPT} with MQTT_BIND_IPV4={bind_ipv4}",
            "inspect mosquitto version and TCP listener",
        ],
        cleanup_commands=[
            "stop Mosquitto MQTT broker service through provider cleanup",
        ],
        artifacts=[
            "live-artifacts/probe/target-services/mqtt-provision.stdout.txt",
            "live-artifacts/probe/target-services/mqtt-provision.stderr.txt",
        ],
        metadata={
            "kind": MQTT_SERVICE_KIND,
            "runtime": MQTT_RUNTIME,
            "deterministic": True,
            "provision_script": MQTT_PROVISION_SCRIPT,
            "config_template": MQTT_CONFIG_TEMPLATE,
            "anonymous_access": True,
            "persistence": False,
        },
    )


def mqtt_broker_service_plans(probe_plans: Sequence[JSONObject]) -> list[JSONObject]:
    """Return the Mosquitto MQTT broker service plan, if any plan requests it."""

    if not probe_plans:
        return []
    plan = probe_plans[0]
    addresses = target_service_address_fields(plan)
    descriptor = mqtt_broker_descriptor(
        bind_ipv4=string_or(addresses.get("bind_ipv4"), ""),
        source_ipv4=string_or(addresses.get("source_ipv4"), ""),
    )
    service: JSONObject = {
        "name": descriptor.name,
        "kind": descriptor.name,
        "protocol": descriptor.protocol,
        "port": descriptor.port,
        "purpose": descriptor.purpose,
        "deterministic": True,
        "requires": list(descriptor.requires),
        **addresses,
        **descriptor.metadata,
    }
    return [service]


def mqtt_broker_probe_plans(probe_plans: Sequence[JSONObject]) -> list[JSONObject]:
    """Return probe plans that require the probe-owned Mosquitto broker."""

    return [plan for plan in probe_plans if probe_plan_requires_mqtt_broker(plan)]


def probe_plan_requires_mqtt_broker(plan: Mapping[str, JSONValue]) -> bool:
    """Return whether a probe plan requests Mosquitto broker target setup."""

    target_service = json_mapping(
        plan.get("target_service", {}),
        "probe_plan.target_service",
    )
    if target_service.get("kind") == MQTT_SERVICE_KIND:
        return True
    case_name = plan.get("case")
    return isinstance(case_name, str) and case_name.startswith("mqtt-")


def mqtt_target_service_contribution(
    probe_plans: Sequence[JSONObject],
    *,
    dry_run: bool,
) -> JSONObject:
    mqtt_plans = mqtt_broker_probe_plans(probe_plans)
    return {
        "services": mqtt_broker_service_plans(mqtt_plans),
        "starts_services": not dry_run and bool(mqtt_plans),
    }


def mqtt_lab_capabilities(substrate: Mapping[str, JSONValue]) -> Mapping[str, object]:
    """Return the MQTT plugin's derived broker capability contribution."""

    ipv4_unicast = capability(substrate, "ipv4_unicast", "ipv4")
    controlled_services = capability(
        substrate,
        "controlled_services",
        "controlled_service",
    )
    return {
        "mqtt_broker": (
            ipv4_unicast
            and controlled_services
            and capability_default_true(substrate, "mqtt_broker")
        ),
    }


def mqtt_rewrite_endpoint_addresses(
    plan: JSONObject,
    *,
    source_ipv4: str,
    target_ipv4: str,
    source_mac: str | None = None,
    target_mac: str | None = None,
    target_interface: str | None = None,
    rewrite_source: str = "wire_endpoint_plan",
) -> JSONObject:
    """Rewrite an MQTT planned exchange onto lab-session endpoint addresses."""

    updated = dict(plan)
    updated["source_ipv4"] = source_ipv4
    updated["destination_ipv4"] = target_ipv4
    updated["expected_reply_source_ipv4"] = target_ipv4
    updated["expected_reply_destination_ipv4"] = source_ipv4
    case_name = str(updated.get("case", ""))
    source_port = int(updated.get("source_port", 0))
    destination_port = int(updated.get("destination_port", MQTT_SERVICE_PORT))
    updated["capture_filter"] = (
        f"tcp and src host {target_ipv4} and dst host {source_ipv4} "
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

    broker_exchange = dict(
        json_object(updated.get("broker_exchange", {}), "probe_plan.broker_exchange")
    )
    if broker_exchange:
        broker_exchange.update(
            {
                "broker_ipv4": target_ipv4,
                "broker_port": destination_port,
                "client_ipv4": source_ipv4,
                "client_port": source_port,
            }
        )
        updated["broker_exchange"] = broker_exchange

    stimulus_shape = dict(
        json_object(
            updated.get("stimulus_packet_shape", {}),
            "probe_plan.stimulus_packet_shape",
        )
    )
    if stimulus_shape:
        stimulus_ipv4 = dict(
            json_object(
                stimulus_shape.get("ipv4", {}),
                "probe_plan.stimulus_packet_shape.ipv4",
            )
        )
        stimulus_ipv4.update(
            {
                "source": source_ipv4,
                "destination": target_ipv4,
            }
        )
        stimulus_tcp = dict(
            json_object(
                stimulus_shape.get("tcp", {}),
                "probe_plan.stimulus_packet_shape.tcp",
            )
        )
        stimulus_tcp.update(
            {
                "source_port": source_port,
                "destination_port": destination_port,
            }
        )
        stimulus_shape["ipv4"] = stimulus_ipv4
        stimulus_shape["tcp"] = stimulus_tcp
        updated["stimulus_packet_shape"] = stimulus_shape

    expected_shape = dict(
        json_object(
            updated.get("expected_response_packet_shape", {}),
            "probe_plan.expected_response_packet_shape",
        )
    )
    if expected_shape:
        expected_ipv4 = dict(
            json_object(
                expected_shape.get("ipv4", {}),
                "probe_plan.expected_response_packet_shape.ipv4",
            )
        )
        expected_ipv4.update(
            {
                "source": target_ipv4,
                "destination": source_ipv4,
            }
        )
        expected_tcp = dict(
            json_object(
                expected_shape.get("tcp", {}),
                "probe_plan.expected_response_packet_shape.tcp",
            )
        )
        expected_tcp.update(
            {
                "source_port": destination_port,
                "destination_port": source_port,
            }
        )
        expected_shape["ipv4"] = expected_ipv4
        expected_shape["tcp"] = expected_tcp
        updated["expected_response_packet_shape"] = expected_shape

    return apply_shared_ipv4_rewrite_tail(
        updated,
        case_name=case_name,
        source_ipv4=source_ipv4,
        target_ipv4=target_ipv4,
        rewrite_source=rewrite_source,
    )


_MQTT_PLAN_BUILDERS: dict[str, object] = {
    name: _mqtt_probe_plan for name in _MQTT_CASE_BY_NAME
}


register(
    ProtocolPlugin(
        name="mqtt",
        cases=MQTT_SMOKE_CASES,
        plan_builders=_MQTT_PLAN_BUILDERS,
        planned_only_cases=_MQTT_PLANNED_ONLY_CASES,
        target_service=mqtt_target_service_contribution,
        rewrite_endpoint_addresses=mqtt_rewrite_endpoint_addresses,
        lab_capabilities=mqtt_lab_capabilities,
    )
)
