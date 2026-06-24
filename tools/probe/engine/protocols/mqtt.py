"""MQTT probe protocol plugin target-service surface."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..model import JSONObject, JSONValue
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


register(
    ProtocolPlugin(
        name="mqtt",
        cases=(),
        target_service=mqtt_target_service_contribution,
    )
)
