"""Generator-stage sampler plugin for the MQTT layer."""

from __future__ import annotations

from collections.abc import Mapping

from ..sampling import _SKIP_FIELD, _SamplingContext, weighted_choice
from .base import ProtocolSampler, register


_SUPPORTED_FIELDS = frozenset(
    {
        "packet_type",
        "flags",
        "remaining_length",
        "protocol_name",
        "protocol_level",
        "connect_flags",
        "keep_alive",
        "client_id",
        "packet_id",
        "topic",
        "topic_filters",
        "payload",
        "return_code",
        "username",
        "password",
    }
)


def _sample_mqtt_field(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    current_fields: Mapping[str, object],
) -> object:
    packet_type = str(current_fields.get("packet_type", ""))
    if field_name == "packet_type":
        return _mqtt_packet_type_for_case(ctx, domain)
    if field_name == "flags":
        return _mqtt_flags_for_packet_type(packet_type)
    if field_name == "remaining_length":
        return _SKIP_FIELD
    if field_name == "protocol_name":
        return "MQTT" if packet_type == "connect" else _SKIP_FIELD
    if field_name == "protocol_level":
        return 4 if packet_type == "connect" else _SKIP_FIELD
    if field_name == "connect_flags":
        return "clean_session" if packet_type == "connect" else _SKIP_FIELD
    if field_name == "keep_alive":
        return 60 if packet_type == "connect" else _SKIP_FIELD
    if field_name == "client_id":
        if packet_type != "connect":
            return _SKIP_FIELD
        if domain == "empty":
            return ""
        if domain == "boundary":
            return "crafter-" + ("x" * 32)
        return "crafter-client"
    if field_name == "packet_id":
        if packet_type not in {
            "publish",
            "puback",
            "pubrec",
            "pubrel",
            "pubcomp",
            "subscribe",
            "unsubscribe",
            "unsuback",
        }:
            return _SKIP_FIELD
        return 1
    if field_name == "topic":
        if packet_type != "publish":
            return _SKIP_FIELD
        return _mqtt_topic_for_domain(domain)
    if field_name == "topic_filters":
        if packet_type not in {"subscribe", "unsubscribe"}:
            return _SKIP_FIELD
        if domain == "multiple":
            return ["crafter/demo", "crafter/ops"]
        if domain == "wildcard":
            return ["crafter/+/status"]
        return ["crafter/demo"]
    if field_name == "payload":
        if packet_type != "publish":
            return _SKIP_FIELD
        if domain == "empty":
            return {"hex": ""}
        if domain == "binary":
            return {"hex": "000102ff"}
        if domain == "boundary":
            return {"hex": "41" * 32}
        return {"hex": "68656c6c6f"}
    if field_name == "return_code":
        if packet_type == "connack":
            if domain == "connack_refused":
                return 3
            return 0
        if packet_type == "suback":
            if domain == "suback_qos1":
                return 1
            if domain == "suback_qos2":
                return 2
            if domain == "suback_failure":
                return 0x80
            return 0
        return _SKIP_FIELD
    if field_name in {"username", "password"}:
        return _SKIP_FIELD
    raise ValueError(f"spec error: unsupported mqtt field sampler: {field_name}")


def _sample(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    return _sample_mqtt_field(ctx, field_name, domain, current_fields)


def _mqtt_packet_type_for_case(ctx: _SamplingContext, domain: object) -> str:
    normalized = ctx.case.replace("_", "-")
    if "ping" in normalized or "disconnect" in normalized:
        return weighted_choice(ctx.rng, (("pingreq", 2), ("pingresp", 1), ("disconnect", 1)))
    if "connect" in normalized:
        return "connect"
    if "publish" in normalized:
        return "publish"
    if "subscribe" in normalized:
        return "subscribe"
    if "unsubscribe" in normalized:
        return "unsubscribe"
    return str(domain)


def _mqtt_flags_for_packet_type(packet_type: str) -> str:
    if packet_type == "publish":
        return "publish_qos1"
    if packet_type == "pubrel":
        return "pubrel_required"
    if packet_type == "subscribe":
        return "subscribe_required"
    if packet_type == "unsubscribe":
        return "unsubscribe_required"
    return "default"


def _mqtt_topic_for_domain(domain: object) -> str:
    if domain == "boundary":
        return "crafter/" + ("x" * 32)
    return "crafter/demo"


register(
    ProtocolSampler(
        layer="mqtt",
        supported_fields=_SUPPORTED_FIELDS,
        sample=_sample,
    )
)
