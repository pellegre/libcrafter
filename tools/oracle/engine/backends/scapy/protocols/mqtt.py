"""Scapy-stage encode plugin for the MQTT layer."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from ....model import JSONObject
from ..bootstrap import import_scapy
from ..encode_helpers import (
    _bool_int,
    _bytes_field,
    _int,
    _layer_fields_for_stack_index,
    _optional_field,
    _required_field,
    _text,
)
from .base import ScapyProtocol, register


_SUPPORTED_FIELDS = frozenset(
    {
        "ack_flags",
        "clean_session",
        "cleansess",
        "clientId",
        "client_id",
        "connect_flags",
        "control_packet_type",
        "dup",
        "flags",
        "keep_alive",
        "klive",
        "len",
        "message_id",
        "msgid",
        "packet_id",
        "packet_type",
        "password",
        "payload",
        "payload_hex",
        "protocol_level",
        "protocol_name",
        "protolevel",
        "protoname",
        "qos",
        "remaining_length",
        "retain",
        "return_code",
        "return_codes",
        "session_present",
        "topic",
        "topic_filters",
        "topics",
        "type",
        "username",
        "value",
        "will_message",
        "will_qos",
        "will_retain",
        "will_topic",
    }
)

_MQTT_PACKET_TYPES: dict[str, int] = {
    "connect": 1,
    "connack": 2,
    "publish": 3,
    "puback": 4,
    "pubrec": 5,
    "pubrel": 6,
    "pubcomp": 7,
    "subscribe": 8,
    "suback": 9,
    "unsubscribe": 10,
    "unsuback": 11,
    "pingreq": 12,
    "pingresp": 13,
    "disconnect": 14,
}
_MQTT_FLAG_DOMAINS: dict[str, int] = {
    "default": 0,
    "publish_qos0": 0,
    "publish_qos1": 0x2,
    "publish_qos2": 0x4,
    "publish_dup": 0x8,
    "publish_retain": 0x1,
    "pubrel_required": 0x2,
    "subscribe_required": 0x2,
    "unsubscribe_required": 0x2,
    "malformed_override": 0xF,
}


def _build(
    plan: Any,
    fields: Mapping[str, JSONObject],
    stack: Any,
    index: int,
    scapy_all: Any,
) -> Any:
    return _mqtt(fields, stack, index)


def _mqtt(
    fields: Mapping[str, JSONObject],
    stack: Sequence[str],
    index: int,
) -> Any:
    scapy_mqtt = import_scapy()["mqtt"]
    mqtt_fields = _layer_fields_for_stack_index(fields, stack, index)
    packet_type = _mqtt_packet_type(
        _required_field(
            mqtt_fields,
            "mqtt",
            "packet_type",
            "control_packet_type",
            "type",
        )
    )
    flags = _mqtt_fixed_flags(mqtt_fields, packet_type)
    header_kwargs: dict[str, Any] = {
        "type": packet_type,
        "DUP": (flags >> 3) & 0x1,
        "QOS": (flags >> 1) & 0x3,
        "RETAIN": flags & 0x1,
    }
    remaining_length = _mqtt_remaining_length(mqtt_fields)
    if remaining_length is not None:
        header_kwargs["len"] = remaining_length

    header = scapy_mqtt.MQTT(**header_kwargs)
    body = _mqtt_body(packet_type, mqtt_fields, scapy_mqtt)
    return header if body is None else header / body


def _mqtt_packet_type(value: object) -> int:
    if isinstance(value, str):
        normalized = value.lower().replace("_", "-")
        if normalized in _MQTT_PACKET_TYPES:
            return _MQTT_PACKET_TYPES[normalized]
        return int(normalized, 0)
    return _int(value, 0)


def _mqtt_remaining_length(fields: Mapping[str, object]) -> int | None:
    value = _optional_field(fields, "remaining_length", "len")
    if isinstance(value, str) and value.lower().replace("-", "_") in {
        "auto",
        "default",
        "derived",
    }:
        return None
    if value is None:
        return None
    return _int(value, 0)


def _mqtt_fixed_flags(fields: Mapping[str, object], packet_type: int) -> int:
    value = _optional_field(fields, "flags")
    if value is not None:
        return _mqtt_flags_value(value, packet_type)
    if packet_type in {6, 8, 10}:
        return 0x2
    if packet_type == 3:
        flags = (_mqtt_qos(_optional_field(fields, "qos")) << 1) & 0x6
        if _bool_int(_optional_field(fields, "dup"), 0):
            flags |= 0x8
        if _bool_int(_optional_field(fields, "retain"), 0):
            flags |= 0x1
        return flags
    return 0


def _mqtt_flags_value(value: object, packet_type: int) -> int:
    if isinstance(value, str):
        normalized = value.lower().replace(" ", "_").replace("-", "_")
        if normalized in _MQTT_FLAG_DOMAINS:
            flags = _MQTT_FLAG_DOMAINS[normalized]
            if normalized == "default" and packet_type in {6, 8, 10}:
                return 0x2
            return flags
        return int(normalized, 0)
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray, str)):
        flags = 0
        for item in value:
            flags |= _mqtt_flags_value(item, packet_type)
        return flags
    return _int(value, 0)


def _mqtt_qos(value: object) -> int:
    if value is None:
        return 0
    if isinstance(value, str):
        normalized = value.lower().replace("-", "_")
        aliases = {
            "qos0": 0,
            "qos_0": 0,
            "at_most_once": 0,
            "qos1": 1,
            "qos_1": 1,
            "at_least_once": 1,
            "qos2": 2,
            "qos_2": 2,
            "exactly_once": 2,
        }
        if normalized in aliases:
            return aliases[normalized]
        return int(normalized, 0)
    return _int(value, 0)


def _mqtt_body(packet_type: int, fields: Mapping[str, object], scapy_mqtt: Any) -> Any | None:
    if packet_type == 1:
        return _mqtt_connect_body(fields, scapy_mqtt)
    if packet_type == 2:
        return scapy_mqtt.MQTTConnack(
            sessPresentFlag=_bool_int(
                _optional_field(fields, "session_present", "ack_flags"),
                0,
            ),
            retcode=_mqtt_return_code(_optional_field(fields, "return_code")),
        )
    if packet_type == 3:
        payload_hex = _optional_field(fields, "payload_hex")
        payload = (
            _bytes_field(payload_hex)
            if payload_hex is not None
            else _mqtt_payload_bytes(_optional_field(fields, "payload", "value"))
        )
        kwargs: dict[str, Any] = {
            "topic": _mqtt_text_bytes(_optional_field(fields, "topic"), "crafter/demo"),
            "value": payload,
        }
        packet_id = _mqtt_packet_id(fields)
        if packet_id is not None:
            kwargs["msgid"] = packet_id
        return scapy_mqtt.MQTTPublish(**kwargs)
    if packet_type in {4, 5, 6, 7, 11}:
        class_name = {
            4: "MQTTPuback",
            5: "MQTTPubrec",
            6: "MQTTPubrel",
            7: "MQTTPubcomp",
            11: "MQTTUnsuback",
        }[packet_type]
        return getattr(scapy_mqtt, class_name)(msgid=_mqtt_packet_id(fields) or 1)
    if packet_type == 8:
        return scapy_mqtt.MQTTSubscribe(
            msgid=_mqtt_packet_id(fields) or 1,
            topics=_mqtt_subscribe_topics(fields, scapy_mqtt),
        )
    if packet_type == 9:
        return scapy_mqtt.MQTTSuback(
            msgid=_mqtt_packet_id(fields) or 1,
            retcodes=_mqtt_return_codes(
                _optional_field(fields, "return_codes", "return_code")
            ),
        )
    if packet_type == 10:
        return scapy_mqtt.MQTTUnsubscribe(
            msgid=_mqtt_packet_id(fields) or 1,
            topics=_mqtt_unsubscribe_topics(fields, scapy_mqtt),
        )
    if packet_type == 14:
        return scapy_mqtt.MQTTDisconnect()
    if packet_type in {12, 13}:
        return None
    return None


def _mqtt_connect_body(fields: Mapping[str, object], scapy_mqtt: Any) -> Any:
    connect_flags_value = _optional_field(fields, "connect_flags")
    connect_flags = _mqtt_connect_flags(connect_flags_value)
    connect_flags_explicit = connect_flags_value is not None
    username = _optional_field(fields, "username")
    password = _optional_field(fields, "password")
    will_topic = _optional_field(fields, "will_topic")
    will_message = _optional_field(fields, "will_message")
    return scapy_mqtt.MQTTConnect(
        protoname=_mqtt_text_bytes(
            _optional_field(fields, "protocol_name", "protoname"),
            "MQTT",
        ),
        protolevel=_int(_optional_field(fields, "protocol_level", "protolevel"), 4),
        usernameflag=_mqtt_flag_bit(
            connect_flags,
            connect_flags_explicit,
            0x80,
            username is not None,
        ),
        passwordflag=_mqtt_flag_bit(
            connect_flags,
            connect_flags_explicit,
            0x40,
            password is not None,
        ),
        willretainflag=_mqtt_flag_bit(
            connect_flags,
            connect_flags_explicit,
            0x20,
            _bool_int(_optional_field(fields, "will_retain"), 0) != 0,
        ),
        willQOSflag=_mqtt_will_qos(fields, connect_flags),
        willflag=_mqtt_flag_bit(
            connect_flags,
            connect_flags_explicit,
            0x04,
            will_topic is not None or will_message is not None,
        ),
        cleansess=_mqtt_flag_bit(
            connect_flags,
            connect_flags_explicit,
            0x02,
            _bool_int(_optional_field(fields, "clean_session", "cleansess"), 1) != 0,
        ),
        reserved=connect_flags & 0x01,
        klive=_int(_optional_field(fields, "keep_alive", "klive"), 60),
        clientId=_mqtt_text_bytes(_optional_field(fields, "client_id", "clientId"), ""),
        willtopic=_mqtt_text_bytes(will_topic, ""),
        willmsg=_mqtt_payload_bytes(will_message),
        username=_mqtt_text_bytes(username, ""),
        password=_mqtt_payload_bytes(password),
    )


def _mqtt_connect_flags(value: object) -> int:
    if value is None:
        return 0
    if isinstance(value, str):
        normalized = value.lower().replace(" ", "_").replace("-", "_")
        aliases = {
            "clean_session": 0x02,
            "will": 0x04,
            "username": 0x80,
            "password": 0x40,
            "malformed_override": 0xFF,
        }
        if normalized in aliases:
            return aliases[normalized]
        return int(normalized, 0)
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray, str)):
        flags = 0
        for item in value:
            flags |= _mqtt_connect_flags(item)
        return flags
    return _int(value, 0)


def _mqtt_flag_bit(flags: int, explicit: bool, mask: int, fallback: bool) -> int:
    if explicit:
        return int(flags & mask != 0)
    return int(fallback)


def _mqtt_will_qos(fields: Mapping[str, object], connect_flags: int) -> int:
    value = _optional_field(fields, "will_qos")
    if value is not None:
        return _mqtt_qos(value)
    return (connect_flags >> 3) & 0x3


def _mqtt_packet_id(fields: Mapping[str, object]) -> int | None:
    value = _optional_field(fields, "packet_id", "message_id", "msgid")
    if value is None:
        return None
    return _int(value, 0)


def _mqtt_return_code(value: object) -> int:
    if value is None:
        return 0
    if isinstance(value, str):
        normalized = value.lower().replace("-", "_")
        aliases = {
            "accepted": 0,
            "connack_accepted": 0,
            "unacceptable_protocol_version": 1,
            "identifier_rejected": 2,
            "server_unavailable": 3,
            "bad_username_or_password": 4,
            "not_authorized": 5,
            "suback_qos0": 0,
            "suback_qos1": 1,
            "suback_qos2": 2,
            "suback_failure": 0x80,
            "failure": 0x80,
        }
        if normalized in aliases:
            return aliases[normalized]
        return int(normalized, 0)
    return _int(value, 0)


def _mqtt_return_codes(value: object) -> list[int]:
    if value is None:
        return []
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray, str)):
        return [_mqtt_return_code(item) for item in value]
    return [_mqtt_return_code(value)]


def _mqtt_subscribe_topics(fields: Mapping[str, object], scapy_mqtt: Any) -> list[Any]:
    return [
        scapy_mqtt.MQTTTopicQOS(topic=_mqtt_text_bytes(topic, ""), QOS=_mqtt_qos(qos))
        for topic, qos in _mqtt_topic_qos_pairs(fields)
    ]


def _mqtt_unsubscribe_topics(fields: Mapping[str, object], scapy_mqtt: Any) -> list[Any]:
    return [
        scapy_mqtt.MQTTTopic(topic=_mqtt_text_bytes(topic, ""))
        for topic in _mqtt_topic_values(fields)
    ]


def _mqtt_topic_qos_pairs(fields: Mapping[str, object]) -> list[tuple[object, object]]:
    value = _optional_field(fields, "topic_filters", "topics")
    if value is None:
        topic = _optional_field(fields, "topic")
        return [
            (
                topic if topic is not None else "crafter/demo",
                _optional_field(fields, "qos"),
            )
        ]
    if not isinstance(value, Sequence) or isinstance(value, (bytes, bytearray, str)):
        return [(value, _optional_field(fields, "qos"))]
    pairs: list[tuple[object, object]] = []
    for item in value:
        if isinstance(item, Mapping):
            topic = _optional_field(item, "topic", "filter", "name")
            qos = _optional_field(item, "qos", "requested_qos")
            pairs.append((topic if topic is not None else "crafter/demo", qos))
        else:
            pairs.append((item, _optional_field(fields, "qos")))
    return pairs


def _mqtt_topic_values(fields: Mapping[str, object]) -> list[object]:
    value = _optional_field(fields, "topic_filters", "topics")
    if value is None:
        topic = _optional_field(fields, "topic")
        return [topic if topic is not None else "crafter/demo"]
    if not isinstance(value, Sequence) or isinstance(value, (bytes, bytearray, str)):
        return [value]
    values: list[object] = []
    for item in value:
        if isinstance(item, Mapping):
            topic = _optional_field(item, "topic", "filter", "name")
            values.append(topic if topic is not None else "crafter/demo")
        else:
            values.append(item)
    return values


def _mqtt_text_bytes(value: object, default: str) -> bytes:
    if value is None:
        return default.encode("utf-8")
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, Mapping):
        return _bytes_field(value)
    return _text(value, default).encode("utf-8")


def _mqtt_payload_bytes(value: object) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, Mapping):
        return _bytes_field(value)
    if isinstance(value, str):
        return value.encode("utf-8")
    raise ValueError(f"expected MQTT bytes-compatible value, got {value!r}")


register(
    ScapyProtocol(
        layer="mqtt",
        scapy_class="MQTT",
        supported_fields=_SUPPORTED_FIELDS,
        build=_build,
    )
)
