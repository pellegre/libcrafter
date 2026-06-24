"""Unit coverage for Scapy backend MQTT contrib support."""

from __future__ import annotations

import unittest

from tools.oracle.engine.model import PacketPlan


def _scapy_available() -> bool:
    try:
        import scapy  # type: ignore[import-untyped]  # noqa: F401
        import scapy.all  # type: ignore[import-untyped]  # noqa: F401
        import scapy.contrib.mqtt  # type: ignore[import-untyped]  # noqa: F401
    except ModuleNotFoundError:
        return False
    return True


@unittest.skipUnless(_scapy_available(), "scapy MQTT contrib is not available")
class ScapyMqttSupportTest(unittest.TestCase):
    def test_bootstrap_exposes_mqtt_contrib_layers(self) -> None:
        from tools.oracle.engine.backends.scapy.bootstrap import import_scapy

        scapy = import_scapy()

        self.assertIn("mqtt", scapy)
        mqtt = scapy["mqtt"]
        for class_name in [
            "MQTT",
            "MQTTConnect",
            "MQTTConnack",
            "MQTTPublish",
            "MQTTPuback",
            "MQTTPubrec",
            "MQTTPubrel",
            "MQTTPubcomp",
            "MQTTSubscribe",
            "MQTTSuback",
            "MQTTUnsubscribe",
            "MQTTUnsuback",
            "MQTTDisconnect",
        ]:
            self.assertTrue(hasattr(mqtt, class_name), class_name)

    def test_connect_plan_materializes_fixed_header_and_remaining_length(self) -> None:
        from tools.oracle.engine.backends.scapy import packets

        vector = packets.encode_packet_plan(
            _mqtt_plan(
                {
                    "packet_type": "connect",
                    "protocol_name": "MQTT",
                    "protocol_level": 4,
                    "clean_session": True,
                    "keep_alive": 30,
                    "client_id": "crafter-client",
                }
            )
        )
        raw = vector.to_bytes()

        self.assertEqual(raw[40:42], bytes.fromhex("101a"))
        self.assertEqual(
            raw[40:].hex(),
            "101a00044d5154540402001e000e637261667465722d636c69656e74",
        )
        self.assertEqual(vector.metadata["scapy_stack"][-1], "MQTT")

    def test_publish_plan_materializes_fixed_header_and_remaining_length(self) -> None:
        from tools.oracle.engine.backends.scapy import packets

        vector = packets.encode_packet_plan(
            _mqtt_plan(
                {
                    "packet_type": "publish",
                    "qos": 1,
                    "topic": "crafter/demo",
                    "packet_id": 2,
                    "payload": "hello",
                }
            )
        )
        raw = vector.to_bytes()

        self.assertEqual(raw[40:42], bytes.fromhex("3215"))
        self.assertEqual(
            raw[40:].hex(),
            "3215000c637261667465722f64656d6f000268656c6c6f",
        )


def _mqtt_plan(mqtt_fields: dict[str, object]) -> PacketPlan:
    return PacketPlan(
        stack=["ipv4", "tcp", "mqtt"],
        fields={
            "ipv4": {
                "src": "192.0.2.10",
                "dst": "198.51.100.20",
                "identification": 3901,
                "ttl": 64,
                "flags": "none",
                "protocol": "tcp",
            },
            "tcp": {
                "src_port": 49194,
                "dst_port": 1883,
                "flags": "ack",
                "sequence": 0x01020304,
                "acknowledgement": 0x05060708,
                "window": 8192,
                "reserved": 0,
            },
            "mqtt": mqtt_fields,
        },
        profile="mqtt-unit",
        seed=3901,
        index=0,
        direction="reference_to_libcrafter",
        family="mqtt",
        feature_tags=["baseline", "ipv4", "tcp", "mqtt"],
        case="mqtt-unit",
        strict_bytes=True,
        metadata={
            "root": "l3:ipv4",
            "root_decoder": "l3:ipv4",
            "stack_name": "ipv4_tcp_mqtt_payload",
        },
    )


if __name__ == "__main__":
    unittest.main()
