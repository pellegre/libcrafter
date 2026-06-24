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

    def test_connect_plan_decodes_to_normalized_mqtt_fields(self) -> None:
        from tools.oracle.engine.backends.scapy import normalize, packets

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
        decoded = normalize.decode_vector(vector)

        self.assertEqual(decoded.layers, ["ipv4", "tcp", "mqtt"])
        self.assertEqual(decoded.root, "l3:ipv4")
        mqtt = decoded.fields["mqtt"]
        self.assertEqual(mqtt["packet_type"], "connect")
        self.assertEqual(mqtt["flags"], 0)
        self.assertEqual(mqtt["remaining_length"], 26)
        self.assertEqual(mqtt["protocol_name"], "MQTT")
        self.assertEqual(mqtt["protocol_level"], 4)
        self.assertEqual(mqtt["connect_flags"], 2)
        self.assertTrue(mqtt["clean_session"])
        self.assertEqual(mqtt["keep_alive"], 30)
        self.assertEqual(mqtt["client_id"], "crafter-client")
        self.assertIn("native", decoded.metadata)

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

    def test_publish_plan_decodes_to_normalized_mqtt_fields(self) -> None:
        from tools.oracle.engine.backends.scapy import normalize, packets

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
        decoded = normalize.decode_vector(vector)

        self.assertEqual(decoded.layers, ["ipv4", "tcp", "mqtt"])
        mqtt = decoded.fields["mqtt"]
        self.assertEqual(mqtt["packet_type"], "publish")
        self.assertEqual(mqtt["flags"], 2)
        self.assertEqual(mqtt["remaining_length"], 21)
        self.assertEqual(mqtt["topic"], "crafter/demo")
        self.assertEqual(mqtt["qos"], 1)
        self.assertFalse(mqtt["dup"])
        self.assertFalse(mqtt["retain"])
        self.assertEqual(mqtt["packet_id"], 2)
        self.assertEqual(mqtt["payload"], {"hex": "68656c6c6f", "length": 5})

    def test_stacked_mqtt_payload_decodes_to_multiple_mqtt_layers(self) -> None:
        from tools.oracle.engine.backends.scapy import normalize
        from tools.oracle.engine.backends.scapy.bootstrap import import_scapy

        scapy = import_scapy()["all"]
        raw = bytes(
            scapy.raw(
                scapy.IP(src="192.0.2.10", dst="198.51.100.20", id=3901, ttl=64)
                / scapy.TCP(sport=49194, dport=1883, flags="A")
                / scapy.Raw(bytes.fromhex("c000d000"))
            )
        )
        decoded = normalize.decode_bytes(raw, root="l3:ipv4", source_hex=raw.hex())

        self.assertEqual(decoded.layers, ["ipv4", "tcp", "mqtt", "mqtt"])
        self.assertEqual(decoded.fields["mqtt"]["packet_type"], "pingreq")
        self.assertEqual(decoded.fields["mqtt"]["remaining_length"], 0)
        self.assertEqual(decoded.fields["mqtt#2"]["packet_type"], "pingresp")
        self.assertEqual(decoded.fields["mqtt#2"]["remaining_length"], 0)


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
