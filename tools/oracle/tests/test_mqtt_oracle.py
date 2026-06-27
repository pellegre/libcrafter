"""Unit coverage for the MQTT oracle path: specs and Scapy backend checks.

These tests keep the standard oracle Python suite deterministic and offline:

* the MQTT layer and feature specs load without importing Scapy;
* the layer declares the expected MQTT 3.1.1 field surface and parent/child
  relationships;
* the IPv4 and IPv6 MQTT stacks place MQTT under TCP; and
* when Scapy is available, CONNECT and PUBLISH plans materialize to the strict
  MQTT golden bytes declared by the feature specs and normalize back to the
  expected MQTT fields.
"""

from __future__ import annotations

import unittest
from collections.abc import Mapping

from tools.oracle.engine.model import PacketPlan
from tools.oracle.engine.spec_loader import (
    FeatureSpec,
    LayerSpec,
    StackSpec,
    load_oracle_specs,
)


_MQTT_STACK = ["ipv4", "tcp", "mqtt"]
_SEED = 3901
_MQTT_MESSAGE_OFFSET = 40


def _require_scapy_backend():
    """Import the Scapy MQTT backend or skip when unavailable."""

    try:
        from tools.oracle.engine.backends.scapy import normalize, packets
    except Exception as exc:  # pragma: no cover - exercised only without Scapy.
        raise unittest.SkipTest(f"Scapy backend unavailable: {exc}")

    try:
        from tools.oracle.engine.backends.scapy.bootstrap import import_scapy

        import_scapy()
    except Exception as exc:  # pragma: no cover - exercised only without Scapy.
        raise unittest.SkipTest(f"Scapy is not importable: {exc}")

    return packets, normalize


def _mqtt_plan(mqtt_fields: Mapping[str, object], *, case: str) -> PacketPlan:
    """Build the canonical IPv4/TCP/MQTT packet plan used by Scapy checks."""

    return PacketPlan(
        stack=list(_MQTT_STACK),
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
            "mqtt": dict(mqtt_fields),
        },
        profile="mqtt-unit",
        seed=_SEED,
        index=0,
        direction="backend_to_libcrafter",
        family="mqtt",
        feature_tags=["baseline", "ipv4", "tcp", "mqtt"],
        case=case,
        strict_bytes=True,
        metadata={
            "root": "l3:ipv4",
            "root_decoder": "l3:ipv4",
            "stack_name": "ipv4_tcp_mqtt_payload",
        },
    )


def _supported_case(feature: FeatureSpec, name: str) -> Mapping[str, object]:
    cases = feature.raw.get("supported_cases", [])
    assert isinstance(cases, list)
    for case in cases:
        if isinstance(case, Mapping) and case.get("name") == name:
            return case
    raise AssertionError(f"feature {feature.name!r} did not declare case {name!r}")


def _case_fields(case: Mapping[str, object]) -> Mapping[str, object]:
    fields = case.get("fields")
    assert isinstance(fields, Mapping)
    mqtt = fields.get("mqtt")
    assert isinstance(mqtt, Mapping)
    return mqtt


def _case_expected(case: Mapping[str, object]) -> Mapping[str, object]:
    expected = case.get("expected")
    assert isinstance(expected, Mapping)
    return expected


class MqttSpecLoadingTest(unittest.TestCase):
    """Backend-neutral MQTT spec checks that always run."""

    def setUp(self) -> None:
        self.specs = load_oracle_specs()

    def test_mqtt_layer_spec_declares_expected_fields_and_cases(self) -> None:
        layer = self.specs.layers.get("mqtt")
        self.assertIsInstance(layer, LayerSpec)
        assert layer is not None

        self.assertEqual(layer.name, "mqtt")
        self.assertIn("tcp", layer.parents)
        self.assertIn("payload", layer.children)
        self.assertIn("mqtt", layer.children)

        field_names = {field.name for field in layer.fields}
        for expected in (
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
        ):
            self.assertIn(expected, field_names)

        for expected_case in (
            "mqtt-connect",
            "mqtt-publish",
            "mqtt-subscribe",
            "mqtt-ping-disconnect",
        ):
            self.assertIn(expected_case, layer.coverage_cases)

        self.assertIn("scapy", layer.backend_support)
        self.assertIn("libcrafter", layer.backend_support)

    def test_mqtt_feature_specs_are_registered(self) -> None:
        for name, expected_cases in (
            (
                "mqtt_connect",
                (
                    "mqtt-connect",
                    "mqtt-connect-will-auth",
                    "mqtt-connack-accepted",
                    "mqtt-connack-server-unavailable",
                ),
            ),
            (
                "mqtt_publish",
                (
                    "mqtt-publish-qos0",
                    "mqtt-publish-qos1",
                    "mqtt-publish-qos2",
                    "mqtt-publish-retain",
                    "mqtt-puback",
                    "mqtt-pubrec",
                    "mqtt-pubrel",
                    "mqtt-pubcomp",
                ),
            ),
            (
                "mqtt_subscribe",
                (
                    "mqtt-subscribe",
                    "mqtt-suback",
                    "mqtt-unsubscribe",
                    "mqtt-unsuback",
                ),
            ),
            (
                "mqtt_ping_disconnect",
                (
                    "mqtt-pingreq",
                    "mqtt-pingresp",
                    "mqtt-disconnect",
                ),
            ),
        ):
            with self.subTest(feature=name):
                feature = self.specs.features.get(name)
                self.assertIsInstance(feature, FeatureSpec)
                assert feature is not None
                self.assertIn("mqtt", feature.layers)
                self.assertIn("tcp", feature.layers)
                for expected_case in expected_cases:
                    self.assertIn(expected_case, feature.coverage_cases)
                self.assertIn("scapy", feature.backend_support)
                self.assertIn("libcrafter", feature.backend_support)

    def test_mqtt_is_parented_under_tcp(self) -> None:
        tcp_children = self.specs.constraints.get("tcp_children")
        self.assertIsNotNone(tcp_children)
        assert tcp_children is not None
        self.assertEqual(tcp_children.parent, "tcp")
        self.assertIn("mqtt", tcp_children.children)

        mqtt_children = self.specs.constraints.get("mqtt_children")
        self.assertIsNotNone(mqtt_children)
        assert mqtt_children is not None
        self.assertEqual(mqtt_children.parent, "mqtt")
        self.assertIn("mqtt", mqtt_children.children)
        self.assertIn("payload", mqtt_children.children)

    def test_mqtt_stacks_are_tcp_rooted(self) -> None:
        for name, root, first_layer in (
            ("ipv4_tcp_mqtt_payload", "l3:ipv4", "ipv4"),
            ("ipv6_tcp_mqtt_payload", "l3:ipv6", "ipv6"),
        ):
            with self.subTest(stack=name):
                stack = self.specs.stacks.get(name)
                self.assertIsInstance(stack, StackSpec)
                assert stack is not None
                self.assertEqual(stack.root, root)
                self.assertEqual(stack.layers[:3], (first_layer, "tcp", "mqtt"))
                self.assertIn("mqtt-connect", stack.coverage_cases)
                self.assertIn("mqtt-publish", stack.coverage_cases)


class MqttScapyBackendAgreementTest(unittest.TestCase):
    """Scapy materialization and normalization agree with MQTT feature specs."""

    def setUp(self) -> None:
        self.specs = load_oracle_specs()

    def _assert_scapy_case_matches_spec(self, feature_name: str, case_name: str) -> None:
        packets, normalize = _require_scapy_backend()

        feature = self.specs.features[feature_name]
        case = _supported_case(feature, case_name)
        expected = _case_expected(case)
        plan = _mqtt_plan(_case_fields(case), case=case_name)

        vector = packets.encode_packet_plan(plan)
        raw = vector.to_bytes()
        self.assertEqual(raw[_MQTT_MESSAGE_OFFSET:].hex(), expected["mqtt_hex"])

        decoded = normalize.decode_vector(vector)
        self.assertEqual(decoded.layers, _MQTT_STACK)
        self.assertEqual(decoded.root, "l3:ipv4")
        self.assertIn("mqtt", decoded.fields)
        mqtt = decoded.fields["mqtt"]
        self.assertIsInstance(mqtt, Mapping)
        assert isinstance(mqtt, Mapping)

        normalized_fields = expected["normalized_fields"]
        self.assertIsInstance(normalized_fields, Mapping)
        assert isinstance(normalized_fields, Mapping)
        for name, value in normalized_fields.items():
            with self.subTest(case=case_name, field=name):
                self.assertEqual(mqtt.get(name), value)

    def test_connect_plan_matches_golden_hex_and_normalized_fields(self) -> None:
        self._assert_scapy_case_matches_spec("mqtt_connect", "mqtt-connect")

    def test_publish_plan_matches_golden_hex_and_normalized_fields(self) -> None:
        self._assert_scapy_case_matches_spec("mqtt_publish", "mqtt-publish-qos1")


if __name__ == "__main__":
    unittest.main()
