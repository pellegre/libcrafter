"""Unit coverage for Scapy backend MQTT contrib support."""

from __future__ import annotations

import unittest


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


if __name__ == "__main__":
    unittest.main()
