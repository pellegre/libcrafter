"""Unit coverage for Scapy backend IEEE 802.15.4 / Zigbee support."""

from __future__ import annotations

import unittest

from tools.oracle.engine.backends.scapy import normalize


def _scapy_available() -> bool:
    try:
        import scapy  # type: ignore[import-untyped]  # noqa: F401
        import scapy.all  # type: ignore[import-untyped]  # noqa: F401
        import scapy.layers.dot15d4  # type: ignore[import-untyped]  # noqa: F401
        import scapy.layers.zigbee  # type: ignore[import-untyped]  # noqa: F401
    except ModuleNotFoundError:
        return False
    return True


@unittest.skipUnless(_scapy_available(), "scapy is not available")
class ScapyDot15d4ZigbeeSupportTest(unittest.TestCase):
    def test_bootstrap_exposes_dot15d4_and_zigbee_layers(self) -> None:
        from tools.oracle.engine.backends.scapy.bootstrap import import_scapy

        scapy = import_scapy()

        # The IEEE 802.15.4 / Zigbee layer modules are loaded and the upper
        # protocol is pinned to Zigbee so MAC payloads dispatch to ZigbeeNWK.
        self.assertIn("dot15d4", scapy)
        self.assertIn("zigbee", scapy)
        dot15d4 = scapy["dot15d4"]
        zigbee = scapy["zigbee"]
        self.assertTrue(hasattr(dot15d4, "Dot15d4"))
        self.assertTrue(hasattr(dot15d4, "Dot15d4FCS"))
        self.assertTrue(hasattr(dot15d4, "Dot15d4Data"))
        self.assertTrue(hasattr(zigbee, "ZigbeeNWK"))
        self.assertTrue(hasattr(zigbee, "ZigbeeAppDataPayload"))
        conf = scapy["all"].conf
        self.assertEqual(conf.dot15d4_protocol, "zigbee")

    def test_scapy_builds_and_parses_dot15d4_zigbee_frame(self) -> None:
        from tools.oracle.engine.backends.scapy.bootstrap import import_scapy

        scapy = import_scapy()
        dot15d4 = scapy["dot15d4"]
        zigbee = scapy["zigbee"]

        # The focused check the step calls for: the scapy backend can build and
        # parse a Dot15d4()/ZigbeeNWK() frame.
        frame = dot15d4.Dot15d4() / zigbee.ZigbeeNWK()
        raw = bytes(frame)
        self.assertGreater(len(raw), 0)
        parsed = dot15d4.Dot15d4(raw)
        self.assertEqual(parsed.__class__.__name__, "Dot15d4")
        self.assertEqual(bytes(parsed), raw)

    def test_normalize_resolves_dot15d4_zigbee_layer_names(self) -> None:
        from tools.oracle.engine.backends.scapy.bootstrap import import_scapy

        scapy = import_scapy()
        dot15d4 = scapy["dot15d4"]
        zigbee = scapy["zigbee"]

        # A data frame so the MAC payload dispatches through the full
        # Dot15d4 -> ZigbeeNWK -> ZigbeeAppDataPayload Zigbee stack.
        frame = (
            dot15d4.Dot15d4(fcf_frametype="Data")
            / dot15d4.Dot15d4Data()
            / zigbee.ZigbeeNWK()
            / zigbee.ZigbeeAppDataPayload()
        )
        raw = bytes(frame)
        parsed = dot15d4.Dot15d4(raw)

        model = normalize.normalize_packet(
            parsed, root="link:ieee802154", source_hex=raw.hex()
        )

        self.assertEqual(model.root, "link:ieee802154")
        self.assertIn("dot15d4", model.layers)
        self.assertIn("zigbee_nwk", model.layers)
        self.assertIn("zigbee_aps", model.layers)


if __name__ == "__main__":
    unittest.main()
