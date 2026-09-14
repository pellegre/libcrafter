"""IEEE802.11ax-2021 Figure9-64a Trigger MAC header oracle checks."""
import struct
import unittest

from tools.oracle.engine.backends.scapy.protocols.wifi import _dot11_bytes
from tools.oracle.engine.protocols.wifi import _dot11_frame_control_for_case
from tools.oracle.engine.backends.wifi.trigger import basic_trigger_body, eht_basic_trigger_body


class TriggerHeaderTest(unittest.TestCase):
    def test_basic_body_literal_layout(self):
        # Common: UL Length=1, GI/LTF=1, SIG-A2 Reserved=511.
        # User: AID=1, all other bits zero; Basic dependent byte; padding.
        self.assertEqual(basic_trigger_body(b""), bytes.fromhex(
            "100010000000c07f 0100000000 00 ffff"))

    def test_eht_basic_body_literal_layout(self):
        self.assertEqual(
            eht_basic_trigger_body(),
            bytes.fromhex(
                "d01212a83a64087f d70786ff1f 5a 2540700144 a5 ff0f"
            ),
        )

    def test_trigger_case_selects_control_subtype_two(self):
        self.assertEqual(
            _dot11_frame_control_for_case("dot11-trigger-header", ["dot11", "payload"]),
            0x24,
        )

    def test_reference_serializes_receiver_and_transmitter(self):
        receiver = bytes.fromhex("00005e005301")
        transmitter = bytes.fromhex("00005e005302")
        for duration in [0, 1, 0x1234, 0xffff]:
            fields = {"dot11": {"frame_control": 0x24, "duration_id": duration,
                                "addr1": "00:00:5e:00:53:01",
                                "addr2": "00:00:5e:00:53:02"}}
            actual = _dot11_bytes(fields)
            self.assertEqual(actual, struct.pack("<HH6s6s", 0x24, duration, receiver, transmitter))
            self.assertEqual(len(actual), 16)
            del fields["dot11"]["frame_control"]
            fields["dot11"].update(frame_type="control", subtype="trigger")
            self.assertEqual(_dot11_bytes(fields), actual)


if __name__ == "__main__":
    unittest.main()
