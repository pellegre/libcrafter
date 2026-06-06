"""Unit coverage for oracle pcap comparison helpers."""

from __future__ import annotations

import unittest

from tools.oracle.engine import cli


class PcapRecordCanonicalizationTest(unittest.TestCase):
    def test_libcrafter_ipv6_extension_layer_names_canonicalize(self) -> None:
        report = {
            "metadata": {
                "records": [
                    {
                        "layers": [
                            "ipv6",
                            "Ipv6HopByHopOptionsHeader",
                            "Ipv6DestinationOptionsHeader",
                            "payload",
                        ],
                        "raw_hex": "00",
                    }
                ]
            }
        }

        records = cli._pcap_records(report)

        self.assertEqual(
            records[0]["layers"],
            [
                "ipv6",
                "ipv6_hop_by_hop",
                "ipv6_destination_options",
                "payload",
            ],
        )
        self.assertEqual(records[0]["raw_hex"], "00")


if __name__ == "__main__":
    unittest.main()
