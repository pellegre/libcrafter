"""Unit coverage for oracle pcap comparison helpers."""

from __future__ import annotations

from pathlib import Path
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

    def test_dot11_rsn_information_element_uses_dot11_layer_contract(self) -> None:
        report = {
            "metadata": {
                "records": [
                    {
                        "layers": ["radiotap", "dot11", "rsn"],
                        "raw_hex": "010203",
                    }
                ]
            }
        }

        records = cli._pcap_records(report)

        self.assertEqual(records[0]["layers"], ["radiotap", "dot11"])
        self.assertEqual(records[0]["raw_hex"], "010203")


class PcapOutputDirTest(unittest.TestCase):
    def test_default_output_uses_mode_subdir(self) -> None:
        self.assertEqual(
            cli._pcap_output_dir(str(cli.DEFAULT_OUTPUT_ROOT)),
            cli.REPO_ROOT / cli.DEFAULT_OUTPUT_ROOT / "pcap",
        )

    def test_explicit_output_is_exact_directory(self) -> None:
        requested = Path("target/oracle/ip-fragment-pcap")

        self.assertEqual(
            cli._pcap_output_dir(str(requested)),
            cli.REPO_ROOT / requested,
        )


class LiveOutputDirTest(unittest.TestCase):
    def test_default_output_uses_mode_subdir(self) -> None:
        self.assertEqual(
            cli._live_output_dir(str(cli.DEFAULT_OUTPUT_ROOT)),
            cli.REPO_ROOT / cli.DEFAULT_OUTPUT_ROOT / "live",
        )

    def test_explicit_output_is_exact_directory(self) -> None:
        requested = Path("target/oracle/ip-fragment-live")

        self.assertEqual(
            cli._live_output_dir(str(requested)),
            cli.REPO_ROOT / requested,
        )


if __name__ == "__main__":
    unittest.main()
