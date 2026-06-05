"""Focused IPv6 extension-header normalization coverage for oracle decoders."""

from __future__ import annotations

import json
import subprocess
import unittest
from collections.abc import Mapping
from pathlib import Path

from tools.oracle.engine.backends.scapy import normalize as scapy_normalize
from tools.oracle.engine.backends.wireshark import normalize as wireshark_normalize


_REPO_ROOT = Path(__file__).resolve().parents[3]

# IPv6(tc=0xab, nh=Hop-by-Hop) / Hop-by-Hop(Router Alert + Pad1s) /
# Destination Options(Home Address + Pad1s) / atomic Fragment / SRH(No Next).
_RAW_IPV6_EXTENSION_CHAIN_HEX = (
    "6ab1234500400040"
    "20010db8000000000000000000000001"
    "20010db8000000000000000000000002"
    "3c00050200000000"
    "2c02c91020010db800000000000000000000004200000000"
    "2b00000011223344"
    "3b0204000080123420010db8000000000000000000000099"
)


def _libcrafter_decode(raw_hex: str) -> Mapping[str, object]:
    document = {
        "backend": "test",
        "metadata": {
            "requested_count": 1,
            "vectors": [
                {
                    "raw_hex": raw_hex,
                    "root": "l3:ipv6",
                    "decoder": "IPv6",
                    "plan": {"feature_tags": ["ipv6", "normalization"]},
                }
            ],
        },
    }
    process = subprocess.run(
        [
            "cargo",
            "run",
            "--quiet",
            "-p",
            "oracle-adapters",
            "--bin",
            "decode_vectors",
            "--",
            "--input",
            "-",
        ],
        cwd=_REPO_ROOT,
        input=json.dumps(document),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=120,
    )
    if process.returncode != 0:
        raise AssertionError(
            "libcrafter decode bridge failed\n"
            f"stdout:\n{process.stdout}\n"
            f"stderr:\n{process.stderr}"
        )
    report = json.loads(process.stdout)
    return report["metadata"]["decoded"][0]


def _assert_enriched_ipv6_model(testcase: unittest.TestCase, model: Mapping[str, object]) -> None:
    fields = model["fields"]
    testcase.assertIsInstance(fields, Mapping)
    testcase.assertEqual(
        model["layers"],
        [
            "ipv6",
            "ipv6_hop_by_hop",
            "ipv6_destination_options",
            "ipv6_fragment",
            "ipv6_routing",
        ],
    )

    ipv6 = fields["ipv6"]
    testcase.assertEqual(ipv6["traffic_class"], 0xAB)
    testcase.assertEqual(ipv6["dscp"], 0x2A)
    testcase.assertEqual(ipv6["ecn"], 0x03)
    testcase.assertEqual(ipv6["next_header"], 0)

    hop = fields["ipv6_hop_by_hop"]
    testcase.assertEqual(hop["next_header"], 60)
    testcase.assertEqual(hop["header_ext_len"], 0)
    testcase.assertEqual(hop["option_count"], 3)
    testcase.assertEqual(hop["options_raw_hex"], "050200000000")
    testcase.assertEqual(hop["options"][0]["kind"], "router_alert")
    testcase.assertEqual(hop["options"][0]["value"], 0)

    dest = fields["ipv6_destination_options"]
    testcase.assertEqual(dest["next_header"], 44)
    testcase.assertEqual(dest["header_ext_len"], 2)
    testcase.assertEqual(dest["option_count"], 5)
    testcase.assertEqual(dest["options"][0]["kind"], "home_address")
    testcase.assertEqual(dest["options"][0]["address"], "2001:db8::42")

    fragment = fields["ipv6_fragment"]
    testcase.assertEqual(fragment["next_header"], 43)
    testcase.assertEqual(fragment["fragment_offset"], 0)
    testcase.assertEqual(fragment["fragment_offset_bytes"], 0)
    testcase.assertIs(fragment["more_fragments"], False)
    testcase.assertEqual(fragment["fragment_status"], "atomic")

    routing = fields["ipv6_routing"]
    testcase.assertEqual(routing["next_header"], 59)
    testcase.assertEqual(routing["header_ext_len"], 2)
    testcase.assertEqual(routing["type"], 4)
    testcase.assertEqual(routing["classification"], "segment_routing")
    testcase.assertEqual(routing["last_entry"], 0)
    testcase.assertEqual(routing["flags"], 0x80)
    testcase.assertEqual(routing["tag"], 0x1234)
    testcase.assertEqual(routing["addresses"], ["2001:db8::99"])
    testcase.assertEqual(routing["segments"], ["2001:db8::99"])
    testcase.assertEqual(routing["raw_trailing_data"], "")


class Ipv6NormalizationTest(unittest.TestCase):
    def test_scapy_and_libcrafter_normalize_enriched_ipv6_decode_fields(self) -> None:
        raw = bytes.fromhex(_RAW_IPV6_EXTENSION_CHAIN_HEX)
        scapy_model = scapy_normalize.decode_bytes(
            raw,
            root="l3:ipv6",
            source_hex=_RAW_IPV6_EXTENSION_CHAIN_HEX,
            feature_tags=["ipv6", "normalization"],
        ).to_dict()
        libcrafter_model = _libcrafter_decode(_RAW_IPV6_EXTENSION_CHAIN_HEX)

        _assert_enriched_ipv6_model(self, scapy_model)
        _assert_enriched_ipv6_model(self, libcrafter_model)

    def test_wireshark_normalizes_synthetic_ipv6_extension_fields(self) -> None:
        packet = {
            "_source": {
                "layers": {
                    "frame": {
                        "frame.protocols": (
                            "raw:ipv6:ipv6.hopopts:ipv6.dstopts:"
                            "ipv6.fragment:ipv6.routing"
                        )
                    },
                    "ipv6": {
                        "ipv6.version": "6",
                        "ipv6.tclass": "0xab",
                        "ipv6.flow": "0x12345",
                        "ipv6.plen": "64",
                        "ipv6.nxt": "0",
                        "ipv6.hlim": "64",
                        "ipv6.src": "2001:db8::1",
                        "ipv6.dst": "2001:db8::2",
                    },
                    "ipv6.hopopts": {
                        "ipv6.hopopts.nxt": "60",
                        "ipv6.hopopts.len": "0",
                        "ipv6.hopopts.options_raw": "05:02:00:00:00:00",
                    },
                    "ipv6.dstopts": {
                        "ipv6.dstopts.nxt": "44",
                        "ipv6.dstopts.len": "2",
                        "ipv6.dstopts.options_raw": (
                            "c9:10:20:01:0d:b8:00:00:00:00:00:00:"
                            "00:00:00:00:00:42:00:00:00:00"
                        ),
                    },
                    "ipv6.fragment": {
                        "ipv6.fragment.nxt": "43",
                        "ipv6.fragment.reserved": "0",
                        "ipv6.fragment.offset": "0",
                        "ipv6.fragment.more": "0",
                        "ipv6.fragment.id": "0x11223344",
                    },
                    "ipv6.routing": {
                        "ipv6.routing.nxt": "59",
                        "ipv6.routing.len": "2",
                        "ipv6.routing.type": "4",
                        "ipv6.routing.segleft": "0",
                        "ipv6.routing.last_entry": "0",
                        "ipv6.routing.flags": "0x80",
                        "ipv6.routing.tag": "0x1234",
                        "ipv6.routing.address": ["2001:db8::99"],
                        "ipv6.routing.raw_trailing_data": "",
                    },
                }
            }
        }
        model = wireshark_normalize.normalize_packet_json(
            packet,
            root="l3:ipv6",
            source_hex=_RAW_IPV6_EXTENSION_CHAIN_HEX,
            feature_tags=["ipv6", "normalization"],
        ).to_dict()

        _assert_enriched_ipv6_model(self, model)


if __name__ == "__main__":
    unittest.main()
