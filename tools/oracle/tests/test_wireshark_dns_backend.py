"""Parser-only Wireshark/tshark coverage for DNS and mDNS packets."""

from __future__ import annotations

import shutil
import unittest
from collections.abc import Mapping

from tools.oracle.engine.backends.wireshark import normalize as wireshark


def _synthetic_mdns_packet(*, protocol: str = "dns") -> dict:
    layer_name = protocol
    prefix = "mdns" if protocol == "mdns" else "dns"
    return {
        "_source": {
            "layers": {
                "frame": {"frame.protocols": f"eth:ip:udp:{protocol}"},
                "eth": {
                    "eth.src": "02:00:00:00:00:01",
                    "eth.dst": "01:00:5e:00:00:fb",
                    "eth.type": "0x0800",
                },
                "ip": {
                    "ip.version": "4",
                    "ip.hdr_len": "20",
                    "ip.src": "192.0.2.10",
                    "ip.dst": "224.0.0.251",
                    "ip.proto": "17",
                    "ip.ttl": "255",
                    "ip.len": "120",
                    "ip.id": "0x0001",
                    "ip.checksum": "0x0000",
                    "ip.flags": "0x00",
                },
                "udp": {
                    "udp.srcport": "5353",
                    "udp.dstport": "5353",
                    "udp.length": "100",
                    "udp.checksum": "0x0000",
                },
                layer_name: {
                    f"{prefix}.id": "0x0000",
                    f"{prefix}.flags.response": "0",
                    f"{prefix}.flags.opcode": "0",
                    f"{prefix}.flags.authoritative": "0",
                    f"{prefix}.flags.rcode": "0",
                    f"{prefix}.count.queries": "1",
                    f"{prefix}.count.answers": "1",
                    f"{prefix}.count.auth_rr": "0",
                    f"{prefix}.count.add_rr": "0",
                    f"{prefix}.qry.name": "_ipp._tcp.local.",
                    f"{prefix}.qry.type": "12",
                    f"{prefix}.qry.class": "0x00008001",
                    f"{prefix}.resp.name": "Office\\032Printer._ipp._tcp.local.",
                    f"{prefix}.resp.type": "16",
                    f"{prefix}.resp.class": "0x00008001",
                    f"{prefix}.resp.ttl": "120",
                    f"{prefix}.txt": "txtvers=1",
                },
            }
        }
    }


def _synthetic_unicast_dns_packet() -> dict:
    packet = _synthetic_mdns_packet(protocol="dns")
    layers = packet["_source"]["layers"]
    layers["frame"]["frame.protocols"] = "eth:ip:udp:dns"
    layers["udp"]["udp.srcport"] = "53"
    layers["udp"]["udp.dstport"] = "53530"
    return packet


def _assert_mdns_model(testcase: unittest.TestCase, model) -> None:
    testcase.assertEqual(model.root, "link:ethernet")
    testcase.assertIn("udp", model.layers)
    testcase.assertIn("mdns", model.layers)
    testcase.assertEqual(
        [layer for layer in model.layers if layer in {"udp", "mdns"}],
        ["udp", "mdns"],
    )

    udp = model.fields.get("udp")
    testcase.assertIsInstance(udp, Mapping)
    testcase.assertEqual(udp.get("src_port"), 5353)
    testcase.assertEqual(udp.get("dst_port"), 5353)

    mdns = model.fields.get("mdns")
    testcase.assertIsInstance(mdns, Mapping)
    transport = mdns.get("transport")
    testcase.assertIsInstance(transport, Mapping)
    testcase.assertEqual(transport.get("service_port"), 5353)
    testcase.assertFalse(transport.get("unicast_reply"))

    questions = mdns.get("questions")
    testcase.assertIsInstance(questions, list)
    testcase.assertEqual(questions[0]["name"], "_ipp._tcp.local.")
    testcase.assertEqual(questions[0]["record_type"], 12)
    testcase.assertEqual(questions[0]["raw_question_class"], 0x8001)
    testcase.assertEqual(questions[0]["base_question_class"], 1)
    testcase.assertTrue(questions[0]["unicast_response_preferred"])

    answers = mdns.get("answers")
    testcase.assertIsInstance(answers, list)
    testcase.assertEqual(answers[0]["name"], "Office\\032Printer._ipp._tcp.local.")
    testcase.assertEqual(answers[0]["record_type"], 16)
    testcase.assertEqual(answers[0]["raw_class"], 0x8001)
    testcase.assertEqual(answers[0]["base_class"], 1)
    testcase.assertTrue(answers[0]["cache_flush"])

    dns_sd = mdns.get("dns_sd")
    testcase.assertIsInstance(dns_sd, Mapping)
    testcase.assertIn("_ipp._tcp.local.", dns_sd.get("service_names"))
    testcase.assertIn(
        "Office\\032Printer._ipp._tcp.local.",
        dns_sd.get("instance_names"),
    )


class WiresharkDnsMdnsNormalizationTest(unittest.TestCase):
    """Pure-Python normalizer coverage; no ``tshark`` executable is required."""

    def test_promotes_dns_over_udp_5353_to_mdns(self) -> None:
        model = wireshark.normalize_packet_json(
            _synthetic_mdns_packet(protocol="dns"),
            root="link:ethernet",
            source_hex=None,
        )

        _assert_mdns_model(self, model)

    def test_accepts_native_mdns_protocol_name(self) -> None:
        model = wireshark.normalize_packet_json(
            _synthetic_mdns_packet(protocol="mdns"),
            root="link:ethernet",
            source_hex=None,
        )

        _assert_mdns_model(self, model)

    def test_ordinary_dns_is_not_promoted_to_mdns(self) -> None:
        model = wireshark.normalize_packet_json(
            _synthetic_unicast_dns_packet(),
            root="link:ethernet",
            source_hex=None,
        )

        self.assertNotIn("mdns", model.layers)
        self.assertIn("udp", model.layers)

    def test_mdns_layer_is_recognized_as_a_layer(self) -> None:
        self.assertEqual(wireshark._PROTOCOL_LAYER_ALIASES.get("mdns"), "mdns")


@unittest.skipUnless(
    shutil.which("tshark"),
    "tshark not installed; skipping parser-only mDNS pcap decode",
)
class WiresharkMdnsTsharkAvailabilityTest(unittest.TestCase):
    def test_tshark_available_for_optional_mdns_decode(self) -> None:
        self.assertIsNotNone(shutil.which("tshark"))


if __name__ == "__main__":
    unittest.main()
