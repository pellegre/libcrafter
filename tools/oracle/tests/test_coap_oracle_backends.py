"""Independent-reference backend coverage for CoAP oracle adapters."""

from __future__ import annotations

import unittest

from tools.oracle.engine.backends.scapy import packets
from tools.oracle.engine.backends.scapy.protocols import SCAPY_REGISTRY
from tools.oracle.engine.backends.scapy.protocols import coap as scapy_coap
from tools.oracle.engine.backends.wireshark.protocols import WIRESHARK_REGISTRY
from tools.oracle.engine.backends.wireshark.protocols import coap as wireshark_coap
from tools.oracle.engine.spec_loader import load_oracle_specs


_CORE_GET = bytes.fromhex("41011234aab6737461747573")


def _datagram_fields(**overrides: object) -> dict[str, dict[str, object]]:
    coap: dict[str, object] = {
        "transport": "datagram",
        "version": 1,
        "message_type": "confirmable",
        "code": 1,
        "message_id": 0x1234,
        "token": {"hex": "aa"},
        "options": [],
        "payload_marker": "absent",
        "payload": {"hex": ""},
    }
    coap.update(overrides)
    return {"coap": coap}


def _ipv4_udp(payload: bytes, *, destination_port: int = 5683) -> bytes:
    udp_length = 8 + len(payload)
    total_length = 20 + udp_length
    ipv4 = bytearray(20)
    ipv4[0] = 0x45
    ipv4[2:4] = total_length.to_bytes(2, "big")
    ipv4[8] = 64
    ipv4[9] = 17
    ipv4[12:16] = bytes([192, 0, 2, 10])
    ipv4[16:20] = bytes([198, 51, 100, 20])
    udp = bytearray(8)
    udp[0:2] = (49152).to_bytes(2, "big")
    udp[2:4] = destination_port.to_bytes(2, "big")
    udp[4:6] = udp_length.to_bytes(2, "big")
    return bytes(ipv4 + udp + payload)


class CoapBackendRegistrationTest(unittest.TestCase):
    def test_plugins_are_auto_discovered_with_exact_field_surface(self) -> None:
        scapy = SCAPY_REGISTRY.require("coap")
        wireshark = WIRESHARK_REGISTRY.require("coap")

        self.assertEqual(scapy.scapy_class, "CoAP")
        self.assertEqual(scapy.supported_fields, scapy_coap._SUPPORTED_FIELDS)
        self.assertIn(("CoAP", "coap"), scapy.layer_aliases)
        self.assertEqual(wireshark.layer, "coap")
        self.assertIn("code", wireshark.tshark_aliases)

    def test_spec_records_partial_support_instead_of_fabricated_agreement(self) -> None:
        layer = load_oracle_specs().layers["coap"]

        self.assertEqual(layer.backend_support["scapy"].status, "partial")
        self.assertTrue(layer.backend_support["scapy"].encode)
        self.assertTrue(layer.backend_support["scapy"].decode)
        self.assertEqual(layer.backend_support["wireshark"].status, "partial")
        self.assertTrue(layer.backend_support["wireshark"].decode)

    def test_capability_gaps_are_stable_and_explicit(self) -> None:
        expected = {"reliable_framing", "extended_tokens", "advanced_options", "oscore"}

        self.assertEqual(set(scapy_coap.SCAPY_COAP_CAPABILITIES["gaps"]), expected)
        self.assertEqual(set(wireshark_coap.WIRESHARK_COAP_CAPABILITIES["gaps"]), expected)
        self.assertTrue(wireshark_coap.WIRESHARK_COAP_CAPABILITIES["parser_only"])

    def test_scapy_feature_gate_admits_all_coap_contracts(self) -> None:
        self.assertTrue(
            {
                "coap_blockwise",
                "coap_datagram",
                "coap_extended_token",
                "coap_link_format",
                "coap_malformed",
                "coap_observe",
                "coap_oscore",
                "coap_pcap",
                "coap_reliable",
            }
            <= packets._SUPPORTED_FEATURES
        )


class CoapScapyWireTest(unittest.TestCase):
    def test_core_get_uses_strict_source_backed_bytes(self) -> None:
        fields = _datagram_fields(options=[{"number": 11, "value_hex": "737461747573"}])

        raw = scapy_coap.coap_message_bytes(fields)
        normalized = scapy_coap.coap_fields_from_bytes(raw)

        self.assertEqual(raw, _CORE_GET)
        assert normalized is not None
        self.assertEqual(normalized["version"], 1)
        self.assertEqual(normalized["message_type"], "confirmable")
        self.assertEqual(normalized["code"], 1)
        self.assertEqual(normalized["message_id"], 0x1234)
        self.assertEqual(normalized["token"], {"hex": "aa", "ascii": "�"})
        self.assertEqual(normalized["options"][0]["number"], 11)
        self.assertEqual(normalized["options"][0]["raw_header"], "b6")

    def test_options_payload_normalize_to_backend_neutral_model(self) -> None:
        fields = _datagram_fields(
            code=2,
            token={"hex": "aabb"},
            options=[
                {"number": 11, "value_hex": "737461747573"},
                {"number": 12, "value_hex": ""},
            ],
            payload_marker="present",
            payload={"hex": "000102ff"},
        )

        raw = scapy_coap.coap_message_bytes(fields)
        normalized = scapy_coap.coap_fields_from_bytes(raw)

        self.assertEqual(raw.hex(), "42021234aabbb673746174757310ff000102ff")
        assert normalized is not None
        self.assertEqual([item["number"] for item in normalized["options"]], [11, 12])
        self.assertEqual(normalized["payload_marker"], "present")
        self.assertEqual(normalized["payload"]["hex"], "000102ff")

    def test_unknown_code_and_option_remain_lossless(self) -> None:
        fields = _datagram_fields(
            code=0x1F,
            options=[{"number": 65000, "value_hex": "deadbeef"}],
        )

        raw = scapy_coap.coap_message_bytes(fields)
        normalized = scapy_coap.coap_fields_from_bytes(raw)

        self.assertEqual(raw.hex(), "411f1234aae4fcdbdeadbeef")
        assert normalized is not None
        self.assertEqual(normalized["code"], 0x1F)
        self.assertEqual(normalized["options"][0]["number"], 65000)
        self.assertEqual(normalized["options"][0]["value"]["hex"], "deadbeef")

    def test_extended_token_is_raw_preserved_but_not_native_agreement(self) -> None:
        fields = _datagram_fields(token={"hex": "a5" * 13})

        raw = scapy_coap.coap_message_bytes(fields)
        normalized = scapy_coap.coap_fields_from_bytes(raw)

        self.assertEqual(raw[:5].hex(), "4d01123400")
        assert normalized is not None
        self.assertEqual(normalized["token_length"]["nibble"], 13)
        self.assertEqual(normalized["token_length"]["extension_hex"], "00")
        self.assertEqual(normalized["token_length"]["declared_length"], 13)

    def test_reliable_frame_is_raw_materialized_with_explicit_gap(self) -> None:
        fields = {
            "coap": {
                "transport": "reliable",
                "code": 0xE1,
                "token": {"hex": ""},
                "signaling_options": [{"number": 2, "value_hex": "0480"}],
                "payload_marker": "absent",
                "payload": {"hex": ""},
            }
        }

        self.assertEqual(scapy_coap.coap_message_bytes(fields).hex(), "30e1220480")
        self.assertIn(
            "RFC 8323",
            scapy_coap.SCAPY_COAP_CAPABILITIES["gaps"]["reliable_framing"],
        )

    def test_oscore_stays_opaque(self) -> None:
        fields = _datagram_fields(
            code=2,
            options=[{"number": 9, "value_hex": "09"}],
            payload_marker="present",
            payload={"hex": "d18b3b5563bf"},
        )

        normalized = scapy_coap.coap_fields_from_bytes(
            scapy_coap.coap_message_bytes(fields)
        )

        assert normalized is not None
        self.assertEqual(normalized["options"][0]["number"], 9)
        self.assertEqual(normalized["payload"]["hex"], "d18b3b5563bf")
        self.assertNotIn("plaintext", normalized)

    def test_raw_fallback_and_malformed_inputs_are_excluded(self) -> None:
        malformed = [
            b"",
            b"\x40\x01\x00",
            b"\x4f\x01\x00\x01",
            b"\x4d\x01\x00\x01",
            b"\x41\x01\x00\x01",
            b"\x40\x01\x00\x01\xf0",
            b"\x40\x00\x00\x01\xff",
            b"not-coap",
        ]
        for raw in malformed:
            with self.subTest(raw=raw.hex()):
                self.assertIsNone(scapy_coap.coap_fields_from_bytes(raw))

    def test_verified_native_scapy_core_round_trip_when_available(self) -> None:
        try:
            from scapy.contrib.coap import CoAP  # type: ignore[import-untyped]
            from scapy.all import raw  # type: ignore[import-untyped]
        except ModuleNotFoundError as exc:
            raise unittest.SkipTest("Scapy is unavailable in the bare acceptance interpreter") from exc

        packet = CoAP(_CORE_GET)
        self.assertEqual(raw(packet), _CORE_GET)
        self.assertEqual(packet.ver, 1)
        self.assertEqual(packet.code, 1)
        self.assertEqual(packet.msg_id, 0x1234)


class CoapWiresharkNormalizationTest(unittest.TestCase):
    def test_source_bytes_match_scapy_canonical_model(self) -> None:
        packet = _ipv4_udp(_CORE_GET)

        scapy_model = scapy_coap.coap_fields_from_bytes(_CORE_GET)
        wireshark_model = wireshark_coap._normalize({}, source_hex=packet.hex())

        self.assertEqual(wireshark_model, scapy_model)

    def test_native_tshark_aliases_normalize_without_source_bytes(self) -> None:
        layers = {
            "coap": {
                "coap.version": "1",
                "coap.type": "0",
                "coap.token_len": "1",
                "coap.code": "1",
                "coap.mid": "0x1234",
                "coap.token": "aa",
                "coap.opt.delta": "11",
                "coap.opt.length": "6",
                "coap.opt.value": "73:74:61:74:75:73",
            }
        }

        normalized = wireshark_coap._normalize(layers)

        self.assertEqual(normalized["code"], 1)
        self.assertEqual(normalized["message_id"], 0x1234)
        self.assertEqual(normalized["token"]["hex"], "aa")
        self.assertEqual(normalized["options"][0]["number"], 11)
        self.assertEqual(normalized["options"][0]["value"]["hex"], "737461747573")

    def test_secure_port_source_is_not_typed_as_cleartext_coap(self) -> None:
        packet = _ipv4_udp(_CORE_GET, destination_port=5684)

        self.assertEqual(wireshark_coap._normalize({}, source_hex=packet.hex()), {})

    def test_wireshark_parser_rejects_malformed_without_exposing_plaintext(self) -> None:
        self.assertIsNone(wireshark_coap.coap_fields_from_bytes(b"\x4d\x01\x00\x01"))
        protected = wireshark_coap.coap_fields_from_bytes(
            bytes.fromhex("41021234aa9109ffd18b3b5563bf")
        )
        assert protected is not None
        self.assertEqual(protected["payload"]["hex"], "d18b3b5563bf")
        self.assertNotIn("plaintext", protected)


if __name__ == "__main__":
    unittest.main()
