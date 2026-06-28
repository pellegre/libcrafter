"""Unit coverage for Scapy-stage SSDP Raw payload normalization."""

from __future__ import annotations

import types
import unittest

from tools.oracle.engine.backends.scapy.protocols import SCAPY_REGISTRY
from tools.oracle.engine.backends.scapy.protocols import ssdp as ssdp_scapy


_StubNoPayload = type("NoPayload", (), {})
_StubRaw = type("Raw", (types.SimpleNamespace,), {})
_StubUdp = type("UDP", (types.SimpleNamespace,), {})


def _udp_packet(payload: bytes, *, sport: int = 1900, dport: int = 1900) -> object:
    return _StubUdp(
        sport=sport,
        dport=dport,
        payload=_StubRaw(load=payload, payload=_StubNoPayload()),
    )


class SsdpScapyBackendRegistrationTest(unittest.TestCase):
    def test_ssdp_registers_as_raw_payload_backend(self) -> None:
        plugin = SCAPY_REGISTRY.require("ssdp")

        self.assertEqual(plugin.scapy_class, "Raw")
        self.assertIn("payload", plugin.supported_fields)
        self.assertIn("headers", plugin.supported_fields)
        self.assertIsNotNone(plugin.normalize)


class SsdpBackendToLibcrafterNormalizationTest(unittest.TestCase):
    def test_materializer_serializes_search_datagram_bytes(self) -> None:
        fields = {
            "ssdp": {
                "message_kind": "m_search",
                "headers": [
                    {"name": "HOST", "value": "239.255.255.250:1900"},
                    {"name": "MAN", "value": '"ssdp:discover"'},
                    {"name": "MX", "value": "1"},
                    {"name": "ST", "value": "ssdp:all"},
                ],
            }
        }

        payload = ssdp_scapy._ssdp_message_bytes(fields)

        self.assertEqual(
            payload,
            (
                b"M-SEARCH * HTTP/1.1\r\n"
                b"HOST: 239.255.255.250:1900\r\n"
                b"MAN: \"ssdp:discover\"\r\n"
                b"MX: 1\r\n"
                b"ST: ssdp:all\r\n"
                b"\r\n"
            ),
        )

    def test_materializer_preserves_wire_values_empty_headers_and_body(self) -> None:
        fields = {
            "ssdp": {
                "message_kind": "response",
                "headers": [
                    {"name": "EXT", "value": ""},
                    {"name": "X-EMPTY", "value": ""},
                    {
                        "name": "X-OWS",
                        "value": "trimmed value",
                        "wire_value": "  trimmed value\t",
                    },
                ],
                "body": {"hex": "626f64792d6279746573"},
            }
        }

        payload = ssdp_scapy._ssdp_message_bytes(fields)

        self.assertEqual(
            payload,
            (
                b"HTTP/1.1 200 OK\r\n"
                b"EXT:\r\n"
                b"X-EMPTY:\r\n"
                b"X-OWS:  trimmed value\t\r\n"
                b"\r\n"
                b"body-bytes"
            ),
        )


class SsdpLibcrafterToBackendNormalizationTest(unittest.TestCase):
    def test_parser_normalizes_response_headers_body_and_duplicates(self) -> None:
        raw = (
            b"HTTP/1.1 200 OK\r\n"
            b"EXT:\r\n"
            b"ST: upnp:rootdevice\r\n"
            b"USN: uuid:device-001::upnp:rootdevice\r\n"
            b"USN: uuid:device-001\r\n"
            b"01-NLS: 1\r\n"
            b"X-OWS:  trimmed value\t\r\n"
            b"\r\n"
            b"body-bytes"
        )

        normalized = ssdp_scapy.ssdp_fields_from_bytes(raw)

        self.assertIsNotNone(normalized)
        assert normalized is not None
        self.assertEqual(normalized["message_kind"], "response")
        self.assertEqual(normalized["status_code"], 200)
        self.assertEqual(normalized["status_code_status"], "source_backed")
        self.assertEqual(normalized["body"], {"hex": "626f64792d6279746573"})
        self.assertEqual(normalized["body_length"], 10)

        headers = normalized["headers"]
        self.assertIsInstance(headers, list)
        self.assertEqual(headers[0]["canonical_name"], "EXT")
        self.assertEqual(headers[0]["value"], "")
        self.assertEqual(headers[0]["wire_value"], "")
        self.assertEqual(headers[2]["canonical_name"], "USN")
        self.assertEqual(headers[2]["duplicate_index"], 0)
        self.assertEqual(headers[3]["canonical_name"], "USN")
        self.assertEqual(headers[3]["duplicate_index"], 1)
        self.assertEqual(headers[4]["canonical_name"], "NLS")
        self.assertEqual(headers[4]["name_kind"], "nls_prefixed")
        self.assertEqual(headers[4]["nls_namespace"], "01")
        self.assertEqual(headers[5]["name_kind"], "unknown")
        self.assertEqual(headers[5]["value"], "trimmed value")
        self.assertEqual(headers[5]["wire_value"], "  trimmed value\t")

    def test_udp_1900_raw_payload_is_canonicalized_to_ssdp_layer(self) -> None:
        raw = (
            b"M-SEARCH * HTTP/1.1\r\n"
            b"HOST: 239.255.255.250:1900\r\n"
            b"MAN: \"ssdp:discover\"\r\n"
            b"MX: 1\r\n"
            b"ST: ssdp:all\r\n"
            b"\r\n"
        )
        packet = _udp_packet(raw, sport=49152, dport=1900)
        layers = ["ipv4", "udp", "payload"]
        fields = {
            "ipv4": {},
            "udp": {"src_port": 49152, "dst_port": 1900},
            "payload": {"hex": raw.hex(), "length": len(raw)},
        }

        ssdp_scapy.canonicalize_ssdp_payload(packet, layers, fields)

        self.assertEqual(layers, ["ipv4", "udp", "ssdp"])
        self.assertNotIn("payload", fields)
        self.assertEqual(fields["ssdp"]["message_kind"], "m_search")
        self.assertEqual(fields["ssdp"]["method_status"], "source_backed")

    def test_unrelated_udp_1900_payload_remains_raw(self) -> None:
        raw = b"not an SSDP message\r\nwithout the required shape"
        packet = _udp_packet(raw)
        layers = ["ipv4", "udp", "payload"]
        fields = {
            "ipv4": {},
            "udp": {"src_port": 1900, "dst_port": 1900},
            "payload": {"hex": raw.hex(), "length": len(raw)},
        }

        ssdp_scapy.canonicalize_ssdp_payload(packet, layers, fields)

        self.assertEqual(layers, ["ipv4", "udp", "payload"])
        self.assertEqual(fields["payload"], {"hex": raw.hex(), "length": len(raw)})

        plugin = SCAPY_REGISTRY.require("ssdp")
        assert plugin.normalize is not None
        self.assertEqual(
            plugin.normalize({"hex": raw.hex()}),
            {"payload": {"hex": raw.hex()}, "payload_length": len(raw)},
        )


if __name__ == "__main__":
    unittest.main()
