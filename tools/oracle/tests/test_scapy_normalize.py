"""Normalized ICMPv4 decode coverage for the Scapy backend.

These tests pin the backend-neutral oracle field names the Scapy normalizer
must report for every supported ICMPv4 shape in the live coverage matrix. The
normalized model has to match what the libcrafter live endpoint and decode
bridge report so live byte/decode comparison can use a single shared model:

  * type / code / checksum / rest_of_header on every ICMPv4 message;
  * identifier / sequence only on the RFC 792/950 query and RFC 8335 extended
    echo types, mirroring libcrafter's is_query_v4 / is_extended_echo_v4 rules;
  * the RFC 4884 length byte on the error types (3/11/12);
  * a single flat trailing ``payload`` layer for the quoted IPv4 datagram,
    timestamp values, address-mask value, router-discovery list, and RFC
    4884/4950 extension blob (libcrafter keeps everything after the four-byte
    rest-of-header in one payload).

The Scapy-native typed fields (gw, ptr, nexthopmtu, addr_mask, ts_ori/rx/tx,
id/seq) must be collapsed into the flat oracle names above; their native names
must never leak into the normalized model.
"""

from __future__ import annotations

import unittest

from tools.oracle.engine.backends.scapy import normalize
from tools.oracle.engine.backends.scapy.bootstrap import import_scapy


def _scapy():
    return import_scapy()["all"]


def _base_ip():
    scapy = _scapy()
    return scapy.IP(src="192.0.2.1", dst="198.51.100.1", id=4242, ttl=64)


def _normalize(packet):
    """Re-encode a Scapy packet and decode it through the oracle normalizer."""

    scapy = _scapy()
    raw = bytes(scapy.raw(packet))
    return normalize.decode_bytes(raw, root="l2:ipv4", source_hex=raw.hex())


class ScapyIpv4FlagNormalizeTest(unittest.TestCase):
    def test_ipv4_reserved_flag_uses_libcrafter_name(self) -> None:
        self.assertEqual(
            normalize._normalize_field_value("ipv4", "flags", "evil"),
            "reserved",
        )

    def test_ipv4_reserved_flag_uses_libcrafter_name_inside_combinations(self) -> None:
        self.assertEqual(
            normalize._normalize_field_value("ipv4", "flags", "MF+DF+evil"),
            "mf|df|reserved",
        )


# Native Scapy ICMP rest-of-header field names that must never survive
# normalization; libcrafter folds them into rest_of_header / payload.
_NATIVE_ICMP_FIELD_NAMES = (
    "gw",
    "ptr",
    "nexthopmtu",
    "addr_mask",
    "ts_ori",
    "ts_rx",
    "ts_tx",
    "unused",
    "reserved",
    "id",
    "seq",
)


class IcmpNormalizedModelTest(unittest.TestCase):
    """The normalized ICMPv4 model uses stable oracle names on a flat stack."""

    def _icmp(self, packet) -> dict:
        decoded = _normalize(packet)
        self.assertEqual(decoded.root, "l3:ipv4")
        self.assertEqual(decoded.layers[0], "ipv4")
        self.assertIn("icmp", decoded.layers)
        icmp = decoded.fields["icmp"]
        # Native typed rest-of-header names must be collapsed away.
        for native in _NATIVE_ICMP_FIELD_NAMES:
            self.assertNotIn(native, icmp, f"native field {native!r} leaked")
        # Every ICMPv4 header carries the flat oracle base fields.
        self.assertIn("type", icmp)
        self.assertIn("code", icmp)
        self.assertIn("checksum", icmp)
        self.assertIn("rest_of_header", icmp)
        self.assertIsInstance(icmp["type"], int)
        self.assertIsInstance(icmp["rest_of_header"], str)
        self.assertEqual(len(icmp["rest_of_header"]), 8)
        return decoded

    # --- query types: identifier / sequence -------------------------------

    def test_echo_request_exposes_identifier_sequence(self) -> None:
        scapy = _scapy()
        decoded = self._icmp(_base_ip() / scapy.ICMP(type=8, id=0x1234, seq=0x5678) / scapy.Raw(b"abcd"))
        icmp = decoded.fields["icmp"]
        self.assertEqual(icmp["type"], 8)
        self.assertEqual(icmp["identifier"], 0x1234)
        self.assertEqual(icmp["sequence"], 0x5678)
        self.assertEqual(icmp["rest_of_header"], "12345678")
        self.assertEqual(decoded.fields["payload"]["hex"], "61626364")

    def test_echo_reply_exposes_identifier_sequence(self) -> None:
        scapy = _scapy()
        decoded = self._icmp(_base_ip() / scapy.ICMP(type=0, id=0x00ff, seq=0x0001))
        icmp = decoded.fields["icmp"]
        self.assertEqual(icmp["type"], 0)
        self.assertEqual(icmp["identifier"], 0x00FF)
        self.assertEqual(icmp["sequence"], 1)

    def test_information_request_exposes_identifier_sequence(self) -> None:
        scapy = _scapy()
        decoded = self._icmp(_base_ip() / scapy.ICMP(type=15, id=7, seq=9))
        icmp = decoded.fields["icmp"]
        self.assertEqual(icmp["type"], 15)
        self.assertEqual(icmp["identifier"], 7)
        self.assertEqual(icmp["sequence"], 9)
        self.assertEqual(icmp["rest_of_header"], "00070009")
        # An information request has no body after the rest-of-header.
        self.assertNotIn("payload", decoded.fields)

    # --- error types: rest_of_header + RFC 4884 length byte ----------------

    def test_destination_unreachable_quoted_ipv4_becomes_flat_payload(self) -> None:
        scapy = _scapy()
        quoted = scapy.IP(src="203.0.113.1", dst="198.51.100.20") / scapy.Raw(b"abcd")
        decoded = self._icmp(_base_ip() / scapy.ICMP(type=3, code=1) / quoted)
        icmp = decoded.fields["icmp"]
        self.assertEqual(icmp["type"], 3)
        self.assertEqual(icmp["code"], 1)
        self.assertEqual(icmp["rest_of_header"], "00000000")
        # The error types carry the RFC 4884 length byte from rest byte 1.
        self.assertIn("length", icmp)
        self.assertEqual(icmp["length"], 0)
        # Scapy's IPerror sub-dissection is collapsed into one flat payload that
        # starts with the quoted IPv4 version nibble.
        self.assertEqual(decoded.layers.count("icmp"), 1)
        self.assertNotIn("ipv4#2", decoded.fields)
        payload_hex = decoded.fields["payload"]["hex"]
        self.assertTrue(payload_hex.startswith("45"))
        self.assertTrue(payload_hex.endswith("61626364"))

    def test_frag_needed_next_hop_mtu_in_rest_of_header(self) -> None:
        scapy = _scapy()
        decoded = self._icmp(_base_ip() / scapy.ICMP(type=3, code=4, nexthopmtu=1280))
        icmp = decoded.fields["icmp"]
        # next-hop MTU lives in rest-of-header bytes 2-3 (0x0500 == 1280).
        self.assertEqual(icmp["rest_of_header"], "00000500")
        self.assertIn("length", icmp)

    def test_time_exceeded_rest_of_header(self) -> None:
        scapy = _scapy()
        decoded = self._icmp(_base_ip() / scapy.ICMP(type=11, code=0))
        icmp = decoded.fields["icmp"]
        self.assertEqual(icmp["type"], 11)
        self.assertEqual(icmp["rest_of_header"], "00000000")
        self.assertIn("length", icmp)

    def test_parameter_problem_pointer_in_rest_of_header(self) -> None:
        scapy = _scapy()
        decoded = self._icmp(_base_ip() / scapy.ICMP(type=12, code=0, ptr=20))
        icmp = decoded.fields["icmp"]
        self.assertEqual(icmp["type"], 12)
        self.assertEqual(icmp["rest_of_header"], "14000000")
        self.assertIn("length", icmp)

    def test_redirect_gateway_in_rest_of_header(self) -> None:
        scapy = _scapy()
        decoded = self._icmp(_base_ip() / scapy.ICMP(type=5, code=1, gw="192.0.2.254"))
        icmp = decoded.fields["icmp"]
        self.assertEqual(icmp["type"], 5)
        self.assertEqual(icmp["rest_of_header"], "c00002fe")
        # Redirect is not an RFC 4884 length-bearing type.
        self.assertNotIn("length", icmp)

    # --- timestamp / address mask: values in the flat payload --------------

    def test_timestamp_values_move_into_flat_payload(self) -> None:
        scapy = _scapy()
        decoded = self._icmp(
            _base_ip()
            / scapy.ICMP(
                type=13,
                id=0x1111,
                seq=0x2222,
                ts_ori=0x01020304,
                ts_rx=0x05060708,
                ts_tx=0x090A0B0C,
            )
        )
        icmp = decoded.fields["icmp"]
        self.assertEqual(icmp["type"], 13)
        self.assertEqual(icmp["identifier"], 0x1111)
        self.assertEqual(icmp["sequence"], 0x2222)
        self.assertEqual(icmp["rest_of_header"], "11112222")
        # The 12 timestamp bytes follow the rest-of-header in the flat payload.
        self.assertEqual(decoded.fields["payload"]["hex"], "0102030405060708090a0b0c")

    def test_address_mask_value_moves_into_flat_payload(self) -> None:
        scapy = _scapy()
        decoded = self._icmp(
            _base_ip() / scapy.ICMP(type=18, id=7, seq=9, addr_mask="255.255.255.0")
        )
        icmp = decoded.fields["icmp"]
        self.assertEqual(icmp["type"], 18)
        self.assertEqual(icmp["identifier"], 7)
        self.assertEqual(icmp["sequence"], 9)
        self.assertEqual(icmp["rest_of_header"], "00070009")
        self.assertEqual(decoded.fields["payload"]["hex"], "ffffff00")

    # --- router discovery: address list in the flat payload ----------------

    def test_router_advertisement_addresses_in_flat_payload(self) -> None:
        scapy = _scapy()
        addresses = bytes.fromhex("c000020100000000c000020200000000")
        decoded = self._icmp(_base_ip() / scapy.ICMP(type=9, code=0) / scapy.Raw(addresses))
        icmp = decoded.fields["icmp"]
        self.assertEqual(icmp["type"], 9)
        # Router advertisement is not a query type and has no length byte.
        self.assertNotIn("identifier", icmp)
        self.assertNotIn("length", icmp)
        self.assertEqual(decoded.fields["payload"]["hex"], addresses.hex())

    def test_router_solicitation_rest_of_header(self) -> None:
        scapy = _scapy()
        decoded = self._icmp(_base_ip() / scapy.ICMP(type=10, code=0))
        icmp = decoded.fields["icmp"]
        self.assertEqual(icmp["type"], 10)
        self.assertEqual(icmp["rest_of_header"], "00000000")
        self.assertNotIn("identifier", icmp)

    # --- extension metadata / MPLS: blob in the flat payload ---------------

    def test_rfc4884_extension_blob_becomes_flat_payload(self) -> None:
        scapy = _scapy()
        # A deterministic RFC 4884/4950 extension blob (version 2 header plus one
        # MPLS object) trailing a destination-unreachable error.
        blob = bytes.fromhex("2000000000080100000010ff")
        decoded = self._icmp(_base_ip() / scapy.ICMP(type=3, code=0) / scapy.Raw(blob))
        icmp = decoded.fields["icmp"]
        self.assertEqual(icmp["type"], 3)
        self.assertEqual(icmp["rest_of_header"], "00000000")
        self.assertIn("length", icmp)
        # The extension header/object blob is the single flat trailing payload.
        self.assertEqual(decoded.layers, ["ipv4", "icmp", "payload"])
        self.assertEqual(decoded.fields["payload"]["hex"], blob.hex())

    # --- legacy / raw-compatible types -------------------------------------

    def test_legacy_traceroute_rest_of_header(self) -> None:
        scapy = _scapy()
        decoded = self._icmp(_base_ip() / scapy.ICMP(type=30, code=0))
        icmp = decoded.fields["icmp"]
        self.assertEqual(icmp["type"], 30)
        self.assertEqual(icmp["rest_of_header"], "00000000")
        # Legacy non-query types carry neither identifier/sequence nor length.
        self.assertNotIn("identifier", icmp)
        self.assertNotIn("length", icmp)

    def test_source_quench_rest_of_header(self) -> None:
        scapy = _scapy()
        decoded = self._icmp(_base_ip() / scapy.ICMP(type=4, code=0))
        icmp = decoded.fields["icmp"]
        self.assertEqual(icmp["type"], 4)
        self.assertEqual(icmp["rest_of_header"], "00000000")
        self.assertNotIn("identifier", icmp)


class IcmpNormalizationContractTest(unittest.TestCase):
    """The normalizer's ICMPv4 type/field contract matches libcrafter's rules."""

    def test_query_id_seq_types_match_libcrafter_query_rule(self) -> None:
        # RFC 792 echo (0/8), RFC 792 timestamp (13/14), RFC 792 information
        # (15/16), RFC 950 address mask (17/18) carry identifier/sequence.
        self.assertEqual(
            normalize._ICMPV4_ID_SEQ_TYPES,
            frozenset({0, 8, 13, 14, 15, 16, 17, 18}),
        )

    def test_extended_echo_types_are_42_43(self) -> None:
        self.assertEqual(
            normalize._ICMPV4_EXTENDED_ECHO_TYPES, frozenset({42, 43})
        )

    def test_extension_length_types_are_error_types(self) -> None:
        # Only RFC 4884 length-bearing error types (dest unreach, time exceeded,
        # parameter problem) carry the rest-of-header length byte.
        self.assertEqual(
            normalize._ICMPV4_EXTENSION_LENGTH_TYPES, frozenset({3, 11, 12})
        )

    def test_extended_echo_sequence_is_single_octet(self) -> None:
        # RFC 8335 narrows the sequence to a single octet (rest byte 2); a typed
        # ICMPv4 type-42 packet built with an explicit rest-of-header normalizes
        # to identifier (bytes 0-1) and sequence (byte 2 only).
        scapy = _scapy()
        rest = bytes.fromhex("01020301")
        ext = bytes.fromhex("20000000000800010102030405060708")
        header = bytes([42, 0, 0, 0]) + rest
        checksum = _icmp_checksum(header + ext)
        icmp_bytes = bytes([42, 0]) + checksum.to_bytes(2, "big") + rest + ext
        packet = _base_ip() / scapy.ICMP(bytes(icmp_bytes))
        decoded = _normalize(packet)
        icmp = decoded.fields["icmp"]
        self.assertEqual(icmp["type"], 42)
        self.assertEqual(icmp["identifier"], 0x0102)
        self.assertEqual(icmp["sequence"], 0x03)
        self.assertEqual(icmp["rest_of_header"], "01020301")


def _icmp_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(int.from_bytes(data[i : i + 2], "big") for i in range(0, len(data), 2))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


if __name__ == "__main__":
    unittest.main()
