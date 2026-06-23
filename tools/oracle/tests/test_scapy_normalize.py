"""Normalized Scapy decode coverage for control-protocol oracle models.

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
from tools.oracle.engine.backends.scapy.protocols import ipv4 as ipv4_scapy


def _scapy():
    return import_scapy()["all"]


def _base_ip():
    scapy = _scapy()
    return scapy.IP(src="192.0.2.1", dst="198.51.100.1", id=4242, ttl=64)


def _base_igmp_ip(dst: str = "224.0.0.1"):
    scapy = _scapy()
    return scapy.IP(src="192.0.2.1", dst=dst, id=4242, ttl=1, proto=2)


def _normalize(packet):
    """Re-encode a Scapy packet and decode it through the oracle normalizer."""

    scapy = _scapy()
    raw = bytes(scapy.raw(packet))
    return normalize.decode_bytes(raw, root="l2:ipv4", source_hex=raw.hex())


class ScapyIpv4FlagNormalizeTest(unittest.TestCase):
    def test_ipv4_reserved_flag_uses_libcrafter_name(self) -> None:
        self.assertEqual(
            ipv4_scapy._normalize_ipv4_flags("evil"),
            "reserved",
        )

    def test_ipv4_reserved_flag_uses_libcrafter_name_inside_combinations(self) -> None:
        self.assertEqual(
            ipv4_scapy._normalize_ipv4_flags("MF+DF+evil"),
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

    def test_destination_unreachable_payload_preserves_wire_bytes_after_scapy_subdecode(
        self,
    ) -> None:
        raw_hex = (
            "450000e212d10000400111d2c6336437c63364da03000b3700000000"
            "45000028424200004011b464c000020ac00002149c40003500140000"
            "71756f7465642d717565727920000000000800010102030405060708"
            "28fceb12efea7f56c8dbe2b4cce87666aa9d68da3d56b20480593c"
            "fec6b9dc19bfa376354abe35e29d07af0bfd1dc9d6f9d4e58a5012"
            "7479caa0037c8323bc066088d92f8f524635cb6c096e2ac1c573d5"
            "5d97acfb15c5254f3fec37bdef223a665ef42b4b457b679749e5ab"
            "619af44365bab8340d1b0ccbd2a88da420b3be1a926105aeb3e58b"
            "4502620b2e0ca3"
        )
        raw = bytes.fromhex(raw_hex)

        decoded = normalize.decode_bytes(raw, root="l2:ipv4", source_hex=raw_hex)

        self.assertEqual(decoded.layers, ["ipv4", "icmp", "payload"])
        self.assertEqual(decoded.fields["payload"]["hex"], raw[28:].hex())

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


class IgmpNormalizedModelTest(unittest.TestCase):
    """IPv4 protocol 2 Raw payloads normalize into stable IGMP layers."""

    def _igmp(self, igmp_bytes: bytes, *, dst: str = "224.0.0.1"):
        scapy = _scapy()
        decoded = _normalize(_base_igmp_ip(dst) / scapy.Raw(igmp_bytes))
        self.assertEqual(decoded.root, "l3:ipv4")
        self.assertEqual(decoded.layers[0], "ipv4")
        self.assertEqual(decoded.layers[1], "igmp")
        igmp = decoded.fields["igmp"]
        self.assertIn("type", igmp)
        self.assertIn("type_label", igmp)
        self.assertIn("code", igmp)
        self.assertIn("checksum", igmp)
        self.assertIn("checksum_status", igmp)
        return decoded

    def test_membership_query_fixed_header(self) -> None:
        decoded = self._igmp(_igmp_packet(0x11, 0, bytes.fromhex("00000000")))
        self.assertEqual(decoded.layers, ["ipv4", "igmp"])
        igmp = decoded.fields["igmp"]
        self.assertEqual(igmp["type"], 0x11)
        self.assertEqual(igmp["type_label"], "membership_query")
        self.assertEqual(igmp["code_label"], "v1_query_zero")
        self.assertEqual(igmp["group_address"], "0.0.0.0")
        self.assertEqual(igmp["checksum_status"], "valid")
        self.assertNotIn("payload", decoded.fields)

    def test_v3_query_sources_and_raw_tail(self) -> None:
        body = (
            bytes([0x0A, 0x7D])
            + (2).to_bytes(2, "big")
            + bytes([198, 51, 100, 10])
            + bytes([203, 0, 113, 20])
            + bytes.fromhex("deadbeef")
        )
        decoded = self._igmp(
            _igmp_packet(0x11, 100, bytes([233, 252, 0, 61]), body),
            dst="233.252.0.61",
        )

        self.assertEqual(decoded.layers, ["ipv4", "igmp", "igmp_query", "payload"])
        igmp = decoded.fields["igmp"]
        query = decoded.fields["igmp_query"]
        self.assertEqual(igmp["group_address"], "233.252.0.61")
        self.assertEqual(igmp["code_label"], "v2_or_v3_max_response_code")
        self.assertEqual(query["query_flags"], 0x0A)
        self.assertEqual(
            query["query_flag_labels"],
            ["suppress_router_side_processing", "qrv"],
        )
        self.assertTrue(query["suppress_router_side_processing"])
        self.assertEqual(query["querier_robustness_variable"], 2)
        self.assertEqual(query["qqic"], 0x7D)
        self.assertEqual(query["number_of_sources"], 2)
        self.assertEqual(query["source_addresses"], ["198.51.100.10", "203.0.113.20"])
        self.assertEqual(decoded.fields["payload"]["hex"], "deadbeef")

    def test_v3_report_record_auxiliary_data(self) -> None:
        record = (
            bytes([4, 1])
            + (1).to_bytes(2, "big")
            + bytes([233, 252, 0, 76])
            + bytes([198, 51, 100, 74])
            + bytes.fromhex("deadbeef")
        )
        body = (0).to_bytes(2, "big") + (1).to_bytes(2, "big") + record
        decoded = self._igmp(
            _igmp_packet(0x22, 0, bytes.fromhex("00000000"), body),
            dst="224.0.0.22",
        )

        self.assertEqual(decoded.layers, ["ipv4", "igmp", "igmp_report"])
        report = decoded.fields["igmp_report"]
        self.assertEqual(report["report_flags"], 0)
        self.assertEqual(report["report_flag_labels"], [])
        self.assertEqual(report["number_of_group_records"], 1)
        self.assertEqual(len(report["group_records"]), 1)
        normalized_record = report["group_records"][0]
        self.assertEqual(normalized_record["record_type"], 4)
        self.assertEqual(normalized_record["record_type_label"], "change_to_exclude_mode")
        self.assertEqual(normalized_record["auxiliary_data_len"], 1)
        self.assertEqual(normalized_record["number_of_sources"], 1)
        self.assertEqual(normalized_record["multicast_address"], "233.252.0.76")
        self.assertEqual(normalized_record["source_addresses"], ["198.51.100.74"])
        self.assertEqual(normalized_record["auxiliary_data"], {"hex": "deadbeef", "length": 4})

    def test_extension_tlvs_parse_when_e_flag_set(self) -> None:
        extension = (0).to_bytes(2, "big") + (4).to_bytes(2, "big") + bytes.fromhex("aabbccdd")
        body = bytes([0x80, 0x7D]) + (0).to_bytes(2, "big") + extension
        decoded = self._igmp(
            _igmp_packet(0x11, 100, bytes([233, 252, 0, 61]), body),
            dst="233.252.0.61",
        )

        self.assertEqual(decoded.layers, ["ipv4", "igmp", "igmp_query", "igmp_extension"])
        query = decoded.fields["igmp_query"]
        extension_fields = decoded.fields["igmp_extension"]
        self.assertEqual(query["query_flags"], 0x80)
        self.assertEqual(query["query_flag_labels"], ["extension"])
        self.assertEqual(extension_fields["extension_type"], 0)
        self.assertEqual(extension_fields["extension_type_label"], "noop")
        self.assertEqual(extension_fields["extension_length"], 4)
        self.assertEqual(extension_fields["extension_value"], {"hex": "aabbccdd", "length": 4})

    def test_mrd_advertisement_and_unknown_type_values(self) -> None:
        mrd = self._igmp(
            _igmp_packet(0x30, 20, (125).to_bytes(2, "big") + (2).to_bytes(2, "big")),
            dst="224.0.0.106",
        )
        self.assertEqual(mrd.layers, ["ipv4", "igmp"])
        self.assertEqual(mrd.fields["igmp"]["type_label"], "multicast_router_advertisement")
        self.assertEqual(mrd.fields["igmp"]["code_label"], "mrd_advertisement_interval")
        self.assertEqual(mrd.fields["igmp"]["mrd_query_interval"], 125)
        self.assertEqual(mrd.fields["igmp"]["mrd_robustness_variable"], 2)

        unknown = self._igmp(
            _igmp_packet(0x09, 0, bytes.fromhex("00000000"), bytes.fromhex("deadbeef")),
            dst="233.252.0.1",
        )
        self.assertEqual(unknown.layers, ["ipv4", "igmp", "payload"])
        self.assertEqual(unknown.fields["igmp"]["type"], 0x09)
        self.assertEqual(unknown.fields["igmp"]["type_label"], "unassigned")
        self.assertEqual(unknown.fields["payload"]["hex"], "deadbeef")


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


def _igmp_packet(type_code: int, code: int, rest: bytes, body: bytes = b"") -> bytes:
    header = bytes([type_code, code, 0, 0]) + rest + body
    checksum = _icmp_checksum(header)
    return bytes([type_code, code]) + checksum.to_bytes(2, "big") + rest + body


if __name__ == "__main__":
    unittest.main()
