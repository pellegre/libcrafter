"""Unit coverage for Scapy-owned raw DNS byte construction.

These tests assert the exact octets the raw helpers emit for low-level DNS
cases that Scapy's high-level fields cannot reliably produce: an explicit
compression pointer and deliberately malformed DNS bytes. The byte builders have
no Scapy dependency, so the tests run under bare ``python3 -m unittest`` while
the optional round-trip check is skipped when Scapy is unavailable.
"""

from __future__ import annotations

import unittest

from tools.oracle.engine.backends.scapy import dns_raw
from tools.oracle.engine.protocols.dns import _dns_compressed_names_raw_spec

try:  # pragma: no cover - import guard
    import scapy.all as _scapy_all  # type: ignore[import-untyped]

    _SCAPY_AVAILABLE = True
except Exception:  # pragma: no cover - scapy optional in bare python3
    _scapy_all = None
    _SCAPY_AVAILABLE = False


class DnsRawNameBytesTest(unittest.TestCase):
    def test_uncompressed_name_labels(self) -> None:
        self.assertEqual(
            dns_raw.dns_name_bytes("example.com."),
            b"\x07example\x03com\x00",
        )

    def test_root_name_is_single_zero(self) -> None:
        self.assertEqual(dns_raw.dns_name_bytes("."), b"\x00")
        self.assertEqual(dns_raw.dns_name_bytes(""), b"\x00")

    def test_decimal_escape_is_byte_preserving(self) -> None:
        # \000 and \255 encode the raw octets without UTF-8 interpretation.
        self.assertEqual(dns_raw.dns_name_bytes("\\000\\255."), b"\x02\x00\xff\x00")

    def test_compression_pointer_marker(self) -> None:
        self.assertEqual(dns_raw.dns_compression_pointer_bytes(12), b"\xc0\x0c")

    def test_partial_name_with_pointer(self) -> None:
        self.assertEqual(
            dns_raw.dns_partial_name_with_pointer("alias", 12),
            b"\x05alias\xc0\x0c",
        )

    def test_pointer_offset_out_of_range_raises(self) -> None:
        with self.assertRaises(ValueError):
            dns_raw.dns_compression_pointer_bytes(0x4000)

    def test_rdata_with_pointer_prefix_pointers_suffix(self) -> None:
        # MX-shaped RDATA: 2-octet preference prefix, one compressed exchange
        # name, no suffix.
        self.assertEqual(
            dns_raw.dns_rdata_with_pointer_bytes(
                {"prefix_hex": "000a", "pointers": [{"prefix": "mail", "pointer_offset": 12}]}
            ),
            b"\x00\x0a\x04mail\xc0\x0c",
        )
        # SOA-shaped RDATA: two compressed names (MNAME, RNAME) then a 20-octet
        # fixed suffix.
        self.assertEqual(
            dns_raw.dns_rdata_with_pointer_bytes(
                {
                    "pointers": [
                        {"prefix": "ns1", "pointer_offset": 12},
                        {"prefix": None, "pointer_offset": 12},
                    ],
                    "suffix_hex": "00" * 20,
                }
            ),
            b"\x03ns1\xc0\x0c" + b"\xc0\x0c" + b"\x00" * 20,
        )


class DnsRawCompressedMessageTest(unittest.TestCase):
    def test_generator_compressed_names_spec_emits_pointers(self) -> None:
        spec = _dns_compressed_names_raw_spec()
        message = dns_raw.build_raw_dns_bytes(spec)

        # 12-octet header: id 0x1234, flags QR+RD+RA, qd=1, an=10, ns=0, ar=0.
        # The case carries one record per byte-preserving record type so every
        # compressed RDATA <domain-name> position is exercised in one message.
        self.assertEqual(message[:2], b"\x12\x34")
        self.assertEqual(message[4:12], b"\x00\x01\x00\x0a\x00\x00\x00\x00")

        # Question name example.com. lands at the fixed offset 12, so every
        # compression pointer in the message targets offset 12 (0xC0 0x0C).
        self.assertEqual(message[12:25], b"\x07example\x03com\x00")

        # CNAME owner is a bare pointer to offset 12, and the CNAME RDATA target
        # is the label "alias" followed by a pointer to offset 12.
        self.assertIn(b"\xc0\x0c", message[29:])
        self.assertIn(b"\x05alias\xc0\x0c", message)
        # The embedded RDATA <domain-name> of each structured record type is a
        # compression pointer after its fixed prefix: NS/PTR target label + ptr,
        # MX exchange after the 2-octet preference, SOA MNAME+RNAME pointers,
        # SRV target after priority/weight/port, RRSIG signer (bare pointer after
        # the 18 fixed octets), NSEC next-domain, and SVCB/HTTPS target after the
        # 2-octet priority.
        self.assertIn(b"\x03ns1\xc0\x0c", message)  # NS target and SOA MNAME.
        self.assertIn(b"\x04host\xc0\x0c", message)  # PTR target.
        self.assertIn(b"\x00\x0a\x04mail\xc0\x0c", message)  # MX pref + exchange.
        self.assertIn(b"\x0ahostmaster\xc0\x0c", message)  # SOA RNAME.
        self.assertIn(b"\x03sip\xc0\x0c", message)  # SRV target.
        self.assertIn(b"\x04next\xc0\x0c", message)  # NSEC next-domain.
        self.assertIn(b"\x03svc\xc0\x0c", message)  # SVCB target.

    @unittest.skipUnless(_SCAPY_AVAILABLE, "scapy not importable")
    def test_scapy_round_trips_compressed_message(self) -> None:
        spec = _dns_compressed_names_raw_spec()
        message = dns_raw.build_raw_dns_bytes(spec)

        decoded = _scapy_all.DNS(message)

        self.assertEqual(decoded.id, 0x1234)
        self.assertEqual(decoded.qr, 1)
        self.assertEqual(decoded.ancount, 10)
        # Scapy expands the compression pointers back to the full names.
        self.assertEqual(decoded.qd[0].qname, b"example.com.")
        self.assertEqual(decoded.an[0].rrname, b"example.com.")
        self.assertEqual(decoded.an[0].rdata, b"alias.example.com.")

    @unittest.skipUnless(_SCAPY_AVAILABLE, "scapy not importable")
    def test_materialize_returns_byte_exact_layer(self) -> None:
        spec = _dns_compressed_names_raw_spec()
        message = dns_raw.build_raw_dns_bytes(spec)

        layer = dns_raw.materialize_raw_dns(spec, _scapy_all)

        self.assertEqual(bytes(_scapy_all.raw(layer)), message)


class DnsRawMalformedBytesTest(unittest.TestCase):
    def test_overrun_rdlength_declares_more_than_rdata(self) -> None:
        # RDLENGTH override claims 32 octets but only a 4-octet A address is
        # present, producing a truncated-RDATA decode for libcrafter.
        record = {
            "name": "example.com.",
            "type": "A",
            "class": "IN",
            "ttl": 60,
            "address": "192.0.2.1",
            "rdlength_override": 32,
        }
        encoded = dns_raw.dns_record_bytes(record, base_offset=dns_raw.DNS_HEADER_LENGTH)

        # Name (13) + type (2) + class (2) + ttl (4) + rdlength (2) = 23, then
        # the declared length 0x0020 followed by only 4 actual RDATA octets.
        self.assertEqual(encoded[21:23], b"\x00\x20")
        self.assertEqual(encoded[23:], b"\xc0\x00\x02\x01")

    def test_truncated_name_pointer_message(self) -> None:
        spec = {
            "transaction_id": 1,
            "questions": [
                {
                    "name_with_pointer": {"prefix": "host", "pointer_offset": 12},
                    "type": "A",
                    "class": "IN",
                }
            ],
        }
        message = dns_raw.build_raw_dns_bytes(spec)

        # Question carries a pointer (0xC00C) that targets the question itself,
        # which is the malformed pointer-cycle shape libcrafter must reject.
        self.assertIn(b"\xc0\x0c", message[12:])
        self.assertEqual(message[4:6], b"\x00\x01")

    def test_explicit_counts_override_for_malformed_message(self) -> None:
        spec = {
            "transaction_id": 7,
            "questions": [{"name": "example.com.", "type": "A", "class": "IN"}],
            "counts": {"qd": 5},
        }
        message = dns_raw.build_raw_dns_bytes(spec)

        # The header advertises 5 questions while only one is present.
        self.assertEqual(message[4:6], b"\x00\x05")

    def test_trailing_bytes_appended_after_records(self) -> None:
        spec = {
            "questions": [{"name": ".", "type": "A", "class": "IN"}],
            "trailing_bytes": "deadbeef",
        }
        message = dns_raw.build_raw_dns_bytes(spec)
        self.assertTrue(message.endswith(b"\xde\xad\xbe\xef"))

    def test_unsupported_type_raises(self) -> None:
        with self.assertRaises(ValueError):
            dns_raw.dns_record_bytes(
                {"name": ".", "type": "NOT_A_TYPE", "data": ""},
                base_offset=dns_raw.DNS_HEADER_LENGTH,
            )


if __name__ == "__main__":
    unittest.main()
