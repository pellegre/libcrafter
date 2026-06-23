"""Unit coverage for the Scapy DNS materialization and raw-byte helpers.

These tests exercise the backend helper APIs that the DNS oracle relies on, so a
broken materializer or raw builder fails here before any full oracle run. They
reuse the public backend helpers (``packets._dns``, ``packets._dns_record_entry``,
``dns_raw.build_raw_dns_bytes``, ``dns_raw.materialize_raw_dns``) instead of
duplicating packet construction in the test bodies.

The raw byte builders have no Scapy dependency, so their deterministic-octet
assertions run under bare ``python3 -m unittest``. The high-level helpers and the
round-trip checks need Scapy and are skipped when it is unavailable. No test
sends or expects live traffic.
"""

from __future__ import annotations

import unittest

from tools.oracle.engine.backends.scapy import dns_raw, normalize, packets
from tools.oracle.engine.protocols.dns import _dns_compressed_names_raw_spec

try:  # pragma: no cover - import guard
    import scapy.all as _scapy_all  # type: ignore[import-untyped]

    _SCAPY_AVAILABLE = True
except Exception:  # pragma: no cover - scapy optional in bare python3
    _scapy_all = None
    _SCAPY_AVAILABLE = False


def _dns_layer(fields: dict[str, object]) -> object:
    """Materialize a DNS layer through the shared ``packets._dns`` helper."""

    return packets._dns({"dns": fields}, _scapy_all)


class HighLevelDnsPacketTest(unittest.TestCase):
    @unittest.skipUnless(_SCAPY_AVAILABLE, "scapy not importable")
    def test_normal_query_response_materializes_and_round_trips(self) -> None:
        layer = _dns_layer(
            {
                "transaction_id": 0x1234,
                "is_response": True,
                "flags": ["recursion_desired", "recursion_available"],
                "questions": [{"name": "example.com.", "type": "A", "class": "IN"}],
                "answers": [
                    {
                        "name": "example.com.",
                        "type": "A",
                        "class": "IN",
                        "ttl": 300,
                        "address": "192.0.2.1",
                    }
                ],
            }
        )
        decoded = _scapy_all.DNS(bytes(_scapy_all.raw(layer)))

        self.assertEqual(decoded.id, 0x1234)
        self.assertEqual(decoded.qr, 1)
        self.assertEqual(decoded.qdcount, 1)
        self.assertEqual(decoded.ancount, 1)
        self.assertEqual(decoded.qd[0].qname, b"example.com.")
        self.assertEqual(decoded.an[0].rrname, b"example.com.")
        self.assertEqual(decoded.an[0].type, 1)
        self.assertEqual(decoded.an[0].ttl, 300)
        self.assertEqual(decoded.an[0].rdata, "192.0.2.1")


class RawCompressedDnsPacketTest(unittest.TestCase):
    def test_compressed_message_bytes_are_deterministic(self) -> None:
        spec = _dns_compressed_names_raw_spec()
        message = dns_raw.build_raw_dns_bytes(spec)

        # Fixed 12-octet header: id 0x1234, one question, ten answers (one per
        # byte-preserving record type whose RDATA carries a compressed name).
        self.assertEqual(message[:2], b"\x12\x34")
        self.assertEqual(message[4:12], b"\x00\x01\x00\x0a\x00\x00\x00\x00")
        # The question name example.com. is fully spelled at offset 12, so every
        # compression pointer in the message targets offset 12.
        self.assertEqual(message[12:25], b"\x07example\x03com\x00")
        # The CNAME owner name is a bare pointer to offset 12, and the CNAME
        # target is the "alias" label followed by a pointer to the same offset.
        self.assertIn(b"\xc0\x0c", message[25:])
        self.assertIn(b"\x05alias\xc0\x0c", message)
        # Each structured record type embeds a compressed <domain-name>.
        self.assertIn(b"\x00\x0a\x04mail\xc0\x0c", message)  # MX exchange.
        self.assertIn(b"\x0ahostmaster\xc0\x0c", message)  # SOA RNAME.
        self.assertIn(b"\x03sip\xc0\x0c", message)  # SRV target.
        self.assertIn(b"\x04next\xc0\x0c", message)  # NSEC next-domain.
        self.assertIn(b"\x03svc\xc0\x0c", message)  # SVCB target.

    @unittest.skipUnless(_SCAPY_AVAILABLE, "scapy not importable")
    def test_materialize_raw_dns_round_trips_pointers(self) -> None:
        spec = _dns_compressed_names_raw_spec()
        layer = dns_raw.materialize_raw_dns(spec, _scapy_all)

        # The materialized layer is byte-exact with the hand-built message.
        self.assertEqual(bytes(_scapy_all.raw(layer)), dns_raw.build_raw_dns_bytes(spec))

        decoded = _scapy_all.DNS(bytes(_scapy_all.raw(layer)))
        # Scapy expands the compression pointers back to the full names.
        self.assertEqual(decoded.qd[0].qname, b"example.com.")
        self.assertEqual(decoded.an[0].rrname, b"example.com.")
        self.assertEqual(decoded.an[0].rdata, b"alias.example.com.")


class EdnsOptionPacketTest(unittest.TestCase):
    _OPT_RECORD = {
        "type": "OPT",
        "name": ".",
        "udp_payload_size": 4096,
        "extended_rcode": 0,
        "version": 0,
        "dnssec_ok": True,
        "options": [
            {"option_code": 10, "option_data": {"hex": "0011223344556677"}},
        ],
    }

    @unittest.skipUnless(_SCAPY_AVAILABLE, "scapy not importable")
    def test_opt_record_carries_edns_state_and_option_tlv(self) -> None:
        record = packets._dns_record_entry(self._OPT_RECORD, _scapy_all)
        decoded = _scapy_all.DNS(
            bytes(_scapy_all.raw(_scapy_all.DNS(arcount=1, ar=record)))
        )

        opt = decoded.ar[0]
        self.assertEqual(opt.type, 41)
        # The OPT CLASS field carries the requestor UDP payload size.
        self.assertEqual(opt.rclass, 4096)
        # The DO bit is the top bit of the OPT TTL "z" field.
        self.assertEqual(opt.z & 0x8000, 0x8000)
        self.assertEqual(opt.rdata[0].optcode, 10)
        self.assertEqual(
            normalize._dns_edns_option_data(opt.rdata[0]),
            bytes.fromhex("0011223344556677"),
        )

    @unittest.skipUnless(_SCAPY_AVAILABLE, "scapy not importable")
    def test_opt_option_tlv_bytes_are_deterministic(self) -> None:
        record = packets._dns_record_entry(self._OPT_RECORD, _scapy_all)
        wire = bytes(_scapy_all.raw(record))

        # The single option TLV is code 0x000a, length 0x0008, then the 8 data
        # octets, and that triplet appears verbatim in the OPT RDATA.
        self.assertIn(b"\x00\x0a\x00\x08\x00\x11\x22\x33\x44\x55\x66\x77", wire)


class RawUnknownRecordTest(unittest.TestCase):
    _SPEC = {
        "transaction_id": 0x2222,
        "is_response": True,
        "questions": [{"name": "example.com.", "type": "A", "class": "IN"}],
        "answers": [
            {
                "name": "example.com.",
                "type": 64999,
                "class": "IN",
                "ttl": 60,
                "data": "deadbeef",
            }
        ],
    }

    def test_unknown_type_record_bytes_preserve_codepoint_and_rdata(self) -> None:
        message = dns_raw.build_raw_dns_bytes(self._SPEC)

        # Owner name pointer or full name, then the unknown TYPE 64999 (0xFDE7),
        # CLASS IN (0x0001), TTL 60, RDLENGTH 4, and the opaque RDATA blob.
        self.assertIn(b"\xfd\xe7\x00\x01\x00\x00\x00\x3c\x00\x04\xde\xad\xbe\xef", message)
        self.assertEqual(message[4:8], b"\x00\x01\x00\x01")

    @unittest.skipUnless(_SCAPY_AVAILABLE, "scapy not importable")
    def test_scapy_decodes_unknown_type_as_opaque_rdata(self) -> None:
        decoded = _scapy_all.DNS(dns_raw.build_raw_dns_bytes(self._SPEC))

        self.assertEqual(decoded.an[0].type, 64999)
        self.assertEqual(bytes(decoded.an[0].rdata), bytes.fromhex("deadbeef"))


class SvcbHttpsRecordTest(unittest.TestCase):
    def test_raw_svcb_record_bytes_encode_priority_and_target(self) -> None:
        # Raw-equivalent SVCB record: AliasMode (priority 0) with a root target,
        # built byte-exact so the encoding is checkable without a Scapy import.
        record = {
            "name": "example.com.",
            "type": 64,  # SVCB
            "class": "IN",
            "ttl": 3600,
            "data": "0000",  # SvcPriority 0 (AliasMode) + root target (single 0x00)
        }
        encoded = dns_raw.dns_record_bytes(record, base_offset=dns_raw.DNS_HEADER_LENGTH)

        # example.com. owner (13) then TYPE 64 (0x0040), CLASS IN, TTL 3600,
        # RDLENGTH 2, and the 2 RDATA octets.
        self.assertEqual(encoded[:13], b"\x07example\x03com\x00")
        self.assertEqual(encoded[13:23], b"\x00\x40\x00\x01\x00\x00\x0e\x10\x00\x02")
        self.assertEqual(encoded[23:], b"\x00\x00")

    @unittest.skipUnless(_SCAPY_AVAILABLE, "scapy not importable")
    def test_https_record_carries_priority_target_and_verbatim_params(self) -> None:
        # Scapy's high-level SvcParam field re-interprets known SvcParamKeys (it
        # length-prefixes the alpn id list and rejects raw port/ipvNhint bytes),
        # so the backend builds the exact SVCB/HTTPS RDATA octets and hands them
        # to a generic DNSRR (TYPE 65). The SvcParamValue is opaque wire data, so
        # the assertion checks the verbatim RDATA bytes rather than Scapy's lossy
        # per-key dissection: SvcPriority 1, root target (single 0x00), then the
        # alpn SvcParam {key 0x0001, length 0x0009, value 0268320568332d3239}.
        record = packets._dns_record_entry(
            {
                "type": "HTTPS",
                "name": "example.com.",
                "ttl": 3600,
                "priority": 1,
                "target": ".",
                "params": [
                    {"key": 1, "value": {"hex": "0268320568332d3239"}},  # alpn
                ],
            },
            _scapy_all,
        )
        self.assertEqual(record.type, 65)  # HTTPS
        rdata = bytes(record.rdata)
        expected_rdata = bytes.fromhex("0001" + "00" + "0001" + "0009" + "0268320568332d3239")
        self.assertEqual(rdata, expected_rdata)

        # The verbatim RDATA bytes survive a full DNS message round trip. Scapy
        # re-dissects TYPE 65 as DNSRRHTTPS on decode, so re-serialize the whole
        # message and confirm the RDATA octets appear unchanged in the wire image
        # rather than reading Scapy's lossy per-key SvcParam fields.
        message = bytes(_scapy_all.raw(_scapy_all.DNS(ancount=1, an=record)))
        self.assertIn(expected_rdata, message)
        reencoded = bytes(_scapy_all.raw(_scapy_all.DNS(message)))
        self.assertIn(expected_rdata, reencoded)


if __name__ == "__main__":
    unittest.main()
