"""Unit coverage for the backend-neutral normalized DNS message model.

The normalization helpers in ``backends/scapy/normalize.py`` build the
backend-neutral DNS model (header, the four sections, names, types, classes,
TTLs, and typed/raw RDATA) from a decoded DNS object. The pure-Python helpers
duck-type the Scapy record fields, so most coverage here runs under bare
``python3 -m unittest`` with lightweight stand-in objects. An optional
end-to-end check decodes a real Scapy packet and is skipped when Scapy is
unavailable.
"""

from __future__ import annotations

import types
import unittest

from tools.oracle.engine.backends.scapy import normalize

try:  # pragma: no cover - import guard
    import scapy.all as _scapy_all  # type: ignore[import-untyped]
    from scapy.layers.dns import (  # type: ignore[import-untyped]
        DNS,
        DNSQR,
        DNSRR,
        DNSRRSOA,
        SvcParam,
    )

    _SCAPY_AVAILABLE = True
except Exception:  # pragma: no cover - scapy optional in bare python3
    _scapy_all = None
    _SCAPY_AVAILABLE = False


def _rec(**fields: object) -> types.SimpleNamespace:
    return types.SimpleNamespace(**fields)


# Stand-in layer classes whose ``__name__`` matches what the chain walker in
# normalize._find_dns_layer keys on ("DNS" and "NoPayload"). Defined via type()
# so the names are exact regardless of the local symbol used to reference them.
_StubDns = type("DNS", (types.SimpleNamespace,), {})
_StubNoPayload = type("NoPayload", (), {})


class DnsNamePresentationTest(unittest.TestCase):
    def test_text_name_round_trips_to_trailing_dot_form(self) -> None:
        model = normalize._normalize_dns_name(b"example.com.")
        self.assertEqual(model["presentation"], "example.com.")
        self.assertEqual(model["labels"], ["6578616d706c65", "636f6d"])
        self.assertFalse(model["is_root"])

    def test_root_name_normalizes_to_dot(self) -> None:
        for value in (b"", b".", "."):
            model = normalize._normalize_dns_name(value)
            self.assertEqual(model["presentation"], ".")
            self.assertEqual(model["labels"], [])
            self.assertTrue(model["is_root"])

    def test_non_text_label_uses_decimal_escapes(self) -> None:
        # A label carrying a raw NUL byte renders with the RFC 1035 Section 5.1
        # \DDD escape, matching libcrafter's byte-preserving presentation form.
        model = normalize._normalize_dns_name(b"a\x00b.")
        self.assertEqual(model["presentation"], "a\\000b.")
        self.assertEqual(model["labels"], ["610062"])

    def test_str_name_is_byte_preserving(self) -> None:
        model = normalize._normalize_dns_name("host.example.com.")
        self.assertEqual(model["presentation"], "host.example.com.")


class DnsRdataNormalizeTest(unittest.TestCase):
    def test_a_record_address_is_text(self) -> None:
        rec = _rec(rrname=b"example.com.", type=1, rclass=1, ttl=300, rdata="192.0.2.1")
        model = normalize._normalize_dns_record(rec)
        self.assertEqual(model["record_type"], 1)
        self.assertEqual(model["record_class"], 1)
        self.assertEqual(model["ttl"], 300)
        self.assertEqual(model["rdata"], {"address": "192.0.2.1"})

    def test_name_target_record_normalizes_target_name(self) -> None:
        rec = _rec(rrname=b"example.com.", type=5, rclass=1, ttl=60, rdata=b"alias.example.com.")
        model = normalize._normalize_dns_record(rec)
        self.assertEqual(model["rdata"]["target"]["presentation"], "alias.example.com.")

    def test_mx_record_carries_preference_and_exchange(self) -> None:
        rec = _rec(
            rrname=b"example.com.", type=15, rclass=1, ttl=60,
            preference=10, exchange=b"mail.example.com.",
        )
        model = normalize._normalize_dns_record(rec)
        self.assertEqual(model["rdata"]["preference"], 10)
        self.assertEqual(model["rdata"]["exchange"]["presentation"], "mail.example.com.")

    def test_txt_strings_are_hex_chunks(self) -> None:
        rec = _rec(rrname=b"example.com.", type=16, rclass=1, ttl=60, rdata=[b"a", b"bb"])
        model = normalize._normalize_dns_record(rec)
        self.assertEqual(model["rdata"]["strings"], [{"hex": "61"}, {"hex": "6262"}])

    def test_unknown_type_normalizes_as_raw_hex(self) -> None:
        # An unknown numeric type must surface as raw RDATA, never a guessed
        # typed record, mirroring DnsRecordData::Raw on the libcrafter side.
        rec = _rec(rrname=b"example.com.", type=99, rclass=1, ttl=60, rdata=b"\xaa\xbb")
        model = normalize._normalize_dns_record(rec)
        self.assertEqual(model["rdata"], {"record_type": 99, "data": "aabb"})

    def test_opt_pseudo_record_decodes_edns_state(self) -> None:
        opt = _rec(type=41, rclass=4096, extrcode=0, version=0, z=0x8000, rdata=[])
        model = normalize._normalize_dns_record(opt)
        self.assertEqual(model["rdata"]["udp_payload_size"], 4096)
        self.assertTrue(model["rdata"]["dnssec_ok"])
        self.assertEqual(model["rdata"]["z_bits"], 0)

    def test_nsec_bitmaps_are_raw_hex(self) -> None:
        rec = _rec(
            rrname=b"example.com.", type=47, rclass=1, ttl=0,
            nextname=b"next.example.com.", typebitmaps=b"\x00\x06\x40\x00\x00\x08",
        )
        model = normalize._normalize_dns_record(rec)
        self.assertEqual(model["rdata"]["next_name"]["presentation"], "next.example.com.")
        self.assertEqual(model["rdata"]["type_bitmaps"], "000640000008")

    def test_svc_params_value_is_concatenated_hex(self) -> None:
        rec = _rec(
            rrname=b"example.com.", type=64, rclass=1, ttl=0,
            svc_priority=1, target_name=b"svc.example.com.",
            svc_params=[_rec(key=1, value=[b"\x00", b"\x01"])],
        )
        model = normalize._normalize_dns_record(rec)
        self.assertEqual(model["rdata"]["priority"], 1)
        self.assertEqual(model["rdata"]["params"], [{"key": 1, "value": "0001"}])


class DnsMessageNormalizeTest(unittest.TestCase):
    def test_none_when_no_dns_layer(self) -> None:
        # A non-DNS chain (terminating immediately) yields no DNS message.
        self.assertIsNone(normalize._normalize_dns_message(_StubNoPayload()))

    def test_header_and_sections_from_stub_layer(self) -> None:
        dns = _StubDns(
            id=0x1234, qr=1, opcode=0, aa=0, tc=0, rd=1, ra=1, z=0, ad=0, cd=0,
            rcode=0, qdcount=1, ancount=1, nscount=0, arcount=0,
            qd=[_rec(qname=b"example.com.", qtype=1, qclass=1)],
            an=[_rec(rrname=b"example.com.", type=1, rclass=1, ttl=300, rdata="192.0.2.1")],
            ns=[], ar=[], payload=_StubNoPayload(),
        )
        message = normalize._normalize_dns_message(dns)
        self.assertIsNotNone(message)
        assert message is not None
        self.assertEqual(message["header"]["transaction_id"], 0x1234)
        self.assertTrue(message["header"]["is_response"])
        self.assertEqual(message["header"]["answer_count"], 1)
        self.assertEqual(len(message["questions"]), 1)
        self.assertEqual(message["questions"][0]["record_type"], 1)
        self.assertEqual(message["questions"][0]["name"]["presentation"], "example.com.")
        self.assertEqual(len(message["answers"]), 1)
        self.assertEqual(message["answers"][0]["rdata"], {"address": "192.0.2.1"})
        self.assertEqual(message["authorities"], [])
        self.assertEqual(message["additionals"], [])

    @unittest.skipUnless(_SCAPY_AVAILABLE, "scapy not importable")
    def test_scapy_round_trip_builds_normalized_message(self) -> None:
        packet = DNS(
            id=0x1234, qr=1, rd=1, ra=1,
            qd=DNSQR(qname="example.com.", qtype="A", qclass="IN"),
            an=DNSRR(rrname="example.com.", type="A", rclass="IN", ttl=300, rdata="192.0.2.1"),
            ns=DNSRRSOA(
                rrname="example.com.", mname="ns.example.com.", rname="hostmaster.example.com.",
                serial=1, refresh=2, retry=3, expire=4, minimum=5,
            ),
        )
        decoded = DNS(bytes(packet))
        message = normalize._normalize_dns_message(decoded)
        self.assertIsNotNone(message)
        assert message is not None
        self.assertEqual(message["header"]["transaction_id"], 0x1234)
        self.assertEqual(message["questions"][0]["name"]["presentation"], "example.com.")
        self.assertEqual(message["answers"][0]["rdata"], {"address": "192.0.2.1"})
        soa = message["authorities"][0]["rdata"]
        self.assertEqual(soa["primary_name"]["presentation"], "ns.example.com.")
        self.assertEqual(soa["serial"], 1)
        self.assertEqual(soa["minimum"], 5)

    @unittest.skipUnless(_SCAPY_AVAILABLE, "scapy not importable")
    def test_compressed_name_normalizes_to_uncompressed_model(self) -> None:
        # A pointer-compressed answer owner name decodes to the same normalized
        # name model as the uncompressed question name, which is the agreement a
        # normalized (non-strict-bytes) compressed-name case relies on.
        wire = bytes.fromhex(
            "12348180000100010000000007"
            "6578616d706c6503636f6d0000010001"
            "c00c000100010000012c0004c0000201"
        )
        decoded = DNS(wire)
        message = normalize._normalize_dns_message(decoded)
        assert message is not None
        self.assertEqual(
            message["answers"][0]["name"]["presentation"],
            message["questions"][0]["name"]["presentation"],
        )
        self.assertEqual(message["answers"][0]["name"]["presentation"], "example.com.")


if __name__ == "__main__":
    unittest.main()
