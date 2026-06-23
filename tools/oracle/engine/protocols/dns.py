"""Generator-stage sampler plugin for the DNS layer.

Moves the ``_sample_dns_field`` sampler and the ``dns_behavior`` feature behavior
(``_apply_dns_behavior``) out of :mod:`generator` and registers them through the
uniform :class:`~.base.ProtocolSampler` contract. The sampling and behavior logic
is moved verbatim (behavior must stay byte-identical); only the dispatch moves
from the generator's legacy if/elif into this self-contained module, which
self-registers on import.

DNS carries a feature behavior like IPv4/UDP: ``apply_behavior`` reproduces the
legacy ``dns_behavior`` branch of ``_apply_feature_behavior`` and
``handles_feature`` claims ownership of the ``"dns_behavior"`` feature name, so
the generator's registry-first feature loop runs it exactly once. The legacy
branch gated on ``"dns" in fields`` and mutated ``fields["dns"]`` in place; that
guard is reproduced here.

The ``_dns_behavior_emits_raw`` helper stays generator-visible because the
generic name-selection code in :mod:`generator` (``_select_behavior_name``) still
consults it to avoid pairing a typed case with a compressed raw-byte builder. It
is defined here (the owning module) and re-imported back into ``generator`` so the
call site keeps working.

This step is generator-stage only: the large Scapy ``dns``/``dns_raw`` encoder and
the Scapy/Wireshark decoders stay on their legacy backend paths (registered
fallbacks) until the next two steps migrate them. Relative imports only so the
package resolves under both the ``engine.*`` (CLI) and ``tools.oracle.engine.*``
(tests) import roots.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..model import JSONObject
from ..sampling import (
    _SamplingContext,
    _integer_domain_value,
    weighted_choice,
)
from .base import ProtocolSampler, register


# DNS fields the generator samples, mirroring the former
# ``generator._SUPPORTED_FIELDS["dns"]`` entry.
_SUPPORTED_FIELDS = frozenset(
    {
        "transaction_id",
        "is_response",
        "opcode",
        "flags",
        "response_code",
        "questions",
    }
)


def _sample_dns_field(ctx: _SamplingContext, field_name: str, domain: object) -> object:
    if field_name == "transaction_id":
        return _integer_domain_value(ctx, domain, field_name, bits=16)
    if field_name == "is_response":
        return False
    if field_name == "opcode":
        return "query"
    if field_name == "flags":
        return ["recursion_desired"]
    if field_name == "response_code":
        return "no_error"
    if field_name == "questions":
        question_count = 2 if domain == "multiple_questions" and ctx.profile in {"boundary", "fuzz"} else 1
        names = ("example.com.", "example.net.", "libcrafter.test.")
        questions: list[JSONObject] = []
        for index in range(question_count):
            questions.append(
                {
                    "qname": names[index % len(names)],
                    "qtype": weighted_choice(ctx.rng, (("A", 3), ("AAAA", 1))),
                }
            )
        return questions
    if field_name == "answers":
        return _dns_answers_for_domain(ctx, domain)
    raise ValueError(f"spec error: unsupported dns field sampler: {field_name}")


def _sample(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    """Uniform sampler adapter: DNS uses only ``ctx``/``field_name``/``domain``."""

    return _sample_dns_field(ctx, field_name, domain)


def _dns_behavior_emits_raw(case: str, behavior: str) -> bool:
    """Whether applying ``behavior`` to ``case`` emits a Scapy-owned raw spec.

    Mirrors the ``dns_raw`` branches in ``_apply_dns_behavior`` so case/behavior
    selection can avoid pairing a typed case with a compressed raw-byte builder
    that only the reference backend can encode.
    """

    key = f"{case} {behavior}".replace("_", "-")
    return "compressed-names" in key or "name-records-compressed" in key


def _apply_dns_behavior(fields: JSONObject, *, case: str, behavior: str) -> None:
    key = f"{case} {behavior}".replace("_", "-")
    if "compressed-names" in key:
        fields.clear()
        fields["dns_raw"] = _dns_compressed_names_raw_spec()
        return
    if "name-records-compressed" in key:
        # Compressed NS/CNAME/PTR input: the Scapy reference owns hand-built
        # bytes whose owner and RDATA names are compression pointers, and
        # libcrafter normalizes to the same uncompressed DnsRecordData::Name
        # model on decode. Checked before the uncompressed name-records branch
        # because that token is a substring of this one.
        fields.clear()
        fields["dns_raw"] = _dns_name_records_compressed_raw_spec()
        return
    if "raw-unknown-records" in key:
        # A response carrying record types this crate intentionally keeps as
        # DnsRecordData::Raw: an unknown private-use numeric TYPE plus the
        # deferred NSEC3PARAM (51), TLSA (52), KEY (25), and NAPTR (35) types
        # from docs/guide/dns.md. Each RDATA is a deterministic opaque blob carried as
        # hex so neither backend reinterprets it, and the TYPE is given as a
        # numeric IANA codepoint so both the Scapy DNSRR(type=N) reference and the
        # libcrafter DnsRecordData::Raw materializer agree byte-for-byte. The
        # owner names, TTLs, and IN class are stable. libcrafter must decode every
        # answer to DnsRecordData::Raw (never a mis-typed record) and recompile the
        # same RDATA bytes. (raw-unknown-records is not a substring of any other
        # case id, so the matcher resolves this branch unambiguously.)
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["authoritative"]
        fields["questions"] = [{"qname": "example.com.", "qtype": 65280}]
        fields["answers"] = [
            {
                # Private-use unknown TYPE 65280 (RFC 6895 Section 3.1): no named
                # mapping on either backend; preserved as a numeric codepoint.
                "name": "unknown.example.com.",
                "type": 65280,
                "ttl": 3600,
                "data": {"hex": "deadbeef"},
            },
            {
                # NSEC3PARAM (51): deferred to Raw (docs/guide/dns.md). Bytes look like a
                # plausible NSEC3PARAM RDATA but are never parsed into typed fields.
                "name": "example.com.",
                "type": 51,
                "ttl": 300,
                "data": {"hex": "0100000a04aabbccdd"},
            },
            {
                # TLSA (52): deferred certificate-association record, kept Raw.
                "name": "_443._tcp.example.com.",
                "type": 52,
                "ttl": 300,
                "data": {"hex": "030101a1b2c3d4e5f6"},
            },
            {
                # KEY (25): cryptographic-key transport type, kept Raw.
                "name": "example.com.",
                "type": 25,
                "ttl": 300,
                "data": {"hex": "010003080a0b0c0d"},
            },
            {
                # NAPTR (35): deferred naming-authority-pointer record, kept Raw.
                "name": "example.com.",
                "type": 35,
                "ttl": 300,
                "data": {"hex": "0064000a0153000455524c00"},
            },
        ]
        return
    if "dnssec-ds-dnskey-rrsig" in key:
        # An authoritative response carrying the three core DNSSEC delegation and
        # signature records (RFC 4034) with raw numeric fields and opaque
        # key/digest/signature material that neither backend interprets
        # cryptographically. The DS RDATA is Key Tag, Algorithm, Digest Type, and
        # Digest (Section 5.1); the DNSKEY RDATA is Flags, Protocol, Algorithm,
        # and Public Key (Section 2.1); the RRSIG RDATA is Type Covered,
        # Algorithm, Labels, Original TTL, Signature Expiration, Signature
        # Inception, Key Tag, the uncompressed Signer's Name, and the Signature
        # (Section 3.1). Every name is uncompressed and the records use stable
        # values, so both backends agree byte-for-byte in both directions.
        # (dnssec-ds-dnskey-rrsig is not a substring of any other case id, so the
        # dispatcher resolves this branch unambiguously.)
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["authoritative"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "DS"}]
        fields["answers"] = [
            {
                # DS: Key Tag 12345, Algorithm 8 (RSASHA256), Digest Type 2
                # (SHA-256), and a 32-octet opaque digest.
                "name": "example.com.",
                "type": "DS",
                "class": "IN",
                "ttl": 3600,
                "key_tag": 12345,
                "algorithm": 8,
                "digest_type": 2,
                "digest": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            },
            {
                # DNSKEY: Flags 257 (Zone Key + SEP), Protocol 3, Algorithm 8, and
                # an opaque public-key blob.
                "name": "example.com.",
                "type": "DNSKEY",
                "class": "IN",
                "ttl": 3600,
                "flags": 257,
                "protocol": 3,
                "algorithm": 8,
                "public_key": "03010001deadbeefcafebabe",
            },
            {
                # RRSIG over the DS RRset: every fixed field carries a stable raw
                # value, the Signer's Name is uncompressed example.com., and the
                # signature is opaque bytes.
                "name": "example.com.",
                "type": "RRSIG",
                "class": "IN",
                "ttl": 3600,
                "type_covered": "DS",
                "algorithm": 8,
                "labels": 2,
                "original_ttl": 3600,
                "signature_expiration": 0x65005D00,
                "signature_inception": 0x645E0B80,
                "key_tag": 12345,
                "signer_name": "example.com.",
                "signature": "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
            },
        ]
        return
    if "dnssec-nsec-bitmaps" in key:
        # An authoritative response carrying two NSEC (type 47) answers whose
        # Type Bit Maps (RFC 4034 Section 4.1.2) exercise the full encoder:
        #
        #   * the first answer mirrors the RFC 4034 Section 4.3 example owner
        #     alfa.example.com. with next name host.example.com. and the present
        #     types A (1), MX (15), RRSIG (46), NSEC (47), and the unknown
        #     codepoint TYPE1234, which spans window block 0 and window block 4;
        #   * the second answer feeds an UNSORTED list with a DUPLICATE entry
        #     spanning three window blocks so that the libcrafter
        #     DnsTypeBitmaps::from_types sort/de-dup and the Scapy DNSRRNSEC
        #     RRlist2bitmap normalization both collapse to the same minimal,
        #     window-ordered encoding.
        #
        # Both backends sort, de-duplicate, and emit minimal windows, so the
        # decoded type set agrees in both directions even though the second
        # answer's source order is deliberately scrambled. The reference-built
        # bytes therefore match the RFC-style minimal encoding, and the
        # libcrafter-built bytes verify the sorted output. (dnssec-nsec-bitmaps
        # is dispatched here before the shorter dnssec-nsec / dnssec-nsec-bitmap
        # substrings, so resolution stays deterministic.)
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["authoritative"]
        fields["questions"] = [{"qname": "alfa.example.com.", "qtype": "NSEC"}]
        fields["answers"] = [
            {
                # RFC 4034 Section 4.3 NSEC example: window 0 (A, MX, RRSIG,
                # NSEC) plus window 4 (the unknown codepoint TYPE1234). The
                # neutral type names and the bare numeric codepoint map to the
                # same RR-type values on both backends.
                "name": "alfa.example.com.",
                "type": "NSEC",
                "class": "IN",
                "ttl": 86400,
                "next_name": "host.example.com.",
                "type_bitmaps": ["A", "MX", "RRSIG", "NSEC", 1234],
            },
            {
                # Unsorted input with a duplicate A (1) entry spanning window
                # blocks 0, 1, and 255 (codepoints 0xff01). libcrafter sorts and
                # de-duplicates on construction and Scapy normalizes identically,
                # so the minimal, window-ordered encoding is deterministic.
                "name": "host.example.com.",
                "type": "NSEC",
                "class": "IN",
                "ttl": 86400,
                "next_name": "alfa.example.com.",
                "type_bitmaps": [47, 1, 300, 1, 0xFF01, 15],
            },
        ]
        return
    if "dnssec-nsec3" in key:
        # An authoritative response carrying three NSEC3 (type 50) answers whose
        # RDATA exercises the full RFC 5155 Section 3.2 wire layout: Hash
        # Algorithm, Flags, Iterations, Salt Length + Salt, Hash Length + next
        # hashed owner name, then Type Bit Maps. NSEC3 hash, salt, and next
        # hashed owner material is wire data only; libcrafter preserves the bytes
        # and never validates DNSSEC cryptography.
        #
        #   * answer 1 uses a NON-EMPTY salt, a non-empty next hashed owner name,
        #     and MULTIPLE type bitmap entries (A, NS, SOA, RRSIG, DNSKEY) in a
        #     single window block;
        #   * answer 2 uses an EMPTY salt (Salt Length 0 omits the Salt field)
        #     with a different next hashed owner name and a small bitmap;
        #   * answer 3 uses an UNKNOWN hash algorithm value (0xfe) and an UNKNOWN
        #     high type bitmap codepoint (TYPE65280) spanning a later window block,
        #     proving the numeric fields and minimal window encoding survive.
        #
        # Salt and next hashed owner are carried as hex blobs so both backends
        # preserve the exact octets as bytes, not text. The Scapy DNSRRNSEC3
        # reference and the libcrafter DnsRecord::nsec3 materializer produce the
        # same uncompressed bytes, so the case is strict-byte in both directions.
        # (dnssec-nsec3 is dispatched here, after dnssec-nsec-bitmaps and before
        # any shorter dnssec-nsec substring branch, so resolution is
        # deterministic.)
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["authoritative"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "NSEC3"}]
        fields["answers"] = [
            {
                # Non-empty salt, non-empty next hashed owner name, and multiple
                # type bitmap entries in a single window block.
                "name": "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.com.",
                "type": "NSEC3",
                "class": "IN",
                "ttl": 86400,
                "hash_algorithm": 1,  # SHA-1
                "flags": 1,  # Opt-Out
                "iterations": 12,
                "salt": {"hex": "aabbccdd"},
                "next_hashed_owner": {
                    "hex": "1112131415161718191a1b1c1d1e1f2021222324"
                },
                "type_bitmaps": ["A", "NS", "SOA", "RRSIG", "DNSKEY"],
            },
            {
                # Empty salt: Salt Length 0 omits the Salt field entirely.
                "name": "2vptu5timamqttgl4luu9kg21e0aor3s.example.com.",
                "type": "NSEC3",
                "class": "IN",
                "ttl": 86400,
                "hash_algorithm": 1,
                "flags": 0,
                "iterations": 0,
                "salt": {"hex": ""},
                "next_hashed_owner": {
                    "hex": "25262728292a2b2c2d2e2f30313233343536373839"
                },
                "type_bitmaps": ["A", "RRSIG"],
            },
            {
                # Unknown hash algorithm value and an unknown high type bitmap
                # codepoint spanning a later window block; both stay raw numeric
                # wire data.
                "name": "th1q5pl8ku5b8c98er8gj7p9hf2d8jcm.example.com.",
                "type": "NSEC3",
                "class": "IN",
                "ttl": 86400,
                "hash_algorithm": 0xFE,  # unassigned hash algorithm
                "flags": 0,
                "iterations": 2500,
                "salt": {"hex": "deadbeef"},
                "next_hashed_owner": {
                    "hex": "393a3b3c3d3e3f404142434445464748494a4b4c"
                },
                "type_bitmaps": ["A", "RRSIG", 65280],
            },
        ]
        return
    if "svcb-https" in key:
        # An authoritative response carrying one answer per SVCB/HTTPS
        # service-binding shape (RFC 9460 / RFC 9461). Every SvcParamValue is
        # opaque wire data carried verbatim through both backends; the Scapy
        # reference owns the exact RDATA bytes and libcrafter materializes the
        # same bytes through DnsRecord::svcb / ::https and SvcParams, so the case
        # is strict-byte in both directions. The third answer feeds params in a
        # deliberately scrambled key order; both the libcrafter SvcParams
        # constructor and the reference RDATA builder sort the params into
        # strictly increasing SvcParamKey order, so the encoded output is
        # deterministic regardless of source order. Values:
        #   * mandatory (0): the two-octet SvcParamKey list [alpn(1), port(3)];
        #   * alpn (1): the length-prefixed ALPN id list "h2"/"h3-29";
        #   * no-default-alpn (2): an empty value;
        #   * port (3): the 16-bit port in network byte order;
        #   * ipv4hint (4): two concatenated documentation IPv4 addresses;
        #   * ipv6hint (6): one documentation IPv6 address;
        #   * dohpath (7): the RFC 9461 DoH URI template as UTF-8 octets;
        #   * an unknown SvcParamKey (65280): opaque bytes preserved verbatim.
        # (svcb-https is dispatched here before any shorter dns-svcb / dns-https
        # substring branch, so resolution stays deterministic.)
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["authoritative"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "HTTPS"}]
        fields["answers"] = [
            {
                # SVCB AliasMode: SvcPriority 0 with a real (non-root) target and
                # an empty SvcParams list (RFC 9460 Section 2.4.2).
                "name": "example.com.",
                "type": "SVCB",
                "class": "IN",
                "ttl": 3600,
                "priority": 0,
                "target": "foo.example.com.",
                "params": [],
            },
            {
                # HTTPS ServiceMode: non-zero SvcPriority with a root target and
                # the full named SvcParam set, listed out of key order to prove
                # the deterministic sort. mandatory lists alpn(1) and port(3).
                "name": "example.com.",
                "type": "HTTPS",
                "class": "IN",
                "ttl": 7200,
                "priority": 1,
                "target": ".",
                "params": [
                    {"key": "ipv6hint", "value": {"hex": "20010db8000000000000000000000001"}},
                    {"key": "port", "value": {"hex": "01bb"}},
                    {"key": "alpn", "value": {"hex": "0268320568332d3239"}},
                    {"key": "mandatory", "value": {"hex": "00010003"}},
                    {"key": "no-default-alpn", "value": {"hex": ""}},
                    {"key": "dohpath", "value": {"hex": "2f646e732d71756572797b3f646e737d"}},
                    {"key": "ipv4hint", "value": {"hex": "c0000201c000020a"}},
                ],
            },
            {
                # SVCB ServiceMode with a non-root target carrying an unknown
                # SvcParamKey (65280, RFC 6895 private use) plus a named param, so
                # an unrecognized key still round trips byte-for-byte as opaque
                # bytes alongside a known key.
                "name": "svc.example.com.",
                "type": "SVCB",
                "class": "IN",
                "ttl": 60,
                "priority": 16,
                "target": "svc.example.net.",
                "params": [
                    {"key": 65280, "value": {"hex": "deadbeef"}},
                    {"key": "no-default-alpn", "value": {"hex": ""}},
                ],
            },
        ]
        return
    if "section-placement" in key:
        # A single authoritative response whose records each land in their own
        # DNS section (RFC 1035 Section 4.1.1): one question (QDCOUNT), one A
        # answer (ANCOUNT), one NS authority record (NSCOUNT), and two additional
        # records (ARCOUNT) -- an EDNS(0) OPT pseudo-record (RFC 6891) plus a
        # non-OPT A record. Both backends materialize the answer, authority, and
        # additional sections from independent plan keys, so the case proves that
        # placement and counts survive decode and recompile and that no record
        # migrates between sections. Every value is stable and uncompressed, so
        # the encoded bytes agree in both directions. ("section-placement" is a
        # substring only of this case id, so the dispatcher resolves this branch
        # unambiguously.)
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["authoritative"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "A"}]
        fields["answers"] = [
            {
                # Answer section: the requested A record.
                "name": "example.com.",
                "type": "A",
                "class": "IN",
                "ttl": 3600,
                "address": "192.0.2.10",
            },
        ]
        fields["authority"] = [
            {
                # Authority section: an NS record delegating the zone.
                "name": "example.com.",
                "type": "NS",
                "class": "IN",
                "ttl": 3600,
                "target": "ns1.example.com.",
            },
        ]
        fields["additional"] = [
            {
                # Additional section: the glue A record for the authority NS.
                "name": "ns1.example.com.",
                "type": "A",
                "class": "IN",
                "ttl": 3600,
                "address": "192.0.2.53",
            },
            {
                # Additional section: an EDNS(0) OPT pseudo-record (RFC 6891) with
                # a root owner name, a non-default UDP payload size, and an empty
                # option list.
                "name": ".",
                "type": "OPT",
                "udp_payload_size": 1232,
                "extended_rcode": 0,
                "version": 0,
                "dnssec_ok": False,
                "options": [],
            },
        ]
        fields.pop("authorities", None)
        fields.pop("additionals", None)
        return
    if "header-flags-opcodes" in key:
        fields["is_response"] = True
        fields["opcode"] = "status"
        fields["response_code"] = "refused"
        fields["flags"] = [
            "authoritative",
            "truncated",
            "recursion_available",
            "authentic_data",
            "checking_disabled",
        ]
        fields.pop("answers", None)
        return
    if "header-empty-sections" in key:
        # Empty answer/authority/additional sections so the auto-filled counts
        # stay zero while the single question keeps QDCOUNT at one.
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["recursion_available"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "A"}]
        fields.pop("answers", None)
        fields.pop("authority", None)
        fields.pop("authorities", None)
        fields.pop("additional", None)
        fields.pop("additionals", None)
        return
    if "header-counts" in key:
        # One record in each of the three response sections so the encoder
        # auto-fills ANCOUNT/NSCOUNT/ARCOUNT to nonzero values from the typed
        # vectors rather than from any user-set count field.
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["authoritative", "recursion_available"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "A"}]
        fields["answers"] = [
            {"name": "example.com.", "type": "A", "ttl": 60, "address": "192.0.2.10"}
        ]
        fields["authority"] = [
            {"name": "example.com.", "type": "NS", "ttl": 300, "target": "ns1.example.com."}
        ]
        fields["additional"] = [
            {"name": "ns1.example.com.", "type": "A", "ttl": 300, "address": "192.0.2.53"}
        ]
        return
    if "header-raw-flags" in key:
        # Reserved Z header bit set through the raw-flags escape hatch; the
        # encoder must preserve a bit that has no named setter.
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["reserved_z"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "A"}]
        fields.pop("answers", None)
        return
    if "header-opcode" in key:
        # A non-default named opcode on a plain query; STATUS keeps the message
        # otherwise minimal so the four opcode bits are the load-bearing field.
        fields["is_response"] = False
        fields["opcode"] = "status"
        fields["response_code"] = "no_error"
        fields["flags"] = ["recursion_desired"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "A"}]
        fields.pop("answers", None)
        return
    if "header-rcode" in key:
        # A named rcode on a response; REFUSED is representable in both
        # materializers and exercises the low four flag-word bits.
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "refused"
        fields["flags"] = ["recursion_available"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "A"}]
        fields.pop("answers", None)
        return
    if "header-flags" in key:
        # Every named header flag bit set on a recursive query so each flag is
        # exercised independently of opcode/rcode.
        fields["is_response"] = False
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = [
            "authoritative",
            "truncated",
            "recursion_desired",
            "recursion_available",
            "authentic_data",
            "checking_disabled",
        ]
        fields["questions"] = [{"qname": "example.com.", "qtype": "A"}]
        fields.pop("answers", None)
        return
    if "header-qr" in key:
        # Response-bit set with recursion-available, the canonical server reply
        # header shape, paired with the matching query via the QR bit.
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["recursion_available"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "A"}]
        fields.pop("answers", None)
        return
    if "header-id" in key:
        # Nonzero transaction ID on an otherwise plain query so the 16-bit ID
        # field is the load-bearing header value.
        fields["is_response"] = False
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["recursion_desired"]
        fields["transaction_id"] = 0x1A2B
        fields["questions"] = [{"qname": "example.com.", "qtype": "A"}]
        fields.pop("answers", None)
        return
    if "name-root-escaped" in key:
        # Byte-preserving name shapes in one message: the root name as the
        # question owner, a trailing-dot text answer name, a CNAME target that
        # carries literal dot and backslash octets via the RFC 1035 Section 5.1
        # \DDD escape, and a PTR target whose label is a non-UTF-8 byte run
        # (\000 and \255). The libcrafter materializer parses these presentation
        # strings back into the exact wire octets, so the decoded header/section
        # model agrees in both directions. The compared subset is header plus
        # section counts, so the special label octets never need a lossless
        # Scapy high-level encode; the faithful byte-preserving assertions live
        # in the crate name tests.
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["recursion_available"]
        fields["questions"] = [{"qname": ".", "qtype": "A"}]
        fields["answers"] = [
            {"name": "example.com.", "type": "A", "ttl": 60, "address": "192.0.2.10"},
            {
                "name": "trailing.example.com.",
                "type": "CNAME",
                "ttl": 300,
                # Literal '.' (\046) and '\' (\092) inside a single label.
                "target": "lit\\046dot\\092slash.example.com.",
            },
            {
                "name": "ptr.example.com.",
                "type": "PTR",
                "ttl": 300,
                # Non-UTF-8 label: NUL (\000) and 0xff (\255) octets.
                "target": "\\000\\255.example.com.",
            },
        ]
        return
    if "record-soa" in key:
        # Focused single-SOA response so a SOA decode failure reproduces without
        # the SRV answer in the message. Every fixed SOA field carries a distinct
        # nonzero value (SERIAL, REFRESH, RETRY, EXPIRE, MINIMUM) and both nested
        # names (MNAME, RNAME) are documentation names, so the strict byte encode
        # pins each field against the Scapy reference. Checked before the combined
        # soa-srv-records branch; the focused id never contains that token.
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["authoritative"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "SOA"}]
        fields["answers"] = [
            {
                "name": "example.com.",
                "type": "SOA",
                "ttl": 300,
                "primary_name": "ns1.example.com.",
                "responsible_name": "hostmaster.example.com.",
                "serial": 2024010101,
                "refresh": 7200,
                "retry": 3600,
                "expire": 1209600,
                "minimum": 300,
            }
        ]
        return
    if "record-srv" in key:
        # Focused single-SRV response so an SRV decode failure reproduces without
        # the SOA answer. The three fixed 16-bit fields (priority, weight, port)
        # are distinct nonzero values and the target is a documentation name, so
        # the strict byte encode pins every SRV field against the Scapy reference.
        # Checked before the combined soa-srv-records branch; the focused id never
        # contains that token.
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["authoritative"]
        fields["questions"] = [{"qname": "_sip._tcp.example.com.", "qtype": "SRV"}]
        fields["answers"] = [
            {
                "name": "_sip._tcp.example.com.",
                "type": "SRV",
                "ttl": 60,
                "priority": 10,
                "weight": 60,
                "port": 5060,
                "target": "sip.example.com.",
            }
        ]
        return
    if "soa-srv-records" in key:
        # A response carrying one SOA authority-style answer and one SRV answer
        # so the libcrafter materializer exercises both typed record builders in
        # a single message and compares against the Scapy reference.
        fields["is_response"] = True
        fields["questions"] = [{"qname": "example.com.", "qtype": "SOA"}]
        fields["answers"] = [
            {
                "name": "example.com.",
                "type": "SOA",
                "ttl": 300,
                "primary_name": "ns1.example.com.",
                "responsible_name": "hostmaster.example.com.",
                "serial": 2024010101,
                "refresh": 7200,
                "retry": 3600,
                "expire": 1209600,
                "minimum": 300,
            },
            {
                "name": "_sip._tcp.example.com.",
                "type": "SRV",
                "ttl": 60,
                "priority": 10,
                "weight": 60,
                "port": 5060,
                "target": "sip.example.com.",
            },
        ]
        return
    if "a-aaaa-records" in key:
        # An authoritative response carrying A and AAAA answers for the same
        # owner name, with stable TTLs and documentation IPv4/IPv6 addresses.
        # The two answers are ordered AAAA before A so the case also exercises a
        # non-canonical answer ordering; both materializers must preserve the
        # supplied order and emit identical uncompressed names so the encode is
        # byte-exact in both directions.
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["authoritative", "recursion_available"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "A"}]
        fields["answers"] = [
            {
                "name": "host.example.com.",
                "type": "AAAA",
                "ttl": 3600,
                "address": "2001:db8:1::10",
            },
            {
                "name": "host.example.com.",
                "type": "A",
                "ttl": 3600,
                "address": "192.0.2.10",
            },
            {
                "name": "alt.example.net.",
                "type": "A",
                "ttl": 300,
                "address": "198.51.100.20",
            },
            {
                "name": "alt.example.net.",
                "type": "AAAA",
                "ttl": 300,
                "address": "2001:db8:2::20",
            },
        ]
        return
    if "name-records" in key:
        # An authoritative response carrying NS, CNAME, and PTR answers. NS,
        # CNAME, and PTR all carry their RDATA as a single nested <domain-name>,
        # so all three map to DnsRecordData::Name and must match Scapy in both
        # the record owner and the RDATA name. The CNAME target is root-adjacent
        # (a single label directly under the root) and the PTR owner is a
        # reverse-DNS name, so the case spans ordinary and boundary name shapes.
        # Both materializers emit every name uncompressed, so the encode is
        # byte-exact in both directions. The compressed companion is the separate
        # dns-name-records-compressed case. (Checked after name-records-compressed,
        # which returns early at the top of this dispatcher.)
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["authoritative"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "NS"}]
        fields["answers"] = [
            {
                "name": "example.com.",
                "type": "NS",
                "ttl": 3600,
                "target": "ns1.example.com.",
            },
            {
                "name": "www.example.com.",
                "type": "CNAME",
                "ttl": 300,
                # Root-adjacent target: a single label directly under the root.
                "target": "host.example.",
            },
            {
                "name": "20.113.0.203.in-addr.arpa.",
                "type": "PTR",
                "ttl": 300,
                "target": "host.example.com.",
            },
        ]
        return
    if "mx-txt-records" in key:
        # A response carrying one MX answer and a sequence of TXT answers so a
        # single message exercises the MX preference + nested exchange name plus
        # every TXT character-string shape libcrafter must preserve: one string,
        # multiple strings, an empty string, a non-UTF-8 binary string (carried
        # as hex so neither materializer mangles the octets), and a single
        # string at the 255-octet length boundary. Both materializers emit
        # uncompressed names and exact-length character-strings, so the encode is
        # byte-exact in both directions.
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["authoritative", "recursion_available"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "MX"}]
        fields["answers"] = [
            {
                "name": "example.com.",
                "type": "MX",
                "ttl": 3600,
                "preference": 10,
                "exchange": "mail.example.com.",
            },
            {
                "name": "example.com.",
                "type": "TXT",
                "ttl": 300,
                "strings": ["v=spf1 -all"],
            },
            {
                "name": "example.com.",
                "type": "TXT",
                "ttl": 300,
                "strings": ["first chunk", "second chunk"],
            },
            {
                "name": "empty.example.com.",
                "type": "TXT",
                "ttl": 300,
                "strings": [""],
            },
            {
                "name": "bin.example.com.",
                "type": "TXT",
                "ttl": 300,
                # Non-UTF-8 octets (NUL, 0xfe, 0xff, DEL) carried as hex so the
                # character-string bytes survive both materializers verbatim.
                "strings": [{"hex": "000a1ffeff617f"}],
            },
            {
                "name": "max.example.com.",
                "type": "TXT",
                "ttl": 300,
                # A single character-string at the 255-octet length boundary.
                "strings": [{"hex": "78" * 255}],
            },
        ]
        return
    if "multi-question-classes" in key:
        # A single query carrying several questions in a deterministic order that
        # exercise the QTYPE and QCLASS axes together: named QTYPEs (A, AAAA, MX,
        # TXT, ANY) and a private unknown numeric QTYPE, paired with every named
        # QCLASS (IN, CH, HS, NONE, ANY) and a private unknown numeric QCLASS.
        # Section counts must auto-fill QDCOUNT from this questions vector, and
        # both materializers must preserve the unknown numeric codepoints.
        fields["is_response"] = False
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["recursion_desired"]
        fields["questions"] = [
            {"qname": "example.com.", "qtype": "A", "qclass": "IN"},
            {"qname": "example.net.", "qtype": "AAAA", "qclass": "CH"},
            {"qname": "mail.example.com.", "qtype": "MX", "qclass": "HS"},
            {"qname": "txt.example.com.", "qtype": "TXT", "qclass": "NONE"},
            {"qname": "any.example.com.", "qtype": "ANY", "qclass": "ANY"},
            # Private-use QTYPE 65280 (RFC 6895 Section 3.1) and QCLASS 65280
            # (RFC 6895 Section 3.2) as raw numeric codepoints neither backend
            # maps to a named type or class.
            {"qname": "unknown.example.com.", "qtype": 65280, "qclass": 65280},
        ]
        fields.pop("answers", None)
        return
    if "edns-options" in key:
        # A response carrying a single EDNS(0) OPT pseudo-record (RFC 6891
        # Section 6.1) whose RDATA holds an ordered list of option TLVs
        # (Section 6.1.2). The matrix spans the three source-backed options with
        # named constructors (NSID RFC 5001, COOKIE RFC 7873, Padding RFC 7830),
        # one option that has a registry mnemonic but no named constructor (DAU
        # RFC 6975, code 5), and one unknown option code (65534) that has no
        # mnemonic at all. The option order is fixed so the encoded byte stream
        # is deterministic, and every OPTION-DATA payload is carried as raw hex
        # so neither backend reinterprets the per-option bit field: Scapy emits
        # each as a generic EDNS0TLV(optcode=N, optdata=...) and libcrafter
        # carries each as an EdnsOption preserving the exact code and data bytes.
        # ("edns-options" is a substring only of this case id, never of
        # dns-edns-opt-basic, so the dispatcher resolves this branch
        # unambiguously and before the edns-opt-basic branch below.)
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["recursion_available"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "A"}]
        fields.pop("answers", None)
        fields["additional"] = [
            {
                "name": ".",
                "type": "OPT",
                "udp_payload_size": 4096,
                "extended_rcode": 0,
                "version": 0,
                "dnssec_ok": True,
                "options": [
                    # NSID (code 3): opaque name-server identifier bytes.
                    {"option_code": 3, "option_data": "6e733031"},
                    # COOKIE (code 10): an 8-octet client cookie.
                    {"option_code": 10, "option_data": "0102030405060708"},
                    # Padding (code 12): zero octets used only for size padding.
                    {"option_code": 12, "option_data": "0000000000000000"},
                    # DAU (code 5): a registered option with a mnemonic but no
                    # named libcrafter constructor; raw algorithm-list bytes.
                    {"option_code": 5, "option_data": "0501080a"},
                    # Unknown option code 65534: no IANA mnemonic, preserved as
                    # opaque bytes.
                    {"option_code": 65534, "option_data": "cafe"},
                ],
            },
        ]
        return
    if "edns-opt-basic" in key:
        # A response carrying several EDNS(0) OPT pseudo-records in the additional
        # section (RFC 6891 Section 6.1). Each OPT exercises a different basic
        # field combination so a regression in any one packed field reproduces in
        # isolation: the UDP payload size lives in the OPT CLASS, while the
        # extended RCODE, EDNS version, and DO flag are packed into the OPT TTL.
        # The owner name is always root ("."), the option list is empty (the
        # option-TLV matrix is the separate dns-edns-options-* cases), and every
        # value round trips byte-for-byte because both the Scapy DNSRROPT
        # reference and the libcrafter DnsRecord::opt builder pack the same wire
        # fields. (edns-opt-basic is a substring only of this case id, so the
        # dispatcher resolves this branch unambiguously.)
        fields["is_response"] = True
        fields["opcode"] = "query"
        fields["response_code"] = "no_error"
        fields["flags"] = ["recursion_available"]
        fields["questions"] = [{"qname": "example.com.", "qtype": "A"}]
        fields.pop("answers", None)
        fields["additional"] = [
            {
                # Bare OPT: default UDP payload size, no extended RCODE/version,
                # DO clear, empty option list.
                "name": ".",
                "type": "OPT",
                "udp_payload_size": 4096,
                "extended_rcode": 0,
                "version": 0,
                "dnssec_ok": False,
                "options": [],
            },
            {
                # Non-default small UDP payload size with the DO flag set.
                "name": ".",
                "type": "OPT",
                "udp_payload_size": 512,
                "extended_rcode": 0,
                "version": 0,
                "dnssec_ok": True,
                "options": [],
            },
            {
                # Non-zero extended RCODE (upper 8 bits of the 12-bit RCODE) on a
                # 1232-octet payload size, DO clear.
                "name": ".",
                "type": "OPT",
                "udp_payload_size": 1232,
                "extended_rcode": 0x12,
                "version": 0,
                "dnssec_ok": False,
                "options": [],
            },
            {
                # Maximum UDP payload size, a non-default EDNS version, DO set.
                "name": ".",
                "type": "OPT",
                "udp_payload_size": 65535,
                "extended_rcode": 0,
                "version": 1,
                "dnssec_ok": True,
                "options": [],
            },
        ]
        return
    if "response" in key:
        fields["is_response"] = True
        fields.pop("answers", None)
    if "multiple-questions" in key:
        fields["questions"] = [
            {"qname": "example.com.", "qtype": "A"},
            {"qname": "example.net.", "qtype": "AAAA"},
        ]
    if "truncated" in key:
        fields["flags"] = ["recursion_desired", "truncated"]
        fields["response_code"] = "server_failure"


def _dns_compressed_names_raw_spec() -> JSONObject:
    """Raw DNS spec with explicit compression pointers for the raw helper.

    The question name ``example.com.`` lands at the fixed offset 12 (right after
    the 12-octet header), so every compressed name in the message points back to
    offset 12. The case exercises a compressed question owner name (re-used as the
    first answer owner via a bare pointer) and a compression pointer in the
    embedded <domain-name> of each byte-preserving record type libcrafter
    decodes: CNAME/NS/PTR (name at RDATA start), MX (after the 2-octet
    preference), SOA (compressed MNAME and RNAME before the 20 fixed octets), SRV
    (after priority/weight/port), RRSIG signer (after the 18 fixed octets), NSEC
    next-domain (before the type bitmap), and SVCB/HTTPS target (after the 2-octet
    priority). Scapy's high-level fields will not emit these pointers, so the
    bytes are built by hand while staying under the Scapy reference backend.
    libcrafter re-encodes every name uncompressed, so this case is normalized: the
    decoded DNS name model agrees while the recompiled bytes differ from the
    pointer input (see specs/features/dns-behavior.yaml byte_policy).
    """

    ptr = 12  # The question name example.com. is at the fixed 12-octet offset.
    # The 20 fixed SOA octets after MNAME/RNAME: serial, refresh, retry, expire,
    # minimum (all 32-bit). The 18 fixed RRSIG octets: type covered (A=0x0001),
    # algorithm, labels, original TTL, expiration, inception, key tag. The NSEC
    # type bitmap is window 0, a 6-octet bitmap, with the A (1), RRSIG (46), and
    # NSEC (47) bits set.
    soa_fixed = "0000000100000e1000000708001baf8000000384"
    rrsig_fixed = "0001050200000e10655f5d00655e0b800539"
    nsec_bitmap = "0006400000000003"
    return {
        "transaction_id": 0x1234,
        "is_response": True,
        "flags": ["recursion_desired", "recursion_available"],
        "response_code": "no_error",
        "questions": [
            {"name": "example.com.", "type": "A", "class": "IN"},
        ],
        "answers": [
            # CNAME owner is a bare pointer to the question name; the RDATA target
            # is the label "alias" plus a pointer back to example.com.
            {
                "name_with_pointer": {"prefix": None, "pointer_offset": ptr},
                "type": "CNAME",
                "class": "IN",
                "ttl": 300,
                "target_with_pointer": {"prefix": "alias", "pointer_offset": ptr},
            },
            # NS RDATA is a bare pointer to the question name.
            {
                "name": "example.com.",
                "type": "NS",
                "class": "IN",
                "ttl": 300,
                "target_with_pointer": {"prefix": "ns1", "pointer_offset": ptr},
            },
            # PTR RDATA is a compressed name.
            {
                "name": "1.2.0.192.in-addr.arpa.",
                "type": "PTR",
                "class": "IN",
                "ttl": 300,
                "target_with_pointer": {"prefix": "host", "pointer_offset": ptr},
            },
            # MX exchange is a compressed name after the 2-octet preference (10).
            {
                "name": "example.com.",
                "type": "MX",
                "class": "IN",
                "ttl": 300,
                "rdata_with_pointer": {
                    "prefix_hex": "000a",
                    "pointers": [{"prefix": "mail", "pointer_offset": ptr}],
                },
            },
            # SOA MNAME and RNAME are both compression pointers before 20 fixed
            # octets.
            {
                "name": "example.com.",
                "type": "SOA",
                "class": "IN",
                "ttl": 300,
                "rdata_with_pointer": {
                    "pointers": [
                        {"prefix": "ns1", "pointer_offset": ptr},
                        {"prefix": "hostmaster", "pointer_offset": ptr},
                    ],
                    "suffix_hex": soa_fixed,
                },
            },
            # SRV target is a compressed name after priority/weight/port.
            {
                "name": "_sip._tcp.example.com.",
                "type": "SRV",
                "class": "IN",
                "ttl": 300,
                "rdata_with_pointer": {
                    "prefix_hex": "000a0005162c",
                    "pointers": [{"prefix": "sip", "pointer_offset": ptr}],
                },
            },
            # RRSIG signer name is a compression pointer after the 18 fixed
            # octets; the remaining bytes are an opaque signature blob.
            {
                "name": "example.com.",
                "type": "RRSIG",
                "class": "IN",
                "ttl": 300,
                "rdata_with_pointer": {
                    "prefix_hex": rrsig_fixed,
                    "pointers": [{"prefix": None, "pointer_offset": ptr}],
                    "suffix_hex": "abcdef0123456789",
                },
            },
            # NSEC next-domain name is a compression pointer before the type
            # bitmap window.
            {
                "name": "example.com.",
                "type": "NSEC",
                "class": "IN",
                "ttl": 300,
                "rdata_with_pointer": {
                    "pointers": [{"prefix": "next", "pointer_offset": ptr}],
                    "suffix_hex": nsec_bitmap,
                },
            },
            # SVCB target is a compression pointer after the 2-octet priority.
            {
                "name": "_dns.example.com.",
                "type": "SVCB",
                "class": "IN",
                "ttl": 300,
                "rdata_with_pointer": {
                    "prefix_hex": "0001",
                    "pointers": [{"prefix": "svc", "pointer_offset": ptr}],
                },
            },
            # HTTPS target is a compression pointer after the 2-octet priority.
            {
                "name": "example.com.",
                "type": "HTTPS",
                "class": "IN",
                "ttl": 300,
                "rdata_with_pointer": {
                    "prefix_hex": "0001",
                    "pointers": [{"prefix": None, "pointer_offset": ptr}],
                },
            },
        ],
    }


def _dns_name_records_compressed_raw_spec() -> JSONObject:
    """Raw DNS spec for the compressed NS/CNAME/PTR name-records case.

    The question name ``example.com.`` is at the fixed 12-octet offset, so every
    owner and embedded RDATA name in this message is a compression pointer back
    to offset 12. NS, CNAME, and PTR all carry their RDATA as a single nested
    <domain-name> at the start of the RDATA, so each answer's target is a label
    prefix plus a pointer to the question name. Scapy's high-level fields will not
    emit these pointers, so the bytes are built by hand under the Scapy reference
    backend; libcrafter follows each pointer on decode and re-encodes every name
    uncompressed, so this case is normalized and matches the uncompressed
    ``dns-name-records`` decoded DnsRecordData::Name model.
    """

    ptr = 12  # The question name example.com. is at the fixed 12-octet offset.
    return {
        "transaction_id": 0x4E43,
        "is_response": True,
        "flags": ["authoritative"],
        "response_code": "no_error",
        "questions": [
            {"name": "example.com.", "type": "NS", "class": "IN"},
        ],
        "answers": [
            # NS owner is a bare pointer to the question name; the RDATA target is
            # the label "ns1" plus a pointer back to example.com.
            {
                "name": "example.com.",
                "type": "NS",
                "class": "IN",
                "ttl": 3600,
                "target_with_pointer": {"prefix": "ns1", "pointer_offset": ptr},
            },
            # CNAME owner is "www" plus a pointer; the RDATA target is "host"
            # plus a pointer back to example.com.
            {
                "name_with_pointer": {"prefix": "www", "pointer_offset": ptr},
                "type": "CNAME",
                "class": "IN",
                "ttl": 300,
                "target_with_pointer": {"prefix": "host", "pointer_offset": ptr},
            },
            # PTR owner is "ptr" plus a pointer; the RDATA target is "host" plus a
            # pointer back to example.com.
            {
                "name_with_pointer": {"prefix": "ptr", "pointer_offset": ptr},
                "type": "PTR",
                "class": "IN",
                "ttl": 300,
                "target_with_pointer": {"prefix": "host", "pointer_offset": ptr},
            },
        ],
    }


def _dns_answers_for_domain(ctx: _SamplingContext, domain: object) -> list[JSONObject]:
    if domain == "aaaa":
        return [{"name": "example.net.", "type": "AAAA", "ttl": 60, "address": ctx.dst_ipv6}]
    if domain == "cname":
        return [{"name": "example.org.", "type": "CNAME", "ttl": 60, "target": "alias.example.org."}]
    return [{"name": "example.com.", "type": "A", "ttl": 60, "address": ctx.dst_ipv4}]


def _apply_behavior(
    fields: dict[str, JSONObject],
    *,
    stack: Sequence[str],
    feature: str,
    case: str,
    behavior: str,
    grammar: JSONObject | None = None,
) -> None:
    """Apply the ``dns_behavior`` feature behavior to the sampled DNS fields.

    Byte-identical to the legacy ``dns_behavior`` branch of
    ``generator._apply_feature_behavior``: it gated on ``"dns" in fields`` and ran
    ``_apply_dns_behavior(fields["dns"], ...)``, mutating the DNS-layer dict in
    place (clearing it for the raw-bytes cases, otherwise pinning header flags and
    section vectors per the selected case/behavior). ``grammar`` is part of the
    uniform ``apply_behavior`` call path (the TCP ``tcp_header`` behavior reads
    it); DNS does not consult it.
    """

    if "dns" in fields:
        _apply_dns_behavior(fields["dns"], case=case, behavior=behavior)


def _handles_feature(feature: str) -> bool:
    return feature == "dns_behavior"


register(
    ProtocolSampler(
        layer="dns",
        supported_fields=_SUPPORTED_FIELDS,
        sample=_sample,
        apply_behavior=_apply_behavior,
        handles_feature=_handles_feature,
    )
)
