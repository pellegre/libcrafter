"""Unit coverage for pcap eligibility byte-policy gating.

Pcap mode can only represent cases whose wire bytes are deterministic. A
``normalized`` case (for example a compressed-name input that libcrafter
re-encodes uncompressed) intentionally carries bytes that differ from the
libcrafter encode, and a ``structured_error`` case is malformed input; neither
is safely representable through a strict pcap roundtrip. These tests assert that
such cases are marked pcap-ineligible with an explicit skip reason -- never
silently dropped -- while ``strict_bytes`` cases stay eligible. The byte-policy
source is the spec ``supported_cases`` block, so the gating stays data-driven.

The suite is Scapy-free: it exercises eligibility metadata only.
"""

from __future__ import annotations

import unittest

from tools.oracle.engine.corpus import (
    SKIP_PCAP_LINK_TYPE_UNAVAILABLE,
    SKIP_PCAP_NORMALIZED_ONLY,
    SKIP_PCAP_STRUCTURED_ERROR,
    CorpusPacket,
    populate_corpus_eligibility,
)
from tools.oracle.engine.generator import case_byte_policy_index
from tools.oracle.engine.model import PacketPlan


_CASE_BYTE_POLICIES = {
    "dns-query": "strict_bytes",
    "dns-compressed-names": "normalized",
    "malformed-dns-pointer-cycle": "structured_error",
}


class CaseBytePolicyIndexTest(unittest.TestCase):
    def test_index_is_data_driven_from_supported_cases(self) -> None:
        index = case_byte_policy_index()

        # Representative cases from each policy class, read straight from specs.
        self.assertEqual(index.get("dns-query"), "strict_bytes")
        self.assertEqual(index.get("dns-compressed-names"), "normalized")
        self.assertEqual(
            index.get("malformed-dns-pointer-cycle"), "structured_error"
        )
        # Undeclared cases are absent, leaving prior eligibility behavior intact.
        self.assertNotIn("default", index)

    def test_index_classifies_at_least_one_case_per_policy(self) -> None:
        policies = set(case_byte_policy_index().values())

        self.assertIn("strict_bytes", policies)
        self.assertIn("normalized", policies)
        self.assertIn("structured_error", policies)


class PcapEligibilityBytePolicyTest(unittest.TestCase):
    def test_strict_bytes_case_is_pcap_eligible(self) -> None:
        packet = _eligibility_for("dns-query")

        self.assertTrue(packet.pcap.eligible)
        self.assertIsNone(packet.pcap.reason)
        self.assertEqual(packet.pcap.metadata["byte_policy"], "strict_bytes")

    def test_normalized_case_is_skipped_with_explicit_reason(self) -> None:
        packet = _eligibility_for("dns-compressed-names")

        self.assertFalse(packet.pcap.eligible)
        self.assertEqual(packet.pcap.reason, SKIP_PCAP_NORMALIZED_ONLY)
        self.assertIn(SKIP_PCAP_NORMALIZED_ONLY, packet.pcap.skip_reasons)
        self.assertEqual(packet.pcap.metadata["byte_policy"], "normalized")

    def test_structured_error_case_is_skipped_with_explicit_reason(self) -> None:
        packet = _eligibility_for("malformed-dns-pointer-cycle")

        self.assertFalse(packet.pcap.eligible)
        self.assertEqual(packet.pcap.reason, SKIP_PCAP_STRUCTURED_ERROR)
        self.assertIn(SKIP_PCAP_STRUCTURED_ERROR, packet.pcap.skip_reasons)
        self.assertEqual(packet.pcap.metadata["byte_policy"], "structured_error")

    def test_link_type_unavailable_still_skips_independently(self) -> None:
        # No pcap link type -> skipped regardless of byte policy.
        plan = _dns_plan("dns-query", root=None)
        [packet] = populate_corpus_eligibility(
            backend="scapy",
            packets=[CorpusPacket.from_plan(plan)],
            case_byte_policies=_CASE_BYTE_POLICIES,
        )

        self.assertFalse(packet.pcap.eligible)
        self.assertIn(SKIP_PCAP_LINK_TYPE_UNAVAILABLE, packet.pcap.skip_reasons)

    def test_default_loader_resolves_real_spec_policies(self) -> None:
        # Without an explicit map, the corpus loads byte policies from the specs.
        plan = _dns_plan("dns-compressed-names", root="l3:ipv4")
        [packet] = populate_corpus_eligibility(
            backend="scapy",
            packets=[CorpusPacket.from_plan(plan)],
            case_byte_policies=case_byte_policy_index(),
        )

        self.assertFalse(packet.pcap.eligible)
        self.assertEqual(packet.pcap.reason, SKIP_PCAP_NORMALIZED_ONLY)


def _eligibility_for(case: str) -> CorpusPacket:
    plan = _dns_plan(case, root="l3:ipv4")
    [packet] = populate_corpus_eligibility(
        backend="scapy",
        packets=[CorpusPacket.from_plan(plan)],
        case_byte_policies=_CASE_BYTE_POLICIES,
    )
    return packet


def _dns_plan(case: str, *, root: str | None) -> PacketPlan:
    metadata: dict[str, object] = {}
    if root is not None:
        metadata["root"] = root
    return PacketPlan(
        stack=["ipv4", "udp", "dns"],
        fields={"ipv4": {"src": "192.0.2.1", "dst": "192.0.2.2"}},
        profile="ci",
        seed=1,
        index=0,
        direction="reference_to_libcrafter",
        family="dns",
        case=case,
        metadata=metadata,
    )


if __name__ == "__main__":
    unittest.main()
