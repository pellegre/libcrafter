"""Unit coverage for live/wire eligibility byte-policy gating.

Live exchange is the two-machine packet writer/capture comparison: one endpoint
writes a packet, the other captures and decodes it. It can only validate cases
whose declared wire bytes are the bytes that travel. A ``normalized`` case (for
example a compressed-name input that libcrafter re-encodes uncompressed) only
agrees on the decoded model, not on the source's declared bytes, and a
``structured_error`` case is malformed input that must stay out of live
exchange. These tests assert that such cases are marked live-ineligible with an
explicit skip reason -- never silently dropped -- while ``strict_bytes`` cases
stay live-eligible. The byte-policy source is the spec ``supported_cases``
block, so the gating stays data-driven and never hardcodes a case list.

The suite is Scapy-free: it exercises wire eligibility metadata only.
"""

from __future__ import annotations

import unittest

from tools.oracle.engine.corpus import (
    SKIP_WIRE_NORMALIZED_ONLY,
    SKIP_WIRE_STRUCTURED_ERROR,
    CorpusPacket,
    populate_corpus_eligibility,
)
from tools.oracle.engine.generator import case_byte_policy_index
from tools.oracle.engine.model import PacketPlan


# A representative case per policy class. Values mirror the spec, but the tests
# also exercise the spec-loaded default below so the gating is proven end to end.
_CASE_BYTE_POLICIES = {
    "dns-query": "strict_bytes",
    "dns-compressed-names": "normalized",
    "malformed-dns-pointer-cycle": "structured_error",
}


class WireEligibilityBytePolicyTest(unittest.TestCase):
    def test_strict_bytes_case_is_live_eligible(self) -> None:
        packet = _eligibility_for("dns-query")

        self.assertTrue(packet.wire.eligible)
        self.assertNotIn(SKIP_WIRE_NORMALIZED_ONLY, packet.wire.skip_reasons)
        self.assertNotIn(SKIP_WIRE_STRUCTURED_ERROR, packet.wire.skip_reasons)
        self.assertEqual(packet.wire.metadata["byte_policy"], "strict_bytes")

    def test_normalized_case_is_skipped_with_explicit_reason(self) -> None:
        packet = _eligibility_for("dns-compressed-names")

        self.assertFalse(packet.wire.eligible)
        self.assertIn(SKIP_WIRE_NORMALIZED_ONLY, packet.wire.skip_reasons)
        self.assertEqual(packet.wire.metadata["byte_policy"], "normalized")

    def test_structured_error_case_is_skipped_with_explicit_reason(self) -> None:
        packet = _eligibility_for("malformed-dns-pointer-cycle")

        self.assertFalse(packet.wire.eligible)
        self.assertIn(SKIP_WIRE_STRUCTURED_ERROR, packet.wire.skip_reasons)
        self.assertEqual(packet.wire.metadata["byte_policy"], "structured_error")

    def test_default_loader_resolves_real_spec_policies(self) -> None:
        # Without an explicit map, the corpus loads byte policies from the specs;
        # a spec-declared normalized case is live-ineligible for the right reason.
        plan = _dns_plan("dns-dnssec-nsec-bitmap")
        [packet] = populate_corpus_eligibility(
            backend="scapy",
            packets=[CorpusPacket.from_plan(plan)],
            case_byte_policies=case_byte_policy_index(),
        )

        self.assertEqual(case_byte_policy_index().get("dns-dnssec-nsec-bitmap"), "normalized")
        self.assertFalse(packet.wire.eligible)
        self.assertIn(SKIP_WIRE_NORMALIZED_ONLY, packet.wire.skip_reasons)

    def test_undeclared_case_keeps_prior_eligibility(self) -> None:
        # A case absent from the byte-policy map is gated only by capabilities,
        # leaving the historical wire eligibility behavior intact.
        plan = _dns_plan("dns-query")
        [packet] = populate_corpus_eligibility(
            backend="scapy",
            packets=[CorpusPacket.from_plan(plan)],
            case_byte_policies={},
        )

        self.assertTrue(packet.wire.eligible)
        self.assertIsNone(packet.wire.metadata["byte_policy"])

    def test_both_directions_eligible_for_strict_bytes(self) -> None:
        # Live exchange runs strict_bytes DNS cases in both directions; eligibility
        # is direction-agnostic, so a strict_bytes plan is eligible regardless of
        # the direction stamped on it.
        for direction in ("libcrafter_to_reference", "reference_to_libcrafter"):
            plan = _dns_plan("dns-query", direction=direction)
            [packet] = populate_corpus_eligibility(
                backend="scapy",
                packets=[CorpusPacket.from_plan(plan)],
                case_byte_policies=_CASE_BYTE_POLICIES,
            )
            self.assertTrue(packet.wire.eligible, direction)


def _eligibility_for(case: str) -> CorpusPacket:
    plan = _dns_plan(case)
    [packet] = populate_corpus_eligibility(
        backend="scapy",
        packets=[CorpusPacket.from_plan(plan)],
        case_byte_policies=_CASE_BYTE_POLICIES,
    )
    return packet


def _dns_plan(case: str, *, direction: str = "reference_to_libcrafter") -> PacketPlan:
    return PacketPlan(
        stack=["ipv4", "udp", "dns"],
        fields={"ipv4": {"src": "192.0.2.1", "dst": "192.0.2.2"}},
        profile="ci",
        seed=1,
        index=0,
        direction=direction,
        family="dns",
        case=case,
        metadata={"root": "l3:ipv4"},
    )


if __name__ == "__main__":
    unittest.main()
