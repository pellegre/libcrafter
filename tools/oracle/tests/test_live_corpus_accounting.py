"""Corpus accounting coverage for l2:ipv4 ICMP live eligibility.

These tests assert that an ICMP corpus rooted at ``l2:ipv4`` is wire-eligible on
Hetzner: plans are generated, comparison canonicalizes to the IPv4 header
(``l3:ipv4``), eligible plans are not skipped, and the only skipped plan is the
intentionally malformed one that wire providers must not exchange. They guard
against the new ICMP matrix silently disappearing from live accounting.
"""

from __future__ import annotations

import unittest

from tools.oracle.engine.corpus import (
    CorpusPacket,
    SKIP_PROVIDER_CAPABILITY_UNAVAILABLE,
    SKIP_WIRE_COMPARE_ROOT_UNAVAILABLE,
    build_corpus_report,
    populate_corpus_eligibility,
)
from tools.oracle.engine.generator import generate_plans
from tools.oracle.engine.model import PacketPlan
from tools.oracle.engine.providers.hetzner import (
    HETZNER_UNSUPPORTED_LIVE_CASE_REASON,
    hetzner_default_provider_capabilities,
)


# Mirror the step-06 acceptance corpus command:
#   tools/oracle/run corpus --backend scapy --root l2:ipv4 --family icmp \
#       --profile smoke --seed 14 --count 6
_BACKEND = "scapy"
_ROOT = "l2:ipv4"
_FAMILY = "icmp"
_PROFILE = "smoke"
_SEED = 14
_COUNT = 6
_DIRECTION = "live_exchange"


def _icmp_l2_ipv4_plans() -> list[PacketPlan]:
    return generate_plans(
        seed=_SEED,
        profile=_PROFILE,
        count=_COUNT,
        backend=_BACKEND,
        root=_ROOT,
        family=_FAMILY,
        direction=_DIRECTION,
    )


def _plan_is_malformed(plan: PacketPlan) -> bool:
    if bool(plan.metadata.get("malformed")):
        return True
    return bool(
        set(plan.feature_tags).intersection({"malformed", "non_strict_reencode"})
    )


class IcmpL2Ipv4CorpusAccountingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.plans = _icmp_l2_ipv4_plans()
        self.packets = populate_corpus_eligibility(
            backend=_BACKEND,
            packets=[CorpusPacket.from_plan(plan) for plan in self.plans],
            wire_provider="hetzner",
        )

    def test_corpus_generates_requested_icmp_l2_ipv4_count(self) -> None:
        self.assertEqual(len(self.plans), _COUNT)
        for plan in self.plans:
            self.assertEqual(plan.family, _FAMILY)
            self.assertEqual(plan.metadata.get("root"), _ROOT)
            self.assertIn("ipv4", plan.stack)
            self.assertIn("icmp", plan.stack)

    def test_eligible_and_skipped_accounting_partitions_every_plan(self) -> None:
        eligible = [p for p in self.packets if p.wire.eligible is True]
        skipped = [p for p in self.packets if p.wire.eligible is not True]

        # Every plan is accounted for exactly once across eligible/skipped.
        self.assertEqual(len(eligible) + len(skipped), _COUNT)
        # The well-formed ICMP plans are wire-eligible; only intentionally
        # malformed plans are excluded, and there is at least one of each so the
        # accounting is meaningful.
        self.assertTrue(eligible, "expected at least one wire-eligible ICMP plan")

        for packet in skipped:
            self.assertTrue(
                _plan_is_malformed(packet.plan),
                f"unexpected wire skip for well-formed plan {packet.packet_id}: "
                f"{packet.wire.skip_reasons}",
            )
            self.assertIn(
                SKIP_PROVIDER_CAPABILITY_UNAVAILABLE,
                packet.wire.skip_reasons,
            )

    def test_eligible_plans_canonicalize_compare_root_to_l3_ipv4(self) -> None:
        eligible = [p for p in self.packets if p.wire.eligible is True]
        for packet in eligible:
            self.assertEqual(packet.wire.compare_root, "l3:ipv4")
            self.assertNotIn(
                SKIP_WIRE_COMPARE_ROOT_UNAVAILABLE,
                packet.wire.skip_reasons,
            )

    def test_all_plans_carry_l3_ipv4_compare_root_even_when_skipped(self) -> None:
        # Comparison canonicalization is independent of wire eligibility, so even
        # the malformed/skipped plan must canonicalize to the IPv4 header rather
        # than silently leaving the compare root unavailable.
        for packet in self.packets:
            self.assertEqual(packet.wire.compare_root, "l3:ipv4")

    def test_hetzner_provider_profile_eligibility_matches_summary(self) -> None:
        report = build_corpus_report(
            backend=_BACKEND,
            profile=_PROFILE,
            seed=_SEED,
            count=_COUNT,
            plans=self.plans,
        )
        summary = report.metadata["eligibility"]

        wire_eligible = summary["eligible_counts"]["wire"]
        wire_skipped = summary["skipped_counts"]["wire"]
        self.assertEqual(summary["total_packets"], _COUNT)
        self.assertEqual(wire_eligible + wire_skipped, _COUNT)

        provider_eligible = summary["wire_provider_eligible_counts"].get("hetzner", 0)
        self.assertEqual(provider_eligible, wire_eligible)

        observed_eligible = sum(
            1 for p in self.packets if p.wire.eligible is True
        )
        observed_skipped = _COUNT - observed_eligible
        self.assertEqual(wire_eligible, observed_eligible)
        self.assertEqual(wire_skipped, observed_skipped)

    def test_local_dry_run_provider_cannot_exchange_icmp_l2_ipv4(self) -> None:
        # The default provider profile set includes a non-exchanging
        # local-dry-run provider; its skips must be attributed to provider
        # capability, never to a missing compare root.
        report = build_corpus_report(
            backend=_BACKEND,
            profile=_PROFILE,
            seed=_SEED,
            count=_COUNT,
            plans=self.plans,
        )
        summary = report.metadata["eligibility"]
        local_skips = summary["wire_provider_skip_counts_by_reason"].get(
            "local-dry-run", {}
        )
        self.assertEqual(local_skips.get(SKIP_WIRE_COMPARE_ROOT_UNAVAILABLE, 0), 0)
        self.assertEqual(
            summary["wire_provider_skipped_counts"].get("local-dry-run", 0),
            _COUNT,
        )

    def test_hetzner_skips_source_quench_with_stable_reason(self) -> None:
        plans = generate_plans(
            seed=47,
            profile=_PROFILE,
            count=2,
            backend=_BACKEND,
            root=_ROOT,
            case="icmpv4-source-quench",
            direction=_DIRECTION,
        )
        packets = populate_corpus_eligibility(
            backend=_BACKEND,
            packets=[CorpusPacket.from_plan(plan) for plan in plans],
            provider_capabilities=hetzner_default_provider_capabilities(dry_run=True),
            wire_provider="hetzner",
        )

        self.assertEqual(len(packets), 2)
        for packet in packets:
            self.assertFalse(packet.wire.eligible)
            self.assertIn(
                SKIP_PROVIDER_CAPABILITY_UNAVAILABLE,
                packet.wire.skip_reasons,
            )
            self.assertIn(
                HETZNER_UNSUPPORTED_LIVE_CASE_REASON,
                packet.wire.skip_reasons,
            )


if __name__ == "__main__":
    unittest.main()
