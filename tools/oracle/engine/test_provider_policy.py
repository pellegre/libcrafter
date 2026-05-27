"""Unit coverage for oracle live provider policy selection."""

from __future__ import annotations

import unittest

from tools.oracle.engine.corpus import (
    CorpusPacket,
    populate_corpus_eligibility,
    wire_comparison_policy,
)
from tools.oracle.engine.model import PacketPlan
from tools.oracle.engine.providers.qemu import qemu_default_provider_capabilities


class LiveProviderPolicyTest(unittest.TestCase):
    def test_hetzner_policy_marks_ipv4_ttl_and_checksum_mutable(self) -> None:
        plan = _ipv4_plan()

        policy = wire_comparison_policy(plan, provider="hetzner")

        self.assertEqual(policy["provider"], "hetzner")
        self.assertEqual(policy["compare_root"], "l3:ipv4")
        self.assertIn("ipv4.ttl", policy["mutable_fields"])
        self.assertIn("ipv4.checksum", policy["mutable_fields"])
        self.assertIn("ipv4.ttl", policy["byte_mutable_fields"])
        self.assertIn("ipv4.checksum", policy["byte_mutable_fields"])
        self.assertFalse(policy["strict_bytes"])

    def test_supplied_fake_provider_policy_does_not_inherit_hetzner_mutables(
        self,
    ) -> None:
        plan = _ipv4_plan()
        capabilities = {
            "provider": "future-wire",
            "live_packet_exchange": True,
            "ipv4_unicast": True,
            "ipv6_unicast": False,
            "link_layer_send": False,
            "link_layer_capture": False,
            "broadcast": False,
            "provider_mac_known": False,
            "controlled_services": True,
            "controlled_router": False,
            "wire_policy": {
                "mutable_fields": ["ipv4.id"],
                "byte_mutable_fields": ["ipv4.id"],
                "transit_mutations": [
                    {
                        "field": "ipv4.id",
                        "reason": "future provider rewrites packet identifiers",
                    }
                ],
            },
        }

        [packet] = populate_corpus_eligibility(
            backend="scapy",
            packets=[CorpusPacket.from_plan(plan)],
            provider_capabilities=capabilities,
            wire_provider="future-wire",
        )

        self.assertEqual(packet.wire.metadata["provider"], "future-wire")
        self.assertEqual(packet.wire.mutable_fields, ["ipv4.id"])
        self.assertNotIn("ipv4.ttl", packet.wire.mutable_fields)
        self.assertNotIn("ipv4.checksum", packet.wire.mutable_fields)

        policy = packet.wire.metadata["provider_profiles"]["future-wire"]["metadata"][
            "mutation_policy"
        ]
        self.assertEqual(policy["provider"], "future-wire")
        self.assertEqual(policy["mutable_fields"], ["ipv4.id"])
        self.assertEqual(policy["byte_mutable_fields"], ["ipv4.id"])
        self.assertNotIn("ipv4.ttl", policy["mutable_fields"])
        self.assertNotIn("ipv4.checksum", policy["mutable_fields"])

    def test_qemu_policy_does_not_inherit_hetzner_ttl_or_checksum_mutables(
        self,
    ) -> None:
        plan = _ipv4_plan()
        capabilities = qemu_default_provider_capabilities(dry_run=True)

        [packet] = populate_corpus_eligibility(
            backend="scapy",
            packets=[CorpusPacket.from_plan(plan)],
            provider_capabilities=capabilities,
            wire_provider="qemu",
        )

        self.assertEqual(packet.wire.metadata["provider"], "qemu")
        self.assertTrue(packet.wire.eligible)
        self.assertNotIn("ipv4.ttl", packet.wire.mutable_fields)
        self.assertNotIn("ipv4.checksum", packet.wire.mutable_fields)

        policy = packet.wire.metadata["provider_profiles"]["qemu"]["metadata"][
            "mutation_policy"
        ]
        self.assertEqual(policy["provider"], "qemu")
        self.assertNotIn("ipv4.ttl", policy["mutable_fields"])
        self.assertNotIn("ipv4.checksum", policy["mutable_fields"])
        self.assertNotIn("ipv4.ttl", policy["byte_mutable_fields"])
        self.assertNotIn("ipv4.checksum", policy["byte_mutable_fields"])
        self.assertFalse(policy["transit_mutations"])


def _ipv4_plan() -> PacketPlan:
    return PacketPlan(
        stack=["ipv4"],
        fields={"ipv4": {"ttl": 1, "src": "192.0.2.1", "dst": "192.0.2.2"}},
        profile="smoke",
        seed=1,
        index=0,
        direction="reference_to_libcrafter",
        family="ipv4",
        metadata={"root": "l3:ipv4"},
    )


if __name__ == "__main__":
    unittest.main()
