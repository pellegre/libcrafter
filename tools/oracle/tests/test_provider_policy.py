"""Unit coverage for oracle live provider policy selection."""

from __future__ import annotations

import unittest

from tools.oracle.engine.corpus import (
    CorpusPacket,
    SKIP_PROVIDER_CAPABILITY_UNAVAILABLE,
    SKIP_REQUIRES_BROADCAST,
    SKIP_REQUIRES_CONTROLLED_SERVICE,
    SKIP_REQUIRES_L2,
    SKIP_REQUIRES_PROVIDER_MAC,
    populate_corpus_eligibility,
    wire_comparison_policy,
)
from tools.oracle.engine.model import PacketPlan
from tools.oracle.engine.providers.hetzner import hetzner_default_provider_capabilities
from tools.oracle.engine.providers.qemu import qemu_default_provider_capabilities
from tools.oracle.engine.providers.virtualbox import (
    virtualbox_default_provider_capabilities,
)


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

    def test_virtualbox_policy_does_not_inherit_hetzner_ttl_or_checksum_mutables(
        self,
    ) -> None:
        plan = _ipv4_plan()
        capabilities = virtualbox_default_provider_capabilities(dry_run=True)

        [packet] = populate_corpus_eligibility(
            backend="scapy",
            packets=[CorpusPacket.from_plan(plan)],
            provider_capabilities=capabilities,
            wire_provider="virtualbox",
        )

        self.assertEqual(packet.wire.metadata["provider"], "virtualbox")
        self.assertTrue(packet.wire.eligible)
        self.assertNotIn("ipv4.ttl", packet.wire.mutable_fields)
        self.assertNotIn("ipv4.checksum", packet.wire.mutable_fields)

        policy = packet.wire.metadata["provider_profiles"]["virtualbox"]["metadata"][
            "mutation_policy"
        ]
        self.assertEqual(policy["provider"], "virtualbox")
        self.assertNotIn("ipv4.ttl", policy["mutable_fields"])
        self.assertNotIn("ipv4.checksum", policy["mutable_fields"])
        self.assertNotIn("ipv4.ttl", policy["byte_mutable_fields"])
        self.assertNotIn("ipv4.checksum", policy["byte_mutable_fields"])
        self.assertFalse(policy["transit_mutations"])


class DhcpLiveEligibilityPolicyTest(unittest.TestCase):
    """Prove DHCP is wire-eligible only where provider capabilities allow it."""

    def test_qemu_marks_ipv4_root_dhcp_wire_eligible(self) -> None:
        self._assert_ipv4_root_dhcp_eligible(
            qemu_default_provider_capabilities(dry_run=True),
            provider="qemu",
        )

    def test_virtualbox_marks_ipv4_root_dhcp_wire_eligible(self) -> None:
        self._assert_ipv4_root_dhcp_eligible(
            virtualbox_default_provider_capabilities(dry_run=True),
            provider="virtualbox",
        )

    def test_hetzner_skips_ipv4_root_dhcp_on_blocked_provider_ports(self) -> None:
        [packet] = populate_corpus_eligibility(
            backend="scapy",
            packets=[CorpusPacket.from_plan(_ipv4_dhcp_plan())],
            provider_capabilities=hetzner_default_provider_capabilities(dry_run=True),
            wire_provider="hetzner",
        )

        self.assertEqual(packet.wire.metadata["provider"], "hetzner")
        self.assertFalse(packet.wire.eligible)
        self.assertEqual(packet.wire.compare_root, "l3:ipv4")
        self.assertIn(SKIP_PROVIDER_CAPABILITY_UNAVAILABLE, packet.wire.skip_reasons)
        profile = packet.wire.metadata["provider_profiles"]["hetzner"]["metadata"]
        self.assertEqual(profile["capabilities"]["blocked_udp_ports"], [67, 68])
        self.assertTrue(profile["requirements"]["blocked_udp_port"])
        self.assertNotIn(SKIP_REQUIRES_L2, packet.wire.skip_reasons)
        self.assertNotIn(SKIP_REQUIRES_PROVIDER_MAC, packet.wire.skip_reasons)

    def test_qemu_marks_ethernet_root_dhcp_wire_eligible(self) -> None:
        self._assert_ethernet_root_dhcp_eligible(
            qemu_default_provider_capabilities(dry_run=True),
            provider="qemu",
        )

    def test_virtualbox_marks_ethernet_root_dhcp_wire_eligible(self) -> None:
        self._assert_ethernet_root_dhcp_eligible(
            virtualbox_default_provider_capabilities(dry_run=True),
            provider="virtualbox",
        )

    def test_ethernet_root_dhcp_skipped_on_routed_only_provider_without_l2(
        self,
    ) -> None:
        # Adding IPv4-root DHCP must not make ethernet / ipv4 / udp / dhcp look
        # safe for live validation on a routed-only provider. Build a provider
        # that explicitly lacks L2 send/capture, broadcast, and provider MAC
        # discovery, then prove the Ethernet-root DHCP plan stays gated with
        # link-layer reasons rather than becoming wire-eligible.
        capabilities = {
            "provider": "routed-only",
            "live_packet_exchange": True,
            "ipv4_unicast": True,
            "ipv6_unicast": True,
            "link_layer_send": False,
            "link_layer_capture": False,
            "broadcast": False,
            "provider_mac_known": False,
            "controlled_services": False,
            "controlled_router": False,
        }
        self.assertFalse(capabilities["link_layer_send"])
        self.assertFalse(capabilities["link_layer_capture"])

        self._assert_ethernet_root_dhcp_skipped(
            capabilities,
            provider="routed-only",
        )

    def _assert_ipv4_root_dhcp_eligible(
        self,
        capabilities: dict[str, object],
        *,
        provider: str,
    ) -> None:
        [packet] = populate_corpus_eligibility(
            backend="scapy",
            packets=[CorpusPacket.from_plan(_ipv4_dhcp_plan())],
            provider_capabilities=capabilities,
            wire_provider=provider,
        )

        self.assertEqual(packet.wire.metadata["provider"], provider)
        self.assertTrue(packet.wire.eligible)
        self.assertEqual(packet.wire.skip_reasons, [])
        self.assertEqual(packet.wire.compare_root, "l3:ipv4")
        # IPv4-root DHCP is a one-way application payload, not a service or
        # lease workflow, so it must not demand a controlled DHCP service nor
        # any other link-layer substrate capability.
        self.assertNotIn(SKIP_REQUIRES_CONTROLLED_SERVICE, packet.wire.skip_reasons)
        self.assertNotIn(SKIP_REQUIRES_L2, packet.wire.skip_reasons)
        self.assertNotIn(SKIP_REQUIRES_BROADCAST, packet.wire.skip_reasons)
        self.assertNotIn(SKIP_REQUIRES_PROVIDER_MAC, packet.wire.skip_reasons)
        requirements = packet.wire.metadata["provider_profiles"][provider]["metadata"][
            "requirements"
        ]
        self.assertTrue(requirements["ipv4_unicast"])
        self.assertFalse(requirements["link_layer_send"])
        self.assertFalse(requirements["link_layer_capture"])
        self.assertFalse(requirements["broadcast"])
        self.assertFalse(requirements["provider_mac_known"])
        self.assertFalse(requirements["controlled_services"])

    def _assert_ethernet_root_dhcp_skipped(
        self,
        capabilities: dict[str, object],
        *,
        provider: str,
    ) -> None:
        [packet] = populate_corpus_eligibility(
            backend="scapy",
            packets=[CorpusPacket.from_plan(_ethernet_dhcp_plan())],
            provider_capabilities=capabilities,
            wire_provider=provider,
        )

        self.assertEqual(packet.wire.metadata["provider"], provider)
        self.assertFalse(packet.wire.eligible)
        self.assertEqual(packet.wire.compare_root, "link:ethernet")
        self.assertIn(SKIP_REQUIRES_L2, packet.wire.skip_reasons)
        self.assertIn(SKIP_REQUIRES_PROVIDER_MAC, packet.wire.skip_reasons)
        self.assertIn(SKIP_REQUIRES_BROADCAST, packet.wire.skip_reasons)

    def _assert_ethernet_root_dhcp_eligible(
        self,
        capabilities: dict[str, object],
        *,
        provider: str,
    ) -> None:
        [packet] = populate_corpus_eligibility(
            backend="scapy",
            packets=[CorpusPacket.from_plan(_ethernet_dhcp_plan())],
            provider_capabilities=capabilities,
            wire_provider=provider,
        )

        self.assertEqual(packet.wire.metadata["provider"], provider)
        self.assertTrue(packet.wire.eligible)
        self.assertEqual(packet.wire.skip_reasons, [])
        self.assertEqual(packet.wire.compare_root, "link:ethernet")
        requirements = packet.wire.metadata["provider_profiles"][provider]["metadata"][
            "requirements"
        ]
        self.assertTrue(requirements["link_layer_send"])
        self.assertTrue(requirements["link_layer_capture"])
        self.assertTrue(requirements["broadcast"])
        self.assertTrue(requirements["provider_mac_known"])


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


def _ipv4_dhcp_plan() -> PacketPlan:
    return PacketPlan(
        stack=["ipv4", "udp", "dhcp"],
        fields={
            "ipv4": {"src": "192.0.2.1", "dst": "192.0.2.2"},
            "udp": {"sport": 68, "dport": 67},
            "dhcp": {"op": 1, "message_type": "discover"},
        },
        profile="smoke",
        seed=1,
        index=0,
        direction="libcrafter_to_reference",
        family="ipv4",
        case="dhcp-discover",
        metadata={"root": "l3:ipv4"},
    )


def _ethernet_dhcp_plan() -> PacketPlan:
    return PacketPlan(
        stack=["ethernet", "ipv4", "udp", "dhcp"],
        fields={
            "ethernet": {
                "src": "02:00:00:00:00:01",
                "dst": "ff:ff:ff:ff:ff:ff",
            },
            "ipv4": {"src": "0.0.0.0", "dst": "255.255.255.255"},
            "udp": {"sport": 68, "dport": 67},
            "dhcp": {"op": 1, "message_type": "discover", "flags": "broadcast"},
        },
        profile="smoke",
        seed=1,
        index=1,
        direction="libcrafter_to_reference",
        family="ipv4",
        case="dhcp-discover",
        metadata={"root": "link:ethernet"},
    )


if __name__ == "__main__":
    unittest.main()
