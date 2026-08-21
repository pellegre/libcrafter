"""Protocol plugin registry invariants."""

from __future__ import annotations

import unittest

from tools.probe.engine import cases, planning
from tools.probe.engine.protocols import PROTOCOL_REGISTRY, registered_plugins


EXPECTED_PROTOCOLS = {
    "arp",
    "bgp",
    "coap",
    "dhcpv4",
    "dhcpv6",
    "dns",
    "icmp",
    "igmp",
    "ipsec",
    "mdns",
    "mqtt",
    "ndp",
    "ntp",
    "ospf",
    "quic",
    "rip",
    "sctp",
    "snmp",
    "ssdp",
    "tcp",
    "tls",
    "udp",
}


class RegistryTest(unittest.TestCase):
    def test_protocol_set_is_complete(self) -> None:
        self.assertEqual(set(PROTOCOL_REGISTRY.names()), EXPECTED_PROTOCOLS)

    def test_builder_keys_are_catalog_cases(self) -> None:
        self.assertLessEqual(set(planning.PLAN_BUILDERS), set(cases.PROBE_CASE_BY_NAME))

    def test_plugins_do_not_expose_execution_hooks(self) -> None:
        forbidden = {
            "provider",
            "target_service",
            "setup_script",
            "lab_capabilities",
            "rewrite_endpoint_addresses",
            "live_plan_candidates",
        }
        for plugin in registered_plugins():
            with self.subTest(protocol=plugin.name):
                self.assertTrue(forbidden.isdisjoint(plugin.__dataclass_fields__))


if __name__ == "__main__":
    unittest.main()
