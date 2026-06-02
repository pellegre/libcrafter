"""Unit coverage for probe target service scripts and typed descriptors.

These tests exercise the deterministic, artifact-producing setup script and the
typed service descriptors owned by :mod:`tools.probe.engine.target_services`,
independently of any lab provider.
"""

from __future__ import annotations

import unittest

from tools.probe.engine import target_services as ts


def _dns_plan(*, port: int = 53, sequence: int = 0) -> dict[str, object]:
    return {
        "case": "dns-query",
        "sequence": sequence,
        "destination_port": port,
        "source_port": 40000 + sequence,
        "destination_ipv4": "10.77.0.20",
        "source_ipv4": "10.77.0.10",
        "query_name": f"probe-{sequence}.libcrafter.test.",
        "query_type": "A",
        "query_type_value": 1,
        "expected_answer_data": "203.0.113.7",
        "answer_ttl": 60,
        "target_service": {
            "bind_ipv4": "10.77.0.20",
            "source_ipv4": "10.77.0.10",
            "port": port,
        },
    }


def _tcp_plan(*, case: str, port: int, sequence: int = 0) -> dict[str, object]:
    return {
        "case": case,
        "sequence": sequence,
        "destination_port": port,
        "source_port": 61000 + sequence,
        "destination_ipv4": "10.77.0.20",
        "source_ipv4": "10.77.0.10",
        "target_service": {
            "bind_ipv4": "10.77.0.20",
            "source_ipv4": "10.77.0.10",
        },
    }


class TargetServiceScriptTest(unittest.TestCase):
    def test_setup_script_is_deterministic(self) -> None:
        dns_plans = [_dns_plan(port=53)]
        first = ts.target_service_setup_script(
            artifact_root="/root/libcrafter/artifacts/probe/target-services",
            bind_ipv4="10.77.0.20",
            open_ports=[19872],
            closed_ports=[23215],
            dns_plans=dns_plans,
        )
        second = ts.target_service_setup_script(
            artifact_root="/root/libcrafter/artifacts/probe/target-services",
            bind_ipv4="10.77.0.20",
            open_ports=[19872],
            closed_ports=[23215],
            dns_plans=dns_plans,
        )
        self.assertEqual(first, second)

    def test_setup_script_binds_and_starts_services(self) -> None:
        script = ts.target_service_setup_script(
            artifact_root="/root/libcrafter/artifacts/probe/target-services",
            bind_ipv4="10.77.0.20",
            open_ports=[19872],
            closed_ports=[23215],
            dns_plans=[_dns_plan(port=53)],
        )
        self.assertTrue(script.startswith("set -euo pipefail"))
        self.assertIn("tcp_bind_ipv4=10.77.0.20", script)
        self.assertIn("dns_bind_ipv4=10.77.0.20", script)
        # Closed port is verified free, open listener and DNS responder start.
        self.assertIn('check_port_free "$tcp_bind_ipv4" 23215', script)
        self.assertIn('check_port_free "$tcp_bind_ipv4" 19872', script)
        self.assertIn("echo listener_19872=running", script)
        self.assertIn("echo dns_responder_53=running", script)
        self.assertIn("answer_data = record.get('answer_data')", script)
        self.assertNotIn("answer_data = record['answer_data']", script)
        # The setup is artifact-producing: it records a disposable cleanup script.
        self.assertIn('cleanup="$artifact_root/cleanup.sh"', script)
        self.assertIn("echo target_service_setup=ok", script)

    def test_setup_script_without_services_only_verifies_closed_ports(self) -> None:
        script = ts.target_service_setup_script(
            artifact_root="/root/libcrafter/artifacts/probe/target-services",
            bind_ipv4="10.77.0.20",
            open_ports=[],
            closed_ports=[23215],
            dns_plans=[],
        )
        self.assertIn('check_port_free "$tcp_bind_ipv4" 23215', script)
        self.assertNotIn("dns_responder", script)
        self.assertNotIn("listener_", script)


class TargetServiceSetupPlanTest(unittest.TestCase):
    def test_dry_run_plan_does_not_start_services(self) -> None:
        plan = ts.target_service_setup_plan(
            probe_plans=[
                _tcp_plan(case="tcp-syn-open", port=19872),
                _tcp_plan(case="tcp-syn-closed", port=23215),
                _dns_plan(port=53),
            ],
            dry_run=True,
        )
        self.assertEqual(plan["role"], "target")
        self.assertTrue(plan["planned"])
        self.assertFalse(plan["starts_services"])
        purposes = {service["purpose"] for service in plan["services"]}
        self.assertEqual(purposes, {"tcp-syn-open", "dns-query"})
        self.assertEqual(plan["closed_tcp_ports"][0]["state"], "planned-unbound")
        for service in plan["services"]:
            self.assertEqual(service["bind_ipv4"], "10.77.0.20")
            self.assertEqual(service["source_ipv4"], "10.77.0.10")

    def test_live_plan_starts_services_and_verifies_closed_ports(self) -> None:
        plan = ts.target_service_setup_plan(
            probe_plans=[
                _tcp_plan(case="tcp-syn-open", port=19872),
                _tcp_plan(case="tcp-syn-closed", port=23215),
                _dns_plan(port=53),
            ],
            dry_run=False,
        )
        self.assertTrue(plan["starts_services"])
        self.assertEqual(plan["closed_tcp_ports"][0]["state"], "verified-unbound")


class TargetServiceDescriptorTest(unittest.TestCase):
    def test_dns_responder_descriptor(self) -> None:
        descriptor = ts.dns_responder_descriptor(
            bind_ipv4="10.77.0.20",
            source_ipv4="10.77.0.10",
            port=53,
            artifact_root="/root/probe/target-services",
        )
        self.assertEqual(descriptor.name, "dns-responder")
        self.assertEqual(descriptor.protocol, "udp")
        self.assertEqual(descriptor.purpose, "dns-query")
        self.assertEqual(descriptor.bind_ipv4, "10.77.0.20")
        self.assertIn("python3", descriptor.requires)
        self.assertTrue(descriptor.setup_commands)
        self.assertTrue(descriptor.cleanup_commands)
        self.assertIn(
            "/root/probe/target-services/dns-responder-53.stdout.txt",
            descriptor.artifacts,
        )

    def test_dhcp_responder_descriptor_requires_link_layer(self) -> None:
        descriptor = ts.dhcp_responder_descriptor(
            bind_ipv4="10.77.0.20",
            source_ipv4="10.77.0.10",
            port=67,
            artifact_root="/root/probe/target-services",
        )
        self.assertEqual(descriptor.name, "dhcp-responder")
        self.assertEqual(descriptor.purpose, "dhcp")
        self.assertIn(ts.SKIP_REQUIRES_LINK_LAYER, descriptor.requires)
        self.assertEqual(descriptor.metadata["layer"], "link")

    def test_udp_responder_descriptor(self) -> None:
        descriptor = ts.udp_responder_descriptor(
            bind_ipv4="10.77.0.20",
            source_ipv4="10.77.0.10",
            port=40000,
            artifact_root="/root/probe/target-services",
        )
        self.assertEqual(descriptor.name, "udp-responder")
        self.assertEqual(descriptor.purpose, "udp-echo")
        self.assertTrue(descriptor.setup_commands)
        self.assertTrue(descriptor.cleanup_commands)

    def test_closed_udp_port_descriptor_verifies_free(self) -> None:
        descriptor = ts.closed_udp_port_descriptor(
            bind_ipv4="10.77.0.20",
            source_ipv4="10.77.0.10",
            port=40444,
        )
        self.assertEqual(descriptor.name, "closed-udp-port")
        self.assertEqual(descriptor.purpose, "udp-port-unreachable")
        self.assertTrue(descriptor.verify_commands)
        self.assertFalse(descriptor.setup_commands)
        self.assertEqual(descriptor.metadata["expects"], "icmp_port_unreachable")

    def test_arp_alias_descriptor_sets_and_cleans_alias(self) -> None:
        descriptor = ts.arp_alias_descriptor(
            bind_ipv4="10.77.0.20",
            source_ipv4="10.77.0.10",
            alias_ipv4="10.77.0.30",
            interface="eth1",
        )
        self.assertEqual(descriptor.name, "arp-alias")
        self.assertEqual(descriptor.metadata["alias_ipv4"], "10.77.0.30")
        setup = "\n".join(descriptor.setup_commands)
        cleanup = "\n".join(descriptor.cleanup_commands)
        self.assertIn("ip addr add", setup)
        self.assertIn("10.77.0.30/32", setup)
        self.assertIn("ip addr del", cleanup)

    def test_arp_sysctl_descriptor_flushes_neighbor_cache(self) -> None:
        descriptor = ts.arp_sysctl_descriptor(
            bind_ipv4="10.77.0.20",
            source_ipv4="10.77.0.10",
            interface="eth1",
        )
        self.assertEqual(descriptor.name, "arp-sysctl")
        setup = "\n".join(descriptor.setup_commands)
        self.assertIn("sysctl -w", setup)
        self.assertIn("ip neigh flush dev eth1", setup)
        self.assertIn("ip neigh flush dev eth1", "\n".join(descriptor.cleanup_commands))


if __name__ == "__main__":
    unittest.main()
