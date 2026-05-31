"""Focused coverage for the DHCP behavioral probe cases.

Each test asserts the deterministic plan shape its case produces and, when the
``uv``/``cargo`` toolchains are available, drives the case end to end through the
probe planner dry-run and the Rust ``stimulus_endpoint`` dry-run via the shared
:mod:`tools.probe.tests.probe_acceptance` harness.

``dhcp-discover-offer`` is the baseline DHCP behavioral check: a BOOTP/DHCP
Discover sent from the client port (68) to the server port (67) against a
controlled DHCP responder on a private L2 lab segment, whose Offer the endpoint
decodes (IPv4/UDP/BOOTP/DHCP) and validates for message type, transaction id,
client hardware address, offered address, server identifier, lease options, and
response direction.
"""

from __future__ import annotations

import ipaddress
import tempfile
import unittest
from pathlib import Path

from tools.probe.engine import planning
from tools.probe.engine.model import ProbeRunRequest
from tools.probe.tests import probe_acceptance


def _request(
    *,
    case_names: list[str] | None = None,
    **overrides: object,
) -> ProbeRunRequest:
    base = {
        "provider": "qemu",
        "profile": "behavior",
        "seed": 1020,
        "count": 1,
        "case_names": case_names or ["dhcp-discover-offer"],
        "dry_run": True,
    }
    base.update(overrides)
    return ProbeRunRequest(**base)  # type: ignore[arg-type]


def _dhcp_discover_offer_plan(*, seed: int = 1020, sequence: int = 0) -> dict:
    return planning.probe_plan_for_case(
        request=_request(seed=seed),
        case=planning.PROBE_CASE_BY_NAME["dhcp-discover-offer"],
        sequence=sequence,
    )


def _dhcp_request_ack_plan(*, seed: int = 1021, sequence: int = 0) -> dict:
    return planning.probe_plan_for_case(
        request=_request(seed=seed, case_names=["dhcp-request-ack"]),
        case=planning.PROBE_CASE_BY_NAME["dhcp-request-ack"],
        sequence=sequence,
    )


def _dhcp_client_identifier_plan(*, seed: int = 1022, sequence: int = 0) -> dict:
    return planning.probe_plan_for_case(
        request=_request(seed=seed, case_names=["dhcp-client-identifier"]),
        case=planning.PROBE_CASE_BY_NAME["dhcp-client-identifier"],
        sequence=sequence,
    )


class DhcpDiscoverOfferPlanTest(unittest.TestCase):
    """The plan carries an RFC-correct Discover stimulus and Offer contract."""

    def test_plan_uses_dedicated_builder(self) -> None:
        self.assertIn("dhcp-discover-offer", planning.PLAN_BUILDERS)
        self.assertIs(
            planning.PLAN_BUILDERS["dhcp-discover-offer"],
            planning._dhcp_discover_offer_probe_plan,
        )

    def test_plan_is_deterministic(self) -> None:
        self.assertEqual(_dhcp_discover_offer_plan(), _dhcp_discover_offer_plan())

    def test_plan_carries_a_discover_stimulus(self) -> None:
        plan = _dhcp_discover_offer_plan()

        self.assertEqual(plan["case"], "dhcp-discover-offer")
        self.assertEqual(plan["stimulus"], "dhcp_discover")
        self.assertEqual(plan["expected_response"], "dhcp_offer")

        # DHCP fixed ports: client 68 -> server 67.
        self.assertEqual(plan["source_port"], 68)
        self.assertEqual(plan["destination_port"], 67)

        # A client hardware address in the RFC 7042 documentation MAC range and a
        # 32-bit transaction id (xid).
        mac = plan["client_mac"]
        self.assertTrue(mac.startswith("00:00:5e:00:53:"))
        self.assertIsInstance(plan["transaction_id"], int)
        self.assertTrue(1 <= plan["transaction_id"] <= 0xFFFFFFFF)

    def test_plan_offer_expectations(self) -> None:
        plan = _dhcp_discover_offer_plan()

        # Offered address is in documentation space (198.51.100.0/24); the server
        # identifier is the responder (target) address.
        self.assertEqual(plan["expected_message_type"], "offer")
        self.assertEqual(plan["expected_message_type_value"], 2)
        offered = ipaddress.IPv4Address(plan["expected_yiaddr"])
        self.assertIn(offered, ipaddress.ip_network("198.51.100.0/24"))
        self.assertEqual(plan["expected_server_identifier"], plan["destination_ipv4"])

        # Lease timing options: T1 < T2 < lease.
        self.assertGreater(plan["expected_lease_time"], 0)
        self.assertLess(plan["expected_renewal_time"], plan["expected_rebinding_time"])
        self.assertLess(plan["expected_rebinding_time"], plan["expected_lease_time"])

    def test_validation_contract_covers_offer_fields_and_direction(self) -> None:
        plan = _dhcp_discover_offer_plan()
        validation = plan["validation"]

        # Peer addresses and ports (Offer flows server -> client, 67 -> 68).
        self.assertEqual(validation["source_ipv4"], plan["expected_reply_source_ipv4"])
        self.assertEqual(
            validation["destination_ipv4"], plan["expected_reply_destination_ipv4"]
        )
        self.assertEqual(validation["source_port"], 67)
        self.assertEqual(validation["destination_port"], 68)
        self.assertEqual(validation["direction"], "server_to_client")

        # BOOTP reply opcode and the Offer message type.
        self.assertEqual(validation["op_value"], 2)
        self.assertEqual(validation["message_type_value"], 2)

        # Identity: transaction id and client hardware address echoed.
        self.assertEqual(validation["transaction_id"], plan["transaction_id"])
        self.assertEqual(validation["client_hardware_address"], plan["client_mac"])

        # Offered address, server identifier, and lease timing options.
        self.assertEqual(validation["yiaddr"], plan["expected_yiaddr"])
        self.assertEqual(
            validation["server_identifier"], plan["expected_server_identifier"]
        )
        self.assertEqual(validation["lease_time"], plan["expected_lease_time"])
        self.assertEqual(validation["renewal_time"], plan["expected_renewal_time"])
        self.assertEqual(validation["rebinding_time"], plan["expected_rebinding_time"])

    def test_target_service_is_controlled_dhcp_responder(self) -> None:
        target_service = _dhcp_discover_offer_plan()["target_service"]
        self.assertTrue(target_service["required"])
        self.assertEqual(target_service["kind"], "dhcp-responder")
        self.assertEqual(target_service["port"], 67)
        self.assertEqual(target_service["client_port"], 68)
        self.assertEqual(target_service["client_mac"], _dhcp_discover_offer_plan()["client_mac"])

    def test_capture_filter_matches_offer_direction(self) -> None:
        plan = _dhcp_discover_offer_plan()
        self.assertIn("src port 67", plan["capture_filter"])
        self.assertIn("dst port 68", plan["capture_filter"])
        self.assertIn(f"src host {plan['expected_reply_source_ipv4']}", plan["capture_filter"])


class DhcpDiscoverOfferTest(unittest.TestCase):
    """End-to-end focused acceptance through planner and stimulus endpoint."""

    def test_focused_case_drives_planner_and_stimulus_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            outcome = probe_acceptance.assert_focused_case(
                self,
                "dhcp-discover-offer",
                out_dir=Path(temp_dir) / "harness",
                provider="qemu",
                profile="behavior",
                seed=1020,
            )

            self.assertEqual(outcome.report.get("status"), "dry-run")
            planned = outcome.report.get("metadata", {}).get("planned_case_names", [])
            self.assertIn("dhcp-discover-offer", planned)

            # The endpoint produced a result for the focused case and it built
            # the Discover (a dry-run plan compiles the outgoing stimulus packet).
            results = [
                result
                for result in outcome.response.get("results", [])
                if result.get("case") == "dhcp-discover-offer"
            ]
            self.assertTrue(results, "endpoint emitted no dhcp-discover-offer result")
            for result in results:
                metadata = result.get("metadata", {})
                self.assertTrue(metadata.get("dry_run"))
                # A planned dry-run carries the compiled stimulus packet bytes.
                self.assertTrue(metadata.get("sent_raw_hex"))


class DhcpRequestAckPlanTest(unittest.TestCase):
    """The plan carries an RFC-correct Request stimulus and Ack contract."""

    def test_plan_uses_dedicated_builder(self) -> None:
        self.assertIn("dhcp-request-ack", planning.PLAN_BUILDERS)
        self.assertIs(
            planning.PLAN_BUILDERS["dhcp-request-ack"],
            planning._dhcp_request_ack_probe_plan,
        )

    def test_plan_is_deterministic(self) -> None:
        self.assertEqual(_dhcp_request_ack_plan(), _dhcp_request_ack_plan())

    def test_plan_carries_a_request_stimulus(self) -> None:
        plan = _dhcp_request_ack_plan()

        self.assertEqual(plan["case"], "dhcp-request-ack")
        self.assertEqual(plan["stimulus"], "dhcp_request")
        self.assertEqual(plan["expected_response"], "dhcp_ack")

        # DHCP fixed ports: client 68 -> server 67.
        self.assertEqual(plan["source_port"], 68)
        self.assertEqual(plan["destination_port"], 67)

        # A client hardware address in the RFC 7042 documentation MAC range and a
        # 32-bit transaction id (xid).
        mac = plan["client_mac"]
        self.assertTrue(mac.startswith("00:00:5e:00:53:"))
        self.assertIsInstance(plan["transaction_id"], int)
        self.assertTrue(1 <= plan["transaction_id"] <= 0xFFFFFFFF)

        # The Request names the requested address (option 50) in documentation
        # space and the chosen server (option 54).
        requested = ipaddress.IPv4Address(plan["requested_ipv4"])
        self.assertIn(requested, ipaddress.ip_network("198.51.100.0/24"))
        self.assertEqual(plan["server_identifier"], plan["destination_ipv4"])

    def test_plan_ack_expectations(self) -> None:
        plan = _dhcp_request_ack_plan()

        # The assigned address equals the requested address and stays in
        # documentation space; the server identifier is the responder address.
        self.assertEqual(plan["expected_message_type"], "ack")
        self.assertEqual(plan["expected_message_type_value"], 5)
        self.assertEqual(plan["expected_yiaddr"], plan["requested_ipv4"])
        assigned = ipaddress.IPv4Address(plan["expected_yiaddr"])
        self.assertIn(assigned, ipaddress.ip_network("198.51.100.0/24"))
        self.assertEqual(plan["expected_server_identifier"], plan["destination_ipv4"])

        # Subnet/router/DNS configuration options the Ack commits.
        self.assertEqual(plan["expected_subnet_mask"], "255.255.255.0")
        self.assertTrue(plan["expected_router_ipv4"])
        dns = ipaddress.IPv4Address(plan["expected_dns_ipv4"])
        self.assertIn(dns, ipaddress.ip_network("198.51.100.0/24"))

        # Lease timing options: T1 < T2 < lease.
        self.assertGreater(plan["expected_lease_time"], 0)
        self.assertLess(plan["expected_renewal_time"], plan["expected_rebinding_time"])
        self.assertLess(plan["expected_rebinding_time"], plan["expected_lease_time"])

    def test_validation_contract_covers_ack_fields_and_direction(self) -> None:
        plan = _dhcp_request_ack_plan()
        validation = plan["validation"]

        # Peer addresses and ports (Ack flows server -> client, 67 -> 68).
        self.assertEqual(validation["source_ipv4"], plan["expected_reply_source_ipv4"])
        self.assertEqual(
            validation["destination_ipv4"], plan["expected_reply_destination_ipv4"]
        )
        self.assertEqual(validation["source_port"], 67)
        self.assertEqual(validation["destination_port"], 68)
        self.assertEqual(validation["direction"], "server_to_client")

        # BOOTP reply opcode and the Ack message type.
        self.assertEqual(validation["op_value"], 2)
        self.assertEqual(validation["message_type_value"], 5)

        # Identity: transaction id and client hardware address echoed.
        self.assertEqual(validation["transaction_id"], plan["transaction_id"])
        self.assertEqual(validation["client_hardware_address"], plan["client_mac"])

        # Assigned address, server identifier, configuration and lease options.
        self.assertEqual(validation["yiaddr"], plan["expected_yiaddr"])
        self.assertEqual(
            validation["server_identifier"], plan["expected_server_identifier"]
        )
        self.assertEqual(validation["subnet_mask"], plan["expected_subnet_mask"])
        self.assertEqual(validation["router_ipv4"], plan["expected_router_ipv4"])
        self.assertEqual(validation["dns_ipv4"], plan["expected_dns_ipv4"])
        self.assertEqual(validation["lease_time"], plan["expected_lease_time"])
        self.assertEqual(validation["renewal_time"], plan["expected_renewal_time"])
        self.assertEqual(validation["rebinding_time"], plan["expected_rebinding_time"])

    def test_target_service_is_controlled_dhcp_responder(self) -> None:
        target_service = _dhcp_request_ack_plan()["target_service"]
        self.assertTrue(target_service["required"])
        self.assertEqual(target_service["kind"], "dhcp-responder")
        self.assertEqual(target_service["port"], 67)
        self.assertEqual(target_service["client_port"], 68)
        self.assertEqual(
            target_service["client_mac"], _dhcp_request_ack_plan()["client_mac"]
        )
        self.assertEqual(
            target_service["requested_ipv4"], _dhcp_request_ack_plan()["requested_ipv4"]
        )

    def test_capture_filter_matches_ack_direction(self) -> None:
        plan = _dhcp_request_ack_plan()
        self.assertIn("src port 67", plan["capture_filter"])
        self.assertIn("dst port 68", plan["capture_filter"])
        self.assertIn(
            f"src host {plan['expected_reply_source_ipv4']}", plan["capture_filter"]
        )


class DhcpRequestAckTest(unittest.TestCase):
    """End-to-end focused acceptance through planner and stimulus endpoint."""

    def test_focused_case_drives_planner_and_stimulus_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            outcome = probe_acceptance.assert_focused_case(
                self,
                "dhcp-request-ack",
                out_dir=Path(temp_dir) / "harness",
                provider="qemu",
                profile="behavior",
                seed=1021,
            )

            self.assertEqual(outcome.report.get("status"), "dry-run")
            planned = outcome.report.get("metadata", {}).get("planned_case_names", [])
            self.assertIn("dhcp-request-ack", planned)

            # The endpoint produced a result for the focused case and it built
            # the Request (a dry-run plan compiles the outgoing stimulus packet).
            results = [
                result
                for result in outcome.response.get("results", [])
                if result.get("case") == "dhcp-request-ack"
            ]
            self.assertTrue(results, "endpoint emitted no dhcp-request-ack result")
            for result in results:
                metadata = result.get("metadata", {})
                self.assertTrue(metadata.get("dry_run"))
                # A planned dry-run carries the compiled stimulus packet bytes.
                self.assertTrue(metadata.get("sent_raw_hex"))


class DhcpClientIdentifierPlanTest(unittest.TestCase):
    """The plan carries a Discover with a client identifier and an echo contract."""

    def test_plan_uses_dedicated_builder(self) -> None:
        self.assertIn("dhcp-client-identifier", planning.PLAN_BUILDERS)
        self.assertIs(
            planning.PLAN_BUILDERS["dhcp-client-identifier"],
            planning._dhcp_client_identifier_probe_plan,
        )

    def test_plan_is_deterministic(self) -> None:
        self.assertEqual(
            _dhcp_client_identifier_plan(), _dhcp_client_identifier_plan()
        )

    def test_plan_carries_a_discover_with_client_identifier(self) -> None:
        plan = _dhcp_client_identifier_plan()

        self.assertEqual(plan["case"], "dhcp-client-identifier")
        self.assertEqual(plan["stimulus"], "dhcp_discover")
        self.assertEqual(plan["expected_response"], "dhcp_offer")

        # DHCP fixed ports: client 68 -> server 67.
        self.assertEqual(plan["source_port"], 68)
        self.assertEqual(plan["destination_port"], 67)

        # A client hardware address in the RFC 7042 documentation MAC range, a
        # 32-bit transaction id (xid), and an option-61 client identifier
        # distinct from the chaddr (carried as encoded option-61 payload hex).
        mac = plan["client_mac"]
        self.assertTrue(mac.startswith("00:00:5e:00:53:"))
        self.assertIsInstance(plan["transaction_id"], int)
        self.assertTrue(1 <= plan["transaction_id"] <= 0xFFFFFFFF)

        client_id_hex = plan["client_identifier_hex"]
        self.assertIsInstance(client_id_hex, str)
        client_id = bytes.fromhex(client_id_hex)
        self.assertGreater(len(client_id), 1)
        # RFC 4361 node-specific identifier: type octet 0xff.
        self.assertEqual(client_id[0], 0xFF)
        # The option-61 identity is not just the chaddr bytes.
        self.assertNotEqual(client_id_hex, mac.replace(":", ""))

    def test_offer_expectations_echo_the_client_identifier(self) -> None:
        plan = _dhcp_client_identifier_plan()

        self.assertEqual(plan["expected_message_type"], "offer")
        self.assertEqual(plan["expected_message_type_value"], 2)
        offered = ipaddress.IPv4Address(plan["expected_yiaddr"])
        self.assertIn(offered, ipaddress.ip_network("198.51.100.0/24"))
        self.assertEqual(plan["expected_server_identifier"], plan["destination_ipv4"])
        # The responder echoes back the same client identifier (RFC 6842).
        self.assertEqual(
            plan["expected_client_identifier_hex"], plan["client_identifier_hex"]
        )

    def test_validation_contract_covers_client_identifier(self) -> None:
        plan = _dhcp_client_identifier_plan()
        validation = plan["validation"]

        # Peer addresses and ports (Offer flows server -> client, 67 -> 68).
        self.assertEqual(validation["source_port"], 67)
        self.assertEqual(validation["destination_port"], 68)
        self.assertEqual(validation["direction"], "server_to_client")

        # Identity: transaction id, client hardware address, and the echoed
        # client identifier (option 61).
        self.assertEqual(validation["transaction_id"], plan["transaction_id"])
        self.assertEqual(validation["client_hardware_address"], plan["client_mac"])
        self.assertEqual(
            validation["client_identifier_hex"], plan["client_identifier_hex"]
        )

        # Offered address and server identifier.
        self.assertEqual(validation["yiaddr"], plan["expected_yiaddr"])
        self.assertEqual(
            validation["server_identifier"], plan["expected_server_identifier"]
        )

    def test_target_service_records_the_client_identifier(self) -> None:
        plan = _dhcp_client_identifier_plan()
        target_service = plan["target_service"]
        self.assertTrue(target_service["required"])
        self.assertEqual(target_service["kind"], "dhcp-responder")
        self.assertEqual(target_service["port"], 67)
        self.assertEqual(target_service["client_port"], 68)
        self.assertEqual(
            target_service["client_identifier_hex"], plan["client_identifier_hex"]
        )

    def test_capture_filter_matches_offer_direction(self) -> None:
        plan = _dhcp_client_identifier_plan()
        self.assertIn("src port 67", plan["capture_filter"])
        self.assertIn("dst port 68", plan["capture_filter"])


class DhcpClientIdentifierTest(unittest.TestCase):
    """End-to-end focused acceptance through planner and stimulus endpoint."""

    def test_focused_case_drives_planner_and_stimulus_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            outcome = probe_acceptance.assert_focused_case(
                self,
                "dhcp-client-identifier",
                out_dir=Path(temp_dir) / "harness",
                provider="qemu",
                profile="behavior",
                seed=1022,
            )

            self.assertEqual(outcome.report.get("status"), "dry-run")
            planned = outcome.report.get("metadata", {}).get("planned_case_names", [])
            self.assertIn("dhcp-client-identifier", planned)

            # The endpoint produced a result for the focused case and it built
            # the Discover (a dry-run plan compiles the outgoing stimulus packet).
            results = [
                result
                for result in outcome.response.get("results", [])
                if result.get("case") == "dhcp-client-identifier"
            ]
            self.assertTrue(
                results, "endpoint emitted no dhcp-client-identifier result"
            )
            for result in results:
                metadata = result.get("metadata", {})
                self.assertTrue(metadata.get("dry_run"))
                # A planned dry-run carries the compiled stimulus packet bytes.
                self.assertTrue(metadata.get("sent_raw_hex"))


if __name__ == "__main__":
    unittest.main()
