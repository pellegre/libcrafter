"""Focused behavior coverage for the mDNS probe cases.

The mDNS registration tests cover broad catalog membership. This module pins the
behavior-facing contracts: deterministic DNS-SD plan shape, validation metadata,
capability/failure taxonomy, target-service setup, and the dry-run path through
the Rust ``stimulus_endpoint`` adapter.
"""

from __future__ import annotations

import ipaddress
import tempfile
import unittest
from pathlib import Path

from tools.probe.engine import capabilities
from tools.probe.engine import cases as probe_cases
from tools.probe.engine import cli
from tools.probe.engine import planning
from tools.probe.engine import target_services
from tools.probe.engine.lab import probe_capabilities_from_lab_capabilities
from tools.probe.engine.model import ProbeRunRequest
from tools.probe.engine.protocols import mdns as mdns_protocol
from tools.probe.testing import probe_acceptance


MDNS_CASE_NAMES = tuple(case.name for case in mdns_protocol.MDNS_PROBE_CASES)


def _request(
    *,
    case_names: list[str] | None = None,
    **overrides: object,
) -> ProbeRunRequest:
    base = {
        "provider": "qemu",
        "profile": mdns_protocol.MDNS_SMOKE_PROFILE,
        "seed": 5353,
        "count": 1,
        "case_names": case_names or ["mdns-ipv4-multicast-browse"],
        "dry_run": True,
    }
    base.update(overrides)
    return ProbeRunRequest(**base)  # type: ignore[arg-type]


def _mdns_plan(case_name: str, *, seed: int = 5353, sequence: int = 0) -> dict:
    case = probe_cases.PROBE_CASE_BY_NAME[case_name]
    return planning.probe_plan_for_case(
        request=_request(case_names=[case_name], seed=seed),
        case=case,
        sequence=sequence,
    )


def _answer_types(message: dict) -> list[str]:
    return [str(record["record_type"]) for record in message["answers"]]


class MdnsBehaviorPlanTest(unittest.TestCase):
    def test_plan_builder_identity_and_profile_are_registered(self) -> None:
        self.assertEqual(
            set(probe_cases.profile_case_names(mdns_protocol.MDNS_SMOKE_PROFILE) or []),
            set(MDNS_CASE_NAMES),
        )
        for case_name in MDNS_CASE_NAMES:
            with self.subTest(case=case_name):
                self.assertIs(
                    planning.PLAN_BUILDERS[case_name],
                    planning._mdns_probe_plan,
                )
                self.assertIn(case_name, planning.PLANNED_ONLY_REGISTERED_CASES)

    def test_ipv4_browse_contract_is_deterministic_dns_sd_over_mdns(self) -> None:
        first = _mdns_plan("mdns-ipv4-multicast-browse")
        second = _mdns_plan("mdns-ipv4-multicast-browse")

        self.assertEqual(first, second)
        self.assertEqual(first["case"], "mdns-ipv4-multicast-browse")
        self.assertEqual(first["protocol"], "mdns")
        self.assertEqual(first["transport"], "udp")
        self.assertEqual(first["address_family"], "ipv4")
        self.assertEqual(first["destination_port"], 5353)
        self.assertEqual(first["destination_ipv4"], "224.0.0.251")
        self.assertEqual(first["multicast_group"], "224.0.0.251")

        question = first["mdns"]["questions"][0]
        self.assertEqual(question["name"], "_ipp._tcp.local.")
        self.assertEqual(question["record_type"], "PTR")
        self.assertFalse(question["unicast_response"])
        self.assertEqual(_answer_types(first["expected_mdns"]), ["PTR", "SRV", "TXT", "A"])

        validation = first["validation"]
        self.assertEqual(validation["expected_decode"], "mdns")
        self.assertEqual(validation["source_port"], 5353)
        self.assertEqual(validation["destination_port"], 5353)
        self.assertEqual(validation["expected_packet_count"], 1)
        self.assertEqual(validation["response_destination"], "multicast")
        self.assertEqual(
            [record["record_type"] for record in validation["expected_records"]],
            ["PTR", "SRV", "TXT", "A"],
        )

        self.assertIn("udp and src host", first["capture_filter"])
        self.assertIn("and src port 5353 and dst port 5353", first["capture_filter"])
        self.assertEqual(
            first["stimulus_driver"]["adapter_module"],
            "tools/probe/adapters/src/mdns.rs",
        )
        self.assertEqual(
            first["target_service"]["kind"],
            "mdns-controlled-responder",
        )
        self.assertEqual(first["target_service"]["runtime"], "probe-mdns-reference")

        self.assertIn(
            ipaddress.ip_address(first["source_ipv4"]),
            ipaddress.ip_network("192.0.2.0/24"),
        )
        self.assertIn(
            ipaddress.ip_address(first["target_ipv4"]),
            ipaddress.ip_network("198.51.100.0/24"),
        )

    def test_qu_suppression_announcement_and_goodbye_contracts(self) -> None:
        qu = _mdns_plan("mdns-qu-unicast-response", sequence=1)
        suppression = _mdns_plan("mdns-known-answer-suppression", sequence=2)
        announcement = _mdns_plan("mdns-announcement", sequence=3)
        goodbye = _mdns_plan("mdns-goodbye", sequence=4)

        self.assertTrue(qu["mdns"]["questions"][0]["unicast_response"])
        self.assertEqual(qu["expected_reply_destination_ipv4"], qu["source_ipv4"])
        self.assertEqual(qu["expected_mdns"]["response_delivery"], "unicast")
        self.assertEqual(qu["validation"]["response_destination"], "unicast")
        self.assertGreaterEqual(qu["source_port"], 49152)

        self.assertEqual(suppression["expected_mdns"]["message_kind"], "suppressed")
        self.assertEqual(suppression["expected_mdns"]["expected_packet_count"], 0)
        self.assertEqual(suppression["validation"]["expected_decode"], "no_mdns_response")
        self.assertEqual(suppression["validation"]["expected_packet_count"], 0)
        self.assertIn("suppressed_answer", suppression["expected_mdns"])

        self.assertEqual(announcement["stimulus_source_role"], "target")
        self.assertTrue(announcement["expected_mdns"]["unsolicited"])
        self.assertEqual(announcement["source_ipv4"], announcement["target_ipv4"])
        self.assertEqual(goodbye["validation"]["ttl"], 0)
        self.assertTrue(goodbye["expected_mdns"]["goodbye"])
        self.assertTrue(all(record["ttl"] == 0 for record in goodbye["expected_mdns"]["answers"]))

    def test_ipv6_browse_contract_records_link_local_scope_requirements(self) -> None:
        plan = _mdns_plan("mdns-ipv6-multicast-browse", sequence=5)

        self.assertEqual(plan["address_family"], "ipv6")
        self.assertEqual(plan["destination_ipv6"], "ff02::fb")
        self.assertEqual(plan["multicast_group"], "ff02::fb")
        self.assertIn("ip6 and udp", plan["capture_filter"])
        self.assertIn("mdns_ipv6_link_local_scope", plan["required_capabilities"])
        self.assertTrue(plan["wire_requirements"]["requires_ipv6_link_local_scope"])

        documentation = ipaddress.ip_network("2001:db8::/32")
        for key in (
            "source_ipv6",
            "target_ipv6",
            "expected_reply_source_ipv6",
            "expected_reply_destination_ipv6",
        ):
            with self.subTest(key=key):
                self.assertIn(ipaddress.ip_address(plan[key]), documentation)


class MdnsTargetServiceAndCapabilityTest(unittest.TestCase):
    def test_target_service_setup_groups_mdns_responder_requirements(self) -> None:
        plans = [
            _mdns_plan("mdns-ipv4-multicast-browse"),
            _mdns_plan("mdns-qu-unicast-response", sequence=1),
            _mdns_plan("mdns-known-answer-suppression", sequence=2),
        ]

        setup = target_services.target_service_setup_plan(
            probe_plans=plans,
            dry_run=True,
        )

        services = [
            service
            for service in setup["services"]
            if service["name"] == "mdns-controlled-responder"
        ]
        self.assertEqual(len(services), 1)
        service = services[0]
        self.assertEqual(service["protocol"], "udp")
        self.assertEqual(service["port"], 5353)
        self.assertEqual(service["runtime"], "probe-mdns-reference")
        self.assertTrue(service["planned_only"])
        self.assertTrue(service["supports"]["bonjour_records"])
        self.assertTrue(service["supports"]["known_answer_suppression"])
        self.assertIn("mdns-qu-unicast-response", service["cases"])

    def test_provider_capability_gates_are_stable(self) -> None:
        case = probe_cases.PROBE_CASE_BY_NAME["mdns-ipv6-multicast-browse"]
        provider_capabilities = probe_capabilities_from_lab_capabilities(
            "ipv6-scope-missing",
            {
                "provider": "ipv6-scope-missing",
                "ipv4_unicast": True,
                "ipv6_unicast": True,
                "controlled_services": True,
                "link_layer_send": True,
                "link_layer_capture": True,
                "multicast": True,
                "provider_mac_known": False,
                "live_packet_exchange": True,
            },
            dry_run=False,
        )

        missing = capabilities.missing_capabilities(case, provider_capabilities)

        self.assertEqual(missing, ["mdns_ipv6_link_local_scope"])
        self.assertEqual(
            capabilities.skip_reason_for_missing_capability(case, missing[0]),
            capabilities.SKIP_REQUIRES_IPV6_LINK_LOCAL_SCOPE_METADATA,
        )

    def test_failure_taxonomy_is_registered_for_every_mdns_case(self) -> None:
        expected = [
            "timeout",
            "wrong_peer",
            "wrong_payload",
            "decode_failed",
            "target_setup_failed",
        ]

        for case_name in MDNS_CASE_NAMES:
            with self.subTest(case=case_name):
                self.assertEqual(mdns_protocol.mdns_failure_reasons(case_name), expected)
                self.assertEqual(cli._failure_reasons_for_case(case_name), expected)


class MdnsDryRunEndpointTest(unittest.TestCase):
    def test_focused_ipv4_browse_drives_planner_and_stimulus_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            outcome = probe_acceptance.assert_focused_case(
                self,
                "mdns-ipv4-multicast-browse",
                out_dir=Path(temp_dir) / "harness",
                provider="qemu",
                profile=mdns_protocol.MDNS_SMOKE_PROFILE,
                seed=5353,
            )

            self.assertEqual(outcome.report.get("status"), "dry-run")
            planned = outcome.report.get("metadata", {}).get("planned_case_names", [])
            self.assertIn("mdns-ipv4-multicast-browse", planned)

            request_plans = [
                plan
                for plan in outcome.request.get("probe_plans", [])
                if plan.get("case") == "mdns-ipv4-multicast-browse"
            ]
            self.assertTrue(request_plans, "request emitted no mDNS browse plan")
            self.assertEqual(request_plans[0]["mdns"]["questions"][0]["record_type"], "PTR")
            self.assertEqual(request_plans[0]["expected_mdns"]["answers"][0]["record_type"], "PTR")

            results = [
                result
                for result in outcome.response.get("results", [])
                if result.get("case") == "mdns-ipv4-multicast-browse"
            ]
            self.assertTrue(results, "endpoint emitted no mDNS browse result")
            for result in results:
                metadata = result.get("metadata", {})
                self.assertEqual(result.get("status"), "planned")
                self.assertTrue(metadata.get("dry_run"))
                self.assertTrue(metadata.get("sent_raw_hex"))
                self.assertEqual(
                    metadata["sent_decoded"]["mdns"]["questions"][0]["type"],
                    12,
                )
                self.assertEqual(
                    metadata["sent_decoded"]["udp"]["dport"],
                    5353,
                )
                self.assertEqual(
                    metadata["target_service"]["kind"],
                    "mdns-controlled-responder",
                )
                self.assertEqual(
                    [record["record_type"] for record in metadata["expected_mdns"]["answers"]],
                    ["PTR", "SRV", "TXT", "A"],
                )


if __name__ == "__main__":
    unittest.main()
