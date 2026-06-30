"""Offline unit coverage for mDNS probe registration and dry-run plans."""

from __future__ import annotations

import ipaddress
import unittest

from tools.probe.engine import capabilities
from tools.probe.engine import cases as probe_cases
from tools.probe.engine import planning
from tools.probe.engine.lab import (
    LOCAL_DRY_RUN_PROVIDER,
    probe_capabilities_for_provider,
    probe_capabilities_from_lab_capabilities,
)
from tools.probe.engine.model import ProbeRunRequest
from tools.probe.engine.protocols import PROTOCOL_REGISTRY
from tools.probe.engine.protocols import mdns as mdns_protocol


MDNS_CASE_NAMES = tuple(case.name for case in mdns_protocol.MDNS_PROBE_CASES)


def _request(**overrides: object) -> ProbeRunRequest:
    base = {
        "provider": "local-dry-run",
        "profile": mdns_protocol.MDNS_SMOKE_PROFILE,
        "seed": 5353,
        "count": len(MDNS_CASE_NAMES),
        "case_names": [],
        "dry_run": True,
    }
    base.update(overrides)
    return ProbeRunRequest(**base)  # type: ignore[arg-type]


def _mdns_plan(case_name: str, *, seed: int = 5353, sequence: int = 0) -> dict:
    case = probe_cases.PROBE_CASE_BY_NAME[case_name]
    return planning.probe_plan_for_case(
        request=_request(seed=seed),
        case=case,
        sequence=sequence,
    )


def _answer_types(plan_section: dict) -> list[str]:
    return [str(answer["record_type"]) for answer in plan_section["answers"]]


class MdnsProbeRegistrationTest(unittest.TestCase):
    def test_mdns_plugin_registers_cases_and_profile_contribution(self) -> None:
        plugin = PROTOCOL_REGISTRY.require("mdns")

        self.assertEqual(tuple(case.name for case in plugin.cases), MDNS_CASE_NAMES)
        self.assertEqual(
            plugin.profile_counts[mdns_protocol.MDNS_SMOKE_PROFILE],
            {name: 1 for name in MDNS_CASE_NAMES},
        )
        self.assertEqual(plugin.planned_only_cases, frozenset(MDNS_CASE_NAMES))
        self.assertIs(plugin.target_service, mdns_protocol.mdns_target_service_contribution)
        self.assertIs(plugin.lab_capabilities, mdns_protocol.mdns_lab_capabilities)

    def test_mdns_cases_are_catalog_entries_with_expected_capabilities(self) -> None:
        expected_capabilities = {
            "mdns-ipv4-multicast-browse": [
                "mdns_ipv4_multicast",
                "mdns_controlled_responder",
            ],
            "mdns-ipv6-multicast-browse": [
                "mdns_ipv6_multicast",
                "mdns_ipv6_link_local_scope",
                "mdns_controlled_responder",
            ],
            "mdns-qu-unicast-response": [
                "mdns_ipv4_multicast",
                "mdns_unicast_response",
                "mdns_controlled_responder",
            ],
        }
        default_capabilities = [
            "mdns_ipv4_multicast",
            "mdns_controlled_responder",
        ]

        for case in mdns_protocol.MDNS_PROBE_CASES:
            with self.subTest(case=case.name):
                self.assertIs(probe_cases.PROBE_CASE_BY_NAME[case.name], case)
                self.assertEqual(case.metadata["protocol"], "mdns")
                self.assertEqual(case.metadata["transport"], "udp")
                self.assertEqual(case.metadata["service"], "mdns-controlled-responder")
                self.assertEqual(case.metadata["udp_port"], 5353)
                self.assertIs(case.metadata["planned_only"], True)
                self.assertEqual(
                    case.required_capabilities,
                    expected_capabilities.get(case.name, default_capabilities),
                )


class MdnsProbePlanDispatchTest(unittest.TestCase):
    def test_plan_builders_are_registered_with_identity(self) -> None:
        for case_name in MDNS_CASE_NAMES:
            with self.subTest(case=case_name):
                self.assertIn(case_name, planning.PLAN_BUILDERS)
                self.assertIs(
                    planning.PLAN_BUILDERS[case_name],
                    planning._mdns_probe_plan,
                )
                self.assertIn(case_name, planning.PLANNED_ONLY_REGISTERED_CASES)

    def test_ipv4_browse_plan_carries_multicast_dns_sd_contract(self) -> None:
        plan = _mdns_plan("mdns-ipv4-multicast-browse")

        self.assertEqual(plan["case"], "mdns-ipv4-multicast-browse")
        self.assertIs(plan["planned_only"], True)
        self.assertIs(plan["live_capable"], True)
        self.assertEqual(plan["protocol"], "mdns")
        self.assertEqual(plan["transport"], "udp")
        self.assertEqual(plan["destination_port"], 5353)
        self.assertEqual(plan["destination_ipv4"], "224.0.0.251")
        self.assertEqual(plan["multicast_group"], "224.0.0.251")
        self.assertEqual(plan["mdns"]["questions"][0]["name"], "_ipp._tcp.local.")
        self.assertEqual(plan["mdns"]["questions"][0]["record_type"], "PTR")
        self.assertFalse(plan["mdns"]["questions"][0]["unicast_response"])
        self.assertEqual(_answer_types(plan["expected_mdns"]), ["PTR", "SRV", "TXT", "A"])
        self.assertEqual(
            plan["target_service"]["kind"],
            "mdns-controlled-responder",
        )
        self.assertEqual(plan["target_service"]["service_name"], "_ipp._tcp.local.")
        self.assertEqual(
            plan["stimulus_driver"]["adapter_module"],
            "tools/probe/adapters/src/mdns.rs",
        )
        self.assertEqual(plan["validation"]["expected_decode"], "mdns")
        self.assertIn("udp and src host", plan["capture_filter"])
        self.assertEqual(
            plan["documentation_prefixes"],
            ["192.0.2.0/24", "198.51.100.0/24"],
        )
        self.assertIn(
            ipaddress.ip_address(plan["source_ipv4"]),
            ipaddress.ip_network("192.0.2.0/24"),
        )
        self.assertIn(
            ipaddress.ip_address(plan["target_ipv4"]),
            ipaddress.ip_network("198.51.100.0/24"),
        )

    def test_ipv6_browse_plan_uses_mdns_link_local_multicast(self) -> None:
        plan = _mdns_plan("mdns-ipv6-multicast-browse", sequence=1)

        self.assertEqual(plan["destination_ipv6"], "ff02::fb")
        self.assertEqual(plan["multicast_group"], "ff02::fb")
        self.assertEqual(plan["target_service"]["bind_ipv6"], plan["target_ipv6"])
        self.assertEqual(plan["validation"]["expected_decode"], "mdns")
        self.assertIn("ip6 and udp", plan["capture_filter"])
        documentation = ipaddress.ip_network("2001:db8::/32")
        for key in (
            "source_ipv6",
            "target_ipv6",
            "expected_reply_source_ipv6",
            "expected_reply_destination_ipv6",
        ):
            with self.subTest(key=key):
                self.assertIn(ipaddress.ip_address(plan[key]), documentation)

    def test_qu_plan_sets_unicast_response_preference(self) -> None:
        plan = _mdns_plan("mdns-qu-unicast-response", sequence=2)

        self.assertGreaterEqual(plan["source_port"], 49152)
        self.assertLess(plan["source_port"], 65536)
        self.assertEqual(plan["expected_reply_destination_ipv4"], plan["source_ipv4"])
        self.assertTrue(plan["mdns"]["questions"][0]["unicast_response"])
        self.assertEqual(plan["expected_mdns"]["response_delivery"], "unicast")
        self.assertEqual(plan["validation"]["response_destination"], "unicast")

    def test_service_resolve_and_bonjour_txt_plans_record_dns_sd_details(self) -> None:
        resolve = _mdns_plan("mdns-service-resolve", sequence=3)
        txt = _mdns_plan("mdns-bonjour-txt", sequence=9)

        self.assertEqual(
            [question["record_type"] for question in resolve["mdns"]["questions"]],
            ["SRV", "TXT"],
        )
        self.assertIn("SRV", _answer_types(resolve["expected_mdns"]))
        self.assertIn("TXT", _answer_types(resolve["expected_mdns"]))
        self.assertEqual(txt["mdns"]["questions"][0]["record_type"], "TXT")
        self.assertEqual(
            txt["validation"]["bonjour_txt_keys"],
            ["txtvers", "qtotal", "rp", "ty", "UUID"],
        )
        self.assertIn("txtvers=1", txt["target_service"]["txt_strings"])

    def test_announcement_goodbye_suppression_and_cache_flush_contracts(self) -> None:
        announcement = _mdns_plan("mdns-announcement", sequence=4)
        goodbye = _mdns_plan("mdns-goodbye", sequence=5)
        suppression = _mdns_plan("mdns-known-answer-suppression", sequence=6)
        cache_flush = _mdns_plan("mdns-cache-flush-response", sequence=7)

        self.assertEqual(announcement["stimulus_source_role"], "target")
        self.assertTrue(announcement["expected_mdns"]["unsolicited"])
        self.assertEqual(goodbye["validation"]["ttl"], 0)
        self.assertTrue(goodbye["expected_mdns"]["goodbye"])
        self.assertEqual(suppression["validation"]["expected_decode"], "no_mdns_response")
        self.assertEqual(suppression["validation"]["expected_packet_count"], 0)
        self.assertTrue(cache_flush["validation"]["cache_flush_required"])
        self.assertTrue(cache_flush["expected_mdns"]["answers"][0]["cache_flush"])

    def test_plans_are_deterministic(self) -> None:
        for sequence, case_name in enumerate(MDNS_CASE_NAMES):
            with self.subTest(case=case_name):
                first = _mdns_plan(case_name, seed=9901, sequence=sequence)
                second = _mdns_plan(case_name, seed=9901, sequence=sequence)

                self.assertEqual(first, second)
                self.assertEqual(first["service_port"], 5353)
                self.assertEqual(first["target_service"]["port"], 5353)


class MdnsProbeCapabilityTest(unittest.TestCase):
    def test_lab_capabilities_derive_mdns_multicast_and_scope_bits(self) -> None:
        substrate = {
            "provider": "qemu",
            "ipv4_unicast": True,
            "ipv6_unicast": True,
            "controlled_services": True,
            "link_layer_send": True,
            "link_layer_capture": True,
            "multicast": True,
            "provider_mac_known": True,
            "live_packet_exchange": True,
        }
        derived = probe_capabilities_from_lab_capabilities(
            "qemu",
            substrate,
            dry_run=True,
        )

        for capability_name in (
            "mdns_controlled_responder",
            "mdns_unicast_response",
            "mdns_ipv4_multicast",
            "mdns_ipv6_multicast",
            "mdns_ipv6_link_local_scope",
        ):
            with self.subTest(capability=capability_name):
                self.assertIs(derived[capability_name], True)

    def test_local_dry_run_grants_mdns_offline_planning_only(self) -> None:
        derived = probe_capabilities_for_provider(
            LOCAL_DRY_RUN_PROVIDER,
            dry_run=True,
        )

        self.assertFalse(derived["live_packet_exchange"])
        self.assertIs(derived["lab_capabilities"]["mdns_offline_plan"], True)
        for capability_name in (
            "mdns_controlled_responder",
            "mdns_unicast_response",
            "mdns_ipv4_multicast",
            "mdns_ipv6_multicast",
            "mdns_ipv6_link_local_scope",
        ):
            with self.subTest(capability=capability_name):
                self.assertIs(derived[capability_name], True)

        for case in mdns_protocol.MDNS_PROBE_CASES:
            with self.subTest(case=case.name):
                self.assertEqual(capabilities.missing_capabilities(case, derived), [])

    def test_mdns_offline_plan_is_dry_run_only(self) -> None:
        substrate = {
            "provider": "local-shape-live",
            "dry_run": False,
            "ipv4_unicast": True,
            "ipv6_unicast": False,
            "controlled_services": True,
            "link_layer_send": False,
            "link_layer_capture": False,
            "multicast": False,
            "provider_mac_known": False,
            "live_packet_exchange": False,
            "mdns_offline_plan": True,
        }

        derived = probe_capabilities_from_lab_capabilities(
            "local-shape-live",
            substrate,
            dry_run=False,
        )

        self.assertIs(derived["mdns_controlled_responder"], True)
        self.assertIs(derived["mdns_unicast_response"], True)
        self.assertIs(derived["mdns_ipv4_multicast"], False)
        self.assertIs(derived["mdns_ipv6_multicast"], False)
        self.assertIs(derived["mdns_ipv6_link_local_scope"], False)

    def test_ipv6_scope_skip_reason_is_stable(self) -> None:
        substrate = {
            "provider": "ipv6-multicast-no-mac",
            "ipv4_unicast": True,
            "ipv6_unicast": True,
            "controlled_services": True,
            "link_layer_send": True,
            "link_layer_capture": True,
            "multicast": True,
            "provider_mac_known": False,
            "live_packet_exchange": True,
        }
        derived = probe_capabilities_from_lab_capabilities(
            "ipv6-multicast-no-mac",
            substrate,
            dry_run=True,
        )
        case = probe_cases.PROBE_CASE_BY_NAME["mdns-ipv6-multicast-browse"]

        self.assertIs(derived["mdns_ipv6_multicast"], True)
        self.assertIs(derived["mdns_ipv6_link_local_scope"], False)
        self.assertEqual(
            capabilities.missing_capabilities(case, derived),
            ["mdns_ipv6_link_local_scope"],
        )
        self.assertEqual(
            capabilities.skip_reason_for_missing_capability(
                case,
                "mdns_ipv6_link_local_scope",
            ),
            capabilities.SKIP_REQUIRES_IPV6_LINK_LOCAL_SCOPE_METADATA,
        )


if __name__ == "__main__":
    unittest.main()
