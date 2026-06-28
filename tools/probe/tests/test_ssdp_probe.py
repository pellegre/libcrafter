"""Offline unit coverage for SSDP probe registration and dry-run plans."""

from __future__ import annotations

import ipaddress
import unittest

from tools.probe.engine import cases as probe_cases
from tools.probe.engine import planning
from tools.probe.engine.model import ProbeRunRequest
from tools.probe.engine.protocols import PROTOCOL_REGISTRY
from tools.probe.engine.protocols import ssdp as ssdp_protocol


SSDP_CASE_NAMES = tuple(case.name for case in ssdp_protocol.SSDP_PROBE_CASES)
SSDP_LIVE_CASES = (
    "ssdp-ipv4-search-exchange",
    "ssdp-ipv6-search-exchange",
    "ssdp-notify-capture",
)
SSDP_OFFLINE_CASES = (
    "ssdp-raw-fallback",
    "ssdp-malformed-observation",
)


def _request(**overrides: object) -> ProbeRunRequest:
    base = {
        "provider": "local-dry-run",
        "profile": ssdp_protocol.SSDP_SMOKE_PROFILE,
        "seed": 4242,
        "count": len(SSDP_CASE_NAMES),
        "case_names": [],
        "dry_run": True,
    }
    base.update(overrides)
    return ProbeRunRequest(**base)  # type: ignore[arg-type]


def _ssdp_plan(case_name: str, *, seed: int = 4242, sequence: int = 0) -> dict:
    case = probe_cases.PROBE_CASE_BY_NAME[case_name]
    return planning.probe_plan_for_case(
        request=_request(seed=seed),
        case=case,
        sequence=sequence,
    )


def _headers_by_name(plan_section: dict) -> dict[str, str]:
    return {
        str(header["name"]): str(header["value"])
        for header in plan_section["headers"]
    }


class SsdpProbeRegistrationTest(unittest.TestCase):
    def test_ssdp_plugin_registers_cases_and_profile_contribution(self) -> None:
        plugin = PROTOCOL_REGISTRY.require("ssdp")

        self.assertEqual(tuple(case.name for case in plugin.cases), SSDP_CASE_NAMES)
        self.assertEqual(
            plugin.profile_counts[ssdp_protocol.SSDP_SMOKE_PROFILE],
            {name: 1 for name in SSDP_CASE_NAMES},
        )
        self.assertEqual(plugin.planned_only_cases, frozenset(SSDP_CASE_NAMES))
        self.assertIs(
            plugin.rewrite_endpoint_addresses,
            ssdp_protocol.ssdp_rewrite_endpoint_addresses,
        )

    def test_ssdp_cases_are_catalog_entries_with_expected_capabilities(self) -> None:
        expected_capabilities = {
            "ssdp-ipv4-search-exchange": [
                "ssdp_ipv4_multicast",
                "ssdp_controlled_responder",
            ],
            "ssdp-ipv6-search-exchange": [
                "ssdp_ipv6_multicast",
                "ssdp_controlled_responder",
            ],
            "ssdp-notify-capture": [
                "ssdp_ipv4_multicast",
                "ssdp_controlled_responder",
            ],
            "ssdp-raw-fallback": ["ssdp_offline_plan"],
            "ssdp-malformed-observation": ["ssdp_offline_plan"],
        }

        for case in ssdp_protocol.SSDP_PROBE_CASES:
            with self.subTest(case=case.name):
                self.assertIs(probe_cases.PROBE_CASE_BY_NAME[case.name], case)
                self.assertEqual(case.metadata["protocol"], "ssdp")
                self.assertEqual(case.metadata["transport"], "udp")
                self.assertEqual(case.metadata["service"], "ssdp-controlled-responder")
                self.assertEqual(case.metadata["udp_port"], 1900)
                self.assertIs(case.metadata["planned_only"], True)
                self.assertEqual(
                    case.required_capabilities,
                    expected_capabilities[case.name],
                )


class SsdpProbePlanDispatchTest(unittest.TestCase):
    def test_plan_builders_are_registered_with_identity(self) -> None:
        for case_name in SSDP_CASE_NAMES:
            with self.subTest(case=case_name):
                self.assertIn(case_name, planning.PLAN_BUILDERS)
                self.assertIs(
                    planning.PLAN_BUILDERS[case_name],
                    planning._ssdp_probe_plan,
                )
                self.assertIn(case_name, planning.PLANNED_ONLY_REGISTERED_CASES)

    def test_ipv4_search_plan_carries_wire_shape(self) -> None:
        plan = _ssdp_plan("ssdp-ipv4-search-exchange")
        headers = _headers_by_name(plan["ssdp"])
        expected_headers = _headers_by_name(plan["expected_ssdp"])

        self.assertEqual(plan["case"], "ssdp-ipv4-search-exchange")
        self.assertIs(plan["planned_only"], True)
        self.assertIs(plan["live_capable"], True)
        self.assertEqual(plan["protocol"], "ssdp")
        self.assertEqual(plan["transport"], "udp")
        self.assertEqual(plan["destination_port"], 1900)
        self.assertEqual(plan["destination_ipv4"], "239.255.255.250")
        self.assertEqual(plan["multicast_group"], "239.255.255.250")
        self.assertGreaterEqual(plan["source_port"], 49152)
        self.assertLess(plan["source_port"], 65536)
        self.assertEqual(plan["ssdp"]["method"], "M-SEARCH")
        self.assertEqual(headers["HOST"], "239.255.255.250:1900")
        self.assertEqual(headers["MAN"], '"ssdp:discover"')
        self.assertEqual(headers["ST"], "ssdp:all")
        self.assertEqual(plan["expected_ssdp"]["status_code"], 200)
        self.assertEqual(expected_headers["ST"], "upnp:rootdevice")
        self.assertTrue(expected_headers["LOCATION"].startswith("http://192.0.2."))
        self.assertEqual(plan["payload_hex"], plan["udp_payload_hex"])
        self.assertEqual(len(bytes.fromhex(plan["payload_hex"])), plan["payload_length"])
        self.assertEqual(
            plan["target_service"]["kind"],
            "ssdp-controlled-responder",
        )
        self.assertEqual(plan["target_service"]["behavior"], "search_response")
        self.assertEqual(
            plan["target_service"]["response_payload_hex"],
            plan["expected_payload_hex"],
        )
        self.assertEqual(
            plan["stimulus_driver"]["adapter_module"],
            "tools/probe/adapters/src/ssdp.rs",
        )
        self.assertEqual(plan["validation"]["expected_decode"], "ssdp")
        documentation = ipaddress.ip_network("198.51.100.0/24")
        self.assertIn(ipaddress.ip_address(plan["source_ipv4"]), documentation)
        self.assertIn(ipaddress.ip_address(plan["target_ipv4"]), documentation)
        self.assertEqual(
            plan["documentation_prefixes"],
            ["198.51.100.0/24", "192.0.2.0/24"],
        )

    def test_ipv6_search_plan_uses_link_local_multicast(self) -> None:
        plan = _ssdp_plan("ssdp-ipv6-search-exchange", sequence=1)
        headers = _headers_by_name(plan["ssdp"])
        documentation = ipaddress.ip_network("2001:db8::/32")

        self.assertEqual(plan["destination_ipv6"], "ff02::c")
        self.assertEqual(plan["multicast_group"], "ff02::c")
        self.assertEqual(headers["HOST"], "[ff02::c]:1900")
        self.assertEqual(plan["target_service"]["behavior"], "search_response_ipv6")
        self.assertEqual(plan["validation"]["expected_decode"], "ssdp")
        self.assertIn("ip6 and udp", plan["capture_filter"])
        for key in (
            "source_ipv6",
            "target_ipv6",
            "expected_reply_source_ipv6",
            "expected_reply_destination_ipv6",
        ):
            with self.subTest(key=key):
                self.assertIn(ipaddress.ip_address(plan[key]), documentation)
        self.assertEqual(
            plan["documentation_prefixes"],
            ["2001:db8::/32", "192.0.2.0/24"],
        )

    def test_notify_plan_records_capture_side_observation(self) -> None:
        plan = _ssdp_plan("ssdp-notify-capture", sequence=2)
        headers = _headers_by_name(plan["ssdp"])

        self.assertEqual(plan["source_port"], 1900)
        self.assertEqual(plan["destination_port"], 1900)
        self.assertEqual(plan["ssdp"]["method"], "NOTIFY")
        self.assertEqual(headers["NT"], "upnp:rootdevice")
        self.assertEqual(headers["NTS"], "ssdp:alive")
        self.assertEqual(plan["expected_payload_hex"], plan["payload_hex"])
        self.assertEqual(plan["target_service"]["behavior"], "notify_emit")
        self.assertEqual(
            plan["target_service"]["notify_payload_hex"],
            plan["payload_hex"],
        )
        self.assertTrue(plan["wire_requirements"]["requires_capture"])
        self.assertEqual(plan["validation"]["method"], "NOTIFY")

    def test_raw_and_malformed_offline_plans_are_decode_safe(self) -> None:
        raw = _ssdp_plan("ssdp-raw-fallback", sequence=3)
        malformed = _ssdp_plan("ssdp-malformed-observation", sequence=4)

        self.assertIs(raw["live_capable"], False)
        self.assertTrue(raw["wire_requirements"]["offline_only"])
        self.assertFalse(raw["wire_requirements"]["requires_live_network"])
        self.assertEqual(raw["validation"]["expected_decode"], "raw")
        self.assertEqual(raw["expected_ssdp"]["message_kind"], "raw_preserved")
        self.assertEqual(raw["target_service"]["kind"], "none")
        self.assertEqual(raw["payload_hex"], raw["expected_payload_hex"])

        self.assertIs(malformed["live_capable"], False)
        self.assertTrue(malformed["wire_requirements"]["offline_only"])
        self.assertEqual(malformed["validation"]["expected_decode"], "structured_error")
        self.assertEqual(malformed["validation"]["error_context"], "ssdp.header")
        self.assertEqual(malformed["expected_ssdp"]["context"], "ssdp.header")
        self.assertEqual(
            malformed["expected_ssdp"]["required"],
            "header-name ':' header-value",
        )
        self.assertEqual(malformed["target_service"]["kind"], "none")

    def test_plans_are_deterministic(self) -> None:
        for sequence, case_name in enumerate(SSDP_CASE_NAMES):
            with self.subTest(case=case_name):
                first = _ssdp_plan(case_name, seed=9901, sequence=sequence)
                second = _ssdp_plan(case_name, seed=9901, sequence=sequence)

                self.assertEqual(first, second)
                self.assertEqual(first["payload_hex"], first["udp_payload_hex"])
                self.assertEqual(
                    len(bytes.fromhex(first["payload_hex"])),
                    first["payload_length"],
                )
                self.assertEqual(
                    len(bytes.fromhex(first["expected_payload_hex"])),
                    first["expected_payload_length"],
                )


class SsdpProbeSkipReasonTest(unittest.TestCase):
    def test_live_capable_cases_record_stable_skip_reasons(self) -> None:
        for case_name in SSDP_LIVE_CASES:
            with self.subTest(case=case_name):
                plan = _ssdp_plan(case_name)

                self.assertEqual(
                    plan["skip_reasons"]["capability"],
                    ["requires_multicast", "requires_controlled_service"],
                )
                self.assertEqual(
                    plan["skip_reasons"]["failure"],
                    [
                        "timeout",
                        "wrong_peer",
                        "wrong_payload",
                        "decode_failed",
                        "target_setup_failed",
                    ],
                )

    def test_offline_cases_record_non_live_skip_reasons(self) -> None:
        expected_failures = {
            "ssdp-raw-fallback": ["wrong_payload", "decode_failed"],
            "ssdp-malformed-observation": ["decode_failed", "wrong_payload"],
        }

        for case_name in SSDP_OFFLINE_CASES:
            with self.subTest(case=case_name):
                plan = _ssdp_plan(case_name)

                self.assertEqual(
                    plan["skip_reasons"]["capability"],
                    ["offline_plan_unavailable"],
                )
                self.assertEqual(
                    plan["skip_reasons"]["failure"],
                    expected_failures[case_name],
                )
                self.assertFalse(plan["live_capable"])


class SsdpProbeAddressRewriteTest(unittest.TestCase):
    def _rewrite(self, case_name: str, **metadata: object) -> dict:
        return ssdp_protocol.ssdp_rewrite_endpoint_addresses(
            _ssdp_plan(case_name),
            source_ipv4="10.77.0.10",
            target_ipv4="10.77.0.20",
            rewrite_source="lab_session",
            **metadata,
        )

    def test_ipv4_search_rewrite_uses_lab_hosts_and_keeps_multicast_send(self) -> None:
        rewritten = self._rewrite("ssdp-ipv4-search-exchange")
        source_port = rewritten["source_port"]

        self.assertEqual(rewritten["source_ipv4"], "10.77.0.10")
        self.assertEqual(rewritten["destination_ipv4"], "239.255.255.250")
        self.assertEqual(rewritten["target_ipv4"], "10.77.0.20")
        self.assertEqual(rewritten["expected_reply_source_ipv4"], "10.77.0.20")
        self.assertEqual(rewritten["expected_reply_destination_ipv4"], "10.77.0.10")
        self.assertEqual(
            rewritten["capture_filter"],
            (
                "udp and src host 10.77.0.20 and dst host 10.77.0.10 "
                f"and src port 1900 and dst port {source_port}"
            ),
        )
        self.assertEqual(rewritten["validation"]["source_ipv4"], "10.77.0.20")
        self.assertEqual(rewritten["validation"]["destination_ipv4"], "10.77.0.10")
        self.assertEqual(rewritten["target_service"]["bind_ipv4"], "10.77.0.20")
        self.assertEqual(rewritten["target_service"]["source_ipv4"], "10.77.0.10")
        self.assertEqual(
            rewritten["live_address_rewrite"],
            {
                "source": "lab_session",
                "status": "rewritten",
                "stimulus_ipv4": "10.77.0.10",
                "target_ipv4": "10.77.0.20",
                "emitted_source_ipv4": "10.77.0.10",
                "preserved_destination_ipv4": "239.255.255.250",
            },
        )

    def test_notify_rewrite_emits_from_target_and_keeps_multicast_destination(self) -> None:
        rewritten = self._rewrite("ssdp-notify-capture")

        self.assertEqual(rewritten["source_ipv4"], "10.77.0.20")
        self.assertEqual(rewritten["destination_ipv4"], "239.255.255.250")
        self.assertEqual(rewritten["target_ipv4"], "10.77.0.20")
        self.assertEqual(rewritten["expected_reply_source_ipv4"], "10.77.0.20")
        self.assertEqual(rewritten["expected_reply_destination_ipv4"], "10.77.0.10")
        self.assertEqual(
            rewritten["capture_filter"],
            (
                "udp and src host 10.77.0.20 and dst host 239.255.255.250 "
                "and src port 1900 and dst port 1900"
            ),
        )
        self.assertEqual(rewritten["validation"]["source_ipv4"], "10.77.0.20")
        self.assertEqual(
            rewritten["validation"]["destination_ipv4"],
            "239.255.255.250",
        )
        self.assertEqual(rewritten["target_service"]["bind_ipv4"], "10.77.0.20")
        self.assertEqual(rewritten["target_service"]["source_ipv4"], "10.77.0.10")
        self.assertEqual(
            rewritten["live_address_rewrite"]["preserved_destination_ipv4"],
            "239.255.255.250",
        )
        self.assertEqual(
            rewritten["live_address_rewrite"]["emitted_source_ipv4"],
            "10.77.0.20",
        )

    def test_ipv6_link_local_rewrite_uses_mac_derived_addresses(self) -> None:
        rewritten = self._rewrite(
            "ssdp-ipv6-search-exchange",
            source_mac="02:00:00:00:00:10",
            target_mac="02:00:00:00:00:20",
            target_interface="eth1",
        )

        self.assertEqual(rewritten["source_ipv6"], "fe80::ff:fe00:10")
        self.assertEqual(rewritten["destination_ipv6"], "ff02::c")
        self.assertEqual(rewritten["target_ipv6"], "fe80::ff:fe00:20")
        self.assertEqual(rewritten["expected_reply_source_ipv6"], "fe80::ff:fe00:20")
        self.assertEqual(
            rewritten["expected_reply_destination_ipv6"],
            "fe80::ff:fe00:10",
        )
        self.assertEqual(
            rewritten["capture_filter"],
            (
                "ip6 and udp and src host fe80::ff:fe00:20 "
                "and dst host fe80::ff:fe00:10 "
                f"and src port 1900 and dst port {rewritten['source_port']}"
            ),
        )
        self.assertEqual(rewritten["validation"]["source_ipv6"], "fe80::ff:fe00:20")
        self.assertEqual(
            rewritten["validation"]["destination_ipv6"],
            "fe80::ff:fe00:10",
        )
        self.assertEqual(rewritten["target_service"]["bind_ipv6"], "fe80::ff:fe00:20")
        self.assertEqual(
            rewritten["target_service"]["source_ipv6"],
            "fe80::ff:fe00:10",
        )
        self.assertEqual(rewritten["target_service"]["interface"], "eth1")
        self.assertEqual(
            rewritten["live_address_rewrite"]["preserved_destination_ipv6"],
            "ff02::c",
        )
        self.assertNotIn("source_ipv4", rewritten)
        self.assertNotIn("destination_ipv4", rewritten)

    def test_ipv6_link_local_rewrite_skips_without_ipv6_scope_metadata(self) -> None:
        plan = _ssdp_plan("ssdp-ipv6-search-exchange")
        rewritten = self._rewrite("ssdp-ipv6-search-exchange")

        self.assertEqual(rewritten["source_ipv6"], plan["source_ipv6"])
        self.assertEqual(rewritten["destination_ipv6"], "ff02::c")
        self.assertEqual(rewritten["target_ipv6"], plan["target_ipv6"])
        self.assertNotIn("source_ipv4", rewritten)
        self.assertNotIn("destination_ipv4", rewritten)
        self.assertEqual(
            rewritten["skip_reasons"]["address_rewrite"],
            ["requires_ipv6_link_local_scope_metadata"],
        )
        self.assertEqual(
            rewritten["wire_requirements"]["address_rewrite_skip_reason"],
            "requires_ipv6_link_local_scope_metadata",
        )
        self.assertEqual(
            rewritten["live_address_rewrite"],
            {
                "source": "lab_session",
                "status": "skipped",
                "reason": "requires_ipv6_link_local_scope_metadata",
                "stimulus_ipv4": "10.77.0.10",
                "target_ipv4": "10.77.0.20",
                "multicast_group": "ff02::c",
                "required_metadata": [
                    "source_mac",
                    "target_mac",
                    "target_interface",
                ],
            },
        )


if __name__ == "__main__":
    unittest.main()
