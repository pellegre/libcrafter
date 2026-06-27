"""Offline coverage for the DHCPv6 probe profile and dry-run plans."""

from __future__ import annotations

import ipaddress
import unittest

from tools.probe.engine import capabilities
from tools.probe.engine import cases as probe_cases
from tools.probe.engine import lab as probe_lab
from tools.probe.engine import planning
from tools.probe.engine import target_services
from tools.probe.engine.model import ProbeRunRequest


DHCPV6_SMOKE_PROFILE = "dhcpv6-smoke"
INFO_REQUEST_CASE = "dhcpv6-information-request-reply"
RELAY_CASE = "dhcpv6-relay-forward-reply"
REPEATED_XID_CASE = "dhcpv6-repeated-transaction-id"


def _request(**overrides: object) -> ProbeRunRequest:
    base = {
        "provider": "qemu",
        "profile": DHCPV6_SMOKE_PROFILE,
        "seed": 9915,
        "count": 10,
        "case_names": [],
        "dry_run": True,
    }
    base.update(overrides)
    return ProbeRunRequest(**base)  # type: ignore[arg-type]


def _dhcpv6_plan(case_name: str = INFO_REQUEST_CASE, *, sequence: int = 0) -> dict:
    case = probe_cases.PROBE_CASE_BY_NAME[case_name]
    return planning.probe_plan_for_case(
        request=_request(),
        case=case,
        sequence=sequence,
    )


class Dhcpv6ProbeProfileTest(unittest.TestCase):
    def test_dhcpv6_smoke_profile_is_registered(self) -> None:
        self.assertIn(DHCPV6_SMOKE_PROFILE, probe_cases.known_profiles())
        self.assertEqual(
            probe_cases.profile_case_names(DHCPV6_SMOKE_PROFILE),
            (
                "dhcpv6-information-request-reply",
                "dhcpv6-solicit-advertise",
                "dhcpv6-request-reply-ia-na",
                "dhcpv6-prefix-delegation",
                "dhcpv6-rapid-commit",
                "dhcpv6-relay-forward-reply",
                "dhcpv6-reconfigure-observation",
                "dhcpv6-leasequery-plan",
                "dhcpv6-unknown-option-preservation",
                "dhcpv6-repeated-transaction-id",
            ),
        )
        self.assertEqual(probe_cases.profile_default_count(DHCPV6_SMOKE_PROFILE), 10)

    def test_cases_require_dhcpv6_service_capability(self) -> None:
        names = probe_cases.profile_case_names(DHCPV6_SMOKE_PROFILE)
        assert names is not None
        for name in names:
            case = probe_cases.PROBE_CASE_BY_NAME[name]
            with self.subTest(case=name):
                self.assertEqual(case.metadata["protocol"], "dhcpv6")
                self.assertEqual(case.required_capabilities, ["dhcpv6_service"])
                self.assertIs(case.metadata["planned_only"], True)

    def test_provider_without_dhcpv6_service_skips_with_stable_reason(self) -> None:
        case = probe_cases.PROBE_CASE_BY_NAME[INFO_REQUEST_CASE]
        provider_capabilities = probe_lab.probe_capabilities_from_lab_capabilities(
            "ipv4-only-lab",
            {
                "provider": "ipv4-only-lab",
                "ipv4_unicast": True,
                "ipv6_unicast": False,
                "multicast": True,
                "controlled_services": True,
            },
            dry_run=True,
        )

        missing = capabilities.missing_capabilities(case, provider_capabilities)

        self.assertEqual(missing, ["dhcpv6_service"])
        self.assertEqual(
            capabilities.skip_reason_for_missing_capability(case, missing[0]),
            capabilities.SKIP_REQUIRES_DHCPV6_SERVICE,
        )


class Dhcpv6ProbePlanTest(unittest.TestCase):
    def test_plan_builders_are_registered_with_identity(self) -> None:
        names = probe_cases.profile_case_names(DHCPV6_SMOKE_PROFILE)
        assert names is not None
        for name in names:
            with self.subTest(case=name):
                self.assertIn(name, planning.PLAN_BUILDERS)
                self.assertIs(planning.PLAN_BUILDERS[name], planning._dhcpv6_probe_plan)

    def test_information_request_plan_carries_wire_shape(self) -> None:
        plan = _dhcpv6_plan(INFO_REQUEST_CASE)

        self.assertEqual(plan["case"], INFO_REQUEST_CASE)
        self.assertTrue(plan["planned_only"])
        self.assertEqual(plan["protocol"], "dhcpv6")
        self.assertEqual(plan["source_port"], 546)
        self.assertEqual(plan["destination_port"], 547)
        self.assertEqual(plan["destination_ipv6"], "ff02::1:2")
        self.assertEqual(plan["destination_mac"], "33:33:00:01:00:02")
        self.assertEqual(plan["dhcpv6"]["message_type"], "information-request")
        self.assertEqual(plan["dhcpv6"]["message_type_code"], 11)
        self.assertEqual(plan["dhcpv6"]["expected_message_type"], "reply")
        self.assertEqual(plan["target_service"]["kind"], "dhcpv6-controlled-responder")
        self.assertEqual(
            plan["stimulus_driver"]["adapter_module"],
            "tools/probe/adapters/src/dhcpv6.rs",
        )
        self.assertTrue(plan["wire_requirements"]["requires_dhcpv6_service"])

    def test_plan_uses_documentation_ipv6_addresses(self) -> None:
        plan = _dhcpv6_plan("dhcpv6-request-reply-ia-na")
        documentation = ipaddress.ip_network("2001:db8::/32")

        for key in (
            "source_ipv6",
            "target_ipv6",
            "expected_reply_source_ipv6",
            "expected_reply_destination_ipv6",
        ):
            with self.subTest(key=key):
                self.assertIn(ipaddress.ip_address(plan[key]), documentation)

    def test_solicit_advertise_plan_carries_ia_na_assignment(self) -> None:
        plan = _dhcpv6_plan("dhcpv6-solicit-advertise")

        self.assertEqual(plan["dhcpv6"]["message_type"], "solicit")
        self.assertEqual(plan["dhcpv6"]["expected_message_type"], "advertise")
        request_options = {option["name"]: option for option in plan["dhcpv6"]["options"]}
        expected_options = {
            option["name"]: option for option in plan["dhcpv6"]["expected_options"]
        }
        self.assertIn("ia_na", request_options)
        self.assertIn("server_identifier", expected_options)
        self.assertIn("ia_na", expected_options)
        self.assertEqual(expected_options["status_code"]["status"], "success")
        iaaddr = expected_options["ia_na"]["addresses"][0]
        self.assertEqual(iaaddr["preferred_lifetime"], 3600)
        self.assertEqual(iaaddr["valid_lifetime"], 7200)
        self.assertEqual(plan["validation"]["reply_decode"]["protocol"], "Dhcpv6")
        self.assertIn("iaaddr", plan["validation"]["reply_decode"]["required_options"])

    def test_request_reply_ia_na_validates_lifetimes_status_and_xid(self) -> None:
        plan = _dhcpv6_plan("dhcpv6-request-reply-ia-na")

        ia_na = plan["validation"]["ia_na"]
        self.assertTrue(ia_na["enabled"])
        self.assertEqual(ia_na["iaid"], plan["dhcpv6"]["transaction_id"])
        self.assertEqual(ia_na["t1"], 1800)
        self.assertEqual(ia_na["t2"], 2880)
        self.assertEqual(ia_na["iaaddr"]["preferred_lifetime"], 3600)
        self.assertEqual(ia_na["iaaddr"]["valid_lifetime"], 7200)
        self.assertEqual(ia_na["status_code"], 0)
        self.assertEqual(ia_na["status"], "success")
        self.assertIs(plan["validation"]["transaction_id_match"], True)
        self.assertEqual(
            plan["validation"]["client_duid_hex"],
            plan["dhcpv6"]["client_duid_hex"],
        )
        self.assertEqual(
            plan["validation"]["server_duid_hex"],
            plan["dhcpv6"]["server_duid_hex"],
        )

    def test_relay_plan_targets_all_servers_multicast(self) -> None:
        plan = _dhcpv6_plan(RELAY_CASE)

        self.assertEqual(plan["source_port"], 547)
        self.assertEqual(plan["destination_port"], 547)
        self.assertEqual(plan["destination_ipv6"], "ff05::1:3")
        self.assertEqual(plan["destination_mac"], "33:33:00:01:00:03")
        self.assertTrue(plan["dhcpv6"]["relay"]["enabled"])
        self.assertEqual(plan["dhcpv6"]["message_type"], "relay-forward")
        self.assertEqual(plan["dhcpv6"]["expected_message_type"], "relay-reply")

    def test_repeated_transaction_id_plan_sends_two_matching_transactions(self) -> None:
        plan = _dhcpv6_plan(REPEATED_XID_CASE)

        sends = plan["dhcpv6_sends"]
        self.assertEqual(len(sends), 2)
        self.assertEqual(sends[0]["transaction_id"], sends[1]["transaction_id"])
        self.assertEqual(sends[0]["transaction_id"], plan["dhcpv6"]["transaction_id"])
        self.assertEqual(plan["validation"]["packet_count"], 2)

    def test_target_service_setup_carries_dhcpv6_responder_metadata(self) -> None:
        setup = target_services.target_service_setup_plan(
            probe_plans=[_dhcpv6_plan(INFO_REQUEST_CASE)],
            dry_run=True,
        )

        services = setup["services"]
        self.assertEqual(len(services), 1)
        self.assertEqual(services[0]["name"], "dhcpv6-controlled-responder")
        self.assertEqual(services[0]["kind"], "dhcpv6-controlled-responder")
        self.assertEqual(services[0]["protocol"], "udp")
        self.assertEqual(services[0]["port"], 547)
        self.assertEqual(services[0]["request_count"], 1)
        self.assertIn("reply", services[0]["expected_replies"])
        self.assertIn(
            "live-artifacts/probe/target-services/dhcpv6-responder-547.stdout.txt",
            services[0]["artifacts"],
        )
        self.assertFalse(setup["starts_services"])

    def test_live_target_service_setup_would_start_inside_lab_endpoint(self) -> None:
        setup = target_services.target_service_setup_plan(
            probe_plans=[_dhcpv6_plan(INFO_REQUEST_CASE)],
            dry_run=False,
        )

        self.assertTrue(setup["starts_services"])
        self.assertEqual(setup["services"][0]["runtime"], "probe-dhcpv6-reference")


if __name__ == "__main__":
    unittest.main()
