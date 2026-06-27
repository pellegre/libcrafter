"""Offline coverage for the DHCPv6 probe profile and dry-run plans."""

from __future__ import annotations

import ipaddress
import unittest

from tools.probe.engine import capabilities
from tools.probe.engine import cases as probe_cases
from tools.probe.engine import cli as probe_cli
from tools.probe.engine import lab as probe_lab
from tools.probe.engine import planning
from tools.probe.engine import target_services
from tools.probe.engine.model import ProbeRunRequest


DHCPV6_SMOKE_PROFILE = "dhcpv6-smoke"
DHCPV6_ADVANCED_PROFILE = "dhcpv6-advanced"
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
                expected_capabilities = (
                    ["dhcpv6_service", "dhcpv6_relay_topology"]
                    if name == RELAY_CASE
                    else ["dhcpv6_service"]
                )
                self.assertEqual(case.required_capabilities, expected_capabilities)
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

    def test_dhcpv6_advanced_profile_is_registered(self) -> None:
        self.assertEqual(
            probe_cases.profile_case_names(DHCPV6_ADVANCED_PROFILE),
            (
                "dhcpv6-reconfigure-observation",
                "dhcpv6-leasequery-plan",
                "dhcpv6-bulk-leasequery-plan",
                "dhcpv6-active-leasequery-plan",
            ),
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

    def test_prefix_delegation_validates_iaprefix_and_exchange_transactions(self) -> None:
        plan = _dhcpv6_plan("dhcpv6-prefix-delegation")

        ia_pd = plan["validation"]["ia_pd"]
        self.assertTrue(ia_pd["enabled"])
        self.assertEqual(ia_pd["iaid"], plan["dhcpv6"]["transaction_id"])
        self.assertEqual(ia_pd["t1"], 1800)
        self.assertEqual(ia_pd["t2"], 2880)
        iaprefix = ia_pd["iaprefix"]
        self.assertEqual(iaprefix["prefix_length"], 56)
        self.assertEqual(iaprefix["preferred_lifetime"], 3600)
        self.assertEqual(iaprefix["valid_lifetime"], 7200)
        delegated_prefix = str(iaprefix["prefix"]).split("/")[0]
        self.assertIn(
            ipaddress.ip_address(delegated_prefix),
            ipaddress.ip_network("2001:db8::/32"),
        )
        self.assertEqual(ia_pd["status"], "success")
        self.assertEqual(plan["validation"]["route_installation"], "out_of_scope")
        self.assertEqual(
            plan["validation"]["reply_decode"]["required_options"],
            ["server_identifier", "client_identifier", "ia_pd", "iaprefix", "status_code"],
        )
        exchanges = plan["validation"]["pd_exchanges"]
        self.assertEqual(
            [(item["stimulus"], item["expected_response"]) for item in exchanges],
            [("solicit", "advertise"), ("request", "reply")],
        )
        self.assertTrue(all(item["transaction_id_match"] for item in exchanges))

    def test_relay_plan_targets_all_servers_multicast(self) -> None:
        plan = _dhcpv6_plan(RELAY_CASE)

        case = probe_cases.PROBE_CASE_BY_NAME[RELAY_CASE]
        self.assertEqual(case.endpoint_roles, ["stimulus", "relay", "target"])
        self.assertEqual(plan["source_port"], 547)
        self.assertEqual(plan["destination_port"], 547)
        self.assertEqual(plan["destination_ipv6"], "ff05::1:3")
        self.assertEqual(plan["destination_mac"], "33:33:00:01:00:03")
        self.assertTrue(plan["dhcpv6"]["relay"]["enabled"])
        self.assertEqual(plan["dhcpv6"]["message_type"], "relay-forward")
        self.assertEqual(plan["dhcpv6"]["expected_message_type"], "relay-reply")
        relay = plan["validation"]["relay"]
        self.assertEqual(relay["topology_roles"], ["stimulus", "relay", "target"])
        self.assertEqual(relay["relay_forward"]["hop_count"], 0)
        self.assertEqual(
            relay["relay_forward"]["link_address"],
            plan["dhcpv6"]["relay"]["link_address"],
        )
        self.assertEqual(
            relay["relay_forward"]["peer_address"],
            plan["dhcpv6"]["relay"]["peer_address"],
        )
        self.assertEqual(
            relay["relay_forward"]["interface_id_hex"],
            "646f632d72656c6179",
        )
        self.assertTrue(relay["relay_message_nesting"])
        self.assertTrue(relay["relay_reply"]["interface_id_echo"])
        self.assertTrue(relay["reply_decapsulation"]["enabled"])
        self.assertTrue(relay["reply_decapsulation"]["transaction_id_match"])
        self.assertEqual(
            plan["validation"]["reply_decode"]["required_options"],
            ["server_identifier", "interface_id", "relay_message"],
        )

    def test_relay_profile_plans_three_lab_roles(self) -> None:
        request = _request(profile="dhcpv6-relay", count=4)
        selected = probe_cases.profile_selected_cases(request.profile, request.case_names)
        planned = planning.planned_cases(selected, seed=request.seed, count=request.count)
        session = probe_cli._probe_lab_dry_run_session(
            request,
            planned_cases=planned,
        )

        self.assertEqual(
            [role.name for role in session.roles],
            ["stimulus", "relay", "target"],
        )
        peers = {role.name: role.peer_roles for role in session.roles}
        self.assertEqual(peers["stimulus"], ["relay"])
        self.assertEqual(peers["relay"], ["stimulus", "target"])
        self.assertEqual(peers["target"], ["relay"])

    def test_advanced_reconfigure_and_leasequery_contracts_are_planned(self) -> None:
        reconfigure = _dhcpv6_plan("dhcpv6-reconfigure-observation")
        leasequery = _dhcpv6_plan("dhcpv6-leasequery-plan")

        self.assertEqual(
            reconfigure["planned_only_reason"],
            "controlled_dhcpv6_service_not_implemented",
        )
        self.assertFalse(reconfigure["target_service"]["implemented"])
        self.assertEqual(
            reconfigure["validation"]["advanced"]["required_request_options"],
            ["server_identifier", "reconfigure_message", "authentication"],
        )
        self.assertEqual(
            reconfigure["validation"]["advanced"]["expected_client_response"],
            "information-request",
        )

        advanced = leasequery["validation"]["advanced"]
        self.assertEqual(advanced["query_type"], "by_address")
        self.assertTrue(leasequery["target_service"]["implemented"])
        self.assertIn(
            "status_code",
            leasequery["validation"]["reply_decode"]["required_options"],
        )
        expected_options = {
            option["name"]: option for option in leasequery["dhcpv6"]["expected_options"]
        }
        self.assertEqual(expected_options["status_code"]["status"], "success")

    def test_bulk_and_active_leasequery_are_planned_only_stream_contracts(self) -> None:
        bulk = _dhcpv6_plan("dhcpv6-bulk-leasequery-plan")
        active = _dhcpv6_plan("dhcpv6-active-leasequery-plan")

        self.assertEqual(bulk["dhcpv6"]["message_type"], "leasequery")
        self.assertEqual(bulk["dhcpv6"]["expected_message_type"], "leasequery-done")
        self.assertFalse(bulk["target_service"]["implemented"])
        self.assertEqual(bulk["validation"]["advanced"]["query_type"], "by_link_address")
        self.assertEqual(
            bulk["validation"]["reply_decode"]["required_options"],
            ["server_identifier", "lq_base_time", "status_code"],
        )

        self.assertEqual(active["dhcpv6"]["message_type"], "activeleasequery")
        self.assertEqual(active["dhcpv6"]["expected_message_type"], "leasequery-reply")
        self.assertFalse(active["target_service"]["implemented"])
        self.assertEqual(active["validation"]["advanced"]["query_type"], "by_relay_id")
        expected_options = {
            option["name"]: option for option in active["dhcpv6"]["expected_options"]
        }
        self.assertEqual(expected_options["status_code"]["status_code"], 13)

    def test_unimplemented_advanced_services_are_not_target_service_plans(self) -> None:
        setup = target_services.target_service_setup_plan(
            probe_plans=[
                _dhcpv6_plan("dhcpv6-bulk-leasequery-plan"),
                _dhcpv6_plan("dhcpv6-active-leasequery-plan"),
            ],
            dry_run=True,
        )

        self.assertEqual(setup["services"], [])

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
