"""Unit coverage for probe sampling profiles.

These tests pin the profile-to-case mapping (smoke stays the legacy set, behavior
selects the full DNS/DHCP/ARP/NDP/UDP suite) and the deterministic seed/count
planning the profile feeds into the planner.
"""

from __future__ import annotations

import unittest

from tools.probe.engine import cases, cli, planning
from tools.probe.engine.model import ProbeRunRequest


_LEGACY_CASE_NAMES = (
    "icmp-echo",
    "tcp-syn-open",
    "tcp-syn-closed",
    "dns-query",
    "ttl-expired",
    "arp-resolution",
)

# The behavior suite carries ten cases each for DNS, DHCP, ARP, and UDP plus the
# three IPv6 Neighbor Discovery behavior cases (NS->NA, RS->RA, DAD), ordered
# dns, dhcp, arp, ndp, udp. Derive the count from the catalog so the suite can
# grow without re-pinning a literal here.
_BEHAVIOR_CASE_COUNT = len(cases.BEHAVIOR_PROFILE_CASE_NAMES)
_BGP_CASE_COUNT = len(cases.BGP_SESSION_PROFILE_CASE_NAMES)
_BEHAVIOR_PROTOCOL_COMPOSITION = {"dns": 10, "dhcp": 10, "arp": 10, "ndp": 3, "udp": 10}
_BEHAVIOR_PROTOCOL_ORDER = (
    ["dns"] * 10 + ["dhcp"] * 10 + ["arp"] * 10 + ["ndp"] * 3 + ["udp"] * 10
)


def _request(**overrides: object) -> ProbeRunRequest:
    base = {
        "provider": "qemu",
        "profile": "behavior",
        "seed": 7,
        "count": _BEHAVIOR_CASE_COUNT,
        "case_names": [],
        "dry_run": True,
    }
    base.update(overrides)
    return ProbeRunRequest(**base)  # type: ignore[arg-type]


class ProbeProfileMembershipTest(unittest.TestCase):
    def test_behavior_profile_selects_full_behavioral_suite(self) -> None:
        names = cases.profile_case_names("behavior")

        self.assertIsNotNone(names)
        assert names is not None
        self.assertEqual(len(names), _BEHAVIOR_CASE_COUNT)
        self.assertEqual(len(set(names)), _BEHAVIOR_CASE_COUNT)

    def test_behavior_profile_protocol_composition(self) -> None:
        selected = cases.profile_selected_cases("behavior", [])
        by_protocol: dict[str, int] = {}
        for case in selected:
            protocol = str(case.metadata.get("protocol"))
            by_protocol[protocol] = by_protocol.get(protocol, 0) + 1

        self.assertEqual(by_protocol, _BEHAVIOR_PROTOCOL_COMPOSITION)

    def test_behavior_profile_order_is_dns_dhcp_arp_ndp_udp(self) -> None:
        selected = cases.profile_selected_cases("behavior", [])
        protocols = [str(case.metadata.get("protocol")) for case in selected]

        self.assertEqual(protocols, _BEHAVIOR_PROTOCOL_ORDER)
        self.assertEqual(
            [case.name for case in selected],
            list(cases.BEHAVIOR_PROFILE_CASE_NAMES),
        )

    def test_behavior_profile_cases_are_catalog_entries(self) -> None:
        for name in cases.BEHAVIOR_PROFILE_CASE_NAMES:
            self.assertIn(name, cases.PROBE_CASE_BY_NAME)
            self.assertIn(name, cases.known_case_names())

    def test_smoke_profile_selects_legacy_cases_unchanged(self) -> None:
        self.assertEqual(cases.profile_case_names("smoke"), _LEGACY_CASE_NAMES)

        selected = cases.profile_selected_cases("smoke", [])
        self.assertEqual([case.name for case in selected], list(_LEGACY_CASE_NAMES))

    def test_explicit_cases_override_profile_selection(self) -> None:
        selected = cases.profile_selected_cases("behavior", ["icmp-echo", "dns-mx-answer"])

        self.assertEqual([case.name for case in selected], ["icmp-echo", "dns-mx-answer"])

    def test_unknown_profile_falls_back_to_full_catalog(self) -> None:
        selected = cases.profile_selected_cases("not-a-profile", [])

        self.assertEqual(
            [case.name for case in selected],
            [case.name for case in cases.PROBE_CASES],
        )

    def test_known_profiles_listed_sorted(self) -> None:
        self.assertEqual(
            cases.known_profiles(),
            ("behavior", "bgp-smoke", "ipsec", "rip-smoke", "smoke", "tcp-smoke"),
        )

    def test_bgp_smoke_profile_selects_bgp_case(self) -> None:
        names = cases.profile_case_names("bgp-smoke")

        self.assertEqual(names, ("bgp-session-smoke",))
        selected = cases.profile_selected_cases("bgp-smoke", [])
        self.assertEqual([case.name for case in selected], ["bgp-session-smoke"])
        self.assertEqual(selected[0].metadata["protocol"], "bgp")
        self.assertEqual(selected[0].metadata["service"], "frr-bgp-peer")
        self.assertIs(selected[0].metadata["stateful"], True)

    def test_tcp_smoke_profile_selects_tcp_cases_with_options(self) -> None:
        names = cases.profile_case_names("tcp-smoke")

        self.assertEqual(
            names,
            ("tcp-syn-options", "tcp-syn-open", "tcp-syn-closed"),
        )

        selected = cases.profile_selected_cases("tcp-smoke", [])
        self.assertEqual(
            [case.name for case in selected],
            ["tcp-syn-options", "tcp-syn-open", "tcp-syn-closed"],
        )
        # Every tcp-smoke case is a TCP case in the catalog.
        for case in selected:
            self.assertEqual(case.metadata.get("protocol"), "tcp")

    def test_tcp_smoke_profile_default_count_is_legacy_five(self) -> None:
        self.assertEqual(cases.profile_default_count("tcp-smoke"), 5)

    def test_tcp_smoke_options_plan_materializes_typed_options(self) -> None:
        plan = planning.probe_plan_for_case(
            request=_request(profile="tcp-smoke", count=5),
            case=cases.PROBE_CASE_BY_NAME["tcp-syn-options"],
            sequence=0,
        )

        self.assertEqual(plan["expected_response"], "tcp_syn_ack")
        self.assertEqual(plan["validation"]["flags"], ["syn", "ack"])
        kinds = [option["kind"] for option in plan["tcp_options"]]
        self.assertEqual(
            kinds,
            ["mss", "sack_permitted", "timestamp", "nop", "window_scale", "user_timeout"],
        )
        # Window-scale shift stays inside the RFC 7323 valid range.
        window_scale = next(o for o in plan["tcp_options"] if o["kind"] == "window_scale")
        self.assertLessEqual(window_scale["window_scale_shift"], 14)

    def test_bgp_smoke_plan_uses_probe_owned_target_service(self) -> None:
        plan = planning.probe_plan_for_case(
            request=_request(profile="bgp-smoke", count=_BGP_CASE_COUNT),
            case=cases.PROBE_CASE_BY_NAME["bgp-session-smoke"],
            sequence=0,
        )

        self.assertTrue(plan["planned_only"])
        self.assertEqual(plan["stimulus_driver"]["name"], "bgp_session")
        service = plan["target_service"]
        self.assertEqual(service["kind"], "frr-bgp-peer")
        self.assertEqual(service["protocol"], "tcp")
        self.assertEqual(service["port"], 179)
        self.assertEqual(service["driver_as"], 65000)
        self.assertEqual(service["peer_as"], 65001)
        self.assertEqual(
            service["provision_script"],
            "tools/probe/target_services/bgp/provision-peer.sh",
        )
        self.assertEqual(
            service["frr_template"],
            "tools/probe/target_services/bgp/frr.conf.template",
        )
        self.assertIn("198.51.100.0/24", service["documentation_prefixes"])


class ProbeProfileDefaultCountTest(unittest.TestCase):
    def test_behavior_profile_default_count_is_full_suite(self) -> None:
        self.assertEqual(
            cases.profile_default_count("behavior"), _BEHAVIOR_CASE_COUNT
        )
        self.assertEqual(
            cases.profile_default_count("behavior"),
            len(cases.BEHAVIOR_PROFILE_CASE_NAMES),
        )

    def test_smoke_profile_default_count_is_legacy_five(self) -> None:
        self.assertEqual(cases.profile_default_count("smoke"), 5)

    def test_bgp_smoke_profile_default_count_is_full_suite(self) -> None:
        self.assertEqual(cases.profile_default_count("bgp-smoke"), _BGP_CASE_COUNT)
        self.assertEqual(
            cases.profile_default_count("bgp-smoke"),
            len(cases.BGP_SESSION_PROFILE_CASE_NAMES),
        )

    def test_unknown_profile_default_count_is_legacy_five(self) -> None:
        self.assertEqual(cases.profile_default_count("ghost"), 5)


class ProbeProfilePlanningDeterminismTest(unittest.TestCase):
    def test_full_behavior_count_plans_every_case_once(self) -> None:
        request = _request(seed=7, count=_BEHAVIOR_CASE_COUNT)
        selected = cases.profile_selected_cases(request.profile, request.case_names)
        planned = planning.planned_cases(selected, seed=request.seed, count=request.count)

        self.assertEqual(len(planned), _BEHAVIOR_CASE_COUNT)
        self.assertEqual(
            {case.name for case in planned},
            set(cases.BEHAVIOR_PROFILE_CASE_NAMES),
        )

    def test_same_seed_and_count_plan_identically(self) -> None:
        selected = cases.profile_selected_cases("behavior", [])
        first = planning.planned_cases(selected, seed=13, count=_BEHAVIOR_CASE_COUNT)
        second = planning.planned_cases(selected, seed=13, count=_BEHAVIOR_CASE_COUNT)

        self.assertEqual(
            [case.name for case in first],
            [case.name for case in second],
        )

    def test_seed_rotates_planned_starting_case(self) -> None:
        selected = cases.profile_selected_cases("behavior", [])
        zero = planning.planned_cases(selected, seed=0, count=_BEHAVIOR_CASE_COUNT)
        shifted = planning.planned_cases(selected, seed=5, count=_BEHAVIOR_CASE_COUNT)

        self.assertEqual(zero[0].name, cases.BEHAVIOR_PROFILE_CASE_NAMES[0])
        self.assertEqual(shifted[0].name, cases.BEHAVIOR_PROFILE_CASE_NAMES[5])
        # A rotation reorders without dropping any case.
        self.assertEqual(
            {case.name for case in zero},
            {case.name for case in shifted},
        )

    def test_count_below_suite_size_is_a_stable_prefix(self) -> None:
        selected = cases.profile_selected_cases("behavior", [])
        names = [case.name for case in planning.planned_cases(selected, seed=0, count=10)]

        self.assertEqual(names, list(cases.BEHAVIOR_PROFILE_CASE_NAMES[:10]))


class ProbeProfileCliWiringTest(unittest.TestCase):
    def test_cli_uses_profile_default_count_when_count_omitted(self) -> None:
        parser = cli._build_parser()
        args = parser.parse_args(
            ["--provider", "qemu", "--dry-run", "--profile", "behavior"]
        )
        request = cli._request_from_args(args)

        self.assertEqual(request.count, _BEHAVIOR_CASE_COUNT)
        self.assertIs(request.metadata["count_explicit"], False)

    def test_cli_explicit_count_overrides_profile_default(self) -> None:
        parser = cli._build_parser()
        args = parser.parse_args(
            ["--provider", "qemu", "--dry-run", "--profile", "behavior", "--count", "12"]
        )
        request = cli._request_from_args(args)

        self.assertEqual(request.count, 12)
        self.assertIs(request.metadata["count_explicit"], True)

    def test_cli_smoke_default_count_preserved(self) -> None:
        parser = cli._build_parser()
        args = parser.parse_args(["--provider", "qemu", "--dry-run"])
        request = cli._request_from_args(args)

        self.assertEqual(request.profile, "smoke")
        self.assertEqual(request.count, 5)

    def test_cli_reexports_profile_helpers(self) -> None:
        self.assertIs(cli._profile_selected_cases, cases.profile_selected_cases)
        self.assertIs(cli._profile_default_count, cases.profile_default_count)
        self.assertEqual(cli.DEFAULT_PROFILE, cases.DEFAULT_PROFILE)


if __name__ == "__main__":
    unittest.main()
