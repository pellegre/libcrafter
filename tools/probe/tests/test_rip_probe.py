"""Offline unit coverage for the RIP/RIPng probe profile and plan dispatch.

These tests guard the probe-side RIP/RIPng planning surface (added in steps
62-71) without provisioning anything: they resolve the ``rip-smoke`` profile to
its cases, drive the deterministic planning dispatch, and assert the emitted
dry-run plans carry the expected stimulus, wire port, multicast group, target
service, and capability -- and that they stay dry-run-safe (no live
confirmation, documentation/private addresses only).
"""

from __future__ import annotations

import ipaddress
import unittest

from tools.probe.engine import cases as probe_cases
from tools.probe.engine import planning
from tools.probe.engine.model import ProbeRunRequest

RIP_SMOKE_PROFILE = "rip-smoke"
RIP_CASE = "rip-update-v2"
RIPNG_CASE = "ripng-update"


def _request(**overrides: object) -> ProbeRunRequest:
    base = {
        "provider": "qemu",
        "profile": RIP_SMOKE_PROFILE,
        "seed": 2,
        "count": 2,
        "case_names": [],
        "dry_run": True,
    }
    base.update(overrides)
    return ProbeRunRequest(**base)  # type: ignore[arg-type]


def _rip_plan(case_name: str = RIP_CASE, *, sequence: int = 0) -> dict:
    case = probe_cases.PROBE_CASE_BY_NAME[case_name]
    return planning.probe_plan_for_case(
        request=_request(),
        case=case,
        sequence=sequence,
    )


class RipProfileResolutionTest(unittest.TestCase):
    def test_rip_smoke_profile_is_registered(self) -> None:
        self.assertIn(RIP_SMOKE_PROFILE, probe_cases.known_profiles())

    def test_rip_smoke_profile_resolves_to_rip_update_case(self) -> None:
        case_names = probe_cases.profile_case_names(RIP_SMOKE_PROFILE)
        self.assertIsNotNone(case_names)
        assert case_names is not None  # narrow for the type checker
        self.assertIn(RIP_CASE, case_names)
        # The IPv4 RIP update is the lead case of the profile.
        self.assertEqual(case_names[0], RIP_CASE)

    def test_rip_smoke_profile_also_carries_ripng_variant(self) -> None:
        case_names = probe_cases.profile_case_names(RIP_SMOKE_PROFILE)
        assert case_names is not None
        self.assertIn(RIPNG_CASE, case_names)

    def test_rip_update_case_requires_rip_peer_capability(self) -> None:
        case = probe_cases.PROBE_CASE_BY_NAME[RIP_CASE]
        self.assertEqual(case.stimulus, "rip_request")
        self.assertIn("rip_peer", case.required_capabilities)


class RipPlanDispatchTest(unittest.TestCase):
    def test_rip_update_plan_carries_stimulus_port_and_service(self) -> None:
        plan = _rip_plan()

        self.assertEqual(plan["case"], RIP_CASE)
        self.assertEqual(plan["stimulus"], "rip_request")
        self.assertEqual(plan["protocol"], "rip")
        self.assertEqual(plan["destination_port"], 520)
        self.assertEqual(plan["multicast_group"], "224.0.0.9")

        target_service = plan["target_service"]
        self.assertEqual(target_service["kind"], "frr-ripd")
        self.assertEqual(target_service["protocol"], "udp")
        self.assertEqual(target_service["port"], 520)
        self.assertTrue(target_service["required"])
        self.assertEqual(target_service["rib_command"], "vtysh -c 'show ip rip'")

    def test_rip_update_plan_routes_through_dispatch_not_fallback(self) -> None:
        # The case is registered with a dedicated builder, so the plan must come
        # from that builder (planned_only=True) and not the bare fallback.
        self.assertIn(RIP_CASE, planning.PLAN_BUILDERS)
        self.assertIn(RIP_CASE, planning.PLANNED_ONLY_REGISTERED_CASES)
        plan = _rip_plan()
        self.assertIs(plan["planned_only"], True)
        self.assertEqual(plan["stimulus_driver"]["cargo_example"], "rip_request")

    def test_rip_update_plan_requires_rip_peer_capability(self) -> None:
        # The capability is carried on the case the dispatch resolves; assert it
        # so the plan stays gated behind a provider that supplies a RIP peer.
        case = probe_cases.PROBE_CASE_BY_NAME[RIP_CASE]
        self.assertIn("rip_peer", case.required_capabilities)
        plan = _rip_plan()
        self.assertTrue(plan["wire_requirements"]["requires_rip_peer"])

    def test_ripng_update_plan_carries_ipv6_port_and_multicast(self) -> None:
        plan = _rip_plan(RIPNG_CASE)

        self.assertEqual(plan["case"], RIPNG_CASE)
        self.assertEqual(plan["stimulus"], "ripng_request")
        self.assertEqual(plan["protocol"], "ripng")
        self.assertEqual(plan["destination_port"], 521)
        self.assertEqual(plan["multicast_group"], "ff02::9")

        target_service = plan["target_service"]
        self.assertEqual(target_service["kind"], "frr-ripngd")
        self.assertEqual(target_service["protocol"], "udp")
        self.assertEqual(target_service["port"], 521)
        self.assertEqual(target_service["multicast_group"], "ff02::9")
        self.assertEqual(target_service["rib_command"], "vtysh -c 'show ipv6 ripng'")

    def test_plan_dispatch_is_deterministic(self) -> None:
        first = _rip_plan()
        second = _rip_plan()
        self.assertEqual(first, second)

        first_v6 = _rip_plan(RIPNG_CASE)
        second_v6 = _rip_plan(RIPNG_CASE)
        self.assertEqual(first_v6, second_v6)


class RipPlanDryRunSafetyTest(unittest.TestCase):
    def test_request_defaults_to_dry_run_without_live_confirmation(self) -> None:
        request = _request()
        self.assertTrue(request.dry_run)
        self.assertFalse(request.confirm_live_run)

    def test_rip_plans_are_planned_only_and_send_nothing(self) -> None:
        for case_name in (RIP_CASE, RIPNG_CASE):
            with self.subTest(case=case_name):
                plan = _rip_plan(case_name)
                self.assertIs(plan["planned_only"], True)
                self.assertIs(plan["stimulus_driver"]["planned_only"], True)
                self.assertEqual(plan["stimulus_driver"]["state"], "planned-only")
                self.assertIs(plan["validation"]["planned_only"], True)
                self.assertNotIn("payload_hex", plan)
                self.assertNotIn("packet_hex", plan)

    def test_rip_plan_advertises_only_documentation_prefixes(self) -> None:
        plan = _rip_plan()
        # IPv4 documentation space per RFC 5737 (192.0.2/24, 198.51.100/24,
        # 203.0.113/24).
        documentation_v4 = (
            ipaddress.ip_network("192.0.2.0/24"),
            ipaddress.ip_network("198.51.100.0/24"),
            ipaddress.ip_network("203.0.113.0/24"),
        )
        prefixes = plan["documentation_prefixes"]
        self.assertTrue(prefixes)
        for prefix in prefixes:
            network = ipaddress.ip_network(prefix)
            self.assertTrue(
                any(network.subnet_of(block) for block in documentation_v4),
                msg=f"{prefix} is not in IPv4 documentation space",
            )

    def test_ripng_plan_advertises_only_documentation_prefixes(self) -> None:
        plan = _rip_plan(RIPNG_CASE)
        # IPv6 documentation space per RFC 3849 (2001:db8::/32).
        documentation_v6 = ipaddress.ip_network("2001:db8::/32")
        prefixes = plan["documentation_prefixes"]
        self.assertTrue(prefixes)
        for prefix in prefixes:
            network = ipaddress.ip_network(prefix)
            self.assertTrue(
                network.subnet_of(documentation_v6),
                msg=f"{prefix} is not in IPv6 documentation space",
            )

    def test_rip_lab_transport_addresses_are_never_public(self) -> None:
        # The lab-transport endpoint addresses (source/destination) ride the
        # private provider network, never a routable public address.
        plan = _rip_plan()
        for key in ("source_ipv4", "destination_ipv4"):
            address = ipaddress.ip_address(plan[key])
            self.assertTrue(
                address.is_private,
                msg=f"{key}={plan[key]} must be a private lab-transport address",
            )

    def test_ripng_lab_transport_addresses_are_documentation_only(self) -> None:
        plan = _rip_plan(RIPNG_CASE)
        documentation_v6 = ipaddress.ip_network("2001:db8::/32")
        for key in ("source_ipv6", "destination_ipv6"):
            address = ipaddress.ip_address(plan[key])
            self.assertIn(
                address,
                documentation_v6,
                msg=f"{key}={plan[key]} must be a documentation IPv6 address",
            )


if __name__ == "__main__":
    unittest.main()
