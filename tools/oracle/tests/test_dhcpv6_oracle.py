"""Unit coverage for DHCPv6 oracle generator selection and field sampling."""

from __future__ import annotations

import unittest
from collections.abc import Mapping, Sequence

from tools.oracle.engine.generator import generate_plans
from tools.oracle.engine.model import PacketPlan


_DHCPV6_STACKS = {
    ("ethernet", "ipv6", "udp", "dhcpv6"),
    ("ipv6", "udp", "dhcpv6"),
}


def _plans_for_case(case: str, count: int = 4) -> list[PacketPlan]:
    return generate_plans(
        seed=9915,
        profile="smoke",
        count=count,
        backend="scapy",
        case=case,
    )


def _first_plan(case: str) -> PacketPlan:
    plans = _plans_for_case(case, count=1)
    assert len(plans) == 1
    return plans[0]


def _dhcpv6_fields(plan: PacketPlan) -> Mapping[str, object]:
    dhcpv6 = plan.fields.get("dhcpv6")
    assert isinstance(dhcpv6, Mapping), f"plan for {plan.case} has no dhcpv6 fields"
    return dhcpv6


def _udp_fields(plan: PacketPlan) -> Mapping[str, object]:
    udp = plan.fields.get("udp")
    assert isinstance(udp, Mapping), f"plan for {plan.case} has no udp fields"
    return udp


def _option_names(dhcpv6: Mapping[str, object]) -> list[str]:
    options = dhcpv6.get("options")
    assert isinstance(options, Sequence)
    output: list[str] = []
    for option in options:
        assert isinstance(option, Mapping)
        name = option.get("name")
        assert isinstance(name, str)
        output.append(name)
    return output


class Dhcpv6GeneratorSelectionTest(unittest.TestCase):
    def test_dhcpv6_solicit_selects_registered_dhcpv6_stacks(self) -> None:
        plans = _plans_for_case("dhcpv6-solicit")
        self.assertEqual(len(plans), 4)
        for plan in plans:
            self.assertIn(tuple(plan.stack), _DHCPV6_STACKS)
            self.assertEqual(plan.case, "dhcpv6-solicit")
            self.assertIn("dhcpv6", plan.feature_tags)

    def test_dhcpv6_solicit_uses_client_ports_and_options(self) -> None:
        plan = _first_plan("dhcpv6-solicit")
        udp = _udp_fields(plan)
        dhcpv6 = _dhcpv6_fields(plan)

        self.assertEqual(udp.get("src_port"), 546)
        self.assertEqual(udp.get("dst_port"), 547)
        self.assertEqual(dhcpv6.get("message_type"), "solicit")
        self.assertIn("transaction_id", dhcpv6)
        self.assertEqual(_option_names(dhcpv6), ["client_id", "oro", "elapsed_time"])

    def test_dhcpv6_reply_uses_server_ports_and_status(self) -> None:
        plan = _first_plan("dhcpv6-reply")
        udp = _udp_fields(plan)
        dhcpv6 = _dhcpv6_fields(plan)

        self.assertEqual(udp.get("src_port"), 547)
        self.assertEqual(udp.get("dst_port"), 546)
        self.assertEqual(dhcpv6.get("message_type"), "reply")
        self.assertEqual(_option_names(dhcpv6), ["client_id", "server_id", "status_code"])

    def test_dhcpv6_relay_forward_uses_relay_fields_and_ports(self) -> None:
        plan = _first_plan("dhcpv6-relay-forward")
        udp = _udp_fields(plan)
        dhcpv6 = _dhcpv6_fields(plan)

        self.assertEqual(udp.get("src_port"), 547)
        self.assertEqual(udp.get("dst_port"), 547)
        self.assertEqual(dhcpv6.get("message_type"), "relay_forward")
        self.assertNotIn("transaction_id", dhcpv6)
        self.assertEqual(dhcpv6.get("hop_count"), 1)
        self.assertEqual(dhcpv6.get("link_address"), "2001:db8:100::")
        self.assertEqual(_option_names(dhcpv6), ["interface_id", "relay_msg"])

    def test_dhcpv6_identity_association_cases_are_nested(self) -> None:
        plan = _first_plan("dhcpv6-ia-pd-iaprefix")
        dhcpv6 = _dhcpv6_fields(plan)
        options = dhcpv6.get("options")
        assert isinstance(options, Sequence)
        ia_pd = next(
            option
            for option in options
            if isinstance(option, Mapping) and option.get("name") == "ia_pd"
        )
        assert isinstance(ia_pd, Mapping)
        nested = ia_pd.get("options")
        assert isinstance(nested, Sequence)
        self.assertEqual(
            [option.get("name") for option in nested if isinstance(option, Mapping)],
            ["ia_prefix"],
        )

    def test_dhcpv6_generation_is_deterministic(self) -> None:
        first = [plan.to_dict() for plan in _plans_for_case("dhcpv6-option-matrix")]
        second = [plan.to_dict() for plan in _plans_for_case("dhcpv6-option-matrix")]
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
