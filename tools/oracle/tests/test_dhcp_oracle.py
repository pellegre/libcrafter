"""Unit coverage for DHCP oracle generator selection.

These tests pin the packet plan shape that ``--case dhcp-discover`` must
produce so the IPv4-root ``ipv4 / udp / dhcp`` stack stays available for
live-friendly oracle validation while the Ethernet-root stack keeps its
link-layer coverage.
"""

from __future__ import annotations

import unittest
from collections.abc import Mapping, Sequence

from tools.oracle.engine.generator import generate_plans
from tools.oracle.engine.model import PacketPlan


_IPV4_ROOT_STACK = ["ipv4", "udp", "dhcp"]


def _dhcp_message_type(plan: PacketPlan) -> str | None:
    """Return the DHCP message type a plan encodes, if any.

    The generator carries the DHCP message type in the ``dhcp.options`` list as
    a ``message-type=<value>`` token rather than a dedicated field, so the
    discover assertion has to look there.
    """

    dhcp = plan.fields.get("dhcp")
    if not isinstance(dhcp, Mapping):
        return None
    options = dhcp.get("options")
    if not isinstance(options, Sequence) or isinstance(options, (str, bytes)):
        return None
    for option in options:
        if isinstance(option, str) and option.startswith("message-type="):
            return option.split("=", 1)[1]
        if (
            isinstance(option, Sequence)
            and not isinstance(option, (str, bytes))
            and len(option) == 2
            and option[0] in {"message_type", "message-type"}
        ):
            return str(option[1])
    return None


def _packet_root(plan: PacketPlan) -> str | None:
    root = plan.metadata.get("root_decoder", plan.metadata.get("root"))
    return root if isinstance(root, str) and root else None


class DhcpGeneratorSelectionTest(unittest.TestCase):
    """Prove ``dhcp-discover`` selects the IPv4-root live DHCP stack."""

    def _ipv4_root_dhcp_plan(self, plans: Sequence[PacketPlan]) -> PacketPlan:
        matches = [plan for plan in plans if list(plan.stack) == _IPV4_ROOT_STACK]
        self.assertTrue(
            matches,
            msg=(
                "expected at least one ipv4/udp/dhcp plan for --case "
                "dhcp-discover, got stacks "
                f"{[list(plan.stack) for plan in plans]}"
            ),
        )
        return matches[0]

    def test_dhcp_discover_selects_ipv4_root_stack(self) -> None:
        plans = generate_plans(
            seed=106,
            profile="smoke",
            count=3,
            backend="scapy",
            case="dhcp-discover",
        )

        plan = self._ipv4_root_dhcp_plan(plans)

        self.assertEqual(list(plan.stack), _IPV4_ROOT_STACK)
        self.assertEqual(_packet_root(plan), "l3:ipv4")
        self.assertEqual(plan.case, "dhcp-discover")

    def test_dhcp_discover_ipv4_root_uses_bootp_ports(self) -> None:
        plans = generate_plans(
            seed=106,
            profile="smoke",
            count=3,
            backend="scapy",
            case="dhcp-discover",
        )

        plan = self._ipv4_root_dhcp_plan(plans)
        udp = plan.fields.get("udp")

        self.assertIsInstance(udp, Mapping)
        self.assertEqual(udp.get("src_port"), 68)
        self.assertEqual(udp.get("dst_port"), 67)

    def test_dhcp_discover_ipv4_root_message_type_is_discover(self) -> None:
        plans = generate_plans(
            seed=106,
            profile="smoke",
            count=3,
            backend="scapy",
            case="dhcp-discover",
        )

        plan = self._ipv4_root_dhcp_plan(plans)

        self.assertEqual(_dhcp_message_type(plan), "discover")

    def test_dhcp_discover_ipv4_root_is_deterministic(self) -> None:
        first = self._ipv4_root_dhcp_plan(
            generate_plans(
                seed=106,
                profile="smoke",
                count=3,
                backend="scapy",
                case="dhcp-discover",
            )
        )
        second = self._ipv4_root_dhcp_plan(
            generate_plans(
                seed=106,
                profile="smoke",
                count=3,
                backend="scapy",
                case="dhcp-discover",
            )
        )

        self.assertEqual(first.to_dict(), second.to_dict())


if __name__ == "__main__":
    unittest.main()
