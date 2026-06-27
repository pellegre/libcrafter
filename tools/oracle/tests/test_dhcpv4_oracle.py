"""Unit coverage for DHCPv4 oracle generator selection and Scapy materialization.

These tests pin the packet plan shape that ``--case dhcpv4-discover`` must
produce so the IPv4-root ``ipv4 / udp / dhcpv4`` stack stays available for
live-friendly oracle validation while the Ethernet-root stack keeps its
link-layer coverage. They also pin how the Scapy reference backend
materializes that IPv4-root stack as ``IP / UDP / BOOTP / DHCPv4`` (no Ethernet)
and decodes back to the normalized ``ipv4 / udp / dhcpv4`` model.
"""

from __future__ import annotations

import unittest
from collections.abc import Mapping, Sequence

from tools.oracle.engine.generator import (
    DHCPV4_OPTION_MATRIX_TOKENS,
    generate_plans,
)
from tools.oracle.engine.backends.scapy import normalize
from tools.oracle.engine.model import PacketPlan


_IPV4_ROOT_STACK = ["ipv4", "udp", "dhcpv4"]

# The Scapy-byte-safe option kinds the dhcpv4_behavior option_matrix samples
# cross-backend, expressed as the backend-neutral option names the generated
# plans carry. Kinds Scapy cannot encode byte-for-byte are covered by native
# libcrafter fixtures instead; see tools/oracle/specs/layers/dhcpv4.yaml.
_EXPECTED_OPTION_MATRIX_KINDS = (
    "message-type",
    "hostname",
    "domain_name",
    "requested_ip",
    "server_id",
    "router",
    "domain_name_server",
    "lease_time",
    "end",
)

# DHCPv4 magic cookie (RFC 2132) that prefaces the option list once decoded.
_DHCPV4_MAGIC_COOKIE = 0x63825363


def _require_scapy_backend():
    """Import the Scapy materialize/decode backend or skip when unavailable.

    Acceptance command 1 runs ``python3 -m unittest`` on the bare interpreter,
    where Scapy is not installed; the oracle CLI only bootstraps Scapy through
    ``uv``. Skip cleanly there so the protocol contract stays backend-owned
    rather than failing for a missing optional dependency.
    """

    try:
        from tools.oracle.engine.backends.scapy.packets import encode_packet_plan
        from tools.oracle.engine.backends.scapy.normalize import decode_vector
    except Exception as exc:  # pragma: no cover - exercised only without Scapy.
        raise unittest.SkipTest(f"Scapy backend unavailable: {exc}")

    try:
        from tools.oracle.engine.backends.scapy.bootstrap import import_scapy

        import_scapy()
    except Exception as exc:  # pragma: no cover - exercised only without Scapy.
        raise unittest.SkipTest(f"Scapy is not importable: {exc}")

    return encode_packet_plan, decode_vector


def _dhcpv4_message_type(plan: PacketPlan) -> str | None:
    """Return the DHCPv4 message type a plan encodes, if any.

    The generator carries the DHCPv4 message type in the ``dhcpv4.options`` list as
    a ``message-type=<value>`` token rather than a dedicated field, so the
    discover assertion has to look there.
    """

    dhcpv4 = plan.fields.get("dhcpv4")
    if not isinstance(dhcpv4, Mapping):
        return None
    options = dhcpv4.get("options")
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


def _dhcpv4_option_kinds(plan: PacketPlan) -> list[str]:
    """Return the DHCPv4 option kinds a plan encodes, in order.

    Options are carried in ``dhcpv4.options`` either as ``name=value`` strings or
    as ``[name, value]`` lists; the bare ``end``/``pad`` markers are kinds too.
    """

    dhcpv4 = plan.fields.get("dhcpv4")
    if not isinstance(dhcpv4, Mapping):
        return []
    options = dhcpv4.get("options")
    if not isinstance(options, Sequence) or isinstance(options, (str, bytes)):
        return []
    kinds: list[str] = []
    for option in options:
        if isinstance(option, str):
            kinds.append(option.split("=", 1)[0] if "=" in option else option)
        elif (
            isinstance(option, Sequence)
            and not isinstance(option, (str, bytes))
            and option
            and isinstance(option[0], str)
        ):
            kinds.append(option[0])
    return kinds


class Dhcpv4GeneratorSelectionTest(unittest.TestCase):
    """Prove ``dhcpv4-discover`` selects the IPv4-root live DHCPv4 stack."""

    def _ipv4_root_dhcpv4_plan(self, plans: Sequence[PacketPlan]) -> PacketPlan:
        matches = [plan for plan in plans if list(plan.stack) == _IPV4_ROOT_STACK]
        self.assertTrue(
            matches,
            msg=(
                "expected at least one ipv4/udp/dhcpv4 plan for --case "
                "dhcpv4-discover, got stacks "
                f"{[list(plan.stack) for plan in plans]}"
            ),
        )
        return matches[0]

    def test_dhcpv4_discover_selects_ipv4_root_stack(self) -> None:
        plans = generate_plans(
            seed=106,
            profile="smoke",
            count=3,
            backend="scapy",
            case="dhcpv4-discover",
        )

        plan = self._ipv4_root_dhcpv4_plan(plans)

        self.assertEqual(list(plan.stack), _IPV4_ROOT_STACK)
        self.assertEqual(_packet_root(plan), "l3:ipv4")
        self.assertEqual(plan.case, "dhcpv4-discover")

    def test_dhcpv4_discover_ipv4_root_uses_bootp_ports(self) -> None:
        plans = generate_plans(
            seed=106,
            profile="smoke",
            count=3,
            backend="scapy",
            case="dhcpv4-discover",
        )

        plan = self._ipv4_root_dhcpv4_plan(plans)
        udp = plan.fields.get("udp")

        self.assertIsInstance(udp, Mapping)
        self.assertEqual(udp.get("src_port"), 68)
        self.assertEqual(udp.get("dst_port"), 67)

    def test_dhcpv4_discover_ipv4_root_message_type_is_discover(self) -> None:
        plans = generate_plans(
            seed=106,
            profile="smoke",
            count=3,
            backend="scapy",
            case="dhcpv4-discover",
        )

        plan = self._ipv4_root_dhcpv4_plan(plans)

        self.assertEqual(_dhcpv4_message_type(plan), "discover")

    def test_dhcpv4_discover_ipv4_root_is_deterministic(self) -> None:
        first = self._ipv4_root_dhcpv4_plan(
            generate_plans(
                seed=106,
                profile="smoke",
                count=3,
                backend="scapy",
                case="dhcpv4-discover",
            )
        )
        second = self._ipv4_root_dhcpv4_plan(
            generate_plans(
                seed=106,
                profile="smoke",
                count=3,
                backend="scapy",
                case="dhcpv4-discover",
            )
        )

        self.assertEqual(first.to_dict(), second.to_dict())


class ScapyIpv4Dhcpv4MaterializationTest(unittest.TestCase):
    """Prove Scapy materializes the IPv4-root ``ipv4 / udp / dhcpv4`` stack.

    The reference backend must build the live DHCPv4 packet as
    ``IP / UDP / BOOTP / DHCPv4`` without an Ethernet frame and decode it back to
    the normalized ``ipv4 / udp / dhcpv4`` model with equivalent UDP ports and
    DHCPv4 fields.
    """

    def _ipv4_root_dhcpv4_plan(self) -> PacketPlan:
        plans = generate_plans(
            seed=110,
            profile="smoke",
            count=4,
            backend="scapy",
            case="dhcpv4-discover",
        )
        matches = [plan for plan in plans if list(plan.stack) == _IPV4_ROOT_STACK]
        self.assertTrue(
            matches,
            msg=(
                "expected at least one ipv4/udp/dhcpv4 plan for --case "
                "dhcpv4-discover, got stacks "
                f"{[list(plan.stack) for plan in plans]}"
            ),
        )
        return matches[0]

    def test_scapy_materializes_ipv4_dhcpv4_without_ethernet(self) -> None:
        encode_packet_plan, _ = _require_scapy_backend()

        plan = self._ipv4_root_dhcpv4_plan()
        vector = encode_packet_plan(plan)

        self.assertEqual(vector.root, "l3:ipv4")
        self.assertEqual(vector.decoder, "IP")
        # The IPv4-root stack must materialize as IP / UDP / BOOTP / DHCPv4 with
        # no Ethernet frame; Scapy reports BOOTP/DHCPv4 as a single DHCPv4 layer.
        self.assertEqual(vector.metadata.get("scapy_stack"), ["IP", "UDP", "DHCP"])

    def test_scapy_decodes_ipv4_dhcpv4_stack_and_root(self) -> None:
        encode_packet_plan, decode_vector = _require_scapy_backend()

        plan = self._ipv4_root_dhcpv4_plan()
        decoded = decode_vector(encode_packet_plan(plan))

        self.assertEqual(decoded.layers, _IPV4_ROOT_STACK)
        self.assertEqual(decoded.root, "l3:ipv4")

    def test_scapy_ipv4_dhcpv4_uses_bootp_ports(self) -> None:
        encode_packet_plan, decode_vector = _require_scapy_backend()

        plan = self._ipv4_root_dhcpv4_plan()
        decoded = decode_vector(encode_packet_plan(plan))
        udp = decoded.fields.get("udp")

        self.assertIsInstance(udp, Mapping)
        self.assertEqual(udp.get("src_port"), 68)
        self.assertEqual(udp.get("dst_port"), 67)

    def test_scapy_ipv4_dhcpv4_fields(self) -> None:
        encode_packet_plan, decode_vector = _require_scapy_backend()

        plan = self._ipv4_root_dhcpv4_plan()
        decoded = decode_vector(encode_packet_plan(plan))
        dhcpv4 = decoded.fields.get("dhcpv4")

        self.assertIsInstance(dhcpv4, Mapping)
        # BOOTP request carrying the Ethernet hardware type and the DHCPv4 magic
        # cookie that prefaces the merged option list.
        self.assertEqual(dhcpv4.get("opcode"), 1)
        self.assertEqual(dhcpv4.get("hardware_type"), 1)
        self.assertEqual(dhcpv4.get("hardware_length"), 6)
        self.assertEqual(dhcpv4.get("magic_cookie"), _DHCPV4_MAGIC_COOKIE)
        self.assertGreaterEqual(dhcpv4.get("option_count"), 1)


class Dhcpv4OptionNormalizeTest(unittest.TestCase):
    def test_dhcpv4_option_decode_stops_at_end_before_udp_surplus(self) -> None:
        option_region_hex = (
            "350101ff"
            "307501040405a0050505dc0206060102030407060a0b0c0d"
        )

        options = normalize._decode_dhcpv4_option_tlvs(option_region_hex)

        self.assertEqual(
            options,
            [
                {"code": 53, "payload_hex": "01"},
                {"code": 255, "payload_hex": ""},
            ],
        )

    def test_dhcpv4_option_details_surface_message_type_before_udp_surplus(self) -> None:
        output: dict[str, object] = {}
        option_region_hex = (
            "350101ff"
            "307501040405a0050505dc0206060102030407060a0b0c0d"
        )

        normalize._apply_dhcpv4_option_details(output, option_region_hex)

        self.assertEqual(output["message_type"], 1)
        self.assertEqual(output["option_count"], 2)


class Dhcpv4OptionMatrixGeneratorTest(unittest.TestCase):
    """Prove the generator samples the byte-safe DHCPv4 option matrix.

    The ``dhcpv4_behavior`` ``dhcpv4-option-matrix`` case must materialize every
    Scapy-byte-safe option kind in a deterministic order for both DHCPv4 roots
    and both directions, so the cross-backend offline runs exercise the option
    matrix rather than only the message-type/server-id subset.
    """

    _SEED = 114
    _PROFILE = "wild"
    _COUNT = 32

    def _matrix_plans(self, direction: str) -> list[PacketPlan]:
        plans = generate_plans(
            seed=self._SEED,
            profile=self._PROFILE,
            count=self._COUNT,
            backend="scapy",
            feature="dhcpv4_behavior",
            direction=direction,
        )
        matrix = [plan for plan in plans if plan.case == "dhcpv4-option-matrix"]
        self.assertTrue(
            matrix,
            msg=(
                "expected at least one dhcpv4-option-matrix plan for "
                f"direction={direction!r}, got cases "
                f"{sorted({plan.case for plan in plans})}"
            ),
        )
        return matrix

    def _matrix_case_plans(self, direction: str) -> list[PacketPlan]:
        return generate_plans(
            seed=self._SEED,
            profile=self._PROFILE,
            count=16,
            backend="scapy",
            case="dhcpv4-option-matrix",
            direction=direction,
        )

    def test_option_matrix_case_is_sampled_in_both_directions(self) -> None:
        for direction in ("libcrafter_to_backend", "backend_to_libcrafter"):
            with self.subTest(direction=direction):
                self._matrix_plans(direction)

    def test_option_matrix_plan_covers_listed_option_kinds(self) -> None:
        for direction in ("libcrafter_to_backend", "backend_to_libcrafter"):
            with self.subTest(direction=direction):
                plan = self._matrix_plans(direction)[0]
                kinds = _dhcpv4_option_kinds(plan)
                self.assertEqual(kinds, list(_EXPECTED_OPTION_MATRIX_KINDS))
                # Every byte-safe kind from the matrix is present and ends with
                # the option-list terminator.
                self.assertEqual(kinds[-1], "end")
                self.assertGreaterEqual(len(set(kinds)), len(_EXPECTED_OPTION_MATRIX_KINDS))

    def test_option_matrix_root_for_each_direction(self) -> None:
        # The IPv4-root live stack and the Ethernet-root offline stack both
        # carry the option matrix; at least the IPv4-root stack must appear so
        # live-friendly cross-backend coverage stays available.
        for direction in ("libcrafter_to_backend", "backend_to_libcrafter"):
            with self.subTest(direction=direction):
                roots = {_packet_root(plan) for plan in self._matrix_case_plans(direction)}
                self.assertIn("l3:ipv4", roots)

    def test_option_matrix_is_deterministic(self) -> None:
        first = self._matrix_plans("libcrafter_to_backend")
        second = self._matrix_plans("libcrafter_to_backend")
        self.assertEqual(
            [plan.to_dict() for plan in first],
            [plan.to_dict() for plan in second],
        )

    def test_option_matrix_tokens_match_published_order(self) -> None:
        plan = self._matrix_plans("backend_to_libcrafter")[0]
        options = plan.fields["dhcpv4"]["options"]
        self.assertEqual(list(options), list(DHCPV4_OPTION_MATRIX_TOKENS))


if __name__ == "__main__":
    unittest.main()
