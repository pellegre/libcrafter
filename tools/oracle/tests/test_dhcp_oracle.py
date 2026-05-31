"""Unit coverage for DHCP oracle generator selection and Scapy materialization.

These tests pin the packet plan shape that ``--case dhcp-discover`` must
produce so the IPv4-root ``ipv4 / udp / dhcp`` stack stays available for
live-friendly oracle validation while the Ethernet-root stack keeps its
link-layer coverage. They also pin how the Scapy reference backend
materializes that IPv4-root stack as ``IP / UDP / BOOTP / DHCP`` (no Ethernet)
and decodes back to the normalized ``ipv4 / udp / dhcp`` model.
"""

from __future__ import annotations

import unittest
from collections.abc import Mapping, Sequence

from tools.oracle.engine.generator import (
    DHCP_OPTION_MATRIX_TOKENS,
    generate_plans,
)
from tools.oracle.engine.backends.scapy import normalize
from tools.oracle.engine.model import PacketPlan


_IPV4_ROOT_STACK = ["ipv4", "udp", "dhcp"]

# The Scapy-byte-safe option kinds the dhcp_behavior option_matrix samples
# cross-backend, expressed as the backend-neutral option names the generated
# plans carry. Kinds Scapy cannot encode byte-for-byte are covered by native
# libcrafter fixtures instead; see tools/oracle/specs/layers/dhcp.yaml.
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

# DHCP magic cookie (RFC 2132) that prefaces the option list once decoded.
_DHCP_MAGIC_COOKIE = 0x63825363


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


def _dhcp_option_kinds(plan: PacketPlan) -> list[str]:
    """Return the DHCP option kinds a plan encodes, in order.

    Options are carried in ``dhcp.options`` either as ``name=value`` strings or
    as ``[name, value]`` lists; the bare ``end``/``pad`` markers are kinds too.
    """

    dhcp = plan.fields.get("dhcp")
    if not isinstance(dhcp, Mapping):
        return []
    options = dhcp.get("options")
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


class ScapyIpv4DhcpMaterializationTest(unittest.TestCase):
    """Prove Scapy materializes the IPv4-root ``ipv4 / udp / dhcp`` stack.

    The reference backend must build the live DHCP packet as
    ``IP / UDP / BOOTP / DHCP`` without an Ethernet frame and decode it back to
    the normalized ``ipv4 / udp / dhcp`` model with equivalent UDP ports and
    DHCP fields.
    """

    def _ipv4_root_dhcp_plan(self) -> PacketPlan:
        plans = generate_plans(
            seed=110,
            profile="smoke",
            count=4,
            backend="scapy",
            case="dhcp-discover",
        )
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

    def test_scapy_materializes_ipv4_dhcp_without_ethernet(self) -> None:
        encode_packet_plan, _ = _require_scapy_backend()

        plan = self._ipv4_root_dhcp_plan()
        vector = encode_packet_plan(plan)

        self.assertEqual(vector.root, "l3:ipv4")
        self.assertEqual(vector.decoder, "IP")
        # The IPv4-root stack must materialize as IP / UDP / BOOTP / DHCP with
        # no Ethernet frame; Scapy reports BOOTP/DHCP as a single DHCP layer.
        self.assertEqual(vector.metadata.get("scapy_stack"), ["IP", "UDP", "DHCP"])

    def test_scapy_decodes_ipv4_dhcp_stack_and_root(self) -> None:
        encode_packet_plan, decode_vector = _require_scapy_backend()

        plan = self._ipv4_root_dhcp_plan()
        decoded = decode_vector(encode_packet_plan(plan))

        self.assertEqual(decoded.layers, _IPV4_ROOT_STACK)
        self.assertEqual(decoded.root, "l3:ipv4")

    def test_scapy_ipv4_dhcp_uses_bootp_ports(self) -> None:
        encode_packet_plan, decode_vector = _require_scapy_backend()

        plan = self._ipv4_root_dhcp_plan()
        decoded = decode_vector(encode_packet_plan(plan))
        udp = decoded.fields.get("udp")

        self.assertIsInstance(udp, Mapping)
        self.assertEqual(udp.get("src_port"), 68)
        self.assertEqual(udp.get("dst_port"), 67)

    def test_scapy_ipv4_dhcp_fields(self) -> None:
        encode_packet_plan, decode_vector = _require_scapy_backend()

        plan = self._ipv4_root_dhcp_plan()
        decoded = decode_vector(encode_packet_plan(plan))
        dhcp = decoded.fields.get("dhcp")

        self.assertIsInstance(dhcp, Mapping)
        # BOOTP request carrying the Ethernet hardware type and the DHCP magic
        # cookie that prefaces the merged option list.
        self.assertEqual(dhcp.get("opcode"), 1)
        self.assertEqual(dhcp.get("hardware_type"), 1)
        self.assertEqual(dhcp.get("hardware_length"), 6)
        self.assertEqual(dhcp.get("magic_cookie"), _DHCP_MAGIC_COOKIE)
        self.assertGreaterEqual(dhcp.get("option_count"), 1)


class DhcpOptionNormalizeTest(unittest.TestCase):
    def test_dhcp_option_decode_stops_at_end_before_udp_surplus(self) -> None:
        option_region_hex = (
            "350101ff"
            "307501040405a0050505dc0206060102030407060a0b0c0d"
        )

        options = normalize._decode_dhcp_option_tlvs(option_region_hex)

        self.assertEqual(
            options,
            [
                {"code": 53, "payload_hex": "01"},
                {"code": 255, "payload_hex": ""},
            ],
        )

    def test_dhcp_option_details_surface_message_type_before_udp_surplus(self) -> None:
        output: dict[str, object] = {}
        option_region_hex = (
            "350101ff"
            "307501040405a0050505dc0206060102030407060a0b0c0d"
        )

        normalize._apply_dhcp_option_details(output, option_region_hex)

        self.assertEqual(output["message_type"], 1)
        self.assertEqual(output["option_count"], 2)


class DhcpOptionMatrixGeneratorTest(unittest.TestCase):
    """Prove the generator samples the byte-safe DHCP option matrix.

    The ``dhcp_behavior`` ``dhcp-option-matrix`` case must materialize every
    Scapy-byte-safe option kind in a deterministic order for both DHCP roots
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
            feature="dhcp_behavior",
            direction=direction,
        )
        matrix = [plan for plan in plans if plan.case == "dhcp-option-matrix"]
        self.assertTrue(
            matrix,
            msg=(
                "expected at least one dhcp-option-matrix plan for "
                f"direction={direction!r}, got cases "
                f"{sorted({plan.case for plan in plans})}"
            ),
        )
        return matrix

    def test_option_matrix_case_is_sampled_in_both_directions(self) -> None:
        for direction in ("libcrafter_to_reference", "reference_to_libcrafter"):
            with self.subTest(direction=direction):
                self._matrix_plans(direction)

    def test_option_matrix_plan_covers_listed_option_kinds(self) -> None:
        for direction in ("libcrafter_to_reference", "reference_to_libcrafter"):
            with self.subTest(direction=direction):
                plan = self._matrix_plans(direction)[0]
                kinds = _dhcp_option_kinds(plan)
                self.assertEqual(kinds, list(_EXPECTED_OPTION_MATRIX_KINDS))
                # Every byte-safe kind from the matrix is present and ends with
                # the option-list terminator.
                self.assertEqual(kinds[-1], "end")
                self.assertGreaterEqual(len(set(kinds)), len(_EXPECTED_OPTION_MATRIX_KINDS))

    def test_option_matrix_root_for_each_direction(self) -> None:
        # The IPv4-root live stack and the Ethernet-root offline stack both
        # carry the option matrix; at least the IPv4-root stack must appear so
        # live-friendly cross-backend coverage stays available.
        for direction in ("libcrafter_to_reference", "reference_to_libcrafter"):
            with self.subTest(direction=direction):
                roots = {_packet_root(plan) for plan in self._matrix_plans(direction)}
                self.assertIn("l3:ipv4", roots)

    def test_option_matrix_is_deterministic(self) -> None:
        first = self._matrix_plans("libcrafter_to_reference")
        second = self._matrix_plans("libcrafter_to_reference")
        self.assertEqual(
            [plan.to_dict() for plan in first],
            [plan.to_dict() for plan in second],
        )

    def test_option_matrix_tokens_match_published_order(self) -> None:
        plan = self._matrix_plans("reference_to_libcrafter")[0]
        options = plan.fields["dhcp"]["options"]
        self.assertEqual(list(options), list(DHCP_OPTION_MATRIX_TOKENS))


if __name__ == "__main__":
    unittest.main()
