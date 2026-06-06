"""Shared Linux guest interface discovery tests."""

from __future__ import annotations

import json
import unittest
from collections.abc import Sequence

from tools.endpoint.engine.process import CommandResult
from tools.endpoint.engine.providers.hetzner.discovery import parse_ip_interface_discovery
from tools.endpoint.engine.providers.vm.discovery import (
    LINUX_INTERFACE_DISCOVERY_COMMAND,
    LINUX_INTERFACE_DISCOVERY_MARKERS,
    discover_linux_endpoint_interfaces,
    parse_interface_discovery_sections,
    parse_linux_interface_discovery,
    select_default_route_interfaces,
    select_lan_candidate_interfaces,
)


class LinuxInterfaceDiscoveryTest(unittest.TestCase):
    def test_parse_marker_delimited_json_returns_all_interfaces(self) -> None:
        interfaces = parse_linux_interface_discovery(
            _virtualbox_discovery_output(),
            exposure="lan",
            prefer_public_or_default=False,
        )

        self.assertEqual([interface.name for interface in interfaces], ["enp0s3", "enp0s8"])
        self.assertEqual(interfaces[0].ipv4, "10.0.2.15")
        self.assertEqual(interfaces[1].ipv4, "192.168.1.44")
        self.assertEqual(interfaces[1].mac, "08:00:27:dd:ee:ff")
        self.assertEqual(interfaces[1].metadata["ifindex"], 3)
        self.assertEqual(interfaces[1].metadata["operstate"], "UP")
        self.assertFalse(interfaces[1].metadata["default_route"])

    def test_default_route_selection_matches_route_device(self) -> None:
        all_interfaces = parse_linux_interface_discovery(
            _virtualbox_discovery_output(),
            exposure="lan",
            prefer_public_or_default=False,
        )

        self.assertEqual(
            [interface.name for interface in select_default_route_interfaces(all_interfaces)],
            ["enp0s3"],
        )
        selected = parse_linux_interface_discovery(
            _virtualbox_discovery_output(),
            exposure="lan",
        )
        self.assertEqual([interface.name for interface in selected], ["enp0s3"])

    def test_virtualbox_lan_candidates_exclude_nat_control_cidr(self) -> None:
        all_interfaces = parse_linux_interface_discovery(
            _virtualbox_discovery_output(),
            exposure="lan",
            prefer_public_or_default=False,
        )

        candidates = select_lan_candidate_interfaces(all_interfaces)

        self.assertEqual([interface.name for interface in candidates], ["enp0s8"])
        self.assertEqual(candidates[0].ipv4, "192.168.1.44")

    def test_discover_linux_endpoint_interfaces_runs_ssh_parser(self) -> None:
        calls: list[tuple[str, ...]] = []

        def fake_runner(argv: Sequence[object], **_: object) -> CommandResult:
            calls.append(tuple(str(part) for part in argv))
            return CommandResult(
                argv=tuple(str(part) for part in argv),
                redacted_argv=tuple(str(part) for part in argv),
                cwd=None,
                exit_code=0,
                stdout=_virtualbox_discovery_output(),
                stderr="",
            )

        interfaces = discover_linux_endpoint_interfaces(
            host="127.0.0.1",
            user="ubuntu",
            identity_file="/tmp/wire-test-key",
            known_hosts="/tmp/wire-test-known-hosts",
            exposure="lan",
            port=2222,
            runner=fake_runner,
            prefer_public_or_default=False,
        )

        self.assertEqual([interface.name for interface in interfaces], ["enp0s3", "enp0s8"])
        self.assertEqual(calls[0][0], "ssh")
        self.assertEqual(calls[0][-1], LINUX_INTERFACE_DISCOVERY_COMMAND)

    def test_hetzner_wrapper_preserves_public_metadata(self) -> None:
        selected = parse_ip_interface_discovery(
            _virtualbox_discovery_output(),
            exposure="wan",
            public_ipv4="192.168.1.44",
        )

        self.assertEqual([interface.name for interface in selected], ["enp0s8"])
        self.assertEqual(selected[0].metadata["hcloud_public_ipv4"], "192.168.1.44")
        self.assertTrue(selected[0].metadata["matched_public_address"])

    def test_parse_sections_rejects_missing_marker(self) -> None:
        missing_route = "\n".join(
            [
                LINUX_INTERFACE_DISCOVERY_MARKERS["addr"],
                "[]",
                LINUX_INTERFACE_DISCOVERY_MARKERS["link"],
                "[]",
            ]
        )

        with self.assertRaisesRegex(RuntimeError, "__WIRE_IP_ROUTE__"):
            parse_interface_discovery_sections(missing_route)


def _virtualbox_discovery_output() -> str:
    addresses = [
        {
            "ifindex": 2,
            "ifname": "enp0s3",
            "address": "08:00:27:aa:bb:cc",
            "operstate": "UP",
            "mtu": 1500,
            "addr_info": [
                {"family": "inet", "local": "10.0.2.15", "prefixlen": 24},
                {"family": "inet6", "local": "fe80::a00:27ff:feaa:bbcc", "prefixlen": 64},
            ],
        },
        {
            "ifindex": 3,
            "ifname": "enp0s8",
            "address": "08:00:27:dd:ee:ff",
            "operstate": "UP",
            "mtu": 1500,
            "addr_info": [
                {"family": "inet", "local": "192.168.1.44", "prefixlen": 24},
                {"family": "inet6", "local": "fe80::a00:27ff:fedd:eeff", "prefixlen": 64},
            ],
        },
    ]
    links = [
        {
            "ifindex": 2,
            "ifname": "enp0s3",
            "address": "08:00:27:aa:bb:cc",
            "operstate": "UP",
            "mtu": 1500,
        },
        {
            "ifindex": 3,
            "ifname": "enp0s8",
            "address": "08:00:27:dd:ee:ff",
            "operstate": "UP",
            "mtu": 1500,
        },
    ]
    routes = [{"dst": "1.1.1.1", "dev": "enp0s3", "prefsrc": "10.0.2.15"}]
    return "\n".join(
        [
            LINUX_INTERFACE_DISCOVERY_MARKERS["addr"],
            json.dumps(addresses),
            LINUX_INTERFACE_DISCOVERY_MARKERS["link"],
            json.dumps(links),
            LINUX_INTERFACE_DISCOVERY_MARKERS["route"],
            json.dumps(routes),
        ]
    )


if __name__ == "__main__":
    unittest.main()
