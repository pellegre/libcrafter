"""Coverage for tracked built-in appliance profile manifests."""

from __future__ import annotations

import json
import unittest

from tools.appliance.engine.checks import (
    CHECK_KIND_DOCKER_DAEMON,
    CHECK_KIND_INTERFACE_EXISTS,
    CHECK_KIND_LAN_REACHABILITY_PLAN,
    CHECK_KIND_PCAP_OPEN,
    CHECK_KIND_RAW_SOCKET_PERMISSION,
    render_profile_check_plans,
)
from tools.appliance.engine.profile import DEFAULT_IMAGE
from tools.appliance.engine.profiles import list_profile_names, resolve_profile
from tools.appliance.engine.runtime import render_docker_run_plan


class BuiltinProfilesTest(unittest.TestCase):
    def test_wan_raw_profile_is_registered_with_coarse_placement(self) -> None:
        self.assertIn("wan-raw", list_profile_names())

        profile = resolve_profile("wan-raw")

        self.assertEqual(profile.metadata["placement"], "wan")
        self.assertEqual(profile.image, DEFAULT_IMAGE)
        self.assertEqual(profile.network_mode, "host")
        self.assertEqual(profile.cap_add, ["NET_RAW"])
        self.assertNotIn("NET_ADMIN", profile.cap_add)
        self.assertEqual(profile.env, {"LIBCRAFTER_IFACE": ""})

    def test_wan_raw_profile_renders_expected_checks_and_mounts(self) -> None:
        profile = resolve_profile("wan-raw")

        check_plans = render_profile_check_plans(profile)
        self.assertEqual(
            [plan.kind for plan in check_plans],
            [
                CHECK_KIND_DOCKER_DAEMON,
                CHECK_KIND_INTERFACE_EXISTS,
                CHECK_KIND_RAW_SOCKET_PERMISSION,
                CHECK_KIND_PCAP_OPEN,
            ],
        )
        self.assertEqual(check_plans[1].command_argv[-2:], ["--iface-env", "LIBCRAFTER_IFACE"])
        self.assertEqual(check_plans[3].command_argv[-2:], ["--iface-env", "LIBCRAFTER_IFACE"])

        run_plan = render_docker_run_plan(
            profile,
            work_dir="/tmp/libcrafter-work",
            artifact_dir="/tmp/libcrafter-artifacts",
            command_argv=["true"],
        )
        mount_args = [
            run_plan.docker_argv[index + 1]
            for index, value in enumerate(run_plan.docker_argv)
            if value == "--mount"
        ]
        self.assertIn(
            "type=bind,source=/tmp/libcrafter-work,target=/work",
            mount_args,
        )
        self.assertIn(
            "type=bind,source=/tmp/libcrafter-artifacts,target=/artifacts",
            mount_args,
        )

    def test_wan_raw_profile_has_no_protocol_specific_enumeration(self) -> None:
        profile = resolve_profile("wan-raw").to_dict()

        keys = _recursive_keys(profile)
        self.assertFalse(
            {
                "protocols",
                "allowed_protocols",
                "supported_protocols",
                "packet_protocols",
                "protocol_capabilities",
            }
            & keys
        )

        profile_json = json.dumps(profile, sort_keys=True).lower()
        for protocol_name in ('"tcp"', '"udp"', '"icmp"'):
            with self.subTest(protocol_name=protocol_name):
                self.assertNotIn(protocol_name, profile_json)

    def test_lan_raw_profile_is_registered_with_lan_placement(self) -> None:
        self.assertIn("lan-raw", list_profile_names())

        profile = resolve_profile("lan-raw")

        self.assertEqual(profile.metadata["placement"], "lan")
        self.assertEqual(profile.image, DEFAULT_IMAGE)
        self.assertEqual(profile.network_mode, "host")
        self.assertEqual(profile.cap_add, ["NET_RAW"])
        self.assertNotIn("NET_ADMIN", profile.cap_add)
        self.assertEqual(profile.metadata["optional_cap_add"], ["NET_ADMIN"])
        self.assertEqual(profile.env, {"LIBCRAFTER_IFACE": ""})

    def test_lan_raw_profile_documents_host_or_vm_lan_requirement(self) -> None:
        profile = resolve_profile("lan-raw")

        requirement_text = " ".join(profile.host_requirements).lower()
        self.assertIn("bridged local vm", requirement_text)
        self.assertIn("prepared linux docker host", requirement_text)
        self.assertIn("lan-visible interface", requirement_text)
        self.assertIn("docker bridge nat alone", requirement_text)
        self.assertIn("not true lan link-layer presence", requirement_text)

    def test_lan_raw_profile_does_not_claim_physical_lan_for_nat_only_docker(self) -> None:
        profile = resolve_profile("lan-raw")
        nat_only = profile.metadata["nat_only_docker_bridge"]

        self.assertIsInstance(nat_only, dict)
        self.assertFalse(nat_only["supported"])
        self.assertTrue(nat_only["nat_backed_l3"])
        self.assertFalse(nat_only["true_lan_l2"])
        self.assertFalse(nat_only["physical_lan_l2"])
        self.assertIn("not true LAN link-layer presence", nat_only["reason"])

    def test_lan_raw_profile_renders_expected_checks(self) -> None:
        profile = resolve_profile("lan-raw")

        check_plans = render_profile_check_plans(profile)
        self.assertEqual(
            [plan.kind for plan in check_plans],
            [
                CHECK_KIND_DOCKER_DAEMON,
                CHECK_KIND_INTERFACE_EXISTS,
                CHECK_KIND_RAW_SOCKET_PERMISSION,
                CHECK_KIND_PCAP_OPEN,
                CHECK_KIND_LAN_REACHABILITY_PLAN,
            ],
        )
        self.assertEqual(check_plans[1].command_argv[-2:], ["--iface-env", "LIBCRAFTER_IFACE"])
        self.assertEqual(check_plans[3].command_argv[-2:], ["--iface-env", "LIBCRAFTER_IFACE"])
        self.assertIn("--dry-run", check_plans[4].command_argv)
        self.assertEqual(check_plans[4].command_argv[-2:], ["--iface-env", "LIBCRAFTER_IFACE"])
        self.assertEqual(
            check_plans[4].metadata,
            {
                "live_transmit": False,
                "placeholder": True,
            },
        )

    def test_lan_raw_profile_uses_same_docker_runtime_engine_as_wan_raw(self) -> None:
        lan_plan = render_docker_run_plan(
            resolve_profile("lan-raw"),
            work_dir="/tmp/libcrafter-work",
            artifact_dir="/tmp/libcrafter-artifacts",
            command_argv=["true"],
        )
        wan_plan = render_docker_run_plan(
            resolve_profile("wan-raw"),
            work_dir="/tmp/libcrafter-work",
            artifact_dir="/tmp/libcrafter-artifacts",
            command_argv=["true"],
        )

        self.assertEqual(lan_plan.docker_command, wan_plan.docker_command)
        self.assertEqual(lan_plan.docker_argv[:2], wan_plan.docker_argv[:2])
        self.assertEqual(lan_plan.network_mode, wan_plan.network_mode)
        self.assertEqual(lan_plan.network_mode, "host")


def _recursive_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        keys = set(value)
        for item in value.values():
            keys.update(_recursive_keys(item))
        return keys
    if isinstance(value, list):
        keys: set[str] = set()
        for item in value:
            keys.update(_recursive_keys(item))
        return keys
    return set()


if __name__ == "__main__":
    unittest.main()
