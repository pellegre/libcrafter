"""Coverage for tracked built-in appliance profile manifests."""

from __future__ import annotations

import io
import json
import re
import tempfile
import unittest
from pathlib import Path

from tools.appliance.checks import serial_device_exists
from tools.appliance.engine.checks import (
    CHECK_KIND_DOCKER_DAEMON,
    CHECK_KIND_DOT11_INJECTION_SMOKE,
    CHECK_KIND_DOT11_MONITOR_INTERFACE,
    CHECK_KIND_INTERFACE_EXISTS,
    CHECK_KIND_LAN_REACHABILITY_PLAN,
    CHECK_KIND_PCAP_OPEN,
    CHECK_KIND_RAW_SOCKET_PERMISSION,
    CHECK_KIND_SERIAL_DEVICE_EXISTS,
    CHECK_KIND_WHAD_DISCOVERY,
    render_profile_check_plans,
)
from tools.appliance.engine.profile import DEFAULT_IMAGE
from tools.appliance.engine.profiles import list_profile_names, profiles_dir, resolve_profile
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

    def test_whad_serial_profile_is_registered_with_serial_placement(self) -> None:
        self.assertIn("whad-serial", list_profile_names())

        profile = resolve_profile("whad-serial")

        self.assertEqual(profile.metadata["placement"], "serial")
        self.assertEqual(profile.image, DEFAULT_IMAGE)
        self.assertEqual(profile.network_mode, "bridge")
        self.assertEqual(profile.cap_add, [])
        self.assertEqual(profile.env, {"LIBCRAFTER_WHAD_DEVICE": ""})
        self.assertEqual(len(profile.devices), 1)
        self.assertEqual(profile.devices[0].host_path, "/dev/ttyACM0")
        self.assertEqual(profile.devices[0].container_path, "/dev/ttyACM0")
        self.assertEqual(profile.devices[0].permissions, "rw")
        requirement_text = " ".join(profile.host_requirements).lower()
        self.assertIn("does not flash firmware", requirement_text)
        self.assertIn("authorized rf environment", requirement_text)
        self.assertIn("dry-run", requirement_text)

    def test_whad_serial_profile_renders_device_plan(self) -> None:
        profile = resolve_profile("whad-serial")

        default_plan = render_docker_run_plan(
            profile,
            work_dir="/tmp/libcrafter-work",
            artifact_dir="/tmp/libcrafter-artifacts",
            command_argv=["true"],
        )
        self.assertIn("/dev/ttyACM0:/dev/ttyACM0:rw", default_plan.docker_argv)

        override_plan = render_docker_run_plan(
            profile,
            work_dir="/tmp/libcrafter-work",
            artifact_dir="/tmp/libcrafter-artifacts",
            command_argv=["true"],
            environment={"LIBCRAFTER_WHAD_DEVICE": "/dev/ttyACM9"},
        )
        self.assertEqual(override_plan.env["LIBCRAFTER_WHAD_DEVICE"], "/dev/ttyACM9")
        self.assertIn("/dev/ttyACM9:/dev/ttyACM9:rw", override_plan.docker_argv)
        self.assertNotIn("/dev/ttyACM0:/dev/ttyACM0:rw", override_plan.docker_argv)

    def test_whad_serial_profile_renders_serial_and_optional_discovery_checks(self) -> None:
        profile = resolve_profile("whad-serial")

        check_plans = render_profile_check_plans(profile)
        self.assertEqual(
            [plan.kind for plan in check_plans],
            [
                CHECK_KIND_DOCKER_DAEMON,
                CHECK_KIND_SERIAL_DEVICE_EXISTS,
                CHECK_KIND_WHAD_DISCOVERY,
            ],
        )
        self.assertEqual(check_plans[1].command_argv[-2:], ["--device", "/dev/ttyACM0"])
        self.assertTrue(check_plans[1].required)
        self.assertEqual(check_plans[2].command_argv[-2:], ["--device", "/dev/ttyACM0"])
        self.assertFalse(check_plans[2].required)
        self.assertEqual(
            check_plans[2].metadata,
            {
                "live_transmit": False,
                "readiness_only": True,
            },
        )

        override_plans = render_profile_check_plans(
            profile,
            environment={"LIBCRAFTER_WHAD_DEVICE": "/dev/ttyACM9"},
        )
        self.assertEqual(override_plans[1].command_argv[-2:], ["--device", "/dev/ttyACM9"])

    def test_dot11_monitor_profile_is_registered_with_wifi_monitor_placement(self) -> None:
        self.assertIn("dot11-monitor", list_profile_names())

        profile = resolve_profile("dot11-monitor")

        self.assertEqual(profile.metadata["placement"], "wifi-monitor")
        self.assertEqual(profile.image, DEFAULT_IMAGE)
        self.assertEqual(profile.network_mode, "host")
        self.assertEqual(profile.cap_add, ["NET_RAW", "NET_ADMIN"])
        self.assertEqual(profile.devices, [])
        self.assertEqual(profile.env, {"LIBCRAFTER_DOT11_IFACE": ""})
        self.assertEqual(profile.metadata["interface_env"], "LIBCRAFTER_DOT11_IFACE")
        self.assertEqual(profile.metadata["optional_channel"]["env"], "LIBCRAFTER_DOT11_CHANNEL")
        self.assertFalse(profile.metadata["optional_channel"]["required"])

    def test_dot11_monitor_profile_documents_host_or_vm_prep_ownership(self) -> None:
        profile = resolve_profile("dot11-monitor")

        requirement_text = " ".join(profile.host_requirements).lower()
        self.assertIn("host or vm preparation owns", requirement_text)
        self.assertIn("wi-fi kernel driver", requirement_text)
        self.assertIn("monitor-mode setup", requirement_text)
        self.assertIn("already exist and be in monitor mode", requirement_text)
        prep = profile.metadata["host_or_vm_prep"]
        self.assertTrue(prep["owns_kernel_driver"])
        self.assertTrue(prep["owns_monitor_mode"])

    def test_dot11_monitor_profile_renders_checks_and_missing_live_iface_policy(self) -> None:
        profile = resolve_profile("dot11-monitor")

        check_plans = render_profile_check_plans(profile)
        self.assertEqual(
            [plan.kind for plan in check_plans],
            [
                CHECK_KIND_DOCKER_DAEMON,
                CHECK_KIND_INTERFACE_EXISTS,
                CHECK_KIND_DOT11_MONITOR_INTERFACE,
                CHECK_KIND_PCAP_OPEN,
                CHECK_KIND_DOT11_INJECTION_SMOKE,
            ],
        )
        self.assertEqual(check_plans[1].command_argv[-2:], ["--iface-env", "LIBCRAFTER_DOT11_IFACE"])
        self.assertEqual(check_plans[2].command_argv[-2:], ["--iface-env", "LIBCRAFTER_DOT11_IFACE"])
        self.assertEqual(check_plans[3].command_argv[-2:], ["--iface-env", "LIBCRAFTER_DOT11_IFACE"])

        injection = check_plans[4]
        self.assertFalse(injection.required)
        self.assertIn("--dry-run", injection.command_argv)
        self.assertEqual(injection.command_argv[-2:], ["--iface-env", "LIBCRAFTER_DOT11_IFACE"])
        self.assertEqual(injection.metadata["missing_interface_policy"], "reject-live-check")
        self.assertTrue(injection.metadata["requires_interface_configuration"])
        self.assertTrue(injection.metadata["requires_live_gate"])
        self.assertFalse(injection.metadata["live_transmit"])

        override_plans = render_profile_check_plans(
            profile,
            environment={"LIBCRAFTER_DOT11_IFACE": "mon0"},
        )
        self.assertEqual(override_plans[4].command_argv[-2:], ["--iface", "mon0"])

    def test_dot11_monitor_profile_does_not_claim_docker_wifi_isolation(self) -> None:
        profile = resolve_profile("dot11-monitor")
        isolation = profile.metadata["docker_wifi_isolation"]

        self.assertIsInstance(isolation, dict)
        self.assertFalse(isolation["sufficient"])
        self.assertIn("userland execution only", isolation["reason"])
        self.assertIn("host or VM preparation", isolation["reason"])
        profile_json = json.dumps(profile.to_dict(), sort_keys=True).lower()
        self.assertNotIn("docker is sufficient", profile_json)
        self.assertNotIn("docker alone is sufficient", profile_json)

    def test_tracked_appliance_manifests_do_not_store_real_hardware_serials(self) -> None:
        for path in _tracked_manifest_paths():
            with self.subTest(path=path):
                manifest = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(_hardware_identifier_findings(manifest), [])

    def test_missing_whad_serial_device_reports_structured_check_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing_device = str(Path(directory) / "ttyACM-missing")
            output = io.StringIO()

            exit_code = serial_device_exists.main(["--device", missing_device], stdout=output)

        payload = json.loads(output.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["check"], CHECK_KIND_SERIAL_DEVICE_EXISTS)
        self.assertEqual(payload["error"], "missing_serial_device")
        self.assertEqual(payload["device"], missing_device)
        self.assertEqual(payload["exists"], False)
        self.assertEqual(payload["readable"], False)


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


def _tracked_manifest_paths() -> list[Path]:
    module_paths = sorted(profiles_dir().parent.glob("modules/*/module.json"))
    return [*sorted(profiles_dir().glob("*.json")), *module_paths]


def _hardware_identifier_findings(value: object, path: str = "$") -> list[str]:
    sensitive_keys = {
        "bssid",
        "hardware_id",
        "hardware_ids",
        "mac",
        "mac_address",
        "pid",
        "serial_number",
        "serial_numbers",
        "ssid",
        "usb_id",
        "usb_ids",
        "vid",
        "vid_pid",
    }
    usb_id = re.compile(r"^[0-9a-fA-F]{4}:[0-9a-fA-F]{4}$")
    mac_address = re.compile(r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$")

    findings: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = key.lower().replace("-", "_")
            if normalized in sensitive_keys and _has_non_empty_value(item):
                findings.append(f"{path}.{key}")
            findings.extend(_hardware_identifier_findings(item, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            findings.extend(_hardware_identifier_findings(item, f"{path}[{index}]"))
    elif isinstance(value, str):
        if usb_id.fullmatch(value) or mac_address.fullmatch(value):
            findings.append(path)
    return findings


def _has_non_empty_value(value: object) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return value != ""
    if isinstance(value, dict):
        return any(_has_non_empty_value(item) for item in value.values())
    if isinstance(value, list):
        return any(_has_non_empty_value(item) for item in value)
    return True


if __name__ == "__main__":
    unittest.main()
