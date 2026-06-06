"""Coverage for lab provider common helpers."""

from __future__ import annotations

import unittest

from tools.lab.engine.model import LabCommandPlan, LabEndpoint, LabRequest, LabRole
from tools.lab.engine.providers.common import (
    build_command_plan,
    lab_endpoint_from_manifest,
    normalize_provider_capabilities,
    peer_address_map,
    profile_seed_label,
    request_session_label,
    select_manifest_interface,
    slug_label,
    validate_remote_dir,
)
from tools.endpoint.engine.model import (
    EndpointManifest,
    EndpointSSHInfo,
    NetworkInterface,
    ProviderResources,
)


class ProviderCommonSlugTest(unittest.TestCase):
    def test_slug_helpers_build_provider_safe_labels(self) -> None:
        self.assertEqual(slug_label(" Smoke_Profile v2 "), "smoke-profile-v2")
        self.assertEqual(slug_label("!!!", fallback="session"), "session")
        self.assertEqual(profile_seed_label("Smoke_Profile", 7), "smoke-profile-seed-7")

        request = LabRequest(
            provider="qemu",
            profile="Smoke_Profile",
            seed=7,
            roles=[LabRole(name="stimulus")],
            workload_label="probe-smoke",
        )

        self.assertEqual(
            request_session_label(request, session_label="Run 01"),
            "lab-probe-smoke-smoke-profile-seed-7-run-01",
        )


class ProviderCommonRemoteDirTest(unittest.TestCase):
    def test_validate_remote_dir_requires_absolute_posix_paths(self) -> None:
        self.assertEqual(validate_remote_dir(None), "/root/libcrafter")
        self.assertEqual(validate_remote_dir("/opt/libcrafter///"), "/opt/libcrafter")
        self.assertEqual(validate_remote_dir("/"), "/")

        with self.assertRaisesRegex(ValueError, "absolute path"):
            validate_remote_dir("relative/path")
        with self.assertRaisesRegex(ValueError, "single quotes"):
            validate_remote_dir("/tmp/agent's-lab")


class ProviderCommonCommandPlanTest(unittest.TestCase):
    def test_build_command_plan_adds_common_metadata(self) -> None:
        plan = build_command_plan(
            purpose="create stimulus endpoint",
            role="provider",
            argv=["tools/endpoint/run", "create-endpoint", "--json"],
            operation="wire.create",
            dry_run=True,
            live_mutation=False,
            provider="qemu",
            exposure="private",
            metadata={"private_group": "lab-smoke"},
        )

        self.assertIsInstance(plan, LabCommandPlan)
        self.assertEqual(plan.operation, "wire.create")
        self.assertTrue(plan.dry_run)
        self.assertFalse(plan.live_mutation)
        self.assertEqual(plan.metadata["provider"], "qemu")
        self.assertEqual(plan.metadata["exposure"], "private")
        self.assertEqual(plan.metadata["private_group"], "lab-smoke")


class ProviderCommonManifestTest(unittest.TestCase):
    def test_select_manifest_interface_by_exposure(self) -> None:
        manifest = _manifest(
            interfaces=[
                NetworkInterface(name="eth0", exposure="control", ipv4="10.0.2.15"),
                NetworkInterface(
                    name="eth1",
                    exposure="private",
                    ipv4="10.77.0.10",
                    mac="02:00:00:00:00:10",
                    provider_network_id="qemu-private-group-lab",
                    metadata={"private_group": "lab"},
                ),
            ]
        )

        selected = select_manifest_interface(manifest, "private")

        self.assertEqual(selected.name, "eth1")
        self.assertEqual(selected.ipv4, "10.77.0.10")
        self.assertEqual(selected.provider_network_id, "qemu-private-group-lab")

        with self.assertRaisesRegex(ValueError, "lacks an 'lan' interface"):
            select_manifest_interface(manifest, "lan")

    def test_lab_endpoint_from_manifest_preserves_manifest_and_peer_addresses(self) -> None:
        role = LabRole(name="stimulus", planned_ipv4="10.77.0.10")
        peer = LabRole(name="target", planned_ipv4="10.77.0.20")
        manifest = _manifest(
            endpoint_id="qemu-private-stimulus",
            interfaces=[
                NetworkInterface(name="eth0", exposure="control", ipv4="10.0.2.15"),
                NetworkInterface(
                    name="eth1",
                    exposure="private",
                    ipv4="10.77.0.10",
                    ipv6="2001:db8::10",
                    mac="02:00:00:00:00:10",
                    provider_network_id="qemu-private-group-lab",
                    metadata={"private_group": "lab", "type": "qemu-private-net"},
                ),
            ],
        )

        endpoint = lab_endpoint_from_manifest(
            manifest,
            role=role,
            exposure="private",
            peer_roles=[peer],
            dry_run=False,
        )

        self.assertIsInstance(endpoint, LabEndpoint)
        self.assertEqual(endpoint.endpoint_id, "qemu-private-stimulus")
        self.assertEqual(endpoint.role, "stimulus")
        self.assertEqual(endpoint.interface, "eth1")
        self.assertEqual(endpoint.ipv4, "10.77.0.10")
        self.assertEqual(endpoint.ipv6, "2001:db8::10")
        self.assertEqual(endpoint.mac, "02:00:00:00:00:10")
        self.assertEqual(endpoint.peer_addresses, {"target": {"ipv4": "10.77.0.20"}})
        self.assertEqual(endpoint.metadata["address_source"], "manifest-interface")
        self.assertEqual(endpoint.metadata["private_group"], "lab")
        self.assertEqual(endpoint.metadata["provider_network_id"], "qemu-private-group-lab")
        self.assertEqual(endpoint.wire_manifest["endpoint_id"], "qemu-private-stimulus")

    def test_lab_endpoint_from_manifest_uses_planned_role_address_for_dry_run(self) -> None:
        endpoint = lab_endpoint_from_manifest(
            _manifest(
                provider="virtualbox",
                exposure="lan",
                interfaces=[NetworkInterface(name="lan", exposure="lan")],
            ),
            role=LabRole(name="target", planned_ipv4="192.0.2.120"),
            exposure="lan",
            dry_run=True,
        )

        self.assertEqual(endpoint.ipv4, "192.0.2.120")
        self.assertTrue(endpoint.metadata["planned_address"])
        self.assertEqual(endpoint.metadata["address_source"], "role-planned-ipv4")
        self.assertEqual(endpoint.metadata["private_group"], "lab")

        with self.assertRaisesRegex(ValueError, "lacks an IPv4 address"):
            lab_endpoint_from_manifest(
                _manifest(
                    provider="virtualbox",
                    exposure="lan",
                    interfaces=[NetworkInterface(name="lan", exposure="lan")],
                ),
                role=LabRole(name="target"),
                exposure="lan",
                dry_run=False,
            )

    def test_peer_address_map_skips_roles_without_planned_addresses(self) -> None:
        self.assertEqual(
            peer_address_map(
                [
                    LabRole(name="target", planned_ipv4="192.0.2.20"),
                    LabRole(name="observer"),
                ]
            ),
            {"target": {"ipv4": "192.0.2.20"}},
        )


class ProviderCommonCapabilitiesTest(unittest.TestCase):
    def test_normalize_provider_capabilities_flattens_common_keys_and_aliases(self) -> None:
        capabilities = normalize_provider_capabilities(
            {
                "provider": "unexpected",
                "capabilities": {
                    "ipv4_unicast": 1,
                    "ipv6_unicast": 0,
                    "link_layer_send": True,
                    "link_layer_capture": True,
                    "provider_mac_known": True,
                    "controlled_services": True,
                    "controlled_router": False,
                },
                "checks": {"ipv4_unicast": {"status": "planned"}},
            },
            provider="qemu",
            dry_run=True,
            source="test",
        )

        self.assertEqual(capabilities["provider"], "qemu")
        self.assertTrue(capabilities["dry_run"])
        self.assertEqual(capabilities["source"], "test")
        self.assertTrue(capabilities["ipv4_unicast"])
        self.assertFalse(capabilities["ipv6_unicast"])
        self.assertTrue(capabilities["ipv4"])
        self.assertFalse(capabilities["ipv6"])
        self.assertTrue(capabilities["l2"])
        self.assertTrue(capabilities["provider_mac"])
        self.assertTrue(capabilities["controlled_service"])
        self.assertIn("controlled_router", capabilities["capability_names"])
        self.assertEqual(capabilities["checks"], {"ipv4_unicast": {"status": "planned"}})


def _manifest(
    *,
    endpoint_id: str = "qemu-private-stimulus",
    provider: str = "qemu",
    exposure: str = "private",
    interfaces: list[NetworkInterface],
) -> EndpointManifest:
    return EndpointManifest(
        endpoint_id=endpoint_id,
        provider=provider,
        exposure=exposure,
        status="planned",
        role="stimulus",
        created_at="2026-05-27T00:00:00Z",
        ssh=EndpointSSHInfo(host="192.0.2.1", user="root"),
        interfaces=interfaces,
        provider_resources=ProviderResources(),
        artifact_dir="/tmp/libcrafter-wire/qemu-private-stimulus",
        metadata={"private_group": "lab"},
    )


if __name__ == "__main__":
    unittest.main()
