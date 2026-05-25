"""Local contract coverage for wire models, registry, and state."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.wire.engine.config import WireConfig
from tools.wire.engine.model import (
    EndpointManifest,
    EndpointSSHInfo,
    NetworkInterface,
    ProviderResources,
    read_json,
    write_json,
)
from tools.wire.engine.registry import (
    ProviderExposureError,
    is_supported_request,
    registered_providers,
    supported_exposures,
    validate_request,
)
from tools.wire.engine.state import (
    read_private_group_record,
    remove_private_group_allocation,
    update_private_group_allocation,
    write_endpoint_manifest,
)


class WireRegistryTest(unittest.TestCase):
    def test_hetzner_supports_only_wan_and_private(self) -> None:
        self.assertEqual(registered_providers(), ("hetzner",))
        self.assertEqual(supported_exposures("hetzner"), ("private", "wan"))
        self.assertTrue(is_supported_request("hetzner", "wan"))
        self.assertTrue(is_supported_request("hetzner", "private"))

    def test_hetzner_rejects_lan_and_wifi_with_explicit_error(self) -> None:
        for exposure in ("lan", "wifi"):
            with self.subTest(exposure=exposure):
                with self.assertRaisesRegex(
                    ProviderExposureError,
                    "unsupported provider/exposure.*supported exposures",
                ):
                    validate_request("hetzner", exposure)

    def test_unknown_provider_and_exposure_are_rejected_before_provider_work(self) -> None:
        with self.assertRaisesRegex(ProviderExposureError, "supported providers"):
            validate_request("virtualbox", "wan")
        with self.assertRaisesRegex(ProviderExposureError, "known exposures"):
            validate_request("hetzner", "bluetooth")


class WireManifestSerializationTest(unittest.TestCase):
    def test_manifest_round_trip_preserves_absolute_paths_and_provider_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = _manifest(root)
            path = root / "state" / "endpoint.json"

            write_json(path, manifest)
            loaded = EndpointManifest.from_dict(read_json(path))  # type: ignore[arg-type]

            self.assertEqual(loaded.to_dict(), manifest.to_dict())
            self.assertTrue(Path(loaded.artifact_dir).is_absolute())
            self.assertTrue(Path(loaded.ssh.identity_file or "").is_absolute())
            self.assertTrue(Path(loaded.ssh.known_hosts_file or "").is_absolute())
            self.assertEqual(
                loaded.provider_resources.metadata["created_by"],
                "tools/wire-test",
            )

    def test_manifest_rejects_relative_local_paths(self) -> None:
        with self.assertRaisesRegex(ValueError, "ssh.identity_file must be an absolute path"):
            EndpointSSHInfo(
                host="198.51.100.10",
                user="root",
                identity_file="relative/id_ed25519",
            )
        with self.assertRaisesRegex(ValueError, "artifact_dir must be an absolute path"):
            EndpointManifest(
                endpoint_id="endpoint-a",
                provider="hetzner",
                exposure="wan",
                status="active",
                role="test",
                created_at="2026-05-25T00:00:00Z",
                ssh=EndpointSSHInfo(host="198.51.100.10", user="root"),
                interfaces=[NetworkInterface(name="public", exposure="wan")],
                provider_resources=ProviderResources(),
                artifact_dir="relative/artifacts",
            )

    def test_state_manifest_path_uses_configured_absolute_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = WireConfig(
                state_root=root / "wire-state",
                artifact_root=root / "wire-artifacts",
            )
            manifest_path = write_endpoint_manifest(_manifest(root), config)

            self.assertEqual(
                manifest_path,
                root / "wire-state" / "endpoints" / "endpoint-a" / "endpoint.json",
            )
            self.assertTrue(manifest_path.is_absolute())


class WirePrivateGroupStateTest(unittest.TestCase):
    def test_private_group_allocations_are_unique_and_removable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = WireConfig(
                state_root=root / "wire-state",
                artifact_root=root / "wire-artifacts",
            )

            update_private_group_allocation(
                provider="hetzner",
                group="oracle-probe",
                endpoint_id="endpoint-a",
                private_ipv4="10.0.0.2",
                network_resource={"network_id": "network-123"},
                config=config,
            )
            record = update_private_group_allocation(
                provider="hetzner",
                group="oracle-probe",
                endpoint_id="endpoint-a",
                private_ipv4="10.0.0.2",
                network_resource={"network_id": "network-123"},
                config=config,
            )
            update_private_group_allocation(
                provider="hetzner",
                group="oracle-probe",
                endpoint_id="endpoint-b",
                private_ipv4="10.0.0.3",
                config=config,
            )

            self.assertEqual(record.allocated_endpoint_ids, ["endpoint-a"])
            stored = read_private_group_record("hetzner", "oracle-probe", config)
            self.assertEqual(stored.allocated_endpoint_ids, ["endpoint-a", "endpoint-b"])
            self.assertEqual(stored.allocated_private_ipv4s, ["10.0.0.2", "10.0.0.3"])
            self.assertEqual(stored.network_resource["network_id"], "network-123")

            updated = remove_private_group_allocation(
                provider="hetzner",
                group="oracle-probe",
                endpoint_id="endpoint-a",
                private_ipv4="10.0.0.2",
                config=config,
            )
            self.assertEqual(updated.allocated_endpoint_ids, ["endpoint-b"])
            self.assertEqual(updated.allocated_private_ipv4s, ["10.0.0.3"])

    def test_private_group_components_reject_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = WireConfig(
                state_root=root / "wire-state",
                artifact_root=root / "wire-artifacts",
            )

            with self.assertRaisesRegex(ValueError, "single path component"):
                update_private_group_allocation(
                    provider="hetzner",
                    group="../other",
                    endpoint_id="endpoint-a",
                    config=config,
                )


def _manifest(root: Path) -> EndpointManifest:
    return EndpointManifest(
        endpoint_id="endpoint-a",
        provider="hetzner",
        exposure="wan",
        status="active",
        role="test",
        created_at="2026-05-25T00:00:00Z",
        ssh=EndpointSSHInfo(
            host="198.51.100.10",
            user="root",
            identity_file=str(root / "state" / "id_ed25519"),
            known_hosts_file=str(root / "state" / "known_hosts"),
        ),
        interfaces=[NetworkInterface(name="public", exposure="wan", ipv4="198.51.100.10")],
        provider_resources=ProviderResources(metadata={"created_by": "tools/wire-test"}),
        artifact_dir=str(root / "artifacts" / "endpoint-a"),
        metadata={
            "state_dir": str(root / "state" / "endpoint-a"),
            "manifest_path": str(root / "state" / "endpoint-a" / "endpoint.json"),
        },
    )


if __name__ == "__main__":
    unittest.main()
