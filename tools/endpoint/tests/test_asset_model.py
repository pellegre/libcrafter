"""Persistent endpoint asset model coverage."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.endpoint.engine.assets import (
    AssetHardware,
    AssetSSHInfo,
    EndpointAsset,
    EndpointLease,
    asset_record_path,
    list_endpoint_assets,
    read_endpoint_asset,
    write_endpoint_asset,
)
from tools.endpoint.engine.model import read_json, write_json


class EndpointAssetModelTest(unittest.TestCase):
    def test_asset_round_trip_persists_under_configured_state_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with _endpoint_env(root):
                asset = _asset(root)

                path = write_endpoint_asset(asset)
                loaded = read_endpoint_asset(asset.asset_id)

                self.assertEqual(
                    path,
                    root / "wire-state" / "assets" / "qemu-reusable-a" / "asset.json",
                )
                self.assertEqual(asset_record_path(asset.asset_id), path)
                self.assertTrue(path.is_absolute())
                self.assertEqual(loaded.to_dict(), asset.to_dict())
                self.assertFalse((root / "wire-artifacts" / "assets").exists())

    def test_asset_from_dict_preserves_json_metadata_and_nested_models(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            asset = EndpointAsset.from_dict(_asset(root).to_dict())

            self.assertEqual(asset.asset_id, "qemu-reusable-a")
            self.assertEqual(asset.ssh.host, "192.0.2.10")
            self.assertEqual(asset.docker["image"], "ghcr.io/example/endpoint:latest")
            self.assertEqual(asset.hardware.cpu_count, 4)
            self.assertEqual(asset.hardware.metadata["nested"], {"enabled": True})
            self.assertEqual(asset.metadata["owner"], "endpoint-test")

    def test_supported_profiles_are_deduplicated_preserving_first_occurrence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            asset = _asset(
                root,
                supported_profiles=[
                    "linux-root",
                    "packet-capture",
                    "linux-root",
                    "docker",
                    "packet-capture",
                ],
            )

            self.assertEqual(
                asset.supported_profiles,
                ["linux-root", "packet-capture", "docker"],
            )

    def test_list_endpoint_assets_is_sorted_by_asset_id(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with _endpoint_env(root):
                write_endpoint_asset(_asset(root, asset_id="qemu-reusable-b"))
                write_endpoint_asset(_asset(root, asset_id="qemu-reusable-a"))

                self.assertEqual(
                    [asset.asset_id for asset in list_endpoint_assets()],
                    ["qemu-reusable-a", "qemu-reusable-b"],
                )

    def test_lease_ttl_fields_are_explicit_json_values(self) -> None:
        lease = EndpointLease(
            holder="agent-29",
            leased_at="2026-06-28T12:00:00Z",
            leased_until="2026-06-28T12:30:00Z",
            ttl_seconds=1800,
            metadata={"purpose": "test"},
        )

        self.assertEqual(
            lease.to_dict(),
            {
                "holder": "agent-29",
                "leased_until": "2026-06-28T12:30:00Z",
                "ttl_seconds": 1800,
                "leased_at": "2026-06-28T12:00:00Z",
                "metadata": {"purpose": "test"},
            },
        )
        self.assertEqual(EndpointLease.from_dict(lease.to_dict()).to_dict(), lease.to_dict())

    def test_asset_serialization_includes_lease_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            asset = _asset(
                root,
                lease=EndpointLease(
                    holder="agent-29",
                    leased_until="2026-06-28T12:30:00Z",
                    ttl_seconds=1800,
                ),
            )

            output = asset.to_dict()

            self.assertEqual(output["lease"]["holder"], "agent-29")  # type: ignore[index]
            self.assertEqual(output["lease"]["ttl_seconds"], 1800)  # type: ignore[index]
            self.assertEqual(EndpointAsset.from_dict(output).lease, asset.lease)

    def test_asset_record_rejects_relative_identity_and_known_hosts_paths(self) -> None:
        with self.assertRaisesRegex(ValueError, "ssh.identity_file must be an absolute path"):
            AssetSSHInfo(
                host="192.0.2.10",
                user="root",
                identity_file="relative/id_ed25519",
            )
        with self.assertRaisesRegex(ValueError, "ssh.known_hosts_file must be an absolute path"):
            AssetSSHInfo(
                host="192.0.2.10",
                user="root",
                known_hosts_file="relative/known_hosts",
            )

    def test_asset_id_rejects_relative_path_components(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            with self.assertRaisesRegex(ValueError, "single path component"):
                _asset(root, asset_id="../qemu-reusable-a")
            with self.assertRaisesRegex(ValueError, "single path component"):
                asset_record_path("nested/qemu-reusable-a")

    def test_invalid_lists_and_ttls_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            with self.assertRaisesRegex(ValueError, "supported_profiles"):
                _asset(root, supported_profiles=["linux-root", ""])
            with self.assertRaisesRegex(ValueError, "lease.ttl_seconds"):
                EndpointLease(
                    holder="agent-29",
                    leased_until="2026-06-28T12:30:00Z",
                    ttl_seconds=0,
                )

    def test_asset_read_requires_json_object(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with _endpoint_env(root):
                path = asset_record_path("qemu-reusable-a")
                write_json(path, ["not", "an", "object"])

                with self.assertRaisesRegex(ValueError, "endpoint asset must be a JSON object"):
                    read_endpoint_asset("qemu-reusable-a")

    def test_asset_json_can_be_loaded_through_model_helpers(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            asset = _asset(root)
            path = root / "asset.json"

            write_json(path, asset)

            loaded = EndpointAsset.from_dict(read_json(path))  # type: ignore[arg-type]
            self.assertEqual(loaded.to_dict(), asset.to_dict())


def _asset(
    root: Path,
    *,
    asset_id: str = "qemu-reusable-a",
    supported_profiles: list[str] | None = None,
    lease: EndpointLease | None = None,
) -> EndpointAsset:
    return EndpointAsset(
        asset_id=asset_id,
        substrate="qemu",
        status="available",
        supported_profiles=(
            ["linux-root", "packet-capture", "linux-root"]
            if supported_profiles is None
            else supported_profiles
        ),
        ssh=AssetSSHInfo(
            host="192.0.2.10",
            user="root",
            port=2222,
            identity_file=str(root / "wire-state" / "assets" / asset_id / "id_ed25519"),
            known_hosts_file=str(root / "wire-state" / "assets" / asset_id / "known_hosts"),
            metadata={"transport": "ssh"},
        ),
        docker={
            "container_id": "container-123",
            "image": "ghcr.io/example/endpoint:latest",
            "labels": {"role": "endpoint-asset"},
        },
        hardware=AssetHardware(
            architecture="x86_64",
            cpu_count=4,
            memory_mb=8192,
            disk_gb=40,
            provider_instance_type="cx22",
            metadata={"nested": {"enabled": True}},
        ),
        last_check="2026-06-28T12:00:00Z",
        lease=lease,
        metadata={"owner": "endpoint-test"},
    )


def _endpoint_env(root: Path) -> mock._patch_dict[str, str]:
    return mock.patch.dict(
        os.environ,
        {
            "LIBCRAFTER_ENDPOINT_STATE_ROOT": str(root / "wire-state"),
            "LIBCRAFTER_ENDPOINT_ARTIFACT_ROOT": str(root / "wire-artifacts"),
        },
    )


if __name__ == "__main__":
    unittest.main()
