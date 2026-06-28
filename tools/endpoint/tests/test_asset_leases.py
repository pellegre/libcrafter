"""Profile-based persistent endpoint asset lease coverage."""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

from tools.endpoint.engine import cli as wire_cli
from tools.endpoint.engine.assets import (
    AssetHardware,
    AssetSSHInfo,
    EndpointAsset,
    EndpointLease,
    acquire_endpoint_asset_lease_by_profile,
    read_endpoint_asset,
    release_endpoint_asset_lease,
    write_endpoint_asset,
)


class EndpointAssetLeaseTest(unittest.TestCase):
    def test_acquire_selects_first_available_profile_asset(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            stdout = io.StringIO()
            lease_uuid = uuid.UUID("00000000-0000-0000-0000-000000000033")

            with _endpoint_env(root):
                write_endpoint_asset(_asset(root, "qemu-reusable-b", host="192.0.2.11"))
                write_endpoint_asset(_asset(root, "qemu-reusable-a", host="192.0.2.10"))

            with (
                _endpoint_env(root),
                mock.patch("tools.endpoint.engine.assets.uuid.uuid4", return_value=lease_uuid),
                contextlib.redirect_stdout(stdout),
            ):
                exit_code = wire_cli.main(
                    [
                        "asset",
                        "acquire",
                        "--profile",
                        "lan-raw",
                        "--lease-ttl",
                        "15m",
                        "--json",
                    ]
                )
            output = json.loads(stdout.getvalue())

            self.assertEqual(exit_code, 0)
            self.assertEqual(output["kind"], "endpoint-asset-acquire")
            self.assertTrue(output["ok"])
            self.assertEqual(output["asset_id"], "qemu-reusable-a")
            self.assertEqual(output["profile"], "lan-raw")
            self.assertEqual(output["ttl_seconds"], 900)
            self.assertEqual(output["lease_id"], f"lease-{lease_uuid.hex}")
            self.assertEqual(output["ssh_target"]["host"], "192.0.2.10")

            with _endpoint_env(root):
                loaded = read_endpoint_asset("qemu-reusable-a")
            self.assertEqual(loaded.lease.holder, f"lease-{lease_uuid.hex}")  # type: ignore[union-attr]
            self.assertEqual(
                loaded.lease.metadata["lease_id"],  # type: ignore[union-attr]
                f"lease-{lease_uuid.hex}",
            )
            self.assertEqual(loaded.lease.metadata["profile"], "lan-raw")  # type: ignore[union-attr]

    def test_busy_assets_reject_acquire_without_overwriting_lease(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            stdout = io.StringIO()
            with _endpoint_env(root):
                write_endpoint_asset(
                    _asset(
                        root,
                        "qemu-reusable-a",
                        lease=EndpointLease(
                            holder="lease-existing",
                            leased_at="2026-06-28T12:00:00Z",
                            leased_until="2999-01-01T00:00:00Z",
                            ttl_seconds=3600,
                            metadata={"lease_id": "lease-existing", "profile": "lan-raw"},
                        ),
                    )
                )

            with _endpoint_env(root), contextlib.redirect_stdout(stdout):
                exit_code = wire_cli.main(
                    [
                        "asset",
                        "acquire",
                        "--profile",
                        "lan-raw",
                        "--lease-ttl",
                        "30s",
                        "--json",
                    ]
                )
            output = json.loads(stdout.getvalue())

            self.assertNotEqual(exit_code, 0)
            self.assertFalse(output["ok"])
            self.assertIn("already leased", output["error"])
            with _endpoint_env(root):
                loaded = read_endpoint_asset("qemu-reusable-a")
            self.assertEqual(loaded.lease.holder, "lease-existing")  # type: ignore[union-attr]

    def test_expired_lease_is_recovered_by_profile_acquire(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with _endpoint_env(root):
                write_endpoint_asset(
                    _asset(
                        root,
                        "qemu-reusable-a",
                        lease=EndpointLease(
                            holder="lease-expired",
                            leased_at="2026-06-28T11:00:00Z",
                            leased_until="2026-06-28T12:00:00Z",
                            ttl_seconds=3600,
                            metadata={"lease_id": "lease-expired", "profile": "lan-raw"},
                        ),
                    )
                )
                output = acquire_endpoint_asset_lease_by_profile(
                    "lan-raw",
                    120,
                    owner="lease-test",
                    now="2026-06-28T12:01:00Z",
                    lease_id_factory=lambda: "lease-recovered",
                )
                loaded = read_endpoint_asset("qemu-reusable-a")

            self.assertTrue(output["ok"])
            self.assertEqual(output["lease_id"], "lease-recovered")
            self.assertEqual(output["expires_at"], "2026-06-28T12:03:00Z")
            self.assertEqual(loaded.lease.holder, "lease-recovered")  # type: ignore[union-attr]
            self.assertEqual(loaded.lease.metadata["owner"], "lease-test")  # type: ignore[union-attr]

    def test_release_by_lease_id_clears_asset_lease(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            stdout = io.StringIO()
            with _endpoint_env(root):
                write_endpoint_asset(
                    _asset(
                        root,
                        "qemu-reusable-a",
                        lease=EndpointLease(
                            holder="generated-holder",
                            leased_at="2026-06-28T12:00:00Z",
                            leased_until="2999-01-01T00:00:00Z",
                            ttl_seconds=3600,
                            metadata={"lease_id": "lease-release-a", "profile": "lan-raw"},
                        ),
                    )
                )

            with _endpoint_env(root), contextlib.redirect_stdout(stdout):
                exit_code = wire_cli.main(
                    ["asset", "release", "lease-release-a", "--json"]
                )
            output = json.loads(stdout.getvalue())

            self.assertEqual(exit_code, 0)
            self.assertEqual(output["kind"], "endpoint-asset-release")
            self.assertTrue(output["ok"])
            self.assertTrue(output["released"])
            self.assertEqual(output["asset_id"], "qemu-reusable-a")
            self.assertEqual(output["profile"], "lan-raw")
            with _endpoint_env(root):
                self.assertIsNone(read_endpoint_asset("qemu-reusable-a").lease)

    def test_unknown_lease_returns_json_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            stdout = io.StringIO()
            with _endpoint_env(root):
                write_endpoint_asset(_asset(root, "qemu-reusable-a"))

            with _endpoint_env(root), contextlib.redirect_stdout(stdout):
                exit_code = wire_cli.main(["asset", "release", "lease-missing", "--json"])
            output = json.loads(stdout.getvalue())

            self.assertNotEqual(exit_code, 0)
            self.assertFalse(output["ok"])
            self.assertEqual(output["kind"], "endpoint-asset-error")
            self.assertIn("unknown endpoint asset lease", output["error"])

    def test_acquire_json_output_shape_includes_target_and_artifact_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with _endpoint_env(root):
                write_endpoint_asset(
                    _asset(
                        root,
                        "qemu-reusable-a",
                        metadata={
                            "appliance": {
                                "remote_work_root": "/srv/libcrafter/work",
                                "remote_artifact_root": "/srv/libcrafter/artifacts",
                            }
                        },
                    )
                )
                output = acquire_endpoint_asset_lease_by_profile(
                    "lan-raw",
                    3600,
                    now="2026-06-28T12:00:00Z",
                    lease_id_factory=lambda: "lease-shape",
                )

            self.assertEqual(
                set(
                    [
                        "kind",
                        "ok",
                        "lease_id",
                        "asset_id",
                        "profile",
                        "expires_at",
                        "ttl_seconds",
                        "ssh_target",
                        "target",
                        "remote_artifact_root",
                        "artifact_root",
                    ]
                )
                - set(output),
                set(),
            )
            self.assertEqual(output["target"], output["ssh_target"])
            self.assertEqual(output["remote_artifact_root"], "/srv/libcrafter/artifacts")
            self.assertEqual(
                output["artifact_root"],
                str(root / "wire-artifacts" / "assets" / "qemu-reusable-a" / "lease-shape"),
            )

            with _endpoint_env(root):
                released = release_endpoint_asset_lease(
                    "lease-shape",
                    now="2026-06-28T12:10:00Z",
                )
            self.assertTrue(released["released"])


def _asset(
    root: Path,
    asset_id: str,
    *,
    host: str = "192.0.2.10",
    lease: EndpointLease | None = None,
    metadata: dict[str, object] | None = None,
) -> EndpointAsset:
    return EndpointAsset(
        asset_id=asset_id,
        substrate="qemu",
        status="available",
        supported_profiles=["lan-raw", "packet-capture"],
        ssh=AssetSSHInfo(
            host=host,
            user="root",
            port=2222,
            identity_file=str(root / "wire-state" / "assets" / asset_id / "id_ed25519"),
            known_hosts_file=str(root / "wire-state" / "assets" / asset_id / "known_hosts"),
        ),
        docker={"command": "docker"},
        hardware=AssetHardware(cpu_count=2, memory_mb=4096),
        lease=lease,
        metadata={} if metadata is None else metadata,
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
