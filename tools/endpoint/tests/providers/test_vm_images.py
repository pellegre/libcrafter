"""Unit coverage for local VM guest image helpers."""

from __future__ import annotations

import tempfile
import unittest
from collections.abc import Sequence
from pathlib import Path

from tools.endpoint.engine.config import WireConfig
from tools.endpoint.engine.process import CommandResult
from tools.endpoint.engine.providers.vm import (
    CLOUD_LOCALDS_COMMAND,
    DEFAULT_VM_DISK_SIZE,
    QEMU_IMG_COMMAND,
    UBUNTU_CLOUD_IMAGE_URL_ENV,
    VM_DISK_SIZE_ENV,
    build_endpoint_guest_artifacts,
    build_guest_disk,
    build_nocloud_seed_iso,
    download_cloud_image,
    plan_guest_artifacts,
    write_nocloud_seed_files,
)
from tools.endpoint.engine.state import ensure_endpoint_dirs


class VMImagePlanTest(unittest.TestCase):
    def test_plan_guest_artifacts_uses_absolute_state_paths_and_url_override(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = WireConfig(
                state_root=root / "state",
                artifact_root=root / "artifacts",
            )
            layout = ensure_endpoint_dirs("endpoint-a", config)

            artifacts = plan_guest_artifacts(
                endpoint_id="endpoint-a",
                provider="virtualbox",
                layout=layout,
                disk_format="vdi",
                env={UBUNTU_CLOUD_IMAGE_URL_ENV: "https://example.invalid/custom.img"},
                include_network_config=True,
            )

            self.assertEqual(artifacts.cloud_image_url, "https://example.invalid/custom.img")
            self.assertEqual(artifacts.disk_path.name, "disk.vdi")
            self.assertEqual(artifacts.base_image_path.name, "custom.img")
            self.assertIsNotNone(artifacts.network_config_path)
            for path in (
                artifacts.base_image_path,
                artifacts.disk_path,
                artifacts.seed_iso_path,
                artifacts.user_data_path,
                artifacts.meta_data_path,
                artifacts.network_config_path,
            ):
                self.assertIsNotNone(path)
                self.assertTrue(Path(path).is_absolute())
                self.assertIn(layout.state_dir, Path(path).parents)

            metadata = artifacts.to_manifest_metadata()["vm_guest_artifacts"]
            self.assertEqual(metadata["disk_format"], "vdi")
            self.assertEqual(metadata["disk_size"], DEFAULT_VM_DISK_SIZE)
            self.assertTrue(Path(str(metadata["disk_path"])).is_absolute())
            self.assertIn("openssh-server", metadata["packages"])
            self.assertEqual(
                [path.name for path in artifacts.artifact_paths()],
                [
                    "base-cloud-image",
                    "guest-disk",
                    "seed-iso",
                    "user-data",
                    "meta-data",
                    "network-config",
                ],
            )

    def test_plan_guest_artifacts_rejects_unsupported_disk_format(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = WireConfig(
                state_root=Path(temp_dir) / "state",
                artifact_root=Path(temp_dir) / "artifacts",
            )
            layout = ensure_endpoint_dirs("endpoint-a", config)

            with self.assertRaisesRegex(ValueError, "unsupported disk format"):
                plan_guest_artifacts(
                    endpoint_id="endpoint-a",
                    provider="qemu",
                    layout=layout,
                    disk_format="raw",
                )

    def test_plan_guest_artifacts_accepts_disk_size_override(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = WireConfig(
                state_root=Path(temp_dir) / "state",
                artifact_root=Path(temp_dir) / "artifacts",
            )
            layout = ensure_endpoint_dirs("endpoint-a", config)

            artifacts = plan_guest_artifacts(
                endpoint_id="endpoint-a",
                provider="qemu",
                layout=layout,
                disk_format="qcow2",
                env={VM_DISK_SIZE_ENV: "24G"},
            )

            self.assertEqual(artifacts.disk_size, "24G")
            self.assertEqual(
                artifacts.to_manifest_metadata()["vm_guest_artifacts"]["disk_size"],
                "24G",
            )


class VMImageBuildTest(unittest.TestCase):
    def test_build_virtualbox_artifacts_uses_injected_runners(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = WireConfig(
                state_root=Path(temp_dir) / "state",
                artifact_root=Path(temp_dir) / "artifacts",
            )
            layout = ensure_endpoint_dirs("endpoint-a", config)
            artifacts = plan_guest_artifacts(
                endpoint_id="endpoint-a",
                provider="virtualbox",
                layout=layout,
                disk_format="vdi",
                include_network_config=True,
            )
            calls: list[tuple[str, ...]] = []
            downloads: list[tuple[str, Path]] = []

            def fake_download(url: str, output_path: Path) -> None:
                downloads.append((url, output_path))
                output_path.write_text("qcow2-base\n", encoding="utf-8")

            def fake_runner(argv: Sequence[object], **_: object) -> CommandResult:
                parts = tuple(str(part) for part in argv)
                calls.append(parts)
                if parts[0] == "ssh-keygen":
                    key_path = Path(parts[parts.index("-f") + 1])
                    key_path.write_text("private\n", encoding="utf-8")
                    key_path.with_name(f"{key_path.name}.pub").write_text(
                        "ssh-ed25519 AAAAendpoint\n",
                        encoding="utf-8",
                    )
                elif parts[0] == CLOUD_LOCALDS_COMMAND:
                    Path(parts[-3]).write_text("seed\n", encoding="utf-8")
                elif parts[:2] == (QEMU_IMG_COMMAND, "convert"):
                    Path(parts[-1]).write_text("vdi\n", encoding="utf-8")
                else:
                    self.fail(f"unexpected command: {parts}")
                return _result(parts)

            key_path, public_path = build_endpoint_guest_artifacts(
                artifacts,
                private_key_path=layout.private_key_path,
                runner=fake_runner,
                download_runner=fake_download,
                network_config={"version": 2, "ethernets": {"enp0s8": {"dhcp4": True}}},
            )

            self.assertEqual(key_path, layout.private_key_path)
            self.assertEqual(public_path, layout.private_key_path.with_name("id_ed25519.pub"))
            self.assertEqual(len(downloads), 1)
            self.assertEqual(downloads[0][1], artifacts.base_image_path)
            self.assertTrue(artifacts.seed_iso_path.exists())
            self.assertTrue(artifacts.disk_path.exists())

            user_data = artifacts.user_data_path.read_text(encoding="utf-8")
            network_config = artifacts.network_config_path.read_text(encoding="utf-8")
            self.assertIn("#cloud-config", user_data)
            self.assertIn("ssh-ed25519 AAAAendpoint", user_data)
            self.assertIn("openssh-server", user_data)
            self.assertIn("PermitRootLogin prohibit-password", user_data)
            self.assertIn("ethernets", network_config)
            self.assertIn("dhcp4: true", network_config)

            self.assertEqual(calls[0][0], "ssh-keygen")
            self.assertIn(f"--network-config={artifacts.network_config_path}", calls[1])
            self.assertEqual(calls[2][:2], (QEMU_IMG_COMMAND, "convert"))
            self.assertEqual(calls[2][-2:], (str(artifacts.base_image_path), str(artifacts.disk_path)))

    def test_qemu_overlay_uses_cached_base_image_without_download(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = WireConfig(
                state_root=Path(temp_dir) / "state",
                artifact_root=Path(temp_dir) / "artifacts",
            )
            layout = ensure_endpoint_dirs("endpoint-a", config)
            artifacts = plan_guest_artifacts(
                endpoint_id="endpoint-a",
                provider="qemu",
                layout=layout,
                disk_format="qcow2",
            )
            artifacts.base_image_path.parent.mkdir(parents=True, exist_ok=True)
            artifacts.base_image_path.write_text("base\n", encoding="utf-8")
            calls: list[tuple[str, ...]] = []

            def fake_download(_: str, __: Path) -> None:
                self.fail("cached image should not be downloaded")

            def fake_runner(argv: Sequence[object], **_: object) -> CommandResult:
                parts = tuple(str(part) for part in argv)
                calls.append(parts)
                return _result(parts)

            self.assertFalse(download_cloud_image(artifacts, download_runner=fake_download))
            build_guest_disk(artifacts, runner=fake_runner)

            self.assertEqual(
                calls,
                [
                    (
                        QEMU_IMG_COMMAND,
                        "create",
                        "-f",
                        "qcow2",
                        "-F",
                        "qcow2",
                        "-b",
                        str(artifacts.base_image_path),
                        str(artifacts.disk_path),
                        DEFAULT_VM_DISK_SIZE,
                    )
                ],
            )

    def test_cloud_localds_failure_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = WireConfig(
                state_root=Path(temp_dir) / "state",
                artifact_root=Path(temp_dir) / "artifacts",
            )
            layout = ensure_endpoint_dirs("endpoint-a", config)
            artifacts = plan_guest_artifacts(
                endpoint_id="endpoint-a",
                provider="qemu",
                layout=layout,
                disk_format="qcow2",
            )
            write_nocloud_seed_files(artifacts, public_key="ssh-ed25519 AAAAendpoint")

            def fake_runner(argv: Sequence[object], **_: object) -> CommandResult:
                return _result(tuple(str(part) for part in argv), exit_code=1, stderr="boom")

            with self.assertRaisesRegex(RuntimeError, "cloud-localds failed"):
                build_nocloud_seed_iso(artifacts, runner=fake_runner)

    def test_network_config_requires_planned_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = WireConfig(
                state_root=Path(temp_dir) / "state",
                artifact_root=Path(temp_dir) / "artifacts",
            )
            layout = ensure_endpoint_dirs("endpoint-a", config)
            artifacts = plan_guest_artifacts(
                endpoint_id="endpoint-a",
                provider="qemu",
                layout=layout,
                disk_format="qcow2",
            )

            with self.assertRaisesRegex(ValueError, "network_config_path"):
                write_nocloud_seed_files(
                    artifacts,
                    public_key="ssh-ed25519 AAAAendpoint",
                    network_config="version: 2",
                )


def _result(
    argv: Sequence[str],
    *,
    exit_code: int = 0,
    stderr: str = "",
) -> CommandResult:
    return CommandResult(
        argv=tuple(argv),
        redacted_argv=tuple(argv),
        cwd=None,
        exit_code=exit_code,
        stdout="",
        stderr=stderr,
    )


if __name__ == "__main__":
    unittest.main()
