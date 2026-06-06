"""Guest image and cloud-init helpers for local VM-backed providers."""

from __future__ import annotations

import json
import os
import shutil
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
import re
from urllib.parse import urlsplit

from ...config import absolute_path
from ...model import ArtifactPath, ProviderResource
from ...process import run_command
from ...ssh import CommandRunner
from ...state import EndpointLayout
from .helpers import command_error, ensure_endpoint_ssh_key, file_resource, short_provider_resource_name


UBUNTU_CLOUD_IMAGE_URL_ENV = "LIBCRAFTER_ENDPOINT_UBUNTU_CLOUD_IMAGE_URL"
DEFAULT_UBUNTU_CLOUD_IMAGE_URL = (
    "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
)
VM_DISK_SIZE_ENV = "LIBCRAFTER_ENDPOINT_VM_DISK_SIZE"
DEFAULT_VM_DISK_SIZE = "16G"
DEFAULT_PACKET_TOOL_PACKAGES = (
    "openssh-server",
    "ca-certificates",
    "iproute2",
    "iputils-ping",
    "tcpdump",
    "ethtool",
    "net-tools",
    "libpcap0.8",
)
QEMU_IMG_COMMAND = "qemu-img"
CLOUD_LOCALDS_COMMAND = "cloud-localds"
DownloadRunner = Callable[[str, Path], None]

_SUPPORTED_DISK_FORMATS = frozenset({"qcow2", "vdi"})


@dataclass(frozen=True, slots=True)
class VMGuestArtifacts:
    """Absolute local paths needed to boot one VM endpoint guest."""

    endpoint_id: str
    provider: str
    disk_format: str
    disk_size: str
    cloud_image_url: str
    base_image_path: Path
    disk_path: Path
    seed_iso_path: Path
    user_data_path: Path
    meta_data_path: Path
    network_config_path: Path | None = None
    packages: tuple[str, ...] = DEFAULT_PACKET_TOOL_PACKAGES

    def __post_init__(self) -> None:
        _non_empty_string(self.endpoint_id, "endpoint_id")
        _non_empty_string(self.provider, "provider")
        _non_empty_string(self.cloud_image_url, "cloud_image_url")
        object.__setattr__(self, "disk_size", vm_disk_size(size=self.disk_size))
        if self.disk_format not in _SUPPORTED_DISK_FORMATS:
            raise ValueError(f"unsupported disk format: {self.disk_format!r}")
        object.__setattr__(self, "base_image_path", absolute_path(self.base_image_path))
        object.__setattr__(self, "disk_path", absolute_path(self.disk_path))
        object.__setattr__(self, "seed_iso_path", absolute_path(self.seed_iso_path))
        object.__setattr__(self, "user_data_path", absolute_path(self.user_data_path))
        object.__setattr__(self, "meta_data_path", absolute_path(self.meta_data_path))
        if self.network_config_path is not None:
            object.__setattr__(
                self,
                "network_config_path",
                absolute_path(self.network_config_path),
            )
        object.__setattr__(self, "packages", _package_tuple(self.packages))

    def artifact_paths(self) -> list[ArtifactPath]:
        """Return manifest-ready absolute artifact path records."""

        paths = [
            ArtifactPath(
                name="base-cloud-image",
                path=str(self.base_image_path),
                metadata={"shared_cache": False, "url": self.cloud_image_url},
            ),
            ArtifactPath(
                name="guest-disk",
                path=str(self.disk_path),
                metadata={"disk_format": self.disk_format},
            ),
            ArtifactPath(name="seed-iso", path=str(self.seed_iso_path)),
            ArtifactPath(name="user-data", path=str(self.user_data_path)),
            ArtifactPath(name="meta-data", path=str(self.meta_data_path)),
        ]
        if self.network_config_path is not None:
            paths.append(ArtifactPath(name="network-config", path=str(self.network_config_path)))
        return paths

    def file_resources(self, *, include_cache: bool = False) -> list[ProviderResource]:
        """Return provider resources for endpoint-owned local files."""

        resources = [
            file_resource(
                self.disk_path,
                name="guest-disk",
                metadata={"role": "guest-disk", "disk_format": self.disk_format},
            ),
            file_resource(
                self.seed_iso_path,
                name="seed-iso",
                metadata={"role": "seed-iso"},
            ),
            file_resource(
                self.user_data_path.parent,
                name="cloud-init-seed-dir",
                metadata={"role": "cloud-init-seed-dir"},
            ),
        ]
        if include_cache:
            resources.append(
                file_resource(
                    self.base_image_path,
                    name="base-cloud-image",
                    cleanup=False,
                    metadata={"role": "base-cloud-image", "url": self.cloud_image_url},
                )
            )
        return resources

    def to_manifest_metadata(self) -> dict[str, object]:
        """Return JSON-compatible metadata for endpoint manifests."""

        return {
            "vm_guest_artifacts": {
                "cloud_image_url": self.cloud_image_url,
                "disk_format": self.disk_format,
                "disk_size": self.disk_size,
                "base_image_path": str(self.base_image_path),
                "disk_path": str(self.disk_path),
                "seed_iso_path": str(self.seed_iso_path),
                "user_data_path": str(self.user_data_path),
                "meta_data_path": str(self.meta_data_path),
                "network_config_path": (
                    None if self.network_config_path is None else str(self.network_config_path)
                ),
                "packages": list(self.packages),
            }
        }


def ubuntu_cloud_image_url(
    *,
    image_url: str | None = None,
    env: Mapping[str, str] | None = None,
) -> str:
    """Return the Ubuntu 24.04 cloud image URL with an environment override."""

    if image_url is not None:
        return _non_empty_string(image_url, "image_url")
    source = os.environ if env is None else env
    return source.get(UBUNTU_CLOUD_IMAGE_URL_ENV) or DEFAULT_UBUNTU_CLOUD_IMAGE_URL


def vm_disk_size(
    *,
    size: str | None = None,
    env: Mapping[str, str] | None = None,
) -> str:
    """Return the requested guest disk virtual size."""

    source = os.environ if env is None else env
    raw_value = size if size is not None else source.get(VM_DISK_SIZE_ENV)
    value = (raw_value or DEFAULT_VM_DISK_SIZE).strip()
    if not _DISK_SIZE_RE.fullmatch(value):
        raise ValueError(
            f"{VM_DISK_SIZE_ENV}={value!r} must be an integer size with optional K/M/G/T suffix"
        )
    return value


def vm_disk_size_mib(size: str) -> int:
    """Return a VM disk size string as whole MiB for VirtualBox."""

    normalized = vm_disk_size(size=size)
    match = _DISK_SIZE_RE.fullmatch(normalized)
    if match is None:
        raise ValueError(f"invalid VM disk size: {size!r}")
    amount = int(match.group("amount"), 10)
    suffix = (match.group("suffix") or "M").upper()
    multipliers = {
        "K": 1 / 1024,
        "M": 1,
        "G": 1024,
        "T": 1024 * 1024,
    }
    mib = amount * multipliers[suffix]
    if mib != int(mib) or int(mib) <= 0:
        raise ValueError(f"{VM_DISK_SIZE_ENV}={size!r} must resolve to whole MiB")
    return int(mib)


def plan_guest_artifacts(
    *,
    endpoint_id: str,
    provider: str,
    layout: EndpointLayout,
    disk_format: str,
    image_url: str | None = None,
    env: Mapping[str, str] | None = None,
    image_cache_dir: str | Path | None = None,
    include_network_config: bool = False,
    packages: Sequence[str] = DEFAULT_PACKET_TOOL_PACKAGES,
) -> VMGuestArtifacts:
    """Plan endpoint-local cloud image, disk, and NoCloud seed paths."""

    _non_empty_string(endpoint_id, "endpoint_id")
    _non_empty_string(provider, "provider")
    if not isinstance(layout, EndpointLayout):
        raise TypeError("layout must be an EndpointLayout")
    if disk_format not in _SUPPORTED_DISK_FORMATS:
        raise ValueError(f"unsupported disk format: {disk_format!r}")

    image_source = ubuntu_cloud_image_url(image_url=image_url, env=env)
    disk_size = vm_disk_size(env=env)
    cache_dir = (
        absolute_path(image_cache_dir)
        if image_cache_dir is not None
        else layout.state_dir / "image-cache"
    )
    vm_dir = layout.state_dir / "vm"
    seed_dir = vm_dir / "seed"
    network_config_path = seed_dir / "network-config" if include_network_config else None

    return VMGuestArtifacts(
        endpoint_id=endpoint_id,
        provider=provider,
        disk_format=disk_format,
        disk_size=disk_size,
        cloud_image_url=image_source,
        base_image_path=cache_dir / _cloud_image_filename(image_source),
        disk_path=vm_dir / f"disk.{disk_format}",
        seed_iso_path=vm_dir / "seed.iso",
        user_data_path=seed_dir / "user-data",
        meta_data_path=seed_dir / "meta-data",
        network_config_path=network_config_path,
        packages=tuple(packages),
    )


def download_url(url: str, output_path: Path) -> None:
    """Download a URL to a path using only Python's standard library."""

    target = absolute_path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f"{target.name}.tmp")
    with urllib.request.urlopen(url, timeout=600) as response:
        with temporary.open("wb") as handle:
            shutil.copyfileobj(response, handle)
    temporary.replace(target)


def download_cloud_image(
    artifacts: VMGuestArtifacts,
    *,
    download_runner: DownloadRunner = download_url,
) -> bool:
    """Ensure the cached base cloud image exists and return whether it was downloaded."""

    _require_artifacts(artifacts)
    if artifacts.base_image_path.is_file() and artifacts.base_image_path.stat().st_size > 0:
        return False
    artifacts.base_image_path.parent.mkdir(parents=True, exist_ok=True)
    download_runner(artifacts.cloud_image_url, artifacts.base_image_path)
    if not artifacts.base_image_path.is_file() or artifacts.base_image_path.stat().st_size <= 0:
        raise RuntimeError(f"cloud image download did not create {artifacts.base_image_path}")
    return True


def write_nocloud_seed_files(
    artifacts: VMGuestArtifacts,
    *,
    public_key: str,
    network_config: str | Mapping[str, object] | None = None,
    packages: Sequence[str] | None = None,
) -> None:
    """Write NoCloud user-data, meta-data, and optional network-config files."""

    _require_artifacts(artifacts)
    ssh_public_key = _non_empty_string(public_key.strip(), "public_key")
    package_names = artifacts.packages if packages is None else _package_tuple(packages)

    artifacts.user_data_path.parent.mkdir(parents=True, exist_ok=True)
    artifacts.user_data_path.write_text(
        "#cloud-config\n" + _to_cloud_yaml(_user_data(ssh_public_key, package_names)),
        encoding="utf-8",
    )
    artifacts.meta_data_path.write_text(
        _to_cloud_yaml(
            {
                "instance-id": artifacts.endpoint_id,
                "local-hostname": short_provider_resource_name(
                    "wire",
                    artifacts.provider,
                    artifacts.endpoint_id,
                    max_length=63,
                ),
            }
        ),
        encoding="utf-8",
    )
    if network_config is not None:
        if artifacts.network_config_path is None:
            raise ValueError("network_config_path is required when network_config is supplied")
        artifacts.network_config_path.write_text(
            _network_config_text(network_config),
            encoding="utf-8",
        )


def build_nocloud_seed_iso(
    artifacts: VMGuestArtifacts,
    *,
    runner: CommandRunner = run_command,
    timeout: float | None = 120,
) -> Path:
    """Build a NoCloud seed ISO with cloud-localds."""

    _require_artifacts(artifacts)
    artifacts.seed_iso_path.parent.mkdir(parents=True, exist_ok=True)
    argv = [CLOUD_LOCALDS_COMMAND]
    if artifacts.network_config_path is not None and artifacts.network_config_path.exists():
        argv.append(f"--network-config={artifacts.network_config_path}")
    argv.extend(
        [
            str(artifacts.seed_iso_path),
            str(artifacts.user_data_path),
            str(artifacts.meta_data_path),
        ]
    )
    result = runner(argv, timeout=timeout)
    if not result.ok:
        raise RuntimeError(command_error("cloud-localds failed", result))
    return artifacts.seed_iso_path


def build_virtualbox_vdi(
    artifacts: VMGuestArtifacts,
    *,
    runner: CommandRunner = run_command,
    timeout: float | None = 300,
) -> Path:
    """Convert the cached Ubuntu qcow2 image into a VirtualBox VDI disk."""

    _require_artifacts(artifacts)
    if artifacts.disk_format != "vdi":
        raise ValueError("VirtualBox disk artifacts must use disk_format='vdi'")
    artifacts.disk_path.parent.mkdir(parents=True, exist_ok=True)
    result = runner(
        [
            QEMU_IMG_COMMAND,
            "convert",
            "-f",
            "qcow2",
            "-O",
            "vdi",
            str(artifacts.base_image_path),
            str(artifacts.disk_path),
        ],
        timeout=timeout,
    )
    if not result.ok:
        raise RuntimeError(command_error("qemu-img convert failed", result))
    return artifacts.disk_path


def build_qemu_overlay(
    artifacts: VMGuestArtifacts,
    *,
    runner: CommandRunner = run_command,
    timeout: float | None = 120,
) -> Path:
    """Create a QEMU qcow2 overlay backed by the cached Ubuntu cloud image."""

    _require_artifacts(artifacts)
    if artifacts.disk_format != "qcow2":
        raise ValueError("QEMU disk artifacts must use disk_format='qcow2'")
    artifacts.disk_path.parent.mkdir(parents=True, exist_ok=True)
    result = runner(
        [
            QEMU_IMG_COMMAND,
            "create",
            "-f",
            "qcow2",
            "-F",
            "qcow2",
            "-b",
            str(artifacts.base_image_path),
            str(artifacts.disk_path),
            artifacts.disk_size,
        ],
        timeout=timeout,
    )
    if not result.ok:
        raise RuntimeError(command_error("qemu-img create failed", result))
    return artifacts.disk_path


def build_guest_disk(
    artifacts: VMGuestArtifacts,
    *,
    runner: CommandRunner = run_command,
    timeout: float | None = None,
) -> Path:
    """Build the provider-specific guest disk for the planned artifacts."""

    if artifacts.disk_format == "vdi":
        return build_virtualbox_vdi(artifacts, runner=runner, timeout=timeout or 300)
    if artifacts.disk_format == "qcow2":
        return build_qemu_overlay(artifacts, runner=runner, timeout=timeout or 120)
    raise ValueError(f"unsupported disk format: {artifacts.disk_format!r}")


def build_endpoint_guest_artifacts(
    artifacts: VMGuestArtifacts,
    *,
    private_key_path: str | Path,
    runner: CommandRunner = run_command,
    download_runner: DownloadRunner = download_url,
    network_config: str | Mapping[str, object] | None = None,
    force_key: bool = False,
) -> tuple[Path, Path]:
    """Build all endpoint guest artifacts and return private/public key paths."""

    _require_artifacts(artifacts)
    key_path, public_path = ensure_endpoint_ssh_key(
        private_key_path,
        artifacts.endpoint_id,
        runner=runner,
        force=force_key,
    )
    public_key = public_path.read_text(encoding="utf-8").strip()
    download_cloud_image(artifacts, download_runner=download_runner)
    write_nocloud_seed_files(artifacts, public_key=public_key, network_config=network_config)
    build_nocloud_seed_iso(artifacts, runner=runner)
    build_guest_disk(artifacts, runner=runner)
    return key_path, public_path


def _cloud_image_filename(image_url: str) -> str:
    path = urlsplit(image_url).path
    name = Path(path).name
    return name or "noble-server-cloudimg-amd64.img"


_DISK_SIZE_RE = re.compile(r"(?P<amount>[1-9][0-9]*)(?P<suffix>[KMGTkmgt]?)")


def _user_data(public_key: str, packages: Sequence[str]) -> dict[str, object]:
    return {
        "disable_root": False,
        "ssh_pwauth": False,
        "package_update": True,
        "packages": list(packages),
        "users": [
            "default",
            {
                "name": "root",
                "lock_passwd": True,
                "shell": "/bin/bash",
                "ssh_authorized_keys": [public_key],
            },
        ],
        "write_files": [
            {
                "path": "/etc/ssh/sshd_config.d/99-libcrafter-root-login.conf",
                "permissions": "0644",
                "content": "PermitRootLogin prohibit-password\n",
            }
        ],
        "runcmd": [["systemctl", "enable", "--now", "ssh"]],
    }


def _network_config_text(value: str | Mapping[str, object]) -> str:
    if isinstance(value, str):
        if value == "":
            raise ValueError("network_config must not be empty")
        return value if value.endswith("\n") else f"{value}\n"
    if not isinstance(value, Mapping):
        raise TypeError("network_config must be a string or mapping")
    return _to_cloud_yaml(value)


def _to_cloud_yaml(value: object) -> str:
    return "\n".join(_cloud_yaml_lines(value, 0)) + "\n"


def _cloud_yaml_lines(value: object, indent: int) -> list[str]:
    prefix = " " * indent
    if isinstance(value, Mapping):
        lines: list[str] = []
        for key, item in value.items():
            if not isinstance(key, str) or key == "":
                raise ValueError("cloud-init mappings must use non-empty string keys")
            if _is_yaml_scalar(item):
                lines.append(f"{prefix}{key}: {_yaml_scalar(item)}")
            else:
                lines.append(f"{prefix}{key}:")
                lines.extend(_cloud_yaml_lines(item, indent + 2))
        return lines
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        lines = []
        for item in value:
            if _is_yaml_scalar(item):
                lines.append(f"{prefix}- {_yaml_scalar(item)}")
                continue
            nested = _cloud_yaml_lines(item, indent + 2)
            if nested:
                lines.append(f"{prefix}- {nested[0].lstrip()}")
                lines.extend(nested[1:])
            else:
                lines.append(f"{prefix}- null")
        return lines
    return [f"{prefix}{_yaml_scalar(value)}"]


def _is_yaml_scalar(value: object) -> bool:
    return value is None or isinstance(value, (str, bool, int, float))


def _yaml_scalar(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value)
    raise TypeError(f"unsupported cloud-init value: {type(value).__name__}")


def _package_tuple(packages: Sequence[str]) -> tuple[str, ...]:
    if not isinstance(packages, Sequence) or isinstance(packages, (str, bytes, bytearray)):
        raise ValueError("packages must be a sequence of strings")
    output: list[str] = []
    for package in packages:
        if not isinstance(package, str) or package == "":
            raise ValueError("packages must contain non-empty strings")
        if package not in output:
            output.append(package)
    return tuple(output)


def _require_artifacts(artifacts: VMGuestArtifacts) -> None:
    if not isinstance(artifacts, VMGuestArtifacts):
        raise TypeError("artifacts must be VMGuestArtifacts")


def _non_empty_string(value: str, name: str) -> str:
    if not isinstance(value, str) or value == "":
        raise ValueError(f"{name} must be a non-empty string")
    return value
