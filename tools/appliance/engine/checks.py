"""Deterministic readiness check plan rendering for appliance profiles."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from tools.appliance.engine.image import DOCKER_COMMAND
from tools.appliance.engine.model import JSONObject, JsonModel, json_object, require_non_empty_string
from tools.appliance.engine.profile import ApplianceProfile, ProfileCheck


PYTHON_COMMAND = "python3"

CHECK_KIND_DOCKER_DAEMON = "docker-daemon"
CHECK_KIND_IMAGE_AVAILABLE = "image-available"
CHECK_KIND_INTERFACE_EXISTS = "interface-exists"
CHECK_KIND_RAW_SOCKET_PERMISSION = "raw-socket-permission"
CHECK_KIND_PCAP_OPEN = "pcap-open"
CHECK_KIND_SERIAL_DEVICE_EXISTS = "serial-device-exists"
CHECK_KIND_WHAD_DISCOVERY = "whad-discovery"
CHECK_KIND_DOT11_MONITOR_INTERFACE = "dot11-monitor-interface"
CHECK_KIND_DOT11_INJECTION_SMOKE = "dot11-injection-smoke"

CHECK_KINDS = (
    CHECK_KIND_DOCKER_DAEMON,
    CHECK_KIND_IMAGE_AVAILABLE,
    CHECK_KIND_INTERFACE_EXISTS,
    CHECK_KIND_RAW_SOCKET_PERMISSION,
    CHECK_KIND_PCAP_OPEN,
    CHECK_KIND_SERIAL_DEVICE_EXISTS,
    CHECK_KIND_WHAD_DISCOVERY,
    CHECK_KIND_DOT11_MONITOR_INTERFACE,
    CHECK_KIND_DOT11_INJECTION_SMOKE,
)

_CHECK_KIND_ALIASES = {
    "docker": CHECK_KIND_DOCKER_DAEMON,
    "docker-info": CHECK_KIND_DOCKER_DAEMON,
    CHECK_KIND_DOCKER_DAEMON: CHECK_KIND_DOCKER_DAEMON,
    "image": CHECK_KIND_IMAGE_AVAILABLE,
    "image-availability": CHECK_KIND_IMAGE_AVAILABLE,
    CHECK_KIND_IMAGE_AVAILABLE: CHECK_KIND_IMAGE_AVAILABLE,
    "interface": CHECK_KIND_INTERFACE_EXISTS,
    "iface": CHECK_KIND_INTERFACE_EXISTS,
    CHECK_KIND_INTERFACE_EXISTS: CHECK_KIND_INTERFACE_EXISTS,
    "raw-socket": CHECK_KIND_RAW_SOCKET_PERMISSION,
    CHECK_KIND_RAW_SOCKET_PERMISSION: CHECK_KIND_RAW_SOCKET_PERMISSION,
    "pcap": CHECK_KIND_PCAP_OPEN,
    CHECK_KIND_PCAP_OPEN: CHECK_KIND_PCAP_OPEN,
    "serial": CHECK_KIND_SERIAL_DEVICE_EXISTS,
    "serial-device": CHECK_KIND_SERIAL_DEVICE_EXISTS,
    CHECK_KIND_SERIAL_DEVICE_EXISTS: CHECK_KIND_SERIAL_DEVICE_EXISTS,
    "whad": CHECK_KIND_WHAD_DISCOVERY,
    CHECK_KIND_WHAD_DISCOVERY: CHECK_KIND_WHAD_DISCOVERY,
    "dot11-monitor": CHECK_KIND_DOT11_MONITOR_INTERFACE,
    CHECK_KIND_DOT11_MONITOR_INTERFACE: CHECK_KIND_DOT11_MONITOR_INTERFACE,
    "dot11-injection": CHECK_KIND_DOT11_INJECTION_SMOKE,
    CHECK_KIND_DOT11_INJECTION_SMOKE: CHECK_KIND_DOT11_INJECTION_SMOKE,
}

_SCRIPT_MODULES = {
    CHECK_KIND_DOCKER_DAEMON: "tools.appliance.checks.docker_daemon",
    CHECK_KIND_IMAGE_AVAILABLE: "tools.appliance.checks.image_available",
    CHECK_KIND_INTERFACE_EXISTS: "tools.appliance.checks.interface_exists",
    CHECK_KIND_RAW_SOCKET_PERMISSION: "tools.appliance.checks.raw_socket_permission",
    CHECK_KIND_PCAP_OPEN: "tools.appliance.checks.pcap_open",
    CHECK_KIND_SERIAL_DEVICE_EXISTS: "tools.appliance.checks.serial_device_exists",
    CHECK_KIND_WHAD_DISCOVERY: "tools.appliance.checks.whad_discovery",
    CHECK_KIND_DOT11_MONITOR_INTERFACE: "tools.appliance.checks.dot11_monitor_interface",
    CHECK_KIND_DOT11_INJECTION_SMOKE: "tools.appliance.checks.dot11_injection_smoke",
}

_DEFAULT_DESCRIPTIONS = {
    CHECK_KIND_DOCKER_DAEMON: "Verify that the target can talk to the Docker daemon.",
    CHECK_KIND_IMAGE_AVAILABLE: "Verify that the appliance image is available on the target.",
    CHECK_KIND_INTERFACE_EXISTS: "Verify that the selected network interface exists.",
    CHECK_KIND_RAW_SOCKET_PERMISSION: "Verify that raw socket creation is permitted.",
    CHECK_KIND_PCAP_OPEN: "Verify that libpcap can open the selected interface.",
    CHECK_KIND_SERIAL_DEVICE_EXISTS: "Verify that the selected serial device exists.",
    CHECK_KIND_WHAD_DISCOVERY: "Verify that WHAD discovery can inspect available adapters.",
    CHECK_KIND_DOT11_MONITOR_INTERFACE: "Verify that the selected interface is in monitor mode.",
    CHECK_KIND_DOT11_INJECTION_SMOKE: "Plan a dry-run dot11 injection smoke check.",
}

_DEFAULT_SCOPES = {
    CHECK_KIND_DOCKER_DAEMON: "host",
    CHECK_KIND_IMAGE_AVAILABLE: "host",
    CHECK_KIND_INTERFACE_EXISTS: "host",
    CHECK_KIND_RAW_SOCKET_PERMISSION: "container",
    CHECK_KIND_PCAP_OPEN: "container",
    CHECK_KIND_SERIAL_DEVICE_EXISTS: "host",
    CHECK_KIND_WHAD_DISCOVERY: "container",
    CHECK_KIND_DOT11_MONITOR_INTERFACE: "host",
    CHECK_KIND_DOT11_INJECTION_SMOKE: "container",
}


class UnknownCheckKindError(ValueError):
    """Raised when a profile declares a readiness check kind we cannot render."""

    def __init__(self, kind: str, known: tuple[str, ...] = CHECK_KINDS) -> None:
        known_text = ", ".join(known)
        super().__init__(f"unknown appliance check kind {kind!r}; known check kinds: {known_text}")
        self.kind = kind
        self.known = known


@dataclass(frozen=True, slots=True)
class CheckPlan(JsonModel):
    """A JSON-serializable readiness check command plan that does not execute."""

    profile: str
    name: str
    kind: str
    description: str
    command_argv: list[str]
    scope: str = "host"
    required: bool = True
    parameters: dict[str, str] = field(default_factory=dict)
    metadata: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "profile", require_non_empty_string(self.profile, "profile"))
        object.__setattr__(self, "name", _check_name(self.name, "name"))
        object.__setattr__(self, "kind", require_non_empty_string(self.kind, "kind"))
        object.__setattr__(self, "description", _string(self.description, "description"))
        object.__setattr__(
            self,
            "command_argv",
            _non_empty_string_list(self.command_argv, "command_argv"),
        )
        object.__setattr__(self, "scope", require_non_empty_string(self.scope, "scope"))
        object.__setattr__(self, "required", _bool(self.required, "required"))
        object.__setattr__(self, "parameters", _string_mapping(self.parameters, "parameters"))
        object.__setattr__(self, "metadata", json_object(self.metadata, "metadata"))


@dataclass(frozen=True, slots=True)
class _CheckSpec:
    name: str
    kind: str
    description: str
    command_argv: list[str]
    scope: str
    required: bool
    parameters: dict[str, str]
    metadata: JSONObject
    explicit_kind: bool = False


def render_profile_check_plans(
    profile: ApplianceProfile | Mapping[str, object],
    checks: Sequence[ProfileCheck | Mapping[str, object]] | None = None,
    *,
    image_tag: str | None = None,
    docker_command: str = DOCKER_COMMAND,
    python_command: str = PYTHON_COMMAND,
    environment: Mapping[str, str] | None = None,
) -> list[CheckPlan]:
    """Return deterministic command plans for the checks declared by ``profile``."""

    appliance_profile, declared_checks = _profile_and_checks(profile)
    if checks is not None:
        declared_checks = checks
    merged_env = dict(appliance_profile.env)
    if environment is not None:
        merged_env.update(_string_mapping(environment, "environment"))

    return [
        render_check_plan(
            appliance_profile,
            check,
            image_tag=image_tag,
            docker_command=docker_command,
            python_command=python_command,
            environment=merged_env,
        )
        for check in declared_checks
    ]


def build_profile_check_plans(*args: object, **kwargs: object) -> list[CheckPlan]:
    """Compatibility wrapper for callers that prefer build-style naming."""

    return render_profile_check_plans(*args, **kwargs)


def profile_check_plans(*args: object, **kwargs: object) -> list[CheckPlan]:
    """Compatibility wrapper for callers that prefer noun-style naming."""

    return render_profile_check_plans(*args, **kwargs)


def render_check_plan(
    profile: ApplianceProfile | Mapping[str, object],
    check: ProfileCheck | Mapping[str, object],
    *,
    image_tag: str | None = None,
    docker_command: str = DOCKER_COMMAND,
    python_command: str = PYTHON_COMMAND,
    environment: Mapping[str, str] | None = None,
) -> CheckPlan:
    """Return one deterministic command plan for one profile readiness check."""

    appliance_profile, _ = _profile_and_checks(profile)
    env = dict(appliance_profile.env)
    if environment is not None:
        env.update(_string_mapping(environment, "environment"))
    spec = _check_spec(check)
    if spec.command_argv:
        return _explicit_command_plan(appliance_profile, spec)

    kind = _canonical_kind(spec.kind or spec.name)
    parameters = dict(spec.parameters)
    command_argv, resolved_parameters, metadata = _render_known_command(
        kind=kind,
        profile=appliance_profile,
        parameters=parameters,
        env=env,
        image_tag=image_tag,
        docker_command=docker_command,
        python_command=python_command,
    )
    parameters.update(resolved_parameters)
    combined_metadata = dict(spec.metadata)
    combined_metadata.update(metadata)
    return CheckPlan(
        profile=appliance_profile.name,
        name=spec.name or kind,
        kind=kind,
        description=spec.description or _DEFAULT_DESCRIPTIONS[kind],
        command_argv=command_argv,
        scope=spec.scope or _DEFAULT_SCOPES[kind],
        required=spec.required,
        parameters=parameters,
        metadata=combined_metadata,
    )


def _explicit_command_plan(profile: ApplianceProfile, spec: _CheckSpec) -> CheckPlan:
    kind = "command"
    if spec.explicit_kind:
        kind = _canonical_kind(spec.kind)
    elif spec.kind:
        kind = _canonical_kind(spec.kind)
    elif spec.name in _CHECK_KIND_ALIASES:
        kind = _canonical_kind(spec.name)
    return CheckPlan(
        profile=profile.name,
        name=spec.name,
        kind=kind,
        description=spec.description or _DEFAULT_DESCRIPTIONS.get(kind, "Run a readiness command."),
        command_argv=spec.command_argv,
        scope=spec.scope or _DEFAULT_SCOPES.get(kind, "host"),
        required=spec.required,
        parameters=spec.parameters,
        metadata=spec.metadata,
    )


def _render_known_command(
    *,
    kind: str,
    profile: ApplianceProfile,
    parameters: Mapping[str, str],
    env: Mapping[str, str],
    image_tag: str | None,
    docker_command: str,
    python_command: str,
) -> tuple[list[str], dict[str, str], JSONObject]:
    command = _script_command(python_command, kind)
    if kind == CHECK_KIND_DOCKER_DAEMON:
        return [*command, "--docker", require_non_empty_string(docker_command, "docker_command")], {}, {}
    if kind == CHECK_KIND_IMAGE_AVAILABLE:
        image = _parameter(parameters, ("image", "image_tag")) or image_tag or profile.image
        return [
            *command,
            "--docker",
            require_non_empty_string(docker_command, "docker_command"),
            "--image",
            require_non_empty_string(image, "image"),
        ], {"image": image}, {}
    if kind == CHECK_KIND_INTERFACE_EXISTS:
        args, resolved = _interface_args(profile, parameters, env, default_env="LIBCRAFTER_IFACE")
        return [*command, *args], resolved, {}
    if kind == CHECK_KIND_RAW_SOCKET_PERMISSION:
        return command, {}, {}
    if kind == CHECK_KIND_PCAP_OPEN:
        args, resolved = _interface_args(
            profile,
            parameters,
            env,
            default_env=_default_interface_env(profile, kind),
        )
        return [*command, *args], resolved, {}
    if kind == CHECK_KIND_SERIAL_DEVICE_EXISTS:
        args, resolved = _device_args(profile, parameters, env)
        return [*command, *args], resolved, {}
    if kind == CHECK_KIND_WHAD_DISCOVERY:
        args, resolved = _optional_device_args(profile, parameters, env)
        return [*command, *args], resolved, {}
    if kind == CHECK_KIND_DOT11_MONITOR_INTERFACE:
        args, resolved = _interface_args(
            profile,
            parameters,
            env,
            default_env="LIBCRAFTER_DOT11_IFACE",
        )
        return [*command, *args], resolved, {}
    if kind == CHECK_KIND_DOT11_INJECTION_SMOKE:
        args, resolved = _interface_args(
            profile,
            parameters,
            env,
            default_env="LIBCRAFTER_DOT11_IFACE",
        )
        return [*command, "--dry-run", *args], resolved, {
            "live_transmit": False,
            "placeholder": True,
        }
    raise UnknownCheckKindError(kind)


def _script_command(python_command: str, kind: str) -> list[str]:
    return [
        require_non_empty_string(python_command, "python_command"),
        "-m",
        _SCRIPT_MODULES[_canonical_kind(kind)],
    ]


def _profile_and_checks(
    value: ApplianceProfile | Mapping[str, object],
) -> tuple[ApplianceProfile, Sequence[ProfileCheck | Mapping[str, object]]]:
    if isinstance(value, ApplianceProfile):
        return value, value.checks
    data = _mapping(value, "profile")
    checks = _sequence(data.get("checks", []), "checks")
    profile_data = dict(data)
    profile_data["checks"] = []
    return ApplianceProfile.from_dict(profile_data), checks


def _check_spec(value: ProfileCheck | Mapping[str, object]) -> _CheckSpec:
    if isinstance(value, ProfileCheck):
        return _CheckSpec(
            name=_check_name(value.name, "check.name"),
            kind="",
            description=value.description,
            command_argv=_string_list(value.command, "check.command"),
            scope="",
            required=True,
            parameters={},
            metadata={},
            explicit_kind=False,
        )

    data = _mapping(value, "check")
    _reject_unknown_keys(
        data,
        {
            "name",
            "kind",
            "description",
            "command",
            "command_argv",
            "scope",
            "required",
            "parameters",
            "args",
            "metadata",
        },
        "check",
    )
    kind = _optional_string(data.get("kind", ""), "check.kind")
    command_value = data.get("command", data.get("command_argv", []))
    parameters = data.get("parameters", data.get("args", {}))
    name_value = data.get("name", kind)
    name = _check_name(name_value, "check.name") if name_value else ""
    if not name and not kind:
        raise ValueError("check.name or check.kind must be a non-empty string")
    return _CheckSpec(
        name=name or _canonical_kind(kind),
        kind=kind,
        description=_optional_string(data.get("description", ""), "check.description"),
        command_argv=_string_list(command_value, "check.command"),
        scope=_optional_string(data.get("scope", ""), "check.scope"),
        required=_bool(data.get("required", True), "check.required"),
        parameters=_string_mapping(parameters, "check.parameters"),
        metadata=json_object(data.get("metadata", {}), "check.metadata"),
        explicit_kind=bool(kind),
    )


def _canonical_kind(value: str) -> str:
    kind = require_non_empty_string(value, "check.kind")
    try:
        return _CHECK_KIND_ALIASES[kind]
    except KeyError as exc:
        raise UnknownCheckKindError(kind) from exc


def _interface_args(
    profile: ApplianceProfile,
    parameters: Mapping[str, str],
    env: Mapping[str, str],
    *,
    default_env: str,
) -> tuple[list[str], dict[str, str]]:
    interface = _parameter(parameters, ("interface", "iface"))
    if interface:
        return ["--iface", interface], {"interface": interface}
    env_name = _parameter(parameters, ("interface_env", "iface_env")) or default_env
    env_value = env.get(env_name, "")
    if env_value:
        return ["--iface", env_value], {"interface": env_value}
    if profile.name == "dot11-monitor" and env_name == "LIBCRAFTER_IFACE":
        env_name = "LIBCRAFTER_DOT11_IFACE"
    return ["--iface-env", env_name], {"interface_env": env_name}


def _device_args(
    profile: ApplianceProfile,
    parameters: Mapping[str, str],
    env: Mapping[str, str],
) -> tuple[list[str], dict[str, str]]:
    device = _device_value(profile, parameters, env)
    if device:
        return ["--device", device], {"device": device}
    return ["--device-env", "LIBCRAFTER_WHAD_DEVICE"], {"device_env": "LIBCRAFTER_WHAD_DEVICE"}


def _optional_device_args(
    profile: ApplianceProfile,
    parameters: Mapping[str, str],
    env: Mapping[str, str],
) -> tuple[list[str], dict[str, str]]:
    device = _device_value(profile, parameters, env)
    if device:
        return ["--device", device], {"device": device}
    env_name = _parameter(parameters, ("device_env", "serial_env")) or "LIBCRAFTER_WHAD_DEVICE"
    return ["--device-env", env_name], {"device_env": env_name}


def _device_value(
    profile: ApplianceProfile,
    parameters: Mapping[str, str],
    env: Mapping[str, str],
) -> str:
    device = _parameter(parameters, ("device", "path", "serial_device"))
    if device:
        return device
    env_name = _parameter(parameters, ("device_env", "serial_env")) or "LIBCRAFTER_WHAD_DEVICE"
    env_device = env.get(env_name, "")
    if env_device:
        return env_device
    if profile.devices:
        return profile.devices[0].host_path
    return ""


def _default_interface_env(profile: ApplianceProfile, kind: str) -> str:
    if profile.name == "dot11-monitor" or kind.startswith("dot11-"):
        return "LIBCRAFTER_DOT11_IFACE"
    return "LIBCRAFTER_IFACE"


def _parameter(parameters: Mapping[str, str], names: Sequence[str]) -> str:
    for name in names:
        value = parameters.get(name, "")
        if value:
            return value
    return ""


def _check_name(value: object, name: str) -> str:
    text = require_non_empty_string(value, name)
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-_.:")
    if any(character not in allowed for character in text):
        raise ValueError(f"{name} must be a stable check name")
    return text


def _string_mapping(value: object, name: str) -> dict[str, str]:
    data = _mapping(value, name)
    output: dict[str, str] = {}
    for key, item in data.items():
        if key == "":
            raise ValueError(f"{name} keys must be non-empty strings")
        if not isinstance(item, str):
            raise ValueError(f"{name}.{key} must be a string")
        output[key] = item
    return output


def _non_empty_string_list(value: object, name: str) -> list[str]:
    output = _string_list(value, name)
    if not output:
        raise ValueError(f"{name} must not be empty")
    for item in output:
        if item == "":
            raise ValueError(f"{name} entries must be non-empty strings")
    return output


def _string_list(value: object, name: str) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError(f"{name} must be a list of strings")
    output: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"{name} must be a list of strings")
        output.append(item)
    return output


def _mapping(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    for key in value:
        if not isinstance(key, str):
            raise ValueError(f"{name} keys must be strings")
    return value


def _sequence(value: object, name: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError(f"{name} must be a list")
    return value


def _optional_string(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    return value


def _string(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    return value


def _bool(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be a boolean")
    return value


def _reject_unknown_keys(data: Mapping[str, object], allowed: set[str], name: str) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        joined = ", ".join(unknown)
        raise ValueError(f"{name} contains unknown field(s): {joined}")


__all__ = [
    "CHECK_KIND_DOCKER_DAEMON",
    "CHECK_KIND_DOT11_INJECTION_SMOKE",
    "CHECK_KIND_DOT11_MONITOR_INTERFACE",
    "CHECK_KIND_IMAGE_AVAILABLE",
    "CHECK_KIND_INTERFACE_EXISTS",
    "CHECK_KIND_PCAP_OPEN",
    "CHECK_KIND_RAW_SOCKET_PERMISSION",
    "CHECK_KIND_SERIAL_DEVICE_EXISTS",
    "CHECK_KIND_WHAD_DISCOVERY",
    "CHECK_KINDS",
    "PYTHON_COMMAND",
    "CheckPlan",
    "UnknownCheckKindError",
    "build_profile_check_plans",
    "profile_check_plans",
    "render_check_plan",
    "render_profile_check_plans",
]
