"""SSH command and file transfer helpers for endpoints."""

from __future__ import annotations

import shlex
import time
from collections.abc import Callable, Sequence
from pathlib import Path

from .config import absolute_path
from .process import CommandResult, run_command


DEFAULT_SSH_PORT = 22
DEFAULT_CONNECT_TIMEOUT = 10
DEFAULT_STRICT_HOST_KEY_CHECKING = "accept-new"
DEFAULT_KEY_TYPE = "ed25519"
DEFAULT_SSH_WAIT_TIMEOUT = 300
DEFAULT_SSH_WAIT_INTERVAL = 5
DEFAULT_SERVER_ALIVE_INTERVAL = 5
DEFAULT_SERVER_ALIVE_COUNT_MAX = 2
DEFAULT_TRANSFER_TIMEOUT = 300

CommandRunner = Callable[..., CommandResult]


def create_key_pair(
    private_key_path: str | Path,
    *,
    comment: str,
    key_type: str = DEFAULT_KEY_TYPE,
    force: bool = False,
    runner: CommandRunner = run_command,
    timeout: float | None = DEFAULT_TRANSFER_TIMEOUT,
) -> CommandResult:
    """Create an SSH key pair with ssh-keygen and return the command result."""

    key_path = _absolute_local_path(private_key_path, "private_key_path")
    key_path.parent.mkdir(parents=True, exist_ok=True)
    public_key_path = key_path.with_name(f"{key_path.name}.pub")

    if force:
        key_path.unlink(missing_ok=True)
        public_key_path.unlink(missing_ok=True)
    elif key_path.exists() or public_key_path.exists():
        raise FileExistsError(f"SSH key already exists: {key_path}")

    return runner(
        [
            "ssh-keygen",
            "-q",
            "-t",
            key_type,
            "-N",
            "",
            "-C",
            comment,
            "-f",
            str(key_path),
        ],
        timeout=timeout,
    )


def ensure_known_hosts_file(known_hosts: str | Path) -> Path:
    """Create and return an absolute known-hosts file path."""

    path = _absolute_local_path(known_hosts, "known_hosts")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(exist_ok=True)
    return path


def remove_known_host(
    *,
    host: str,
    known_hosts: str | Path,
    runner: CommandRunner = run_command,
    timeout: float | None = DEFAULT_TRANSFER_TIMEOUT,
) -> CommandResult:
    """Remove one host from a known-hosts file with ssh-keygen."""

    path = ensure_known_hosts_file(known_hosts)
    result = runner(
        ["ssh-keygen", "-f", str(path), "-R", _non_empty(host, "host")],
        timeout=timeout,
    )
    path.with_name(f"{path.name}.old").unlink(missing_ok=True)
    return result


def ssh_argv(
    *,
    host: str,
    user: str,
    identity_file: str | Path,
    known_hosts: str | Path,
    command: str | Sequence[object] | None = None,
    port: int = DEFAULT_SSH_PORT,
    connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
    strict_host_key_checking: str = DEFAULT_STRICT_HOST_KEY_CHECKING,
) -> list[str]:
    """Build an ssh argv for an endpoint command or interactive shell."""

    argv = [
        "ssh",
        *ssh_options_argv(
            identity_file=identity_file,
            known_hosts=known_hosts,
            port=port,
            connect_timeout=connect_timeout,
            strict_host_key_checking=strict_host_key_checking,
        ),
        remote_host(host=host, user=user),
    ]
    if command is None:
        return argv
    if isinstance(command, str):
        argv.append(command)
    else:
        # ssh joins the trailing command tokens with spaces and the remote login
        # shell re-splits them, so a multi-token command such as
        # ["bash", "-lc", "<script with spaces>"] must be shell-quoted into a
        # single argument to survive intact on the remote side. Without this the
        # remote shell mangles any token that contains whitespace.
        argv.append(shlex.join(str(part) for part in command))
    return argv


def scp_argv(
    *,
    source: str,
    destination: str,
    identity_file: str | Path,
    known_hosts: str | Path,
    port: int = DEFAULT_SSH_PORT,
    connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
    strict_host_key_checking: str = DEFAULT_STRICT_HOST_KEY_CHECKING,
    recursive: bool = False,
) -> list[str]:
    """Build an scp argv for one file transfer."""

    argv = ["scp"]
    if recursive:
        argv.append("-r")
    argv.extend(
        scp_options_argv(
            identity_file=identity_file,
            known_hosts=known_hosts,
            port=port,
            connect_timeout=connect_timeout,
            strict_host_key_checking=strict_host_key_checking,
        )
    )
    argv.extend([source, destination])
    return argv


def run_ssh_command(
    *,
    host: str,
    user: str,
    identity_file: str | Path,
    known_hosts: str | Path,
    command: str | Sequence[object],
    port: int = DEFAULT_SSH_PORT,
    connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
    runner: CommandRunner = run_command,
    timeout: float | None = None,
) -> CommandResult:
    """Run a command on an endpoint through ssh."""

    return runner(
        ssh_argv(
            host=host,
            user=user,
            identity_file=identity_file,
            known_hosts=known_hosts,
            command=command,
            port=port,
            connect_timeout=connect_timeout,
        ),
        timeout=timeout,
    )


def wait_for_ssh(
    *,
    host: str,
    user: str,
    identity_file: str | Path,
    known_hosts: str | Path,
    port: int = DEFAULT_SSH_PORT,
    connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
    wait_timeout: float = DEFAULT_SSH_WAIT_TIMEOUT,
    interval: float = DEFAULT_SSH_WAIT_INTERVAL,
    runner: CommandRunner = run_command,
) -> CommandResult:
    """Wait until SSH accepts a simple command and return the successful result."""

    deadline = time.monotonic() + _positive_float(wait_timeout, "wait_timeout")
    sleep_interval = _positive_float(interval, "interval")
    last_result: CommandResult | None = None

    while True:
        last_result = run_ssh_command(
            host=host,
            user=user,
            identity_file=identity_file,
            known_hosts=known_hosts,
            command="true",
            port=port,
            connect_timeout=connect_timeout,
            runner=runner,
            timeout=connect_timeout + 5,
        )
        if last_result.ok:
            return last_result

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(_ssh_wait_error(host=host, port=port, result=last_result))
        time.sleep(min(sleep_interval, remaining))


def upload(
    *,
    host: str,
    user: str,
    identity_file: str | Path,
    known_hosts: str | Path,
    local_path: str | Path,
    remote_path: str,
    port: int = DEFAULT_SSH_PORT,
    connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
    recursive: bool = False,
    runner: CommandRunner = run_command,
    timeout: float | None = None,
) -> CommandResult:
    """Upload an absolute local path to an endpoint with scp."""

    local = _required_absolute_local_path(local_path, "local_path")
    remote = _remote_path(host=host, user=user, path=remote_path)
    return runner(
        scp_argv(
            source=str(local),
            destination=remote,
            identity_file=identity_file,
            known_hosts=known_hosts,
            port=port,
            connect_timeout=connect_timeout,
            recursive=recursive,
        ),
        timeout=timeout,
    )


def download(
    *,
    host: str,
    user: str,
    identity_file: str | Path,
    known_hosts: str | Path,
    remote_path: str,
    local_path: str | Path,
    port: int = DEFAULT_SSH_PORT,
    connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
    recursive: bool = False,
    runner: CommandRunner = run_command,
    timeout: float | None = None,
) -> CommandResult:
    """Download from an endpoint to an absolute local path with scp."""

    local = _required_absolute_local_path(local_path, "local_path")
    local.parent.mkdir(parents=True, exist_ok=True)
    remote = _remote_path(host=host, user=user, path=remote_path)
    return runner(
        scp_argv(
            source=remote,
            destination=str(local),
            identity_file=identity_file,
            known_hosts=known_hosts,
            port=port,
            connect_timeout=connect_timeout,
            recursive=recursive,
        ),
        timeout=timeout,
    )


def ssh_options_argv(
    *,
    identity_file: str | Path,
    known_hosts: str | Path,
    port: int = DEFAULT_SSH_PORT,
    connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
    strict_host_key_checking: str = DEFAULT_STRICT_HOST_KEY_CHECKING,
) -> list[str]:
    """Return common ssh options for endpoint connections."""

    return [
        "-i",
        str(_absolute_local_path(identity_file, "identity_file")),
        "-p",
        str(_port(port)),
        "-o",
        f"StrictHostKeyChecking={_non_empty(strict_host_key_checking, 'strict_host_key_checking')}",
        "-o",
        f"UserKnownHostsFile={_absolute_local_path(known_hosts, 'known_hosts')}",
        "-o",
        f"ConnectTimeout={_positive_int(connect_timeout, 'connect_timeout')}",
        "-o",
        f"ServerAliveInterval={DEFAULT_SERVER_ALIVE_INTERVAL}",
        "-o",
        f"ServerAliveCountMax={DEFAULT_SERVER_ALIVE_COUNT_MAX}",
    ]


def scp_options_argv(
    *,
    identity_file: str | Path,
    known_hosts: str | Path,
    port: int = DEFAULT_SSH_PORT,
    connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
    strict_host_key_checking: str = DEFAULT_STRICT_HOST_KEY_CHECKING,
) -> list[str]:
    """Return common scp options for endpoint transfers."""

    options = ssh_options_argv(
        identity_file=identity_file,
        known_hosts=known_hosts,
        port=port,
        connect_timeout=connect_timeout,
        strict_host_key_checking=strict_host_key_checking,
    )
    port_index = options.index("-p")
    options[port_index] = "-P"
    return options


def remote_host(*, host: str, user: str) -> str:
    """Return the user@host target string used by ssh and scp."""

    return f"{_non_empty(user, 'user')}@{_non_empty(host, 'host')}"


def _remote_path(*, host: str, user: str, path: str) -> str:
    return f"{remote_host(host=host, user=user)}:{_non_empty(path, 'remote_path')}"


def _absolute_local_path(path: str | Path, name: str) -> Path:
    return absolute_path(_non_empty_path(path, name))


def _required_absolute_local_path(path: str | Path, name: str) -> Path:
    output = Path(_non_empty_path(path, name)).expanduser()
    if not output.is_absolute():
        raise ValueError(f"{name} must be an absolute local path: {path!s}")
    return output.resolve(strict=False)


def _non_empty(value: str, name: str) -> str:
    if not isinstance(value, str) or value == "":
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _non_empty_path(path: str | Path, name: str) -> Path:
    if isinstance(path, str) and path == "":
        raise ValueError(f"{name} must be a non-empty path")
    output = Path(path).expanduser()
    if str(output) == "":
        raise ValueError(f"{name} must be a non-empty path")
    return output


def _port(value: int) -> int:
    return _positive_int(value, "port")


def _positive_int(value: int, name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be a positive integer")
    output = int(value)
    if output <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return output


def _positive_float(value: float, name: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be a positive number")
    output = float(value)
    if output <= 0:
        raise ValueError(f"{name} must be a positive number")
    return output


def _ssh_wait_error(*, host: str, port: int, result: CommandResult) -> str:
    details = result.stderr.strip() or result.stdout.strip() or result.error or "no output"
    return f"wait for ssh timed out for {host}:{port}: {details}"
