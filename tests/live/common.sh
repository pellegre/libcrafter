#!/usr/bin/env bash
set -euo pipefail

live_script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="${LIBCRAFTER_PROJECT_ROOT:-$(cd -- "$live_script_dir/../.." && pwd)}"
artifact_root="${LIBCRAFTER_LIVE_ARTIFACT_DIR:-$project_root/target/live/all}"
live_suite_mode="${LIBCRAFTER_LIVE_SUITE_MODE:-live}"
suite_name=""
suite_dir=""

timestamp_utc() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

parse_live_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dry-run)
        live_suite_mode="dry-run"
        shift
        ;;
      --live)
        live_suite_mode="live"
        shift
        ;;
      *)
        echo "error: unknown live-suite argument: $1" >&2
        exit 64
        ;;
    esac
  done
}

is_dry_run() {
  [[ "$live_suite_mode" == "dry-run" ]]
}

init_suite() {
  suite_name="$1"
  suite_dir="$artifact_root/$suite_name"
  mkdir -p "$suite_dir"
  echo "suite=$suite_name"
  echo "mode=$live_suite_mode"
  echo "artifact_dir=$suite_dir"
}

require_tool() {
  local tool="$1"

  if command -v "$tool" >/dev/null 2>&1; then
    return 0
  fi

  echo "error: required tool '$tool' is not installed" >&2
  exit 69
}

require_live_lab() {
  if is_dry_run; then
    return 0
  fi

  case "${LIBCRAFTER_LIVE_LAB:-}" in
    1|true|TRUE|yes|YES|isolated)
      ;;
    *)
      echo "error: live suite requires LIBCRAFTER_LIVE_LAB=1 inside a disposable lab" >&2
      exit 78
      ;;
  esac

  if [[ "$(id -u)" != "0" ]]; then
    echo "error: live suite requires root inside the disposable lab" >&2
    exit 77
  fi
}

run_logged() {
  local name="$1"
  shift
  local log_file="$suite_dir/$name.log"

  {
    echo "started_at=$(timestamp_utc)"
    printf 'command='
    printf '%q ' "$@"
    printf '\n'
  } >"$log_file"

  if "$@" >>"$log_file" 2>&1; then
    echo "log=$log_file"
    return 0
  fi

  local status=$?
  echo "exit=$status" >>"$log_file"
  echo "error: command failed: $name (exit $status)" >&2
  tail -n 40 "$log_file" >&2 || true
  return "$status"
}

run_shell_logged() {
  local name="$1"
  local script="$2"
  run_logged "$name" bash -lc "$script"
}

run_scapy_logged() {
  local name="$1"
  local script_file="$suite_dir/$name.py"
  local log_file="$suite_dir/$name.log"
  local venv_dir="${LIBCRAFTER_SCAPY_VENV:-$project_root/.libcrafter-live/live-scapy-venv}"

  cat >"$script_file"
  {
    echo "started_at=$(timestamp_utc)"
    echo "script=$script_file"
  } >"$log_file"

  local status=0

  set +e
  if python3 - <<'PY' >/dev/null 2>&1
import scapy.all
PY
  then
    python3 "$script_file" >>"$log_file" 2>&1
    status=$?
  elif command -v uv >/dev/null 2>&1; then
    UV_NO_PROGRESS=1 uv run --quiet --no-project --with 'scapy>=2.5,<3' -- python3 "$script_file" >>"$log_file" 2>&1
    status=$?
  else
    python3 -m venv "$venv_dir" >>"$log_file" 2>&1
    status=$?
    if [[ "$status" -eq 0 ]]; then
      "$venv_dir/bin/python" -m pip install --upgrade pip >>"$log_file" 2>&1
      status=$?
    fi
    if [[ "$status" -eq 0 ]]; then
      "$venv_dir/bin/python" -m pip install 'scapy>=2.5,<3' >>"$log_file" 2>&1
      status=$?
    fi
    if [[ "$status" -eq 0 ]]; then
      "$venv_dir/bin/python" "$script_file" >>"$log_file" 2>&1
      status=$?
    fi
  fi
  set -e
  if [[ "$status" -eq 0 ]]; then
    echo "log=$log_file"
    return 0
  fi

  echo "exit=$status" >>"$log_file"
  echo "error: Scapy command failed: $name (exit $status)" >&2
  tail -n 40 "$log_file" >&2 || true
  return "$status"
}

write_suite_json() {
  local status="$1"
  local reason="$2"
  local file="$suite_dir/summary.json"

  python3 - "$file" "$suite_name" "$status" "$reason" "$live_suite_mode" "$suite_dir" <<'PY'
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone

file_name, suite, status, reason, mode, artifact_dir = sys.argv[1:7]
with open(file_name, "w", encoding="utf-8") as handle:
    json.dump(
        {
            "suite": suite,
            "status": status,
            "reason": reason,
            "mode": mode,
            "artifact_dir": artifact_dir,
            "finished_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        },
        handle,
        indent=2,
        sort_keys=True,
    )
    handle.write("\n")
PY
  echo "summary=$file"
}

start_tcpdump() {
  local iface="$1"
  local filter="$2"
  local pcap_file="$3"
  local log_file="$4"
  local timeout_seconds="${LIBCRAFTER_LIVE_TCPDUMP_TIMEOUT:-15}"

  require_tool tcpdump
  timeout "$timeout_seconds" tcpdump -i "$iface" -n -U -w "$pcap_file" "$filter" >"$log_file" 2>&1 &
  echo "$!"
  sleep 1
}

stop_background() {
  local pid="${1:-}"

  if [[ -z "$pid" ]]; then
    return 0
  fi

  kill -INT "$pid" >/dev/null 2>&1 || true
  wait "$pid" >/dev/null 2>&1 || true
}

pcap_has_packets() {
  local pcap_file="$1"

  [[ -s "$pcap_file" ]] || return 1
  tcpdump -r "$pcap_file" -c 1 >/dev/null 2>&1
}
