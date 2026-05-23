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

write_reference_backend_version() {
  local output_json="$1"
  local output_log="${2:-$output_json.log}"

  if "$project_root/tools/oracle/run" backend-info --backend scapy >"$output_json" 2>"$output_log"; then
    python3 - "$output_json" <<'PY'
from __future__ import annotations

import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    metadata = json.load(handle)
print(f"reference_tool={metadata.get('scapy_version', 'unknown')}")
PY
    return 0
  fi

  local status=$?
  echo "reference_tool=unavailable:oracle-backend"
  if [[ -s "$output_log" ]]; then
    sed 's/^/reference_tool_error: /' "$output_log" >&2
  fi
  return "$status"
}

run_oracle_legacy_scapy_logged() {
  local name="$1"
  shift

  run_logged "$name" \
    "$project_root/tools/oracle/run" legacy-live-example \
      --backend scapy \
      --suite-dir "$suite_dir" \
      "$@"
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

start_libpcap_capture() {
  local iface="$1"
  local filter="$2"
  local pcap_file="$3"
  local log_file="$4"
  local count="${5:-1}"
  local timeout_seconds="${LIBCRAFTER_LIVE_CAPTURE_TIMEOUT:-15}"
  local target_dir="${CARGO_TARGET_DIR:-$project_root/target}"
  local binary="$target_dir/debug/examples/capture_pcap"

  if [[ "$target_dir" != /* ]]; then
    target_dir="$project_root/$target_dir"
    binary="$target_dir/debug/examples/capture_pcap"
  fi

  require_tool cargo
  {
    echo "started_at=$(timestamp_utc)"
    echo "interface=$iface"
    echo "filter=$filter"
    echo "pcap=$pcap_file"
    echo "count=$count"
    echo "timeout_seconds=$timeout_seconds"
    cd "$project_root"
    cargo build --quiet --example capture_pcap
  } >"$log_file" 2>&1

  "$binary" \
    --iface "$iface" \
    --filter "$filter" \
    --out "$pcap_file" \
    --count "$count" \
    --timeout-seconds "$timeout_seconds" >>"$log_file" 2>&1 &
  echo "$!"
  sleep 1
}

wait_for_capture() {
  local pid="${1:-}"
  local log_file="${2:-}"
  local wait_seconds="${LIBCRAFTER_LIVE_CAPTURE_WAIT:-20}"
  local elapsed=0

  if [[ -z "$pid" ]]; then
    return 0
  fi

  while kill -0 "$pid" >/dev/null 2>&1; do
    if [[ "$elapsed" -ge "$wait_seconds" ]]; then
      echo "error: libpcap capture did not finish within ${wait_seconds}s" >&2
      if [[ -n "$log_file" ]]; then
        tail -n 40 "$log_file" >&2 || true
      fi
      stop_background "$pid"
      return 1
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done

  if wait "$pid"; then
    return 0
  fi

  local status=$?
  echo "error: libpcap capture failed (exit $status)" >&2
  if [[ -n "$log_file" ]]; then
    tail -n 40 "$log_file" >&2 || true
  fi
  return "$status"
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
  local log_file="$suite_dir/pcap-read-check.log"

  [[ -s "$pcap_file" ]] || return 1
  (cd "$project_root" && cargo run --quiet --example read_pcap -- --in "$pcap_file") >"$log_file" 2>&1
}
