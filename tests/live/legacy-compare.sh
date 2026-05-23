#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$script_dir/common.sh"

parse_live_args "$@"
init_suite "legacy-compare"
require_tool python3
require_live_lab

examples_dir="${LIBCRAFTER_EXAMPLES_DIR:-$project_root/../libcrafter-examples}"
legacy_out="$suite_dir/legacy"
legacy_work="${LIBCRAFTER_LEGACY_WORK_ROOT:-$project_root/.libcrafter-live/live-suite-legacy-work}"
mkdir -p "$legacy_out"

run_logged legacy-harness-dry-run \
  "$project_root/tools/reference/legacy-libcrafter.sh" --dry-run --examples IPv6RoutingHeader --out "$legacy_out" --work-dir "$legacy_work"

if [[ ! -d "$examples_dir" ]]; then
  cat >"$suite_dir/legacy-skipped.env" <<EOF
result=skipped
reason=examples_dir_missing
examples_dir=$examples_dir
EOF
  write_suite_json ok "legacy dry-run completed; external examples checkout not present"
  exit 0
fi

if is_dry_run; then
  write_suite_json ok "dry-run validated selected legacy harness command"
  exit 0
fi

run_logged legacy-ipv6-routing-header \
  "$project_root/tools/reference/legacy-libcrafter.sh" --clean --examples IPv6RoutingHeader --out "$legacy_out" --work-dir "$legacy_work"

if [[ -f "$legacy_out/IPv6RoutingHeader.stdout.sha256" ]]; then
  cp "$legacy_out/IPv6RoutingHeader.stdout.sha256" "$suite_dir/legacy-ipv6-routing-header.sha256"
fi

write_suite_json ok "selected legacy IPv6RoutingHeader comparison completed"
