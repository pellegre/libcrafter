#!/usr/bin/env bash
set -euo pipefail

ARTIFACT_ROOT="${IGMP_ARTIFACT_ROOT:-target/probe/target-services/igmp}"
GROUP="${IGMP_GROUP:-233.252.0.42}"
BIND_IFACE="${IGMP_BIND_IFACE:-}"
DRY_RUN="${IGMP_DRY_RUN:-0}"
PROVIDER_MULTICAST="${IGMP_PROVIDER_MULTICAST:-0}"
PROVIDER_CONTROLLED_ROUTER="${IGMP_PROVIDER_CONTROLLED_ROUTER:-0}"

case "${1:-}" in
--dry-run)
    DRY_RUN=1
    shift
    ;;
--help)
    cat <<'EOF'
Usage: provision-router.sh [--dry-run]

Record or provision the controlled IGMP router test role. Providers that do not
declare multicast and controlled-router capability skip cleanly with exit 0.
Live mode requires LIBCRAFTER_PROBE_LAB_TARGET=1.
EOF
    exit 0
    ;;
"") ;;
*) printf 'provision-router: unknown argument: %s\n' "$1" >&2; exit 2 ;;
esac

die() {
    printf 'provision-router: %s\n' "$*" >&2
    exit 1
}

require_value() {
    local name="$1"
    local value="$2"

    [[ -n "$value" ]] || die "$name must not be empty"
    [[ "$value" != *$'\n'* ]] || die "$name must not contain newlines"
    [[ "$value" != *'"'* ]] || die "$name must not contain double quotes"
}

write_plan() {
    local dry_run_json="$1"
    local state="$2"

    install -d -m 0755 "$ARTIFACT_ROOT"
    cat >"$ARTIFACT_ROOT/router-plan.json" <<EOF
{
  "role": "igmp-router",
  "lab_only": true,
  "dry_run": ${dry_run_json},
  "state": "${state}",
  "group": "${GROUP}",
  "bind_iface": "${BIND_IFACE}",
  "requires": [
    "multicast",
    "controlled_router"
  ],
  "artifacts": [
    "${ARTIFACT_ROOT}/router-plan.json",
    "${ARTIFACT_ROOT}/router-skip.json"
  ]
}
EOF
}

write_skip() {
    local reason="$1"

    install -d -m 0755 "$ARTIFACT_ROOT"
    cat >"$ARTIFACT_ROOT/router-skip.json" <<EOF
{
  "role": "igmp-router",
  "skipped": true,
  "reason": "${reason}",
  "safe_to_skip": true
}
EOF
    printf 'igmp_router=skipped reason=%s\n' "$reason"
}

require_value IGMP_ARTIFACT_ROOT "$ARTIFACT_ROOT"
require_value IGMP_GROUP "$GROUP"

if [[ "$DRY_RUN" == "1" ]]; then
    write_plan true planned
    printf 'igmp_router=dry-run\n'
    exit 0
fi

[[ "${LIBCRAFTER_PROBE_LAB_TARGET:-}" == "1" ]] ||
    die "live router provisioning requires LIBCRAFTER_PROBE_LAB_TARGET=1; use --dry-run locally"

if [[ "$PROVIDER_MULTICAST" != "1" ]]; then
    write_skip requires_multicast
    exit 0
fi

if [[ "$PROVIDER_CONTROLLED_ROUTER" != "1" ]]; then
    write_skip requires_controlled_router
    exit 0
fi

write_plan false ready
printf 'igmp_router=ready\n'

