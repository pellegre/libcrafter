#!/usr/bin/env bash
set -euo pipefail

ARTIFACT_ROOT="${IGMP_ARTIFACT_ROOT:-target/probe/target-services/igmp}"

if [ -f "$ARTIFACT_ROOT/listener.pid" ]; then
    pid="$(cat "$ARTIFACT_ROOT/listener.pid")"
    if kill -0 "$pid" >/dev/null 2>&1; then
        kill "$pid" || true
    fi
    rm -f "$ARTIFACT_ROOT/listener.pid"
fi

rm -f "$ARTIFACT_ROOT/igmp-listener.py"
printf 'igmp_target_cleanup=ok\n'

