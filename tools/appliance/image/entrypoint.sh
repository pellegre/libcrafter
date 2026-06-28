#!/usr/bin/env bash
set -euo pipefail

workdir="${LIBCRAFTER_APPLIANCE_WORKDIR:-/work}"

mkdir -p "${workdir}"
cd "${workdir}"

if [[ "$#" -eq 0 ]]; then
    exec /bin/bash
fi

exec "$@"
