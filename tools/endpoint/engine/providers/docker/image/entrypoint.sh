#!/usr/bin/env bash
set -euo pipefail

AUTHORIZED_KEY_FILE="${LIBCRAFTER_AUTHORIZED_KEY_FILE:-/run/libcrafter/authorized_key.pub}"
ROOT_HOME="/root"
SSH_DIR="${ROOT_HOME}/.ssh"
AUTHORIZED_KEYS="${SSH_DIR}/authorized_keys"

mkdir -p /run/sshd "${SSH_DIR}"
chmod 0755 /run/sshd
chmod 0700 "${SSH_DIR}"

if [[ ! -s "${AUTHORIZED_KEY_FILE}" ]]; then
    echo "libcrafter docker endpoint: missing injected public key at ${AUTHORIZED_KEY_FILE}" >&2
    exit 1
fi

install -m 0600 "${AUTHORIZED_KEY_FILE}" "${AUTHORIZED_KEYS}"
chmod 0700 "${SSH_DIR}"
chmod 0600 "${AUTHORIZED_KEYS}"

exec /usr/sbin/sshd -D -e
