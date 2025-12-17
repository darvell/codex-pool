#!/usr/bin/env bash
set -euo pipefail

export PROXY_DEBUG="${PROXY_DEBUG:-1}"
export POOL_DIR="${POOL_DIR:-./pool}"
export PROXY_LISTEN_ADDR="${PROXY_LISTEN_ADDR:-127.0.0.1:8989}"

if command -v air >/dev/null 2>&1; then
  exec air
fi

exec go run .

