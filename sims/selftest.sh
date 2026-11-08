#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Bring up the simulator stack and exercise every sim from a throwaway
# client container on the snmpnet network (net-snmp CLI tools + snmptrapd),
# checking each answer against the sim's /truth for the same time step.
#
#   sims/selftest.sh                 # build, up, test, down
#   KEEP_UP=1 sims/selftest.sh       # leave the stack running afterwards
#   sims/selftest.sh sim-quirky      # only test some sims
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
COMPOSE=(docker compose -f "$HERE/docker-compose.yml")
# Build locally even when the default buildx builder is a remote/cloud one.
export BUILDX_BUILDER="${BUILDX_BUILDER:-default}"

cleanup() {
  if [[ "${KEEP_UP:-0}" != "1" ]]; then
    "${COMPOSE[@]}" down --remove-orphans >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

"${COMPOSE[@]}" up -d --build --wait --wait-timeout 120

# The client is an ordinary `docker run --rm --network snmpnet` container,
# which is also how test harnesses are expected to reach the sims.
docker run --rm --name nfsnmp-selftest --network snmpnet \
  -v "$HERE/selftest.py:/selftest.py:ro" \
  nfsnmp-sim-device:latest python3 /selftest.py "$@"
