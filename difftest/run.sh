#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Host wrapper for the nf-snmp difftest (docs/internals.md §3).
#
#   difftest/run.sh [run.js args...]        e.g. difftest/run.sh --targets 'sim-.*' -v
#
# 1. builds the difftest image (net-snmp tools, gosnmp, pysnmp, Node 22, snmpd),
# 2. picks the docker network: $SNMPNET, else a network named snmpnet / *_snmpnet (the sims
#    compose), else creates the throwaway nfsnmp-dt-net,
# 3. makes sure the extra agent targets run on that network: real-snmpd (stock net-snmp snmpd)
#    and edge-agent (difftest/agent/edge_agent.py),
# 4. runs difftest/run.js inside the image with the repo mounted at /app.
# Env: SNMPNET, DIFFTEST_IMAGE (default nfsnmp-difftest:dev), DIFFTEST_NO_BUILD=1, DIFFTEST_KEEP_AGENTS=1.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(dirname "$HERE")
IMAGE=${DIFFTEST_IMAGE:-nfsnmp-difftest:dev}

if [ -z "${DIFFTEST_NO_BUILD:-}" ]; then
  docker build -q -t "$IMAGE" "$HERE" >/dev/null
fi

NET=${SNMPNET:-}
if [ -z "$NET" ]; then
  NET=$(docker network ls --format '{{.Name}}' | grep -E '(^|_)snmpnet$' | head -n1 || true)
fi
if [ -z "$NET" ]; then
  NET=nfsnmp-dt-net
  docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null
fi
echo "difftest: network $NET, image $IMAGE" >&2

# ensure_agent <container> <alias> <cmd...>
ensure_agent() {
  name=$1; alias=$2; shift 2
  if docker inspect "$name" >/dev/null 2>&1; then
    running=$(docker inspect -f '{{.State.Running}}' "$name")
    onnet=$(docker inspect -f "{{if index .NetworkSettings.Networks \"$NET\"}}yes{{end}}" "$name")
    img=$(docker inspect -f '{{.Config.Image}}' "$name")
    if [ "$running" = true ] && [ "$onnet" = yes ] && [ "$img" = "$IMAGE" ]; then return; fi
    docker rm -f "$name" >/dev/null
  fi
  docker run -d --name "$name" --network "$NET" --network-alias "$alias" \
    -v "$HERE/agent:/opt/agent:ro" "$IMAGE" "$@" >/dev/null
}
ensure_agent nfsnmp-dt-real-snmpd real-snmpd /bin/sh /opt/agent/start-snmpd.sh
ensure_agent nfsnmp-dt-edge edge-agent python3 -I /opt/agent/edge_agent.py
sleep 1

set +e
docker run --rm --network "$NET" -u "$(id -u):$(id -g)" -e HOME=/tmp -v "$REPO:/app" -w /app "$IMAGE" node /app/difftest/run.js "$@"
rc=$?
if [ -z "${DIFFTEST_KEEP_AGENTS:-}" ] && [ "${DIFFTEST_STOP_AGENTS:-}" = 1 ]; then
  docker rm -f nfsnmp-dt-real-snmpd nfsnmp-dt-edge >/dev/null 2>&1
fi
exit $rc
