#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Verify every OID/type/access served by the device models against the real
# vendor/IETF MIB text, using net-snmp's snmptranslate inside the sim image.
# MIBs are fetched from the LibreNMS MIB collection at a pinned commit into a
# temporary directory (they are not vendored into this repo).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
LIBRENMS_REF="${LIBRENMS_REF:-1c22ea7cae6eebb3856c281effd6eb64cf4bf53a}"
BASE="https://raw.githubusercontent.com/librenms/librenms/${LIBRENMS_REF}/mibs"
IMAGE="${IMAGE:-nfsnmp-sim-device:latest}"
MIBS=(
  apc/PowerNet-MIB raritan/PDU2-MIB UPS-MIB ENTITY-SENSOR-MIB ENTITY-MIB IF-MIB
  liebert/LIEBERT-GP-REGISTRATION-MIB liebert/LIEBERT-GP-ENVIRONMENTAL-MIB
  liebert/LIEBERT-GP-CONDITIONS-MIB liebert/LIEBERT-GP-NOTIFICATIONS-MIB
  SNMPv2-SMI SNMPv2-TC SNMPv2-CONF SNMPv2-MIB RFC1155-SMI RFC-1212 RFC-1215 RFC1213-MIB
  IANAifType-MIB INET-ADDRESS-MIB SNMP-FRAMEWORK-MIB IANA-ENTITY-MIB UUID-TC-MIB HCNUM-TC
  cisco/CISCO-SMI cisco/CISCO-PRODUCTS-MIB cisco/CISCO-ENTITY-VENDORTYPE-OID-MIB
)
dir="${MIB_DIR:-}"
if [[ -z "$dir" ]]; then
  dir="$(mktemp -d /tmp/nfsnmp-mibs.XXXXXX)"
  trap 'rm -rf "$dir"' EXIT
  for m in "${MIBS[@]}"; do
    curl -sfL -o "$dir/$(basename "$m")" "$BASE/$m" || { echo "fetch failed: $m" >&2; exit 1; }
  done
fi
docker run --rm -v "$dir:/mibs:ro" -v "$HERE/verify-oids.py:/verify-oids.py:ro" \
  "$IMAGE" python3 /verify-oids.py /mibs
