# nf-snmp device simulators: real net-snmp snmpd + a pass_persist model script.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# One image for all device models (SIM_MODEL selects). It also carries the
# net-snmp command line tools and snmptrapd, so it doubles as the throwaway
# client / trap-receiver image used by selftest.sh.
FROM debian:bookworm-slim

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      snmpd snmp snmptrapd python3 \
 && rm -rf /var/lib/apt/lists/* /usr/share/doc /usr/share/man \
 && rm -f /etc/snmp/snmpd.conf

COPY . /opt/sim/
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SIM_MODEL=apc-ups \
    SIM_STEP_MS=10000

EXPOSE 161/udp 8000/tcp
CMD ["python3", "/opt/sim/simd.py"]
