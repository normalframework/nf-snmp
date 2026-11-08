# SPDX-License-Identifier: GPL-3.0-or-later
# nf-snmp difftest image: net-snmp CLI tools, gosnmp ref, pysnmp ref, Node 22 (for `ours`
# and the harness), and snmpd (used as the stock "real agent" target).
# Build context: difftest/
FROM golang:1.24-bookworm AS gobuild
WORKDIR /src
COPY refs/gosnmp/go.mod refs/gosnmp/go.sum ./
RUN go mod download
COPY refs/gosnmp/*.go ./
RUN CGO_ENABLED=0 go build -trimpath -o /out/ref-gosnmp .

FROM node:22.23.4-bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends snmp snmpd python3 python3-venv ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
COPY refs/pysnmp/requirements.txt /opt/pysnmp/requirements.txt
RUN python3 -m venv /opt/pysnmp/venv \
 && /opt/pysnmp/venv/bin/pip install --no-cache-dir -r /opt/pysnmp/requirements.txt
COPY --from=gobuild /out/ref-gosnmp /usr/local/bin/ref-gosnmp
COPY refs/pysnmp/ref_pysnmp.py /opt/pysnmp/ref_pysnmp.py
COPY refs/netsnmp/ref_netsnmp.py /opt/netsnmp/ref_netsnmp.py
COPY agent/ /opt/agent/
RUN printf '#!/bin/sh\nexec /opt/pysnmp/venv/bin/python3 -I /opt/pysnmp/ref_pysnmp.py "$@"\n' > /usr/local/bin/ref-pysnmp \
 && printf '#!/bin/sh\nexec python3 -I /opt/netsnmp/ref_netsnmp.py "$@"\n' > /usr/local/bin/ref-netsnmp \
 && chmod +x /usr/local/bin/ref-pysnmp /usr/local/bin/ref-netsnmp /opt/agent/*.sh \
 && mkdir -p /var/lib/snmp
ENV MIBS="" MIBDIRS=/nonexistent
WORKDIR /app
CMD ["node", "/app/difftest/run.js"]
