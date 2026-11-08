# sim-quirky: pysnmp/pyasn1 based buggy SNMP v1/v2c agent with fault injection.
# SPDX-License-Identifier: GPL-3.0-or-later
# Build context: sims/ (shares device/simcore.py).
FROM python:3.12-slim

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends snmp \
 && rm -rf /var/lib/apt/lists/* /usr/share/doc /usr/share/man
COPY quirky/requirements.txt /opt/sim/requirements.txt
RUN pip install --no-cache-dir --root-user-action=ignore -r /opt/sim/requirements.txt
COPY device/simcore.py quirky/quirkyd.py /opt/sim/
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SIM_STEP_MS=10000
EXPOSE 161/udp 8000/tcp
CMD ["python3", "/opt/sim/quirkyd.py"]
