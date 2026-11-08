#!/bin/sh
# Start the stock net-snmp snmpd (the non-synthetic difftest target) with the §2 difftest
# users appended to the config.
set -e
mkdir -p /var/lib/snmp
cp /opt/agent/snmpd.conf /tmp/snmpd.conf
cat >> /tmp/snmpd.conf <<'USERS'
createUser noauth
createUser authsha SHA authpass123
createUser md5des MD5 authpass123 DES privpass123
createUser shaaes SHA authpass123 AES privpass123
createUser sha256aes SHA-256 authpass123 AES privpass123
createUser sha512aes SHA-512 authpass123 AES privpass123
createUser sha256aes256 SHA-256 authpass123 AES-256 privpass123
createUser shaaes256 SHA authpass123 AES-256 privpass123
USERS
exec snmpd -f -LOw -C -c /tmp/snmpd.conf -p /tmp/snmpd.pid
