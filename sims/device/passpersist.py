#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""snmpd pass_persist handler serving one model subtree.

    pass_persist [-p prio] <root> /usr/bin/python3 /opt/sim/passpersist.py <root>

Protocol (snmpd(8) / snmpd.conf(5) "pass_persist"): PING->PONG, then
get/getnext/set requests; answers are OID, type, value lines or NONE.
Values are recomputed for floor(now/stepMs) on every request (cached per step
and per write-state version) so they match GET /truth for the same instant.
"""

import os
import sys
import time
from bisect import bisect_right

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from simcore import StateStore, WriteError, oid_key  # noqa: E402
from models import get_model  # noqa: E402

PP_TYPES = {"Integer": "integer", "Gauge32": "gauge", "Counter32": "counter",
            "Counter64": "counter64", "TimeTicks": "timeticks", "IpAddress": "ipaddress",
            "OID": "objectid"}
SET_TYPES = {"integer": "Integer", "gauge": "Gauge32", "counter": "Counter32",
             "counter64": "Counter64", "timeticks": "TimeTicks", "ipaddress": "IpAddress",
             "objectid": "OID", "string": "OctetString", "octet": "OctetString",
             "opaque": "Opaque", "unsigned": "Gauge32"}


# snmpd dup()s our stderr onto the same pipe it reads answers from, so
# nothing may ever be written to stderr: send diagnostics to a file instead.
try:
    _LOG = open(os.environ.get("SIM_PP_LOG", "/run/sim/passpersist.log"), "a")
except OSError:
    _LOG = open(os.devnull, "w")
sys.stderr = _LOG


def log(msg):
    _LOG.write("passpersist[%d]: %s\n" % (os.getpid(), msg))
    _LOG.flush()


class Server:
    def __init__(self, root):
        self.root = root.strip(".")
        self.rootk = oid_key(self.root)
        self.step_ms = int(os.environ.get("SIM_STEP_MS", "10000"))
        self.state = StateStore(os.environ.get("SIM_STATE", "/run/sim/state.json"))
        self.model = get_model(os.environ.get("SIM_MODEL", "apc-ups"))(self.state, self.step_ms)
        self._cache_key = None
        self._keys = []
        self._rows = []

    def table(self):
        step = int(time.time() * 1000) // self.step_ms
        self.state.load()
        ck = (step, self.state._mtime)
        if ck != self._cache_key:
            rows, _ = self.model.snapshot(step)
            n = len(self.rootk)
            rows = [r for r in rows if r[0][:n] == self.rootk]
            self._rows = rows
            self._keys = [r[0] for r in rows]
            self._cache_key = ck
        return self._keys, self._rows

    @staticmethod
    def fmt(row):
        _k, oid, typ, val = row
        if typ == "OctetString":
            b = bytes.fromhex(val)
            if all(0x20 <= c < 0x7f for c in b):
                return ".%s\nstring\n%s\n" % (oid, b.decode("ascii"))
            return ".%s\noctet\n%s\n" % (oid, " ".join("%02x" % c for c in b))
        if typ == "OID":
            return ".%s\nobjectid\n.%s\n" % (oid, val)
        return ".%s\n%s\n%s\n" % (oid, PP_TYPES[typ], val)

    def get(self, oid):
        keys, rows = self.table()
        k = oid_key(oid)
        i = bisect_right(keys, k) - 1
        if i >= 0 and keys[i] == k:
            return self.fmt(rows[i])
        return "NONE\n"

    def getnext(self, oid):
        keys, rows = self.table()
        i = bisect_right(keys, oid_key(oid))
        if i < len(rows):
            return self.fmt(rows[i])
        return "NONE\n"

    def set(self, oid, tv):
        oid = oid.strip(".")
        word, _, rest = tv.partition(" ")
        typ = SET_TYPES.get(word.lower())
        if typ is None:
            return "wrong-type\n"
        rest = rest.strip()
        if len(rest) >= 2 and rest[0] == '"' and rest[-1] == '"':
            rest = rest[1:-1]
        if typ == "OctetString":
            if word.lower() == "octet":
                try:
                    val = bytes(int(x, 16) for x in rest.split()).hex()
                except ValueError:
                    return "wrong-value\n"
            else:
                val = rest.encode("utf-8").hex()
        elif typ in ("OID", "IpAddress"):
            val = rest.strip(".")
        else:
            val = rest
        step = int(time.time() * 1000) // self.step_ms
        try:
            stored = self.model.validate_write(oid, typ, val, step)
        except WriteError as e:
            return "%s\n" % e.args[0]
        self.state.put(oid, typ, stored)
        self._cache_key = None
        log("set %s %s = %s" % (oid, typ, stored))
        return "DONE\n"


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: passpersist.py <root-oid>")
    srv = Server(sys.argv[1])
    out = sys.stdout
    inp = sys.stdin
    trace = None
    if os.environ.get("SIM_PP_TRACE"):
        trace = open("/run/sim/pp-%s-%d.log" % (sys.argv[1].strip("."), os.getpid()), "a")
        _readline = inp.readline

        class _In:
            def readline(self):
                ln = _readline()
                trace.write("< %r\n" % ln)
                trace.flush()
                return ln
        inp = _In()

        class _Out:
            def write(self, s):
                trace.write("> %r\n" % s)
                trace.flush()
                sys.stdout.write(s)

            def flush(self):
                sys.stdout.flush()
        out = _Out()
    log("started for %s" % sys.argv[1])
    while True:
        line = inp.readline()
        if not line:
            log("EOF from snmpd, exiting")
            return
        cmd = line.strip().lower()
        if cmd == "":
            # snmpd terminates some requests (e.g. set) with an extra blank line
            continue
        try:
            if cmd == "ping":
                resp = "PONG\n"
            elif cmd == "get":
                resp = srv.get(inp.readline().strip())
            elif cmd == "getnext":
                resp = srv.getnext(inp.readline().strip())
            elif cmd == "set":
                oid = inp.readline().strip()
                tv = inp.readline().strip()
                resp = srv.set(oid, tv)
            else:
                resp = "NONE\n"
        except Exception as e:  # never kill snmpd's pipe on a model bug
            log("error handling %r: %r" % (cmd, e))
            resp = "NONE\n" if cmd != "set" else "inconsistent-value\n"
        out.write(resp)
        out.flush()


if __name__ == "__main__":
    main()
