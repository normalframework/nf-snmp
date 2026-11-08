#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""sim-quirky: a deliberately buggy SNMP v1/v2c agent (pysnmp low-level
proto API + pyasn1) with PDU-level fault injection, plus the same ground-truth
HTTP API as the device sims (docs/internals.md §2).

Faults (env SIM_FAULTS as JSON, e.g. '{"delayMs": 200, "bulkCrashAboveN": 10}',
and POST /set-fault {"kind": ..., "value"|"n"|"oid"|"enabled": ...}):

  bulkIgnoresMaxRep   GETBULK ignores max-repetitions and returns `n` (default 200)
                      repetitions (stopping only at end of MIB)
  bulkCrashAboveN     GETBULK with max-repetitions > n is silently dropped
  nonIncreasing       GETNEXT/GETBULK from `oid` returns `oid` again (walk loops)
  dropRate            fraction (0..1) of requests silently dropped
  delayMs             every response delayed by this many ms
  tooBigAboveN        tooBig error for any response with more than n varbinds
  counter32Wrap       qtOctets (Counter32) increments ~`rate` B/s (default 50e6),
                      so it wraps every ~86 s
  floatAsString       qtTemperature becomes a DisplayString like "23.5 C"
  noSuchInstanceGaps  qtValue has holes (rows where index % 4 == 3)
"""

import asyncio
import json
import os
import random
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from pyasn1.codec.ber import decoder, encoder
from pyasn1.error import PyAsn1Error
from pysnmp.proto import api

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from simcore import (Model, Obj, Var, StateStore, WriteError, wave, rint,  # noqa: E402
                     ramp_counter, check_int, check_str, norm_value, oid_key,
                     TWO32)

STEP_MS = int(os.environ.get("SIM_STEP_MS", "10000"))
HTTP_PORT = int(os.environ.get("SIM_HTTP_PORT", "8000"))
SNMP_PORT = int(os.environ.get("SIM_SNMP_PORT", "161"))
STATE_PATH = os.environ.get("SIM_STATE", "/run/sim/state.json")
ROWS = int(os.environ.get("SIM_QUIRKY_ROWS", "50"))

Q = "NF-QUIRKY-SIM (synthetic)"
QB = "1.3.6.1.4.1.99998.1.1"
SYS = "SNMPv2-MIB"


def log(msg):
    sys.stderr.write("quirkyd: %s\n" % msg)
    sys.stderr.flush()


# --------------------------------------------------------------------------
# faults
# --------------------------------------------------------------------------

FAULT_KINDS = {
    # kind: (param name, default)
    "bulkIgnoresMaxRep": ("n", 200),
    "bulkCrashAboveN": ("n", 10),
    "nonIncreasing": ("oid", QB + ".1.1.2.5"),
    "dropRate": ("value", 0.0),
    "delayMs": ("value", 0),
    "tooBigAboveN": ("n", 5),
    "counter32Wrap": ("rate", 50_000_000.0),
    "floatAsString": (None, True),
    "noSuchInstanceGaps": (None, True),
}


class Faults:
    def __init__(self):
        self.lock = threading.Lock()
        self.active = {}
        self.defaults = self.parse_env(os.environ.get("SIM_FAULTS", ""))
        self.reset()

    @staticmethod
    def parse_env(s):
        s = s.strip()
        if not s:
            return {}
        if s.startswith("{"):
            items = json.loads(s).items()
        else:  # "delayMs=100,noSuchInstanceGaps"
            items = []
            for part in s.split(","):
                k, _, v = part.strip().partition("=")
                items.append((k, json.loads(v) if v else True))
        out = {}
        for k, v in items:
            out.update(Faults.normalize(dict(v, kind=k) if isinstance(v, dict)
                                        else {"kind": k, "value": v}))
        return out

    @staticmethod
    def normalize(req):
        """{"kind", "value"|"n"|"oid"|"rate"|"enabled"} -> {kind: params or None}."""
        kind = req.get("kind")
        if kind not in FAULT_KINDS:
            raise ValueError("unknown fault kind %r (one of %s)" % (kind, ", ".join(FAULT_KINDS)))
        pname, default = FAULT_KINDS[kind]
        if req.get("enabled") is False:
            return {kind: None}
        if pname is None:
            return {kind: {"enabled": True} if req.get("value", True) else None}
        v = req.get(pname, req.get("value", default))
        if v is True:
            v = default
        if v is None or v is False:
            return {kind: None}
        if pname == "n":
            v = int(v)
        elif pname == "oid":
            v = str(v).strip(".")
        else:
            v = float(v)
            if pname == "value" and v == 0:
                return {kind: None}
        return {kind: {pname: v}}

    def apply(self, upd):
        with self.lock:
            for k, v in upd.items():
                if v is None:
                    self.active.pop(k, None)
                else:
                    self.active[k] = v

    def reset(self):
        with self.lock:
            self.active = {}
        self.apply(self.defaults)

    def get(self, kind):
        return self.active.get(kind)

    def snapshot(self):
        with self.lock:
            return json.loads(json.dumps(self.active))


faults = Faults()

# --------------------------------------------------------------------------
# data model
# --------------------------------------------------------------------------

O = {}


def o(mib, name, oid, typ, units=None, **kw):
    O[name] = Obj(mib, name, oid, typ, units=units, **kw)
    return O[name]


o(SYS, "sysDescr", "1.3.6.1.2.1.1.1", "OctetString")
o(SYS, "sysObjectID", "1.3.6.1.2.1.1.2", "OID")
o(SYS, "sysUpTime", "1.3.6.1.2.1.1.3", "TimeTicks", "s")
o(SYS, "sysName", "1.3.6.1.2.1.1.5", "OctetString")
o(SYS, "sysServices", "1.3.6.1.2.1.1.7", "Integer")
o(Q, "qtIndex", QB + ".1.1.1", "Integer")
o(Q, "qtName", QB + ".1.1.2", "OctetString")
o(Q, "qtTemperature", QB + ".1.1.3", "Integer", "degC")   # tenths, or string fault
o(Q, "qtValue", QB + ".1.1.4", "Gauge32", "%")
o(Q, "qtOctets", QB + ".1.1.5", "Counter32", "octets")
o(Q, "qtOctetsHC", QB + ".1.1.6", "Counter64", "octets")
o(Q, "qtSetpoint", QB + ".1.1.7", "Integer", "degC", writable=True, check=check_int(10, 35))
o(Q, "qtRowCount", QB + ".2", "Integer")
TEMP_STR = Obj(Q, "qtTemperature", QB + ".1.1.3", "OctetString", "degC")
# boot: start of the UTC day containing the step - keeps sysUpTime < 2^32 and deterministic
DAY_MS = 86_400_000


class Quirky(Model):
    name = "quirky"
    sysObjectID = "1.3.6.1.4.1.99998.1"
    sysDescr = "Quirky SNMP Agent 0.9 (nf-snmp fault injection simulator)"
    sysName = "quirky-1"
    contact = "nobody@example.com"
    location = "Lab bench"
    objects = list(O.values())

    def sample(self, step):
        at_ms = step * self.step_ms
        t = (at_ms - (at_ms // DAY_MS) * DAY_MS) / 1000.0  # seconds since "boot"
        tb = self.t_of(step)
        V = []

        def add(name, idx, raw, eng=None, units=None):
            V.append(Var(O[name], idx, raw, eng, units))

        add("sysDescr", 0, self.sysDescr)
        add("sysObjectID", 0, self.sysObjectID)
        up = rint(t * 100) % TWO32
        add("sysUpTime", 0, up, up / 100.0)
        add("sysName", 0, self.sysName)
        add("sysServices", 0, 72, 72)
        fs = faults.get("floatAsString")
        gaps = faults.get("noSuchInstanceGaps")
        cw = faults.get("counter32Wrap")
        for i in range(1, ROWS + 1):
            add("qtIndex", i, i, i)
            add("qtName", i, "sensor-%02d" % i)
            temp = wave("temp%d" % i, tb, 21.0 + (i % 7), 1.5, 900 + 13 * i, 0.1, step)
            tt = rint(temp * 10)
            if fs:
                V.append(Var(TEMP_STR, i, "%.1f C" % (tt / 10.0), tt / 10.0, "degC"))
            else:
                add("qtTemperature", i, tt, tt / 10.0)
            if not (gaps and i % 4 == 3):
                v = max(0, min(100, rint(wave("val%d" % i, tb, 50, 30, 600 + 7 * i, 2, step))))
                add("qtValue", i, v, float(v))
            rate = cw["rate"] if cw else 1000.0 * i
            # counter is defined from "boot" (t), so switching the fault on
            # gives a fast counter immediately (it is still f(step)).
            c = ramp_counter("oct%d" % i, t, rate, wobble=0.2)
            add("qtOctets", i, c % TWO32, c % TWO32)
            add("qtOctetsHC", i, c, c)
            sp = int(self.state.get("%s.%d" % (O["qtSetpoint"].oid, i), "22"))
            add("qtSetpoint", i, sp, float(sp))
        add("qtRowCount", 0, ROWS, ROWS)
        return V


state = StateStore(STATE_PATH)
model = Quirky(state, STEP_MS)

_cache = {"key": None}


def table():
    step = int(time.time() * 1000) // STEP_MS
    state.load()
    key = (step, state._mtime, json.dumps(faults.snapshot(), sort_keys=True))
    if key != _cache["key"]:
        rows, _ = model.snapshot(step)
        _cache.update(key=key, rows=rows, keys=[r[0] for r in rows],
                      idx={r[1]: r for r in rows}, step=step)
    return _cache


# --------------------------------------------------------------------------
# SNMP engine
# --------------------------------------------------------------------------

def to_asn1(pmod, v1, typ, val):
    if typ == "Integer":
        return pmod.Integer(int(val))
    if typ == "OctetString":
        return pmod.OctetString(hexValue=val) if val else pmod.OctetString("")
    if typ == "OID":
        return pmod.ObjectIdentifier(val)
    if typ == "IpAddress":
        return pmod.IpAddress(val)
    if typ == "TimeTicks":
        return pmod.TimeTicks(int(val))
    if typ == "Counter32":
        return (pmod.Counter if v1 else pmod.Counter32)(int(val))
    if typ == "Gauge32":
        return (pmod.Gauge if v1 else pmod.Gauge32)(int(val))
    if typ == "Counter64":
        return pmod.Counter64(int(val))
    raise ValueError(typ)


def from_asn1(value):
    """pyasn1 SET value -> (§1 type, normalized value)."""
    tn = value.__class__.__name__
    if tn in ("Integer", "Integer32"):
        return "Integer", str(int(value))
    if tn == "OctetString":
        return "OctetString", bytes(value).hex()
    if tn == "ObjectIdentifier":
        return "OID", str(value)
    if tn == "IpAddress":
        return "IpAddress", ".".join(str(b) for b in bytes(value))
    if tn in ("Counter", "Counter32"):
        return "Counter32", str(int(value))
    if tn in ("Gauge", "Gauge32", "Unsigned32"):
        return "Gauge32", str(int(value))
    if tn == "TimeTicks":
        return "TimeTicks", str(int(value))
    if tn == "Counter64":
        return "Counter64", str(int(value))
    return tn, ""


# error-status codes
NO_ERROR, TOO_BIG, NO_SUCH_NAME, BAD_VALUE, READ_ONLY, GEN_ERR = 0, 1, 2, 3, 4, 5
NO_ACCESS, WRONG_TYPE, WRONG_LENGTH, WRONG_VALUE, NO_CREATION, NOT_WRITABLE = 6, 7, 8, 10, 11, 17
V2_SET_ERR = {"not-writable": NOT_WRITABLE, "wrong-type": WRONG_TYPE,
              "wrong-length": WRONG_LENGTH, "wrong-value": WRONG_VALUE}
V1_SET_ERR = {"not-writable": NO_SUCH_NAME, "wrong-type": BAD_VALUE,
              "wrong-length": BAD_VALUE, "wrong-value": BAD_VALUE}
COMMUNITIES = {"public": "ro", "private": "rw"}


class Agent(asyncio.DatagramProtocol):
    def __init__(self):
        self.transport = None
        self.stats = {"rx": 0, "tx": 0, "dropped": 0, "badCommunity": 0, "decodeErrors": 0}

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.stats["rx"] += 1
        try:
            rsp = self.handle(data)
        except (PyAsn1Error, ValueError, KeyError, IndexError) as e:
            self.stats["decodeErrors"] += 1
            log("bad request from %s: %r" % (addr, e))
            return
        if rsp is None:
            self.stats["dropped"] += 1
            return
        dr = faults.get("dropRate")
        if dr and random.random() < dr["value"]:
            self.stats["dropped"] += 1
            return
        dl = faults.get("delayMs")
        if dl:
            asyncio.get_running_loop().call_later(dl["value"] / 1000.0, self.send, rsp, addr)
        else:
            self.send(rsp, addr)

    def send(self, rsp, addr):
        self.stats["tx"] += 1
        self.transport.sendto(rsp, addr)

    # -- request processing --
    def handle(self, data):
        ver = int(api.decodeMessageVersion(data))
        if ver not in (api.SNMP_VERSION_1, api.SNMP_VERSION_2C):
            return None
        v1 = ver == api.SNMP_VERSION_1
        pmod = api.PROTOCOL_MODULES[ver]
        req, _ = decoder.decode(data, asn1Spec=pmod.Message())
        community = bytes(pmod.apiMessage.get_community(req)).decode("latin-1")
        access = COMMUNITIES.get(community)
        if access is None:
            self.stats["badCommunity"] += 1
            return None  # like most agents: silently ignore (no authenticationFailure trap)
        rsp = pmod.apiMessage.get_response(req)
        reqpdu = pmod.apiMessage.get_pdu(req)
        rsppdu = pmod.apiMessage.get_pdu(rsp)
        vbs = pmod.apiPDU.get_varbinds(reqpdu)
        tab = table()

        if reqpdu.isSameTypeWith(pmod.GetRequestPDU()):
            out, err = self.do_get(pmod, v1, tab, vbs)
        elif reqpdu.isSameTypeWith(pmod.GetNextRequestPDU()):
            out, err = self.do_next(pmod, v1, tab, vbs)
        elif not v1 and reqpdu.isSameTypeWith(pmod.GetBulkRequestPDU()):
            nr = int(pmod.apiBulkPDU.get_non_repeaters(reqpdu))
            mr = int(pmod.apiBulkPDU.get_max_repetitions(reqpdu))
            bc = faults.get("bulkCrashAboveN")
            if bc and mr > bc["n"]:
                return None
            out, err = self.do_bulk(pmod, tab, vbs, nr, mr)
        elif reqpdu.isSameTypeWith(pmod.SetRequestPDU()):
            if access != "rw":
                # v2c: noAccess on the first varbind; v1: noSuchName
                out, err = list(vbs), ((NO_SUCH_NAME if v1 else NO_ACCESS), 1)
            else:
                out, err = self.do_set(pmod, v1, tab, vbs)
        else:
            return None

        tb = faults.get("tooBigAboveN")
        if err is None and tb and len(out) > tb["n"]:
            err = (TOO_BIG, 0)
        if err:
            # RFC 3416 4.2.1: v2c tooBig carries an empty varbind list;
            # otherwise (and in v1, RFC 1157) echo the request varbinds.
            pmod.apiPDU.set_varbinds(rsppdu, [] if (err[0] == TOO_BIG and not v1) else vbs)
            pmod.apiPDU.set_error_status(rsppdu, err[0])
            pmod.apiPDU.set_error_index(rsppdu, err[1])
        else:
            pmod.apiPDU.set_varbinds(rsppdu, out)
        return encoder.encode(rsp)

    @staticmethod
    def vb_of(pmod, v1, row):
        _k, oid, typ, val = row
        return (pmod.ObjectIdentifier(oid), to_asn1(pmod, v1, typ, val))

    def next_row(self, v1, tab, oid):
        """Lexicographic successor (honours the nonIncreasing fault)."""
        from bisect import bisect_right
        ni = faults.get("nonIncreasing")
        if ni and oid == ni["oid"] and ni["oid"] in tab["idx"]:
            return tab["idx"][ni["oid"]]           # same OID again -> walk loops
        keys = tab["keys"]
        i = bisect_right(keys, oid_key(oid))
        rows = tab["rows"]
        while i < len(rows):
            if v1 and rows[i][2] == "Counter64":   # v1 cannot carry Counter64
                i += 1
                continue
            return rows[i]
        return None

    def do_get(self, pmod, v1, tab, vbs):
        out = []
        for n, (oid, _v) in enumerate(vbs, 1):
            row = tab["idx"].get(str(oid))
            if row is None or (v1 and row[2] == "Counter64"):
                if v1:
                    return None, (NO_SUCH_NAME, n)
                # noSuchObject if no object has this prefix, else noSuchInstance
                s = str(oid)
                known = any(s.startswith(ob.oid + ".") or s == ob.oid for ob in model.all_objects())
                out.append((oid, pmod.NoSuchInstance("") if known else pmod.NoSuchObject("")))
            else:
                out.append(self.vb_of(pmod, v1, row))
        return out, None

    def do_next(self, pmod, v1, tab, vbs):
        out = []
        for n, (oid, _v) in enumerate(vbs, 1):
            row = self.next_row(v1, tab, str(oid))
            if row is None:
                if v1:
                    return None, (NO_SUCH_NAME, n)
                out.append((oid, pmod.EndOfMibView("")))
            else:
                out.append(self.vb_of(pmod, v1, row))
        return out, None

    def do_bulk(self, pmod, tab, vbs, nr, mr):
        nr = max(0, min(nr, len(vbs)))
        out = []
        for oid, _v in vbs[:nr]:
            row = self.next_row(False, tab, str(oid))
            out.append(self.vb_of(pmod, False, row) if row else (oid, pmod.EndOfMibView("")))
        rep = list(vbs[nr:])
        ig = faults.get("bulkIgnoresMaxRep")
        reps = ig["n"] if ig else max(0, mr)
        cur = [str(oid) for oid, _v in rep]
        for _r in range(reps):
            if not cur:
                break
            all_end = True
            for j, oid in enumerate(cur):
                row = self.next_row(False, tab, oid)
                if row is None:
                    out.append((pmod.ObjectIdentifier(oid), pmod.EndOfMibView("")))
                else:
                    all_end = False
                    out.append(self.vb_of(pmod, False, row))
                    cur[j] = row[1]
            if all_end:
                break
            if len(out) > 2000:   # keep the datagram under 64 KiB
                break
        return out, None

    def do_set(self, pmod, v1, tab, vbs):
        errmap = V1_SET_ERR if v1 else V2_SET_ERR
        step = int(time.time() * 1000) // STEP_MS
        staged = []
        for n, (oid, val) in enumerate(vbs, 1):
            typ, nv = from_asn1(val)
            try:
                stored = model.validate_write(str(oid), typ, nv, step)
            except WriteError as e:
                return None, (errmap.get(e.args[0], GEN_ERR), n)
            staged.append((str(oid), typ, stored))
        for oid, typ, stored in staged:
            state.put(oid, typ, stored)
        return list(vbs), None


agent = Agent()

# --------------------------------------------------------------------------
# HTTP API
# --------------------------------------------------------------------------


def truth(at_ms):
    step = at_ms // STEP_MS
    rows, eng = model.snapshot(step)
    return {"at": at_ms, "step": step, "stepMs": STEP_MS,
            "raw": {oid: {"type": typ, "value": val} for _k, oid, typ, val in rows},
            "eng": eng, "faults": faults.snapshot()}


def info():
    tab = table()
    wobjs = model.writable_objects()
    return {
        "model": model.name, "simModel": "quirky",
        "sysObjectID": model.sysObjectID, "sysDescr": model.sysDescr,
        "stepMs": STEP_MS, "communities": COMMUNITIES, "users": [],
        "writable": [r[1] for r in tab["rows"]
                     if any(r[1].startswith(ob.oid + ".") for ob in wobjs)],
        "faults": faults.snapshot(),
        "faultKinds": {k: v[0] for k, v in FAULT_KINDS.items()},
        "stats": dict(agent.stats),
        "roots": ["1.3.6.1.4.1.99998"],
        "trapOID": "1.3.6.1.6.3.1.1.5.1",
    }


def send_trap(req):
    target = req.get("target")
    if not target:
        raise ValueError("target required (host:port)")
    version = str(req.get("version", "2c"))
    inform = bool(req.get("inform", False))
    if version not in ("1", "2c"):
        raise ValueError("sim-quirky supports only v1/v2c")
    if inform and version == "1":
        raise ValueError("SNMPv1 has no inform")
    host = target if target.startswith(("udp:", "tcp:")) else "udp:" + target
    args = ["snmpinform" if inform else "snmptrap", "-v", version,
            "-c", req.get("community", "public"), "-r", "1", "-t", "2", host]
    vbs = [("1.3.6.1.2.1.1.5.0", "OctetString", model.sysName)]
    if version == "1":   # coldStart: generic 0
        args += ["." + model.sysObjectID, "", "0", "0", ""]
    else:
        args += ["", ".1.3.6.1.6.3.1.1.5.1"]
    args += [".1.3.6.1.2.1.1.5.0", "s", model.sysName]
    p = subprocess.run(args, capture_output=True, text=True, timeout=30)
    return {"ok": p.returncode == 0, "rc": p.returncode, "stderr": p.stderr.strip(),
            "version": version, "inform": inform, "trapOID": "1.3.6.1.6.3.1.1.5.1",
            "v1": {"enterprise": model.sysObjectID, "generic": 0, "specific": 0}
            if version == "1" else None,
            "varbinds": [{"oid": o_, "type": t_, "value": norm_value(t_, v_)}
                         for o_, t_, v_ in vbs]}


class Handler(BaseHTTPRequestHandler):
    server_version = "nfsnmp-quirky/1"

    def log_message(self, fmt, *args):
        if os.environ.get("SIM_HTTP_LOG"):
            log("http " + fmt % args)

    def reply(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}") if n else {}

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        try:
            if u.path == "/info":
                return self.reply(200, info())
            if u.path == "/truth":
                at = int(q["at"][0]) if "at" in q else int(time.time() * 1000)
                return self.reply(200, truth(at))
            if u.path in ("/", "/health"):
                return self.reply(200, {"ok": True, "model": model.name})
            return self.reply(404, {"error": "not found"})
        except Exception as e:  # pragma: no cover
            return self.reply(500, {"error": repr(e)})

    def do_POST(self):
        u = urlparse(self.path)
        try:
            if u.path == "/reset":
                state.reset()
                faults.reset()
                return self.reply(200, {"ok": True, "faults": faults.snapshot()})
            if u.path == "/set-fault":
                b = self.body()
                if b.get("kind") in ("none", "clear"):
                    faults.apply({k: None for k in FAULT_KINDS})
                else:
                    faults.apply(Faults.normalize(b))
                return self.reply(200, {"ok": True, "faults": faults.snapshot()})
            if u.path == "/trap":
                r = send_trap(self.body())
                return self.reply(200 if r["ok"] else 502, r)
            return self.reply(404, {"error": "not found"})
        except ValueError as e:
            return self.reply(400, {"error": str(e)})
        except Exception as e:  # pragma: no cover
            return self.reply(500, {"error": repr(e)})


async def amain():
    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(lambda: agent, local_addr=("0.0.0.0", SNMP_PORT))
    log("SNMP v1/v2c on udp/%d, HTTP on :%d, faults=%s" % (SNMP_PORT, HTTP_PORT,
                                                            json.dumps(faults.snapshot())))
    await asyncio.Event().wait()


def main():
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    state.reset()
    httpd = ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), Handler)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
