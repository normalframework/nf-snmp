#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Generated SNMP simulator: one process serving many simulated devices (one UDP port each) from a
spec built by genspec.js. pysnmp low-level proto API (an SNMP stack independent of nf-snmp's
net-snmp client). v1/v2c, community "public", GET/GETNEXT/GETBULK.

  python3 gensimd.py spec.json [--http 8000]

HTTP:  GET /devices                     -> [{id, port, sysObjectID}]
       GET /truth?device=<id>&at=<ms>   -> {at, step, raw: {oid: {type, value}}, eng: {key: {value}}}
"""
import asyncio
import json
import math
import sys
import threading
import time
from bisect import bisect_right
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from pyasn1.codec.ber import decoder, encoder
from pyasn1.error import PyAsn1Error
from pysnmp.proto import api

SPEC = json.load(open(sys.argv[1]))
STEP_MS = SPEC.get("stepMs", 10000)
HTTP_PORT = int(sys.argv[sys.argv.index("--http") + 1]) if "--http" in sys.argv else 8000
SYS = "1.3.6.1.2.1.1"


def okey(oid):
    return tuple(int(x) for x in oid.split("."))


def raw_value(o, step):
    k = o["kind"]
    if k == "const":
        return o["value"]
    if k == "text":
        return o["value"]
    if k == "enum":
        v = o["values"]
        return v[(step + o["phase"]) % len(v)]
    if k == "counter":
        return (o["base"] + o["rate"] * step) % (2 ** o["bits"])
    if k in ("wave", "textnum"):
        v = round(o["center"] + o["amp"] * math.sin(2 * math.pi * (step + o["phase"]) / o["period"]))
        return max(o["lo"], min(o["hi"], v))
    raise ValueError(k)


def sample(dev, step):
    """[(okey, oid, type, value)] sorted, plus eng truth."""
    rows, eng = [], {}
    sysrows = [("%s.1.0" % SYS, "OctetString", dev["sysDescr"].encode().hex()),
               ("%s.2.0" % SYS, "OID", dev["sysObjectID"]),
               ("%s.3.0" % SYS, "TimeTicks", (step * STEP_MS // 10) % (2 ** 32)),
               ("%s.4.0" % SYS, "OctetString", b"gensim".hex()),
               ("%s.5.0" % SYS, "OctetString", dev["sysName"].encode().hex()),
               ("%s.6.0" % SYS, "OctetString", b"lab".hex())]
    for oid, typ, val in sysrows:
        rows.append((okey(oid), oid, typ, val))
    for o in dev["objects"]:
        if o["oid"].startswith(SYS + "."):
            continue
        rv = raw_value(o, step)
        typ, val = o["type"], rv
        if o["kind"] == "textnum":
            num = round(rv * o["mult"], o.get("decimals", 1))
            text = ("%.*f" % (o.get("decimals", 1), num))
            typ, val = "OctetString", o["template"].replace("{}", text, 1).encode().hex()
            if o.get("key"):
                eng[o["key"]] = {"value": num}
        elif o.get("key") and o["kind"] in ("wave", "enum", "counter", "const"):
            eng[o["key"]] = {"value": round(rv * o.get("mult", 1) + o.get("offset", 0), 9)}
        rows.append((okey(o["oid"]), o["oid"], typ, val))
    rows.sort()
    return rows, eng


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
        return (pmod.Gauge if v1 else pmod.Gauge32)(int(val) & 0xFFFFFFFF)
    if typ == "Counter64":
        return pmod.Counter64(int(val))
    raise ValueError(typ)


class Agent(asyncio.DatagramProtocol):
    def __init__(self, dev):
        self.dev = dev
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        try:
            rsp = self.handle(data)
        except (PyAsn1Error, ValueError, KeyError, IndexError):
            return
        if rsp is not None:
            self.transport.sendto(rsp, addr)

    def handle(self, data):
        ver = int(api.decodeMessageVersion(data))
        if ver not in (api.SNMP_VERSION_1, api.SNMP_VERSION_2C):
            return None
        v1 = ver == api.SNMP_VERSION_1
        pmod = api.PROTOCOL_MODULES[ver]
        req, _ = decoder.decode(data, asn1Spec=pmod.Message())
        if bytes(pmod.apiMessage.get_community(req)) != b"public":
            return None
        rsp = pmod.apiMessage.get_response(req)
        reqpdu = pmod.apiMessage.get_pdu(req)
        rsppdu = pmod.apiMessage.get_pdu(rsp)
        vbs = pmod.apiPDU.get_varbinds(reqpdu)
        rows, _ = sample(self.dev, int(time.time() * 1000) // STEP_MS)
        if v1:
            rows = [r for r in rows if r[2] != "Counter64"]
        idx = {r[1]: r for r in rows}
        keys = [r[0] for r in rows]

        def nxt(oid):
            i = bisect_right(keys, okey(oid))
            return rows[i] if i < len(rows) else None

        vb = lambda r: (pmod.ObjectIdentifier(r[1]), to_asn1(pmod, v1, r[2], r[3]))
        out, err = [], None
        if reqpdu.isSameTypeWith(pmod.GetRequestPDU()):
            for n, (oid, _v) in enumerate(vbs, 1):
                r = idx.get(str(oid))
                if r is None:
                    if v1:
                        err = (2, n)
                        break
                    out.append((oid, pmod.NoSuchInstance("")))
                else:
                    out.append(vb(r))
        elif reqpdu.isSameTypeWith(pmod.GetNextRequestPDU()):
            for n, (oid, _v) in enumerate(vbs, 1):
                r = nxt(str(oid))
                if r is None:
                    if v1:
                        err = (2, n)
                        break
                    out.append((oid, pmod.EndOfMibView("")))
                else:
                    out.append(vb(r))
        elif not v1 and reqpdu.isSameTypeWith(pmod.GetBulkRequestPDU()):
            nr = max(0, min(int(pmod.apiBulkPDU.get_non_repeaters(reqpdu)), len(vbs)))
            mr = int(pmod.apiBulkPDU.get_max_repetitions(reqpdu))
            for oid, _v in vbs[:nr]:
                r = nxt(str(oid))
                out.append(vb(r) if r else (oid, pmod.EndOfMibView("")))
            cur = [str(oid) for oid, _v in vbs[nr:]]
            for _ in range(max(0, mr)):
                if not cur or len(out) > 1500:
                    break
                ended = True
                for j, oid in enumerate(cur):
                    r = nxt(oid)
                    if r is None:
                        out.append((pmod.ObjectIdentifier(oid), pmod.EndOfMibView("")))
                    else:
                        ended = False
                        out.append(vb(r))
                        cur[j] = r[1]
                if ended:
                    break
        else:
            return None
        if err:
            pmod.apiPDU.set_varbinds(rsppdu, vbs)
            pmod.apiPDU.set_error_status(rsppdu, err[0])
            pmod.apiPDU.set_error_index(rsppdu, err[1])
        else:
            pmod.apiPDU.set_varbinds(rsppdu, out)
        return encoder.encode(rsp)


BY_ID = {d["id"]: d for d in SPEC["devices"]}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/health":
            return self.reply(200, {"ok": True, "devices": len(BY_ID)})
        if u.path == "/devices":
            return self.reply(200, [{"id": d["id"], "port": d["port"], "sysObjectID": d["sysObjectID"]} for d in SPEC["devices"]])
        if u.path == "/truth":
            dev = BY_ID.get((q.get("device") or [""])[0])
            if not dev:
                return self.reply(404, {"error": "unknown device"})
            at = int((q.get("at") or [int(time.time() * 1000)])[0])
            step = at // STEP_MS
            rows, eng = sample(dev, step)
            return self.reply(200, {"at": at, "step": step, "raw": {r[1]: {"type": r[2], "value": str(r[3])} for r in rows}, "eng": eng})
        self.reply(404, {"error": "not found"})


async def main():
    loop = asyncio.get_running_loop()
    for d in SPEC["devices"]:
        await loop.create_datagram_endpoint(lambda d=d: Agent(d), local_addr=("0.0.0.0", d["port"]))
    srv = ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print("gensimd: %d devices on udp %d..%d, http %d" % (len(SPEC["devices"]), SPEC["devices"][0]["port"], SPEC["devices"][-1]["port"], HTTP_PORT), flush=True)
    await asyncio.Event().wait()


asyncio.run(main())
