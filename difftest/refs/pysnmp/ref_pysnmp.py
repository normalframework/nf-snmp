#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""ref-pysnmp: difftest reference client built on pysnmp (LeXtudio fork, pinned in
requirements.txt), asyncio v3arch hlapi.

Reads one JSON request on stdin, writes docs/internals.md §1 JSON lines on stdout.

Walks use single-shot next_cmd / bulk_cmd (not walk_cmd / bulk_walk_cmd, whose
lexicographicMode / ignoreNonIncreasingOid handling would hide the shared stop rules in
difftest/README.md).

pysnmp caveats handled here:
  * pysnmp presents every response as SMIv2: a v1 noSuchName response keeps its error-status
    but its varbinds are rewritten (endOfMibView for GETNEXT, noSuchObject otherwise,
    RFC 2576 4.1.2.2). We act on the error-status only.
  * USM_PRIV_CFB256_AES is the *Reeder* key extension; Blumenthal is
    USM_PRIV_CFB256_AES_BLUMENTHAL.
"""
import asyncio
import json
import socket
import sys

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData, ContextData, ObjectIdentity, ObjectType, SnmpEngine, UdpTransportTarget,
    UsmUserData, bulk_cmd, get_cmd, next_cmd, set_cmd)
from pysnmp.hlapi.v3arch.asyncio import auth as A
from pysnmp.proto import rfc1902, rfc1905

AUTH = {"none": A.USM_AUTH_NONE, "md5": A.USM_AUTH_HMAC96_MD5, "sha": A.USM_AUTH_HMAC96_SHA,
        "sha224": A.USM_AUTH_HMAC128_SHA224, "sha256": A.USM_AUTH_HMAC192_SHA256,
        "sha384": A.USM_AUTH_HMAC256_SHA384, "sha512": A.USM_AUTH_HMAC384_SHA512}
PRIV = {"none": A.USM_PRIV_NONE, "des": A.USM_PRIV_CBC56_DES, "aes": A.USM_PRIV_CFB128_AES,
        "aes256b": A.USM_PRIV_CFB256_AES_BLUMENTHAL, "aes256r": A.USM_PRIV_CFB256_AES}

STATUS_NAMES = ["noError", "tooBig", "noSuchName", "badValue", "readOnly", "genErr",
                "noAccess", "wrongType", "wrongLength", "wrongEncoding", "wrongValue",
                "noCreation", "inconsistentValue", "resourceUnavailable", "commitFailed",
                "undoFailed", "authorizationError", "notWritable", "inconsistentName"]
DIRECT = {"tooBig", "noSuchName", "badValue", "readOnly", "genErr", "noAccess", "wrongType",
          "notWritable"}
AUTH_INDICATIONS = {"UnknownUserName", "WrongDigest", "UnsupportedSecurityLevel",
                    "DecryptionError", "NotInTimeWindow", "UnknownEngineID",
                    "UnknownSecurityName", "AuthenticationError", "AuthenticationFailure"}
MAX_WALK = 200000


def emit(obj):
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")


class SnmpError(Exception):
    def __init__(self, cls, msg, **extra):
        super().__init__(msg)
        self.cls, self.msg, self.extra = cls, msg, extra


def status_error(status, index):
    s = int(status)
    name = STATUS_NAMES[s] if s < len(STATUS_NAMES) else "status%d" % s
    cls = name if name in DIRECT else ("noAccess" if name == "authorizationError" else "other")
    return SnmpError(cls, name, status=name, index=int(index))


def indication_error(ind):
    name = type(ind).__name__
    text = str(ind)
    if name == "RequestTimedOut" or "timeout" in text.lower() or "timed out" in text.lower():
        return SnmpError("timeout", text)
    if name in AUTH_INDICATIONS or any(k in text.lower() for k in (
            "unknown user", "wrong digest", "security level", "decryption", "time window",
            "engine id", "authentic")):
        return SnmpError("authError", "%s: %s" % (name, text))
    if "too big" in text.lower() or name == "TooBig":
        return SnmpError("tooBig", text)
    if "decod" in text.lower() or "parse" in text.lower():
        return SnmpError("decodeError", text)
    return SnmpError("other", "%s: %s" % (name, text))


def norm_oid(s):
    return str(s).strip().lstrip(".")


def oid_arcs(s):
    s = norm_oid(s)
    return [int(x) for x in s.split(".")] if s else []


def ts(cls):
    return cls.tagSet


def normalize(val):
    t = val.tagSet
    if t == rfc1905.EndOfMibView.tagSet:
        return "EndOfMibView", ""
    if t == rfc1905.NoSuchObject.tagSet:
        return "NoSuchObject", ""
    if t == rfc1905.NoSuchInstance.tagSet:
        return "NoSuchInstance", ""
    if t == rfc1902.Integer32.tagSet:
        return "Integer", str(int(val))
    if t == rfc1902.Counter32.tagSet:
        return "Counter32", str(int(val))
    if t == rfc1902.Gauge32.tagSet:
        return "Gauge32", str(int(val))
    if t == rfc1902.TimeTicks.tagSet:
        return "TimeTicks", str(int(val))
    if t == rfc1902.Counter64.tagSet:
        return "Counter64", str(int(val))
    if t == rfc1902.IpAddress.tagSet:
        return "IpAddress", socket.inet_ntoa(bytes(val))
    if t == rfc1902.Opaque.tagSet:
        return "Opaque", bytes(val).hex()
    if t == rfc1902.OctetString.tagSet:
        return "OctetString", bytes(val).hex()
    if t == rfc1902.ObjectIdentifier.tagSet:
        return "OID", ".".join(str(x) for x in val)
    if t == rfc1902.Null.tagSet:
        return "Null", ""
    return "Unknown(%s)" % type(val).__name__, val.prettyPrint()


def make_auth(t):
    v = str(t.get("version", "2c"))
    if v == "1":
        return CommunityData(t.get("community") or "public", mpModel=0)
    if v in ("2c", "2"):
        return CommunityData(t.get("community") or "public", mpModel=1)
    if v == "3":
        ap = (t.get("authProtocol") or "none").lower()
        pp = (t.get("privProtocol") or "none").lower()
        if ap not in AUTH:
            raise SnmpError("other", "unsupported authProtocol %s" % ap)
        if pp not in PRIV:
            raise SnmpError("other", "unsupported privProtocol %s" % pp)
        kw = {}
        if ap != "none":
            kw.update(authKey=t.get("authKey") or "", authProtocol=AUTH[ap])
            if pp != "none":
                kw.update(privKey=t.get("privKey") or "", privProtocol=PRIV[pp])
        return UsmUserData(t.get("user") or "", **kw)
    raise SnmpError("other", "unsupported version %s" % v)


def flatten(vbs):
    out = []
    for x in vbs:
        if isinstance(x, (list, tuple)) and x and isinstance(x[0], (list, tuple, ObjectType)):
            out.extend(x)
        else:
            out.append(x)
    return out


class Client:
    def __init__(self, t):
        self.t = t
        self.v1 = str(t.get("version")) == "1"
        self.auth = make_auth(t)
        self.engine = SnmpEngine()
        self.ctx = ContextData(contextName=t.get("context") or "")
        self.transport = None

    async def open(self):
        timeout = (self.t.get("timeoutMs") or 2000) / 1000.0
        retries = self.t.get("retries")
        if retries is None:
            retries = 1
        try:
            self.transport = await UdpTransportTarget.create(
                (self.t["host"], int(self.t.get("port") or 161)), timeout=timeout,
                retries=int(retries))
        except Exception as e:  # noqa: BLE001  (resolution failures)
            raise SnmpError("other", str(e))

    def close(self):
        try:
            self.engine.close_dispatcher()
        except Exception:  # noqa: BLE001
            pass

    def check(self, res, walk=False):
        ind, status, index, vbs = res
        if ind:
            raise indication_error(ind)
        if status and int(status):
            if walk and self.v1 and int(status) == 2:
                return None  # v1 end of MIB view
            raise status_error(status, index)
        return [(norm_oid(o), v) for o, v in flatten(vbs)]

    async def get(self, oids):
        res = await get_cmd(self.engine, self.auth, self.transport, self.ctx,
                            *[ObjectType(ObjectIdentity(o)) for o in oids], lookupMib=False)
        return self.check(res)

    async def next(self, oid):
        res = await next_cmd(self.engine, self.auth, self.transport, self.ctx,
                             ObjectType(ObjectIdentity(oid)), lookupMib=False)
        return self.check(res, walk=True)

    async def bulk(self, oid, max_rep):
        res = await bulk_cmd(self.engine, self.auth, self.transport, self.ctx, 0, max_rep,
                             ObjectType(ObjectIdentity(oid)), lookupMib=False)
        return self.check(res, walk=True)

    async def set(self, pairs):
        res = await set_cmd(self.engine, self.auth, self.transport, self.ctx,
                            *[ObjectType(ObjectIdentity(o), v) for o, v in pairs],
                            lookupMib=False)
        return self.check(res)


def emit_vbs(vbs):
    for oid, val in vbs:
        t, v = normalize(val)
        emit({"oid": oid, "type": t, "value": v})


async def do_walk(c, root, bulk, max_rep):
    root_arcs = oid_arcs(root)
    last = root_arcs
    cur = norm_oid(root)
    n = 0
    while True:
        vbs = await (c.bulk(cur, max_rep) if bulk else c.next(cur))
        if not vbs:
            return
        for oid, val in vbs:
            t, v = normalize(val)
            if t in ("EndOfMibView", "NoSuchObject", "NoSuchInstance"):
                return
            arcs = oid_arcs(oid)
            if len(arcs) <= len(root_arcs) or arcs[:len(root_arcs)] != root_arcs:
                return
            if arcs <= last:
                emit({"error": "nonIncreasing",
                      "message": "%s after %s" % (oid, ".".join(map(str, last)))})
                return
            emit({"oid": oid, "type": t, "value": v})
            last = arcs
            n += 1
            if n >= MAX_WALK:
                emit({"error": "other", "message": "walk limit reached"})
                return
        cur = ".".join(map(str, last))


def make_value(vb):
    t, v = vb["type"], vb.get("value", "")
    if t == "Integer":
        return rfc1902.Integer32(int(v))
    if t == "OctetString":
        return rfc1902.OctetString(hexValue=v)
    if t == "OID":
        return rfc1902.ObjectIdentifier(norm_oid(v))
    if t == "IpAddress":
        return rfc1902.IpAddress(v)
    if t == "Counter32":
        return rfc1902.Counter32(int(v))
    if t == "Gauge32":
        return rfc1902.Gauge32(int(v))
    if t == "TimeTicks":
        return rfc1902.TimeTicks(int(v))
    if t == "Counter64":
        return rfc1902.Counter64(int(v))
    if t == "Opaque":
        return rfc1902.Opaque(hexValue=v)
    if t == "Null":
        return rfc1902.Null("")
    raise SnmpError("other", "pysnmp cannot SET type %s" % t)


async def amain(req):
    t = req["target"]
    op = req["op"]
    c = Client(t)
    try:
        await c.open()
        if op == "get":
            emit_vbs(await c.get([norm_oid(o) for o in req.get("oids", [])]))
        elif op == "walk":
            await do_walk(c, req["root"], False, 0)
        elif op == "bulkwalk":
            if c.v1:
                raise SnmpError("other", "GETBULK not supported in SNMPv1")
            await do_walk(c, req["root"], True, int(req.get("maxRepetitions") or 10))
        elif op == "set":
            pairs = [(norm_oid(vb["oid"]), make_value(vb)) for vb in req.get("varbinds", [])]
            emit_vbs(await c.set(pairs))
        else:
            raise ValueError("unknown op %s" % op)
    finally:
        c.close()


def main():
    try:
        req = json.load(sys.stdin)
    except Exception as e:  # noqa: BLE001
        print("bad request: %s" % e, file=sys.stderr)
        return 2
    try:
        asyncio.run(amain(req))
    except SnmpError as e:
        o = {"error": e.cls, "message": e.msg}
        o.update(e.extra)
        emit(o)
    except ValueError as e:
        if str(e).startswith("unknown op"):
            print(str(e), file=sys.stderr)
            return 2
        emit({"error": "other", "message": "%s: %s" % (type(e).__name__, e)})
    except Exception as e:  # noqa: BLE001  (pysnmp raises assorted errors, e.g. PyAsn1Error)
        cls = "decodeError" if "asn1" in type(e).__module__.lower() else "other"
        emit({"error": cls, "message": "%s: %s" % (type(e).__name__, e)})
    return 0


if __name__ == "__main__":
    sys.exit(main())
