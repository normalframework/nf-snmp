#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""ref-netsnmp: difftest reference client wrapping the net-snmp C command line tools.

Reads one JSON request on stdin, writes docs/internals.md §1 JSON lines on stdout.

Every SNMP request is one invocation of snmpget / snmpgetnext / snmpbulkget / snmpset with
numeric, MIB-less output (-On -Oe -Ox -OU, MIBS=""; -Ot is NOT used: without MIBs it drops the type tag), parsed back into §1.  Walks are a loop
of snmpgetnext / snmpbulkget processes so the stop rules are exactly the shared ones (see
difftest/README.md); snmpwalk/snmpbulkwalk are not used because they apply their own rules
(e.g. they print the offending varbind before "OID not increasing", fall back to GET on an
empty walk, and treat an OID below the root as in-subtree).
"""
import json
import os
import re
import struct
import subprocess
import sys
import tempfile

AUTH = {"md5": "MD5", "sha": "SHA", "sha224": "SHA-224", "sha256": "SHA-256",
        "sha384": "SHA-384", "sha512": "SHA-512"}
PRIV = {"des": "DES", "aes": "AES", "aes256b": "AES256", "aes256r": "AES256C"}

STATUS_NAMES = ["noError", "tooBig", "noSuchName", "badValue", "readOnly", "genErr",
                "noAccess", "wrongType", "wrongLength", "wrongEncoding", "wrongValue",
                "noCreation", "inconsistentValue", "resourceUnavailable", "commitFailed",
                "undoFailed", "authorizationError", "notWritable", "inconsistentName"]
DIRECT = {"tooBig", "noSuchName", "badValue", "readOnly", "genErr", "noAccess", "wrongType",
          "notWritable"}

MAX_WALK = 200000


def emit(obj):
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")


def emit_err(cls, msg, **extra):
    o = {"error": cls, "message": msg}
    o.update(extra)
    emit(o)


def status_class(name):
    if name in DIRECT:
        return name
    if name == "authorizationError":
        return "noAccess"
    return "other"


class SnmpError(Exception):
    def __init__(self, cls, msg, **extra):
        super().__init__(msg)
        self.cls, self.msg, self.extra = cls, msg, extra


def norm_oid(s):
    return s.strip().lstrip(".")


def oid_arcs(s):
    s = norm_oid(s)
    return [int(x) for x in s.split(".")] if s else []


def common_args(t):
    v = str(t.get("version", "2c"))
    timeout = t.get("timeoutMs") or 2000
    retries = t.get("retries")
    if retries is None:
        retries = 1
    args = ["-t", "%g" % (timeout / 1000.0), "-r", str(retries)]
    if v == "1":
        args += ["-v1", "-c", t.get("community") or "public"]
    elif v in ("2c", "2"):
        args += ["-v2c", "-c", t.get("community") or "public"]
    elif v == "3":
        ap = (t.get("authProtocol") or "none").lower()
        pp = (t.get("privProtocol") or "none").lower()
        args += ["-v3", "-u", t.get("user") or ""]
        if ap == "none":
            args += ["-l", "noAuthNoPriv"]
        else:
            if ap not in AUTH:
                raise SnmpError("other", "unsupported authProtocol %s" % ap)
            args += ["-a", AUTH[ap], "-A", t.get("authKey") or ""]
            if pp == "none":
                args += ["-l", "authNoPriv"]
            else:
                if pp not in PRIV:
                    raise SnmpError("other", "unsupported privProtocol %s" % pp)
                args += ["-l", "authPriv", "-x", PRIV[pp], "-X", t.get("privKey") or ""]
        if t.get("context"):
            args += ["-n", t["context"]]
    else:
        raise SnmpError("other", "unsupported version %s" % v)
    host = t["host"]
    if ":" in host and not host.startswith("["):
        host = "[%s]" % host
    args.append("udp:%s:%d" % (host, int(t.get("port") or 161)))
    return args


OUT_FLAGS = ["-On", "-Oe", "-Ox", "-OU", "-Op", ".17g", "-Le"]

_env = None


def env():
    global _env
    if _env is None:
        d = tempfile.mkdtemp(prefix="ref-netsnmp-")
        _env = dict(os.environ, MIBS="", MIBDIRS=d, SNMP_PERSISTENT_DIR=d, SNMPCONFPATH=d,
                    HOME=d)
    return _env


EXC = {
    "No Such Object available on this agent at this OID": "NoSuchObject",
    "No Such Instance currently exists at this OID": "NoSuchInstance",
}


def parse_hex(s):
    s = s.strip()
    if s in ('""', ""):
        return ""
    return "".join(s.split()).lower()


def parse_value(rest):
    """Parse the right-hand side of 'OID = ...' into (type, value)."""
    rest = rest.strip()
    if rest in EXC:
        return EXC[rest], ""
    if rest.startswith("No more variables left in this MIB View"):
        return "EndOfMibView", ""
    if rest == "NULL" or rest.startswith("NULL"):
        return "Null", ""
    if rest == '""':
        return "OctetString", ""
    m = re.match(r"^([A-Za-z0-9 -]+?):\s?(.*)$", rest, re.S)
    if not m:
        raise SnmpError("decodeError", "unparseable value: %r" % rest)
    tag, val = m.group(1), m.group(2)
    if tag == "INTEGER":
        return "Integer", val.strip()
    if tag in ("Hex-STRING", "STRING"):
        if tag == "STRING":
            # Only reached for values -Ox could not hexify (should not happen); hex the text.
            v = val.strip()
            if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
                v = v[1:-1]
            return "OctetString", v.encode("latin-1", "replace").hex()
        return "OctetString", parse_hex(val)
    if tag == "OID":
        return "OID", norm_oid(val)
    if tag == "IpAddress":
        return "IpAddress", val.strip()
    if tag in ("Counter32", "Gauge32", "Counter64", "UInteger32", "Unsigned32"):
        t = {"UInteger32": "Gauge32", "Unsigned32": "Gauge32"}.get(tag, tag)
        return t, val.strip()
    if tag == "Timeticks":
        v = val.strip()
        m2 = re.match(r"^\((\d+)\)", v)  # in case -Ot was ignored
        return "TimeTicks", m2.group(1) if m2 else v
    if tag in ("Opaque", "OPAQUE"):
        # net-snmp decodes the net-snmp Opaque-wrapped float/double extensions and prints both
        # as "Opaque: Float: <num>" (it never says "Double"). Re-encode as raw Opaque content:
        # float32 if the number round-trips through float32, else double (heuristic; a double
        # holding a float32-representable value is re-encoded as a float -> allowlisted).
        m2 = re.match(r"^(Float|Double|I64|U64|Counter64):\s*(.*?)f?$", val.strip())
        if m2:
            kind, num = m2.group(1), m2.group(2).strip()
            if kind in ("Float", "Double"):
                x = float(num)
                f32 = struct.unpack(">f", struct.pack(">f", x))[0]
                if f32 == x or (x != x):
                    return "Opaque", "9f7804" + struct.pack(">f", x).hex()
                return "Opaque", "9f7908" + struct.pack(">d", x).hex()
            return "Opaque", "%s:%s" % (kind, num)  # not re-encodable faithfully; will diff
        return "Opaque", parse_hex(val)
    if tag == "BITS":
        return "OctetString", parse_hex(val.split("  ")[0] if val else "")
    if tag == "Network Address":
        return "IpAddress", ".".join(str(int(x, 16)) for x in val.strip().split(":"))
    raise SnmpError("decodeError", "unknown type tag %r" % tag)


VB_START = re.compile(r"^(\.?\d+(?:\.\d+)*) = (.*)$")


def parse_varbinds(stdout):
    """Group lines into varbinds (Hex-STRING values continue onto following lines)."""
    vbs = []
    cur = None
    for line in stdout.split("\n"):
        m = VB_START.match(line)
        if m:
            if cur:
                vbs.append(cur)
            cur = [m.group(1), m.group(2)]
        elif cur is not None and line.strip() != "":
            cur[1] += " " + line
    if cur:
        vbs.append(cur)
    res = []
    for oid, rest in vbs:
        t, v = parse_value(rest)
        res.append({"oid": norm_oid(oid), "type": t, "value": v})
    return res


NOISE = re.compile(r"^Created directory: .*$", re.M)


def classify_text(text):
    """Map net-snmp stderr diagnostics to an SnmpError (or None)."""
    text = NOISE.sub("", text).strip()
    if not text:
        return None
    m = re.search(r"Reason: \(?([A-Za-z]+)\)?", text)
    if m:
        name = m.group(1)
        if name == "genError":
            name = "genErr"
        extra = {"status": name}
        f = re.search(r"Failed object: (\S+)", text)
        if f:
            extra["failedOid"] = norm_oid(f.group(1))
        return SnmpError(status_class(name), name, **extra)
    low = text.lower()
    if "timeout" in low:
        return SnmpError("timeout", text.strip())
    for key in ("unknown user name", "authentication failure", "decryption error",
                "unsupported security level", "not in time window", "unknown engine id",
                "authorizationerror"):
        if key in low:
            return SnmpError("authError", text.strip())
    if "too long" in low or "toobig" in low or "message size" in low:
        return SnmpError("tooBig", text.strip())
    if "unknown host" in low:
        return SnmpError("other", text.strip())
    if "asn" in low or "parse" in low or "decod" in low:
        return SnmpError("decodeError", text.strip())
    return None


def run(tool, target, extra):
    cmd = [tool] + OUT_FLAGS + common_args(target) + extra
    p = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, env=env())
    out = p.stdout.decode("latin-1")
    err = p.stderr.decode("latin-1")
    e = classify_text(err) if (p.returncode != 0 or err.strip()) else None
    if e is None and p.returncode != 0:
        e = classify_text(out) or SnmpError("other", (err or out).strip() or "exit %d" % p.returncode)
    if e is not None:
        # A packet error ("Error in packet ... Reason") is authoritative even if some varbind text
        # was printed (snmpget -Cf prints none).
        raise e
    return parse_varbinds(out)


def with_index(e, oids):
    """Turn net-snmp's "Failed object" into the 1-based error-index of the request."""
    f = e.extra.pop("failedOid", None)
    if f is not None and f in oids:
        e.extra["index"] = oids.index(f) + 1
    return e


def do_get(t, oids):
    try:
        vbs = run("snmpget", t, ["-Cf"] + oids)
    except SnmpError as e:
        raise with_index(e, oids)
    for vb in vbs:
        emit(vb)


def do_walk(t, root, bulk, max_rep):
    root_arcs = oid_arcs(root)
    last = root_arcs
    cur = norm_oid(root)
    v1 = str(t.get("version")) == "1"
    n = 0
    while True:
        try:
            if bulk:
                vbs = run("snmpbulkget", t, ["-Cn0", "-Cr%d" % max_rep, cur])
            else:
                vbs = run("snmpgetnext", t, [cur])
        except SnmpError as e:
            if v1 and not bulk and e.extra.get("status") == "noSuchName":
                return  # v1 end of MIB view
            if e.extra.pop("failedOid", None) is not None:
                e.extra["index"] = 1  # single-varbind request
            raise
        if not vbs:
            return
        for vb in vbs:
            if vb["type"] in ("EndOfMibView", "NoSuchObject", "NoSuchInstance"):
                return
            arcs = oid_arcs(vb["oid"])
            if len(arcs) <= len(root_arcs) or arcs[:len(root_arcs)] != root_arcs:
                return
            if arcs <= last:
                emit_err("nonIncreasing", "%s after %s" % (vb["oid"], ".".join(map(str, last))))
                return
            emit(vb)
            last = arcs
            n += 1
            if n >= MAX_WALK:
                emit_err("other", "walk limit reached")
                return
        cur = ".".join(map(str, last))


SET_LETTER = {"Integer": "i", "OctetString": "x", "OID": "o", "IpAddress": "a",
              "Gauge32": "u", "TimeTicks": "t", "Counter32": "c", "Counter64": "C",
              "Null": "n"}


def do_set(t, varbinds):
    args = []
    for vb in varbinds:
        letter = SET_LETTER.get(vb["type"])
        if letter is None:
            raise SnmpError("other", "net-snmp cannot SET type %s" % vb["type"])
        val = vb.get("value", "")
        if letter == "x" and val == "":
            letter, val = "s", ""
        if letter == "n":
            val = "0"
        args += [norm_oid(vb["oid"]), letter, val]
    try:
        vbs = run("snmpset", t, args)
    except SnmpError as e:
        raise with_index(e, [norm_oid(vb["oid"]) for vb in varbinds])
    for vb in vbs:
        emit(vb)


def main():
    try:
        req = json.load(sys.stdin)
    except Exception as e:  # noqa: BLE001
        print("bad request: %s" % e, file=sys.stderr)
        return 2
    t = req["target"]
    op = req["op"]
    try:
        if op == "get":
            do_get(t, [norm_oid(o) for o in req.get("oids", [])])
        elif op == "walk":
            do_walk(t, req["root"], False, 0)
        elif op == "bulkwalk":
            if str(t.get("version")) == "1":
                raise SnmpError("other", "GETBULK not supported in SNMPv1")
            do_walk(t, req["root"], True, int(req.get("maxRepetitions") or 10))
        elif op == "set":
            do_set(t, req.get("varbinds", []))
        else:
            print("unknown op %s" % op, file=sys.stderr)
            return 2
    except SnmpError as e:
        emit_err(e.cls, e.msg, **e.extra)
    except FileNotFoundError as e:
        emit_err("other", str(e))
    return 0


if __name__ == "__main__":
    sys.exit(main())
