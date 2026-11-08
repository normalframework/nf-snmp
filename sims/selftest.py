#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Simulator self-test. Runs inside a throwaway container on the `snmpnet`
network (see selftest.sh) and drives the sims with the net-snmp CLI tools,
checking every answer against the sims' GET /truth for the same time step.

Exit status 0 when every check passes.
"""

import json
import os
import re
import subprocess
import sys
import time
import urllib.request

SIMS = {
    "sim-apc-ups": "172.31.161.11",
    "sim-ups-rfc1628": "172.31.161.12",
    "sim-raritan-pdu": "172.31.161.13",
    "sim-liebert-crac": "172.31.161.14",
    "sim-switch": "172.31.161.15",
    "sim-quirky": "172.31.161.16",
}
AUTH, PRIV = "authpass123", "privpass123"
NETSNMP_AUTH = {"md5": "MD5", "sha": "SHA", "sha224": "SHA-224", "sha256": "SHA-256",
                "sha384": "SHA-384", "sha512": "SHA-512"}
NETSNMP_PRIV = {"des": "DES", "aes": "AES", "aes256b": "AES-256"}
TRAP_PORT = 1162
TRAP_LOG = "/tmp/traps.log"

results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print("%s  %s%s" % ("PASS" if ok else "FAIL", name, ("  -- " + detail) if detail and not ok else ""),
          flush=True)
    return ok


# --------------------------------------------------------------------------
# HTTP helpers
# --------------------------------------------------------------------------

def http(host, path, body=None):
    url = "http://%s:8000%s" % (host, path)
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=40) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read() or b"{}")


def truth(host, at_ms=None):
    return http(host, "/truth" + ("?at=%d" % at_ms if at_ms is not None else ""))


# --------------------------------------------------------------------------
# net-snmp CLI -> §1 normalized varbinds
# --------------------------------------------------------------------------

LINE = re.compile(r"^\.?(\d+(?:\.\d+)*) = (.*)$")
HEXCONT = re.compile(r"^([0-9A-Fa-f]{2} ?)+$")


def parse_value(s):
    if s == '""':
        return "OctetString", ""
    if s.startswith("No Such Instance"):
        return "NoSuchInstance", ""
    if s.startswith("No Such Object"):
        return "NoSuchObject", ""
    if s.startswith("No more variables"):
        return "EndOfMibView", ""
    t, _, v = s.partition(": ")
    v = v.strip()
    if t == "Hex-STRING":
        return "OctetString", v.replace(" ", "").replace("\n", "").lower()
    if t == "STRING":   # only without -Ox
        return "OctetString", v.strip('"').encode().hex()
    if t == "INTEGER":
        return "Integer", v
    if t in ("Gauge32", "Counter32", "Counter64"):
        return t, v
    if t == "Timeticks":
        return "TimeTicks", re.match(r"\((\d+)\)", v).group(1)
    if t == "OID":
        return "OID", v.lstrip(".")
    if t == "IpAddress":
        return "IpAddress", v
    return t, v


def snmp_cmd(tool, target, args, extra=()):
    """target: dict(host, version, community | user...)."""
    cmd = [tool, "-On", "-Oe", "-Ox", "-OU", "-m", "", "-t", str(target.get("timeout", 2)),
           "-r", str(target.get("retries", 1))]
    v = target.get("version", "2c")
    if v in ("1", "2c"):
        cmd += ["-v", v, "-c", target.get("community", "public")]
    else:
        cmd += ["-v", "3", "-u", target["user"], "-l", target["level"]]
        if target.get("auth", "none") != "none":
            cmd += ["-a", NETSNMP_AUTH[target["auth"]], "-A", AUTH]
        if target.get("priv", "none") != "none":
            cmd += ["-x", NETSNMP_PRIV[target["priv"]], "-X", PRIV]
    cmd += list(extra) + [target["host"]] + list(args)
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    vbs = []
    for ln in p.stdout.splitlines():
        m = LINE.match(ln)
        if m:
            vbs.append([m.group(1), m.group(2)])
        elif vbs and HEXCONT.match(ln) and vbs[-1][1].startswith("Hex-STRING"):
            vbs[-1][1] += "\n" + ln   # continuation of a wrapped Hex-STRING
    out = []
    for oid, s in vbs:
        t, v = parse_value(s)
        if t == "EndOfMibView" and tool in ("snmpwalk", "snmpbulkwalk"):
            break   # walk terminator (net-snmp prints it when it is inside the subtree)
        out.append({"oid": oid, "type": t, "value": v})
    return p.returncode, out, (p.stderr + p.stdout).strip()


def same_step_query(host, fn, step_ms, tries=5):
    """Run fn() and fetch /truth for the same step; retry if a step boundary
    was crossed while the request ran."""
    for _ in range(tries):
        t0 = int(time.time() * 1000)
        res = fn()
        t1 = int(time.time() * 1000)
        if t0 // step_ms == t1 // step_ms:
            return res, truth(host, t0)
        time.sleep(0.2)
    raise RuntimeError("could not complete request within one step")


def compare(vbs, tr, label, expect_oids=None):
    raw = tr["raw"]
    bad = []
    for vb in vbs:
        exp = raw.get(vb["oid"])
        if exp is None:
            bad.append("%s not in truth (got %s %s)" % (vb["oid"], vb["type"], vb["value"]))
        elif exp["type"] != vb["type"] or exp["value"] != vb["value"]:
            bad.append("%s: snmp %s/%s truth %s/%s" % (vb["oid"], vb["type"], vb["value"],
                                                       exp["type"], exp["value"]))
    if expect_oids is not None:
        got = {vb["oid"] for vb in vbs}
        missing = [o for o in expect_oids if o not in got]
        if missing:
            bad.append("%d truth OIDs not returned, e.g. %s" % (len(missing), missing[:3]))
    return check(label, not bad and vbs, "; ".join(bad[:4]) or "no varbinds")


def in_root(oid, root):
    return oid == root or oid.startswith(root + ".")


# --------------------------------------------------------------------------
# trap receiver
# --------------------------------------------------------------------------

def start_trapd(infos):
    lines = ["disableAuthorization yes", "doNotLogTraps no"]
    for inf in infos.values():
        eid = inf.get("engineID")
        if not eid:
            continue
        for u in inf["users"]:
            if u["level"] == "authPriv":
                lines.append("createUser -e 0x%s %s %s %s %s %s" % (
                    eid, u["user"], NETSNMP_AUTH[u["authProtocol"]], AUTH,
                    NETSNMP_PRIV[u["privProtocol"]], PRIV))
    # informs: snmptrapd is the authoritative engine
    any_dev = next((i for i in infos.values() if i.get("engineID")), {"users": []})
    for u in any_dev["users"]:
        if u["level"] == "authPriv":
            lines.append("createUser %s %s %s %s %s" % (
                u["user"], NETSNMP_AUTH[u["authProtocol"]], AUTH,
                NETSNMP_PRIV[u["privProtocol"]], PRIV))
    os.makedirs("/tmp/trapd", exist_ok=True)
    with open("/tmp/trapd/snmptrapd.conf", "w") as f:
        f.write("\n".join(lines) + "\n")
    p = subprocess.Popen(["snmptrapd", "-f", "-C", "-c", "/tmp/trapd/snmptrapd.conf", "-m", "",
                          "-On", "-n", "-Lf", TRAP_LOG, "--persistentDir=/tmp/trapd",
                          "udp:%d" % TRAP_PORT],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.0)
    return p


def my_ip():
    out = subprocess.run(["hostname", "-I"], capture_output=True, text=True).stdout.split()
    for ip in out:
        if ip.startswith("172.31.161."):
            return ip
    return out[0]


def trap_log_size():
    try:
        return os.path.getsize(TRAP_LOG)
    except OSError:
        return 0


def wait_trap(start, needles, timeout=6.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with open(TRAP_LOG, errors="replace") as f:
                f.seek(start)
                chunk = f.read()
        except OSError:
            chunk = ""
        if all(n in chunk for n in needles):
            return True, chunk
        time.sleep(0.2)
    return False, chunk


def test_traps(name, host, info, me):
    trap_oid = info["trapOID"]
    cases = [("v2c trap", {"version": "2c"}), ("v1 trap", {"version": "1"}),
             ("v2c inform", {"version": "2c", "inform": True})]
    if info.get("users"):
        cases += [("v3 trap shaaes", {"version": "3", "user": "shaaes"}),
                  ("v3 inform sha256aes", {"version": "3", "user": "sha256aes", "inform": True})]
    for label, req in cases:
        req = dict(req, target="%s:%d" % (me, TRAP_PORT))
        start = trap_log_size()
        r = http(host, "/trap", req)
        if req["version"] == "1":
            v1 = r.get("v1") or {}
            needles = [host, "." + v1.get("enterprise", "?")]
        else:
            needles = [host, "." + trap_oid]
        needles += ["." + vb["oid"] for vb in r.get("varbinds", [])[:1]]
        ok, chunk = wait_trap(start, needles)
        check("%s: %s received" % (name, label), r.get("ok") and ok,
              "http=%s log=%r" % (json.dumps(r)[:300], chunk[-300:]))


# --------------------------------------------------------------------------
# per-sim tests
# --------------------------------------------------------------------------

def v3_targets(host, info):
    for u in info["users"]:
        yield u["user"], {"host": host, "version": "3", "user": u["user"], "level": u["level"],
                          "auth": u["authProtocol"], "priv": u["privProtocol"]}


def test_reads(name, host, info):
    step_ms = info["stepMs"]
    v2 = {"host": host, "version": "2c"}
    sysoids = ["1.3.6.1.2.1.1.%d.0" % i for i in (1, 2, 4, 5, 6)]
    (rc, vbs, err), tr = same_step_query(host, lambda: snmp_cmd("snmpget", v2, sysoids), step_ms)
    compare(vbs, tr, "%s: v2c get system group == truth" % name)
    check("%s: sysObjectID matches /info" % name,
          any(vb["oid"] == "1.3.6.1.2.1.1.2.0" and vb["value"] == info["sysObjectID"] for vb in vbs))

    for root in info["roots"]:
        (rc, vbs, err), tr = same_step_query(
            host, lambda: snmp_cmd("snmpbulkwalk", v2, [root], ["-Cr25"]), step_ms)
        exp = [o for o in tr["raw"] if in_root(o, root)]
        compare(vbs, tr, "%s: v2c bulkwalk %s == truth (%d vbs)" % (name, root, len(vbs)), exp)
    root = info["roots"][0]
    v1 = {"host": host, "version": "1"}
    (rc, vbs, err), tr = same_step_query(host, lambda: snmp_cmd("snmpwalk", v1, [root]), step_ms)
    exp = [o for o, v in tr["raw"].items() if in_root(o, root) and v["type"] != "Counter64"]
    compare(vbs, tr, "%s: v1 walk %s == truth (Counter64 skipped)" % (name, root), exp)

    probe = sorted((o for o in tr["raw"] if in_root(o, root)),
                   key=lambda o: [int(x) for x in o.split(".")])[:3]
    for uname, tgt in v3_targets(host, info):
        (rc, vbs, err), tr = same_step_query(
            host, lambda: snmp_cmd("snmpget", tgt, ["1.3.6.1.2.1.1.2.0"] + probe), step_ms)
        compare(vbs, tr, "%s: v3 %s get == truth" % (name, uname))


def test_writes(name, host, info):
    step_ms = info["stepMs"]
    rw = {"host": host, "version": "2c", "community": "private"}
    ro = {"host": host, "version": "2c", "community": "public"}
    rc, vbs, err = snmp_cmd("snmpset", rw, ["1.3.6.1.2.1.1.6.0", "s", "Selftest Room 42"])
    tr = truth(host)
    check("%s: v2c set sysLocation -> /truth" % name,
          rc == 0 and tr["eng"].get("sysLocation.0", {}).get("value") == "Selftest Room 42",
          err)
    rc, vbs, err = snmp_cmd("snmpset", ro, ["1.3.6.1.2.1.1.6.0", "s", "nope"])
    check("%s: set with read-only community rejected" % name, rc != 0, err)
    if info.get("users"):
        u = next(x for x in info["users"] if x["user"] == "sha512aes")
        tgt = {"host": host, "version": "3", "user": u["user"], "level": u["level"],
               "auth": u["authProtocol"], "priv": u["privProtocol"]}
        rc, vbs, err = snmp_cmd("snmpset", tgt, ["1.3.6.1.2.1.1.4.0", "s", "selftest@example.com"])
        tr = truth(host)
        check("%s: v3 sha512aes set sysContact -> /truth" % name,
              rc == 0 and tr["eng"].get("sysContact.0", {}).get("value") == "selftest@example.com",
              err)
        nu = next(x for x in info["users"] if x["user"] == "noauth")
        tgt = {"host": host, "version": "3", "user": "noauth", "level": nu["level"]}
        rc, vbs, err = snmp_cmd("snmpset", tgt, ["1.3.6.1.2.1.1.4.0", "s", "nope"])
        check("%s: v3 noauth (read-only user) set rejected" % name, rc != 0, err)

    model = info["model"]
    if model == "raritan-px2":
        sw = "1.3.6.1.4.1.13742.6.4.1.2.1.2.1.2"
        rc, vbs, err = snmp_cmd("snmpset", rw, [sw, "i", "0"])
        (rc2, vbs2, err2), tr = same_step_query(host, lambda: snmp_cmd(
            "snmpget", ro, ["1.3.6.1.4.1.13742.6.4.1.2.1.3.1.2",
                            "1.3.6.1.4.1.13742.6.5.4.3.1.4.1.2.1"]), step_ms)
        e = tr["eng"]
        check("raritan: switch outlet 2 off -> state off(8), current 0 in snmp+truth",
              rc == 0 and [v["value"] for v in vbs2] == ["8", "0"]
              and e["outletSwitchingState.1.2"]["value"] == 8
              and e["measurementsOutletSensorValue.1.2.1"]["value"] == 0.0, err + err2)
        compare(vbs2, tr, "raritan: post-switch get == truth")
        rc, vbs, err = snmp_cmd("snmpset", rw, [sw, "i", "7"])
        check("raritan: invalid switchingOperation rejected", rc != 0, err)
        rc, vbs, err = snmp_cmd("snmpset", rw, ["1.3.6.1.4.1.13742.6.3.5.3.1.3.1.8", "s", "spare-8"])
        tr = truth(host)
        check("raritan: set outletName.1.8 (string) -> /truth",
              rc == 0 and tr["eng"]["outletName.1.8"]["value"] == "spare-8", err)
        # decimal-digit scaling is consistent in the truth itself
        raw, eng = tr["raw"], tr["eng"]
        okdd = True
        for k, v in eng.items():
            if k.startswith("measurementsInletSensorValue."):
                idx = k.split(".", 1)[1]
                dd = int(raw["1.3.6.1.4.1.13742.6.3.3.4.1.7." + idx]["value"])
                rv = int(raw["1.3.6.1.4.1.13742.6.5.2.3.1.4." + idx]["value"])
                okdd &= abs(v["value"] - rv / 10 ** dd) < 1e-9
        check("raritan: eng == raw / 10^inletSensorDecimalDigits", okdd)
    elif model == "liebert-crac":
        sp = "1.3.6.1.4.1.476.1.42.3.4.1.3.1.0"
        rc, vbs, err = snmp_cmd("snmpset", rw, [sp, "i", "24"])
        tr = truth(host)
        check("liebert: set lgpEnvTemperatureSettingDegC=24 -> /truth",
              rc == 0 and tr["eng"]["lgpEnvTemperatureSettingDegC.0"]["value"] == 24.0, err)
        rc, vbs, err = snmp_cmd("snmpset", rw, [sp, "i", "99"])
        check("liebert: out-of-range setpoint rejected (wrongValue)",
              rc != 0 and "wrongValue" in err, err)
    elif model == "cisco-2960x":
        al = "1.3.6.1.2.1.31.1.1.1.18.10103"
        rc, vbs, err = snmp_cmd("snmpset", rw, [al, "s", "to fw-2"])
        tr = truth(host)
        check("switch: set ifAlias.10103 -> /truth",
              rc == 0 and tr["eng"]["ifAlias.10103"]["value"] == "to fw-2", err)
    for w in info["writable"][:1]:
        check("%s: /info lists writable OIDs" % name, w in truth(host)["raw"])
    http(host, "/reset", {})
    tr = truth(host)
    check("%s: POST /reset restores defaults" % name,
          tr["eng"]["sysLocation.0"]["value"] != "Selftest Room 42")


def test_switch_counters(host, info):
    step_ms = info["stepMs"]
    now = int(time.time() * 1000)
    tr0 = truth(host, now)
    ok_mod = all(int(tr0["raw"]["1.3.6.1.2.1.2.2.1.10." + i]["value"])
                 == int(tr0["raw"]["1.3.6.1.2.1.31.1.1.1.6." + i]["value"]) % (1 << 32)
                 for i in ("1", "10101", "10102", "10103", "10601"))
    check("switch: ifInOctets == ifHCInOctets mod 2^32", ok_mod)
    prev = int(tr0["raw"]["1.3.6.1.2.1.2.2.1.10.10101"]["value"])
    wrapped_at = None
    for k in range(1, 400 * 1000 // step_ms):
        cur = int(truth(host, now + k * step_ms)["raw"]["1.3.6.1.2.1.2.2.1.10.10101"]["value"])
        if cur < prev:
            wrapped_at = k * step_ms / 1000.0
            break
        prev = cur
    check("switch: Counter32 ifInOctets.10101 wraps within 5 min (%.0fs)" % (wrapped_at or -1),
          wrapped_at is not None and wrapped_at <= 300)
    hc = int(tr0["raw"]["1.3.6.1.2.1.31.1.1.1.6.10601"]["value"])
    check("switch: Te1/0/1 ifHCInOctets > 2^53 (exact Counter64 exercise)", hc > (1 << 53))
    e = tr0["eng"]
    check("switch: ENTITY-SENSOR eng uses scale/precision",
          abs(e["entPhySensorValue.1010"]["value"]
              - int(tr0["raw"]["1.3.6.1.2.1.99.1.1.1.4.1010"]["value"]) / 1000.0) < 1e-9
          and e["entPhySensorValue.1021"]["value"] is None)
    a = truth(host, now)
    b = truth(host, now)
    check("switch: /truth?at= is reproducible", a["raw"] == b["raw"])


def test_quirky(host, info):
    name = "sim-quirky"
    step_ms = info["stepMs"]
    v2 = {"host": host, "version": "2c"}
    col_name = "1.3.6.1.4.1.99998.1.1.1.1.2"
    http(host, "/reset", {})

    def fault(**kw):
        return http(host, "/set-fault", kw)

    tgt = {"host": host, "version": "3", "user": "shaaes", "level": "authPriv", "auth": "sha",
           "priv": "aes", "timeout": 1, "retries": 0}
    rc, vbs, err = snmp_cmd("snmpget", tgt, ["1.3.6.1.2.1.1.2.0"])
    check("quirky: v3 not supported (no answer)", rc != 0, err)

    fault(kind="bulkIgnoresMaxRep", n=40)
    (rc, vbs, err), tr = same_step_query(host, lambda: snmp_cmd(
        "snmpbulkget", v2, [col_name], ["-Cn0", "-Cr5"]), step_ms)
    check("quirky: bulkIgnoresMaxRep returns 40 vbs for max-rep 5 (got %d)" % len(vbs),
          len(vbs) == 40, err)
    compare(vbs, tr, "quirky: GETBULK under bulkIgnoresMaxRep == truth")
    fault(kind="bulkIgnoresMaxRep", enabled=False)

    fault(kind="bulkCrashAboveN", n=10)
    t1 = dict(v2, timeout=1, retries=0)
    rc, vbs, err = snmp_cmd("snmpbulkget", t1, [col_name], ["-Cn0", "-Cr11"])
    check("quirky: bulkCrashAboveN drops max-rep 11", rc != 0 and "Timeout" in err, err)
    rc, vbs, err = snmp_cmd("snmpbulkget", t1, [col_name], ["-Cn0", "-Cr10"])
    check("quirky: bulkCrashAboveN answers max-rep 10", rc == 0 and len(vbs) == 10, err)
    fault(kind="bulkCrashAboveN", enabled=False)

    fault(kind="tooBigAboveN", n=3)
    rc, vbs, err = snmp_cmd("snmpget", v2, ["1.3.6.1.2.1.1.%d.0" % i for i in (1, 2, 3, 5)])
    check("quirky: tooBigAboveN -> tooBig for 4-varbind GET", rc != 0 and "tooBig" in err, err)
    rc, vbs, err = snmp_cmd("snmpget", v2, ["1.3.6.1.2.1.1.%d.0" % i for i in (1, 2, 5)])
    check("quirky: tooBigAboveN allows 3-varbind GET", rc == 0 and len(vbs) == 3, err)
    fault(kind="tooBigAboveN", enabled=False)

    fault(kind="nonIncreasing")
    rc, vbs, err = snmp_cmd("snmpwalk", v2, [col_name])
    check("quirky: nonIncreasing makes snmpwalk report OID not increasing",
          "not increasing" in err, err[-200:])
    fault(kind="nonIncreasing", enabled=False)

    fault(kind="noSuchInstanceGaps")
    fault(kind="floatAsString")
    fault(kind="counter32Wrap")
    (rc, vbs, err), tr = same_step_query(host, lambda: snmp_cmd(
        "snmpbulkwalk", v2, ["1.3.6.1.4.1.99998"], ["-Cr20"]), step_ms)
    exp = [o for o in tr["raw"] if in_root(o, "1.3.6.1.4.1.99998")]
    compare(vbs, tr, "quirky: bulkwalk with gaps+floatAsString+counter32Wrap == truth (%d vbs)"
            % len(vbs), exp)
    rc, vbs, err = snmp_cmd("snmpget", v2, ["1.3.6.1.4.1.99998.1.1.1.1.4.3",
                                             "1.3.6.1.4.1.99998.1.1.1.1.3.1"])
    check("quirky: gap -> noSuchInstance, temperature -> OctetString",
          [v["type"] for v in vbs] == ["NoSuchInstance", "OctetString"]
          and bytes.fromhex(vbs[1]["value"]).decode().endswith(" C"), json.dumps(vbs))
    rc, vbs, err = snmp_cmd("snmpget", {"host": host, "version": "1"},
                            ["1.3.6.1.4.1.99998.1.1.1.1.4.3"])
    check("quirky: v1 gap -> noSuchName", rc != 0 and "noSuchName" in err, err)
    now = int(time.time() * 1000)
    prev, wrapped = None, None
    for k in range(0, 200 * 1000 // step_ms):
        cur = int(truth(host, now + k * step_ms)["raw"]["1.3.6.1.4.1.99998.1.1.1.1.5.1"]["value"])
        if prev is not None and cur < prev:
            wrapped = k * step_ms / 1000.0
            break
        prev = cur
    check("quirky: counter32Wrap wraps qtOctets within 2 min (%.0fs)" % (wrapped or -1),
          wrapped is not None and wrapped <= 120)
    fault(kind="clear")

    fault(kind="delayMs", value=1500)
    rc, vbs, err = snmp_cmd("snmpget", t1, ["1.3.6.1.2.1.1.5.0"])
    rc2, vbs2, err2 = snmp_cmd("snmpget", dict(v2, timeout=4, retries=0), ["1.3.6.1.2.1.1.5.0"])
    check("quirky: delayMs 1500 -> timeout at 1s, answer at 4s", rc != 0 and rc2 == 0, err + err2)
    fault(kind="delayMs", value=0)
    fault(kind="dropRate", value=1.0)
    rc, vbs, err = snmp_cmd("snmpget", t1, ["1.3.6.1.2.1.1.5.0"])
    check("quirky: dropRate 1.0 -> no answer", rc != 0, err)
    fault(kind="dropRate", value=0.5)
    answered = sum(snmp_cmd("snmpget", dict(v2, timeout=0.5, retries=0),
                            ["1.3.6.1.2.1.1.5.0"])[0] == 0 for _ in range(20))
    check("quirky: dropRate 0.5 -> some but not all answered (%d/20)" % answered,
          0 < answered < 20)
    fault(kind="clear")

    rw = {"host": host, "version": "2c", "community": "private"}
    rc, vbs, err = snmp_cmd("snmpset", rw, ["1.3.6.1.4.1.99998.1.1.1.1.7.3", "i", "26",
                                            "1.3.6.1.2.1.1.6.0", "s", "Selftest Room 42"])
    tr = truth(host)
    check("quirky: v2c set qtSetpoint.3 + sysLocation -> /truth",
          rc == 0 and tr["eng"]["qtSetpoint.3"]["value"] == 26.0
          and tr["eng"]["sysLocation.0"]["value"] == "Selftest Room 42", err)
    rc, vbs, err = snmp_cmd("snmpset", rw, ["1.3.6.1.4.1.99998.1.1.1.1.7.3", "i", "99"])
    check("quirky: out-of-range set -> wrongValue", rc != 0 and "wrongValue" in err, err)
    http(host, "/reset", {})
    check("quirky: /reset clears writes", truth(host)["eng"]["qtSetpoint.3"]["value"] == 22.0)


def main():
    only = set(sys.argv[1:])
    sims = {k: v for k, v in SIMS.items() if not only or k in only}
    infos = {}
    for name, host in sims.items():
        for _ in range(30):
            try:
                infos[name] = http(host, "/info")
                break
            except OSError:
                time.sleep(1)
        check("%s: /info reachable" % name, name in infos)
        if name in infos:
            http(host, "/reset", {})
    me = my_ip()
    trapd = start_trapd(infos)
    try:
        for name, host in sims.items():
            info = infos.get(name)
            if not info:
                continue
            if info.get("users"):
                check("%s: v3 users configured (%s)" % (name, ",".join(
                    u["user"] for u in info["users"])), len(info["users"]) >= 6)
            test_reads(name, host, info)
            if name == "sim-quirky":
                test_quirky(host, info)
            else:
                test_writes(name, host, info)
            if name == "sim-switch":
                test_switch_counters(host, info)
            test_traps(name, host, info, me)
    finally:
        trapd.terminate()
    passed = sum(1 for r in results if r[1])
    failed = [r for r in results if not r[1]]
    print("\n==== selftest summary: %d passed, %d failed ====" % (passed, len(failed)))
    for n, _ok, d in failed:
        print("FAILED: %s -- %s" % (n, d))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
