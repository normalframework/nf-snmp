#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Cross-check every (MIB, name, OID, type, access) the device models serve
against real MIB text using net-snmp's snmptranslate.

Run via tools/verify-oids.sh (downloads the MIBs, runs this inside the device
image).  Usage: verify-oids.py <mib-dir>
"""

import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, "/opt/sim")
from models import MODELS  # noqa: E402

BASE_TYPES = {
    "Integer": {"INTEGER", "Integer32", "EnumVal"},
    "Gauge32": {"Gauge", "Unsigned"},
    "Counter32": {"Counter"},
    "Counter64": {"Counter64"},
    "TimeTicks": {"TimeTicks"},
    "OctetString": {"String", "OCTETSTR"},
    "OID": {"ObjID"},
    "IpAddress": {"IpAddr"},
}

MIBDIR = sys.argv[1] if len(sys.argv) > 1 else "/mibs"


def translate(mib, name):
    base = ["snmptranslate", "-M", "+" + MIBDIR, "-m", mib]
    env = dict(os.environ, MIBS="")
    oid = subprocess.run(base + ["-On", "%s::%s" % (mib, name)], capture_output=True,
                         text=True, env=env).stdout.strip()
    tree = subprocess.run(base + ["-Tp", "%s::%s" % (mib, name)], capture_output=True,
                          text=True, env=env).stdout
    line = next((ln for ln in tree.splitlines() if "%s(" % name in ln), "")
    return oid, line


def check(item):
    model, obj, kind = item
    oid, line = translate(obj.mib, obj.name)
    problems = []
    if oid != "." + obj.oid:
        problems.append("OID mismatch: model %s, MIB %s" % (obj.oid, oid or "<unknown>"))
    toks = line.replace("+--", " ").split()
    access, base = None, None
    if len(toks) >= 3 and toks[0].startswith("-") and toks[0].endswith("-"):
        access, base = toks[0], toks[1]
    if kind == "obj":
        if base is None:
            problems.append("not an OBJECT-TYPE leaf: %r" % line.strip())
        elif base not in BASE_TYPES[obj.typ]:
            problems.append("type mismatch: model %s, MIB %s" % (obj.typ, base))
        if obj.writable and access and "W" not in access:
            problems.append("model writable but MIB access %s" % access)
    elif kind == "ref" and base is not None and obj.typ in BASE_TYPES \
            and obj.typ != "OID" and base not in BASE_TYPES[obj.typ]:
        problems.append("type mismatch: model %s, MIB %s" % (obj.typ, base))
    return model, obj, kind, oid, base, problems


def main():
    items = []
    for key, cls in MODELS.items():
        for obj in cls.__new__(cls).all_objects():
            items.append((key, obj, "obj"))
        for obj in getattr(cls, "ref_objects", []):
            items.append((key, obj, "ref"))
    with ThreadPoolExecutor(8) as ex:
        results = list(ex.map(check, items))
    bad = 0
    seen = set()
    for model, obj, kind, oid, base, problems in results:
        tag = "FAIL" if problems else "ok"
        if (obj.mib, obj.name) in seen and not problems:
            continue
        seen.add((obj.mib, obj.name))
        print("%-4s %-12s %-28s %-42s %-45s %s %s" % (
            tag, model, obj.mib, obj.name, obj.oid, base or "-", "; ".join(problems)))
        bad += bool(problems)
    print("\n%d objects checked, %d problems" % (len(seen), bad))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
