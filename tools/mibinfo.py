#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Resolve MIB objects with net-snmp's snmptranslate (authoritative SMI parser).

Runs inside the nfsnmp-sim-device image (has net-snmp tools):
  docker run --rm -i -v $PWD/mibs:/mibs:ro -v $PWD/tools:/tools:ro --entrypoint python3 \
      nfsnmp-sim-device:latest -I /tools/mibinfo.py < queries.json > mibinfo.json

stdin:  [{"mib": "UPS-MIB", "name": "upsBatteryVoltage", "oid": "1.3.6.1.2.1.33.1.2.5"}, ...]
        (oid = the object OID without instance suffix; mib may be wrong-case or empty)
stdout: {"byName": {"<MIB>::<name>": info}, "byOid": {"<oid>": info}, "missingMibs": [...]}
info:   {name, mib, oid, base, tc, range, enum, units, hint, access, descr}
"""
import json
import os
import re
import subprocess
import sys

MIBDIRS = "/mibs:/usr/share/snmp/mibs"
files = {f.upper(): f for f in os.listdir("/mibs")}


def parse(out):
    """Split snmptranslate -Td -On output into per-object info dicts."""
    res = []
    for block in re.split(r"\n(?=\.\d)", out.strip()):
        lines = block.strip().split("\n")
        if not lines or not lines[0].startswith("."):
            continue
        oid = lines[0][1:].strip()
        m = re.match(r"(\S+)\s+OBJECT-TYPE", lines[1]) if len(lines) > 1 else None
        if not m:
            res.append({"oid": oid, "name": None})
            continue
        text = "\n".join(lines[1:])
        info = {"oid": oid, "name": m.group(1)}
        mm = re.search(r"-- FROM\s+(\S+)", text)
        info["mib"] = mm.group(1) if mm else None
        mm = re.search(r"-- TEXTUAL CONVENTION\s+(\S+)", text)
        info["tc"] = mm.group(1) if mm else None
        mm = re.search(r"SYNTAX\s+(.*)", text)
        syn = mm.group(1).strip() if mm else ""
        info["syntax"] = syn
        base = re.match(r"([A-Za-z0-9]+(?: STRING| IDENTIFIER)?)", syn)
        info["base"] = base.group(1) if base else None
        info["enum"] = {v: k for k, v in re.findall(r"([A-Za-z][A-Za-z0-9-]*)\((-?\d+)\)", syn)} if "{" in syn else None
        rng = re.search(r"\((-?\d+)\.\.(-?\d+)\)", syn)
        info["range"] = [int(rng.group(1)), int(rng.group(2))] if rng else None
        size = re.search(r"SIZE\s*\((\d+)(?:\.\.(\d+))?\)", syn)
        info["size"] = [int(size.group(1)), int(size.group(2) or size.group(1))] if size else None
        mm = re.search(r'DISPLAY-HINT\s+"([^"]*)"', text)
        info["hint"] = mm.group(1) if mm else None
        mm = re.search(r'UNITS\s+"([^"]*)"', text)
        info["units"] = mm.group(1) if mm else None
        mm = re.search(r"MAX-ACCESS\s+(\S+)", text) or re.search(r"ACCESS\s+(\S+)", text)
        info["access"] = mm.group(1) if mm else None
        mm = re.search(r"::=\s*\{[^}]*?\s([A-Za-z][A-Za-z0-9-]*)\(\d+\)\s+\d+\s*\}", text)
        info["parent"] = mm.group(1) if mm else None
        info["column"] = bool(info["parent"] and info["parent"].endswith("Entry"))
        info["leaf"] = bool(info["base"]) and not syn.startswith("SEQUENCE") and info.get("access") not in ("not-accessible",)
        mm = re.search(r'DESCRIPTION\s+"(.*?)"', text, re.S)
        info["descr"] = re.sub(r"\s+", " ", mm.group(1)).strip()[:600] if mm else None
        res.append(info)
    return res


def run(mib, args):
    p = subprocess.run(["snmptranslate", "-M", MIBDIRS, "-m", mib, "-Td", "-On"] + args,
                       capture_output=True, text=True, errors="replace")
    return parse(p.stdout)


def translate(mib, args):
    """snmptranslate stops at the first unknown name, so batches are verified and anything
    unresolved is retried one at a time."""
    out = []
    for i in range(0, len(args), 150):
        batch = args[i:i + 150]
        got = run(mib, batch)
        if len(got) == len(batch):
            out.extend(got)
            continue
        for a in batch:
            out.extend(run(mib, [a]))
    return out


def main():
    queries = json.load(sys.stdin)
    by_mib = {}
    missing = set()
    for q in queries:
        mib = files.get((q.get("mib") or "").upper())
        if not mib:
            missing.add(q.get("mib") or "")
            mib = "ALL" if not q.get("mib") else None
        if mib:
            by_mib.setdefault(mib, []).append(q)
    by_name, by_oid = {}, {}
    for mib, qs in sorted(by_mib.items()):
        names = sorted({"%s::%s" % (mib, q["name"]) for q in qs if q.get("name")})
        oids = sorted({q["oid"] for q in qs if q.get("oid")})
        for info in translate(mib, names):
            if info.get("name"):
                by_name["%s::%s" % (mib.upper(), info["name"])] = info
        for info in translate(mib, oids):
            if info.get("name"):
                by_oid[info["oid"]] = info
    json.dump({"byName": by_name, "byOid": by_oid, "missingMibs": sorted(m for m in missing if m)}, sys.stdout)


main()
