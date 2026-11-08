#!/usr/bin/env node
// Verify every profile symbol against its MIB with net-snmp's snmptranslate (tools/mibinfo.py in the
// nfsnmp-sim-device image), and verify + enrich the imported Datadog profiles in place.
//
//   node tools/verify-profiles.mjs            # rewrite profiles/datadog/*, write reports + sims/generated/mibinfo.json
//   node tools/verify-profiles.mjs --check    # report only; exit 1 if a hand-written profile has a problem
//
// Imported profiles (profiles/datadog):
//   name/OID disagree     -> OID is authoritative (profiles were built against real devices); the
//                            symbol is renamed to the MIB's name for that OID
//   neither resolves      -> dropped (only when the MIB itself is available)
//   MIB not available     -> kept, marked "unverified"
//   enrichment (only when the profile is silent): units + scale from UNITS / DISPLAY-HINT / "tenths
//   of" in DESCRIPTION, enum labels from SYNTAX, counter type from Counter32/64. Never enables SET.
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CHECK = process.argv.includes('--check');
const DD = path.join(ROOT, 'profiles', 'datadog');

function walk(d) {
  const out = [];
  for (const e of fs.readdirSync(d, { withFileTypes: true })) {
    const p = path.join(d, e.name);
    if (e.isDirectory()) out.push(...walk(p));
    else if (e.name.endsWith('.json')) out.push(p);
  }
  return out;
}

const files = walk(path.join(ROOT, 'profiles'));
const profiles = files.map((f) => ({ file: f, p: JSON.parse(fs.readFileSync(f, 'utf8')), imported: f.startsWith(DD + path.sep) }));

/** every (symbol, isColumn, mib) */
function entries(p) {
  const out = [];
  for (const s of p.symbols || []) out.push({ s, col: false, mib: s.mib || p.mib });
  for (const t of p.tables || []) for (const c of t.columns) out.push({ s: c, col: true, mib: c.mib || t.mib || p.mib });
  return out;
}
const baseOid = (e) => (e.col ? e.s.oid : e.s.oid.replace(/\.\d+$/, ''));

// ---- 1. query snmptranslate
const queries = [];
for (const { p } of profiles) {
  for (const e of entries(p)) {
    queries.push({ mib: e.mib || '', name: e.s.name, oid: baseOid(e) });
    if (!e.col) queries.push({ mib: e.mib || '', oid: e.s.oid }); // maybe an instance-less scalar OID
  }
}
// helper OIDs that profiles reference (decimal digits, labels, units, entity sensor) — the generated simulator needs their types
for (const { p } of profiles) {
  for (const t of p.tables || []) {
    const extra = [t.label && t.label.oid, ...t.columns.flatMap((c) => [c.decimalDigitsOid, c.unitsFrom && c.unitsFrom.oid, c.entitySensor && c.entitySensor.scaleOid, c.entitySensor && c.entitySensor.precisionOid, c.entitySensor && c.entitySensor.statusOid])].filter(Boolean);
    for (const o of extra) queries.push({ mib: '', oid: o.replace(/^\./, '') });
  }
}
const uniq = [...new Map(queries.map((q) => [`${q.mib}|${q.name}|${q.oid}`, q])).values()];
const mibName = fs.readdirSync(path.join(ROOT, 'mibs')).map((f) => f);
// queries without a known MIB go to "ALL" — load only MIB files that exist, case-normalized
const info = JSON.parse(execFileSync('docker', ['run', '--rm', '-i', '-v', `${ROOT}/mibs:/mibs:ro`, '-v', `${ROOT}/tools:/tools:ro`, '--entrypoint', 'python3', 'nfsnmp-sim-device:latest', '-I', '/tools/mibinfo.py'], { input: JSON.stringify(uniq), maxBuffer: 256 * 1024 * 1024, stdio: ['pipe', 'pipe', 'ignore'] }).toString());
const missingMibs = new Set(info.missingMibs.map((m) => m.toUpperCase()));
const haveMib = (m) => !!m && mibName.some((f) => f.toUpperCase() === m.toUpperCase());
void haveMib;

// ---- 2. enrichment helpers
const UNIT_RULES = [
  [/fahrenheit|deg(rees)?\s*f\b|°f/i, 'degF'],
  [/celsius|centigrade|deg(rees)?\s*c\b|°c/i, 'degC'],
  [/kilowatt[- ]?hours?|\bkwh\b/i, 'kWh'],
  [/watt[- ]?hours?|\bwh\b/i, 'Wh'],
  [/volt[- ]?amp(ere)?s?\b(?!.*hour)|\bva\b/i, 'VA'],
  [/milli[- ]?amp/i, 'mA'],
  [/milli[- ]?volt/i, 'mV'],
  [/\bamp(ere)?s?\b|\bamps\b|\bA rms\b|\barms\b/i, 'A'],
  [/\bvolts?\b|\bvdc\b|\bvac\b|\bvrms\b/i, 'V'],
  [/kilo[- ]?watts?|\bkw\b/i, 'kW'],
  [/\bwatts?\b/i, 'W'],
  [/hertz|\bhz\b/i, 'Hz'],
  [/percent|%/i, '%'],
  [/\brpm\b/i, 'rpm'],
  [/\bseconds?\b|\bsecs?\b/i, 's'],
  [/\bminutes?\b|\bmins?\b/i, 'min'],
  [/\bhours?\b/i, 'h'],
  [/octets|bytes/i, 'B'],
];
function unitsOf(text) {
  if (!text) return null;
  for (const [re, u] of UNIT_RULES) if (re.test(text)) return u;
  return null;
}
function scaleOf(text) {
  if (!text) return null;
  if (/\btenths?\b|\b0?\.1\s|1\/10\b|in units of 0?\.1\b/i.test(text)) return 0.1;
  if (/\bhundredths?\b|\b0?\.01\s|1\/100\b/i.test(text)) return 0.01;
  if (/\bthousandths?\b|\b0?\.001\s|1\/1000\b/i.test(text)) return 0.001;
  return null;
}

// ---- 3. verify / enrich
const rep = { profiles: 0, symbols: 0, verified: 0, renamed: 0, aliased: 0, dropped: 0, unverified: 0, enrichedScale: 0, enrichedUnits: 0, enrichedEnum: 0, counters: 0, missingMibs: [...missingMibs].sort(), handProblems: [], byProfile: {} };
for (const pr of profiles) {
  const { p } = pr;
  const r = { verified: 0, renamed: [], aliased: [], dropped: [], unverified: 0, scale: [], units: 0, enum: 0 };
  const keep = new Set();
  for (const e of entries(p)) {
    rep.symbols++;
    const mibU = (e.mib || '').toUpperCase();
    const leaf = (m) => (m && m.leaf ? m : null);
    // scalar written without its instance (".0" missing): the full OID is itself a leaf object
    const stripped = e.s.oid.replace(/\.\d+$/, '');
    if (!e.col && !/\.0$/.test(e.s.oid) && leaf(info.byOid[e.s.oid]) && !info.byOid[e.s.oid].column && !leaf(info.byOid[stripped])) {
      if (pr.imported) {
        r.instanceFixed = (r.instanceFixed || 0) + 1;
        e.s.oid += '.0';
      }
    }
    const byName = leaf(info.byName[`${mibU}::${e.s.name}`] || Object.entries(info.byName).find(([k]) => k.endsWith(`::${e.s.name}`) && k.startsWith(mibU))?.[1]);
    const byOid = leaf(info.byOid[baseOid(e)]);
    // a scalar pinned to one row of a table column (Datadog: hrMemoryBuffers = hrStorageUsed.6) is valid
    if (!e.col && byOid && byOid.column && byOid.name !== e.s.name) {
      keep.add(e.s);
      r.verified++;
      if (pr.imported) {
        e.s.description = e.s.description || `${byOid.name} row ${e.s.oid.slice(byOid.oid.length + 1)}`;
        delete e.s.mibVerified;
      }
      continue;
    }
    let mi = null;
    if (byName && byName.oid === baseOid(e)) mi = byName;
    else if (byOid && byOid.name === e.s.name) mi = byOid;
    else if (byOid) {
      mi = byOid;
      if (pr.imported) {
        // Datadog uses normalized aliases (cpu.usage, memory.total, ucd.memTotalSwap): keep as description
        const isMibIdent = /^[a-z][A-Za-z0-9-]*$/.test(e.s.name);
        if (isMibIdent) r.renamed.push(`${e.s.name} -> ${byOid.name} (${baseOid(e)})`);
        else {
          r.aliased.push(e.s.name);
          e.s.description = `Datadog metric ${e.s.name}`;
        }
        e.s.name = byOid.name;
      } else rep.handProblems.push(`${p.id}: ${e.s.name} is ${byOid.name} at ${baseOid(e)}`);
    } else if (byName) {
      // name known, OID unknown to the MIB: the OID is wrong for this MIB version
      if (pr.imported) {
        r.dropped.push(`${e.s.name} (${baseOid(e)}; MIB has it at ${byName.oid})`);
        continue;
      }
      rep.handProblems.push(`${p.id}: ${e.s.name} OID ${baseOid(e)} != MIB ${byName.oid}`);
    } else if (!e.mib || missingMibs.has(mibU)) {
      r.unverified++;
      if (pr.imported) e.s.mibVerified = false;
    } else {
      if (pr.imported) {
        r.dropped.push(`${e.s.name} (${baseOid(e)} not in ${e.mib})`);
        continue;
      }
      rep.handProblems.push(`${p.id}: ${e.s.name} not in ${e.mib}`);
    }
    keep.add(e.s);
    if (!mi) continue;
    r.verified++;
    if (!pr.imported) continue;
    delete e.s.mibVerified;
    if (e.s.mib && e.s.mib !== mi.mib) e.s.mib = mi.mib;
    const numeric = /INTEGER|Integer32|Gauge|Unsigned|Counter|TimeTicks/.test(mi.base || '');
    if (/Counter/.test(mi.base || '') && !e.s.type) {
      e.s.type = 'counter';
      rep.counters++;
    }
    if (numeric && !mi.enum && e.s.scale === undefined && !e.s.displayHint && !e.s.regex && e.s.type !== 'counter') {
      const hm = /^d-(\d+)$/.exec(mi.hint || '');
      const sc = hm ? null : scaleOf(mi.units) ?? (mi.units ? null : scaleOf(mi.descr));
      if (hm) {
        e.s.displayHint = mi.hint;
        r.scale.push(`${e.s.name} hint ${mi.hint}`);
      } else if (sc) {
        e.s.scale = sc;
        r.scale.push(`${e.s.name} x${sc} (${mi.units ? 'UNITS' : 'DESCRIPTION'})`);
      }
    }
    if (numeric && !e.s.units && !mi.enum) {
      const u = unitsOf(mi.units) || (mi.units ? null : unitsOf((mi.descr || '').slice(0, 160)));
      if (u) {
        e.s.units = u;
        r.units++;
      }
    }
    if (mi.enum && !e.s.enum && Object.keys(mi.enum).length <= 64) {
      e.s.enum = Object.fromEntries(Object.entries(mi.enum).map(([k, v]) => [k, v]));
      r.enum++;
    }
  }
  if (pr.imported) {
    if (p.symbols) p.symbols = p.symbols.filter((s) => keep.has(s));
    for (const t of p.tables || []) t.columns = t.columns.filter((c) => keep.has(c));
    if (p.tables) p.tables = p.tables.filter((t) => t.columns.length);
    for (const t of p.tables || []) if (!t.columns.some((c) => c.oid === t.indexOid)) t.indexOid = t.columns[0].oid;
    if (p.tables && !p.tables.length) delete p.tables;
    if (p.symbols && !p.symbols.length) delete p.symbols;
    p.verification = { verified: r.verified, renamed: r.renamed.length, dropped: r.dropped.length, unverified: r.unverified, tool: 'tools/verify-profiles.mjs (net-snmp snmptranslate)' };
    if (!CHECK) fs.writeFileSync(pr.file, JSON.stringify(p, null, 1) + '\n');
  }
  rep.profiles++;
  rep.verified += r.verified;
  rep.renamed += r.renamed.length;
  rep.aliased += r.aliased.length;
  rep.instanceFixed = (rep.instanceFixed || 0) + (r.instanceFixed || 0);
  rep.dropped += r.dropped.length;
  rep.unverified += r.unverified;
  rep.enrichedScale += r.scale.length;
  rep.enrichedUnits += r.units;
  rep.enrichedEnum += r.enum;
  if (r.renamed.length || r.dropped.length || r.unverified || r.scale.length) rep.byProfile[p.id] = r;
}

// ---- 4. MIB facts for the generated simulator (no descriptions)
if (!CHECK) {
  const slim = {};
  for (const m of [...Object.values(info.byName), ...Object.values(info.byOid)]) {
    slim[m.oid] = { name: m.name, mib: m.mib, base: m.base, enum: m.enum, range: m.range, size: m.size, hint: m.hint, units: m.units, access: m.access, tc: m.tc };
  }
  fs.mkdirSync(path.join(ROOT, 'sims', 'generated'), { recursive: true });
  fs.writeFileSync(path.join(ROOT, 'sims', 'generated', 'mibinfo.json'), JSON.stringify(slim) + '\n');
  const md = [`# Imported profile verification`, '', `Generated by \`tools/verify-profiles.mjs\` (net-snmp \`snmptranslate\` against \`mibs/\`).`, '',
    `| | count |`, `|---|---|`,
    ...['profiles', 'symbols', 'verified', 'renamed', 'aliased', 'instanceFixed', 'dropped', 'unverified', 'enrichedScale', 'enrichedUnits', 'enrichedEnum', 'counters'].map((k) => `| ${k} | ${rep[k]} |`), '',
    `MIBs not available (symbols kept unverified): ${rep.missingMibs.join(', ') || 'none'}`, '', '## Per profile', '',
    ...Object.entries(rep.byProfile).filter(([id]) => id.startsWith('dd/')).sort().map(([id, r]) => [`### ${id}`, r.renamed.length ? `- renamed: ${r.renamed.join('; ')}` : '', r.dropped.length ? `- dropped: ${r.dropped.join('; ')}` : '', r.unverified ? `- unverified (MIB unavailable): ${r.unverified}` : '', r.scale.length ? `- scaling from MIB: ${r.scale.join('; ')}` : ''].filter(Boolean).join('\n'))].join('\n');
  fs.writeFileSync(path.join(DD, 'VERIFICATION.md'), md + '\n');
}
const { byProfile, ...summary } = rep;
console.log(JSON.stringify(summary, null, 1));
if (rep.handProblems.length) process.exitCode = 1;
