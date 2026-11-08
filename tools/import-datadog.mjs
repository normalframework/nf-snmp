#!/usr/bin/env node
// Convert Datadog SNMP profiles (vendor/datadog-profiles, BSD-3-Clause, pinned commit in
// SOURCE_COMMIT) into nf-snmp profiles: profiles/datadog/<name>.json (ids "dd/<name>").
// MIB verification/enrichment is a separate step (tools/verify-profiles.mjs).
//
//   node tools/import-datadog.mjs [--out profiles/datadog]
//
// Mapping:
//   sysobjectid (string|list, '*' wildcards)   -> match[{sysObjectID}]
//   extends x.yaml                              -> extends dd/x   (_base.yaml -> _base/system)
//   metrics[].symbol                            -> symbols[]      (scalar)
//   metrics[].table + symbols                   -> tables[] (merged per table OID)
//   metric_tags symbol tag (same/cross table)   -> table label (first name-like tag)
//   index_transform [{start,end}]               -> label.indexParts
//   scale_factor -> scale, extract_value -> regex, monotonic_count* -> type counter
//   constant_value_one, flag_stream, mapping-only tags                -> skipped (row counts / bit flags)
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';
import { createRequire } from 'node:module';
const { enterpriseName } = createRequire(import.meta.url)('../lib/profiles/enterprises.js');

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SRC = path.join(ROOT, 'vendor', 'datadog-profiles');
const outArg = process.argv.indexOf('--out');
const OUT = outArg > 0 ? path.resolve(process.argv[outArg + 1]) : path.join(ROOT, 'profiles', 'datadog');
const COMMIT = fs.readFileSync(path.join(SRC, 'SOURCE_COMMIT'), 'utf8').trim();
const OVERRIDES = JSON.parse(fs.readFileSync(path.join(ROOT, 'vendor', 'datadog-overrides.json'), 'utf8'));

const files = fs.readdirSync(SRC).filter((f) => f.endsWith('.yaml'));
const exists = new Set(files.map((f) => f.replace(/\.yaml$/, '')));
const report = { converted: 0, abstract: 0, skipped: [], droppedExtends: [], skippedSymbols: { constant_value_one: 0, flag_stream: 0, no_oid: 0 }, labels: 0 };

const LABEL_PREF = [/name$/i, /descr/i, /label/i, /alias/i, /^(sensor|outlet|interface|port|fan|psu|disk|volume|cpu|mem|branch|phase|circuit)/i];

function idOf(file) {
  const base = file.replace(/\.yaml$/, '');
  return base === '_base' ? '_base/system' : `dd/${base}`;
}
const cleanOid = (o) => String(o).trim().replace(/^\./, '');

function convSymbol(s, m, mib, isColumn) {
  if (!s || typeof s !== 'object') return null;
  if (s.constant_value_one) {
    report.skippedSymbols.constant_value_one++;
    return null;
  }
  const mtype = s.metric_type || m.metric_type || m.forced_type;
  if (mtype === 'flag_stream') {
    report.skippedSymbols.flag_stream++;
    return null;
  }
  if (!s.OID || !s.name) {
    report.skippedSymbols.no_oid++;
    return null;
  }
  const out = { name: s.name, oid: cleanOid(s.OID) };
  if (mib) out.mib = mib;
  if (s.scale_factor !== undefined) out.scale = Number(s.scale_factor);
  if (s.extract_value) out.regex = `/${s.extract_value}/`;
  if (mtype && /monotonic_count/.test(mtype)) out.type = 'counter';
  const ov = OVERRIDES[out.oid];
  if (ov) {
    for (const [k, v] of Object.entries(ov)) if (!k.startsWith('_')) out[k] = v;
    report.overrides = (report.overrides || 0) + 1;
  }
  return out;
}

function chooseLabel(tags, tableOid) {
  const cands = [];
  for (const t of tags || []) {
    const sym = t.symbol || (t.column ? t.column : null);
    if (!sym || t.mapping || t.match) continue;
    const name = typeof sym === 'string' ? sym : sym.name;
    const oid = typeof sym === 'object' ? sym.OID : t.OID;
    if (!oid) continue;
    let score = 0;
    LABEL_PREF.forEach((re, i) => {
      if (!score && (re.test(name) || re.test(t.tag || ''))) score = 10 - i;
    });
    const label = { oid: cleanOid(oid) };
    if (t.index_transform) {
      const parts = [];
      for (const r of t.index_transform) for (let i = Number(r.start); i <= Number(r.end); i++) parts.push(i);
      label.indexParts = parts;
    }
    cands.push({ score, label, name });
  }
  cands.sort((a, b) => b.score - a.score);
  return cands[0] ? cands[0].label : null;
}

function convert(file) {
  const d = YAML.parse(fs.readFileSync(path.join(SRC, file), 'utf8')) || {};
  const id = idOf(file);
  if (id === '_base/system') return null; // nf-snmp has its own base
  const sysoids0 = [].concat(d.sysobjectid || []).map(String);
  const ent = sysoids0.map((s) => /^\.?1\.3\.6\.1\.4\.1\.(\d+)/.exec(s.trim())).find(Boolean);
  const vendor = (d.device && d.device.vendor && String(d.device.vendor)) || (ent ? enterpriseName(Number(ent[1])) || '' : '');
  const pretty = file.replace(/\.yaml$/, '').replace(/^_/, '').split(/[-_]/).map((w) => (/^(ups|pdu|ilo|wlc|asa|ap|idrac|bmc|nas|san|f5|mx|ex|srx|sd|wan|vpn)$|\d/i.test(w) ? w.toUpperCase() : w.charAt(0).toUpperCase() + w.slice(1))).join(' ');
  const p = {
    id,
    name: `${pretty} (Datadog)`,
    vendor,
    source: { from: 'datadog/integrations-core', file: `snmp/datadog_checks/snmp/data/default_profiles/${file}`, commit: COMMIT, license: 'BSD-3-Clause' },
    priority: -5, // hand-written nf-snmp profiles win equal matches
  };
  const ext = [];
  for (const e of d.extends || []) {
    const base = e.replace(/\.yaml$/, '');
    if (!exists.has(base)) {
      report.droppedExtends.push(`${file}: ${e}`);
      continue;
    }
    ext.push(idOf(`${base}.yaml`));
  }
  if (!ext.includes('_base/system')) ext.unshift('_base/system');
  p.extends = ext;
  const sysoids = [].concat(d.sysobjectid || []).map(String);
  if (sysoids.length) p.match = sysoids.map((s) => ({ sysObjectID: s.trim() }));
  else p.abstract = true;

  const symbols = new Map();
  const tables = new Map();
  for (const m of d.metrics || []) {
    const mib = m.MIB;
    if (m.table && m.symbols) {
      const tOid = cleanOid(m.table.OID);
      let t = tables.get(tOid);
      if (!t) {
        t = { name: m.table.name || `table_${tOid}`, columns: [], _cols: new Set() };
        tables.set(tOid, t);
      }
      for (const s of m.symbols) {
        const c = convSymbol(s, m, mib, true);
        if (!c || t._cols.has(c.oid)) continue;
        t._cols.add(c.oid);
        t.columns.push(c);
      }
      if (!t.label) {
        const l = chooseLabel(m.metric_tags, tOid);
        if (l) t.label = l;
      }
    } else {
      const s = m.symbol ? m.symbol : m.OID ? { OID: m.OID, name: m.name } : null;
      const c = convSymbol(s, m, mib, false);
      if (c && !symbols.has(c.oid)) symbols.set(c.oid, c);
    }
  }
  if (symbols.size) p.symbols = [...symbols.values()];
  const tl = [...tables.values()].filter((t) => t.columns.length).map((t) => {
    delete t._cols;
    t.indexOid = t.columns[0].oid;
    if (t.label) report.labels++;
    return t;
  });
  if (tl.length) p.tables = tl;
  if (p.abstract) report.abstract++;
  report.converted++;
  return p;
}

fs.rmSync(OUT, { recursive: true, force: true });
fs.mkdirSync(OUT, { recursive: true });
for (const f of files) {
  try {
    const p = convert(f);
    if (!p) continue;
    fs.writeFileSync(path.join(OUT, `${p.id.slice(3)}.json`), JSON.stringify(p, null, 1) + '\n');
  } catch (e) {
    report.skipped.push(`${f}: ${e.message}`);
  }
}
fs.copyFileSync(path.join(SRC, 'LICENSE'), path.join(OUT, 'LICENSE-datadog'));
console.log(JSON.stringify(report, null, 1));
