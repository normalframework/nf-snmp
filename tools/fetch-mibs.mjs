#!/usr/bin/env node
// Fetch MIB modules (and everything they IMPORT, recursively) from the LibreNMS MIB collection at
// the commit pinned in vendor/librenms/SOURCE_COMMIT, into mibs/<MODULE>.
//   node tools/fetch-mibs.mjs MODULE...        |   node tools/fetch-mibs.mjs --profiles
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const MIBS = path.join(ROOT, 'mibs');
const SHA = fs.readFileSync(path.join(ROOT, 'vendor/librenms/SOURCE_COMMIT'), 'utf8').trim();
const index = new Map();
for (const p of fs.readFileSync(path.join(ROOT, 'vendor/librenms/mibs-index.txt'), 'utf8').split('\n').filter(Boolean)) {
  const k = p.split('/').pop().toUpperCase();
  if (!index.has(k) || p.split('/').length < index.get(k).split('/').length) index.set(k, p); // prefer top-level copies
}
// modules net-snmp's parser provides itself, or that are pure macro definitions
const BUILTIN = new Set(['SNMPV2-SMI', 'SNMPV2-TC', 'SNMPV2-CONF', 'RFC1155-SMI', 'RFC-1212', 'RFC-1215', 'RFC1213-MIB', 'SNMPV2-MIB']);

export function imports(text) {
  const m = /\bIMPORTS\b([\s\S]*?);/.exec(text.replace(/--[^\n]*/g, ''));
  if (!m) return [];
  return [...m[1].matchAll(/\bFROM\s+([A-Za-z0-9-]+)/g)].map((x) => x[1]);
}

export function localFile(mod) {
  const f = fs.readdirSync(MIBS).find((x) => x.toUpperCase() === mod.toUpperCase());
  return f ? path.join(MIBS, f) : null;
}

export async function fetchModules(mods, log = () => {}) {
  const seen = new Set();
  const missing = new Set();
  const queue = [...mods];
  let fetched = 0;
  while (queue.length) {
    const batch = queue.splice(0, 16).filter((m) => !seen.has(m.toUpperCase()));
    batch.forEach((m) => seen.add(m.toUpperCase()));
    await Promise.all(batch.map(async (mod) => {
      let file = localFile(mod);
      if (!file) {
        const p = index.get(mod.toUpperCase());
        if (!p) {
          if (!BUILTIN.has(mod.toUpperCase())) missing.add(mod);
          return;
        }
        const res = await fetch(`https://raw.githubusercontent.com/librenms/librenms/${SHA}/${p}`);
        if (!res.ok) {
          missing.add(mod);
          return;
        }
        file = path.join(MIBS, p.split('/').pop());
        fs.writeFileSync(file, Buffer.from(await res.arrayBuffer()));
        fetched++;
      }
      for (const dep of imports(fs.readFileSync(file, 'latin1'))) if (!seen.has(dep.toUpperCase())) queue.push(dep);
    }));
  }
  log(`fetched ${fetched}, missing ${missing.size}`);
  return { fetched, missing: [...missing].sort() };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  let mods = process.argv.slice(2);
  if (mods[0] === '--profiles') {
    const s = new Set();
    const walk = (d) => {
      for (const e of fs.readdirSync(d, { withFileTypes: true })) {
        const p = path.join(d, e.name);
        if (e.isDirectory()) walk(p);
        else if (e.name.endsWith('.json')) {
          const j = JSON.parse(fs.readFileSync(p, 'utf8'));
          if (j.mib) s.add(j.mib);
          for (const x of [...(j.symbols || []), ...(j.tables || []).flatMap((t) => t.columns)]) if (x.mib) s.add(x.mib);
        }
      }
    };
    walk(path.join(ROOT, 'profiles'));
    mods = [...s];
  }
  const r = await fetchModules(mods, console.log);
  console.log(JSON.stringify(r.missing));
}
