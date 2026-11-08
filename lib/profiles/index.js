'use strict';
/**
 * Profile library: load profiles/<vendor>/<model>.json, resolve `extends`, validate, match.
 * Format: docs/internals.md §4.
 */
const fs = require('fs');
const path = require('path');
const { cleanOid } = require('../snmp/normalize');

const BUILTIN_DIR = path.resolve(__dirname, '..', '..', 'profiles');

const SYMBOL_KEYS = new Set([
  'name', 'oid', 'scale', 'offset', 'decimalDigitsOid', 'displayHint', 'entitySensor', 'enum', 'regex',
  'type', 'units', 'class', 'writable', 'setType', 'point', 'sentinels', 'description', 'trueValues', 'periodSeconds', 'rawTicks', 'unitsFrom', 'mib', 'mibVerified',
]);

class Library {
  constructor() {
    /** @type {Map<string, any>} raw profiles by id */
    this.raw = new Map();
    /** @type {Map<string, any>} resolved cache */
    this.cache = new Map();
  }

  ids() {
    return [...this.raw.keys()].sort();
  }

  /** @param {string} id */
  get(id) {
    const p = this.raw.get(id);
    if (!p) throw Object.assign(new Error(`unknown profile ${id}`), { code: 'E_PROFILE' });
    return p;
  }

  /** Profile with `extends` merged (parents first; child symbols/tables override by name). */
  resolve(id, seen = new Set()) {
    if (typeof id === 'object') id = id.id;
    if (this.cache.has(id)) return this.cache.get(id);
    if (seen.has(id)) throw Object.assign(new Error(`profile extends cycle at ${id}`), { code: 'E_PROFILE' });
    seen.add(id);
    const p = this.get(id);
    const symbols = new Map();
    const tables = new Map();
    const helpers = new Map();
    for (const parent of p.extends || []) {
      const r = this.resolve(parent, seen);
      for (const s of r.symbols) symbols.set(s.name, s);
      for (const t of r.tables) tables.set(t.name, t);
    }
    for (const s of p.symbols || []) symbols.set(s.name, s);
    for (const t of p.tables || []) tables.set(t.name, t);
    void helpers;
    const out = Object.assign({}, p, { symbols: [...symbols.values()], tables: [...tables.values()] });
    this.cache.set(id, out);
    return out;
  }

  /** @param {any} p @param {string} [file] */
  add(p, file) {
    validate(p, file);
    this.raw.set(p.id, p);
    this.cache.clear();
  }

  /**
   * Rank profiles for an identified device.
   * @param {{sysObjectID?: string, sysDescr?: string}} ident
   * @param {(oid: string) => Promise<boolean>} [probe] does this OID exist on the device
   * @returns {Promise<{id: string, score: number, reason: string}[]>}
   */
  async rank(ident, probe) {
    const out = [];
    for (const p of this.raw.values()) {
      if (p.abstract) continue;
      let best = null;
      for (const alt of p.match || []) {
        const r = await scoreAlt(alt, ident, probe);
        if (r && (!best || r.score > best.score)) best = r;
      }
      // priority breaks ties between generic probe-only profiles (UPS-MIB beats IF-MIB)
      if (best) out.push({ id: p.id, score: best.score + Number(p.priority || 0), reason: best.reason });
    }
    out.sort((a, b) => b.score - a.score || a.id.localeCompare(b.id));
    return out;
  }
}

async function scoreAlt(alt, ident, probe) {
  let score = 0;
  const reasons = [];
  if (alt.sysObjectID !== undefined) {
    const have = ident.sysObjectID || '';
    const pat = String(alt.sysObjectID).trim().replace(/^\./, '');
    if (pat.includes('*')) {
      // Datadog-style wildcard: "1.3.6.1.4.1.318.1.*"; score by the fixed arcs before the first '*'
      const re = new RegExp('^' + pat.split('*').map((x) => x.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('[0-9.]*') + '$');
      if (!re.test(have)) return null;
      const fixed = pat.slice(0, pat.indexOf('*')).replace(/\.$/, '');
      const arcs = fixed ? fixed.split('.').length : 0;
      // A pattern that does not even fix the enterprise number (1.3.6.1.4.1.<n>) is a catch-all:
      // rank it below any positive evidence (a MIB probe scores 10).
      score += arcs >= 7 ? 100 * arcs : 1;
      reasons.push(`sysObjectID ${have} matches ${pat}`);
    } else {
      const want = cleanOid(pat);
      if (!(have === want || have.startsWith(want + '.'))) return null;
      // an exact match outranks a same-length prefix match
      score += 100 * want.split('.').length + (have === want ? 50 : 0);
      reasons.push(`sysObjectID ${have} under ${want}`);
    }
  }
  if (alt.sysDescr !== undefined) {
    if (!toRegex(alt.sysDescr).test(ident.sysDescr || '')) return null;
    score += 50;
    reasons.push(`sysDescr matches ${alt.sysDescr}`);
  }
  if (alt.probe !== undefined) {
    if (!probe) return null;
    const ok = await probe(cleanOid(alt.probe));
    if (!ok) return null;
    score += 10;
    reasons.push(`probe ${alt.probe} exists`);
  }
  if (!reasons.length) return null;
  return { score, reason: reasons.join(', ') };
}

function toRegex(s) {
  const m = /^\/(.*)\/([a-z]*)$/.exec(s);
  return m ? new RegExp(m[1], m[2]) : new RegExp(s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
}

function fail(file, msg) {
  throw Object.assign(new Error(`${file || 'profile'}: ${msg}`), { code: 'E_PROFILE' });
}

function validateSymbol(s, where, file) {
  if (!s || typeof s !== 'object') fail(file, `${where} must be an object`);
  if (!s.name) fail(file, `${where} needs a name`);
  if (!s.oid) fail(file, `${where} (${s.name}) needs an oid`);
  try {
    cleanOid(s.oid);
  } catch {
    fail(file, `${where} (${s.name}) has an invalid oid ${s.oid}`);
  }
  for (const k of Object.keys(s)) if (!SYMBOL_KEYS.has(k)) fail(file, `${where} (${s.name}) has unknown key ${k}`);
  if (s.displayHint && !/^d-\d+$/.test(s.displayHint)) fail(file, `${where} (${s.name}) displayHint must be d-N`);
  if (s.regex) {
    try {
      toRegex(s.regex);
    } catch (e) {
      fail(file, `${where} (${s.name}) bad regex: ${e.message}`);
    }
  }
}

function validate(p, file) {
  if (!p || typeof p !== 'object') fail(file, 'not an object');
  if (!p.id || typeof p.id !== 'string') fail(file, 'missing id');
  if (!p.abstract && !p.name) fail(file, 'missing name');
  (p.symbols || []).forEach((s, i) => validateSymbol(s, `symbols[${i}]`, file));
  (p.tables || []).forEach((t, i) => {
    if (!t.name) fail(file, `tables[${i}] needs a name`);
    if (!Array.isArray(t.columns) || !t.columns.length) fail(file, `tables[${i}] (${t.name}) needs columns`);
    t.columns.forEach((c, j) => validateSymbol(c, `tables[${i}].columns[${j}]`, file));
    if (t.indexOid) cleanOid(t.indexOid);
    if (t.label && t.label.column && !t.columns.find((c) => c.name === t.label.column)) fail(file, `tables[${i}] label column ${t.label.column} not in columns`);
  });
  for (const m of p.match || []) {
    if (m.sysObjectID && !String(m.sysObjectID).includes('*')) cleanOid(m.sysObjectID);
    if (m.sysObjectID && !/^\.?[0-9*]+(\.[0-9*]+)*$/.test(String(m.sysObjectID).trim())) fail(file, `bad sysObjectID pattern ${m.sysObjectID}`);
    if (m.probe) cleanOid(m.probe);
  }
}

/**
 * @param {{dirs?: string[], strict?: boolean, log?: any}} [opts]
 */
function loadLibrary(opts = {}) {
  const lib = new Library();
  const dirs = opts.dirs || [BUILTIN_DIR];
  for (const dir of dirs) {
    if (!fs.existsSync(dir)) continue;
    for (const file of walkJson(dir)) {
      try {
        lib.add(JSON.parse(fs.readFileSync(file, 'utf8')), path.relative(dir, file));
      } catch (e) {
        if (opts.strict) throw e;
        if (opts.log) opts.log.warn('skipping bad profile', { file, error: e.message });
      }
    }
  }
  // resolve everything once so extends errors surface at load
  for (const id of lib.ids()) {
    try {
      lib.resolve(id);
    } catch (e) {
      if (opts.strict) throw e;
      lib.raw.delete(id);
      if (opts.log) opts.log.warn('skipping profile', { id, error: e.message });
    }
  }
  return lib;
}

function walkJson(dir) {
  const out = [];
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, ent.name);
    if (ent.isDirectory()) out.push(...walkJson(p));
    else if (ent.name.endsWith('.json')) out.push(p);
  }
  return out.sort();
}

module.exports = { loadLibrary, Library, validate, toRegex, BUILTIN_DIR };
