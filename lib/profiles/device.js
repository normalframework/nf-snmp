'use strict';
/**
 * Device-level profile operations:
 *   identify(client, lib)                  -> sysObjectID/sysDescr + ranked profiles
 *   materialize(client, profile)           -> concrete point specs (tables expanded by walking)
 *   readSpecs(client, specs, helperCache)  -> decoded values per spec
 */
const { decode, DecodeError } = require('./decode');
const { hexToText, cleanOid } = require('../snmp/normalize');
const { enterpriseName } = require('./enterprises');

const SYS = {
  sysDescr: '1.3.6.1.2.1.1.1.0',
  sysObjectID: '1.3.6.1.2.1.1.2.0',
  sysUpTime: '1.3.6.1.2.1.1.3.0',
  sysContact: '1.3.6.1.2.1.1.4.0',
  sysName: '1.3.6.1.2.1.1.5.0',
  sysLocation: '1.3.6.1.2.1.1.6.0',
};

const HELPER_TTL_MS = 10 * 60 * 1000;

/**
 * @param {import('../snmp/client').SnmpClient} client
 * @param {import('./index').Library} lib
 */
async function identify(client, lib) {
  // readMany: splits on tooBig, isolates v1 noSuchName, fails fast on a dead device
  const res = await client.readMany(Object.values(SYS));
  const by = {};
  let answered = false;
  for (const [k, oid] of Object.entries(SYS)) {
    const vb = res.get(oid);
    if (!vb) continue;
    if (vb.error) {
      if (vb.error === 'timeout' || vb.error === 'authError') throw Object.assign(new Error(vb.message || vb.error), { class: vb.error });
      if (!/^NoSuch/.test(vb.error)) continue;
      answered = true;
      continue;
    }
    answered = true;
    by[k] = vb.type === 'OctetString' ? hexToText(vb.value) ?? vb.value : vb.value;
  }
  if (!answered) throw Object.assign(new Error('device did not answer the system group'), { class: 'other' });
  const ent = /^1\.3\.6\.1\.4\.1\.(\d+)/.exec(by.sysObjectID || '');
  const enterprise = ent ? Number(ent[1]) : null;
  const probeCache = new Map();
  const probe = async (oid) => {
    if (probeCache.has(oid)) return probeCache.get(oid);
    let ok = false;
    try {
      const [vb] = await client.get([oid]);
      ok = !!vb && !['NoSuchObject', 'NoSuchInstance', 'EndOfMibView'].includes(vb.type);
      if (!ok) {
        // a probe of a table column (no instance) is satisfied by any row
        const [nx] = await client.getNext([oid]);
        ok = !!nx && nx.oid.startsWith(oid + '.');
      }
    } catch {
      ok = false;
    }
    probeCache.set(oid, ok);
    return ok;
  };
  const candidates = await lib.rank(by, probe);
  const best = candidates[0] || null;
  let confidence = 'none';
  if (best) confidence = best.score >= 100 * 9 ? 'high' : best.score >= 50 ? 'medium' : 'low';
  return {
    sysObjectID: by.sysObjectID || null,
    sysDescr: by.sysDescr || null,
    sysName: by.sysName || null,
    sysLocation: by.sysLocation || null,
    sysUpTime: by.sysUpTime !== undefined ? Number(by.sysUpTime) / 100 : null,
    enterprise,
    vendor: enterprise !== null ? enterpriseName(enterprise) : null,
    candidates,
    profile: best ? { id: best.id, name: lib.get(best.id).name, reason: best.reason } : null,
    confidence,
  };
}

/**
 * Expand a resolved profile into concrete point specs for one device.
 * @param {import('../snmp/client').SnmpClient} client
 * @param {any} profile resolved profile
 * @returns {Promise<{specs: any[], warnings: string[]}>}
 */
async function materialize(client, profile) {
  let specs = [];
  const warnings = [];
  for (const s of profile.symbols || []) {
    if (s.point === false) continue;
    specs.push(makeSpec(s, cleanOid(s.oid), null, null));
  }
  for (const t of profile.tables || []) {
    const idxCol = cleanOid(t.indexOid || t.columns[0].oid);
    const w = await client.walk(idxCol);
    if (w.error) warnings.push(`table ${t.name}: walk of ${idxCol} stopped: ${w.error.message}`);
    let indexes = w.varbinds.map((vb) => vb.oid.slice(idxCol.length + 1));
    if (t.maxRows && indexes.length > t.maxRows) {
      warnings.push(`table ${t.name}: ${indexes.length} rows, keeping first ${t.maxRows}`);
      indexes = indexes.slice(0, t.maxRows);
    }
    if (t.rowFilter) {
      const f = t.rowFilter;
      const col = cleanOid(f.oid || t.columns.find((c) => c.name === f.column).oid);
      const vals = await client.readMany(indexes.map((i) => `${col}.${i}`));
      indexes = indexes.filter((i) => {
        const vb = vals.get(`${col}.${i}`);
        if (!vb || vb.error) return false;
        const v = vb.type === 'OctetString' ? hexToText(vb.value) : vb.value;
        if (f.in) return f.in.map(String).includes(String(v));
        if (f.notIn) return !f.notIn.map(String).includes(String(v));
        return true;
      });
    }
    // labels: a column in this table, or another OID with the same index (e.g. entPhysicalName)
    const labels = new Map();
    if (t.label) {
      const lo = t.label.oid ? cleanOid(t.label.oid) : cleanOid(t.columns.find((c) => c.name === t.label.column).oid);
      const vals = await client.readMany(indexes.map((i) => `${lo}.${unitIndex(i, t.label)}`));
      for (const i of indexes) {
        const vb = vals.get(`${lo}.${unitIndex(i, t.label)}`);
        if (vb && !vb.error) {
          const txt = vb.type === 'OctetString' ? hexToText(vb.value) : vb.value;
          if (txt) labels.set(i, sanitizeLabel(txt));
        }
      }
    }
    // per-row units / class from another column (e.g. entPhySensorType, Raritan sensor type)
    const unitRows = new Map();
    for (const c of t.columns) {
      if (!c.unitsFrom) continue;
      const uo = cleanOid(c.unitsFrom.oid);
      const vals = await client.readMany(indexes.map((i) => `${uo}.${unitIndex(i, c.unitsFrom)}`));
      for (const i of indexes) {
        const vb = vals.get(`${uo}.${unitIndex(i, c.unitsFrom)}`);
        if (vb && !vb.error) unitRows.set(`${c.name}|${i}`, c.unitsFrom.map[String(vb.value)]);
      }
    }
    for (const i of indexes) {
      for (const c of t.columns) {
        if (c.point === false) continue;
        const spec = makeSpec(c, `${cleanOid(c.oid)}.${i}`, i, labels.get(i) || null, t);
        const u = unitRows.get(`${c.name}|${i}`);
        if (u) {
          if (u.skip) continue;
          if (u.units !== undefined) spec.units = u.units;
          if (u.class) spec.class = u.class;
          if (u.scale !== undefined) spec.decode.scale = u.scale;
        }
        specs.push(spec);
      }
    }
  }
  // Drop points the device says do not exist (firmware/model variation, e.g. APC
  // upsHighPrecExtd* on older cards, Raritan state-only sensors). Only definitive
  // "no such" answers prune; timeouts and other errors keep the point.
  // Also: NF trends numbers only, so symbols whose value is text (model names, firmware
  // versions, labels) become attributes of the device point instead of points.
  const attrs = {};
  let unsupported = [];
  if (specs.length) {
    const res = await client.readMany(specs.map((sp) => sp.oid));
    const missing = profile.keepMissing ? [] : specs.filter((sp) => {
      const r = res.get(sp.oid);
      return r && r.error && /^NoSuch/.test(r.error);
    });
    const text = specs.filter((sp) => {
      const r = res.get(sp.oid);
      if (!r || r.error || sp.enum) return false;
      if (sp.decode.type === 'string' || ((r.type === 'OctetString' || r.type === 'OID' || r.type === 'IpAddress') && !sp.decode.regex && sp.decode.type !== 'number')) {
        try {
          const v = decode(r, sp);
          if (typeof v === 'string') {
            attrs[attrName(sp)] = v;
            return true;
          }
        } catch {
          return false;
        }
      }
      return false;
    });
    if (missing.length) warnings.push(`${missing.length} profile objects not supported by this device: ${[...new Set(missing.map((m) => m.name))].join(', ')}`);
    unsupported = missing.map((m) => ({ name: m.displayName, oid: m.oid }));
    const gone = new Set([...missing, ...text]);
    specs = specs.filter((sp) => !gone.has(sp));
  }
  return { specs, warnings, unsupported, attrs };
}

/** device-point attribute name for a text symbol, e.g. upsBasicIdentModel, outletName_Rack_A */
function attrName(sp) {
  const base = sp.name.replace(/[^A-Za-z0-9_]/g, '_');
  return sp.label ? `${base}_${sp.label.replace(/[^A-Za-z0-9]+/g, '_')}` : sp.index ? `${base}_${sp.index.replace(/\./g, '_')}` : base;
}

function unitIndex(i, from) {
  if (from.indexParts === undefined) return i;
  const parts = i.split('.');
  return from.indexParts.map((p) => parts[p]).join('.');
}

function sanitizeLabel(s) {
  return String(s).replace(/[\x00-\x1f]/g, '').trim().slice(0, 80);
}

function makeSpec(sym, oid, index, label, table) {
  const withIdx = (o) => (o ? (index !== null && index !== undefined ? `${cleanOid(o)}.${index}` : cleanOid(o)) : undefined);
  const decodeRules = {
    type: sym.type,
    scale: sym.scale,
    offset: sym.offset,
    displayHint: sym.displayHint,
    enum: sym.enum,
    regex: sym.regex,
    sentinels: sym.sentinels,
    trueValues: sym.trueValues,
    rawTicks: sym.rawTicks,
    decimalDigitsOid: withIdx(sym.decimalDigitsOid),
  };
  if (sym.entitySensor) {
    decodeRules.entitySensor = {
      scaleOid: withIdx(sym.entitySensor.scaleOid),
      precisionOid: withIdx(sym.entitySensor.precisionOid),
      statusOid: withIdx(sym.entitySensor.statusOid),
    };
  }
  for (const k of Object.keys(decodeRules)) if (decodeRules[k] === undefined) delete decodeRules[k];
  const key = index !== null && index !== undefined ? `${sym.name}.${index}` : sym.name.endsWith('.0') ? sym.name : `${sym.name}.0`;
  return {
    oid,
    name: sym.name,
    key, // "<MIB object>.<index>" — matches simulator truth keys
    index: index ?? null,
    label,
    table: table ? table.name : null,
    displayName: label ? `${label} ${sym.name}` : sym.name,
    units: sym.units || null,
    class: sym.class || null,
    writable: !!sym.writable,
    setType: sym.setType || null,
    enum: sym.enum || null,
    periodSeconds: sym.periodSeconds || null,
    decode: decodeRules,
  };
}

/** Helper OIDs a spec needs to decode. */
function helperOids(spec) {
  const d = spec.decode || {};
  const out = [];
  if (d.decimalDigitsOid) out.push(d.decimalDigitsOid);
  if (d.entitySensor) {
    for (const k of ['scaleOid', 'precisionOid', 'statusOid']) if (d.entitySensor[k]) out.push(d.entitySensor[k]);
  }
  return out;
}

class HelperCache {
  constructor(ttlMs = HELPER_TTL_MS, now = Date.now) {
    this.ttlMs = ttlMs;
    this.now = now;
    this.map = new Map();
  }
  get(oid) {
    const e = this.map.get(oid);
    if (!e) return undefined;
    if (this.now() - e.at > this.ttlMs) return undefined;
    return e.vb;
  }
  set(oid, vb) {
    this.map.set(oid, { vb, at: this.now() });
  }
}

/**
 * Read and decode specs in as few PDUs as possible. Helper OIDs are cached.
 * @param {import('../snmp/client').SnmpClient} client
 * @param {any[]} specs
 * @param {HelperCache} [helpers]
 * @returns {Promise<{spec: any, value?: any, raw?: any, error?: string, code?: string}[]>}
 */
async function readSpecs(client, specs, helpers = new HelperCache()) {
  const want = new Set();
  for (const s of specs) {
    want.add(s.oid);
    for (const h of helperOids(s)) if (helpers.get(h) === undefined) want.add(h);
  }
  const res = await client.readMany([...want]);
  for (const s of specs) for (const h of helperOids(s)) if (res.has(h) && !res.get(h).error) helpers.set(h, res.get(h));
  const lookup = (oid) => helpers.get(oid) || res.get(oid);
  return specs.map((spec) => {
    const raw = res.get(spec.oid);
    if (!raw || raw.error) return { spec, raw, error: (raw && (raw.message || raw.error)) || 'no response', code: (raw && raw.error) || 'E_READ' };
    try {
      return { spec, raw, value: decode(raw, spec, lookup) };
    } catch (e) {
      return { spec, raw, error: e.message, code: e instanceof DecodeError ? e.code : 'E_DECODE' };
    }
  });
}

/** CLI helper: materialize + read a whole profile. */
async function readProfile(client, profile) {
  const { specs, warnings } = await materialize(client, profile);
  const rows = await readSpecs(client, specs);
  return {
    profile: profile.id,
    warnings,
    points: rows.map((r) => ({ key: r.spec.key, name: r.spec.displayName, oid: r.spec.oid, value: r.value, units: r.spec.units, error: r.error })),
  };
}

module.exports = { identify, materialize, readSpecs, readProfile, HelperCache, helperOids, SYS };
