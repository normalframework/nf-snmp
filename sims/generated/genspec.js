'use strict';
// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Build a generated-simulator spec for every (non-abstract) profile: one simulated device per
 * profile, with the objects that profile reads, value types from the MIB (sims/generated/mibinfo.json,
 * produced by tools/verify-profiles.mjs), plausible engineering values chosen by unit, and the raw
 * encoding the device would use (inverse of the profile's scaling). gensimd.py serves the spec.
 *
 * Each object: {oid, type, kind, ...params, mult, key}
 *   kind wave:    raw = round(center + amp * sin(2π (step + phase) / period)), clamped to [lo, hi]
 *   kind enum:    raw = values[(step + phase) % values.length]
 *   kind counter: raw = (base + rate * step) mod 2^bits
 *   kind const:   raw = value
 *   kind text:    OctetString value (hex)            kind textnum: `${(wave * mult).toFixed(1)}${suffix}`
 *   eng = raw * mult (for wave/enum/counter/const) — written to /truth under `key` when key is set.
 * This is a smoke-test oracle: scaling comes from the same profile, so it proves profiles resolve,
 * expand and decode consistently, not that a vendor's scaling is right (see sims/device for that).
 */
const crypto = require('crypto');

const T = { INTEGER: 'Integer', Integer32: 'Integer', Gauge32: 'Gauge32', Gauge: 'Gauge32', Unsigned32: 'Gauge32', Counter32: 'Counter32', Counter: 'Counter32', Counter64: 'Counter64', TimeTicks: 'TimeTicks', 'OCTET STRING': 'OctetString', DisplayString: 'OctetString', 'OBJECT IDENTIFIER': 'OID', IpAddress: 'IpAddress', Opaque: 'OctetString', BITS: 'OctetString' };

const RANGES = { degC: [15, 35], degF: [60, 95], '%': [10, 90], '%RH': [30, 60], V: [110, 240], mV: [3000, 5000], A: [1, 30], mA: [100, 900], W: [100, 5000], kW: [1, 50], VA: [100, 5000], Wh: [1000, 90000], kWh: [10, 9000], Hz: [49, 61], s: [60, 9000], min: [5, 120], h: [1, 500], rpm: [1000, 6000], B: [0, 1e9] };

function h32(s) {
  return crypto.createHash('sha1').update(s).digest().readUInt32BE(0);
}

/** concrete sysObjectID for a match pattern */
function concreteOid(pat) {
  return String(pat).trim().replace(/^\./, '').split('.').map((a) => (a.includes('*') ? '1' : a)).join('.');
}

/**
 * Sample text for an extraction regex: the first capture group becomes "{}" (the number), simple
 * regex syntax is rendered literally (".*?" -> " ", "\\s+" -> " ", "\\(" -> "(").
 * integer: the group only admits digits.
 */
function regexTemplate(re) {
  let src = String(re).replace(/^\/(.*)\/[a-z]*$/, '$1').replace(/^\^/, '').replace(/\$$/, '');
  const g = /\((?!\?)((?:\\.|[^()])*)\)/.exec(src);
  const integer = g ? !/\.|\[[^\]]*\.[^\]]*\]|\\\.|\[\.]/.test(g[1]) || /^\\d\+$/.test(g[1]) : false;
  if (g) src = src.slice(0, g.index) + '\u0000' + src.slice(g.index + g[0].length);
  const lit = src
    .replace(/\.\*\??|\.\+\??|\\s[*+]\??|\[\^?[^\]]*\][*+]\??/g, ' ')
    .replace(/\\s/g, ' ')
    .replace(/\\(.)/g, '$1')
    .replace(/[?*+]/g, '')
    .replace(/\u0000/, '{}');
  return { template: g ? lit : `${lit} {}`, integer: g ? /^\\d\+$/.test(g[1]) : false };
}

function baseOf(oid, isCol) {
  return isCol ? oid : oid.replace(/\.\d+$/, '');
}

/**
 * @param {any} lib nf-snmp Library
 * @param {Record<string, any>} mib  mibinfo.json (oid -> facts)
 * @param {{rows?: number, basePort?: number, ids?: string[]}} [opts]
 */
function buildSpec(lib, mib, opts = {}) {
  const rows = opts.rows || 3;
  let port = opts.basePort || 20001;
  const devices = [];
  for (const id of opts.ids || lib.ids()) {
    const raw = lib.get(id);
    if (raw.abstract) continue;
    const p = lib.resolve(id);
    const dev = { id, port: port++, objects: [], warnings: [] };
    const m = (p.match || [])[0] || {};
    dev.sysObjectID = m.sysObjectID ? concreteOid(m.sysObjectID) : `1.3.6.1.4.1.99999.${h32(id) % 100000}`;
    dev.sysDescr = m.sysDescr ? String(m.sysDescr).replace(/^\/|\/[a-z]*$/g, '').replace(/[\\^$.*+?()[\]{}|]/g, '') : `Generated simulator for ${id}`;
    dev.sysName = `gen-${id.replace(/[^A-Za-z0-9]+/g, '-')}`;
    const add = (o) => {
      if (!dev.objects.some((x) => x.oid === o.oid)) dev.objects.push(o);
    };

    const objFor = (sym, oid, isCol, helpers, key) => {
      const facts = mib[baseOf(oid, isCol)] || {};
      let type = T[facts.base] || null;
      const units = sym.units || null;
      const enumVals = sym.enum ? Object.keys(sym.enum).map(Number).filter(Number.isFinite) : facts.enum ? Object.keys(facts.enum).map(Number) : null;
      if (!type) type = sym.type === 'counter' ? 'Counter32' : sym.regex || sym.type === 'string' ? 'OctetString' : 'Gauge32';
      const seed = h32(oid);
      if (type === 'OctetString' || type === 'OID' || type === 'IpAddress') {
        if (sym.regex) {
          const [lo, hi] = RANGES[units] || [10, 90];
          const { template, integer } = regexTemplate(sym.regex);
          const m10 = integer ? 1 : 10;
          return { oid, type: 'OctetString', kind: 'textnum', center: (lo + hi) / 2 * m10, amp: (hi - lo) / 4 * m10, period: 7 + (seed % 11), phase: seed % 13, lo: lo * m10, hi: hi * m10, mult: 1 / m10, decimals: integer ? 0 : 1, template, key };
        }
        if (type === 'OID') return { oid, type, kind: 'const', value: '1.3.6.1.4.1.99999.1' };
        if (type === 'IpAddress') return { oid, type, kind: 'const', value: '10.0.0.' + (1 + (seed % 200)) };
        return { oid, type, kind: 'text', value: Buffer.from(`gen-${sym.name}`.slice(0, 32)).toString('hex') };
      }
      if (sym.type === 'counter' || type === 'Counter32' || type === 'Counter64') {
        const bits = type === 'Counter64' ? 64 : 32;
        return { oid, type: type === 'Counter64' ? 'Counter64' : type === 'Counter32' ? 'Counter32' : type, kind: 'counter', base: seed % 100000, rate: 1 + (seed % 997), bits: type === 'Counter64' ? 64 : type === 'Counter32' ? 32 : 31, mult: 1, key, _bits: bits };
      }
      if (enumVals && enumVals.length) return { oid, type, kind: 'enum', values: enumVals.slice(0, 8), phase: seed % 5, mult: 1, key };
      // numeric: pick an engineering range by units, then encode with the profile's scaling
      let mult = 1;
      const d = sym;
      if (type === 'TimeTicks' && d.scale === undefined && !d.rawTicks) mult *= 0.01;
      if (helpers.decimalDigits !== undefined) mult /= 10 ** helpers.decimalDigits;
      if (helpers.entity) mult *= 0.1; // scale units(9), precision 1
      if (d.displayHint) mult /= 10 ** Number(/^d-(\d+)$/.exec(d.displayHint)[1]);
      if (d.scale !== undefined) mult *= Number(d.scale);
      let [lo, hi] = RANGES[units] || [5, 500];
      if (type === 'TimeTicks') [lo, hi] = [60, 90000];
      let rlo = Math.ceil(lo / mult);
      let rhi = Math.floor(hi / mult);
      if (facts.range) {
        rlo = Math.max(rlo, facts.range[0]);
        rhi = Math.min(rhi, facts.range[1]);
        if (rlo > rhi) [rlo, rhi] = [facts.range[0], facts.range[1]];
      }
      if (type !== 'Integer') rlo = Math.max(0, rlo);
      if (!(rhi >= rlo)) [rlo, rhi] = [0, 100];
      const center = Math.round((rlo + rhi) / 2);
      const amp = Math.max(1, Math.floor((rhi - rlo) / 3));
      return { oid, type, kind: 'wave', center, amp, period: 7 + (seed % 11), phase: seed % 13, lo: rlo, hi: rhi, mult, offset: d.offset || 0, key };
    };

    for (const s of p.symbols || []) {
      if (s.point === false) {
        add(objFor(s, s.oid, false, {}, null));
        continue;
      }
      const key = s.name.endsWith('.0') ? s.name : `${s.name}.0`;
      const helpers = {};
      if (s.decimalDigitsOid) {
        helpers.decimalDigits = 1;
        add({ oid: s.decimalDigitsOid, type: 'Gauge32', kind: 'const', value: 1 });
      }
      add(objFor(s, s.oid, false, helpers, s.oid.endsWith('.0') ? key : `${s.name}.${s.oid.split('.').pop()}`));
    }
    for (const t of p.tables || []) {
      const parts = [];
      const collect = (ip) => (ip || []).forEach((x) => parts.push(x));
      if (t.label) collect(t.label.indexParts);
      for (const c of t.columns) if (c.unitsFrom) collect(c.unitsFrom.indexParts);
      const arity = parts.length ? Math.max(...parts) + 1 : 1;
      const idx = Array.from({ length: rows }, (_, i) => [i + 1, ...Array(arity - 1).fill(1)].join('.'));
      const proj = (i, ip) => (ip ? ip.map((n) => i.split('.')[n]).join('.') : i);
      for (const i of idx) {
        if (t.label) add({ oid: `${t.label.oid}.${proj(i, t.label.indexParts)}`, type: 'OctetString', kind: 'text', value: Buffer.from(`Row ${i}`).toString('hex') });
        if (t.rowFilter) {
          const col = t.rowFilter.oid || t.columns.find((c) => c.name === t.rowFilter.column).oid;
          const v = t.rowFilter.in ? Number(t.rowFilter.in[0]) : 1;
          add({ oid: `${col}.${i}`, type: 'Integer', kind: 'const', value: v });
        }
        for (const c of t.columns) {
          const helpers = {};
          if (c.decimalDigitsOid) {
            helpers.decimalDigits = 1;
            add({ oid: `${c.decimalDigitsOid}.${i}`, type: 'Gauge32', kind: 'const', value: 1 });
          }
          if (c.entitySensor) {
            helpers.entity = true;
            add({ oid: `${c.entitySensor.scaleOid}.${i}`, type: 'Integer', kind: 'const', value: 9 });
            add({ oid: `${c.entitySensor.precisionOid}.${i}`, type: 'Integer', kind: 'const', value: 1 });
            if (c.entitySensor.statusOid) add({ oid: `${c.entitySensor.statusOid}.${i}`, type: 'Integer', kind: 'const', value: 1 });
          }
          let units = c.units;
          if (c.unitsFrom) {
            const hit = Object.entries(c.unitsFrom.map).find(([, v]) => v && v.units && !v.skip);
            const k = hit ? hit[0] : Object.keys(c.unitsFrom.map)[0];
            units = hit ? hit[1].units : units;
            add({ oid: `${c.unitsFrom.oid}.${proj(i, c.unitsFrom.indexParts)}`, type: 'Integer', kind: 'const', value: Number(k) });
          }
          if (t.rowFilter && (c.name === t.rowFilter.column || c.oid === t.rowFilter.oid)) continue;
          add(objFor(Object.assign({}, c, { units }), `${c.oid}.${i}`, true, helpers, c.point === false ? null : `${c.name}.${i}`));
        }
      }
    }
    if (m.probe) {
      const po = m.probe.replace(/^\./, '');
      if (!dev.objects.some((o) => o.oid === po || o.oid.startsWith(po + '.'))) add({ oid: `${po}.0`, type: 'Integer', kind: 'const', value: 1 });
    }
    devices.push(dev);
  }
  return { generatedAt: new Date().toISOString(), stepMs: 10000, devices };
}

module.exports = { buildSpec, concreteOid, regexTemplate };
