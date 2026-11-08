'use strict';
/**
 * Raw normalized varbind -> engineering value, per the profile symbol rules (docs/internals.md §4).
 */
const { hexToText } = require('../snmp/normalize');

const INT_TYPES = new Set(['Integer', 'Counter32', 'Gauge32', 'TimeTicks', 'Counter64']);

class DecodeError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

/** RFC 3433 entPhySensorScale enum (1..17) -> power of ten. scale 9 = units (10^0). */
function entitySensorPower(scale) {
  const s = Number(scale);
  if (!(s >= 1 && s <= 17)) throw new DecodeError('E_HELPER', `invalid entPhySensorScale ${scale}`);
  return 3 * (s - 9);
}

/**
 * @param {{type: string, value: string}} raw normalized varbind
 * @param {object} spec point spec decode rules
 * @param {(oid: string) => ({type:string,value:string}|undefined)} helper lookup of helper OID values
 * @returns {number|string|boolean}
 */
function decode(raw, spec, helper = () => undefined) {
  const d = spec.decode || spec;
  if (!raw || raw.error) throw new DecodeError('E_READ', (raw && (raw.message || raw.error)) || 'no value');
  if (d.sentinels && d.sentinels.map(String).includes(rawScalarString(raw))) {
    throw new DecodeError('E_NOT_AVAILABLE', `sentinel value ${rawScalarString(raw)}`);
  }
  const want = d.type || 'auto';

  // ---- strings
  if (raw.type === 'OctetString' || raw.type === 'Opaque') {
    const text = hexToText(raw.value);
    if (d.regex) {
      const re = new RegExp(d.regex.replace(/^\/(.*)\/$/, '$1'));
      const m = re.exec(text ?? '');
      if (!m) throw new DecodeError('E_PARSE', `"${text}" does not match ${d.regex}`);
      // A number parsed out of text ("23.5 C") is already in engineering units: no scale/offset.
      const n = Number(m[1] !== undefined ? m[1] : m[0]);
      if (!Number.isFinite(n)) throw new DecodeError('E_PARSE', `"${text}" has no number`);
      return n;
    }
    if (want === 'number') {
      const n = Number(String(text ?? '').trim());
      if (!Number.isFinite(n)) throw new DecodeError('E_PARSE', `"${text}" is not a number`);
      return applyNumeric(n, d, helper);
    }
    if (want === 'hex' || text === null) return raw.value;
    return text;
  }
  if (raw.type === 'OID' || raw.type === 'IpAddress') return raw.value;
  if (!INT_TYPES.has(raw.type)) throw new DecodeError('E_TYPE', `cannot decode ${raw.type}`);

  // ---- numbers
  let n = Number(raw.value);
  if (want === 'string') return raw.value;
  if (want === 'boolean') {
    const t = d.trueValues ? d.trueValues.map(Number) : [1];
    return t.includes(n);
  }
  if (raw.type === 'TimeTicks' && d.scale === undefined && !d.rawTicks) n = n / 100; // centiseconds -> seconds
  return applyNumeric(n, d, helper);
}

function applyNumeric(n, d, helper) {
  let v = n;
  if (d.entitySensor) {
    const es = d.entitySensor;
    const s = helper(es.scaleOid);
    const p = helper(es.precisionOid);
    const st = es.statusOid ? helper(es.statusOid) : undefined;
    if (!s || s.error) throw new DecodeError('E_HELPER', 'entPhySensorScale unavailable');
    if (st && !st.error && Number(st.value) !== 1) throw new DecodeError('E_NOT_AVAILABLE', `entPhySensorOperStatus ${st.value}`);
    if (Math.abs(v) >= 1e9) throw new DecodeError('E_NOT_AVAILABLE', 'entPhySensorValue out of range');
    const prec = p && !p.error ? Number(p.value) : 0;
    v = v * Math.pow(10, entitySensorPower(s.value)) / Math.pow(10, prec);
  }
  if (d.decimalDigitsOid) {
    const h = helper(d.decimalDigitsOid);
    if (!h || h.error) throw new DecodeError('E_HELPER', `decimal digits (${d.decimalDigitsOid}) unavailable`);
    v = v / Math.pow(10, Number(h.value));
  }
  if (d.displayHint) {
    const m = /^d-(\d+)$/.exec(d.displayHint);
    if (m) v = v / Math.pow(10, Number(m[1]));
  }
  if (d.scale !== undefined) v = v * Number(d.scale);
  if (d.offset !== undefined) v = v + Number(d.offset);
  // tame binary float noise from scaling (0.1*243 = 24.300000000000004)
  if (!Number.isInteger(v)) v = Number(v.toPrecision(12));
  return v;
}

function rawScalarString(raw) {
  return raw.type === 'OctetString' ? hexToText(raw.value) ?? raw.value : raw.value;
}

/**
 * Engineering value -> normalized varbind for SET (inverse of decode for numeric symbols).
 * @param {any} value @param {object} spec
 */
function encode(value, spec, helper = () => undefined) {
  const d = spec.decode || spec;
  const setType = spec.setType || 'Integer';
  if (setType === 'OctetString') return { oid: spec.oid, type: 'OctetString', value: Buffer.from(String(value)).toString('hex') };
  let v = typeof value === 'boolean' ? (value ? 1 : 0) : Number(value);
  if (d.enum && typeof value === 'string' && Number.isNaN(v)) {
    const hit = Object.entries(d.enum).find(([, label]) => label === value);
    if (!hit) throw new DecodeError('E_VALUE', `unknown enum label ${value}`);
    return { oid: spec.oid, type: setType, value: String(Number(hit[0])) }; // enum values are not scaled
  }
  if (!Number.isFinite(v)) throw new DecodeError('E_VALUE', `value ${value} is not a number`);
  if (d.offset !== undefined) v = v - Number(d.offset);
  if (d.scale !== undefined) v = v / Number(d.scale);
  if (d.displayHint) {
    const m = /^d-(\d+)$/.exec(d.displayHint);
    if (m) v = v * Math.pow(10, Number(m[1]));
  }
  if (d.decimalDigitsOid) {
    const h = helper(d.decimalDigitsOid);
    if (!h || h.error) throw new DecodeError('E_HELPER', 'decimal digits unavailable');
    v = v * Math.pow(10, Number(h.value));
  }
  v = Math.round(v);
  return { oid: spec.oid, type: setType, value: String(v) };
}

module.exports = { decode, encode, DecodeError, entitySensorPower };
