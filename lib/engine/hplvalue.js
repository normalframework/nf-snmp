'use strict';
/**
 * hpl.v1.Value protojson <-> JS values for the HTTP driver.
 * protojson oneof names: null, boolean, unsigned, signed, real, double, octetString, characterString.
 */

/** @param {any} v hpl Value JSON @returns {{value: any, ts: number|undefined}} */
function fromHplValue(v) {
  if (v === undefined || v === null) return { value: null, ts: undefined };
  const ts = v.ts ? Date.parse(v.ts) : undefined;
  const has = (k) => Object.prototype.hasOwnProperty.call(v, k);
  let value = null;
  if (has('null')) value = null;
  else if (has('boolean')) value = v.boolean === true || v.boolean === 'true';
  else if (has('unsigned') || has('signed') || has('real') || has('double')) {
    const k = ['unsigned', 'signed', 'real', 'double'].find(has);
    value = Number(v[k]);
  } else if (has('characterString') || has('character_string')) value = String(v.characterString ?? v.character_string);
  else if (has('enumerated')) value = Number(v.enumerated);
  else if (has('octetString') || has('octet_string')) value = Buffer.from(String(v.octetString ?? v.octet_string), 'base64').toString('utf8');
  return { value, ts: Number.isNaN(ts) ? undefined : ts };
}

/** @param {any} value @param {number} [ts] */
function toHplValue(value, ts) {
  const out = {};
  if (ts !== undefined) out.ts = new Date(ts).toISOString();
  if (value === null || value === undefined) out.null = true;
  else if (typeof value === 'boolean') out.boolean = value;
  // NF keeps time series as float64; `real` (float32) would round 53.4 to 53.400001525878906.
  else if (typeof value === 'number') out.double = value;
  else out.characterString = String(value);
  return out;
}

module.exports = { fromHplValue, toHplValue };
