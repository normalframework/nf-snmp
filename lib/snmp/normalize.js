'use strict';
/**
 * Conversion between net-snmp varbinds and the normalized varbind format (docs/internals.md §1).
 */
const snmp = require('net-snmp');

const T = snmp.ObjectType;

/** net-snmp type tag -> normalized type name */
const TYPE_NAMES = {
  [T.Boolean]: 'Integer',
  [T.Integer]: 'Integer',
  [T.BitString]: 'OctetString',
  [T.OctetString]: 'OctetString',
  [T.Null]: 'Null',
  [T.OID]: 'OID',
  [T.IpAddress]: 'IpAddress',
  [T.Counter]: 'Counter32',
  [T.Gauge]: 'Gauge32',
  [T.TimeTicks]: 'TimeTicks',
  [T.Opaque]: 'Opaque',
  [T.Counter64]: 'Counter64',
  [T.NoSuchObject]: 'NoSuchObject',
  [T.NoSuchInstance]: 'NoSuchInstance',
  [T.EndOfMibView]: 'EndOfMibView',
};

/** normalized type name -> net-snmp type tag (for SET) */
const TYPE_TAGS = {
  Integer: T.Integer,
  Integer32: T.Integer,
  OctetString: T.OctetString,
  OID: T.OID,
  IpAddress: T.IpAddress,
  Counter32: T.Counter,
  Gauge32: T.Gauge,
  Unsigned32: T.Gauge,
  TimeTicks: T.TimeTicks,
  Opaque: T.Opaque,
  Counter64: T.Counter64,
  Null: T.Null,
};

const EXCEPTIONS = new Set(['NoSuchObject', 'NoSuchInstance', 'EndOfMibView']);

/** @param {string} oid */
function cleanOid(oid) {
  const s = String(oid).trim().replace(/^\./, '');
  if (!/^\d+(\.\d+)*$/.test(s)) throw Object.assign(new Error(`invalid OID "${oid}"`), { code: 'E_OID' });
  return s;
}

/** Big-endian unsigned bytes -> decimal string. @param {Buffer} buf */
function bufToDecimal(buf) {
  let n = 0n;
  for (const b of buf) n = (n << 8n) | BigInt(b);
  return n.toString(10);
}

/** decimal string/number/bigint -> 8-byte big-endian Buffer (net-snmp's Counter64 form). */
function decimalToBuf(v) {
  const n = BigInt(v);
  if (n < 0n || n > 0xffffffffffffffffn) throw new Error('Counter64 out of range');
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(n);
  return b;
}

/**
 * @param {{oid: string, type: number, value: any}} vb net-snmp varbind
 * @returns {{oid: string, type: string, value: string}}
 */
function fromVarbind(vb) {
  const type = TYPE_NAMES[vb.type] || `Unknown(${vb.type})`;
  let value = '';
  const v = vb.value;
  switch (type) {
    case 'Integer':
      value = typeof v === 'boolean' ? (v ? '1' : '0') : String(v);
      break;
    case 'Counter32':
    case 'Gauge32':
    case 'TimeTicks':
      value = String(v >>> 0);
      break;
    case 'Counter64':
      value = Buffer.isBuffer(v) ? bufToDecimal(v) : String(v);
      break;
    case 'OctetString':
    case 'Opaque':
      value = Buffer.isBuffer(v) ? v.toString('hex') : Buffer.from(String(v ?? ''), 'utf8').toString('hex');
      break;
    case 'OID':
    case 'IpAddress':
      value = String(v);
      break;
    default:
      value = '';
  }
  return { oid: cleanOid(vb.oid), type, value };
}

/**
 * normalized {oid,type,value} -> net-snmp varbind for SET.
 * @param {{oid: string, type: string, value: string|number}} n
 */
function toVarbind(n) {
  const tag = TYPE_TAGS[n.type];
  if (tag === undefined) throw Object.assign(new Error(`unsupported SET type ${n.type}`), { code: 'E_TYPE' });
  let value;
  switch (n.type) {
    case 'OctetString':
    case 'Opaque':
      value = typeof n.value === 'string' && /^([0-9a-f]{2})*$/i.test(n.value) && n.hex !== false ? Buffer.from(n.value, 'hex') : Buffer.from(String(n.value));
      break;
    case 'Counter64':
      value = decimalToBuf(n.value);
      break;
    case 'OID':
    case 'IpAddress':
      value = String(n.value);
      break;
    case 'Null':
      value = null;
      break;
    default: {
      const num = Number(n.value);
      if (!Number.isFinite(num) || !Number.isInteger(num)) throw Object.assign(new Error(`${n.type} value must be an integer, got ${n.value}`), { code: 'E_TYPE' });
      value = num;
    }
  }
  return { oid: cleanOid(n.oid), type: tag, value };
}

/** @param {string} type */
function isException(type) {
  return EXCEPTIONS.has(type);
}

/** Compare two dotted OIDs. @returns {-1|0|1} */
function compareOids(a, b) {
  const pa = a.split('.');
  const pb = b.split('.');
  const n = Math.min(pa.length, pb.length);
  for (let i = 0; i < n; i++) {
    const x = Number(pa[i]);
    const y = Number(pb[i]);
    if (x !== y) return x < y ? -1 : 1;
  }
  return pa.length === pb.length ? 0 : pa.length < pb.length ? -1 : 1;
}

/** true if oid is strictly inside root's subtree. */
function inSubtree(root, oid) {
  return oid.startsWith(root + '.');
}

/** Decode a hex OctetString as text if it is printable, else null. @param {string} hex */
function hexToText(hex) {
  const b = Buffer.from(hex, 'hex');
  const s = b.toString('utf8');
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x08\x0e-\x1f\x7f�]/.test(s.replace(/\x00+$/, ''))) return null;
  return s.replace(/\x00+$/, '');
}

module.exports = { fromVarbind, toVarbind, cleanOid, compareOids, inSubtree, isException, hexToText, bufToDecimal, decimalToBuf, TYPE_NAMES, TYPE_TAGS };
