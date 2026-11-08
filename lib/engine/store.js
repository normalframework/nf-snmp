'use strict';
/**
 * Persistent engine state under <root>/local/ (untracked, survives app upgrades):
 *   devices.json   device configs (credentials included; file is only readable via NF app files API)
 *   points.json    uuid -> point spec, per device (the materialized profile)
 * Writes are atomic (tmp + rename).
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Fixed namespace for deterministic UUIDs (uuidv5 over "<host>:<port>" and "<device>/<oid>").
const NS = '6f1c2e57-3a86-4c55-9f0e-6b1d0c5a1e42';

function uuidv5(name, ns = NS) {
  const nsBytes = Buffer.from(ns.replace(/-/g, ''), 'hex');
  const h = crypto.createHash('sha1').update(Buffer.concat([nsBytes, Buffer.from(String(name), 'utf8')])).digest();
  const b = Buffer.from(h.subarray(0, 16));
  b[6] = (b[6] & 0x0f) | 0x50;
  b[8] = (b[8] & 0x3f) | 0x80;
  const x = b.toString('hex');
  return `${x.slice(0, 8)}-${x.slice(8, 12)}-${x.slice(12, 16)}-${x.slice(16, 20)}-${x.slice(20)}`;
}

const DEVICE_FIELDS = [
  'uuid', 'name', 'host', 'port', 'version', 'community', 'user', 'authProtocol', 'authKey', 'privProtocol', 'privKey', 'context',
  'profile', 'periodSeconds', 'enabled', 'timeoutMs', 'retries', 'maxOidsPerGet', 'maxRepetitions', 'disableBulk', 'attrs', 'writeCommunity',
];
const SECRET_FIELDS = ['community', 'authKey', 'privKey', 'writeCommunity'];

/**
 * Validate + normalize a device config. Throws E_CONFIG.
 * @param {any} d
 */
function normalizeDevice(d) {
  const err = (m) => Object.assign(new Error(m), { code: 'E_CONFIG' });
  if (!d || typeof d !== 'object') throw err('device must be an object');
  const out = {};
  for (const k of DEVICE_FIELDS) if (d[k] !== undefined && d[k] !== null && d[k] !== '') out[k] = d[k];
  if (!out.host || typeof out.host !== 'string' || !/^[A-Za-z0-9_.:\-[\]]+$/.test(out.host)) throw err('host is required (IP or DNS name)');
  out.port = Number(out.port || 161);
  if (!(out.port > 0 && out.port < 65536)) throw err('port must be 1..65535');
  out.version = String(out.version || '2c').replace(/^v/, '');
  if (!['1', '2c', '3'].includes(out.version)) throw err('version must be 1, 2c or 3');
  if (out.version === '3' && !out.user) throw err('SNMPv3 needs a user');
  if (out.version !== '3' && out.community === undefined) out.community = 'public';
  out.periodSeconds = Number(out.periodSeconds || 60);
  if (!(out.periodSeconds >= 1 && out.periodSeconds <= 86400)) throw err('periodSeconds must be 1..86400');
  out.enabled = out.enabled !== false;
  out.profile = out.profile || 'auto';
  if (!out.uuid) out.uuid = uuidv5(`${out.host}:${out.port}`);
  if (!out.name) out.name = out.host;
  if (out.attrs && typeof out.attrs !== 'object') throw err('attrs must be an object');
  return out;
}

/** Device config without secrets, for UIs and logs. */
function redact(d) {
  const o = Object.assign({}, d);
  for (const k of SECRET_FIELDS) if (o[k] !== undefined) o[k] = '********';
  return o;
}

class Store {
  /** @param {string} dir */
  constructor(dir) {
    this.dir = dir;
    fs.mkdirSync(dir, { recursive: true });
    this.devices = this._read('devices.json', {});
    this.points = this._read('points.json', {});
    this.traps = this._read('traps.json', {});
  }

  saveTraps() {
    this._write('traps.json', this.traps);
  }

  _read(name, dflt) {
    try {
      return JSON.parse(fs.readFileSync(path.join(this.dir, name), 'utf8'));
    } catch {
      return dflt;
    }
  }

  _write(name, obj) {
    const p = path.join(this.dir, name);
    const tmp = `${p}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(obj, null, 1), { mode: 0o600 });
    fs.renameSync(tmp, p);
  }

  saveDevices() {
    this._write('devices.json', this.devices);
  }

  savePoints() {
    this._write('points.json', this.points);
  }

  /** @param {any} cfg  merges secrets that the UI sends back redacted */
  putDevice(cfg) {
    const prev = cfg.uuid ? this.devices[cfg.uuid] : undefined;
    const merged = Object.assign({}, cfg);
    if (prev) for (const k of SECRET_FIELDS) if (merged[k] === '********') merged[k] = prev[k];
    const d = normalizeDevice(merged);
    this.devices[d.uuid] = d;
    this.saveDevices();
    return d;
  }

  deleteDevice(uuid) {
    delete this.devices[uuid];
    if (this.traps[uuid]) {
      delete this.traps[uuid];
      this.saveTraps();
    }
    delete this.points[uuid];
    this.saveDevices();
    this.savePoints();
  }

  /** @param {string} deviceUuid @param {{profile: string, specs: any[], materializedAt: number}} m */
  setPoints(deviceUuid, m) {
    this.points[deviceUuid] = m;
    this.savePoints();
  }
}

module.exports = { Store, normalizeDevice, redact, uuidv5, NS };
