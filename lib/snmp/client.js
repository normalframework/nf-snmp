'use strict';
/**
 * SNMP client: a thin, defensive wrapper over net-snmp that speaks the normalized varbind
 * format (docs/internals.md §1) and implements walks and batched reads ourselves so that
 * agent quirks (non-increasing OIDs, broken GETBULK, tooBig, v1 noSuchName) are handled
 * explicitly instead of inside the library.
 */
const snmp = require('net-snmp');
const N = require('./normalize');
require('./des').install(snmp); // OpenSSL 3 has no DES; see des.js

const DEFAULTS = {
  port: 161,
  version: '2c',
  community: 'public',
  timeoutMs: 2000,
  retries: 1,
  maxRepetitions: 10,
  maxOidsPerGet: 20,
  maxWalkVarbinds: 100000,
};

// RFC 3416 error-status names and the §1 error class each maps to (docs/internals.md §1;
// same mapping as the difftest reference clients). Unlisted statuses -> "other".
const STATUS_NAMES = ['noError', 'tooBig', 'noSuchName', 'badValue', 'readOnly', 'genErr', 'noAccess', 'wrongType', 'wrongLength', 'wrongEncoding',
  'wrongValue', 'noCreation', 'inconsistentValue', 'resourceUnavailable', 'commitFailed', 'undoFailed', 'authorizationError', 'notWritable', 'inconsistentName'];
const STATUS_CLASS = { 1: 'tooBig', 2: 'noSuchName', 3: 'badValue', 4: 'readOnly', 5: 'genErr', 6: 'noAccess', 7: 'wrongType', 16: 'noAccess', 17: 'notWritable' };

class SnmpError extends Error {
  /** @param {string} cls @param {string} message @param {object} [extra] */
  constructor(cls, message, extra) {
    super(message);
    this.class = cls;
    Object.assign(this, extra || {});
  }
}

/** Map a net-snmp error to an SnmpError with a §1 error class. */
function classify(err) {
  if (err instanceof SnmpError) return err;
  const msg = (err && err.message) || String(err);
  if (err instanceof snmp.RequestTimedOutError || /timed out/i.test(msg)) return new SnmpError('timeout', msg);
  if (err instanceof snmp.RequestFailedError) {
    const cls = STATUS_CLASS[err.status] || 'other';
    return new SnmpError(cls, msg, { status: STATUS_NAMES[err.status] || String(err.status), statusCode: err.status, index: err.index });
  }
  if (err instanceof snmp.ResponseInvalidError) {
    const code = err.code;
    if (code === 5 || code === 4 || code === 14 || code === 10) return new SnmpError('authError', msg, { code });
    return new SnmpError('decodeError', msg, { code });
  }
  if (/usm|authenticat|decrypt|engine/i.test(msg)) return new SnmpError('authError', msg);
  return new SnmpError('other', msg);
}

const VERSIONS = { 1: snmp.Version1, '1': snmp.Version1, v1: snmp.Version1, '2c': snmp.Version2c, v2c: snmp.Version2c, 2: snmp.Version2c, 3: snmp.Version3, '3': snmp.Version3, v3: snmp.Version3 };

/**
 * @typedef {object} Target
 * @property {string} host
 * @property {number} [port]
 * @property {'1'|'2c'|'3'} [version]
 * @property {string} [community]
 * @property {string} [user]
 * @property {string} [authProtocol]
 * @property {string} [authKey]
 * @property {string} [privProtocol]
 * @property {string} [privKey]
 * @property {string} [context]
 * @property {number} [timeoutMs]
 * @property {number} [retries]
 * @property {number} [maxRepetitions]
 * @property {number} [maxOidsPerGet]
 * @property {boolean} [disableBulk]
 */

class SnmpClient {
  /** @param {Target} target @param {{log?: any}} [opts] */
  constructor(target, opts = {}) {
    this.target = Object.assign({}, DEFAULTS, target);
    this.target.version = String(this.target.version).replace(/^v/, '');
    if (!this.target.host) throw new SnmpError('other', 'target.host is required');
    this.log = opts.log;
    this.session = null;
    this.stats = { requests: 0, timeouts: 0, errors: 0, tooBig: 0, lastOk: 0, lastError: null };
    // adaptive limits learned from the agent (tooBig / timeouts on large PDUs)
    this.maxOidsPerGet = Math.max(1, Number(this.target.maxOidsPerGet) || DEFAULTS.maxOidsPerGet);
    this.maxRepetitions = Math.max(1, Number(this.target.maxRepetitions) || DEFAULTS.maxRepetitions);
  }

  _open() {
    if (this.session) return this.session;
    const t = this.target;
    const version = VERSIONS[t.version];
    if (version === undefined) throw new SnmpError('other', `unsupported SNMP version ${t.version}`);
    const options = {
      port: Number(t.port) || 161,
      retries: Math.max(0, Number(t.retries ?? 1)),
      timeout: Math.max(50, Number(t.timeoutMs) || 2000),
      backoff: 1.0,
      transport: t.host.includes(':') && !t.host.startsWith('[') ? 'udp6' : 'udp4',
      version,
      // we validate ordering ourselves (walk), and want raw responses back
      backwardsGetNexts: true,
      reportOidMismatchErrors: false,
      idBitsSize: 32,
    };
    if (t.context) options.context = t.context;
    let s;
    if (version === snmp.Version3) {
      const authP = (t.authProtocol || 'none').toLowerCase();
      const privP = (t.privProtocol || 'none').toLowerCase();
      if (!(authP in snmp.AuthProtocols)) throw new SnmpError('other', `unsupported authProtocol ${t.authProtocol}`);
      if (!(privP in snmp.PrivProtocols)) throw new SnmpError('other', `unsupported privProtocol ${t.privProtocol}`);
      const user = { name: t.user || '' };
      if (authP === 'none') user.level = snmp.SecurityLevel.noAuthNoPriv;
      else if (privP === 'none') user.level = snmp.SecurityLevel.authNoPriv;
      else user.level = snmp.SecurityLevel.authPriv;
      if (authP !== 'none') {
        user.authProtocol = snmp.AuthProtocols[authP];
        user.authKey = t.authKey || '';
      }
      if (user.level === snmp.SecurityLevel.authPriv) {
        user.privProtocol = snmp.PrivProtocols[privP];
        user.privKey = t.privKey || '';
      }
      s = snmp.createV3Session(t.host, user, options);
    } else {
      s = snmp.createSession(t.host, t.community ?? 'public', options);
    }
    s.on('error', (e) => {
      if (this.log) this.log.warn('snmp socket error', { host: t.host, error: e.message });
      this._reset();
    });
    this.session = s;
    return s;
  }

  _reset() {
    const s = this.session;
    this.session = null;
    if (s) {
      try {
        s.close();
      } catch {
        /* already closed */
      }
    }
  }

  close() {
    this._reset();
  }

  /** @param {(s: any, cb: Function) => void} fn */
  _call(fn) {
    this.stats.requests++;
    const t = this.target;
    // Hard deadline: net-snmp reports some failures (DNS, socket errors) only as session events,
    // which would otherwise leave the request pending forever.
    const deadlineMs = (Math.max(50, Number(t.timeoutMs) || 2000) * (Math.max(0, Number(t.retries ?? 1)) + 1)) + 1500;
    return new Promise((resolve, reject) => {
      let timer = setTimeout(() => {
        timer = null;
        this.stats.errors++;
        this.stats.timeouts++;
        this.stats.lastError = 'request deadline exceeded';
        this._reset();
        reject(new SnmpError('timeout', `no response within ${deadlineMs} ms`));
      }, deadlineMs);
      const settle = (f, v) => {
        if (!timer) return;
        clearTimeout(timer);
        timer = null;
        f(v);
      };
      const res0 = resolve;
      const rej0 = reject;
      resolve = (v) => settle(res0, v);
      reject = (e) => settle(rej0, e);
      let s;
      try {
        s = this._open();
      } catch (e) {
        reject(classify(e));
        return;
      }
      let done = false;
      try {
        fn(s, (err, res) => {
          if (done) return;
          done = true;
          if (err) {
            const e = classify(err);
            this.stats.errors++;
            if (e.class === 'timeout') this.stats.timeouts++;
            if (e.class === 'tooBig') this.stats.tooBig++;
            this.stats.lastError = e.message;
            reject(e);
          } else {
            this.stats.lastOk = Date.now();
            resolve(res);
          }
        });
      } catch (e) {
        done = true;
        this.stats.errors++;
        reject(classify(e));
      }
    });
  }

  /** One GET PDU. @param {string[]} oids @returns {Promise<{oid,type,value}[]>} */
  async get(oids) {
    const clean = oids.map(N.cleanOid);
    const vbs = await this._call((s, cb) => s.get(clean, cb));
    return vbs.map(N.fromVarbind);
  }

  /** One GETNEXT PDU. */
  async getNext(oids) {
    const clean = oids.map(N.cleanOid);
    const vbs = await this._call((s, cb) => s.getNext(clean, cb));
    return vbs.map(N.fromVarbind);
  }

  /**
   * One GETBULK PDU. Returns the flat list of varbinds in response order.
   * @param {string[]} oids @param {number} nonRepeaters @param {number} maxRepetitions
   */
  async getBulk(oids, nonRepeaters, maxRepetitions) {
    if (this.target.version === '1') throw new SnmpError('other', 'GETBULK is not available in SNMPv1');
    const clean = oids.map(N.cleanOid);
    const res = await this._call((s, cb) => s.getBulk(clean, nonRepeaters, maxRepetitions, cb));
    // net-snmp groups repeaters per requested OID: [nonrep..., [rep0 rows...], ...]; flatten
    // back into PDU order: non-repeaters first, then row-major repetitions.
    const out = [];
    for (let i = 0; i < nonRepeaters && i < res.length; i++) out.push(N.fromVarbind(res[i]));
    const cols = res.slice(nonRepeaters);
    const rows = cols.reduce((m, c) => Math.max(m, Array.isArray(c) ? c.length : 0), 0);
    for (let r = 0; r < rows; r++) for (const c of cols) if (Array.isArray(c) && c[r]) out.push(N.fromVarbind(c[r]));
    return out;
  }

  /** One SET PDU. @param {{oid,type,value}[]} varbinds */
  async set(varbinds) {
    const vbs = varbinds.map(N.toVarbind);
    const res = await this._call((s, cb) => s.set(vbs, cb));
    return res.map(N.fromVarbind);
  }

  /**
   * Walk a subtree with GETNEXT (bulk=false) or GETBULK. Never throws for SNMP-level errors
   * after the first response; returns what was collected plus the terminating error, if any.
   * @param {string} root
   * @param {{bulk?: boolean, maxRepetitions?: number, maxVarbinds?: number}} [opts]
   * @returns {Promise<{varbinds: {oid,type,value}[], error?: {error: string, message: string}}>}
   */
  async walk(root, opts = {}) {
    const r = N.cleanOid(root);
    const bulk = opts.bulk !== undefined ? opts.bulk : this.target.version !== '1' && !this.target.disableBulk;
    const maxVb = opts.maxVarbinds || DEFAULTS.maxWalkVarbinds;
    let maxRep = Math.max(1, Number(opts.maxRepetitions) || this.maxRepetitions);
    const out = [];
    let cur = r;
    for (;;) {
      let batch;
      try {
        batch = bulk ? await this.getBulk([cur], 0, maxRep) : await this.getNext([cur]);
      } catch (e) {
        const err = classify(e);
        // tooBig on GETBULK: shrink and retry from the same position
        if (bulk && err.class === 'tooBig' && maxRep > 1) {
          maxRep = Math.max(1, Math.floor(maxRep / 2));
          continue;
        }
        // v1 agents answer the end of the MIB with noSuchName
        if (!bulk && err.class === 'noSuchName' && this.target.version === '1') return { varbinds: out };
        return { varbinds: out, error: errorLine(err) };
      }
      if (!batch.length) return { varbinds: out };
      for (const vb of batch) {
        // endOfMibView is the RFC answer past the end; some agents (incl. net-snmp's Node agent)
        // answer noSuchObject/noSuchInstance instead. Either way nothing follows: stop.
        if (vb.type === 'EndOfMibView' || N.isException(vb.type)) return { varbinds: out };
        if (!N.inSubtree(r, vb.oid)) return { varbinds: out };
        if (N.compareOids(vb.oid, cur) <= 0) {
          return { varbinds: out, error: { error: 'nonIncreasing', message: `agent returned ${vb.oid} after ${cur}` } };
        }
        out.push(vb);
        cur = vb.oid;
        if (out.length >= maxVb) return { varbinds: out, error: { error: 'other', message: `walk exceeded ${maxVb} varbinds` } };
      }
    }
  }

  /**
   * Read many scalar instance OIDs, robustly: batches of maxOidsPerGet, tooBig → split,
   * v1 noSuchName → drop the offending OID and retry the rest, timeouts on a large batch →
   * split once before giving up. Per-OID results are a normalized varbind or {error,message}.
   * @param {string[]} oids
   * @returns {Promise<Map<string, {oid?,type?,value?,error?,message?}>>}
   */
  async readMany(oids) {
    const results = new Map();
    const uniq = [...new Set(oids.map(N.cleanOid))];
    const queue = [];
    for (let i = 0; i < uniq.length; i += this.maxOidsPerGet) queue.push(uniq.slice(i, i + this.maxOidsPerGet));
    while (queue.length) {
      const batch = queue.shift();
      try {
        const vbs = await this.get(batch);
        for (let i = 0; i < batch.length; i++) {
          const vb = vbs[i];
          if (!vb) results.set(batch[i], { error: 'decodeError', message: 'missing varbind in response' });
          else if (vb.oid !== batch[i]) results.set(batch[i], { error: 'decodeError', message: `agent answered ${vb.oid} for ${batch[i]}` });
          else if (N.isException(vb.type)) results.set(batch[i], { error: vb.type, message: vb.type });
          else results.set(batch[i], vb);
        }
      } catch (e) {
        const err = classify(e);
        if (err.class === 'tooBig' && batch.length > 1) {
          this.maxOidsPerGet = Math.max(1, Math.floor(batch.length / 2));
          const h = Math.ceil(batch.length / 2);
          queue.unshift(batch.slice(0, h), batch.slice(h));
          continue;
        }
        if (err.class === 'noSuchName' && batch.length > 1) {
          // v1: error-index (1-based) names the bad varbind
          const idx = Number(err.index) - 1; // 1-based error-index
          if (idx >= 0 && idx < batch.length) {
            results.set(batch[idx], { error: 'NoSuchName', message: 'noSuchName' });
            const rest = batch.filter((_, i) => i !== idx);
            if (rest.length) queue.unshift(rest);
          } else {
            for (const o of batch) queue.unshift([o]);
          }
          continue;
        }
        if (err.class === 'timeout' && batch.length > 1 && !batch.splitOnTimeout) {
          // Some agents silently drop large PDUs. Split once; if halves also time out, the device is down.
          const h = Math.ceil(batch.length / 2);
          const a = batch.slice(0, h);
          const b = batch.slice(h);
          a.splitOnTimeout = b.splitOnTimeout = true;
          try {
            await this.get([a[0]]);
          } catch (e2) {
            // Device is not answering at all: fail everything left instead of timing out per batch.
            for (const o of batch) results.set(o, { error: 'timeout', message: err.message });
            for (const rest of queue.splice(0)) for (const o of rest) results.set(o, { error: 'timeout', message: err.message });
            continue;
          }
          this.maxOidsPerGet = Math.max(1, h);
          queue.unshift(a, b);
          continue;
        }
        for (const o of batch) results.set(o, { error: err.class === 'noSuchName' ? 'NoSuchName' : err.class, message: err.message });
        // single-OID batch timed out: the device is down, don't wait out every remaining batch
        if (err.class === 'timeout') for (const rest of queue.splice(0)) for (const o of rest) results.set(o, { error: 'timeout', message: err.message });
      }
    }
    return results;
  }
}

/** §1 error line for an SnmpError. */
function errorLine(e) {
  const o = { error: e.class, message: e.message };
  if (e.status !== undefined) o.status = e.status;
  if (e.index !== undefined && e.index !== null) o.index = Number(e.index);
  return o;
}

module.exports = { SnmpClient, SnmpError, classify, errorLine, DEFAULTS, STATUS_NAMES };
