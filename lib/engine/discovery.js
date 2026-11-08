'use strict';
/**
 * Discovery jobs: probe a bounded host list with a small ordered set of credentials, identify each
 * responder (sysObjectID/sysDescr -> profile), and report. Opt-in and deliberately conservative:
 * multi-community sweeps across a subnet look like an attack to IDS (Snort sid 1411), so the
 * number of hosts, credentials and in-flight probes are capped.
 */
const crypto = require('crypto');
const { SnmpClient } = require('../snmp/client');
const { identify } = require('../profiles/device');
const { uuidv5 } = require('./store');

const LIMITS = { maxHosts: 1024, maxCredentials: 4, maxConcurrency: 16, maxJobs: 8, keepMs: 60 * 60 * 1000 };

/** Expand "10.0.0.5", "10.0.0.0/28", "10.0.0.10-20", "10.0.0.10-10.0.0.20", "host.name" */
function expandHosts(specs, max = LIMITS.maxHosts) {
  const out = [];
  const push = (h) => {
    if (out.length >= max) throw Object.assign(new Error(`more than ${max} hosts`), { code: 'E_CONFIG' });
    if (!out.includes(h)) out.push(h);
  };
  for (const raw of [].concat(specs || [])) {
    for (const spec of String(raw).split(/[\s,]+/).filter(Boolean)) {
      let m;
      if ((m = /^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/.exec(spec))) {
        const bits = Number(m[2]);
        if (bits < 16 || bits > 32) throw Object.assign(new Error(`CIDR ${spec}: prefix must be /16../32`), { code: 'E_CONFIG' });
        const base = ipToInt(m[1]) & (bits === 32 ? 0xffffffff : (~((1 << (32 - bits)) - 1) >>> 0));
        const size = 2 ** (32 - bits);
        for (let i = 0; i < size; i++) {
          if (size > 2 && (i === 0 || i === size - 1)) continue; // network / broadcast
          push(intToIp((base + i) >>> 0));
        }
      } else if ((m = /^(\d+\.\d+\.\d+\.)(\d+)-(\d+)$/.exec(spec))) {
        for (let i = Number(m[2]); i <= Number(m[3]); i++) push(`${m[1]}${i}`);
      } else if ((m = /^(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$/.exec(spec))) {
        for (let i = ipToInt(m[1]); i <= ipToInt(m[2]); i++) push(intToIp(i >>> 0));
      } else if (/^[A-Za-z0-9_.\-:]+$/.test(spec)) {
        push(spec);
      } else {
        throw Object.assign(new Error(`bad host spec ${spec}`), { code: 'E_CONFIG' });
      }
    }
  }
  return out;
}

function ipToInt(ip) {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some((x) => !(x >= 0 && x <= 255))) throw Object.assign(new Error(`bad IP ${ip}`), { code: 'E_CONFIG' });
  return ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
}
function intToIp(n) {
  return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

class Discovery {
  constructor({ library, log, engine }) {
    this.library = library;
    this.log = log;
    this.engine = engine;
    this.jobs = new Map();
  }

  /**
   * @param {{hosts: string|string[], credentials: any[], port?: number, timeoutMs?: number, retries?: number, concurrency?: number}} req
   */
  start(req) {
    this._gc();
    const running = [...this.jobs.values()].filter((j) => j.state === 'running').length;
    if (running >= LIMITS.maxJobs) throw Object.assign(new Error('too many discovery jobs running'), { code: 'E_CONFIG' });
    const hosts = expandHosts(req.hosts);
    if (!hosts.length) throw Object.assign(new Error('no hosts'), { code: 'E_CONFIG' });
    const creds = [].concat(req.credentials || [{ version: '2c', community: 'public' }]);
    if (creds.length > LIMITS.maxCredentials) throw Object.assign(new Error(`at most ${LIMITS.maxCredentials} credential sets per job`), { code: 'E_CONFIG' });
    const job = {
      id: crypto.randomUUID(),
      state: 'running',
      startedAt: Date.now(),
      finishedAt: null,
      total: hosts.length,
      done: 0,
      found: [],
      errors: 0,
      cancelled: false,
      params: { port: Number(req.port) || 161, timeoutMs: Math.min(Number(req.timeoutMs) || 1000, 10000), retries: Math.min(Number(req.retries ?? 0), 2), concurrency: Math.min(Number(req.concurrency) || 8, LIMITS.maxConcurrency), credentials: creds },
    };
    this.jobs.set(job.id, job);
    this._run(job, hosts).catch((e) => {
      job.state = 'error';
      job.error = e.message;
      job.finishedAt = Date.now();
    });
    return { jobId: job.id, total: job.total };
  }

  async _run(job, hosts) {
    const queue = hosts.slice();
    const worker = async () => {
      while (queue.length && !job.cancelled) {
        const host = queue.shift();
        try {
          const r = await this._probe(job, host);
          if (r) job.found.push(r);
        } catch (e) {
          job.errors++;
        }
        job.done++;
      }
    };
    await Promise.all(Array.from({ length: job.params.concurrency }, worker));
    job.state = job.cancelled ? 'cancelled' : 'done';
    job.finishedAt = Date.now();
  }

  async _probe(job, host) {
    const { port, timeoutMs, retries, credentials } = job.params;
    for (let i = 0; i < credentials.length; i++) {
      const target = Object.assign({}, credentials[i], { host, port, timeoutMs, retries });
      const c = new SnmpClient(target, { log: this.log });
      try {
        const id = await identify(c, this.library);
        const uuid = uuidv5(`${host}:${port}`);
        return {
          host,
          port,
          credentialIndex: i,
          version: target.version || '2c',
          identity: id,
          existingDevice: this.engine && this.engine.store.devices[uuid] ? uuid : null,
        };
      } catch (e) {
        // timeout = nobody home (or wrong community on v1/v2c, which is silent); try next credential.
        if (e.class !== 'timeout' && e.class !== 'authError') return { host, port, credentialIndex: i, error: e.message };
      } finally {
        c.close();
      }
    }
    return null;
  }

  get(id) {
    const j = this.jobs.get(id);
    if (!j) throw Object.assign(new Error(`unknown job ${id}`), { code: 'E_NOT_FOUND' });
    const { params, ...rest } = j;
    return Object.assign({}, rest, { params: Object.assign({}, params, { credentials: params.credentials.map((c) => ({ version: c.version, user: c.user })) }) });
  }

  list() {
    return [...this.jobs.keys()].map((id) => {
      const j = this.get(id);
      return { id: j.id, state: j.state, total: j.total, done: j.done, found: j.found.length, startedAt: j.startedAt };
    });
  }

  cancel(id) {
    const j = this.jobs.get(id);
    if (j) j.cancelled = true;
    return { ok: !!j };
  }

  cancelAll() {
    for (const j of this.jobs.values()) j.cancelled = true;
  }

  /** Create devices for found hosts of a job. */
  async addFound(id, { hosts, periodSeconds, namePrefix } = {}) {
    const j = this.jobs.get(id);
    if (!j) throw Object.assign(new Error(`unknown job ${id}`), { code: 'E_NOT_FOUND' });
    const out = [];
    for (const f of j.found) {
      if (f.error || !f.identity || (hosts && !hosts.includes(f.host))) continue;
      const cred = j.params.credentials[f.credentialIndex];
      const name = `${namePrefix || ''}${f.identity.sysName || f.host}`;
      try {
        const d = await this.engine.putDevice(Object.assign({}, cred, { host: f.host, port: f.port, name, profile: 'auto', periodSeconds: periodSeconds || 60 }));
        out.push({ host: f.host, uuid: d.uuid, profile: d.matchedProfile, points: d.pointCount });
      } catch (e) {
        out.push({ host: f.host, error: e.message });
      }
    }
    return { added: out };
  }

  _gc() {
    const now = Date.now();
    for (const [id, j] of this.jobs) if (j.finishedAt && now - j.finishedAt > LIMITS.keepMs) this.jobs.delete(id);
  }
}

module.exports = { Discovery, expandHosts, LIMITS };
