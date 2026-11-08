'use strict';
/**
 * The nf-snmp engine. One process-wide instance, started by hooks/engine.js.
 *
 *   NF poll service --POST /driver/read-->  Engine.read()   --SNMP GET--> devices
 *   NF command svc  --POST /driver/write--> Engine.write()  --SNMP SET--> devices
 *   UI --admin hook--> /admin/*            device CRUD, identify, discovery, preview, walk, traps
 *
 * Devices are materialized (profile tables expanded by walking) when added or resynced; the
 * resulting point specs are persisted and published to NF on the app layer with a period, a
 * parent (the device) and device_address, so NF's generic poller schedules reads (docs/internals.md §5).
 */
const path = require('path');
const { SnmpClient } = require('../snmp/client');
const fs = require('fs');
const { loadLibrary, validate, BUILTIN_DIR } = require('../profiles');
const { identify, materialize, readSpecs, HelperCache } = require('../profiles/device');
const { decode, encode } = require('../profiles/decode');
const { Store, redact, uuidv5 } = require('./store');
const { createServer } = require('./server');
const { toHplValue, fromHplValue } = require('./hplvalue');
const { Discovery } = require('./discovery');
const { TrapReceiver, trapPointUuid } = require('./traps');
const { SelfPoller } = require('./selfpoll');

const nullLog = { debug() {}, info() {}, warn() {}, error() {} };

class Mutex {
  constructor() {
    this.p = Promise.resolve();
  }
  run(fn) {
    const r = this.p.then(fn, fn);
    this.p = r.catch(() => {});
    return r;
  }
}

class Engine {
  /**
   * @param {{nf?: any, log?: any, root: string, port?: number, layer?: string, trapPort?: number,
   *   profileDirs?: string[], now?: () => number, publish?: boolean}} opts
   */
  constructor(opts) {
    this.nf = opts.nf || null;
    this.log = opts.log || nullLog;
    this.root = opts.root;
    this.layer = opts.layer || 'snmp';
    this.port = opts.port === undefined ? 47081 : opts.port;
    this.trapPort = opts.trapPort;
    this.now = opts.now || Date.now;
    this.publishEnabled = opts.publish !== false && !!this.nf;
    this.store = new Store(path.join(this.root, 'local'));
    this.userProfileDir = path.join(this.root, 'local', 'profiles');
    this.profileDirs = [...(opts.profileDirs || [BUILTIN_DIR]), this.userProfileDir];
    this.library = loadLibrary({ dirs: this.profileDirs, log: this.log });
    /** @type {Map<string, any>} device uuid -> runtime */
    this.rt = new Map();
    /** @type {Map<string, {deviceUuid: string, spec: any}>} point uuid -> spec */
    this.index = new Map();
    this.server = null;
    this.discovery = new Discovery({ library: this.library, log: this.log, engine: this });
    this.traps = null;
    this.selfPoll = opts.selfPoll === false ? null : new SelfPoller({ engine: this, log: this.log, graceMs: opts.selfPollGraceMs, now: this.now });
    this.started = false;
    this.counters = { reads: 0, readErrors: 0, writes: 0, writeErrors: 0, syncs: 0, syncErrors: 0 };
  }

  // ------------------------------------------------------------------ lifecycle
  async start() {
    for (const [uuid, m] of Object.entries(this.store.points)) this._indexDevice(uuid, m);
    this.server = createServer({ engine: this, port: this.port, log: this.log });
    this.port = await this.server.start();
    if (this.trapPort !== undefined && this.trapPort !== null && this.trapPort !== 0) {
      this.traps = new TrapReceiver({ engine: this, port: this.trapPort, log: this.log });
      try {
        await this.traps.start();
      } catch (e) {
        this.log.warn('trap receiver not started', { port: this.trapPort, error: e.message });
      }
    }
    this.started = true;
    if (this.selfPoll) this.selfPoll.start();
    for (const d of Object.values(this.store.devices)) {
      if (!d.enabled) continue;
      // Re-publish known points (cheap, idempotent) and resync devices never materialized.
      const m = this.store.points[d.uuid];
      if (m && m.specs && m.specs.length) this._bg(this.publish(d.uuid), 'publish');
      else this._bg(this.sync(d.uuid), 'sync');
    }
    this.log.info('engine started', { port: this.port, devices: Object.keys(this.store.devices).length, points: this.index.size });
  }

  async stop() {
    this.started = false;
    if (this.selfPoll) this.selfPoll.stop();
    this.discovery.cancelAll();
    if (this.traps) await this.traps.stop();
    if (this.server) await this.server.stop();
    for (const r of this.rt.values()) r.client.close();
    this.rt.clear();
  }

  _bg(p, what) {
    p.catch((e) => this.log.warn(`background ${what} failed`, { error: e.message }));
  }

  health() {
    return { ok: this.started, port: this.port, devices: Object.keys(this.store.devices).length, points: this.index.size, polling: this.selfPoll ? this.selfPoll.status() : { mode: 'nf' } };
  }

  // ------------------------------------------------------------------ devices
  /** Runtime for a device (client, helper cache, status), created lazily. */
  runtime(uuid) {
    let r = this.rt.get(uuid);
    const cfg = this.store.devices[uuid];
    if (!cfg) throw Object.assign(new Error(`unknown device ${uuid}`), { code: 'E_NOT_FOUND' });
    if (r && r.cfgKey !== JSON.stringify(cfg)) {
      r.client.close();
      r = null;
    }
    if (!r) {
      r = {
        cfgKey: JSON.stringify(cfg),
        client: new SnmpClient(cfg, { log: this.log }),
        helpers: new HelperCache(),
        mutex: new Mutex(),
        status: (this.rt.get(uuid) || {}).status || { state: 'connecting', lastOk: 0, lastError: null, consecutiveFailures: 0 },
      };
      this.rt.set(uuid, r);
    }
    return r;
  }

  listDevices() {
    return Object.values(this.store.devices).map((d) => {
      const m = this.store.points[d.uuid] || {};
      const r = this.rt.get(d.uuid);
      return Object.assign(redact(d), {
        status: r ? r.status : { state: d.enabled ? 'idle' : 'disabled' },
        matchedProfile: m.profile || null,
        identity: m.identity || null,
        pointCount: (m.specs || []).length,
        warnings: m.warnings || [],
        materializedAt: m.materializedAt || null,
        stats: r ? r.client.stats : null,
      });
    });
  }

  /** Add or update a device; resyncs it. */
  async putDevice(cfg, { sync = true } = {}) {
    const d = this.store.putDevice(cfg);
    if (this.traps) this.traps.syncUsers();
    if (sync && d.enabled) await this.sync(d.uuid);
    return this.listDevices().find((x) => x.uuid === d.uuid);
  }

  async deleteDevice(uuid, { deletePoints = true } = {}) {
    const m = this.store.points[uuid];
    const uuids = (m ? m.specs.map((s) => s.uuid) : []).concat([uuid, trapPointUuid(uuid)]);
    for (const u of uuids) this.index.delete(u);
    const r = this.rt.get(uuid);
    if (r) r.client.close();
    this.rt.delete(uuid);
    this.store.deleteDevice(uuid);
    if (deletePoints && this.publishEnabled) await this.nf.points.remove(uuids);
    return { deleted: uuids.length };
  }

  /**
   * Identify + materialize + publish one device.
   * @param {string} uuid
   */
  async sync(uuid) {
    const cfg = this.store.devices[uuid];
    if (!cfg) throw Object.assign(new Error(`unknown device ${uuid}`), { code: 'E_NOT_FOUND' });
    const r = this.runtime(uuid);
    this.counters.syncs++;
    return r.mutex.run(async () => {
      try {
        const identity = await identify(r.client, this.library);
        const profileId = cfg.profile === 'auto' ? identity.profile && identity.profile.id : cfg.profile;
        if (!profileId) throw Object.assign(new Error(`no profile matches sysObjectID ${identity.sysObjectID} (${identity.vendor || 'unknown vendor'})`), { code: 'E_NO_PROFILE' });
        const profile = this.library.resolve(profileId);
        const { specs, warnings, attrs } = await materialize(r.client, profile);
        for (const s of specs) s.uuid = uuidv5(`${uuid}/${s.oid}`);
        const prev = this.store.points[uuid];
        const m = { profile: profileId, identity, specs, warnings, attrs, materializedAt: this.now() };
        this.store.setPoints(uuid, m);
        this._indexDevice(uuid, m);
        r.status = { state: 'ok', lastOk: this.now(), lastError: null, consecutiveFailures: 0 };
        if (this.publishEnabled) {
          await this.publish(uuid);
          const stale = prev ? prev.specs.map((s) => s.uuid).filter((u) => !m.specs.some((s) => s.uuid === u)) : [];
          if (stale.length) {
            for (const u of stale) this.index.delete(u);
            await this.nf.points.remove(stale);
          }
        }
        this.log.info('device synced', { device: cfg.name, profile: profileId, points: specs.length, warnings: warnings.length });
        return m;
      } catch (e) {
        this.counters.syncErrors++;
        r.status = Object.assign({}, r.status, { state: 'error', lastError: e.message });
        throw e;
      }
    });
  }

  _indexDevice(uuid, m) {
    for (const [u, v] of this.index) if (v.deviceUuid === uuid) this.index.delete(u);
    for (const s of m.specs || []) this.index.set(s.uuid, { deviceUuid: uuid, spec: s });
  }

  /** NF point objects for a device (device point + one per spec). */
  nfPoints(uuid) {
    const d = this.store.devices[uuid];
    const m = this.store.points[uuid];
    if (!d || !m) return [];
    const id = m.identity || {};
    const devAttrs = Object.assign({}, d.attrs || {}, {
      device: d.name,
      device_uuid: uuid,
      device_address: `SNMP:${d.host}:${d.port}`,
      profile: m.profile,
      sys_object_id: id.sysObjectID || '',
      vendor: id.vendor || '',
    });
    const out = [{
      uuid,
      layer: this.layer,
      name: d.name,
      pointType: 'DEVICE',
      description: id.sysDescr || '',
      attrs: Object.assign({}, m.attrs || {}, devAttrs, { oid: '', symbol: '', sys_name: id.sysName || '', sys_location: id.sysLocation || '' }),
    }];
    const tr = this.store.traps[uuid] || {};
    out.push({
      uuid: trapPointUuid(uuid),
      layer: this.layer,
      name: `${d.name} snmpTrap`,
      parentUuid: uuid,
      parentName: d.name,
      hplDriver: this.layer,
      description: 'Number of SNMP traps/informs received from this device; the last one is in attributes last_trap / last_trap_at',
      attrs: Object.assign({}, devAttrs, { oid: '', symbol: 'snmpTrap', index: '', units: '', class_hint: '', writable: 'false', enum: '', last_trap: tr.last || '', last_trap_at: tr.at ? new Date(tr.at).toISOString() : '' }),
    });
    for (const s of m.specs) {
      out.push({
        uuid: s.uuid,
        layer: this.layer,
        name: s.displayName,
        parentUuid: uuid,
        parentName: d.name,
        hplDriver: this.layer,
        periodSeconds: s.periodSeconds || d.periodSeconds,
        displayUnits: s.units || undefined,
        protocolId: s.oid,
        attrs: Object.assign({}, devAttrs, {
          oid: s.oid,
          symbol: s.label ? `${s.name}.${s.label}` : s.name,
          index: s.index === null ? '' : s.index,
          units: s.units || '',
          class_hint: s.class || '',
          writable: s.writable ? 'true' : 'false',
          enum: s.enum ? Object.entries(s.enum).map(([k, v]) => `${k}=${v}`).join(',') : '',
        }),
      });
    }
    return out;
  }

  async publish(uuid) {
    if (!this.publishEnabled) return { published: 0 };
    const pts = this.nfPoints(uuid).map(sanitizeTags);
    if (!pts.length) return { published: 0 };
    await this.nf.points.upsert(pts);
    return { published: pts.length };
  }

  /**
   * A trap/inform from a configured device: bump its persisted count (the snmpTrap point's value,
   * since NF trends numbers only) and record the trap text on the point's attributes.
   */
  async recordTrap(deviceUuid, rec, summary) {
    const t = this.store.traps[deviceUuid] || { count: 0 };
    t.count += 1;
    t.last = summary.slice(0, 1000);
    t.at = rec.ts;
    this.store.traps[deviceUuid] = t;
    this.store.saveTraps();
    if (!this.publishEnabled) return;
    const tp = this.nfPoints(deviceUuid).find((p) => p.uuid === trapPointUuid(deviceUuid));
    if (tp) await this.nf.points.upsert([sanitizeTags(tp)]);
    await this.pushValues([{ uuid: trapPointUuid(deviceUuid), value: t.count, ts: rec.ts }]);
  }

  /** Push values (e.g. traps) for engine-owned points. @param {{uuid, value, ts}[]} items */
  async pushValues(items) {
    if (!this.publishEnabled || !items.length) return;
    await this.nf.points.writeData(this.layer, items.map((i) => ({ uuid: i.uuid, values: [toHplValue(i.value, i.ts)] })));
  }

  // ------------------------------------------------------------------ driver
  /** Find the spec for an NF point (engine index first, then point attrs). */
  specFor(point) {
    const hit = this.index.get(point.uuid);
    if (hit) return hit;
    const attrs = pointAttrs(point, this.layer);
    if (attrs.device_uuid && attrs.oid && this.store.devices[attrs.device_uuid]) {
      return { deviceUuid: attrs.device_uuid, spec: { uuid: point.uuid, oid: attrs.oid, name: attrs.symbol || attrs.oid, decode: {} } };
    }
    return null;
  }

  /**
   * hplv1.ReadRequest -> hplv1.ReadReply
   * @param {any} req
   */
  async read(req, { internal = false } = {}) {
    if (!internal && this.selfPoll) this.selfPoll.noteNfRead();
    const reads = (req && req.reads) || [];
    const results = [];
    const errors = [];
    const byDev = new Map();
    for (const r of reads) {
      const p = (r && r.point) || {};
      if (!p.uuid) continue;
      this.counters.reads++;
      const hit = this.specFor(p);
      if (!hit) {
        errors.push({ uuid: p.uuid, error: { message: 'point is not managed by nf-snmp (unknown uuid)' } });
        continue;
      }
      if (!byDev.has(hit.deviceUuid)) byDev.set(hit.deviceUuid, []);
      byDev.get(hit.deviceUuid).push(hit.spec);
    }
    await Promise.all([...byDev.entries()].map(async ([devUuid, specs]) => {
      const cfg = this.store.devices[devUuid];
      if (!cfg || !cfg.enabled) {
        for (const s of specs) errors.push({ uuid: s.uuid, error: { message: 'device disabled or removed' } });
        return;
      }
      const r = this.runtime(devUuid);
      const rows = await r.mutex.run(() => readSpecs(r.client, specs, r.helpers));
      const ts = this.now();
      let ok = 0;
      for (const row of rows) {
        if (row.error === undefined) {
          ok++;
          results.push({ uuid: row.spec.uuid, hplValue: toHplValue(row.value, ts) });
        } else {
          this.counters.readErrors++;
          errors.push({ uuid: row.spec.uuid, error: { message: `${row.code}: ${row.error}`, ts: new Date(ts).toISOString() } });
        }
      }
      const allTimeout = rows.length && rows.every((x) => x.code === 'timeout');
      if (ok) r.status = { state: 'ok', lastOk: ts, lastError: rows.length - ok ? `${rows.length - ok} point errors` : null, consecutiveFailures: 0 };
      else r.status = { state: allTimeout ? 'unreachable' : 'error', lastOk: r.status.lastOk, lastError: rows[0] && rows[0].error, consecutiveFailures: (r.status.consecutiveFailures || 0) + 1 };
    }));
    const reply = {};
    if (results.length) reply.results = results;
    if (errors.length) reply.errors = errors;
    return reply;
  }

  /**
   * hplv1.WriteRequest -> hplv1.WriteReply. SNMP has no priority array: the NF command service
   * emulates priorities and restores the saved value on relinquish, so we only ever SET values.
   * @param {any} req
   */
  async write(req) {
    const writes = (req && req.writes) || [];
    const errors = [];
    const byDev = new Map();
    for (const w of writes) {
      const p = (w && w.point) || {};
      this.counters.writes++;
      const hit = p.uuid ? this.index.get(p.uuid) : null;
      if (!hit) {
        errors.push({ uuid: p.uuid || '', error: { message: 'point is not managed by nf-snmp' } });
        continue;
      }
      if (!hit.spec.writable) {
        errors.push({ uuid: p.uuid, error: { message: `${hit.spec.name} is not writable (profile does not allow SET)` } });
        continue;
      }
      let value;
      try {
        const wv = (w && w.value) || {};
        if (wv.normalized === undefined) throw new Error('only normalized values are supported');
        value = fromHplValue(wv.normalized).value;
        if (value === null) throw new Error('SNMP cannot write null; relinquish is handled by restoring the saved value');
      } catch (e) {
        errors.push({ uuid: p.uuid, error: { message: e.message } });
        continue;
      }
      if (!byDev.has(hit.deviceUuid)) byDev.set(hit.deviceUuid, []);
      byDev.get(hit.deviceUuid).push({ spec: hit.spec, value });
    }
    await Promise.all([...byDev.entries()].map(async ([devUuid, items]) => {
      const cfg = this.store.devices[devUuid];
      const r = this.runtime(devUuid);
      await r.mutex.run(async () => {
        const writer = cfg.writeCommunity && cfg.version !== '3' ? new SnmpClient(Object.assign({}, cfg, { community: cfg.writeCommunity }), { log: this.log }) : r.client;
        try {
          for (const it of items) {
            try {
              const helper = (oid) => r.helpers.get(oid);
              // decimal-digit helpers may not be cached yet
              const need = [it.spec.decode && it.spec.decode.decimalDigitsOid].filter((o) => o && !r.helpers.get(o));
              if (need.length) {
                const res = await r.client.readMany(need);
                for (const o of need) if (res.get(o) && !res.get(o).error) r.helpers.set(o, res.get(o));
              }
              const vb = encode(it.value, it.spec, helper);
              const resp = await writer.set([vb]);
              const got = resp[0];
              if (got && got.type !== vb.type && !['Integer', 'Gauge32'].includes(got.type)) {
                throw new Error(`agent answered ${got.type} for ${vb.type}`);
              }
              this.log.info('snmp set', { device: cfg.name, oid: vb.oid, value: vb.value });
            } catch (e) {
              this.counters.writeErrors++;
              errors.push({ uuid: it.spec.uuid, error: { message: `${e.class || e.code || 'error'}: ${e.message}` } });
            }
          }
        } finally {
          if (writer !== r.client) writer.close();
        }
      });
    }));
    return errors.length ? { errors } : {};
  }

  /** hplv1.GetDriverStatusReply */
  driverStatus() {
    const map = { ok: 'STATUS_CONNECTED', connecting: 'STATUS_CONNECTING', idle: 'STATUS_CONNECTING', error: 'STATUS_ERROR', unreachable: 'STATUS_ERROR' };
    return {
      devices: Object.values(this.store.devices).map((d) => {
        if (!d.enabled) return { name: d.name, status: 'STATUS_DISABLED' };
        const r = this.rt.get(d.uuid);
        return { name: d.name, status: map[(r && r.status.state) || 'idle'] || 'STATUS_CONNECTING' };
      }),
    };
  }

  // ------------------------------------------------------------------ tools (admin API)
  async identifyTarget(target) {
    const c = new SnmpClient(target, { log: this.log });
    try {
      return await identify(c, this.library);
    } finally {
      c.close();
    }
  }

  /** Read a profile against a device or ad-hoc target without publishing anything. */
  async preview({ uuid, target, profile }) {
    let client;
    let own = false;
    if (uuid) client = this.runtime(uuid).client;
    else {
      client = new SnmpClient(target, { log: this.log });
      own = true;
    }
    try {
      let pid = profile;
      let identity = null;
      if (!pid || pid === 'auto') {
        identity = await identify(client, this.library);
        pid = identity.profile && identity.profile.id;
        if (!pid) return { identity, profile: null, points: [] };
      }
      const p = this.library.resolve(pid);
      const { specs, warnings } = await materialize(client, p);
      const rows = await readSpecs(client, specs);
      return {
        identity,
        profile: pid,
        warnings,
        points: rows.map((x) => ({ key: x.spec.key, name: x.spec.displayName, oid: x.spec.oid, units: x.spec.units, value: x.value, raw: x.raw && !x.raw.error ? x.raw : undefined, error: x.error, writable: x.spec.writable })),
      };
    } finally {
      if (own) client.close();
    }
  }

  async walkTarget({ uuid, target, root, bulk, maxVarbinds }) {
    const client = uuid ? this.runtime(uuid).client : new SnmpClient(target, { log: this.log });
    try {
      return await client.walk(root || '1.3.6.1', { bulk, maxVarbinds: Math.min(Number(maxVarbinds) || 5000, 50000) });
    } finally {
      if (!uuid) client.close();
    }
  }

  _isBuiltin(id) {
    if (!this._builtinIds) this._builtinIds = new Set(loadLibrary({ dirs: [BUILTIN_DIR] }).ids());
    return this._builtinIds.has(id);
  }

  profiles() {
    return this.library.ids().map((id) => {
      const p = this.library.get(id);
      const r = this.library.resolve(id);
      return { id, name: p.name || id, vendor: p.vendor || '', abstract: !!p.abstract, user: !this._isBuiltin(id), equipType: p.equipType || null, match: p.match || [], symbols: r.symbols.length, tables: r.tables.length };
    });
  }

  /**
   * Add or replace a user profile (local/profiles/<id>.json) and reload the library.
   * Built-in ids cannot be overwritten.
   */
  putProfile(profile) {
    validate(profile, 'profile');
    if (!/^[a-z0-9_.-]+\/[a-z0-9_.-]+$/i.test(profile.id)) throw Object.assign(new Error('profile id must look like vendor/model'), { code: 'E_CONFIG' });
    const builtin = loadLibrary({ dirs: [BUILTIN_DIR] });
    if (builtin.raw.has(profile.id)) throw Object.assign(new Error(`${profile.id} is a built-in profile; use another id`), { code: 'E_CONFIG' });
    const file = path.join(this.userProfileDir, `${profile.id.replace('/', '__')}.json`);
    fs.mkdirSync(this.userProfileDir, { recursive: true });
    fs.writeFileSync(file, JSON.stringify(profile, null, 1));
    const lib = loadLibrary({ dirs: this.profileDirs, log: this.log });
    lib.resolve(profile.id); // extends must resolve
    this.library = lib;
    this.discovery.library = lib;
    return { id: profile.id, file: path.relative(this.root, file) };
  }

  deleteProfile(id) {
    const file = path.join(this.userProfileDir, `${String(id).replace('/', '__')}.json`);
    if (!fs.existsSync(file)) throw Object.assign(new Error(`no user profile ${id}`), { code: 'E_NOT_FOUND' });
    fs.unlinkSync(file);
    this.library = loadLibrary({ dirs: this.profileDirs, log: this.log });
    this.discovery.library = this.library;
    return { deleted: id };
  }

  /** Decode helper exposed for the UI's "test a value" box. */
  decodeSample(raw, spec) {
    return decode(raw, spec);
  }
}

// RediSearch TAG fields split on commas ("Raritan Computer, Inc." -> two tags), so TAG-typed
// layer components (app.json structuredComponents) must not contain them.
const TAG_ATTRS = ['device', 'device_uuid', 'device_address', 'profile', 'oid', 'class_hint', 'vendor'];
function sanitizeTags(p) {
  const attrs = Object.assign({}, p.attrs);
  for (const k of TAG_ATTRS) if (typeof attrs[k] === 'string') attrs[k] = attrs[k].replace(/\s*,\s*/g, ' ').trim();
  if (typeof attrs.enum === 'string') attrs.enum = attrs.enum.replace(/,/g, ';');
  return Object.assign({}, p, { attrs });
}

/** Attributes of `layer` from an hpl Point (attrs or splitAttrs form). */
function pointAttrs(p, layer) {
  if (p.splitAttrs || p.split_attrs) {
    const s = (p.splitAttrs || p.split_attrs).find((x) => x.layer === layer);
    if (s) return s.attrs || {};
  }
  return p.attrs || {};
}

module.exports = { Engine, pointAttrs };
