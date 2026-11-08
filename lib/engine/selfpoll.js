'use strict';
/**
 * Self-poll fallback.
 *
 * NF's poll service (gobac src/poll/main.go pollDrivers) lists polled layers once at startup, so a
 * layer created by installing this app is not polled until the poll service restarts (NF restart).
 * Until NF's poller calls /driver/read, the engine schedules reads itself and pushes the results
 * through AddData. As soon as NF reads arrive the fallback stands down (no double polling); if NF
 * stops reading for longer than the grace period, it takes over again.
 */
class SelfPoller {
  /** @param {{engine: any, log: any, tickMs?: number, graceMs?: number, now?: () => number}} o */
  constructor(o) {
    this.engine = o.engine;
    this.log = o.log;
    this.tickMs = o.tickMs || 1000;
    this.graceMs = o.graceMs || 90000;
    this.now = o.now || Date.now;
    this.timer = null;
    this.active = false;
    this.since = this.now();
    this.lastNfRead = 0;
    /** @type {Map<string, number>} point uuid -> next due ms */
    this.due = new Map();
    this.inflight = new Set();
    this.counts = { cycles: 0, points: 0, errors: 0, activations: 0 };
  }

  start() {
    if (this.timer) return;
    this.timer = setInterval(() => this.tick().catch((e) => this.log.warn('self-poll tick failed', { error: e.message })), this.tickMs);
    if (this.timer.unref) this.timer.unref();
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  /** Called by the engine for every NF /driver/read. */
  noteNfRead() {
    this.lastNfRead = this.now();
    if (this.active) {
      this.active = false;
      this.log.info('NF poll service is reading the snmp layer; self-poll fallback stands down');
    }
  }

  mode() {
    return this.active ? 'self' : this.lastNfRead ? 'nf' : 'waiting';
  }

  status() {
    return { mode: this.mode(), lastNfRead: this.lastNfRead || null, graceMs: this.graceMs, counts: this.counts };
  }

  async tick() {
    const now = this.now();
    const e = this.engine;
    if (!e.publishEnabled || !e.index.size) return;
    const quietFor = now - Math.max(this.lastNfRead, this.since);
    if (!this.active && quietFor > this.graceMs) {
      this.active = true;
      this.counts.activations++;
      this.log.warn('NF poll service is not reading the snmp layer (it loads polled layers at startup; restart NF to hand polling back). Polling from the engine meanwhile.', { quietMs: quietFor });
    }
    if (!this.active) return;
    // Schedule per (device, period) group so one cycle reads a whole device in as few PDUs as
    // possible; groups are phase-shifted by a hash of the device so devices don't align.
    const groups = new Map();
    for (const [uuid, { deviceUuid, spec }] of e.index) {
      const cfg = e.store.devices[deviceUuid];
      if (!cfg || !cfg.enabled) continue;
      const period = 1000 * (spec.periodSeconds || cfg.periodSeconds || 60);
      const key = `${deviceUuid}|${period}`;
      if (!groups.has(key)) groups.set(key, { deviceUuid, period, uuids: [] });
      groups.get(key).uuids.push(uuid);
    }
    const byDev = new Map();
    for (const [key, g] of groups) {
      if (this.inflight.has(g.deviceUuid)) continue;
      let next = this.due.get(key);
      if (next === undefined) {
        next = now + (hash(g.deviceUuid) % g.period);
        this.due.set(key, next);
      }
      if (next > now) continue;
      this.due.set(key, now + g.period);
      if (!byDev.has(g.deviceUuid)) byDev.set(g.deviceUuid, []);
      byDev.get(g.deviceUuid).push(...g.uuids);
    }
    for (const [dev, uuids] of byDev) {
      this.inflight.add(dev);
      this.cycle(uuids)
        .catch((err) => this.log.warn('self-poll cycle failed', { error: err.message }))
        .finally(() => this.inflight.delete(dev));
    }
  }

  async cycle(uuids) {
    this.counts.cycles++;
    const reply = await this.engine.read({ reads: uuids.map((u) => ({ point: { uuid: u } })) }, { internal: true });
    const items = [];
    for (const r of reply.results || []) items.push({ uuid: r.uuid, values: [r.hplValue] });
    for (const er of reply.errors || []) items.push({ uuid: er.uuid, values: [], errors: [{ ts: er.error.ts || new Date(this.now()).toISOString(), message: er.error.message }] });
    this.counts.points += (reply.results || []).length;
    this.counts.errors += (reply.errors || []).length;
    if (items.length) await this.engine.nf.points.writeData(this.engine.layer, items);
  }
}

function hash(s) {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
  return h;
}

module.exports = { SelfPoller };
