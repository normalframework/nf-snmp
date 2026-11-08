// Full-stack test: NF (nf-full) + nf-snmp app + synthetic SNMP devices (sims/).
// Verifies install, identification/profile matching, NF poll-service trending against the
// simulators' ground truth, commanded SET through NF's command service, traps, and discovery.
//
// Prereqs: sims and test/e2e compose stacks up (see docker-compose.yml). Env: NF_URL (default
// http://127.0.0.1:18090), NF_CONTAINER (nfsnmp-e2e-nf-1), SKIP_INSTALL=1 to reuse an install.
import { describe, it, expect, beforeAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { createNfClient } from './nf-client.mjs';
import fs from 'node:fs';
import { installApp } from '../../tools/install-lib.mjs';

const NF_URL = process.env.NF_URL || 'http://127.0.0.1:18090';
const NF_CONTAINER = process.env.NF_CONTAINER || 'nfsnmp-e2e-nf-1';
const NF_SNMPNET_IP = process.env.NF_SNMPNET_IP || '172.31.161.20';
const APP = 'snmp';
const nf = createNfClient({ url: NF_URL, timeoutMs: 120000 });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const admin = (action, args) => nf.hooks.run(APP, 'admin', action, args, { timeoutMs: 120000 });
const truth = async (ip, at) => (await fetch(`http://${ip}:8000/truth${at ? `?at=${at}` : ''}`)).json();
const info = async (ip) => (await fetch(`http://${ip}:8000/info`)).json();
const AUTH = { authKey: 'authpass123', privKey: 'privpass123' };
const PERIOD = 10;

// [name, ip, credentials, expected profile]
const DEVICES = [
  ['e2e-apc', '172.31.161.11', { version: '2c', community: 'public', writeCommunity: 'private' }, 'apc/smart-ups'],
  ['e2e-ups', '172.31.161.12', { version: '3', user: 'shaaes', authProtocol: 'sha', privProtocol: 'aes', ...AUTH }, '_generic/ups-mib'],
  ['e2e-pdu', '172.31.161.13', { version: '3', user: 'sha256aes', authProtocol: 'sha256', privProtocol: 'aes', ...AUTH }, 'raritan/px-pdu2'],
  ['e2e-crac', '172.31.161.14', { version: '1', community: 'public', writeCommunity: 'private' }, 'vertiv/liebert-gp-env'],
  ['e2e-switch', '172.31.161.15', { version: '2c', community: 'public' }, '_generic/switch'],
  ['e2e-quirky', '172.31.161.16', { version: '2c', community: 'public', writeCommunity: 'private', maxOidsPerGet: 20, retries: 2 }, 'nfsnmp-test/quirky'],
];

async function waitFor(fn, { timeoutMs = 120000, everyMs = 2000, what = 'condition' } = {}) {
  const end = Date.now() + timeoutMs;
  let last;
  while (Date.now() < end) {
    try {
      last = await fn();
      if (last) return last;
    } catch (e) {
      last = e;
    }
    await sleep(everyMs);
  }
  throw new Error(`timed out waiting for ${what}: ${last && last.message ? last.message : JSON.stringify(last)}`);
}

async function layerPoints() {
  const out = [];
  for (let off = 0; ; ) {
    const r = await nf.request('POST', '/api/v1/point/query', { body: { layer: 'snmp', pageSize: 500, pageOffset: off } });
    const pts = r.points || [];
    out.push(...pts);
    off += pts.length;
    if (!pts.length || off >= Number(r.totalCount || 0)) return out;
  }
}

async function series(uuid, fromMs) {
  const r = await nf.request('GET', '/api/v1/point/data', { params: { uuids: uuid, from: new Date(fromMs).toISOString() } });
  return ((r.data || [])[0] || {}).values || [];
}

const num = (v) => (v.real ?? v.double ?? v.signed ?? v.unsigned);

beforeAll(async () => {
  await waitFor(async () => (await fetch(`${NF_URL}/api/v1/apps`)).ok, { what: 'NF API' });
}, 300000);

describe('nf-snmp end to end', () => {
  const devs = {};
  let t0;

  it('installs the app and the engine comes up', async () => {
    if (!process.env.SKIP_INSTALL) await installApp({ nf, appId: APP });
    await waitFor(async () => (await admin('status')).ok, { timeoutMs: 180000, everyMs: 5000, what: 'engine' });
  }, 400000);

  it('accepts a user profile', async () => {
    const profile = JSON.parse(fs.readFileSync(new URL('./profiles/quirky.json', import.meta.url)));
    expect((await admin('put-profile', { profile })).id).toBe('nfsnmp-test/quirky');
  }, 60000);

  it('adds devices over v1, v2c and v3 and matches the right profiles', async () => {
    for (const [name, ip, cred, profile] of DEVICES) {
      const r = await admin('put-device', { device: { name, host: ip, periodSeconds: PERIOD, timeoutMs: 1500, retries: 1, ...cred } });
      devs[name] = r.device;
      expect(r.device.matchedProfile, name).toBe(profile);
      expect(r.device.pointCount, name).toBeGreaterThan(2);
      expect(r.device.status.state, name).toBe('ok');
    }
    const pts = await layerPoints();
    for (const d of Object.values(devs)) expect(pts.filter((p) => p.parentUuid === d.uuid).length).toBe(d.pointCount + 1); // + snmpTrap
  }, 300000);

  it('hands polling to NF (poll service restart) and trends values matching simulator truth', async () => {
    // nf-full <= 3.10.11 loads polled layers at startup only; restart the poll service.
    execFileSync('docker', ['exec', NF_CONTAINER, '/command/s6-svc', '-r', '/run/service/poll']);
    t0 = Date.now();
    await waitFor(async () => (await admin('status')).polling.mode === 'nf', { timeoutMs: 90000, what: 'NF to read the layer' });
    await sleep(PERIOD * 3 * 1000);
    const pts = await layerPoints();
    const report = [];
    for (const [name, ip] of DEVICES) {
      const d = devs[name];
      const step = (await info(ip)).stepMs || 10000;
      for (const p of pts.filter((x) => x.parentUuid === d.uuid && x.period)) {
        const vals = await series(p.uuid, t0);
        const key = `${p.attrs.symbol.split('.')[0]}.${p.attrs.index || '0'}`;
        if (!vals.length) {
          // acceptable only if the device reports the value unavailable (e.g. a failed fan sensor)
          const er = await nf.request('GET', '/api/v1/point/errors', { params: { uuids: p.uuid } });
          const msgs = (er.errors || []).flatMap((x) => (x.errors || []).map((e) => e.message));
          if (!msgs.some((m) => /E_NOT_AVAILABLE/.test(m))) report.push({ device: name, point: p.name, problem: 'no samples', errors: msgs.slice(0, 2) });
          continue;
        }
        const last = vals[vals.length - 1];
        const ts = Date.parse(last.ts);
        // sample may have been taken just before the timestamp NF assigned: accept this or the previous step
        const cands = [await truth(ip, ts), await truth(ip, ts - step)];
        const exp = cands.map((c) => c.eng && c.eng[key]).filter(Boolean);
        if (!exp.length) continue; // helper/aux point without a modeled engineering value
        const got = num(last) ?? last.characterString;
        const ok = exp.some((e) => (typeof e.value === 'number' ? Math.abs(Number(got) - e.value) <= Math.max(1e-9, Math.abs(e.value) * 1e-12) : String(got) === String(e.value)));
        if (!ok) report.push({ device: name, point: p.name, key, got, expected: exp.map((e) => e.value) });
      }
    }
    expect(report, JSON.stringify(report, null, 1)).toEqual([]);
  }, 400000);

  it('writes a setpoint through the NF command service and restores it on cancel', async () => {
    const pts = await layerPoints();
    const sp = pts.find((p) => p.parentUuid === devs['e2e-crac'].uuid && p.attrs.symbol === 'lgpEnvTemperatureSettingDegC');
    expect(sp).toBeTruthy();
    const before = (await truth('172.31.161.14')).eng['lgpEnvTemperatureSettingDegC.0'].value;
    const cmd = await nf.request('POST', '/api/v2/command', { body: { name: `e2e-${Date.now()}`, duration: '120s' } });
    const id = cmd.id || (cmd.command && cmd.command.id);
    const target = before + 2;
    const w = await nf.request('POST', '/api/v2/command/write', { body: { commandId: id, writes: [{ point: { uuid: sp.uuid, layer: 'snmp' }, value: { real: target }, systemPriority: '12' }] } });
    expect(w.errors || []).toEqual([]);
    await waitFor(async () => (await truth('172.31.161.14')).eng['lgpEnvTemperatureSettingDegC.0'].value === target, { timeoutMs: 60000, what: 'setpoint written' });
    await nf.request('DELETE', `/api/v2/command/${id}`);
    await waitFor(async () => (await truth('172.31.161.14')).eng['lgpEnvTemperatureSettingDegC.0'].value === before, { timeoutMs: 60000, what: 'setpoint restored' });
  }, 200000);

  it('refuses commanded writes to read-only points', async () => {
    const pts = await layerPoints();
    const ro = pts.find((p) => p.parentUuid === devs['e2e-crac'].uuid && p.attrs.writable === 'false' && p.period);
    const cmd = await nf.request('POST', '/api/v2/command', { body: { name: `e2e-ro-${Date.now()}`, duration: '60s' } });
    const id = cmd.id || (cmd.command && cmd.command.id);
    const res = await nf.request('POST', '/api/v2/command/write', { body: { commandId: id, writes: [{ point: { uuid: ro.uuid, layer: 'snmp' }, value: { real: 1 }, systemPriority: '12' }] } }).catch((e) => ({ error: e.message }));
    await sleep(3000);
    const c = await nf.request('GET', `/api/v2/command/${id}`);
    await nf.request('DELETE', `/api/v2/command/${id}`).catch(() => {});
    expect(JSON.stringify([res, c])).toMatch(/not writable/);
  }, 120000);

  it('receives a trap and records it on the device snmpTrap point', async () => {
    const before = Date.now();
    const r = await fetch('http://172.31.161.11:8000/trap', { method: 'POST', body: JSON.stringify({ target: `${NF_SNMPNET_IP}:162`, version: '2c' }) });
    expect(r.ok).toBe(true);
    const tr = await waitFor(async () => (await admin('traps', { limit: 20 })).traps.find((t) => t.from === '172.31.161.11' && t.ts >= before - 1000), { timeoutMs: 30000, what: 'trap' });
    expect(tr.device).toBe('e2e-apc');
    const pts = await layerPoints();
    const tp = pts.find((p) => p.parentUuid === devs['e2e-apc'].uuid && p.attrs.symbol === 'snmpTrap');
    const vals = await waitFor(async () => { const v = await series(tp.uuid, before - 1000); return v.length ? v : null; }, { timeoutMs: 30000, what: 'trap point value' });
    expect(num(vals[vals.length - 1])).toBeGreaterThanOrEqual(1);
    const after = (await layerPoints()).find((p) => p.uuid === tp.uuid);
    expect(after.attrs.last_trap).toContain(tr.trapOid);
  }, 120000);

  it('keeps trending through packet loss, floats-as-strings and table gaps (quirky agent)', async () => {
    const Q = 'http://172.31.161.16:8000';
    const fault = (b) => fetch(`${Q}/set-fault`, { method: 'POST', body: JSON.stringify(b) });
    try {
      await fault({ kind: 'dropRate', value: 0.3 });
      await fault({ kind: 'floatAsString' });
      const pts = await layerPoints();
      const temp = pts.find((p) => p.parentUuid === devs['e2e-quirky'].uuid && p.attrs.symbol === 'qtTemperature.sensor-07');
      expect(temp).toBeTruthy();
      const from = Date.now();
      await sleep(PERIOD * 4 * 1000);
      const vals = await series(temp.uuid, from);
      expect(vals.length).toBeGreaterThanOrEqual(2);
      for (const v of vals.slice(-2)) {
        const ts = Date.parse(v.ts);
        const exp = [await truth('172.31.161.16', ts), await truth('172.31.161.16', ts - 10000)].map((t) => t.eng['qtTemperature.7'] && t.eng['qtTemperature.7'].value);
        expect(exp).toContain(num(v));
      }
    } finally {
      await fault({ kind: 'clear' });
    }
  }, 200000);

  it('discovers the simulators on the network', async () => {
    const { jobId } = await admin('discover', { hosts: '172.31.161.10-16', credentials: [{ version: '2c', community: 'public' }], timeoutMs: 800, concurrency: 8 });
    const job = await waitFor(async () => { const j = await admin('discover-get', { jobId }); return j.state !== 'running' ? j : null; }, { timeoutMs: 60000, what: 'discovery' });
    const byHost = Object.fromEntries(job.found.map((f) => [f.host, f]));
    expect(byHost['172.31.161.11'].identity.profile.id).toBe('apc/smart-ups');
    expect(byHost['172.31.161.13'].identity.vendor).toMatch(/Raritan/);
    expect(byHost['172.31.161.11'].existingDevice).toBe(devs['e2e-apc'].uuid);
    expect(byHost['172.31.161.10']).toBeUndefined();
  }, 120000);
});
