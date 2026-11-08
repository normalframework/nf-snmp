import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import snmp from 'net-snmp';
import fs from 'fs';
import os from 'os';
import path from 'path';
import engineMod from '../../lib/engine/index.js';
import fake from '../../lib/nf/fake.js';
const { Engine } = engineMod;

const PORT = 17100 + Math.floor(Math.random() * 1000);
const ENT = '1.3.6.1.4.1.55555';
let agent, eng, nf, tmp, mib;
const sets = [];

function startAgent() {
  agent = snmp.createAgent({ port: PORT, address: '127.0.0.1', accessControlModelType: snmp.AccessControlModelType.None }, () => {});
  agent.getAuthorizer().addCommunity('public');
  mib = agent.getMib();
  const scalar = (name, oid, type, value, rw) => {
    mib.registerProvider({ name, type: snmp.MibProviderType.Scalar, oid, scalarType: type, maxAccess: rw ? snmp.MaxAccess['read-write'] : snmp.MaxAccess['read-only'],
      handler: (r) => { if (r.operation === snmp.PduType.SetRequest) sets.push(r.instanceNode.value); r.done(); } });
    mib.setScalarValue(name, value);
  };
  scalar('sysDescr', '1.3.6.1.2.1.1.1', snmp.ObjectType.OctetString, 'Test UPS v1');
  scalar('sysObjectID', '1.3.6.1.2.1.1.2', snmp.ObjectType.OID, `${ENT}.7.1`);
  scalar('sysUpTime', '1.3.6.1.2.1.1.3', snmp.ObjectType.TimeTicks, 12345);
  scalar('sysName', '1.3.6.1.2.1.1.5', snmp.ObjectType.OctetString, 'ups-a');
  scalar('temp', `${ENT}.1.1`, snmp.ObjectType.Integer, 243);
  scalar('setpoint', `${ENT}.1.2`, snmp.ObjectType.Integer, 220, true);
  scalar('digits', `${ENT}.1.3`, snmp.ObjectType.Gauge, 2);
  scalar('amps', `${ENT}.1.4`, snmp.ObjectType.Gauge, 1234);
  // table ENT.2.1.{col}.{idx}
  mib.registerProvider({ name: 'outTable', type: snmp.MibProviderType.Table, oid: `${ENT}.2.1`, maxAccess: snmp.MaxAccess['not-accessible'],
    tableColumns: [
      { number: 1, name: 'idx', type: snmp.ObjectType.Integer, maxAccess: snmp.MaxAccess['read-only'] },
      { number: 2, name: 'label', type: snmp.ObjectType.OctetString, maxAccess: snmp.MaxAccess['read-only'] },
      { number: 3, name: 'watts', type: snmp.ObjectType.Gauge, maxAccess: snmp.MaxAccess['read-only'] },
    ], tableIndex: [{ columnName: 'idx' }] });
  mib.addTableRow('outTable', [1, 'Rack A', 500]);
  mib.addTableRow('outTable', [2, 'Rack B', 750]);
}

beforeAll(async () => {
  startAgent();
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'nfsnmp-'));
  fs.mkdirSync(path.join(tmp, 'profiles'));
  fs.writeFileSync(path.join(tmp, 'profiles', 'test.json'), JSON.stringify({
    id: 'test/ups', name: 'Test UPS', match: [{ sysObjectID: `${ENT}.7` }],
    symbols: [
      { name: 'temp', oid: `${ENT}.1.1.0`, scale: 0.1, units: 'degC' },
      { name: 'setpoint', oid: `${ENT}.1.2.0`, scale: 0.1, units: 'degC', writable: true, setType: 'Integer' },
      { name: 'amps', oid: `${ENT}.1.4.0`, decimalDigitsOid: `${ENT}.1.3.0`, units: 'A' },
    ],
    tables: [{ name: 'out', indexOid: `${ENT}.2.1.1`, label: { column: 'label' }, columns: [
      { name: 'label', oid: `${ENT}.2.1.2`, point: false },
      { name: 'watts', oid: `${ENT}.2.1.3`, units: 'W' },
    ] }],
  }));
  nf = fake.create();
  eng = new Engine({ nf, root: tmp, port: 0, profileDirs: [path.join(tmp, 'profiles')] });
  await eng.start();
});
afterAll(async () => { await eng.stop(); agent.close(); });

const post = async (p, body) => (await fetch(`http://127.0.0.1:${eng.port}${p}`, { method: 'POST', body: JSON.stringify(body) })).json();

describe('engine', () => {
  let dev;
  it('adds a device, auto-matches the profile and publishes points', async () => {
    const r = await post('/admin/devices', { device: { host: '127.0.0.1', port: PORT, name: 'UPS-A', periodSeconds: 30, timeoutMs: 500, retries: 0 } });
    dev = r.device;
    expect(dev.matchedProfile).toBe('test/ups');
    expect(dev.pointCount).toBe(5);
    const pts = [...nf._points.values()];
    const dp = pts.find((p) => p.uuid === dev.uuid);
    expect(dp.pointType).toBe('DEVICE');
    const watts = pts.filter((p) => p.attrs.symbol && p.attrs.symbol.startsWith('watts'));
    expect(watts.map((p) => p.name).sort()).toEqual(['Rack A watts', 'Rack B watts']);
    expect(watts[0]).toMatchObject({ parentUuid: dev.uuid, periodSeconds: 30, hplDriver: 'snmp', layer: 'snmp' });
    expect(watts[0].attrs.device_address).toBe(`SNMP:127.0.0.1:${PORT}`);
  });
  it('serves driver reads with decoded values (scale, decimal digits, tables)', async () => {
    const uuids = [...nf._points.values()].filter((p) => p.periodSeconds).map((p) => p.uuid);
    const rep = await post('/driver/read', { reads: uuids.map((u) => ({ point: { uuid: u } })) });
    expect(rep.errors).toBeUndefined();
    const byName = Object.fromEntries(rep.results.map((r) => [nf._points.get(r.uuid).name, r.hplValue.double]));
    expect(byName).toEqual({ temp: 24.3, setpoint: 22, amps: 12.34, 'Rack A watts': 500, 'Rack B watts': 750 });
  });
  it('writes a writable point with inverse scaling and rejects read-only', async () => {
    const sp = [...nf._points.values()].find((p) => p.name === 'setpoint');
    const t = [...nf._points.values()].find((p) => p.name === 'temp');
    const rep = await post('/driver/write', { writes: [
      { point: { uuid: sp.uuid }, value: { normalized: { real: 23.5 } } },
      { point: { uuid: t.uuid }, value: { normalized: { real: 1 } } },
    ] });
    expect(rep.errors).toHaveLength(1);
    expect(rep.errors[0].uuid).toBe(t.uuid);
    expect(mib.getScalarValue('setpoint')).toBe(235);
  });
  it('reports driver status and unknown points', async () => {
    expect((await post('/driver/status', {})).devices).toEqual([{ name: 'UPS-A', status: 'STATUS_CONNECTED' }]);
    const rep = await post('/driver/read', { reads: [{ point: { uuid: 'nope' } }] });
    expect(rep.errors[0].uuid).toBe('nope');
  });
  it('marks a dead device unreachable with per-point timeout errors', async () => {
    const r = await post('/admin/devices', { device: { host: '127.0.0.1', port: 9, name: 'dead', profile: 'test/ups', timeoutMs: 200, retries: 0 }, sync: false });
    // never materialized: synthesize via attrs fallback
    const rep = await post('/driver/read', { reads: [{ point: { uuid: 'x1', attrs: { device_uuid: r.device.uuid, oid: `${ENT}.1.1.0` } } }] });
    expect(rep.errors[0].error.message).toMatch(/timeout/);
    const st = (await post('/driver/status', {})).devices.find((d) => d.name === 'dead');
    expect(st.status).toBe('STATUS_ERROR');
  });
  it('persists state and restores the index after restart', async () => {
    await eng.stop();
    const e2 = new Engine({ nf: fake.create(), root: tmp, port: 0, profileDirs: [path.join(tmp, 'profiles')] });
    await e2.start();
    expect(e2.index.size).toBe(5);
    await e2.stop();
    eng = new Engine({ nf, root: tmp, port: 0, profileDirs: [path.join(tmp, 'profiles')] });
    await eng.start();
  });
  it('deletes a device and its points', async () => {
    const r = await post('/admin/devices/delete', { uuid: dev.uuid });
    expect(r.deleted).toBe(7);
    expect(nf._points.has(dev.uuid)).toBe(false);
  });
});

describe('self-poll fallback', () => {
  it('polls and pushes data when NF never calls /driver/read, and stands down when it does', async () => {
    const tmp2 = fs.mkdtempSync(path.join(os.tmpdir(), 'nfsnmp-sp-'));
    const nf2 = fake.create();
    const e = new Engine({ nf: nf2, root: tmp2, port: 0, profileDirs: [path.join(tmp, 'profiles')], selfPollGraceMs: 300 });
    e.selfPoll.tickMs = 50;
    await e.start();
    await e.putDevice({ host: '127.0.0.1', port: PORT, name: 'sp', periodSeconds: 1, timeoutMs: 500, retries: 0 });
    await new Promise((r) => setTimeout(r, 2500));
    expect(e.selfPoll.mode()).toBe('self');
    const pushed = nf2._data.filter((d) => d.values && d.values.length);
    expect(pushed.length).toBeGreaterThanOrEqual(5);
    expect(pushed.find((d) => nf2._points.get(d.uuid).name === 'temp').values[0].double).toBe(24.3);
    await post2(e, '/driver/read', { reads: [{ point: { uuid: pushed[0].uuid } }] });
    expect(e.selfPoll.mode()).toBe('nf');
    await e.stop();
  });
});
async function post2(e, p, body) { return (await fetch(`http://127.0.0.1:${e.port}${p}`, { method: 'POST', body: JSON.stringify(body) })).json(); }

describe('user profiles', () => {
  it('adds, uses and deletes a user profile; refuses to shadow built-ins', async () => {
    const r = await post('/admin/profiles', { profile: { id: 'acme/thing', name: 'Acme', match: [{ sysObjectID: `${ENT}.7.1` }], symbols: [{ name: 'temp', oid: `${ENT}.1.1.0` }] } });
    expect(r.id).toBe('acme/thing');
    expect((await (await fetch(`http://127.0.0.1:${eng.port}/admin/profiles`)).json()).profiles.find((p) => p.id === 'acme/thing').user).toBe(true);
    const bad = await fetch(`http://127.0.0.1:${eng.port}/admin/profiles`, { method: 'POST', body: JSON.stringify({ profile: { id: 'apc/smart-ups', name: 'x' } }) });
    expect(bad.status).toBe(400);
    expect((await post('/admin/profiles/delete', { id: 'acme/thing' })).deleted).toBe('acme/thing');
  });
});

describe('tag sanitizing', () => {
  it('removes commas from TAG attributes before publishing', async () => {
    const tmp3 = fs.mkdtempSync(path.join(os.tmpdir(), 'nfsnmp-tag-'));
    const nf3 = fake.create();
    const e = new Engine({ nf: nf3, root: tmp3, port: 0, profileDirs: [path.join(tmp, 'profiles')] });
    await e.start();
    await e.putDevice({ host: '127.0.0.1', port: PORT, name: 'UPS, rack 4', timeoutMs: 500, retries: 0, attrs: { site: 'x' } });
    const dp = [...nf3._points.values()].find((p) => p.pointType === 'DEVICE');
    expect(dp.attrs.device).toBe('UPS rack 4');
    await e.stop();
  });
});
