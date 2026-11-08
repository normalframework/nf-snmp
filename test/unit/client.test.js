import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import snmp from 'net-snmp';
import helper from './agent-helper.js';
import clientMod from '../../lib/snmp/client.js';
const { SnmpClient } = clientMod;
const PORT = 16100 + Math.floor(Math.random() * 1000);
let ag;
beforeAll(async () => {
  ag = await helper.startAgent({ port: PORT, scalars: {
    '1.3.6.1.4.1.55555.1.1.0': { type: snmp.ObjectType.Integer, value: -42 },
    '1.3.6.1.4.1.55555.1.2.0': { type: snmp.ObjectType.OctetString, value: 'hello' },
    '1.3.6.1.4.1.55555.1.3.0': { type: snmp.ObjectType.Counter64, value: Buffer.from('0000000100000000', 'hex') },
    '1.3.6.1.4.1.55555.1.4.0': { type: snmp.ObjectType.Gauge, value: 4294967295 },
    '1.3.6.1.4.1.55555.1.5.0': { type: snmp.ObjectType.OctetString, value: '' },
  } });
});
afterAll(() => ag && ag.close());
const t = (o = {}) => ({ host: '127.0.0.1', port: PORT, timeoutMs: 500, retries: 0, ...o });
describe('SnmpClient', () => {
  it('gets mixed types in normalized form', async () => {
    const c = new SnmpClient(t());
    const vbs = await c.get(['1.3.6.1.4.1.55555.1.1.0', '.1.3.6.1.4.1.55555.1.2.0', '1.3.6.1.4.1.55555.1.3.0', '1.3.6.1.4.1.55555.1.4.0', '1.3.6.1.4.1.55555.1.5.0', '1.3.6.1.4.1.55555.9.0']);
    c.close();
    expect(vbs).toEqual([
      { oid: '1.3.6.1.4.1.55555.1.1.0', type: 'Integer', value: '-42' },
      { oid: '1.3.6.1.4.1.55555.1.2.0', type: 'OctetString', value: '68656c6c6f' },
      { oid: '1.3.6.1.4.1.55555.1.3.0', type: 'Counter64', value: '4294967296' },
      { oid: '1.3.6.1.4.1.55555.1.4.0', type: 'Gauge32', value: '4294967295' },
      { oid: '1.3.6.1.4.1.55555.1.5.0', type: 'OctetString', value: '' },
      { oid: '1.3.6.1.4.1.55555.9.0', type: 'NoSuchObject', value: '' },
    ]);
  });
  it('walks and bulkwalks the same subtree identically', async () => {
    const c = new SnmpClient(t());
    const a = await c.walk('1.3.6.1.4.1.55555', { bulk: false });
    const b = await c.walk('1.3.6.1.4.1.55555', { bulk: true, maxRepetitions: 2 });
    c.close();
    expect(a.error).toBeUndefined();
    expect(a.varbinds.length).toBe(5);
    expect(b).toEqual(a);
  });
  it('v3 authPriv works and wrong key is an authError', async () => {
    const ok = new SnmpClient(t({ version: '3', user: 'shaaes', authProtocol: 'sha', authKey: 'authpass123', privProtocol: 'aes', privKey: 'privpass123' }));
    expect((await ok.get(['1.3.6.1.4.1.55555.1.1.0']))[0].value).toBe('-42');
    ok.close();
    const bad = new SnmpClient(t({ version: '3', user: 'shaaes', authProtocol: 'sha', authKey: 'wrongpass99', privProtocol: 'aes', privKey: 'privpass123' }));
    await expect(bad.get(['1.3.6.1.4.1.55555.1.1.0'])).rejects.toMatchObject({ class: expect.stringMatching(/authError|timeout/) });
    bad.close();
  });
  it('readMany reports per-oid errors and timeouts', async () => {
    const c = new SnmpClient(t({ maxOidsPerGet: 2 }));
    const m = await c.readMany(['1.3.6.1.4.1.55555.1.1.0', '1.3.6.1.4.1.55555.1.2.0', '1.3.6.1.4.1.55555.7.0']);
    c.close();
    expect(m.get('1.3.6.1.4.1.55555.1.1.0').value).toBe('-42');
    expect(m.get('1.3.6.1.4.1.55555.7.0').error).toBe('NoSuchObject');
    const dead = new SnmpClient({ host: '127.0.0.1', port: 9, timeoutMs: 200, retries: 0 });
    const d = await dead.readMany(['1.3.6.1.2.1.1.1.0']);
    dead.close();
    expect(d.get('1.3.6.1.2.1.1.1.0').error).toBe('timeout');
  });
});

describe('readMany on a dead device', () => {
  it('fails fast instead of timing out every batch', async () => {
    const dead = new SnmpClient({ host: '127.0.0.1', port: 9, timeoutMs: 200, retries: 0, maxOidsPerGet: 2 });
    const oids = Array.from({ length: 20 }, (_, i) => `1.3.6.1.4.1.1.${i}.0`);
    const t = Date.now();
    const m = await dead.readMany(oids);
    dead.close();
    expect([...m.values()].every((v) => v.error === 'timeout')).toBe(true);
    expect(m.size).toBe(20);
    expect(Date.now() - t).toBeLessThan(1500); // 2 timeouts, not 10
  });
  it('walks an empty subtree on an agent that answers noSuchObject past the end', async () => {
    const c = new SnmpClient(t());
    const w = await c.walk('1.3.6.1.4.1.55555.9', { bulk: false });
    const b = await c.walk('1.3.6.1.4.1.55555.9', { bulk: true });
    c.close();
    expect(w).toEqual({ varbinds: [] });
    expect(b).toEqual({ varbinds: [] });
  });
});
