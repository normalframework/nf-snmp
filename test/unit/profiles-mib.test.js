// Every profile symbol's name must resolve, in the profile's MIB, to the OID the profile uses
// (scalars: OID + ".0"; columns: the column OID; instance suffixes after the column are allowed for
// fixed instances like pduModel.1). Guards against the classic hand-written-profile bug of a
// right name with a wrong OID.
import { describe, it, expect } from 'vitest';
import snmp from 'net-snmp';
import path from 'path';
import fs from 'fs';
import lib from '../../lib/profiles/index.js';

const MIBDIR = path.resolve(__dirname, '../../mibs');
const DEPS = { 'PowerNet-MIB': ['RFC1155-SMI', 'RFC-1212', 'RFC-1215', 'RFC1213-MIB', 'SNMP-FRAMEWORK-MIB'], 'PDU2-MIB': ['INET-ADDRESS-MIB', 'SNMP-FRAMEWORK-MIB'], 'LIEBERT-GP-ENVIRONMENTAL-MIB': ['LIEBERT-GP-REGISTRATION-MIB'], 'ENTITY-SENSOR-MIB': ['SNMP-FRAMEWORK-MIB', 'UUID-TC-MIB', 'ENTITY-MIB'], 'IF-MIB': ['IANAifType-MIB'], 'UPS-MIB': [] };
const store = snmp.createModuleStore();
const loaded = new Set();
function mod(name) {
  for (const d of [...(DEPS[name] || []), name]) if (!loaded.has(d)) { store.loadFromFile(path.join(MIBDIR, d)); loaded.add(d); }
  return store.getModule(name);
}
// names from secondary MIBs used for labels/helpers
const EXTRA = { 'ENTITY-SENSOR-MIB': ['ENTITY-MIB'], 'IF-MIB': [], 'PDU2-MIB': [] };

const L = lib.loadLibrary({ strict: true });
describe('profiles match their MIBs', () => {
  for (const id of L.ids()) {
    const raw = L.get(id);
    if (!raw.mib) continue;
    it(id, () => {
      const objs = Object.assign({}, mod(raw.mib), ...(EXTRA[raw.mib] || []).map(mod));
      const syms = [...(raw.symbols || []), ...(raw.tables || []).flatMap((t) => t.columns)];
      for (const s of syms) {
        const o = objs[s.name];
        expect(o, `${s.name} not found in ${raw.mib}`).toBeTruthy();
        const isCol = (raw.tables || []).some((t) => t.columns.includes(s));
        if (isCol) expect(s.oid, s.name).toBe(o.OID);
        else expect(s.oid.startsWith(o.OID + '.'), `${s.name}: ${s.oid} vs MIB ${o.OID}`).toBe(true);
        if (s.writable) expect(o['MAX-ACCESS'] || o.ACCESS, `${s.name} writable`).toMatch(/write|create/);
      }
    });
  }
});
