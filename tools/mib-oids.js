#!/usr/bin/env node
'use strict';
// Resolve MIB object names to OIDs (+ syntax/units/hint/enum) with net-snmp's MIB parser.
//   node tools/mib-oids.js <MODULE> <name...>     (MIB files from ./mibs)
const snmp = require('net-snmp');
const path = require('path');
const [mod, ...names] = process.argv.slice(2);
const store = snmp.createModuleStore();
const dir = path.resolve(__dirname, '..', 'mibs');
const deps = { 'PowerNet-MIB': ['RFC1155-SMI', 'RFC-1212', 'RFC-1215', 'RFC1213-MIB'], 'PDU2-MIB': ['INET-ADDRESS-MIB'], 'LIEBERT-GP-ENVIRONMENTAL-MIB': ['LIEBERT-GP-REGISTRATION-MIB'], 'ENTITY-SENSOR-MIB': ['ENTITY-MIB'], 'IF-MIB': ['IANAifType-MIB'] };
for (const d of [...(deps[mod] || []), mod]) store.loadFromFile(path.join(dir, d));
const all = store.getModule(mod);
for (const n of names.length ? names : Object.keys(all)) {
  const o = all[n];
  if (!o) { console.log(JSON.stringify({ name: n, missing: true })); continue; }
  const syn = o.SYNTAX;
  console.log(JSON.stringify({ name: n, oid: o.OID, syntax: typeof syn === 'object' ? JSON.stringify(syn) : syn, units: o.UNITS, hint: o['DISPLAY-HINT'], access: o['MAX-ACCESS'] || o.ACCESS }));
}
