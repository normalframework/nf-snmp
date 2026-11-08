#!/usr/bin/env node
// Call the nf-snmp admin hook on an NF instance:  NF_URL=... node tools/admin.mjs <action> '<json args>'
import { createNfClient } from '../test/e2e/nf-client.mjs';
const nf = createNfClient({ url: process.env.NF_URL || 'http://localhost:8080', token: process.env.NF_TOKEN, timeoutMs: 120000 });
const [action, json] = process.argv.slice(2);
const r = await nf.hooks.run(process.env.APP_ID || 'snmp', 'admin', action, json ? JSON.parse(json) : {});
console.log(JSON.stringify(r, null, 1));
