#!/usr/bin/env node
// NF_URL=http://localhost:8080 [NF_TOKEN=...] [APP_ID=snmp] node tools/install.mjs
import { createNfClient } from '../test/e2e/nf-client.mjs';
import { installApp } from './install-lib.mjs';
const nf = createNfClient({ url: process.env.NF_URL || 'http://localhost:8080', token: process.env.NF_TOKEN, timeoutMs: 120000 });
const app = await installApp({ nf, appId: process.env.APP_ID || 'snmp', log: console.log });
console.log(JSON.stringify({ layer: app.layer && app.layer.name, driver: app.layer && app.layer.driver, hooks: (app.hooks || []).map((h) => h.name) }));
