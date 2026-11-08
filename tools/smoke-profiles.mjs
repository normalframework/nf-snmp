#!/usr/bin/env node
// Smoke-test every profile against the generated simulator (sims/generated):
//   1. build sims/generated/spec.json from the profile library + sims/generated/mibinfo.json
//   2. (re)start the nfsnmp-sim-generated container on snmpnet (172.31.161.17, one UDP port per profile)
//   3. per profile: identify (records which profile auto-matches), materialize with that profile,
//      read every point, compare decoded values with the simulator's /truth
//   4. write sims/generated/REPORT.md + report.json; exit 1 on any failure
//
//   node tools/smoke-profiles.mjs [--only <regex>] [--no-restart]
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const { loadLibrary } = require('../lib/profiles');
const { identify, materialize, readSpecs } = require('../lib/profiles/device');
const { SnmpClient } = require('../lib/snmp/client');
const { buildSpec } = require('../sims/generated/genspec');

const IP = process.env.GENSIM_IP || '172.31.161.17';
const only = process.argv.includes('--only') ? new RegExp(process.argv[process.argv.indexOf('--only') + 1]) : null;
const GEN = path.join(ROOT, 'sims', 'generated');

const lib = loadLibrary({ strict: true });
const mib = JSON.parse(fs.readFileSync(path.join(GEN, 'mibinfo.json'), 'utf8'));
const spec = buildSpec(lib, mib);
fs.writeFileSync(path.join(GEN, 'spec.json'), JSON.stringify(spec));

if (!process.argv.includes('--no-restart')) {
  execFileSync('docker', ['rm', '-f', 'nfsnmp-sim-generated'], { stdio: 'ignore' });
  execFileSync('docker', ['run', '-d', '--name', 'nfsnmp-sim-generated', '--network', 'snmpnet', '--ip', IP, '-v', `${GEN}:/gen:ro`, '--entrypoint', 'python3', 'nfsnmp-sim-quirky:latest', '/gen/gensimd.py', '/gen/spec.json', '--http', '8000'], { stdio: 'ignore' });
}
for (let i = 0; i < 60; i++) {
  try {
    if ((await fetch(`http://${IP}:8000/health`)).ok) break;
  } catch { /* starting */ }
  await new Promise((r) => setTimeout(r, 500));
}

const results = [];
async function run(dev) {
  const r = { id: dev.id, port: dev.port, matched: null, points: 0, compared: 0, ok: 0, mismatches: [], errors: [], warnings: [], attrs: 0 };
  const client = new SnmpClient({ host: IP, port: dev.port, timeoutMs: 2000, retries: 1, maxOidsPerGet: 40 });
  try {
    const id = await identify(client, lib);
    r.matched = id.profile ? id.profile.id : null;
    const prof = lib.resolve(dev.id);
    const m = await materialize(client, prof);
    r.points = m.specs.length;
    r.attrs = Object.keys(m.attrs || {}).length;
    r.warnings = m.warnings;
    const t0 = Date.now();
    const rows = await readSpecs(client, m.specs);
    const t1 = Date.now();
    const truths = await Promise.all([t0 - spec.stepMs, t0, t1].map(async (at) => (await (await fetch(`http://${IP}:8000/truth?device=${encodeURIComponent(dev.id)}&at=${at}`)).json()).eng));
    for (const row of rows) {
      if (row.error !== undefined) {
        r.errors.push(`${row.spec.key}: ${row.code} ${row.error}`);
        continue;
      }
      const exp = truths.map((t) => t[row.spec.key]).filter(Boolean).map((e) => e.value);
      if (!exp.length) continue;
      r.compared++;
      if (exp.some((e) => Math.abs(Number(row.value) - e) <= Math.max(1e-6, Math.abs(e) * 1e-9))) r.ok++;
      else r.mismatches.push(`${row.spec.key}: got ${row.value}, expected ${exp.join(' or ')}`);
    }
  } catch (e) {
    r.errors.push(`fatal: ${e.message}`);
  } finally {
    client.close();
  }
  return r;
}

const devs = spec.devices.filter((d) => !only || only.test(d.id));
const queue = devs.slice();
await Promise.all(Array.from({ length: 8 }, async () => {
  while (queue.length) results.push(await run(queue.shift()));
}));
results.sort((a, b) => a.id.localeCompare(b.id));

const failed = results.filter((r) => r.mismatches.length || r.errors.length || r.points === 0);
const shadowed = results.filter((r) => r.matched !== r.id);
const sum = { profiles: results.length, passed: results.length - failed.length, failed: failed.length, points: results.reduce((a, r) => a + r.points, 0), compared: results.reduce((a, r) => a + r.compared, 0), autoMatchOther: shadowed.length };
fs.writeFileSync(path.join(GEN, 'report.json'), JSON.stringify({ summary: sum, results }, null, 1));
const md = ['# Generated-simulator smoke test', '', 'Every profile is served by `sims/generated/gensimd.py` from a spec built out of the profile and its MIB, then',
  'identified, materialized and read by nf-snmp; decoded values are compared with the simulator\'s truth.', '',
  `| profiles | passed | failed | points | values compared | auto-match picked another profile |`, '|---|---|---|---|---|---|',
  `| ${sum.profiles} | ${sum.passed} | ${sum.failed} | ${sum.points} | ${sum.compared} | ${sum.autoMatchOther} |`, '',
  '## Failures', '', ...(failed.length ? failed.map((r) => `- **${r.id}** (${r.points} points): ${[...r.errors, ...r.mismatches].slice(0, 5).join('; ')}`) : ['none']), '',
  '## Auto-match differs from the profile under test', '',
  'Expected where a more specific or hand-written profile covers the same sysObjectID (e.g. several Datadog APC profiles share `1.3.6.1.4.1.318.1.*`).', '',
  ...shadowed.map((r) => `- ${r.id} → ${r.matched || 'none'}`)].join('\n');
fs.writeFileSync(path.join(GEN, 'REPORT.md'), md + '\n');
console.log(JSON.stringify(sum));
for (const r of failed.slice(0, 40)) console.log('FAIL', r.id, r.points, [...r.errors, ...r.mismatches].slice(0, 3).join(' | '));
process.exitCode = failed.length ? 1 : 0;
