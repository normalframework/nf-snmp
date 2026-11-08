// Every profile against the generated simulator (needs docker + the snmpnet network from sims/).
// Run: SMOKE=1 npx vitest run test/profiles   (or: node tools/smoke-profiles.mjs)
import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
const run = process.env.SMOKE ? describe : describe.skip;
run('profile smoke test (generated simulator)', () => {
  it('every profile identifies, expands and decodes against its generated device', () => {
    let out = '';
    try {
      out = execFileSync('node', ['tools/smoke-profiles.mjs'], { encoding: 'utf8', timeout: 600000 });
    } catch (e) {
      out = String(e.stdout || '') + String(e.stderr || '');
    }
    const rep = JSON.parse(fs.readFileSync('sims/generated/report.json', 'utf8'));
    expect(rep.summary.failed, out).toBe(0);
    expect(rep.summary.profiles).toBeGreaterThan(150);
  }, 700000);
});
