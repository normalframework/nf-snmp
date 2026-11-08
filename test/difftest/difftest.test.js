// SPDX-License-Identifier: GPL-3.0-or-later
// Differential test (docs/internals.md §3).
//  - harness logic tests: always run, no docker.
//  - full matrix: only with DIFFTEST=1 (needs docker; runs difftest/run.sh, which builds the
//    image, starts the extra agents and runs every implementation on every case).
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import harness from '../../difftest/run.js';

const { diffOutputs, allowed, expandCase, parseLines } = harness;
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

const vb = (oid, type, value) => ({ oid, type, value });

describe('difftest harness', () => {
  it('reports value, type, missing and extra diffs in walks', () => {
    const base = [vb('1.3.1', 'Integer', '1'), vb('1.3.2', 'Integer', '2'), vb('1.3.3', 'Gauge32', '3')];
    const other = [vb('1.3.1', 'Integer', '9'), vb('1.3.3', 'Counter32', '3'), vb('1.3.4', 'Integer', '4')];
    const kinds = diffOutputs('walk', base, other, []).map((d) => `${d.kind}:${d.oid}`);
    expect(kinds).toEqual(['value:1.3.1', 'missing:1.3.2', 'type:1.3.3', 'extra:1.3.4']);
  });

  it('ignores volatile values but not volatile types', () => {
    const d = diffOutputs('get', [vb('1.3.6.1.2.1.1.3.0', 'TimeTicks', '1')],
      [vb('1.3.6.1.2.1.1.3.0', 'TimeTicks', '2')], ['1.3.6.1.2.1.1.3.0']);
    expect(d).toEqual([]);
    const d2 = diffOutputs('get', [vb('1.3.6.1.2.1.1.3.0', 'TimeTicks', '1')],
      [vb('1.3.6.1.2.1.1.3.0', 'Gauge32', '1')], ['1.3.6.1.2.1.1.3.0']);
    expect(d2.map((x) => x.kind)).toEqual(['type']);
  });

  it('compares error class, and status/index only when both sides report them', () => {
    expect(diffOutputs('get', [{ error: 'noSuchName', status: 'noSuchName', index: 2 }],
      [{ error: 'noSuchName', message: 'x' }], [])).toEqual([]);
    expect(diffOutputs('get', [{ error: 'noSuchName', index: 2 }], [{ error: 'noSuchName', index: 1 }], []))
      .toHaveLength(1);
    expect(diffOutputs('walk', [vb('1.1', 'Integer', '1'), { error: 'nonIncreasing' }],
      [vb('1.1', 'Integer', '1')], []).map((d) => d.kind)).toEqual(['error']);
  });

  it('marks non-JSON output and crashes', () => {
    expect(parseLines('garbage\n', 0, '', false)[0].error).toBe('badOutput');
    expect(parseLines('', 1, 'boom', false)[0].error).toBe('crash');
  });

  it('matches allowlist entries by impl/case/kind/oid prefix', () => {
    const e = { impl: 'gosnmp', case: 'enterprise-.*', kind: 'type', oid: '1.3.6.1.4.1.99997' };
    const ctx = { impl: 'gosnmp', target: 'x', cred: 'v2c', case: 'enterprise-walk', op: 'walk' };
    expect(allowed(e, ctx, { kind: 'type', oid: '1.3.6.1.4.1.99997.1.5.0' })).toBe(true);
    expect(allowed(e, { ...ctx, impl: 'pysnmp' }, { kind: 'type', oid: '1.3.6.1.4.1.99997.1.5.0' })).toBe(false);
    expect(allowed(e, ctx, { kind: 'type', oid: '1.3.6.1.4.1.9999' })).toBe(false);
  });

  it('expands placeholders and maxRepetitions', () => {
    const cs = expandCase({ id: 'b', op: 'bulkwalk', root: '$roots', maxRepetitions: [1, 10] },
      { roots: ['1.3.1', '1.3.2'] });
    expect(cs.map((c) => c.id)).toEqual(['b[1.3.1]/r1', 'b[1.3.1]/r10', 'b[1.3.2]/r1', 'b[1.3.2]/r10']);
    expect(expandCase({ id: 'g', op: 'get', oids: '$missing' }, {})).toEqual([]);
  });
});

describe.skipIf(!process.env.DIFFTEST)('difftest matrix (docker)', () => {
  it('has no un-allowlisted divergences', () => {
    const r = spawnSync(path.join(ROOT, 'difftest/run.sh'), [], { stdio: 'inherit', timeout: 3600_000 });
    const report = JSON.parse(fs.readFileSync(path.join(ROOT, 'difftest/out/report.json'), 'utf8'));
    expect(report.cases).toBeGreaterThan(0);
    expect(report.failures).toBe(0);
    expect(r.status).toBe(0);
  }, 3600_000);
});
