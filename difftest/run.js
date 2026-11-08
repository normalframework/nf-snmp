#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
//
// nf-snmp differential test harness (docs/internals.md §3).
//
// Runs every implementation (net-snmp, gosnmp, pysnmp, ours) on every case of a matrix
// (targets x credential sets x ops/OID sets), normalizes the §1 output, diffs each
// implementation against the baseline, applies difftest/allowlist.json and writes
// difftest/out/report.json.  Node stdlib only.
//
// Normally started by difftest/run.sh, which builds the image and runs this inside the
// difftest container on the sims' docker network.  Usage:
//
//   node difftest/run.js [--matrix F] [--allowlist F] [--out F] [--impls a,b] [--baseline x]
//                        [--targets re] [--cases re] [--creds re] [--list] [--no-fail] [-v]
'use strict';

const fs = require('fs');
const path = require('path');
const dns = require('dns').promises;
const http = require('http');
const { spawn } = require('child_process');

const HERE = __dirname;
const REPO = path.resolve(HERE, '..');

// ---------- args ----------

function parseArgs(argv) {
  const a = {
    matrix: path.join(HERE, 'matrix.json'),
    allowlist: path.join(HERE, 'allowlist.json'),
    out: path.join(HERE, 'out', 'report.json'),
    impls: null, baseline: null, targets: null, cases: null, creds: null,
    list: false, fail: true, verbose: false, attempts: 3,
  };
  for (let i = 2; i < argv.length; i++) {
    const k = argv[i];
    const v = () => argv[++i];
    switch (k) {
      case '--matrix': a.matrix = v(); break;
      case '--allowlist': a.allowlist = v(); break;
      case '--out': a.out = v(); break;
      case '--impls': a.impls = v().split(','); break;
      case '--baseline': a.baseline = v(); break;
      case '--targets': a.targets = new RegExp(v()); break;
      case '--cases': a.cases = new RegExp(v()); break;
      case '--creds': a.creds = new RegExp(v()); break;
      case '--attempts': a.attempts = Number(v()); break;
      case '--list': a.list = true; break;
      case '--no-fail': a.fail = false; break;
      case '-v': case '--verbose': a.verbose = true; break;
      case '-h': case '--help':
        console.log(fs.readFileSync(__filename, 'utf8').split('\n').slice(2, 16).join('\n'));
        process.exit(0);
        break;
      default: throw new Error(`unknown argument ${k}`);
    }
  }
  return a;
}

// ---------- implementations ----------

function implCommands() {
  const local = (p) => path.join(HERE, 'refs', p);
  const pyVenv = '/opt/pysnmp/venv/bin/python3';
  return {
    // Prefer the repo copy of the script refs (edit without rebuilding the image).
    netsnmp: () => fs.existsSync(local('netsnmp/ref_netsnmp.py'))
      ? ['python3', ['-I', local('netsnmp/ref_netsnmp.py')]] : ['ref-netsnmp', []],
    pysnmp: () => fs.existsSync(pyVenv) && fs.existsSync(local('pysnmp/ref_pysnmp.py'))
      ? [pyVenv, ['-I', local('pysnmp/ref_pysnmp.py')]] : ['ref-pysnmp', []],
    gosnmp: () => ['ref-gosnmp', []],
    ours: (op) => ['node', [path.join(REPO, 'bin', 'nf-snmp.js'), op, '--json']],
  };
}

function implAvailable(name) {
  if (name === 'ours') {
    return fs.existsSync(path.join(REPO, 'bin', 'nf-snmp.js'))
      ? null : 'bin/nf-snmp.js not present';
  }
  const [cmd] = implCommands()[name]('get');
  if (cmd.includes('/')) return fs.existsSync(cmd) ? null : `${cmd} not found`;
  const found = (process.env.PATH || '').split(':').some((d) => fs.existsSync(path.join(d, cmd)));
  return found ? null : `${cmd} not on PATH`;
}

function runImpl(name, req, timeoutMs) {
  const [cmd, args] = implCommands()[name](req.op);
  return new Promise((resolve) => {
    const t0 = Date.now();
    const p = spawn(cmd, args, { stdio: ['pipe', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    let killed = false;
    const timer = setTimeout(() => { killed = true; p.kill('SIGKILL'); }, timeoutMs);
    p.stdout.on('data', (d) => { out += d; });
    p.stderr.on('data', (d) => { err += d; });
    p.on('error', (e) => { err += String(e); });
    p.on('close', (code) => {
      clearTimeout(timer);
      resolve({ impl: name, lines: parseLines(out, code, err, killed), stderr: err.slice(0, 2000),
        code, ms: Date.now() - t0 });
    });
    p.stdin.on('error', () => {});
    p.stdin.end(JSON.stringify(req));
  });
}

function parseLines(out, code, stderr, killed) {
  const lines = [];
  for (const l of out.split('\n')) {
    if (!l.trim()) continue;
    let o;
    try { o = JSON.parse(l); } catch { lines.push({ error: 'badOutput', message: l.slice(0, 300) }); continue; }
    if (o && typeof o.error === 'string') { lines.push(o); continue; }
    if (o && typeof o.oid === 'string' && typeof o.type === 'string' && typeof o.value === 'string') {
      lines.push({ oid: o.oid.replace(/^\./, ''), type: o.type, value: o.value });
    } else {
      lines.push({ error: 'badOutput', message: l.slice(0, 300) });
    }
  }
  if (killed) lines.push({ error: 'crash', message: 'killed: harness timeout' });
  else if (code !== 0 && !lines.some((x) => x.error)) {
    lines.push({ error: 'crash', message: `exit ${code}: ${stderr.trim().slice(0, 300)}` });
  }
  return lines;
}

// ---------- OIDs ----------

const arcs = (s) => s.split('.').filter(Boolean).map(Number);
function cmpOid(a, b) {
  const x = arcs(a); const y = arcs(b);
  for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i] - y[i];
  return x.length - y.length;
}
const under = (oid, prefix) => oid === prefix || oid.startsWith(prefix + '.');

// ---------- diff ----------

function splitOut(lines) {
  return { vbs: lines.filter((l) => !l.error), errs: lines.filter((l) => l.error) };
}

const isVolatile = (oid, vol) => vol.some((p) => under(oid, p));

// Compare `other` against `base`; returns list of {kind, oid?, base?, other?}.
function diffOutputs(op, base, other, volatile) {
  const d = [];
  const B = splitOut(base);
  const O = splitOut(other);
  const eb = B.errs[B.errs.length - 1];
  const eo = O.errs[O.errs.length - 1];
  const errKey = (e) => e && [e.error, e.status !== undefined ? e.status : null];
  if (eb || eo) {
    const sameClass = eb && eo && eb.error === eo.error;
    const statusConflict = sameClass && eb.status !== undefined && eo.status !== undefined && eb.status !== eo.status;
    const indexConflict = sameClass && eb.index !== undefined && eo.index !== undefined && eb.index !== eo.index;
    if (!sameClass || statusConflict || indexConflict) {
      d.push({ kind: 'error', base: eb ? pickErr(eb) : null, other: eo ? pickErr(eo) : null });
    }
    void errKey;
  }
  const cmpVb = (b, o) => {
    if (b.oid !== o.oid) { d.push({ kind: 'oid', oid: b.oid, base: b, other: o }); return; }
    if (b.type !== o.type) d.push({ kind: 'type', oid: b.oid, base: b, other: o });
    else if (b.value !== o.value && !isVolatile(b.oid, volatile)) d.push({ kind: 'value', oid: b.oid, base: b, other: o });
  };
  if (op === 'get' || op === 'set') {
    const n = Math.max(B.vbs.length, O.vbs.length);
    for (let i = 0; i < n; i++) {
      const b = B.vbs[i]; const o = O.vbs[i];
      if (!o) d.push({ kind: 'missing', oid: b.oid, base: b });
      else if (!b) d.push({ kind: 'extra', oid: o.oid, other: o });
      else cmpVb(b, o);
    }
    return d;
  }
  // walks: merge by OID (both should be strictly increasing)
  let i = 0; let j = 0;
  while (i < B.vbs.length || j < O.vbs.length) {
    const b = B.vbs[i]; const o = O.vbs[j];
    const c = !b ? 1 : !o ? -1 : cmpOid(b.oid, o.oid);
    if (c === 0) { cmpVb(b, o); i++; j++; } else if (c < 0) {
      if (!isVolatile(b.oid, volatile)) d.push({ kind: 'missing', oid: b.oid, base: b });
      i++;
    } else {
      if (!isVolatile(o.oid, volatile)) d.push({ kind: 'extra', oid: o.oid, other: o });
      j++;
    }
  }
  return d;
}

const pickErr = (e) => {
  const r = { error: e.error };
  if (e.status !== undefined) r.status = e.status;
  if (e.index !== undefined) r.index = e.index;
  if (e.message) r.message = String(e.message).slice(0, 200);
  return r;
};

// ---------- allowlist ----------

function loadAllowlist(file) {
  if (!fs.existsSync(file)) return [];
  const j = JSON.parse(fs.readFileSync(file, 'utf8'));
  return (j.entries || j).map((e) => ({ ...e, hits: 0 }));
}

const reMatch = (pat, s) => pat === undefined || pat === '*' || new RegExp(`^(?:${pat})$`).test(s || '');

function allowed(entry, ctx, diff) {
  if (!reMatch(entry.impl, ctx.impl)) return false;
  if (!reMatch(entry.target, ctx.target)) return false;
  if (!reMatch(entry.case, ctx.case)) return false;
  if (!reMatch(entry.cred, ctx.cred)) return false;
  if (!reMatch(entry.op, ctx.op)) return false;
  if (!reMatch(entry.kind, diff.kind)) return false;
  if (entry.oid && !(diff.oid && under(diff.oid, entry.oid))) return false;
  if (entry.baseType && !(diff.base && diff.base.type === entry.baseType)) return false;
  if (entry.otherType && !(diff.other && diff.other.type === entry.otherType)) return false;
  if (entry.baseError && !(diff.base && diff.base.error === entry.baseError)) return false;
  if (entry.otherError && !(diff.other && diff.other.error === entry.otherError)) return false;
  return true;
}

// ---------- sims (ground truth) ----------

function httpJson(url, timeoutMs = 3000) {
  return new Promise((resolve, reject) => {
    const req = http.get(url, { timeout: timeoutMs }, (res) => {
      let b = '';
      res.on('data', (d) => { b += d; });
      res.on('end', () => {
        if (res.statusCode !== 200) return reject(new Error(`${url}: HTTP ${res.statusCode}`));
        try { resolve(JSON.parse(b)); } catch (e) { reject(e); }
      });
    });
    req.on('timeout', () => req.destroy(new Error(`${url}: timeout`)));
    req.on('error', reject);
  });
}

function httpPost(url, body, timeoutMs = 3000) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = http.request(url, { method: 'POST', timeout: timeoutMs,
      headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(data) } }, (res) => {
      let b = '';
      res.on('data', (d) => { b += d; });
      res.on('end', () => (res.statusCode === 200 ? resolve(b) : reject(new Error(`${url}: HTTP ${res.statusCode} ${b}`))));
    });
    req.on('timeout', () => req.destroy(new Error(`${url}: timeout`)));
    req.on('error', reject);
    req.end(data);
  });
}

// ---------- matrix expansion ----------

function resolvePlaceholder(v, vars) {
  if (typeof v === 'string' && v.startsWith('$')) return vars[v.slice(1)];
  if (Array.isArray(v)) {
    const r = [];
    for (const x of v) {
      const y = resolvePlaceholder(x, vars);
      if (y === undefined) return undefined;
      if (typeof x === 'string' && x.startsWith('$') && Array.isArray(y)) r.push(...y); else r.push(y);
    }
    return r;
  }
  return v;
}

function credList(spec, matrix) {
  if (Array.isArray(spec)) return spec.flatMap((s) => credList(s, matrix));
  if (matrix.credentialGroups && matrix.credentialGroups[spec]) return credList(matrix.credentialGroups[spec], matrix);
  return [spec];
}

// Expand a case for a target into concrete {id, op, oids|root|varbinds, maxRepetitions}.
function expandCase(c, vars) {
  const out = [];
  if (c.op === 'walk' || c.op === 'bulkwalk') {
    let roots = resolvePlaceholder(c.root, vars);
    if (roots === undefined || (Array.isArray(roots) && !roots.length)) return out;
    roots = Array.isArray(roots) ? roots : [roots];
    const reps = c.maxRepetitions === undefined ? [undefined] : [].concat(c.maxRepetitions);
    for (const r of roots) {
      for (const m of reps) {
        let id = c.id;
        if (roots.length > 1) id += `[${r}]`;
        if (reps.length > 1 || (m !== undefined && c.op === 'bulkwalk')) id += `/r${m}`;
        out.push({ id, op: c.op, root: r, maxRepetitions: m });
      }
    }
  } else if (c.op === 'get') {
    const oids = resolvePlaceholder(c.oids, vars);
    if (oids && oids.length) out.push({ id: c.id, op: 'get', oids });
  } else if (c.op === 'set') {
    const vbs = resolvePlaceholder(c.varbinds, vars);
    if (vbs && vbs.length) {
      if (c.each) vbs.forEach((vb) => out.push({ id: `${c.id}[${vb.oid}]`, op: 'set', varbinds: [vb] }));
      else out.push({ id: c.id, op: 'set', varbinds: vbs });
    }
  }
  return out;
}

const TYPE_ORDER = ['Integer', 'OctetString', 'OID', 'IpAddress', 'Counter32', 'Gauge32', 'TimeTicks', 'Opaque', 'Counter64'];

// Derive per-target vars from the sim's /info and /truth.
async function simVars(t) {
  const base = t.http || `http://${t.host}:8000`;
  const info = await httpJson(`${base}/info`);
  const truth = await httpJson(`${base}/truth`);
  const raw = truth.raw || {};
  const oids = Object.keys(raw).sort(cmpOid);
  const v = { info };
  if (info.sysObjectID) v.enterprise = info.sysObjectID.split('.').slice(0, 7).join('.');
  // roots: distinct enterprise (7 arcs) / mib-2 group (8 arcs) prefixes of the truth OIDs
  const roots = new Set();
  for (const o of oids) {
    const a = o.split('.');
    if (under(o, '1.3.6.1.4.1')) roots.add(a.slice(0, 7).join('.'));
    else if (under(o, '1.3.6.1.2.1') && a[5] !== '1') roots.add(a.slice(0, 8).join('.'));
    else if (under(o, '1.3.6.1.2.1')) continue;
    else roots.add(a.slice(0, Math.min(a.length - 1, 7)).join('.'));
  }
  v.roots = [...roots].filter((r) => r !== v.enterprise).sort(cmpOid);
  // one OID per type, plus a nonexistent one in the middle
  const seen = new Map();
  for (const o of oids) if (!seen.has(raw[o].type)) seen.set(raw[o].type, o);
  v.mixed = TYPE_ORDER.filter((ty) => seen.has(ty)).map((ty) => seen.get(ty));
  if (v.mixed.length) v.mixedWithMissing = [v.mixed[0], `${v.enterprise || '1.3.6.1.4.1.99999'}.424242.0`, ...v.mixed.slice(1)];
  v.writable = (info.writable || []).filter((o) => raw[o]).map((o) => ({ oid: o, type: raw[o].type, value: raw[o].value }));
  v.wrongtype = v.writable.slice(0, 1).map((w) => (w.type === 'Integer'
    ? { oid: w.oid, type: 'OctetString', value: '7a7a' } : { oid: w.oid, type: 'Integer', value: '1' }));
  v.users = info.users;
  v.stepMs = info.stepMs || 10000;
  return v;
}

// ---------- main ----------

async function main() {
  const args = parseArgs(process.argv);
  const matrix = JSON.parse(fs.readFileSync(args.matrix, 'utf8'));
  const allow = loadAllowlist(args.allowlist);
  const baseline = args.baseline || matrix.baseline || 'netsnmp';
  let impls = args.impls || matrix.impls || ['netsnmp', 'gosnmp', 'pysnmp', 'ours'];
  if (!impls.includes(baseline)) impls = [baseline, ...impls];
  const skippedImpls = {};
  impls = impls.filter((i) => {
    const why = implAvailable(i);
    if (why) skippedImpls[i] = why;
    return !why;
  });
  if (!impls.includes(baseline)) throw new Error(`baseline ${baseline} unavailable: ${skippedImpls[baseline]}`);
  // baseline first, the rest back-to-back after it
  impls = [baseline, ...impls.filter((i) => i !== baseline)];
  const globalVolatile = matrix.volatile || [];
  const defaults = matrix.defaults || {};
  const implTimeout = matrix.implTimeoutMs || 300000;

  // Resolve targets
  const targets = [];
  const skippedTargets = {};
  for (const t of matrix.targets) {
    if (args.targets && !args.targets.test(t.name)) continue;
    try { await dns.lookup(t.host); } catch { skippedTargets[t.name] = `host ${t.host} does not resolve`; continue; }
    let vars = { ...(t.vars || {}) };
    if (t.kind === 'sim') {
      try {
        vars = { ...(await simVars(t)), ...vars };
      } catch (e) { skippedTargets[t.name] = `sim API: ${e.message}`; continue; }
    }
    targets.push({ ...t, vars });
  }

  // Plan
  const plan = [];
  for (const t of targets) {
    const tCases = matrix.cases.filter((c) => (!c.kinds || c.kinds.includes(t.kind || 'agent'))
      && (!t.cases || t.cases.some((p) => new RegExp(`^(?:${p})$`).test(c.id)))
      && !(t.skipCases || []).some((p) => new RegExp(`^(?:${p})$`).test(c.id)));
    for (const c of tCases) {
      for (const credName of credList(c.creds || 'core', matrix)) {
        const cred = matrix.credentials[credName];
        if (!cred) throw new Error(`unknown credential ${credName}`);
        if (args.creds && !args.creds.test(credName)) continue;
        if (t.versions && !t.versions.includes(cred.version)) continue;
        if (cred.version === '3' && cred.requireUser !== false && t.vars.users
          && !t.vars.users.some((u) => (u.user || u.name || u) === cred.user)) continue;
        if (c.op === 'bulkwalk' && cred.version === '1') continue;
        for (const ec of expandCase(c, t.vars)) {
          if (args.cases && !args.cases.test(ec.id)) continue;
          const { requireUser, ...credTarget } = cred;
          void requireUser;
          const target = { ...defaults, ...credTarget, host: t.host, port: t.port || 161 };
          const req = { target, op: ec.op };
          if (ec.oids) req.oids = ec.oids;
          if (ec.root) req.root = ec.root;
          if (ec.maxRepetitions !== undefined) req.maxRepetitions = ec.maxRepetitions;
          if (ec.varbinds) req.varbinds = ec.varbinds;
          plan.push({ target: t, cred: credName, caseId: ec.id, op: ec.op, req, isSet: ec.op === 'set' });
        }
      }
    }
  }
  if (args.list) {
    for (const p of plan) console.log(`${p.target.name}\t${p.cred}\t${p.caseId}\t${JSON.stringify(p.req)}`);
    console.log(`${plan.length} cases; impls: ${impls.join(',')}; skipped impls: ${JSON.stringify(skippedImpls)}; skipped targets: ${JSON.stringify(skippedTargets)}`);
    return 0;
  }

  const t0 = Date.now();
  const results = [];
  const truthCache = new Map();

  async function truthAt(t, ms) {
    const step = Math.floor(ms / t.vars.stepMs);
    const key = `${t.name}@${step}`;
    if (!truthCache.has(key)) {
      const base = t.http || `http://${t.host}:8000`;
      truthCache.set(key, httpJson(`${base}/truth?at=${step * t.vars.stepMs}`).catch(() => null));
    }
    return truthCache.get(key);
  }

  async function runCase(p) {
    const t = p.target;
    const volatile = [...globalVolatile, ...(t.volatile || [])];
    const ctxBase = { target: t.name, cred: p.cred, case: p.caseId, op: p.op };
    let attempt = 0;
    let rec;
    const history = [];
    while (attempt < args.attempts) {
      attempt++;
      const start = Date.now();
      const outs = {};
      for (const i of impls) outs[i] = await runImpl(i, p.req, implTimeout); // back-to-back
      const end = Date.now();
      const stepMs = t.vars.stepMs;
      const sameStep = !stepMs || Math.floor(start / stepMs) === Math.floor(end / stepMs);
      const comparisons = {};
      let unallowed = 0;
      for (const i of impls) {
        if (i === baseline) continue;
        const diffs = diffOutputs(p.op, outs[baseline].lines, outs[i].lines, volatile);
        const ctx = { ...ctxBase, impl: i };
        const marked = diffs.map((d) => {
          const e = allow.find((a) => allowed(a, ctx, d));
          return e ? { ...d, allowed: e.id } : d;
        });
        const bad = marked.filter((d) => !d.allowed).length;
        unallowed += bad;
        comparisons[i] = { status: !diffs.length ? 'same' : bad ? 'diff' : 'allowed', diffs: marked };
      }
      // ground truth for sims (only meaningful within one step)
      let truth = null;
      if (t.kind === 'sim' && p.op !== 'set' && sameStep) {
        const tr = await truthAt(t, start);
        if (tr && tr.raw) {
          truth = {};
          for (const i of impls) {
            const mism = [];
            for (const vb of splitOut(outs[i].lines).vbs) {
              const exp = tr.raw[vb.oid];
              if (!exp || isVolatile(vb.oid, volatile)) continue;
              if (exp.type !== vb.type || exp.value !== vb.value) mism.push({ oid: vb.oid, got: { type: vb.type, value: vb.value }, truth: exp });
            }
            if (mism.length) truth[i] = mism;
          }
        }
      }
      rec = { ...ctxBase, request: p.req, attempt, sameStep, ms: end - start,
        outputs: Object.fromEntries(impls.map((i) => [i, { lines: outs[i].lines, ms: outs[i].ms, stderr: outs[i].stderr || undefined }])),
        comparisons, truth };
      history.push(unallowed);
      if (!unallowed) break;
      if (!args.attempts) break;
    }
    rec.flaky = history.length > 1 && history[history.length - 1] === 0;
    rec.attempts = history;
    if (args.verbose) {
      const s = Object.entries(rec.comparisons).map(([i, c]) => `${i}:${c.status}`).join(' ');
      console.error(`[${t.name}] ${p.cred} ${p.caseId}: ${s}${rec.flaky ? ' (flaky)' : ''}`);
    }
    return rec;
  }

  // Hosts in parallel; within a host, target variants (fault presets) one after another,
  // within a target sequential, reads first then sets.
  const byHost = new Map();
  for (const p of plan) {
    if (!byHost.has(p.target.host)) byHost.set(p.target.host, new Map());
    const m = byHost.get(p.target.host);
    if (!m.has(p.target.name)) m.set(p.target.name, []);
    m.get(p.target.name).push(p);
  }
  await Promise.all([...byHost.values()].map(async (variants) => {
    for (const ps of variants.values()) {
      const t = ps[0].target;
      const base = t.http || `http://${t.host}:8000`;
      if (t.faults) {
        try {
          await httpPost(`${base}/set-fault`, { kind: 'clear' });
          for (const f of t.faults) await httpPost(`${base}/set-fault`, f);
        } catch (e) {
          skippedTargets[t.name] = `set-fault: ${e.message}`;
          continue;
        }
      }
      try {
        const ordered = [...ps.filter((p) => !p.isSet), ...ps.filter((p) => p.isSet)];
        for (const p of ordered) results.push(await runCase(p));
      } finally {
        if (t.faults) await httpPost(`${base}/set-fault`, { kind: 'clear' }).catch(() => {});
      }
    }
  }));

  // allowlist hit counts
  for (const r of results) {
    for (const c of Object.values(r.comparisons)) {
      for (const d of c.diffs) if (d.allowed) { const e = allow.find((a) => a.id === d.allowed); if (e) e.hits++; }
    }
  }

  // Summary
  const summary = {};
  for (const r of results) {
    for (const [i, c] of Object.entries(r.comparisons)) {
      const k = `${r.target}|${i}`;
      summary[k] = summary[k] || { target: r.target, impl: i, cases: 0, same: 0, allowed: 0, diff: 0, flaky: 0 };
      summary[k].cases++;
      summary[k][c.status]++;
      if (r.flaky) summary[k].flaky++;
    }
  }
  const truthSummary = {};
  for (const r of results) {
    if (!r.truth) continue;
    for (const [i, m] of Object.entries(r.truth)) {
      const k = `${r.target}|${i}`;
      truthSummary[k] = (truthSummary[k] || 0) + m.length;
    }
  }
  const failures = results.filter((r) => Object.values(r.comparisons).some((c) => c.status === 'diff'));
  const report = {
    generatedAt: new Date().toISOString(), durationMs: Date.now() - t0, baseline, impls,
    skippedImpls, skippedTargets, cases: results.length,
    summary: Object.values(summary), truthMismatches: truthSummary,
    allowlist: allow.map(({ id, hits, reason }) => ({ id, hits, reason })),
    failures: failures.length, results,
  };
  fs.mkdirSync(path.dirname(args.out), { recursive: true });
  fs.writeFileSync(args.out, JSON.stringify(report, null, 1));

  // Console report
  const pad = (s, n) => String(s).padEnd(n);
  console.log(`difftest: ${results.length} cases, baseline ${baseline}, impls ${impls.join(',')} (${((Date.now() - t0) / 1000).toFixed(1)}s)`);
  for (const [i, why] of Object.entries(skippedImpls)) console.log(`  skipped impl ${i}: ${why}`);
  for (const [n, why] of Object.entries(skippedTargets)) console.log(`  skipped target ${n}: ${why}`);
  console.log(`  ${pad('target', 32)}${pad('impl', 9)}${pad('cases', 7)}${pad('same', 6)}${pad('allowed', 9)}${pad('DIFF', 6)}flaky`);
  for (const s of Object.values(summary)) {
    console.log(`  ${pad(s.target, 32)}${pad(s.impl, 9)}${pad(s.cases, 7)}${pad(s.same, 6)}${pad(s.allowed, 9)}${pad(s.diff, 6)}${s.flaky}`);
  }
  for (const [k, n] of Object.entries(truthSummary)) console.log(`  truth mismatches ${k}: ${n} varbinds`);
  for (const r of failures) {
    for (const [i, c] of Object.entries(r.comparisons)) {
      if (c.status !== 'diff') continue;
      const bad = c.diffs.filter((d) => !d.allowed);
      console.log(`DIFF ${r.target} ${r.cred} ${r.case} ${i} vs ${baseline}: ${bad.length} diffs`);
      for (const d of bad.slice(0, 4)) console.log(`    ${fmtDiff(d)}`);
      if (bad.length > 4) console.log(`    ... ${bad.length - 4} more`);
    }
  }
  const unused = allow.filter((a) => !a.hits);
  if (unused.length && args.verbose) console.log(`  allowlist entries not hit: ${unused.map((a) => a.id).join(', ')}`);
  console.log(`report: ${path.relative(process.cwd(), args.out)}; ${failures.length} failing cases`);
  return failures.length && args.fail ? 1 : 0;
}

function fmtDiff(d) {
  const f = (x) => (!x ? '-' : x.error ? `error:${x.error}${x.status ? `/${x.status}` : ''}${x.index ? `@${x.index}` : ''}`
    : `${x.type}=${x.value.length > 40 ? `${x.value.slice(0, 40)}...` : x.value}`);
  return `${d.kind} ${d.oid || ''} base=${f(d.base)} other=${f(d.other)}`;
}

if (require.main === module) {
  main().then((code) => process.exit(code), (e) => { console.error(e.stack || e); process.exit(2); });
}

module.exports = { diffOutputs, allowed, expandCase, parseLines, cmpOid };
