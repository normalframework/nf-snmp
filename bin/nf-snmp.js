#!/usr/bin/env node
'use strict';
/**
 * nf-snmp CLI.
 *
 *   nf-snmp <get|walk|bulkwalk|set> --json      read a request JSON on stdin (docs/internals.md §1/§3),
 *                                               write normalized varbind JSON lines to stdout
 *   nf-snmp identify --json                     stdin {target} -> identification + matched profile
 *   nf-snmp profile-read --json                 stdin {target, profile?} -> decoded points
 *   nf-snmp validate-profiles                   load and check every built-in profile
 */
const { SnmpClient, classify, errorLine } = require('../lib/snmp/client');

function readStdin() {
  return new Promise((resolve, reject) => {
    const chunks = [];
    process.stdin.on('data', (c) => chunks.push(c));
    process.stdin.on('end', () => {
      const txt = Buffer.concat(chunks).toString('utf8').trim();
      try {
        resolve(txt ? JSON.parse(txt) : {});
      } catch (e) {
        reject(e);
      }
    });
    process.stdin.on('error', reject);
  });
}

process.stdout.on('error', (e) => {
  if (e.code === 'EPIPE') process.exit(0); // e.g. piped into head
  throw e;
});

function emit(obj) {
  process.stdout.write(JSON.stringify(obj) + '\n');
}

function emitError(e) {
  emit(errorLine(classify(e)));
}

async function runOp(op, req) {
  const client = new SnmpClient(req.target || {});
  try {
    switch (op) {
      case 'get': {
        try {
          for (const vb of await client.get(req.oids || [])) emit(vb);
        } catch (e) {
          emitError(e);
        }
        break;
      }
      case 'walk':
      case 'bulkwalk': {
        const res = await client.walk(req.root, { bulk: op === 'bulkwalk', maxRepetitions: req.maxRepetitions });
        for (const vb of res.varbinds) emit(vb);
        if (res.error) emit(res.error);
        break;
      }
      case 'set': {
        try {
          for (const vb of await client.set(req.varbinds || [])) emit(vb);
        } catch (e) {
          emitError(e);
        }
        break;
      }
      default:
        throw new Error(`unknown op ${op}`);
    }
  } finally {
    client.close();
  }
}

async function main() {
  const [cmd] = process.argv.slice(2);
  if (['get', 'walk', 'bulkwalk', 'set'].includes(cmd)) {
    const req = await readStdin();
    await runOp(cmd, req);
    return;
  }
  if (cmd === 'identify' || cmd === 'profile-read') {
    const req = await readStdin();
    const { identify, readProfile } = require('../lib/profiles/device');
    const lib = require('../lib/profiles').loadLibrary();
    const client = new SnmpClient(req.target || {});
    try {
      if (cmd === 'identify') emit(await identify(client, lib));
      else {
        const id = req.profile ? { profile: lib.get(req.profile) } : await identify(client, lib);
        if (!id.profile) throw new Error('no profile matched');
        const res = await readProfile(client, lib.resolve(id.profile.id || id.profile));
        emit(res);
      }
    } finally {
      client.close();
    }
    return;
  }
  if (cmd === 'validate-profiles') {
    const lib = require('../lib/profiles').loadLibrary({ strict: true });
    emit({ ok: true, profiles: lib.ids() });
    return;
  }
  process.stderr.write('usage: nf-snmp <get|walk|bulkwalk|set|identify|profile-read|validate-profiles> [--json]\n');
  process.exitCode = 2;
}

main().catch((e) => {
  process.stderr.write(`nf-snmp: ${e && e.stack ? e.stack : e}\n`);
  process.exitCode = 1;
});
