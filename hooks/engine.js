'use strict';
/**
 * Scheduled every minute (hooks-update/engine.json). The first invocation starts a module-level
 * Engine singleton in the background and returns at once; later invocations act as a watchdog and
 * restart a dead engine, or restart it when a config option changed. The hook runtime process (and
 * this module's state) survives scheduled re-invocations, so the engine keeps running between them.
 * Never awaits anything slow: invokeTimeout is 1 minute.
 */
const path = require('path');

const APP_ROOT = path.resolve(__dirname, '..');
const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };
const state = { engine: null, starting: null, stopping: null, lastError: null, restarts: 0, configKey: null };
let handlersInstalled = false;

function makeLog(level) {
  const min = LEVELS[level] || LEVELS.info;
  const out = (lvl) => (msg, fields) => {
    if (LEVELS[lvl] < min) return;
    let f = '';
    if (fields && Object.keys(fields).length) {
      try { f = ' ' + JSON.stringify(fields); } catch { f = ''; }
    }
    // eslint-disable-next-line no-console
    (lvl === 'error' ? console.error : lvl === 'warn' ? console.warn : console.log)(`[nf-snmp] ${lvl.toUpperCase()} ${msg}${f}`);
  };
  return { debug: out('debug'), info: out('info'), warn: out('warn'), error: out('error') };
}

function settings(cfg) {
  return {
    port: Number(cfg.adminPort) || 47081,
    trapPort: cfg.trapPort === undefined || cfg.trapPort === null || cfg.trapPort === '' ? 162 : Number(cfg.trapPort),
    logLevel: cfg.logLevel || 'info',
  };
}

async function startEngine(sdk, cfg) {
  const s = settings(cfg);
  const log = makeLog(s.logLevel);
  if (!handlersInstalled) {
    handlersInstalled = true;
    process.on('unhandledRejection', (e) => log.error('unhandled rejection', { error: e && e.message ? e.message : String(e) }));
  }
  const { Engine } = require('../lib/engine');
  const nf = require('../lib/nf').create({ http: sdk.http, log });
  const engine = new Engine({ nf, log, root: APP_ROOT, port: s.port, trapPort: s.trapPort });
  await engine.start();
  return engine;
}

function summary(extra) {
  const h = state.engine ? state.engine.health() : null;
  return Object.assign({ running: !!(h && h.ok), starting: !!state.starting, port: h ? h.port : null, devices: h ? h.devices : 0, points: h ? h.points : 0, restarts: state.restarts, lastError: state.lastError }, extra || {});
}

const ok = (r) => ({ result: 'success', message: JSON.stringify(r) });

function stopCurrent() {
  const e = state.engine;
  state.engine = null;
  state.stopping = e.stop().catch(() => {}).finally(() => { state.stopping = null; });
}

module.exports = async ({ sdk, config }) => {
  const cfg = config || {};
  const key = JSON.stringify(settings(cfg));
  if (cfg.enabled === false) {
    if (state.engine && !state.stopping) stopCurrent();
    return ok(summary({ disabled: true }));
  }
  if (state.starting || state.stopping) return ok(summary());
  if (state.engine && state.configKey !== key) {
    state.restarts++;
    stopCurrent();
    state.configKey = key;
    return ok(summary({ restarting: 'config changed' }));
  }
  if (!state.engine) {
    state.configKey = key;
    state.starting = startEngine(sdk, cfg)
      .then((e) => { state.engine = e; state.lastError = null; })
      .catch((e) => {
        state.lastError = e && e.message ? e.message : String(e);
        // eslint-disable-next-line no-console
        console.error(`[nf-snmp] ERROR engine start failed: ${state.lastError}`);
      })
      .finally(() => { state.starting = null; });
    return ok(summary({ starting: true }));
  }
  if (!state.engine.health().ok) {
    state.restarts++;
    state.lastError = 'engine unhealthy';
    stopCurrent();
    return ok(summary({ restarting: state.lastError }));
  }
  return ok(summary());
};
module.exports._state = state;
