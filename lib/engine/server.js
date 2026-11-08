'use strict';
/**
 * Localhost HTTP server inside the engine process.
 *
 *   POST /driver/read    hplv1.ReadRequest (protojson)  -> hplv1.ReadReply
 *   POST /driver/write   hplv1.WriteRequest             -> hplv1.WriteReply
 *   POST /driver/status  GetDriverStatusRequest         -> GetDriverStatusReply
 *
 * NF (gobac src/common/driver.go HttpDriver) ignores HTTP status and parses the body as the reply
 * proto, so driver endpoints always answer 200 with a well-formed reply.
 *
 *   GET  /admin/health | /admin/status | /admin/devices | /admin/profiles | /admin/traps
 *   POST /admin/devices            {device}              add/update (+sync)
 *   POST /admin/devices/delete     {uuid, deletePoints?}
 *   POST /admin/devices/sync       {uuid}
 *   POST /admin/identify           {target}
 *   POST /admin/preview            {uuid}|{target, profile?}
 *   POST /admin/walk               {uuid}|{target}, root, bulk?, maxVarbinds?
 *   POST /admin/discover           {hosts, credentials, port?, timeoutMs?, concurrency?}  -> {jobId}
 *   GET  /admin/discover?jobId=    job status/results;  POST /admin/discover/cancel {jobId}
 *   POST /admin/discover/add       {jobId, hosts?: [...], periodSeconds?}  add found devices
 *
 * Binds 127.0.0.1 only; same trust level as the NF services that call it.
 */
const http = require('http');
const { URL } = require('url');

const MAX_BODY = 16 * 1024 * 1024;

function createServer({ engine, port = 47081, host = '127.0.0.1', log }) {
  const counters = { driverReads: 0, driverWrites: 0, status: 0, admin: 0, badRequests: 0 };
  const server = http.createServer((req, res) => {
    handle(req, res).catch((e) => {
      log.error('server error', { error: e.message, url: req.url });
      if (String(req.url || '').startsWith('/driver/')) send(res, 200, {});
      else send(res, e.code === 'E_CONFIG' || e.code === 'E_OID' ? 400 : e.code === 'E_NOT_FOUND' ? 404 : 500, { error: e.message, code: e.code, class: e.class });
    });
  });
  server.keepAliveTimeout = 65000;
  server.requestTimeout = 0;

  async function handle(req, res) {
    const url = new URL(req.url || '/', 'http://localhost');
    const p = url.pathname.replace(/\/+$/, '') || '/';
    const body = req.method === 'POST' ? await readJson(req, res) : {};
    if (body === undefined) return;
    switch (`${req.method} ${p}`) {
      case 'POST /driver/read':
        counters.driverReads++;
        return send(res, 200, await engine.read(body));
      case 'POST /driver/write':
        counters.driverWrites++;
        return send(res, 200, await engine.write(body));
      case 'POST /driver/status':
        counters.status++;
        return send(res, 200, engine.driverStatus());
    }
    if (!p.startsWith('/admin/')) return send(res, 404, { error: `not found: ${req.method} ${p}` });
    counters.admin++;
    const q = (k) => body[k] ?? url.searchParams.get(k);
    switch (`${req.method} ${p}`) {
      case 'GET /admin/health':
        return send(res, 200, engine.health());
      case 'GET /admin/status':
        return send(res, 200, Object.assign(engine.health(), { counters: engine.counters, server: counters, devices: engine.listDevices(), traps: engine.traps ? engine.traps.status() : null }));
      case 'GET /admin/devices':
        return send(res, 200, { devices: engine.listDevices() });
      case 'POST /admin/devices':
        return send(res, 200, { device: await engine.putDevice(body.device || body, { sync: body.sync !== false }) });
      case 'POST /admin/devices/delete':
        return send(res, 200, await engine.deleteDevice(q('uuid'), { deletePoints: body.deletePoints !== false }));
      case 'POST /admin/devices/sync': {
        const m = await engine.sync(q('uuid'));
        return send(res, 200, { profile: m.profile, points: m.specs.length, warnings: m.warnings, identity: m.identity });
      }
      case 'GET /admin/profiles':
        return send(res, 200, { profiles: engine.profiles() });
      case 'GET /admin/profile':
        return send(res, 200, { profile: engine.library.resolve(q('id')) });
      case 'POST /admin/profiles':
        return send(res, 200, engine.putProfile(body.profile || body));
      case 'POST /admin/profiles/delete':
        return send(res, 200, engine.deleteProfile(q('id')));
      case 'POST /admin/identify':
        return send(res, 200, await engine.identifyTarget(body.target));
      case 'POST /admin/preview':
        return send(res, 200, await engine.preview(body));
      case 'POST /admin/walk':
        return send(res, 200, await engine.walkTarget(body));
      case 'POST /admin/discover':
        return send(res, 200, engine.discovery.start(body));
      case 'GET /admin/discover':
        return send(res, 200, q('jobId') ? engine.discovery.get(q('jobId')) : { jobs: engine.discovery.list() });
      case 'POST /admin/discover/cancel':
        return send(res, 200, engine.discovery.cancel(q('jobId')));
      case 'POST /admin/discover/add':
        return send(res, 200, await engine.discovery.addFound(q('jobId'), body));
      case 'GET /admin/traps':
        return send(res, 200, { traps: engine.traps ? engine.traps.recent(Number(q('limit')) || 100) : [], status: engine.traps ? engine.traps.status() : null });
      default:
        return send(res, 404, { error: `unknown admin endpoint ${req.method} ${p}` });
    }
  }

  function readJson(req, res) {
    return new Promise((resolve) => {
      const chunks = [];
      let size = 0;
      req.on('data', (c) => {
        size += c.length;
        if (size > MAX_BODY) {
          counters.badRequests++;
          send(res, 413, { error: 'request too large' });
          req.destroy();
          resolve(undefined);
          return;
        }
        chunks.push(c);
      });
      req.on('end', () => {
        const txt = Buffer.concat(chunks).toString('utf8').trim();
        if (!txt) return resolve({});
        try {
          resolve(JSON.parse(txt));
        } catch (e) {
          counters.badRequests++;
          send(res, 400, { error: `invalid JSON: ${e.message}` });
          resolve(undefined);
        }
      });
      req.on('error', () => resolve(undefined));
    });
  }

  const api = {
    server,
    counters,
    port: null,
    start() {
      return new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, host, () => {
          server.removeListener('error', reject);
          api.port = server.address().port;
          log.info('driver/admin server listening', { host, port: api.port });
          resolve(api.port);
        });
      });
    },
    stop() {
      return new Promise((resolve) => {
        if (!server.listening) return resolve();
        server.close(() => resolve());
        if (server.closeAllConnections) server.closeAllConnections();
      });
    },
  };
  return api;
}

function send(res, code, body) {
  if (res.headersSent) return;
  const txt = JSON.stringify(body === undefined ? {} : body);
  res.writeHead(code, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(txt) });
  res.end(txt);
}

module.exports = { createServer };
