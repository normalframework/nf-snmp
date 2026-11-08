'use strict';
/**
 * On-request admin hook: the UI's only way into the engine. The UI calls StartHook with
 * {action, json: JSON.stringify(args)}; we proxy to http://127.0.0.1:<adminPort>/admin/<route>
 * and return {result: "success", message: JSON.stringify(reply)} (or result "error").
 *
 * Actions -> engine routes:
 *   status devices profiles traps            GET  /admin/<action>
 *   profile {id}                             GET  /admin/profile?id=
 *   discover-get {jobId}                     GET  /admin/discover?jobId=
 *   put-device {device} delete-device {uuid} sync-device {uuid} identify {target} preview {...}
 *   walk {...} discover {...} discover-cancel {jobId} discover-add {jobId, hosts?}   POST
 */
const http = require('http');

const ROUTES = {
  status: ['GET', '/admin/status'],
  devices: ['GET', '/admin/devices'],
  profiles: ['GET', '/admin/profiles'],
  traps: ['GET', '/admin/traps'],
  profile: ['GET', '/admin/profile', ['id']],
  'discover-get': ['GET', '/admin/discover', ['jobId']],
  'put-device': ['POST', '/admin/devices'],
  'delete-device': ['POST', '/admin/devices/delete'],
  'sync-device': ['POST', '/admin/devices/sync'],
  identify: ['POST', '/admin/identify'],
  'put-profile': ['POST', '/admin/profiles'],
  'delete-profile': ['POST', '/admin/profiles/delete'],
  preview: ['POST', '/admin/preview'],
  walk: ['POST', '/admin/walk'],
  discover: ['POST', '/admin/discover'],
  'discover-cancel': ['POST', '/admin/discover/cancel'],
  'discover-add': ['POST', '/admin/discover/add'],
};

function parseArgs(raw) {
  if (raw && typeof raw.json === 'string' && raw.json) {
    try {
      const o = JSON.parse(raw.json);
      if (o && typeof o === 'object') return Object.assign({}, o, { action: raw.action || o.action });
    } catch { /* fall through */ }
  }
  const a = {};
  for (const [k, v] of Object.entries(raw || {})) {
    if (k === 'json') continue;
    try { a[k] = /^[[{]/.test(String(v).trim()) ? JSON.parse(v) : v; } catch { a[k] = v; }
  }
  return a;
}

function call(port, method, path, body) {
  return new Promise((resolve, reject) => {
    const data = method === 'POST' ? JSON.stringify(body || {}) : undefined;
    const req = http.request({ host: '127.0.0.1', port, method, path, timeout: 55000, headers: data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {} }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const txt = Buffer.concat(chunks).toString('utf8');
        let json;
        try { json = JSON.parse(txt); } catch { json = { error: txt }; }
        if (res.statusCode >= 400) reject(Object.assign(new Error(json.error || `HTTP ${res.statusCode}`), { body: json }));
        else resolve(json);
      });
    });
    req.on('timeout', () => req.destroy(new Error('engine did not answer in time')));
    req.on('error', (e) => reject(e.code === 'ECONNREFUSED' ? new Error('engine is not running (it starts within a minute of enabling the app)') : e));
    if (data) req.write(data);
    req.end();
  });
}

module.exports = async ({ args, config }) => {
  const a = parseArgs(args || {});
  const port = Number((config || {}).adminPort) || 47081;
  const r = ROUTES[a.action];
  if (!r) return { result: 'error', message: JSON.stringify({ error: `unknown action ${a.action}` }) };
  try {
    const [method, path, query] = r;
    let p = path;
    if (query) p += '?' + query.filter((k) => a[k] !== undefined).map((k) => `${k}=${encodeURIComponent(a[k])}`).join('&');
    const { action, ...body } = a;
    void action;
    return { result: 'success', message: JSON.stringify(await call(port, method, p, body)) };
  } catch (e) {
    return { result: 'error', message: JSON.stringify({ error: e.message }) };
  }
};
module.exports._call = call;
