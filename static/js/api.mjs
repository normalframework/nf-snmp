// NF REST access for the nf-snmp UI. The engine is reached only through the app's "admin" hook:
// StartHook (POST /api/v1/apps/{id}/hooks/{hookId}, args map<string,string>) returns a pid, and the
// result is polled from GET /api/v1/apps/{id}/hooks/{hookId}/results?pid=. The hook returns
// InvokeSuccess(JSON.stringify(reply)) — see hooks/admin.js.

function readParam(name) {
  const q = new URLSearchParams(window.location.search);
  let v = q.get(name);
  if (!v && window.location.hash) v = new URLSearchParams(window.location.hash.slice(1)).get(name);
  return v || null;
}

export const config = {
  origin: window.location.origin,
  token: readParam('token') || readParam('auth_token'),
  applicationId: readParam('applicationId') || (window.location.pathname.match(/\/api\/v1\/apps\/static\/([^/]+)\//) || [])[1] || 'snmp',
};

export class ApiError extends Error {
  constructor(message, extra = {}) {
    super(message);
    Object.assign(this, extra);
  }
}

export async function request(method, path, { body } = {}) {
  const headers = { Accept: 'application/json' };
  if (config.token) headers.Authorization = `Bearer ${config.token}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(config.origin + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { json = null; }
  if (res.status === 401 || res.status === 403) throw new ApiError('Not authorized (session expired? reload the page)', { status: res.status });
  if (!res.ok) throw new ApiError(`${method} ${path}: ${res.status} ${(json && (json.message || json.error)) || text}`, { status: res.status });
  return json ?? {};
}

let hookId = null;
async function adminHookId() {
  if (hookId) return hookId;
  const r = await request('GET', `/api/v1/apps/${encodeURIComponent(config.applicationId)}`);
  const app = (r.applications || [])[0];
  const h = ((app && app.hooks) || []).find((x) => x.name === 'admin');
  if (!h) throw new ApiError('The app has no "admin" hook (is it installed and restarted?)');
  hookId = h.id;
  return hookId;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Call an admin action; resolves to the engine's JSON reply. */
export async function admin(action, args = {}, { timeoutMs = 90000 } = {}) {
  const id = await adminHookId();
  const base = `/api/v1/apps/${encodeURIComponent(config.applicationId)}/hooks/${id}`;
  const start = await request('POST', base, { body: { action, json: JSON.stringify(args) } });
  if (start.error && start.error.message) throw new ApiError(start.error.message);
  const pid = start.pid;
  const deadline = Date.now() + timeoutMs;
  let delay = 150;
  while (Date.now() < deadline) {
    await sleep(delay);
    delay = Math.min(delay * 1.6, 1500);
    const r = await request('GET', `${base}/results?pid=${encodeURIComponent(pid)}&pageSize=5`);
    const done = (r.results || []).find((x) => (!x.pid || String(x.pid) === String(pid)) && /SUCCESS|ERROR|ABORTED|STOPPED|SKIPPED/.test(String(x.state)));
    if (!done) continue;
    let payload = done.returnValue;
    if (!/SUCCESS/.test(String(done.state))) {
      const msg = (done.error && done.error.message) || payload || done.state;
      let parsed = msg;
      try { parsed = JSON.parse(msg).error || msg; } catch { /* text */ }
      throw new ApiError(parsed);
    }
    try { return payload ? JSON.parse(payload) : null; } catch { return payload; }
  }
  throw new ApiError(`${action}: no answer within ${timeoutMs / 1000}s`);
}
