/**
 * Minimal NF REST client for the live end-to-end test (Node 20+ fetch, no dependencies).
 *
 * - `http` is an axios-shaped shim ({get, post, delete} → {data}) so lib/nf can run against a
 *   live site exactly as it does inside the hook.
 * - apps / files / hooks follow the same endpoints as static/js/api.mjs (gobac program.proto).
 */
import { setTimeout as sleep } from 'node:timers/promises';

export class NfError extends Error {
  constructor(message, { status, body } = {}) {
    super(message);
    this.status = status;
    this.body = body;
  }
}

/** True when an error means "file not found" (ReadFile answers 500 "error reading file"). */
export function isNotFound(e) {
  if (!(e instanceof NfError)) return false;
  if (e.status === 404) return true;
  const msg = typeof e.body === 'string' ? e.body : (e.body && (e.body.message || e.body.error)) || '';
  return e.status === 500 && /error reading file|does not exist|no such file|not found/i.test(msg);
}

/**
 * @param {{url: string, token?: string, timeoutMs?: number}} o
 */
export function createNfClient({ url, token, timeoutMs = 30000 }) {
  const base = url.replace(/\/+$/, '');

  async function request(method, path, { body, params, raw, signal } = {}) {
    let qs = '';
    if (params) {
      const sp = new URLSearchParams();
      for (const [k, v] of Object.entries(params)) {
        if (v === undefined || v === null) continue;
        if (Array.isArray(v)) for (const x of v) sp.append(k, String(x));
        else sp.append(k, String(v));
      }
      const s = sp.toString();
      if (s) qs = `?${s}`;
    }
    const headers = { Accept: 'application/json' };
    if (token) headers.Authorization = `Bearer ${token}`;
    let payload;
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      payload = JSON.stringify(body);
    }
    const res = await fetch(`${base}${path}${qs}`, { method, headers, body: payload, signal: signal || AbortSignal.timeout(timeoutMs) });
    const text = await res.text();
    let json = null;
    if (text) {
      try {
        json = JSON.parse(text);
      } catch {
        json = null;
      }
    }
    if (!res.ok) throw new NfError(`${method} ${path}: ${res.status} ${(json && (json.message || json.error)) || text}`.trim(), { status: res.status, body: json ?? text });
    if (raw) return text;
    return json ?? {};
  }

  /** axios-shaped shim for lib/nf (only what the adapter uses). */
  const http = {
    async get(path, opts = {}) {
      return { data: await request('GET', path, { params: opts.params }) };
    },
    async post(path, body, opts = {}) {
      return { data: await request('POST', path, { body, params: opts.params }) };
    },
    async delete(path, opts = {}) {
      return { data: await request('DELETE', path, { params: opts.params }) };
    },
    async patch(path, body) {
      return { data: await request('PATCH', path, { body }) };
    },
    async put(path, body) {
      return { data: await request('PUT', path, { body }) };
    },
  };

  const enc = (p) => String(p).replace(/^\/+/, '').split('/').map(encodeURIComponent).join('/');

  const apps = {
    /** @returns {Promise<any|null>} */
    async get(id) {
      try {
        const r = await request('GET', `/api/v1/apps/${encodeURIComponent(id)}`);
        return (r.applications || []).find((a) => a.id === id) || null;
      } catch (e) {
        if (e instanceof NfError && (e.status === 404 || e.status === 500)) return null;
        throw e;
      }
    },
    create({ id, name, gitUrl, gitAuthToken, description }) {
      return request('POST', '/api/v1/apps', { body: { id, name, description: description || '', gitUrl: gitUrl || '', gitAuthToken: gitAuthToken || '' } });
    },
    upgrade(id, gitAuthToken) {
      return request('PUT', `/api/v1/apps/${encodeURIComponent(id)}/upgrade`, { body: { applicationId: id, gitAuthToken: gitAuthToken || '' } });
    },
    installDependencies(id) {
      return request('PATCH', `/api/v1/apps/${encodeURIComponent(id)}/dependencies`, { body: {} });
    },
    restart(id, runtimesOnly = false) {
      return request('PATCH', `/api/v1/apps/${encodeURIComponent(id)}/restart`, { body: { runtimesOnly } });
    },
    remove(id) {
      return request('DELETE', `/api/v1/apps/${encodeURIComponent(id)}`);
    },
  };

  const files = {
    async read(app, path) {
      const r = await request('GET', `/api/v1/apps/${encodeURIComponent(app)}/files/${enc(path)}`);
      return typeof r.data === 'string' ? Buffer.from(r.data, 'base64').toString('utf8') : '';
    },
    async readOptional(app, path) {
      try {
        return await files.read(app, path);
      } catch (e) {
        if (isNotFound(e)) return null;
        throw e;
      }
    },
    /** WriteFile binds the body to `data` (bytes), so the JSON body is a base64 string. */
    write(app, path, content) {
      const b = Buffer.isBuffer(content) ? content : Buffer.from(typeof content === 'string' ? content : JSON.stringify(content, null, 2) + '\n');
      return request('POST', `/api/v1/apps/${encodeURIComponent(app)}/files/${enc(path)}`, { body: b.toString('base64') });
    },
    async remove(app, path) {
      try {
        await request('DELETE', `/api/v1/apps/${encodeURIComponent(app)}/files/${enc(path)}`);
      } catch (e) {
        if (!isNotFound(e)) throw e;
      }
    },
  };

  const hooks = {
    async id(app, name) {
      const a = await apps.get(app);
      const h = ((a && a.hooks) || []).find((x) => x.name === name);
      return h ? h.id : null;
    },
    /**
     * StartHook + poll GetHookResults (the admin hook contract in docs/internals.md).
     * @returns {Promise<any>} the parsed JSON the hook returned
     */
    async run(app, name, action, args = {}, { timeoutMs: tmo = 90000 } = {}) {
      const hookId = await hooks.id(app, name);
      if (!hookId) throw new NfError(`hook ${name} not found in app ${app}`);
      const flat = { action };
      for (const [k, v] of Object.entries(args)) if (v !== undefined) flat[k] = typeof v === 'string' ? v : JSON.stringify(v);
      flat.json = JSON.stringify(args);
      const start = await request('POST', `/api/v1/apps/${encodeURIComponent(app)}/hooks/${hookId}`, { body: flat });
      if (start.error && start.error.message) throw new NfError(`admin ${action}: ${start.error.message}`);
      const pid = start.pid;
      if (!pid) throw new NfError(`admin ${action}: StartHook returned no pid`);
      const deadline = Date.now() + tmo;
      let delay = 200;
      while (Date.now() < deadline) {
        await sleep(delay);
        delay = Math.min(delay * 2, 2000);
        const r = await request('GET', `/api/v1/apps/${encodeURIComponent(app)}/hooks/${hookId}/results`, { params: { pid, pageSize: 10 } });
        const done = (r.results || []).find((x) => (!x.pid || x.pid === pid) && /SUCCESS|ERROR|ABORTED|STOPPED|SKIPPED/.test(String(x.state)));
        if (!done) continue;
        if (!/SUCCESS/.test(String(done.state))) {
          const msg = (done.error && done.error.message) || done.returnValue || done.state;
          let parsed = msg;
          try {
            parsed = JSON.parse(msg).error || msg;
          } catch { /* plain text */ }
          throw new NfError(`admin ${action} failed (${done.state}): ${parsed}`, { body: done });
        }
        if (done.returnValue === undefined || done.returnValue === '') return null;
        try {
          return JSON.parse(done.returnValue);
        } catch {
          return done.returnValue;
        }
      }
      throw new NfError(`admin ${action}: timed out after ${tmo} ms`);
    },
  };

  return { request, http, apps, files, hooks };
}
