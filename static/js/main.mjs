// nf-snmp UI: devices, discovery, explore (identify/preview/walk), traps, profiles.
import { admin } from './api.mjs';

const $ = (sel, root = document) => root.querySelector(sel);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const view = $('#view');
let profiles = [];
let timer = null;

function toast(msg, err = false) {
  const t = $('#toast');
  t.textContent = msg;
  t.className = `toast${err ? ' err' : ''}`;
  clearTimeout(toast.t);
  toast.t = setTimeout(() => t.classList.add('hidden'), err ? 8000 : 3500);
}

async function guard(fn, btn) {
  if (btn) btn.disabled = true;
  try {
    return await fn();
  } catch (e) {
    toast(e.message || String(e), true);
    return undefined;
  } finally {
    if (btn) btn.disabled = false;
  }
}

function statePill(st) {
  const s = (st && st.state) || 'idle';
  const cls = s === 'ok' ? 'ok' : s === 'error' || s === 'unreachable' ? 'err' : 'muted';
  return `<span class="pill ${cls}" title="${esc(st && st.lastError)}">${esc(s)}</span>`;
}

function ago(ms) {
  if (!ms) return '—';
  const s = Math.round((Date.now() - ms) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  return `${Math.round(s / 3600)}h ago`;
}

// ------------------------------------------------------------------ credentials form fragment
function credFields(prefix, v = {}) {
  const ver = v.version || '2c';
  return `
    <label>Version<select name="${prefix}version">
      ${['1', '2c', '3'].map((x) => `<option value="${x}" ${x === ver ? 'selected' : ''}>v${x}</option>`).join('')}
    </select></label>
    <label class="v12">Community<input name="${prefix}community" value="${esc(v.community ?? 'public')}" autocomplete="off"></label>
    <label class="v3">User<input name="${prefix}user" value="${esc(v.user || '')}" autocomplete="off"></label>
    <label class="v3">Auth<select name="${prefix}authProtocol">${['none', 'md5', 'sha', 'sha224', 'sha256', 'sha384', 'sha512'].map((x) => `<option ${x === (v.authProtocol || 'sha') ? 'selected' : ''}>${x}</option>`).join('')}</select></label>
    <label class="v3">Auth key<input type="password" name="${prefix}authKey" value="${esc(v.authKey || '')}" autocomplete="new-password"></label>
    <label class="v3">Privacy<select name="${prefix}privProtocol">${['none', 'des', 'aes', 'aes256b', 'aes256r'].map((x) => `<option ${x === (v.privProtocol || 'aes') ? 'selected' : ''}>${x}</option>`).join('')}</select></label>
    <label class="v3">Priv key<input type="password" name="${prefix}privKey" value="${esc(v.privKey || '')}" autocomplete="new-password"></label>`;
}

function wireCred(form, prefix = '') {
  const sel = form.querySelector(`[name="${prefix}version"]`);
  const upd = () => {
    const v3 = sel.value === '3';
    form.querySelectorAll('.v3').forEach((e) => e.classList.toggle('hidden', !v3));
    form.querySelectorAll('.v12').forEach((e) => e.classList.toggle('hidden', v3));
  };
  sel.addEventListener('change', upd);
  upd();
}

function readCred(form, prefix = '') {
  const g = (n) => form.querySelector(`[name="${prefix}${n}"]`)?.value;
  const version = g('version');
  if (version !== '3') return { version, community: g('community') };
  return { version, user: g('user'), authProtocol: g('authProtocol'), authKey: g('authKey'), privProtocol: g('privProtocol'), privKey: g('privKey') };
}

// ------------------------------------------------------------------ devices
async function renderDevices() {
  view.innerHTML = `
    <div class="card">
      <h2 id="formTitle">Add device</h2>
      <form id="dev" class="grid">
        <input type="hidden" name="uuid">
        <label>Name<input name="name" placeholder="UPS-1"></label>
        <label>Host / IP<input name="host" required placeholder="10.0.0.20"></label>
        <label>Port<input name="port" type="number" value="161"></label>
        ${credFields('')}
        <label>Profile<select name="profile"><option value="auto">auto-detect</option>${profiles.filter((p) => !p.abstract).map((p) => `<option value="${esc(p.id)}">${esc(p.name)}</option>`).join('')}</select></label>
        <label>Poll period (s)<input name="periodSeconds" type="number" value="60" min="1"></label>
        <label>Timeout (ms)<input name="timeoutMs" type="number" value="2000"></label>
        <label>Retries<input name="retries" type="number" value="1" min="0" max="5"></label>
        <label>OIDs per GET<input name="maxOidsPerGet" type="number" value="20" min="1"></label>
        <label>Bulk repetitions<input name="maxRepetitions" type="number" value="10" min="1"></label>
        <label>Write community (v1/v2c)<input name="writeCommunity" autocomplete="off" placeholder="(same as read)"></label>
      </form>
      <div class="row" style="margin-top:10px">
        <button class="btn primary" id="save">Save &amp; sync</button>
        <button class="btn" id="test">Test (preview)</button>
        <button class="btn" id="reset">Clear</button>
      </div>
      <div id="testOut"></div>
    </div>
    <div class="card"><h2>Devices</h2><div id="devs" class="table-wrap muted">Loading…</div></div>`;
  const form = $('#dev');
  wireCred(form);
  const collect = () => {
    const o = Object.fromEntries(new FormData(form).entries());
    const d = Object.assign({}, readCred(form), {
      uuid: o.uuid || undefined,
      name: o.name || undefined,
      host: o.host.trim(),
      port: Number(o.port) || 161,
      profile: o.profile,
      periodSeconds: Number(o.periodSeconds) || 60,
      timeoutMs: Number(o.timeoutMs) || 2000,
      retries: Number(o.retries),
      maxOidsPerGet: Number(o.maxOidsPerGet) || 20,
      maxRepetitions: Number(o.maxRepetitions) || 10,
    });
    if (o.writeCommunity) d.writeCommunity = o.writeCommunity;
    return d;
  };
  $('#save').onclick = (ev) => guard(async () => {
    const d = collect();
    if (!d.host) throw new Error('host is required');
    const r = await admin('put-device', { device: d });
    toast(`Saved ${r.device.name}: ${r.device.matchedProfile || 'no profile'} (${r.device.pointCount} points)`);
    resetForm();
    loadDevices();
  }, ev.target);
  $('#test').onclick = (ev) => guard(async () => {
    const d = collect();
    const r = await admin('preview', { target: d, profile: d.profile });
    $('#testOut').innerHTML = previewTable(r);
  }, ev.target);
  const resetForm = () => {
    form.reset();
    form.uuid.value = '';
    $('#formTitle').textContent = 'Add device';
    wireCred(form);
    $('#testOut').innerHTML = '';
  };
  $('#reset').onclick = resetForm;
  view._edit = (d) => {
    for (const [k, v] of Object.entries(d)) if (form.elements[k] && typeof v !== 'object') form.elements[k].value = v;
    $('#formTitle').textContent = `Edit ${d.name}`;
    wireCred(form);
    window.scrollTo(0, 0);
  };
  await loadDevices();
  clearInterval(timer);
  timer = setInterval(() => document.visibilityState === 'visible' && loadDevices(true), 10000);
}

async function loadDevices(quiet) {
  const box = $('#devs');
  if (!box) return;
  const r = quiet ? await admin('devices').catch(() => null) : await guard(() => admin('devices'));
  if (!r) return;
  if (!r.devices.length) {
    box.innerHTML = '<p class="muted">No devices yet. Add one above or use Discover.</p>';
    return;
  }
  box.innerHTML = `<table><thead><tr><th>Name</th><th>Address</th><th>Ver</th><th>Profile</th><th class="num">Points</th><th>Status</th><th>Last OK</th><th class="num">Req / err</th><th></th></tr></thead><tbody>
    ${r.devices.map((d) => `<tr data-uuid="${esc(d.uuid)}">
      <td><b>${esc(d.name)}</b><div class="small muted">${esc(d.identity && d.identity.sysDescr ? d.identity.sysDescr.slice(0, 80) : '')}</div></td>
      <td class="mono">${esc(d.host)}:${esc(d.port)}</td>
      <td>v${esc(d.version)}</td>
      <td>${esc(d.matchedProfile || '—')}${d.profile === 'auto' ? ' <span class="muted small">(auto)</span>' : ''}${d.warnings && d.warnings.length ? `<div class="small" style="color:var(--warn)">${esc(d.warnings.join('; '))}</div>` : ''}</td>
      <td class="num">${d.pointCount}</td>
      <td>${d.enabled === false ? '<span class="pill muted">disabled</span>' : statePill(d.status)}</td>
      <td>${ago(d.status && d.status.lastOk)}</td>
      <td class="num">${d.stats ? `${d.stats.requests} / ${d.stats.errors}` : '—'}</td>
      <td class="row"><button class="btn" data-act="edit">Edit</button><button class="btn" data-act="sync">Resync</button><button class="btn" data-act="preview">Values</button><button class="btn danger" data-act="del">Delete</button></td>
    </tr>`).join('')}</tbody></table><div id="devPreview"></div>`;
  box.querySelectorAll('button[data-act]').forEach((b) => {
    const uuid = b.closest('tr').dataset.uuid;
    const d = r.devices.find((x) => x.uuid === uuid);
    b.onclick = () => guard(async () => {
      if (b.dataset.act === 'edit') view._edit(d);
      if (b.dataset.act === 'sync') {
        const s = await admin('sync-device', { uuid });
        toast(`${d.name}: ${s.profile}, ${s.points} points`);
        loadDevices();
      }
      if (b.dataset.act === 'preview') $('#devPreview').innerHTML = `<h3>${esc(d.name)}</h3>` + previewTable(await admin('preview', { uuid, profile: d.matchedProfile || d.profile }));
      if (b.dataset.act === 'del' && confirm(`Delete ${d.name} and its ${d.pointCount} points (and their history) from NF?`)) {
        await admin('delete-device', { uuid });
        toast(`Deleted ${d.name}`);
        loadDevices();
      }
    }, b);
  });
}

function previewTable(r) {
  if (!r) return '';
  const id = r.identity;
  const head = id ? `<p class="small">sysObjectID <span class="mono">${esc(id.sysObjectID)}</span> · ${esc(id.vendor || 'unknown vendor')} · ${esc(id.sysName || '')}<br>${esc(id.sysDescr || '')}<br>Profile: <b>${esc(r.profile || 'none')}</b> ${id.profile ? `<span class="muted">(${esc(id.profile.reason)}, ${esc(id.confidence)} confidence)</span>` : ''}</p>` : `<p class="small">Profile: <b>${esc(r.profile)}</b></p>`;
  if (!r.points || !r.points.length) return head + '<p class="muted">No points.</p>';
  return `${head}${(r.warnings || []).map((w) => `<p class="small" style="color:var(--warn)">${esc(w)}</p>`).join('')}
    <div class="table-wrap"><table><thead><tr><th>Point</th><th>OID</th><th class="num">Value</th><th>Units</th><th>Raw</th></tr></thead><tbody>
    ${r.points.map((p) => `<tr><td>${esc(p.name)}${p.writable ? ' <span class="pill warn">writable</span>' : ''}</td><td class="mono small">${esc(p.oid)}</td>
      <td class="num">${p.error ? `<span class="err-text small">${esc(p.error)}</span>` : esc(p.value)}</td><td>${esc(p.units || '')}</td>
      <td class="mono small muted">${p.raw ? esc(`${p.raw.type} ${p.raw.value}`) : ''}</td></tr>`).join('')}</tbody></table></div>`;
}

// ------------------------------------------------------------------ discover
async function renderDiscover() {
  view.innerHTML = `
    <div class="card">
      <h2>Discover devices</h2>
      <p class="small muted">Probes each host for sysObjectID/sysDescr with up to 4 credential sets, in order. Keep the range small and the credentials specific:
      sweeping many communities across a subnet triggers intrusion-detection alerts on IT networks.</p>
      <form id="disc" class="grid">
        <label style="grid-column: span 2">Hosts (IPs, ranges a.b.c.10-20, CIDR /16../32, names)<input name="hosts" placeholder="10.0.20.0/24"></label>
        <label>Port<input name="port" type="number" value="161"></label>
        <label>Timeout (ms)<input name="timeoutMs" type="number" value="1000"></label>
        <label>Concurrency<input name="concurrency" type="number" value="8" min="1" max="16"></label>
        ${credFields('c0_')}
      </form>
      <details style="margin-top:8px"><summary>Additional credential set</summary><form id="disc2" class="grid">${credFields('c1_', { version: '1' })}</form></details>
      <div class="row" style="margin-top:10px"><button class="btn primary" id="go">Start</button><button class="btn" id="cancel" disabled>Cancel</button></div>
      <div id="job" style="margin-top:12px"></div>
    </div>`;
  const f = $('#disc');
  const f2 = $('#disc2');
  wireCred(f, 'c0_');
  wireCred(f2, 'c1_');
  let jobId = null;
  $('#go').onclick = (ev) => guard(async () => {
    const creds = [readCred(f, 'c0_')];
    if ($('details').open) creds.push(readCred(f2, 'c1_'));
    const r = await admin('discover', { hosts: f.hosts.value, port: Number(f.port.value), timeoutMs: Number(f.timeoutMs.value), concurrency: Number(f.concurrency.value), credentials: creds });
    jobId = r.jobId;
    $('#cancel').disabled = false;
    poll();
  }, ev.target);
  $('#cancel').onclick = () => guard(() => admin('discover-cancel', { jobId }));
  async function poll() {
    if (!jobId || !$('#job')) return;
    const j = await admin('discover-get', { jobId }).catch((e) => ({ error: e.message }));
    if (j.error) return toast(j.error, true);
    const pct = j.total ? Math.round((100 * j.done) / j.total) : 0;
    $('#job').innerHTML = `<div class="row small"><b>${esc(j.state)}</b> ${j.done}/${j.total} hosts · ${j.found.length} found</div><div class="progress"><div style="width:${pct}%"></div></div>
      ${j.found.length ? `<div class="table-wrap" style="margin-top:10px"><table><thead><tr><th><input type="checkbox" id="all" checked></th><th>Host</th><th>sysName</th><th>Vendor</th><th>Description</th><th>Profile</th><th>Confidence</th></tr></thead><tbody>
      ${j.found.map((x) => `<tr><td>${x.error ? '' : `<input type="checkbox" class="pick" value="${esc(x.host)}" ${x.existingDevice ? '' : 'checked'}>`}</td><td class="mono">${esc(x.host)}</td>
        ${x.error ? `<td colspan="5" class="err-text small">${esc(x.error)}</td>` : `<td>${esc(x.identity.sysName || '')}</td><td>${esc(x.identity.vendor || '')}</td><td class="small">${esc((x.identity.sysDescr || '').slice(0, 90))}</td>
        <td>${esc(x.identity.profile ? x.identity.profile.name : '—')}${x.existingDevice ? ' <span class="pill muted">exists</span>' : ''}</td><td>${esc(x.identity.confidence)}</td>`}</tr>`).join('')}
      </tbody></table></div><div class="row" style="margin-top:8px"><label>Poll period (s)<input id="addPeriod" type="number" value="60"></label><button class="btn primary" id="add">Add selected</button></div>` : ''}`;
    const all = $('#all');
    if (all) all.onchange = () => document.querySelectorAll('.pick').forEach((c) => (c.checked = all.checked));
    const add = $('#add');
    if (add) add.onclick = () => guard(async () => {
      const hosts = [...document.querySelectorAll('.pick:checked')].map((c) => c.value);
      const r = await admin('discover-add', { jobId, hosts, periodSeconds: Number($('#addPeriod').value) || 60 }, { timeoutMs: 180000 });
      toast(`Added ${r.added.filter((x) => !x.error).length} devices${r.added.some((x) => x.error) ? `; errors: ${r.added.filter((x) => x.error).map((x) => `${x.host}: ${x.error}`).join(', ')}` : ''}`);
    }, add);
    if (j.state === 'running') setTimeout(poll, 1500);
    else $('#cancel').disabled = true;
  }
}

// ------------------------------------------------------------------ explore
async function renderExplore() {
  view.innerHTML = `
    <div class="card"><h2>Explore a device</h2>
      <form id="ex" class="grid">
        <label>Host / IP<input name="host" required></label>
        <label>Port<input name="port" type="number" value="161"></label>
        ${credFields('')}
        <label>Walk root OID<input name="root" value="1.3.6.1.2.1.1"></label>
        <label>Max varbinds<input name="max" type="number" value="2000"></label>
      </form>
      <div class="row" style="margin-top:10px"><button class="btn primary" id="ident">Identify</button><button class="btn" id="walk">Walk</button><button class="btn" id="bwalk">Bulk walk</button></div>
      <div id="exOut" style="margin-top:12px"></div>
    </div>`;
  const f = $('#ex');
  wireCred(f);
  const target = () => Object.assign(readCred(f), { host: f.host.value.trim(), port: Number(f.port.value) || 161, timeoutMs: 2000, retries: 1 });
  $('#ident').onclick = (ev) => guard(async () => {
    const r = await admin('identify', { target: target() });
    $('#exOut').innerHTML = `<pre>${esc(JSON.stringify(r, null, 2))}</pre>`;
  }, ev.target);
  const walk = (bulk) => (ev) => guard(async () => {
    const r = await admin('walk', { target: target(), root: f.root.value.trim(), bulk, maxVarbinds: Number(f.max.value) || 2000 });
    const rows = r.varbinds.map((v) => {
      let val = v.value;
      if (v.type === 'OctetString') {
        try {
          const s = decodeURIComponent(val.replace(/(..)/g, '%$1'));
          if (!/[\x00-\x08\x0e-\x1f]/.test(s)) val = `"${s}"`;
        } catch { /* binary */ }
      }
      return `<tr><td class="mono small">${esc(v.oid)}</td><td class="small">${esc(v.type)}</td><td class="mono small">${esc(val)}</td></tr>`;
    }).join('');
    $('#exOut').innerHTML = `<p class="small">${r.varbinds.length} varbinds${r.error ? ` · <span class="err-text">${esc(r.error.error)}: ${esc(r.error.message)}</span>` : ''}</p><div class="table-wrap"><table><thead><tr><th>OID</th><th>Type</th><th>Value</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }, ev.target);
  $('#walk').onclick = walk(false);
  $('#bwalk').onclick = walk(true);
}

// ------------------------------------------------------------------ traps
async function renderTraps() {
  view.innerHTML = '<div class="card"><h2>Traps &amp; informs</h2><div id="tr" class="muted">Loading…</div></div>';
  const load = async () => {
    const r = await admin('traps', { limit: 200 }).catch((e) => ({ error: e.message }));
    const box = $('#tr');
    if (!box) return;
    if (r.error) return (box.innerHTML = `<span class="err-text">${esc(r.error)}</span>`);
    const st = r.status;
    box.innerHTML = `<p class="small">${st ? `Receiver on UDP ${st.port}: ${st.listening ? 'listening' : 'not listening'} · received ${st.counts.received}, from devices ${st.counts.matched}, unknown sources ${st.counts.unknownSource}` : 'Receiver disabled (trapPort = 0)'}</p>
      ${r.traps.length ? `<div class="table-wrap"><table><thead><tr><th>Time</th><th>From</th><th>Device</th><th>Kind</th><th>Trap OID</th><th>Varbinds</th></tr></thead><tbody>
      ${r.traps.map((t) => `<tr><td class="small">${new Date(t.ts).toLocaleString()}</td><td class="mono">${esc(t.from)}</td><td>${esc(t.device || '—')}</td><td>${esc(t.kind)}</td><td class="mono small">${esc(t.trapOid)}</td><td class="mono small">${esc(t.varbinds.map((v) => `${v.oid}=${v.value}`).join('  '))}</td></tr>`).join('')}
      </tbody></table></div>` : '<p class="muted">No traps received yet.</p>'}`;
  };
  await load();
  clearInterval(timer);
  timer = setInterval(() => document.visibilityState === 'visible' && load(), 5000);
}

// ------------------------------------------------------------------ profiles
async function renderProfiles() {
  const list = profiles.filter((p) => !p.abstract);
  view.innerHTML = `<div class="card"><div class="row"><h2 style="margin-right:auto">Device profiles (${list.length})</h2><input id="pf" placeholder="Filter: vendor, model, sysObjectID…" style="min-width:280px"></div><div class="table-wrap"><table><thead><tr><th>Profile</th><th>Vendor</th><th>Matches</th><th class="num">Symbols</th><th class="num">Tables</th><th></th></tr></thead><tbody>
    ${list.map((p) => `<tr data-q="${esc(`${p.id} ${p.name} ${p.vendor} ${JSON.stringify(p.match)}`.toLowerCase())}"><td><b>${esc(p.name)}</b>${p.user ? ' <span class="pill ok">user</span>' : p.id.startsWith('dd/') ? ' <span class="pill muted">Datadog</span>' : ''}<div class="small mono muted">${esc(p.id)}</div></td><td>${esc(p.vendor)}</td>
      <td class="small mono" title="${esc(p.match.map((m) => Object.values(m).join(' ')).join('\n'))}">${esc(p.match.slice(0, 3).map((m) => Object.entries(m).map(([k, v]) => `${k}=${v}`).join(' & ')).join(' | '))}${p.match.length > 3 ? ` <span class="muted">+${p.match.length - 3} more</span>` : ''}</td><td class="num">${p.symbols}</td><td class="num">${p.tables}</td>
      <td><button class="btn" data-id="${esc(p.id)}">Show</button></td></tr>`).join('')}</tbody></table></div><div id="pv"></div></div>`;
  $('#pf').oninput = (ev) => {
    const q = ev.target.value.trim().toLowerCase();
    view.querySelectorAll('tr[data-q]').forEach((tr) => tr.classList.toggle('hidden', !!q && !tr.dataset.q.includes(q)));
  };
  view.querySelectorAll('button[data-id]').forEach((b) => (b.onclick = () => guard(async () => {
    const r = await admin('profile', { id: b.dataset.id });
    $('#pv').innerHTML = `<pre>${esc(JSON.stringify(r.profile, null, 2))}</pre>`;
  }, b)));
}

// ------------------------------------------------------------------ shell
const TABS = { devices: renderDevices, discover: renderDiscover, explore: renderExplore, traps: renderTraps, profiles: renderProfiles };
async function show(tab) {
  clearInterval(timer);
  document.querySelectorAll('#tabs button').forEach((b) => b.classList.toggle('active', b.dataset.tab === tab));
  try { sessionStorage.setItem('nfsnmp.tab', tab); } catch { /* ignore */ }
  await TABS[tab]();
}

async function engineStatus() {
  const pill = $('#engine');
  try {
    const s = await admin('status');
    const mode = s.polling && s.polling.mode;
    pill.className = `pill ${s.ok ? (mode === 'self' ? 'warn' : 'ok') : 'err'}`;
    pill.textContent = `engine ${s.ok ? 'running' : 'down'} · ${s.devices.length} devices · ${s.points} points${mode === 'self' ? ' · self-polling' : ''}`;
    pill.title = mode === 'self' ? 'NF\'s poll service is not reading the snmp layer yet (it loads layers at startup). The engine polls meanwhile; restart NF to hand polling back.' : '';
  } catch (e) {
    pill.className = 'pill err';
    pill.textContent = 'engine unreachable';
    pill.title = e.message;
  }
}

document.querySelectorAll('#tabs button').forEach((b) => (b.onclick = () => show(b.dataset.tab)));
(async () => {
  const r = await guard(() => admin('profiles'));
  profiles = (r && r.profiles) || [];
  let tab = 'devices';
  try { tab = sessionStorage.getItem('nfsnmp.tab') || 'devices'; } catch { /* ignore */ }
  await show(TABS[tab] ? tab : 'devices');
  engineStatus();
  setInterval(() => document.visibilityState === 'visible' && engineStatus(), 30000);
})();
