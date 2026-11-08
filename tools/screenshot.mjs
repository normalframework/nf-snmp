#!/usr/bin/env node
// Real-time screenshot of a page via Chromium DevTools protocol (no deps; Node 22 WebSocket).
//   node tools/screenshot.mjs <url> <out.png> [waitMs=12000] [clickSelector]
import { spawn } from 'node:child_process';
import fs from 'node:fs';
const [url, out, waitMs = '12000', click] = process.argv.slice(2);
const port = 9333 + Math.floor(Math.random() * 500);
const bin = process.env.CHROME || 'chromium-browser';
const proc = spawn(bin, ['--headless=new', '--no-sandbox', '--disable-gpu', `--remote-debugging-port=${port}`, '--window-size=1400,1000', 'about:blank'], { stdio: 'ignore' });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let targets;
for (let i = 0; i < 50; i++) { try { targets = await (await fetch(`http://127.0.0.1:${port}/json`)).json(); break; } catch { await sleep(200); } }
const page = targets.find((t) => t.type === 'page');
const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener('open', r));
let id = 0; const pending = new Map();
ws.addEventListener('message', (m) => { const d = JSON.parse(m.data); if (d.id && pending.has(d.id)) { pending.get(d.id)(d); pending.delete(d.id); } });
const send = (method, params = {}) => new Promise((r) => { const i = ++id; pending.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
await send('Page.enable');
await send('Page.navigate', { url });
await sleep(Number(waitMs));
if (click) { await send('Runtime.evaluate', { expression: `document.querySelector(${JSON.stringify(click)}).click()` }); await sleep(Number(waitMs)); }
const shot = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: !process.env.VIEWPORT_ONLY });
fs.writeFileSync(out, Buffer.from(shot.result.data, 'base64'));
ws.close(); proc.kill();
console.log('wrote', out);
