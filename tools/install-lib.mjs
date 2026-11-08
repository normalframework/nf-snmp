// Install or update nf-snmp on an NF instance by writing the repo's files over the REST API.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SHIP = ['app.json', 'logo.svg', 'LICENSE', 'NOTICE', 'README.md', 'hooks', 'hooks-update', 'lib', 'profiles', 'data', 'static', 'bin', 'local/.gitkeep'];

export function shippableFiles() {
  const out = [];
  const walk = (rel) => {
    const abs = path.join(ROOT, rel);
    if (!fs.existsSync(abs)) return;
    if (fs.statSync(abs).isDirectory()) for (const e of fs.readdirSync(abs)) walk(path.join(rel, e));
    else out.push(rel);
  };
  SHIP.forEach(walk);
  return out;
}

/** @param {{nf: any, appId?: string, log?: (m: string) => void}} o */
export async function installApp({ nf, appId = 'snmp', log = () => {} }) {
  const def = JSON.parse(fs.readFileSync(path.join(ROOT, 'app.json'), 'utf8'));
  const existing = await nf.apps.get(appId).catch(() => null);
  if (!existing) {
    await nf.request('POST', '/api/v1/apps', { body: { id: appId, name: def.name, description: def.description, layer: def.layer, options: def.options } });
    log(`created app ${appId}`);
  } else log(`updating app ${appId}`);
  // NF runs `npm install` in the app sandbox, which also installs devDependencies (vitest ->
  // esbuild, whose postinstall fails there). Ship a production-only package.json, no lockfile.
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  delete pkg.devDependencies;
  delete pkg.scripts;
  await nf.files.write(appId, 'package.json', Buffer.from(JSON.stringify(pkg, null, 2) + '\n'));
  await nf.files.remove(appId, 'package-lock.json').catch(() => {});
  const list = shippableFiles();
  for (const f of list) await nf.files.write(appId, f.split(path.sep).join('/'), fs.readFileSync(path.join(ROOT, f)));
  log(`wrote ${list.length} files`);
  await nf.apps.installDependencies(appId);
  log('installed dependencies');
  await nf.apps.restart(appId);
  log('restarted');
  return nf.apps.get(appId);
}
