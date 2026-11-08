'use strict';
/** IANA Private Enterprise Number -> organization (data/enterprises.tsv, built by tools/build-enterprises.js). */
const fs = require('fs');
const path = require('path');
let map = null;
function load() {
  map = new Map();
  try {
    const txt = fs.readFileSync(path.resolve(__dirname, '..', '..', 'data', 'enterprises.tsv'), 'utf8');
    for (const line of txt.split('\n')) {
      const t = line.indexOf('\t');
      if (t > 0) map.set(Number(line.slice(0, t)), line.slice(t + 1));
    }
  } catch {
    /* registry missing: names unknown */
  }
}
/** @param {number} n */
function enterpriseName(n) {
  if (!map) load();
  return map.get(Number(n)) || null;
}
module.exports = { enterpriseName };
