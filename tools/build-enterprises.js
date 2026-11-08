#!/usr/bin/env node
'use strict';
// Build data/enterprises.tsv (number<TAB>organization) from the IANA Private Enterprise Numbers
// registry (https://www.iana.org/assignments/enterprise-numbers.txt). Contacts/emails are dropped.
//   curl -sfL https://www.iana.org/assignments/enterprise-numbers.txt | node tools/build-enterprises.js > data/enterprises.tsv
const lines = require('fs').readFileSync(0, 'utf8').split(/\r?\n/);
const out = [];
for (let i = 0; i < lines.length; i++) {
  if (/^\d+$/.test(lines[i]) && i + 1 < lines.length && /^  \S/.test(lines[i + 1])) {
    const name = lines[i + 1].trim().replace(/\t/g, ' ');
    if (name && !/^(---none---|unassigned|reserved)$/i.test(name)) out.push(`${lines[i]}\t${name}`);
  }
}
process.stdout.write(out.join('\n') + '\n');
