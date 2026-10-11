import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
const root = 'D:/RVE/.codex/local/rea-aion-round9';
const destinations = ['F:/RVE-Workspace/cases/aionclassic2-2026-10-10/reports/rea-aion-round9', 'D:/RVE/.codex/local/aion-report-backup/rea-aion-round9'];
const hash = data => crypto.createHash('sha256').update(data).digest('hex');
const files = fs.readdirSync(root).filter(name => /\.(json|md|mjs|py|log)$/.test(name) && name !== 'backup-verification.json');
const copied = [];
for (const destination of destinations) {
  assert.ok(fs.existsSync(path.dirname(destination)), 'Backup parent unavailable');
  fs.mkdirSync(destination,{recursive:true});
  for (const name of files) {
    const raw = fs.readFileSync(path.join(root,name));
    fs.writeFileSync(path.join(destination,name), raw);
    assert.equal(hash(fs.readFileSync(path.join(destination,name))), hash(raw));
    if (destination === destinations[0]) copied.push({file:name,bytes:raw.length,sha256:hash(raw)});
  }
}
const verification = { allReadBackHashesMatched:true, source:root, destinations, files:copied, excludes:['IDA database and sidecars','Commercial tool installation and product keys'] };
fs.writeFileSync(root + '/backup-verification.json',JSON.stringify(verification,null,2));
console.log(JSON.stringify({copiedFiles:copied.length,bytes:copied.reduce((n,x)=>n+x.bytes,0),allReadBackHashesMatched:true,destinations}));
