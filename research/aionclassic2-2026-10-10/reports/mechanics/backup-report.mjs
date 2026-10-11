import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
const source = 'D:/RVE/.codex/local/aion-mechanics-report';
const destinations = ['F:/RVE-Workspace/cases/aionclassic2-2026-10-10/reports/aion-mechanics-report', 'D:/RVE/.codex/local/aion-report-backup/aion-mechanics-report'];
const hash = file => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
function inventory(folder, relative = '') {
  return fs.readdirSync(folder, { withFileTypes: true }).flatMap(entry => {
    const next = path.join(folder, entry.name), rel = path.posix.join(relative, entry.name);
    return entry.isDirectory() ? inventory(next, rel) : rel === 'backup-verification.json' ? [] : [{ path: rel, bytes: fs.statSync(next).size, sha256: hash(next) }];
  });
}
const files = inventory(source);
for (const destination of destinations) {
  assert.ok(fs.statSync(path.dirname(destination)).isDirectory());
  for (const file of files) {
    const next = path.join(destination, file.path);
    fs.mkdirSync(path.dirname(next), { recursive: true });
    fs.copyFileSync(path.join(source, file.path), next);
    assert.equal(hash(next), file.sha256, next);
  }
}
const manifest = { source, destinations, files, fileCount: files.length, totalBytes: files.reduce((n, file) => n + file.bytes, 0), allReadBackHashesMatched: true };
fs.writeFileSync(source + '/backup-verification.json', JSON.stringify(manifest, null, 2));
for (const destination of destinations) fs.copyFileSync(source + '/backup-verification.json', destination + '/backup-verification.json');
console.log(JSON.stringify({ fileCount: manifest.fileCount, totalBytes: manifest.totalBytes, destinations, allReadBackHashesMatched: true }));
