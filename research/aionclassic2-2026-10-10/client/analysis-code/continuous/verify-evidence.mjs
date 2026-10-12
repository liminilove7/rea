import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { access, readFile, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const study = path.resolve(here, '../../..');
const repository = path.resolve(study, '../..');
const root = path.join(study, 'evidence/continuous');
const expected = '834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786';
const knownSamples = new Map([
  ['Game.dll', expected],
  ['CrySystem.dll', '8705aeef77411a28e178832f2f242128b0b018b9546f58878c9e69df8f4e9061'],
]);
const { toolContract } = await import(pathToFileURL(path.join(repository, 'dist/contracts/toolContracts.js')).href);
const { analysisErrorProjectionSchema } = await import(pathToFileURL(path.join(repository, 'dist/contracts/errorSchemas.js')).href);
const { evidenceSchema } = await import(pathToFileURL(path.join(repository, 'dist/domain/evidence.js')).href);
assert.equal(createHash('sha256').update(await readFile(path.join(study, 'samples/Game.dll'))).digest('hex'), expected);
const sessions = [];
for (const entry of await readdir(root, { withFileTypes: true })) {
  if (!entry.isDirectory()) continue;
  const directory = path.join(root, entry.name);
  const read = async file => JSON.parse(await readFile(path.join(directory, file), 'utf8'));
  let progress;
  try { progress = await read('progress.json'); } catch (error) { if (error.code === 'ENOENT') continue; throw error; }
  const rows = [...progress.records]; // Verify this consistent prefix while a session may still append.
  const workspaces = new Set();
  const failures = [];
  let successes = 0;
  const sessionDigest = knownSamples.get(path.basename(progress.target));
  assert.ok(sessionDigest, 'Session must bind a known case sample');
  assert.equal(path.resolve(progress.target), path.join(study, 'samples', path.basename(progress.target)));
  assert.equal(progress.targetSha256, sessionDigest);
  assert.equal(createHash('sha256').update(await readFile(progress.target)).digest('hex'), sessionDigest);
  for (const row of rows) {
    const response = await read(row.file + '.mcp.json');
    assert.equal(response.name, row.name);
    if (response.result.isError === true) {
      analysisErrorProjectionSchema.parse(response.result.structuredContent.error);
      failures.push({ file: row.file, tool: row.name, error: response.result.structuredContent.error });
      continue;
    }
    toolContract(response.name).outputSchema.parse(response.result.structuredContent);
    const evidence = evidenceSchema.parse(response.result.structuredContent.evidence);
    assert.equal(evidence.provider.id, 'ida');
    assert.equal(evidence.subject.digest.sha256, sessionDigest);
    assert.equal(evidence.analysis_profile.parameters.mode, 'headless');
    const before = evidence.raw_result.metadata_before;
    const after = evidence.raw_result.metadata_after;
    assert.equal(before.imagebase, '0x180000000');
    assert.equal(before.input_path, after.input_path);
    assert.equal(before.auto_analysis_ready, true);
    assert.equal(after.auto_analysis_ready, true);
    workspaces.add(path.dirname(before.input_path));
    successes++;
  }
  let closed = false;
  let cleanupConfirmed = false;
  let cleanupFailure = null;
  const retainedWorkspaces = [];
  try {
    const summary = await read('session-summary.json');
    assert.equal(summary.afterSha256, sessionDigest);
    const close = await read('close-session.json');
    if (close.isError === true) {
      cleanupFailure = analysisErrorProjectionSchema.parse(close.structuredContent.error);
      for (const workspace of workspaces) {
        try { await access(workspace); retainedWorkspaces.push(workspace); }
        catch (error) { if (error.code !== 'ENOENT') throw error; }
      }
    } else {
      assert.equal(close.structuredContent.result, null);
      closed = true;
      for (const workspace of workspaces) await assert.rejects(access(workspace), { code: 'ENOENT' });
      cleanupConfirmed = true;
    }
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
  sessions.push({ directory: entry.name, sample: path.basename(progress.target), targetSha256: sessionDigest, requests: rows.length, successes, failures,
    closed, cleanupConfirmed, cleanupFailure, retainedWorkspaces, privateWorkspaces: [...workspaces] });
}
const report = { passed: true, targetSha256: expected, targetExecuted: false, analysisComplete: false,
  verifiedAt: new Date().toISOString(), cleanupComplete: sessions.every(session => session.closed && session.cleanupConfirmed), sessions,
  checks: ['Source Game.dll identity unchanged', 'Successful named output contracts and Evidence schemas validated',
    'Successful Evidence binds the source digest, image base and ready private database before/after',
    'Failure payloads preserved and validated independently', 'Successful close receipts checked for private directory removal; failed cleanup is preserved separately'] };
await writeFile(path.join(root, 'verification.json'), JSON.stringify(report, null, 2));
console.log(JSON.stringify({ passed: true, sessions: sessions.map(({ directory, requests, successes, failures, closed }) =>
  ({ directory, requests, successes, failures: failures.length, closed })) }));
