import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { access, readFile, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const study = path.resolve(here, '../../..');
const repository = path.resolve(here, '../../../../..');
const root = path.join(study, 'evidence/round11');
const read = async relative => JSON.parse(await readFile(path.join(root, relative), 'utf8'));
const { evidenceSchema } = await import(pathToFileURL(path.join(repository, 'dist/domain/evidence.js')).href);
const { toolContract } = await import(pathToFileURL(path.join(repository, 'dist/contracts/toolContracts.js')).href);
const { analysisErrorProjectionSchema } = await import(pathToFileURL(path.join(repository, 'dist/contracts/errorSchemas.js')).href);
const expected = '834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786';
const bytes = await readFile(path.join(study, 'samples/Game.dll'));
assert.equal(createHash('sha256').update(bytes).digest('hex'), expected);
const batches = [];
const requests = [];
const workspaces = new Set();
for (const entry of await readdir(root, { withFileTypes: true })) {
  if (!entry.isDirectory()) continue;
  const summaryPath = path.join(root, entry.name, 'batch-summary.json');
  try { await access(summaryPath); } catch (error) { if (error.code === 'ENOENT') continue; throw error; }
  const batch = entry.name;
  batches.push(batch);
  const summary = await read(`${batch}/batch-summary.json`);
  assert.equal(summary.targetSha256, expected);
  assert.equal(summary.targetExecuted, false);
  assert.equal((await read(`${batch}/open-session.json`)).structuredContent.result.sha256, expected);
  const closed = await read(`${batch}/close-session.json`);
  assert.notEqual(closed.isError, true);
  assert.equal(closed.structuredContent.result, null);
  for (const row of summary.results) {
    const response = await read(`${batch}/${row.file}.mcp.json`);
    const error = response.result.isError === true;
    const request = { batch, file: row.file, tool: response.name, error,
      failure: error ? response.result.structuredContent.error : null };
    requests.push(request);
    if (error) {
      analysisErrorProjectionSchema.parse(request.failure);
      continue;
    }
    toolContract(response.name).outputSchema.parse(response.result.structuredContent);
    const evidence = evidenceSchema.parse(response.result.structuredContent.evidence);
    assert.equal(evidence.subject.digest.sha256, expected);
    assert.equal(evidence.provider.id, 'ida');
    assert.equal(evidence.analysis_profile.parameters.mode, 'headless');
    const { metadata_before: before, metadata_after: after } = evidence.raw_result;
    assert.equal(before.imagebase, '0x180000000');
    assert.equal(before.input_path, after.input_path);
    assert.equal(before.auto_analysis_ready, true);
    assert.equal(after.auto_analysis_ready, true);
    workspaces.add(path.dirname(before.input_path));
    request.evidenceId = evidence.evidence_id;
  }
}
assert.ok(batches.length > 0);
for (const workspace of workspaces) await assert.rejects(access(workspace), { code: 'ENOENT' });
const diagnosis = await read('ida95-finalize-diagnostic/diagnostic-summary.json');
assert.equal(diagnosis.result.ok, false);
assert.equal(diagnosis.close.ok, true);
assert.equal(diagnosis.afterSha256, expected);
const observations = await read('ida95-finalize-diagnostic/producer-observations.json');
const health = observations.filter(row => row.name === 'server_health').map(row => row.result);
assert.equal(health[0].auto_analysis_ready, true);
assert.equal(health.at(-1).auto_analysis_ready, false);
assert.ok(observations.some(row => row.name === 'decompile'));
assert.ok(observations.some(row => row.name === 'idb_close' && row.result.success && row.arguments.save === false));
assert.ok(observations.some(row => row.name === 'idb_list' && row.result.count === 0));
for (const metadata of health) await assert.rejects(access(path.dirname(metadata.input_path)), { code: 'ENOENT' });
const table = await read('ui-node-original-pe.json');
assert.equal(table.source_sha256, expected);
assert.equal(table.derived_table_va, '0x1807f5f78');
for (const entry of [table.lea, ...table.first_three_qwords]) {
  const offset = Number.parseInt(entry.file_offset, 16);
  const raw = Buffer.from(entry.bytes_hex, 'hex');
  assert.deepEqual(bytes.subarray(offset, offset + raw.length), raw);
}
const checks = ['Established Game.dll SHA-256 unchanged',
  'Every batch closed normally without executing the target',
  'Successful responses validated against their named output contracts; error payloads retained separately',
  'Successful Evidence bound to the same source digest and ready headless metadata before/after',
  'Successful private workspaces removed',
  'Diagnostic captured true-to-false readiness transition after decompilation',
  'Diagnostic closed without saving, returned an empty inventory, and removed its private workspace',
  'UIChainNode LEA and selected pointer bytes match the original PE offsets'];
const contains = async (relative, expectedLines) => {
  const result = await read(relative);
  const lines = typeof result.instructions === 'string' ? result.instructions.split('\n') : result.instructions;
  for (const line of expectedLines) assert.ok(lines.includes(line), `${relative}: ${line}`);
};
await contains('ida95-registry-instructions/registry-reset-instructions.normalized.json', [
  '0x18039d6c3: call sub_1806844F0', '0x18039d6d9: lea rdi, [rsi+68h]',
  '0x18039d6dd: mov [rsi+28h], rax', '0x18039d755: sub r14, 1']);
checks.push('Reset frees relation nodes, resets their vector end, and traverses the four keyed containers');
await contains('ida95-condition-consumers/condition-query-instructions.normalized.json', [
  '0x18039e754: mov rax, [rax+20h]', '0x18039e761: cmp [rax+8], rcx',
  '0x18039e767: xor eax, eax']);
checks.push('Selected query checks relation presence and nonempty entries rather than proving runtime cast eligibility');
await contains('ida95-condition-consumers/chain-node-slot1-instructions.normalized.json', [
  '0x18027eadc: mov ecx, [rax+7A4h]', '0x18027eae2: imul ecx, edi',
  '0x18027eae5: add ecx, [rax+7A8h]', "0x18027eaeb: cmp ecx, 64h ; 'd'",
  '0x18027ec2e: call sub_18061A020']);
checks.push('UIChainNode slot1 consumes both chain probability fields on a path to drawing calls');
await contains('ida95-condition-consumers/condition-ui-select-b-instructions.normalized.json', [
  '0x1802841fb: mov [rcx], r11d', '0x180284205: mov [rcx], ebx',
  '0x180284218: call sub_18039ECF0']);
checks.push('A UI path swaps two dword entries then calls the registry refresh helper');
await contains('ida95-condition-state/condition-pair-query-instructions.normalized.json', [
  '0x18039e78a: cmp edx, r8d', '0x18039e7f8: call sub_18039E770',
  '0x18039e813: mov eax, 1']);
checks.push('Pair query tests equality and recursively traverses registered dword relations');
await contains('ida95-condition-state/condition-state-refresh-instructions.normalized.json', [
  '0x18039ef8a: lea rdx, aChainskill; "chainskill"', '0x18039f0b3: mov dword ptr [rdi], 65h ; \'e\'',
  '0x18039f184: call sub_180507710', '0x18039f195: call sub_180507470']);
checks.push('Refresh builds a tag-101 representation under the chainskill name and compares/updates it via observed helper calls');
const report = { passed: true, targetSha256: expected, targetExecuted: false, batches,
  requests: requests.length, successes: requests.filter(row => !row.error).length,
  failures: requests.filter(row => row.error), checks, evidenceIds: requests.flatMap(row => row.evidenceId ? [row.evidenceId] : []),
  privateWorkspacesConfirmedRemoved: [...workspaces], diagnosis };
await writeFile(path.join(root, 'verification.json'), JSON.stringify(report, null, 2));
console.log(JSON.stringify({ passed: true, requests: report.requests, successes: report.successes,
  failures: report.failures.length, checks: checks.length }));
