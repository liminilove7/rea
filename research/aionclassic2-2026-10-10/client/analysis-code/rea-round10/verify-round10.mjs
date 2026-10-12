import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { access, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const study = path.resolve(here, '../../..');
const repository = path.resolve(here, '../../../../..');
const root = path.join(study, 'evidence/round10');
const { evidenceSchema } = await import(pathToFileURL(path.join(repository, 'dist/domain/evidence.js')).href);
const { toolContract } = await import(pathToFileURL(path.join(repository, 'dist/contracts/toolContracts.js')).href);
const expected = '834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786';
const read = async (relative) => JSON.parse(await readFile(path.join(root, relative), 'utf8'));
const targetBytes = await readFile(path.join(study, 'samples/Game.dll'));
assert.equal(createHash('sha256').update(targetBytes).digest('hex'), expected);
const checks = [];
const check = (name, predicate) => { assert.ok(predicate, name); checks.push(name); };
const batches = ['ida95-first', 'ida95-counter', 'ida95-follow', 'ida95-consumers', 'ida95-registry-owners'];
const results = [];
const evidenceIds = [];
const workspaces = new Set();
for (const batch of batches) {
  const summary = await read(`${batch}/batch-summary.json`);
  assert.equal(summary.targetSha256, expected);
  assert.equal(summary.targetExecuted, false);
  const opened = await read(`${batch}/open-session.json`);
  assert.equal(opened.structuredContent.result.sha256, expected);
  const closed = await read(`${batch}/close-session.json`);
  assert.notEqual(closed.isError, true);
  assert.equal(closed.structuredContent.result, null);
  for (const row of summary.results) {
    const response = await read(`${batch}/${row.file}.mcp.json`);
    results.push({ batch, file: row.file, tool: response.name, isError: response.result.isError ?? false,
      error: response.result.structuredContent?.error ?? null });
    if (response.result.isError === true) continue;
    toolContract(response.name).outputSchema.parse(response.result.structuredContent);
    const evidence = evidenceSchema.parse(response.result.structuredContent.evidence);
    assert.equal(evidence.provider.id, 'ida');
    assert.equal(evidence.subject.digest.sha256, expected);
    assert.equal(evidence.analysis_profile.parameters.mode, 'headless');
    assert.equal(evidence.raw_result.metadata_before.imagebase, '0x180000000');
    assert.equal(evidence.raw_result.metadata_before.input_path, evidence.raw_result.metadata_after.input_path);
    workspaces.add(path.dirname(evidence.raw_result.metadata_before.input_path));
    evidenceIds.push(evidence.evidence_id);
  }
}
for (const workspace of workspaces) await assert.rejects(access(workspace), { code: 'ENOENT' });
check('All five batch targets retained the established Game.dll SHA-256 and closed normally', batches.length === 5);
check('Successful responses passed their named tool output contracts and Evidence schema', evidenceIds.length === results.filter(row => !row.isError).length);
const parser = await read('ida95-counter/counter-name-parser-dossier.normalized.json');
check('Counter name comparison is an indirect call through the pointer slot at RVA 0x6BC748', parser.assembly.includes('0x18053c1d9: call cs:qword_1806BC748'));
check('Counter parser tests the low-32-bit result for zero and bounds the six-entry scan', parser.assembly.includes('0x18053c1df: test eax, eax') && parser.assembly.includes('0x18053c1e9: cmp ebx, 6'));
const tables = await read('counter-status-tables.json');
assert.equal(tables.source_sha256, expected);
check('Original-file pointer bytes match the independently read uint64 at the recorded file offset',
  BigInt(tables.comparison_pointer_slot.qword_value) === targetBytes.readBigUInt64LE(Number.parseInt(tables.comparison_pointer_slot.file_offset, 16)));
check('The original comparison slot value does not fall within this PE preferred image address space', BigInt(tables.comparison_pointer_slot.qword_value) < BigInt(tables.image_base));
assert.deepEqual(tables.counter_name_table.map(item => [item.name.text, item.returned_low32]),
  [['1', 480], ['all', 480], ['dodge', 128], ['parry', 64], ['block', 32], ['resist', 256]]);
checks.push('Six original UTF-16 counter names and returned low32 values match the selected raw table');
assert.deepEqual(tables.registry_records.map(item => [item.label.text, item.mask]), [['dodge', '0x80'], ['parry', '0x40'], ['block', '0x20']]);
checks.push('Counter registration labels and masks are separately bound to their original table bytes');
const owner = await read('ida95-follow/registry-owner-instructions.normalized.json');
check('The full returned owner instruction stream includes mask selection and registration calls',
  owner.instructions.includes('0x18039e036: and rax, rdx') && owner.instructions.includes('0x18039e08a: call sub_18039F2F0'));
const registry = await read('ida95-counter/counter-registry-dossier.normalized.json');
check('Registration separates tag 0 dword entries from tag 2 qword entries',
  registry.assembly.includes('0x18039f3a0: cmp eax, 2') && registry.assembly.includes('0x18039f3bd: add qword ptr [rcx+8], 8') && registry.assembly.includes('0x18039f3fd: add qword ptr [rcx+8], 4'));
const status = await read('ida95-follow/registry-secondary-consumer-dossier.normalized.json');
check('The secondary registration reference resolves to a name/table parser with a seven-entry bound',
  status.procedure.address === '0x18039f430' && status.assembly.includes('0x18039f526: cmp ebx, 7') && status.assembly.includes('0x18039f5ed: call sub_18039F2F0'));
const icons = await read('ida95-consumers/counter-mask-consumer-b-dossier.normalized.json');
check('A distinct mask consumer constructs a counter icon resource path', icons.pseudocode.includes('Data/Skills/counter_%S') && icons.procedure.address === '0x1805921b0');
const update = await read('ida95-registry-owners/registry-update-small-dossier.normalized.json');
check('A local object value change at +0x228 reaches registry rebuilding',
  update.assembly.includes('0x1804b4b08: mov [rcx+228h], edx') && update.assembly.includes('0x1804b4baf: call sub_18039D860'));
const xrefs = await read('ida95-counter/counter-registry-xrefs.evidence.json');
const nativeRefs = xrefs.raw_result.observations.find(item => item.tool === 'xrefs_to').result[0].xrefs;
check('The data-only reference at 0x1813ED8B0 is not counted as a caller', nativeRefs.some(item => item.addr === '0x1813ed8b0' && item.type === 'data' && item.fn === null));
const die = await read('die-static/manifest.json');
check('All four DIE runs completed and retained their source hashes', die.Passed && die.Results.length === 4 && die.Results.every(item => item.ExitCode === 0 && item.SourceSha256 === item.AfterSha256));
for (const item of die.Results) {
  const current = createHash('sha256').update(await readFile(item.SourcePath)).digest('hex');
  assert.equal(current, item.SourceSha256);
}
const report = { passed: true, targetSha256: expected, targetExecuted: false, batches, requests: results.length,
  successes: results.filter(row => !row.isError).length, failures: results.filter(row => row.isError),
  evidenceIds, checks, privateWorkspacesConfirmedRemoved: [...workspaces],
  normalizerAudit: await read('ida95-owner-diagnostic/normalizer-audit.json'),
  unknowns: ['Comparison target resolution and Block/block case semantics', 'Live counter readiness and authoritative cast acceptance',
    'chain_skill_prob2 execution consumer', 'Exact protection versions and complete unpacking',
    'Cause of the first unreadable_output responses; recorded later internal normalization succeeded', 'Official server PVP/damage formula'] };
await writeFile(path.join(root, 'verification.json'), JSON.stringify(report, null, 2));
console.log(JSON.stringify({ passed: report.passed, requests: report.requests, successes: report.successes,
  failures: report.failures.length, checks: checks.length, removedWorkspaces: workspaces.size }));
