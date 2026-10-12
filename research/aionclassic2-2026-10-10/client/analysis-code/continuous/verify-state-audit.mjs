import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const study = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const root = path.join(study, 'evidence/continuous');
const session = '20261012-state-audit';
const digest = '834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786';
const source = await readFile(path.join(study, 'samples/Game.dll'));
assert.equal(createHash('sha256').update(source).digest('hex'), digest);
const anchors = [];
async function instructions(file, snippets, directory = session) {
  const response = JSON.parse(await readFile(path.join(root, directory, file + '.mcp.json'), 'utf8'));
  assert.notEqual(response.result.isError, true);
  assert.equal(response.result.structuredContent.evidence.subject.digest.sha256, digest);
  const body = response.result.structuredContent.result.instructions.join('\n').toLowerCase();
  for (const snippet of snippets) assert.ok(body.includes(snippet.toLowerCase()), file + ': ' + snippet);
  anchors.push({ directory, file, evidenceId: response.result.structuredContent.evidence_id, snippets });
}
await instructions('ambiguous-state-setter-instructions', ['0x180581b40: mov [rcx+2ECh], edx']);
await instructions('ambiguous-state-setter-caller-instructions', [
  '0x18009bb5e: call sub_1805802E0', '0x18009bb63: mov rdi, rax',
  '0x18009bd53: mov rcx, rdi', '0x18009bd56: call sub_180581B40']);
await instructions('model-widget-cast-instructions', [
  '0x1805802f4: mov rbx, rcx', "0x1805802fe: lea rax, const UI3DView::`vftable'",
  '0x180580305: mov [rbx], rax', '0x1805805cf: mov rax, rbx']);
await instructions('player-lifecycle-reset-wrapper-instructions', ['0x1800638fa: call sub_1804BB4C0']);
await instructions('actor-last-skill-reset-instructions', [
  '0x1804bb5ee: mov [rbx+2ECh], edi', '0x1804bb608: mov [rbx+324h], rdi'], '20261012-session-b');
await instructions('object-reset-status-loader-instructions', [
  '0x18032329c: lea rcx, [rbx+1F8h]', '0x1803232a3: call qword ptr [rbx+1F8h]']);
await instructions('local-status-message-handler-retry-instructions', [
  '0x18042df00: call sub_1804F9810', '0x18042df12: mov rcx, rax', '0x18042df15: call sub_1804FCB00',
  '0x18042df48: lea rdx, rva byte_180D71B78[r9]', '0x18042df5d: movups xmmword ptr [rdx-80h], xmm0']);
await instructions('local-status-player-object-consumer-instructions', [
  '0x1804fcb63: mov edx, [rbx+0A4h]', '0x1804fcb69: call sub_1804B4AF0',
  '0x1804fcb6e: mov r8d, [rbx+3Ch]', '0x1804fcb75: mov edx, [rbx+40h]', '0x1804fcb78: call sub_180488F00']);
const read = async file => JSON.parse(await readFile(path.join(root, session, file), 'utf8'));
const tables = await read('original-character-result-slots.json');
assert.equal(tables.targetSha256, digest);
for (const table of tables.tables) {
  for (const [slot, value] of Object.entries(table.slots)) {
    assert.equal('0x' + source.readBigUInt64LE(Number.parseInt(table.fileOffset, 16) + Number.parseInt(slot, 16)).toString(16), value);
  }
}
assert.equal(tables.tables.find(row => row.type === '.?AVPlayer@@').slots['0x1f8'], '0x1800638e0');
const unwind = await read('original-player-reset-unwind-xrefs.json');
assert.equal(unwind.targetSha256, digest);
for (const entry of unwind.entries) {
  assert.equal(entry.flags, 4);
  assert.equal(entry.version, 1);
  const header = Number.parseInt(entry.unwindInfoRva, 16);
  const tail = header + 4 + Math.ceil(entry.countOfCodes / 2) * 4;
  assert.equal(tail, Number.parseInt(entry.referenceRva, 16));
  assert.equal(source.subarray(header, header + 4).toString('hex'), entry.rawHeader);
  assert.equal(source.subarray(tail, tail + 12).toString('hex'), entry.chainEntryBytes);
  assert.equal(source.readUInt32LE(tail), 0x638e0);
  assert.equal(source.readUInt32LE(tail + 4), 0x638f6);
  assert.equal(source.readUInt32LE(tail + 8), 0x8a1040);
}
const emulation = JSON.parse(await readFile(path.join(root, '20261012-clock-emulation-memory/report.json'), 'utf8'));
assert.equal(emulation.targetSha256, digest);
assert.equal(emulation.nativeTargetExecuted, false);
assert.equal(emulation.emulatedTargetInstructions, true);
assert.equal(emulation.results[0].fixturePassed, true);
const trials = [];
for (const row of emulation.results.slice(1)) {
  const trace = (await readFile(path.join(root, '20261012-clock-emulation-memory', row.trace), 'utf8'))
    .trim().split('\n').map(line => JSON.parse(line));
  assert.equal(row.steps, trace.filter(line => line.kind === 'instruction').length);
  const reads = trace.filter(line => line.kind === 'shadow_image_read');
  assert.deepEqual(reads, [{ kind: 'shadow_image_read', rip: '0x181256113', address: '0x1810e4790', size: 8, bytes: '442408e916feffff' }]);
  assert.equal(row.imageWrites, 0);
  assert.equal(row.stop.reason, 'unmapped_or_disallowed_memory');
  assert.equal(row.finalRegisters.rip, '0xfffffe168e9c20f3');
  trials.push({ label: row.label, steps: row.steps, observedShadowReads: reads, stop: row.stop });
}
const report = { passed: true, targetSha256: digest, nativeTargetExecuted: false, wholeClientComplete: false,
  verifiedAt: new Date().toISOString(), anchors, originalVtableSlotsChecked: tables.tables,
  chainedUnwindEntries: unwind.entries, auxiliaryEmulation: trials,
  limitations: ['Selected pointer paths establish object identity only for those paths.',
    'Exception metadata and equal virtual slot offsets do not establish business callers.',
    'Offline original-image faults are not observed game process behavior or resolved clock API identity.'] };
await writeFile(path.join(root, 'state-audit-verification.json'), JSON.stringify(report, null, 2));
console.log(JSON.stringify({ passed: true, instructionAnchors: anchors.length, unwindEntries: unwind.entries.length, auxiliaryTrials: trials.length }));
