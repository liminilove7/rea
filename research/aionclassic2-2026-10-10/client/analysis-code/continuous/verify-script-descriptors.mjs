import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const study = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const root = path.join(study, 'evidence/continuous');
const session = '20261012-script-descriptors';
const expected = 'ea42f2e51de3d46b14e958f11c4f33dc9e78a92cf62765c6a42f0cb79584ca27';
const source = await readFile(path.join(study, 'samples/ScriptDLL64.dll'));
assert.equal(createHash('sha256').update(source).digest('hex'), expected);
const read = async (directory, file) => JSON.parse(await readFile(path.join(root, directory, file), 'utf8'));
const manifest = JSON.parse(await readFile(path.join(root, 'original-four-module-entries.json'), 'utf8'));
const meta = manifest.modules.find(row => row.sample === 'ScriptDLL64.dll');
function offset(rva, size) {
  const matches = meta.sections.filter(row => row.rva <= rva && rva + size <= row.rva + row.rawSize);
  assert.equal(matches.length, 1);
  return matches[0].fileOffset + rva - matches[0].rva;
}
const anchors = [];
async function instructions(directory, file, snippets) {
  const response = await read(directory, file + '.mcp.json');
  assert.notEqual(response.result.isError, true);
  assert.equal(response.result.structuredContent.evidence.subject.digest.sha256, expected);
  const body = response.result.structuredContent.result.instructions.join('\n').toLowerCase();
  for (const snippet of snippets) assert.ok(body.includes(snippet.toLowerCase()), file + ': ' + snippet);
  anchors.push({ directory, file, evidenceId: response.result.structuredContent.evidence_id, snippets });
}
await instructions(session, 'shared-descriptor-initialize', ['0x1801c5066: lea rcx, xmmword_180F054B8',
  '0x1801c506d: mov r8d, 0A0h', "0x1801c507f: lea rax, const CMonster::`vftable'",
  '0x1801c5091: mov cs:qword_180F054B0, rax', '0x1801c50c8: call sub_1806BF3E0']);
await instructions(session, 'first-script-constructor-shared-descriptor', ['1Skill_Bs_Ev15s_UseSk1S',
  '0x1800010d5: lea rax, qword_180F054B0', '0x1800010e6: mov cs:qword_180F84A68, rax']);
await instructions('20261012-script-interface', 'compiled-magic-damage-script-registration-instructions', [
  '0x180172fa5: lea rax, qword_180F054B0', '0x180172faf: mov cs:qword_180F708A8, rax']);
await instructions(session, 'script-interface-maintenance-body', ['0x1806e0507: mov rdx, [rbx+20h]',
  '0x1806e050e: call qword ptr [rax]', '0x1806e05ad: call qword ptr [rax+8]']);
await instructions(session, 'external-consumer-first', ['0x1806c22d9: mov rcx, cs:qword_18103F710',
  '0x1806c22ea: call qword ptr [r9+40h]', '0x1806c2386: mov rcx, cs:qword_18103F710',
  '0x1806c2395: call qword ptr [rax+48h]']);
await instructions(session, 'external-consumer-second', ['0x1806c3162: call qword ptr [rax+40h]',
  '0x1806c3317: mov rcx, cs:qword_18103F710', '0x1806c3326: call qword ptr [rax+48h]']);
await instructions(session, 'external-consumer-last', ['0x180923a44: mov rcx, cs:qword_18103F710',
  '0x180923a55: call qword ptr [r9+50h]', '0x180923a9e: call qword ptr [r8+58h]',
  '0x180923abf: call qword ptr [rax+58h]']);
await instructions(session, 'parent-vtable-noop-return', ['0x1806bf100: retn 0']);
// Reuse the earlier successful same-sample body; this session's retry was interrupted.
await instructions('20261012-script-interface', 'compiled-script-method-b-instructions', [
  '0x1806bf0f0: xor eax, eax', '0x1806bf0f2: retn']);
const parent = await read(session, 'original-shared-script-parent-object.json');
assert.equal(parent.targetSha256, expected);
assert.equal(parent.typeName, '.?AVCMonster@@');
const leaRva = Number.parseInt(parent.constructorLeaRva, 16);
const leaRaw = offset(leaRva, 7);
assert.equal(source.subarray(leaRaw, leaRaw + 7).toString('hex'), parent.constructorLeaBytes);
assert.equal(leaRva + 7 + source.readInt32LE(leaRaw + 3), Number.parseInt(parent.vtableRva, 16));
assert.equal(source.readBigUInt64LE(offset(Number.parseInt(parent.initializerPointerCellRva, 16), 8)), 0x1801c5060n);
const child = await read('20261012-script-interface', 'original-magic-damage-script-binding.json');
assert.deepEqual(parent.functions.map(row => row.preferredVa), child.functions.map(row => row.preferredVa));
for (const row of parent.functions) assert.equal(source.readBigUInt64LE(Number.parseInt(row.pointerFileOffset, 16)), BigInt(row.preferredVa));
const scan = await read(session, 'original-descriptor-reference-candidates.json');
assert.equal(scan.targetSha256, expected);
assert.equal(scan.nativeTargetExecuted, false);
const counts = {};
for (const row of scan.ripReferences) {
  const rva = Number.parseInt(row.instructionRva, 16);
  const raw = Number.parseInt(row.fileOffset, 16);
  assert.equal(raw, offset(rva, row.instructionSize));
  assert.equal(source.subarray(raw, raw + row.instructionSize).toString('hex'), row.originalBytes);
  assert.equal(BigInt(row.instructionVa), BigInt(scan.imagebase) + BigInt(rva));
  counts[row.targetRva] = (counts[row.targetRva] ?? 0) + 1;
}
for (const rva of ['0x1c5091', '0x10d5', '0x172fa5']) assert.ok(scan.ripReferences.some(row => row.instructionRva === rva && row.targetRva === '0xf054b0'));
assert.ok(scan.coverage.incompleteRanges.length > 0);
const report = { passed: true, targetSha256: expected, nativeTargetExecuted: false, wholeModuleComplete: false,
  verifiedAt: new Date().toISOString(), anchors, parentType: parent.typeName, parentVirtualSlots: parent.functions,
  candidateScanCounts: counts, candidateScanCoverage: scan.coverage,
  unknowns: ['All register-derived parent-pointer consumers and semantic inheritance behavior',
    'Exact implementation and runtime identity of the external interface',
    'Protected loader initializer execution and authoritative damage formula'] };
await writeFile(path.join(root, 'script-descriptors-verification.json'), JSON.stringify(report, null, 2));
console.log(JSON.stringify({ passed: true, instructionAnchors: anchors.length, candidateReferencesChecked: scan.ripReferences.length, parentVirtualSlots: parent.functions.length }));
