import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const study = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const root = path.join(study, 'evidence/continuous');
const session = path.join(root, '20261012-session-a');
const expected = '834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786';
const bytes = await readFile(path.join(study, 'samples/Game.dll'));
assert.equal(createHash('sha256').update(bytes).digest('hex'), expected);
const checks = [];
const anchors = [];
async function instructions(file, expectedLines) {
  const x = JSON.parse(await readFile(path.join(session, file + '.normalized.json'), 'utf8'));
  const lines = typeof x.instructions === 'string' ? x.instructions.split('\n') : x.instructions;
  for (const line of expectedLines) assert.ok(lines.includes(line), `${file}: ${line}`);
  const response = JSON.parse(await readFile(path.join(session, file + '.mcp.json'), 'utf8'));
  assert.notEqual(response.result.isError, true);
  anchors.push({ file, evidenceId: response.result.structuredContent.evidence_id, instructions: expectedLines });
}
await instructions('skill-check-instructions', [
  '0x18061ef19: call sub_1806A8642', '0x18061ef98: shr rcx, 2',
  '0x18061ef9c: and ecx, 20h', '0x18061efa1: or edx, 40h',
  '0x18061efaf: bts ecx, 7', '0x18061efc1: bts eax, 0Dh',
  '0x18061efcb: and eax, [rbp+2ECh]', '0x18061efd1: mov [rsi], eax']);
checks.push('Skill counter mask is translated and intersected with the local object state, then written to an output argument');
await instructions('counter-state-source-instructions', [
  '0x18047717f: movss xmm1, cs:dword_180874FA8',
  '0x1804771a3: bts ecx, 7', '0x1804771b6: bts r8d, 0Dh',
  '0x1804771c5: call sub_1804BC8D0']);
checks.push('Counter source uses the same state conversion and passes its float constant in XMM1 to the setter');
await instructions('state-owner-body-1804bc8d0', [
  '0x1804bc944: mulss xmm2, cs:dword_1808754A0',
  '0x1804bc94c: or eax, r8d', '0x1804bc94f: mov [rcx+2ECh], eax',
  '0x1804bc97c: mov [rcx+2F8h], eax']);
checks.push('Setter stores the converted remaining counter and ORs the flag without incrementing a charge counter at these locations');
await instructions('state-owner-body-1804bca40', [
  '0x1804bca97: mulss xmm0, cs:dword_1808754A0',
  '0x1804bcb14: sub edx, eax', '0x1804bcb16: mov [rbx+2F8h], edx',
  '0x1804bcb1e: btr ecx, 7', '0x1804bcb28: mov [rbx+2F8h], edi']);
checks.push('Block state counter is decremented and its bit cleared when the recorded remainder is exhausted');
await instructions('skill-eligibility-main-instructions', [
  '0x18061fa37: call sub_18061EE50', '0x18061fa40: cmp dword ptr [rbp+700h+arg_0], ebx',
  '0x18061fa46: jz loc_18061FB29']);
checks.push('Unmatched condition output reaches the rejecting branch of the main client check');
await instructions('skill-state-boolean-instructions', [
  '0x180620abc: call sub_18061F860', '0x180620ac3: jnz short loc_180620B00',
  '0x180620b00: xor eax, eax']);
checks.push('Boolean wrapper treats the nonzero main-check result as unavailable');
await instructions('skill-record-default-instructions', [
  '0x18012014d: xor edx, edx', '0x18012014f: mov r8d, 7D8h', '0x180120158: call sub_1806A8630']);
await instructions('skill-record-parser-instructions', [
  '0x18053c737: lea rcx, [rbp+1D50h+var_1D60]', '0x18053c73f: call sub_1801200C0']);
checks.push('XML record parsing initializes the 2008-byte record through the observed zeroing constructor');
const constants = JSON.parse(await readFile(path.join(session, 'counter-trigger-duration-constant.json'), 'utf8'));
assert.equal(constants.sha256, expected);
for (const c of constants.values) {
  const offset = Number.parseInt(c.file_offset, 16);
  assert.equal(bytes.subarray(offset, offset + 4).toString('hex'), c.bytes_hex);
  assert.equal(bytes.readFloatLE(offset), c.float32);
}
assert.equal(constants.values.find(c => c.rva === '0x874fa8').float32, 3);
assert.equal(constants.values.find(c => c.rva === '0x8754a0').float32, 1000);
checks.push('Original float bytes establish the observed 3.0 and 1000.0 constants independently');
const registry = JSON.parse(await readFile(path.join(session, 'current-message-name-map.json'), 'utf8'));
const names = new Map(registry.entries.map(row => [row.name, row.internal_id]));
assert.equal(names.get('S_SKILL_SUCCEDED'), 43);
assert.equal(names.get('S_USE_SKILL'), 33);
assert.equal(names.get('S_SKILL_CANCELED'), 42);
assert.equal(names.get('S_SKILL_ACTIVATED'), 208);
checks.push('Current named skill message registrations retain their internal IDs and source spelling');
await writeFile(path.join(root, 'counter-mechanism-verification.json'), JSON.stringify({ passed: true,
  targetSha256: expected, targetExecuted: false, analysisComplete: false, checks, anchors,
  limitations: ['Static branch and byte checks do not establish live server acceptance.',
    'Elapsed-time interface units and skill-use consumption require their downstream evidence.'] }, null, 2));
console.log(JSON.stringify({ passed: true, semanticChecks: checks.length, anchoredResponses: anchors.length }));
