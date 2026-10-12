import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const study = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const root = path.join(study, 'evidence/continuous');
const identities = new Map([
  ['Game.dll', '834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786'],
  ['CrySystem.dll', '8705aeef77411a28e178832f2f242128b0b018b9546f58878c9e69df8f4e9061'],
]);
const original = new Map();
for (const [sample, digest] of identities) {
  const bytes = await readFile(path.join(study, 'samples', sample));
  assert.equal(createHash('sha256').update(bytes).digest('hex'), digest);
  original.set(sample, bytes);
}
const anchors = [];
async function anchor(session, sample, name, fragments) {
  const prefix = path.join(root, session, name);
  const normalized = JSON.parse(await readFile(prefix + '.normalized.json', 'utf8'));
  const response = JSON.parse(await readFile(prefix + '.mcp.json', 'utf8'));
  assert.notEqual(response.result.isError, true);
  assert.equal(response.result.structuredContent.evidence.subject.digest.sha256, identities.get(sample));
  const lines = normalized.instructions;
  assert.ok(Array.isArray(lines));
  for (const fragment of fragments) assert.ok(lines.some(line => line.includes(fragment)), `${name}: ${fragment}`);
  anchors.push({ session, sample, name, evidenceId: response.result.structuredContent.evidence_id, fragments });
}
const a = '20261012-session-a';
const b = '20261012-session-b';
const c = '20261012-session-c';
const t = '20261012-cry-timer';
await anchor(a, 'Game.dll', 'skill-record-parser-instructions', ['0x18053d7c3: mov [rbp+1D50h+var_1C90], eax',
  '0x18053d80d: mov [rbp+1D50h+var_1C80], eax', '0x18053d813: lea rcx, qword_18095A6A8',
  '0x18053d81d: call sub_18034FFE0', '0x18053d857: mov [rbp+1D50h+var_1C8C], eax']);
await anchor(b, 'Game.dll', 'skill-success-flag-update-instructions', ['0x1803b2567: mov [rax+50h], ebx',
  '0x1803b257f: mov [r14+54h], eax', '0x1803b2606: mov ecx, [rax+0E0h]',
  '0x1803b2610: mov rbp, cs:qword_18095A6A8', '0x1803b26fb: mov edi, [rsp+838h+var_744]',
  '0x1803b272e: mov [rsi+50h], edi', '0x1803b2739: mov [rsi+54h], eax']);
await anchor(b, 'Game.dll', 'character-constructor-retry-instructions', ['0x1804b157c: lea rcx, [rdi+2C0h]',
  '0x1804b1596: xor edx, edx', '0x1804b159f: mov r8d, 27Ch', '0x1804b1661: call sub_1806A8630']);
await anchor(b, 'Game.dll', 'actor-last-skill-reset-instructions', ['0x1804bb548: xor edi, edi',
  '0x1804bb5ee: mov [rbx+2ECh], edi', '0x1804bb608: mov [rbx+324h], rdi']);
await anchor(c, 'Game.dll', 'player-batch-reset-body-retry-instructions', ['0x1800638fa: call sub_1804BB4C0']);
await anchor(c, 'Game.dll', 'options-transmit-instructions', ['0x180062bc3: call sub_18039ECF0',
  '0x180062bf1: call sub_1805092B0', '0x180062c69: call qword ptr [rax+118h]', '0x180062c9c: call sub_180359240']);
await anchor(c, 'Game.dll', 'options-content-loader-instructions', ['"<options>\\r\\n"',
  '0x18050a112: mov [rsi], eax', '0x18050a140: mov [rax], cx']);
await anchor(c, 'Game.dll', 'options-save-filename-instructions', ['"%s_%s.opt"',
  '"%s_%s_environment.opt"', '"%s_%s_quickbar.opt"', '0x180125be1: call sub_18050BED0']);
await anchor(c, 'Game.dll', 'options-local-output-instructions', ['"wb"',
  '0x18050bf6d: call sub_1805092B0', '0x18050bf82: call sub_1800B8DD0',
  '0x18050bfaa: call sub_181251910', '0x18050bfbe: call sub_181251910', '0x18050bfdb: call sub_1812440B0']);
await anchor(c, 'Game.dll', 'options-request-send-instructions', ['"SaveClientSetting type(%d)"',
  '0x1803593b7: call sub_18041FD80']);
await anchor(a, 'Game.dll', 'message-router-instructions', ['0x1804283b9: movsxd rdx, dword ptr [rbx+20h];',
  '0x1804283ff: call sub_18005A910']);
await anchor(c, 'Game.dll', 'options-received-input-instructions', ['0x18005a9a1: call qword ptr [r10+120h]',
  '0x18005a9bb: call sub_18050A200']);
await anchor(c, 'Game.dll', 'game-export-create-instructions', ['0x18033a8a0: lea rax, qword_180D647C0']);
await anchor(c, 'Game.dll', 'game-interface-slot-0-instructions', ['0x180044c48: mov rdi, rdx',
  '0x180044c4b: mov rsi, rcx', '0x180044c74: mov [rsi+6630h], rdi']);
assert.equal(0x180d647c0n + 0x6630n, 0x180d6adf0n);
await anchor(t, 'CrySystem.dll', 'system-constructor-instructions', ['0x18016ce11: add rcx, 8',
  '0x18016ce15: call sub_18018A700']);
await anchor(t, 'CrySystem.dll', 'system-timer-getter-instructions', ['0x1800212f0: lea rax, [rcx+8]']);
await anchor(t, 'CrySystem.dll', 'timer-frame-time-instructions', ['0x180171e70: movss xmm0, dword ptr [rcx+30h]']);
await anchor(t, 'CrySystem.dll', 'timer-current-time-instructions', ['0x180171df0: movss xmm0, dword ptr [rcx+34h]']);
await anchor(t, 'CrySystem.dll', 'timer-update-slot-instructions', ['0x18018a902: call qword ptr [rcx+8]',
  '0x18018a947: divss xmm1, xmm0', '0x18018a94e: movss dword ptr [rbx+30h], xmm1',
  '0x18018a93a: movss dword ptr [rbx+34h], xmm1', '0x18018aa00: movss dword ptr [rcx+30h], xmm1']);
await anchor(t, 'CrySystem.dll', 'timer-frequency-initialization-instructions', ['0x18018a84a: mov [rbx+20h], rax',
  '0x18018a857: mov qword ptr [rbx+20h], 3E8h', '0x18018a85f: lea rax, sub_18018B080',
  '0x18018a866: mov [rbx+8], rax']);
const tables = JSON.parse(await readFile(path.join(root, t, 'original-timer-system-tables.json'), 'utf8'));
assert.equal(tables.source_sha256, identities.get('CrySystem.dll'));
for (const table of tables.tables) {
  for (const slot of table.slots) {
    const offset = Number.parseInt(slot.file_offset, 16);
    assert.equal(original.get('CrySystem.dll').subarray(offset, offset + 8).toString('hex'), slot.bytes_hex);
    assert.equal(original.get('CrySystem.dll').readBigUInt64LE(offset), BigInt(slot.original_pointer));
  }
}
const options = JSON.parse(await readFile(path.join(root, c, 'chain-option-resource-definitions.json'), 'utf8'));
assert.equal(createHash('sha256').update(await readFile(options.source_path)).digest('hex'), options.source_sha256);
assert.deepEqual(options.records.find(row => row.name === 'chainskill'), {
  default: '', desc: '', name: 'chainskill', save_frequently: '1', setting_type: '1', type: 'binary', version: '153',
});
const resources = JSON.parse(await readFile(path.join(root, c, 'block-skill-resource-fields.json'), 'utf8'));
assert.equal(createHash('sha256').update(await readFile(resources.source_path)).digest('hex'), resources.source_sha256);
assert.equal(resources.records.length, 17);
const shield = resources.records.find(row => row.id === '154');
assert.equal(shield.delay_id, '123');
assert.equal(shield.delay_type, '0');
assert.equal(shield.delay_time, '15000');
assert.equal(shield.chain_skill_prob2, '10');
assert.equal(shield.chain_skill_prob1, undefined);
await writeFile(path.join(root, 'storage-time-cooldown-verification.json'), JSON.stringify({ passed: true,
  targetExecuted: false, analysisComplete: false, anchors,
  checks: ['Received cooldown update follows the same group key written by named resource parsing',
    'Local option file stream and network request consumers traced separately from serialization',
    'Game global system pointer equals the initialized singleton member address',
    'CrySystem timer slots, member construction and counter/frequency calculations anchored',
    'Both original DLL hashes and current resource hashes retained'],
  limitations: ['Static consistency checks do not establish game execution, wall-clock window length or server acceptance.',
    'Counter API targets inside protection stubs and exhaustive indirect state writers remain unknown.'] }, null, 2));
console.log(JSON.stringify({ passed: true, anchoredResponses: anchors.length }));
