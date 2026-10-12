import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const study = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const root = path.join(study, 'evidence/continuous');
const session = '20261012-system-game-binding';
const cryDigest = '8705aeef77411a28e178832f2f242128b0b018b9546f58878c9e69df8f4e9061';
const gameDigest = '834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786';
const cry = await readFile(path.join(study, 'samples/CrySystem.dll'));
assert.equal(createHash('sha256').update(cry).digest('hex'), cryDigest);
assert.equal(createHash('sha256').update(await readFile(path.join(study, 'samples/Game.dll'))).digest('hex'), gameDigest);
const anchors = [];
async function instructions(directory, file, digest, snippets) {
  const response = JSON.parse(await readFile(path.join(root, directory, file + '.mcp.json'), 'utf8'));
  assert.notEqual(response.result.isError, true);
  assert.equal(response.result.structuredContent.evidence.subject.digest.sha256, digest);
  const body = response.result.structuredContent.result.instructions.join('\n').toLowerCase();
  for (const snippet of snippets) assert.ok(body.includes(snippet.toLowerCase()), file + ': ' + snippet);
  anchors.push({ directory, file, targetSha256: digest, evidenceId: response.result.structuredContent.evidence_id, snippets });
}
await instructions(session, 'system-initialization-first-slot-instructions', cryDigest, [
  '0x18016e10b: mov r14, rdx', '0x18016e10e: mov rdi, rcx',
  '0x18016e3b8: lea rdx, aCreategameinst', 'CreateGameInstance', '0x18016e3bf: call sub_1806BCFC7',
  '0x18016e3cc: mov rbx, rax', '0x18016e3f4: call rbx', '0x18016e3f6: mov [rdi+3538h], rax',
  '0x18016e44c: mov [r13+0], rdi', '0x18016e478: lea r8, sub_180170F20',
  '0x18016e4b6: mov rcx, [rdi+3538h]', '0x18016e4bd: mov rdx, rdi', '0x18016e4d5: call qword ptr [rax]']);
await instructions(session, 'system-game-initialization-callback-instructions', cryDigest, [
  '0x180170f2e: mov rcx, [rcx]', '0x180170f34: call qword ptr [rax+0D8h]',
  '0x180170f4b: mov rcx, rax', '0x180170f58: mov rdx, [rbx]', '0x180170f5b: call qword ptr [r10]']);
await instructions(session, 'system-game-interface-slot-d8-instructions', cryDigest, ['0x180171f70: mov rax, [rcx+3538h]']);
await instructions('20261012-session-c', 'game-interface-slot-0-instructions', gameDigest, [
  '0x180044c48: mov rdi, rdx', '0x180044c4b: mov rsi, rcx', '0x180044c74: mov [rsi+6630h], rdi']);
await instructions(session, 'system-game-interface-getter-instructions', cryDigest, ['0x18016fa70: mov rax, [rcx+26F0h]']);
await instructions(session, 'system-script-binding-slot-148-instructions', cryDigest, ['0x180172040: mov rax, [rcx+2DA0h]']);
await instructions(session, 'system-script-binding-initializer-instructions', cryDigest, ['0x18013e781: call qword ptr [rax+148h]']);
const slots = JSON.parse(await readFile(path.join(root, session, 'original-system-game-script-slots.json'), 'utf8'));
assert.equal(slots.targetSha256, cryDigest);
assert.equal(slots.type, 'CSystem');
for (const row of slots.slots) {
  const position = Number.parseInt(slots.tableFileOffset, 16) + Number.parseInt(row.slot, 16);
  assert.equal(position, Number.parseInt(row.fileOffset, 16));
  assert.equal('0x' + cry.readBigUInt64LE(position).toString(16), row.preferredVa);
}
assert.equal(slots.slots.find(row => row.slot === '0x0').preferredVa, '0x18016e0f0');
assert.equal(slots.slots.find(row => row.slot === '0xd8').preferredVa, '0x180171f70');
assert.equal(slots.slots.find(row => row.slot === '0x148').preferredVa, '0x180172040');
const report = { passed: true, sourceDigests: { 'CrySystem.dll': cryDigest, 'Game.dll': gameDigest },
  nativeTargetExecuted: false, wholeClientComplete: false, verifiedAt: new Date().toISOString(), anchors,
  originalSystemSlots: slots.slots,
  observations: ['Named Game factory pointer is invoked and stored in CSystem +3538.',
    'Both returned-Game initialization paths pass the CSystem pointer; callback uses the bound +D8 getter.',
    'Game initialization stores that parameter into its +6630 field.',
    'System slot +140 returns +26F0 and is not the bound Game getter; +148 returns +2DA0 for script binding.'],
  unknowns: ['Runtime DLL paths and original protected API targets', 'Full built-in script object semantics and ScriptDLL external parameter binding'] };
await writeFile(path.join(root, 'system-game-binding-verification.json'), JSON.stringify(report, null, 2));
console.log(JSON.stringify({ passed: true, instructionAnchors: anchors.length, modules: 2, selectedSystemSlots: slots.slots.length }));
