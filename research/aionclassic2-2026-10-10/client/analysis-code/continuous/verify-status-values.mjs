import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const study = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const root = path.join(study, 'evidence/continuous');
const session = '20261012-status-values';
const expected = '834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786';
const source = await readFile(path.join(study, 'samples/Game.dll'));
assert.equal(createHash('sha256').update(source).digest('hex'), expected);
const anchors = [];
async function instructions(directory, file, snippets) {
  const response = JSON.parse(await readFile(path.join(root, directory, file + '.mcp.json'), 'utf8'));
  assert.notEqual(response.result.isError, true);
  assert.equal(response.result.structuredContent.evidence.subject.digest.sha256, expected);
  const normalized = response.result.structuredContent.result;
  const body = (normalized.instructions ?? normalized.assembly).join('\n').toLowerCase();
  for (const snippet of snippets) assert.ok(body.includes(snippet.toLowerCase()), file + ': ' + snippet);
  anchors.push({ directory, file, evidenceId: response.result.structuredContent.evidence_id, snippets });
}
const route = '20261012-chain-value';
await instructions(route, 'skill-list-route-instructions', [
  '0x180427e45: movsxd rax, dword ptr [rbx+20h]; jumptable 00000001804270A0 case 3',
  '0x180427e54: mov ebx, [rax+4]', '0x180427e57: mov edi, [rax]',
  '0x180427e83: mov r8d, ebx', '0x180427e86: mov edx, edi', '0x180427e8b: call sub_180488F00',
  '0x18042b468: mov rdx, rbx; jumptable 00000001804270A0 case 245', '0x18042b46b: call sub_18043F370']);
await instructions(session, 'received-status-pair-consumer-retry-instructions', [
  '0x180488f1b: mov [rcx+11A4h], edx', '0x180488f24: mov [rcx+11A0h], r8d',
  '0x180488f30: mov [rcx+119Ch], edx', '0x180488f36: call qword ptr [rax+440h]',
  '0x180488f3f: mov edx, 64h', '0x180488f46: call sub_18124E7DF',
  '0x180488f74: cmovz eax, ecx', '0x180488f77: mov [rbx+40h], al']);
await instructions(session, 'received-status-mode-consumer-instructions', [
  '0x1804b4aff: mov esi, [rcx+228h]', '0x1804b4b08: mov [rcx+228h], edx']);
await instructions(session, 'status-value-received-update-instructions', [
  '0x18043f37b: imul eax, [rax], 3E8h', '0x18043f381: mov cs:dword_180D71BCC, eax',
  '0x18043f387: imul eax, ecx, 3E8h', '0x18043f38d: mov cs:dword_180D71BC8, eax']);
await instructions(session, 'status-value-ui-primary-instructions', [
  '0x1801033ff: mov eax, [rsi+11A0h]', '0x180103412: mov eax, [rsi+119Ch]',
  '0x18010343f: cmovz eax, cs:dword_180D71BC8', '0x180103451: cmovz eax, cs:dword_180D71BCC']);
await instructions(session, 'status-value-script-consumer-instructions', [
  '0x18058e31e: mov eax, [rsi+119Ch]', '0x18058e328: mov r8d, [rsi+11A0h]',
  '0x18058e530: mov eax, cs:dword_180D71BCC', '0x18058e54b: mov eax, cs:dword_180D71BC8',
  '0x18058e55e: divss xmm1, xmm0']);
await instructions(session, 'status-pair-lifecycle-caller-instructions', [
  '0x1804bb2e3: mov dword ptr [rdi+2C0h], 7', '0x1804bb32d: xor edx, edx',
  '0x1804bb332: call sub_180488F00', '0x1804bb340: mov [rdi+119Ch], eax']);
await instructions(session, 'hp-zero-player-state-direct-caller-instructions', ['0x18001e12d: call sub_1804BB040']);
await instructions(session, 'player-hp-update-notification-instructions', [
  '0x18006467f: por xmm1, xmm0', '0x180064683: movdqu xmmword ptr [rax+rsi+0D720C0h], xmm1']);
const map = JSON.parse(await readFile(path.join(root, '20261012-session-a/current-message-name-map.json'), 'utf8'));
assert.ok(map.entries.some(row => row.name === 'S_HIT_POINT' && row.internal_id === 3));
assert.ok(map.entries.some(row => row.name === 'S_FLIGHT_POINT' && row.internal_id === 245));
for (const row of map.entries.filter(row => ['S_HIT_POINT', 'S_FLIGHT_POINT'].includes(row.name))) {
  await instructions('20261012-session-a', 'message-name-registration-instructions', [row.name_instruction, row.id_instruction]);
}
const slots = JSON.parse(await readFile(path.join(root, session, 'original-status-update-slots.json'), 'utf8'));
assert.equal(slots.targetSha256, expected);
assert.equal(slots.nativeTargetExecuted, false);
for (const table of slots.tables) {
  for (const slot of table.slots) {
    const pointerOffset = Number.parseInt(table.fileOffset, 16) + Number.parseInt(slot.slotOffset, 16);
    assert.equal(pointerOffset, Number.parseInt(slot.pointerFileOffset, 16));
    assert.equal('0x' + source.readBigUInt64LE(pointerOffset).toString(16), slot.value);
  }
}
const report = { passed: true, targetSha256: expected, nativeTargetExecuted: false, wholeClientComplete: false,
  verifiedAt: new Date().toISOString(), anchors, originalStatusUpdateSlots: slots.tables,
  interpretations: ['Named local HP notification is bound to its payload, object setter and display consumer.',
    'Named flight-point notification is distinct from the HP fields and scales both incoming values by 1000.'],
  unknowns: ['Protected HP ratio helper full arithmetic', 'Runtime values and display transition behavior',
    'Authoritative current-server damage and PvP formula', 'All indirect Player reset callers'] };
await writeFile(path.join(root, 'status-values-verification.json'), JSON.stringify(report, null, 2));
console.log(JSON.stringify({ passed: true, instructionAnchors: anchors.length, vtableSlots: slots.tables.reduce((total, row) => total + row.slots.length, 0) }));
