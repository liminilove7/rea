import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const study = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const root = path.join(study, 'evidence/continuous');
const session = '20261012-chain-value';
const expected = '834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786';
const anchors = [];
async function instructions(directory, file, snippets) {
  const response = JSON.parse(await readFile(path.join(root, directory, file + '.mcp.json'), 'utf8'));
  assert.notEqual(response.result.isError, true);
  assert.equal(response.result.structuredContent.evidence.subject.digest.sha256, expected);
  const normalized = response.result.structuredContent.result;
  const lines = normalized.instructions ?? normalized.assembly;
  assert.ok(Array.isArray(lines));
  const body = lines.join('\n').toLowerCase();
  for (const snippet of snippets) assert.ok(body.includes(snippet.toLowerCase()), file + ': ' + snippet);
  anchors.push({ directory, file, evidenceId: response.result.structuredContent.evidence_id, snippets });
}
await instructions('../round11/ida95-condition-state', 'chain-node-slot1-dossier', [
  '0x18027eaa9: call sub_18027E820', '0x18027eabc: mov edi, [rax+64h]',
  '0x18027eadc: mov ecx, [rax+7A4h]', '0x18027eae2: imul ecx, edi',
  '0x18027eae5: add ecx, [rax+7A8h]']);
await instructions(session, 'chain-value-getter-instructions', [
  '0x18027e997: call sub_1803B2100', '0x18027e9d6: mov ecx, [r14+8]', '0x18027e9dc: mov rax, r14']);
await instructions(session, 'learned-skill-map-getter-instructions', [
  '0x1803b2100: mov r9, [rcx+830h]', '0x1803b21bc: mov rax, [rax+10h]']);
await instructions(session, 'skill-rank-comparator-instructions', ['0x1805427d2: mov eax, [rax+794h]']);
await instructions('20261012-session-a', 'skill-record-parser-instructions', [
  '"chain_category_level"', '0x18053fc9f: mov [rbp+1D50h+var_15CC], eax',
  '"chain_skill_prob1"', '0x18053fdc2: mov [rbp+1D50h+var_15BC], eax',
  '0x18053c73f: call sub_1801200C0', '0x18053c7ba: call sub_1801200C0',
  '0x18053c7c6: mov r8d, 7D8h', '0x18053c7cc: call sub_1806A8642']);
await instructions(session, 'skill-object-constructor-instructions', [
  "0x1803a198e: lea rax, const SkillItem::`vftable'", '0x1803a199b: mov [rcx+60h], rdx']);
await instructions(session, 'skill-object-main-update-instructions', [
  '0x1803b238c: movzx esi, r9w', '0x1803b241c: call sub_1803A1940',
  '0x1803b246b: movsx eax, si', '0x1803b246e: mov [rbx+64h], eax',
  '0x1803b24cd: lea rdx, [rbp+830h]', '0x1803b24da: call sub_1803B1A60']);
await instructions(session, 'skill-list-route-instructions', [
  '0x1804288cb: mov rdx, rbx; jumptable', 'case 44', '0x1804288ce: call sub_180431ED0',
  '0x180428a13: imul r8d, edx, 3E8h', '0x180428a1d: add r8d, esi', '0x180428a20: call sub_1803B27D0',
  '0x180428955: movzx edi, byte ptr [rax+2]', '0x180428978: mov r8d, [rax+0D4h]',
  '0x180428988: movzx r9d, dil', '0x18042898c: call sub_1803B2500']);
await instructions(session, 'skill-value-update-instructions', [
  '0x1803b27e7: call sub_1803B2100', '0x1803b27f1: mov [rax+54h], r10d',
  '0x1803b27ff: lea rcx, [rbx+868h]']);
await instructions(session, 'skill-list-message-instructions', [
  '0x180431f43: mov edi, [rsi+2]', '0x180431fa7: movzx r9d, di', '0x180431fbf: call sub_1803B2370']);
await instructions(session, 'skill-object-group-insert-instructions', [
  '0x1803b1d39: movzx ecx, word ptr [r14+64h]', '0x1803b1d50: cmp [rax+20h], cx']);
await instructions('20261012-session-a', 'skill-cast-entry-instructions', [
  '0x1803b2f7c: movzx r9d, word ptr [rdi+64h]', '0x1803b2f8c: call sub_180014E40']);
await instructions('20261012-session-a', 'skill-player-action-instructions', [
  '0x180014e40: mov [rsp+arg_18], r9w', '0x18001552b: movzx eax, [rsp+8A8h+arg_18]',
  '0x180015533: mov [rbx+14E0h], ax', '0x180015691: mov eax, 80h', '0x18001569d: or [rbx+14E0h], ax']);
await instructions('20261012-session-b', 'skill-casting-tick-instructions', [
  '0x180047c88: movzx r15d, word ptr [rdi+14E0h]', '0x180047cc9: movzx r8d, r15w',
  '0x180047ced: call sub_1803503C0']);
await instructions(session, 'skill-request-serializer-retry-instructions', ['0x1803503e2: mov [rcx+9], r8b']);
await instructions(session, 'skill-item-time-update-retry-instructions', [
  '0x1803a19c0: mov r8d, [rcx+6Ch]', '0x1803a19d5: mov [rcx+6Ch], r8d']);
await instructions(session, 'skill-map-edit-a-instructions', [
  '0x1803a4376: call qword ptr [rax+10h]', '0x1803a4389: mulss xmm0, cs:dword_1808754A0',
  '0x1803a4391: cvttss2si ebp, xmm0', '0x1803a43b0: sub esi, eax',
  '0x1803a43d4: mov edx, esi', '0x1803a43d9: call qword ptr [r8+18h]']);
await instructions('20261012-session-a', 'skill-record-default-instructions', [
  '0x18012014d: xor edx, edx', '0x18012014f: mov r8d, 7D8h', '0x180120158: call sub_1806A8630']);
const resource = JSON.parse(await readFile(path.join(root, session, 'chain-probability-resource-fields.json'), 'utf8'));
const resourceData = await readFile(path.join(study, resource.source));
assert.equal(createHash('sha256').update(resourceData).digest('hex'), resource.sourceSha256);
assert.equal(resource.totalSkillRecords, 7160);
assert.equal(resource.records.length, 185);
assert.equal(resource.records.filter(row => row.chain_skill_prob1 !== null).length, 48);
assert.ok(resource.records.every(row => row.chain_skill_prob1 === null || row.chain_skill_prob1 === '0'));
assert.equal(resource.records.find(row => row.id === '154').chain_skill_prob2, '10');
const map = JSON.parse(await readFile(path.join(root, '20261012-session-a/current-message-name-map.json'), 'utf8'));
assert.ok(map.entries.some(row => row.name === 'S_ADD_SKILL' && row.internal_id === 44));
assert.ok(map.entries.some(row => row.name === 'S_LOAD_SKILL_COOLTIME' && row.internal_id === 51));
assert.ok(map.entries.some(row => row.name === 'S_RESET_SKILL_COOLING_TIME' && row.internal_id === 73));
const table = JSON.parse(await readFile(path.join(root, session, 'original-skill-item-vtable.json'), 'utf8'));
assert.equal(table.targetSha256, expected);
assert.equal(table.rttiTypeName, '.?AVSkillItem@@');
assert.equal(table.slots['0x18'], '0x1803a19c0');
const sample = await readFile(path.join(study, 'samples/Game.dll'));
assert.equal(createHash('sha256').update(sample).digest('hex'), expected);
const report = { passed: true, targetSha256: expected, targetExecuted: false,
  anchoredResponses: anchors.length, anchors, resourceSha256: resource.sourceSha256,
  observations: ['SkillItem type and constructor-to-field-to-group-to-UI identity are linked.',
    'Incoming DWORD is narrowed through 16 bits and sign-extended into +0x64.',
    'Selected cast path forwards a 16-bit representation; the serializer writes its low byte.',
    'Player +0x14E0 can also carry a 0x80 action flag; the outgoing byte is not proved to be pure level.',
    'All explicit prob1 XML fields are zero; other records have absent prob1.',
    'SkillItem +0x6C is distinct from the +0x54 deadline.'],
  inferences: ['The received value and ordered skill map support interpreting +0x64 as a skill level value.',
    'With the observed zero-default XML loading path and no later override, UI linear scores do not depend on +0x64.'],
  unknowns: ['Runtime overrides, actual loaded levels, authoritative server probabilities and byte acceptance.',
    'Protected time helper target and comparison target remain unresolved.'] };
await writeFile(path.join(root, 'chain-object-verification.json'), JSON.stringify(report, null, 2));
console.log(JSON.stringify({ passed: true, anchoredResponses: anchors.length,
  totalSkillRecords: resource.totalSkillRecords, explicitProb1Count: 48, nonzeroExplicitProb1Count: 0 }));
