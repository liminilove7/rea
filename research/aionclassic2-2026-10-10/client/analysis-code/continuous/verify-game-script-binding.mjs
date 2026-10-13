import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const study = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const root = path.join(study, 'evidence/continuous');
const session = '20261013-game-script-binding';
const expected = '834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786';
const scriptDigest = 'ea42f2e51de3d46b14e958f11c4f33dc9e78a92cf62765c6a42f0cb79584ca27';
const source = await readFile(path.join(study, 'samples/Game.dll'));
assert.equal(createHash('sha256').update(source).digest('hex'), expected);
const read = async (directory, file) => JSON.parse(await readFile(path.join(root, directory, file), 'utf8'));
const anchors = [];
async function instructions(directory, file, digest, snippets) {
  const response = await read(directory, file + '.mcp.json');
  assert.notEqual(response.result.isError, true);
  assert.equal(response.result.structuredContent.evidence.subject.digest.sha256, digest);
  const result = response.result.structuredContent.result;
  const body = (result.instructions ?? result.assembly).join('\n').toLowerCase();
  for (const snippet of snippets) assert.ok(body.includes(snippet.toLowerCase()), file + ': ' + snippet);
  anchors.push({ directory, file, targetSha256: digest, evidenceId: response.result.structuredContent.evidence_id, snippets });
}
const game = (file, snippets) => instructions(session, file, expected, snippets);
await game('game-script-loader', ['0x180074c71: lea r8, aScriptdll64Dll', 'ScriptDLL64.dll',
  '0x180074c8c: call sub_18124A742', '0x180074c92: mov cs:qword_180938AF0, rax']);
await game('game-script-interface-factory', ['0x180074cfa: lea rdx, aGetinterface',
  '0x180074d09: call sub_18124AD87', '0x180074d3d: lea rcx, off_180938A90',
  '0x180074d44: call rax', '0x180074d46: mov cs:qword_180938AF8, rax',
  '0x180074d55: cmp eax, 28h', 'interface version', '0x18007503e: call qword ptr [rax+8]',
  '0x18007507a: call qword ptr [rax+10h]', '0x18007508e: call qword ptr [rax+18h]',
  '0x1800750a2: call qword ptr [rax+20h]', '0x1800750b6: call qword ptr [rax+28h]',
  '0x1800750ca: call qword ptr [rax+48h]',
  '0x180075084: mov cs:qword_180938AC8, rax', '0x180075098: mov cs:qword_180938AD0, rax',
  '0x1800750ac: mov qword ptr cs:xmmword_180938AE0, rax',
  '0x1800750c0: mov qword ptr cs:xmmword_180938AE0+8, rax', '0x1800750d5: mov cs:qword_180938AD8, rax']);
await game('game-script-init-error-consumer', ['0x180046128: call sub_180074CD0',
  '0x18004612d: test eax, eax', '0x180046138: lea rdx, aErrorFailedToI', '0x180046145: xor al, al']);
await game('game-caller-register-script', ['0x180075108: call qword ptr [rax]',
  '0x180075112: lea rdx, [rbx+8]', '0x18007514c: lea rcx, [rdi+8]',
  '0x18007515e: mov [rsp+78h+var_18], rbx', '0x180075163: call sub_180079670']);
await game('game-caller-register-secondary', ['0x180075187: mov rax, [rcx+28h]',
  '0x180075204: call sub_180075300', '0x180075282: lea rcx, [rbp+18h]', '0x1800752d2: mov [rax], rsi']);
await game('game-caller-report-error', ['0x180074bc0: mov rcx, [rcx+70h]', '0x180074bcc: jmp qword ptr [rax+10h]']);
await game('game-caller-fourth-slot-retry', ['0x180077a99: mov rcx, [rdi+70h]', '0x180077ab1: call qword ptr [rax+40h]']);
await game('game-caller-zero-return', ['0x18000c9f0: retn 0']);
await game('game-caller-short-return-retry', ['0x18002cf80: xor eax, eax', '0x18002cf82: retn']);
await game('game-caller-last-slot', ['0x180074be0: mov eax, 0FFFFFFFFh']);
await game('game-primary-registry-initialize-retry', ['0x1800010ad: mov cs:qword_180938A98, rax',
  '0x1800010c7: mov cs:qword_180938AA8, rax', '0x1800010e4: mov cs:qword_180938AB8, rax',
  '0x18000112a: lea rcx, sub_1806B2A30']);
await game('game-primary-registry-lifetime', ["0x1806b2a46: lea rax, const NpcScriptMgr::`vftable'",
  '0x1806b2a86: call sub_1800790C0', '0x1806b2ab4: mov cs:qword_180938AA0, rsi']);
await game('game-caller-script-name-lookup', ['0x180075356: mov rdi, [rsi+18h]',
  '0x180075444: mov rax, [rdi+40h]', '0x180075448: mov [r14], rax']);
await game('game-quest-parser-analysis', ['0x18007585f: lea rdx, aQuests', '"quests"',
  '0x180075903: lea rdx, aQuest', '0x180075c46: call sub_1800761A0', '0x180075cb0: call sub_180079830']);
await instructions('20261012-script-interface', 'script-module-interface-export-instructions', scriptDigest, [
  '0x1806e21b0: mov cs:qword_18103F710, rcx', '0x1806e21b7: lea rax, off_180DAE450']);
await instructions('20261012-script-interface', 'script-interface-slot-00-instructions', scriptDigest, [
  '0x1806e04d0: mov eax, 28h']);
await instructions('20261012-script-descriptors', 'script-interface-maintenance-body', scriptDigest, [
  '0x1806e0500: mov rcx, cs:qword_18103F710', '0x1806e0507: mov rdx, [rbx+20h]',
  '0x1806e050e: call qword ptr [rax]']);
const caller = await read(session, 'original-game-script-caller-rtti.json');
assert.equal(caller.targetSha256, expected);
assert.equal(caller.typeName, '.?AVNpcScriptMgr@@');
assert.equal(source.readBigUInt64LE(Number.parseInt(caller.objectPointerFileOffset, 16)), 0x180772c60n);
for (const row of caller.functions) assert.equal(source.readBigUInt64LE(Number.parseInt(row.pointerFileOffset, 16)), BigInt(row.preferredVa));
const bySlot = new Map(caller.functions.map(row => [row.slotOffset, row.preferredVa]));
for (const slot of ['0x40', '0x48', '0x58']) assert.equal(bySlot.get(slot), '0x18002cf80');
assert.equal(bySlot.get('0x50'), '0x18000c9f0');
assert.equal(new Set(caller.functions.map(row => row.preferredVa)).size, 7);
const report = { passed: true, targetSha256: expected, scriptTargetSha256: scriptDigest,
  nativeTargetExecuted: false, wholeModuleComplete: false, verifiedAt: new Date().toISOString(), anchors,
  callerType: caller.typeName, callerSlots: caller.functions,
  interfaceVersionRequirement: '0x28',
  unknowns: ['Runtime resolution of protected module loading and named export lookup',
    'Actually loaded module identity and any patched runtime vtables', 'All parent-link consumers and complete NPC script behavior',
    'Current authoritative server damage calculation'] };
await writeFile(path.join(root, 'game-script-binding-verification.json'), JSON.stringify(report, null, 2));
console.log(JSON.stringify({ passed: true, instructionAnchors: anchors.length, callerSlots: caller.functions.length, uniqueCallerMethods: 7, modules: 2 }));
