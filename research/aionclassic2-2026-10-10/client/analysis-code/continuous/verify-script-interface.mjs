import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const study = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const root = path.join(study, 'evidence/continuous');
const session = '20261012-script-interface';
const expected = 'ea42f2e51de3d46b14e958f11c4f33dc9e78a92cf62765c6a42f0cb79584ca27';
const source = await readFile(path.join(study, 'samples/ScriptDLL64.dll'));
assert.equal(createHash('sha256').update(source).digest('hex'), expected);
const manifest = JSON.parse(await readFile(path.join(root, 'original-four-module-entries.json'), 'utf8'));
const meta = manifest.modules.find(row => row.sample === 'ScriptDLL64.dll');
assert.equal(meta.targetSha256, expected);
const base = BigInt(meta.imagebase);
function offset(rva, size) {
  const matches = meta.sections.filter(row => row.rva <= rva && rva + size <= row.rva + row.rawSize);
  assert.equal(matches.length, 1);
  return matches[0].fileOffset + rva - matches[0].rva;
}
const anchors = [];
async function instructions(file, snippets) {
  const response = JSON.parse(await readFile(path.join(root, session, file + '.mcp.json'), 'utf8'));
  assert.notEqual(response.result.isError, true);
  assert.equal(response.result.structuredContent.evidence.subject.digest.sha256, expected);
  const body = response.result.structuredContent.result.instructions.join('\n').toLowerCase();
  for (const snippet of snippets) assert.ok(body.includes(snippet.toLowerCase()), file + ': ' + snippet);
  anchors.push({ file, evidenceId: response.result.structuredContent.evidence_id, snippets });
}
await instructions('script-module-interface-export-instructions', [
  '0x1806e21b0: mov cs:qword_18103F710, rcx', '0x1806e21b7: lea rax, off_180DAE450']);
const read = async file => JSON.parse(await readFile(path.join(root, session, file), 'utf8'));
const rtti = await read('original-script-interface-rtti.json');
assert.equal(rtti.targetSha256, expected);
assert.equal(rtti.typeName, '.?AVIScriptDLLImpl@@');
assert.equal(source.readBigUInt64LE(Number.parseInt(rtti.returnedObjectFileOffset, 16)), BigInt(rtti.originalVtableVa));
const slotSnippets = {
  '00': '0x1806e04d0: mov eax, 28h',
  '08': '0x1806e0500: mov rcx, cs:qword_18103F710',
  '10': '0x1806e0660: lea rax, qword_18103F838',
  '18': '0x1806e0670: lea rax, qword_18103F860',
  '20': '0x1806e0680: lea rax, Buffer+104h',
  '28': '0x1806e0690: lea rax, qword_18103F890',
  '30': '0x1806e0637: jmp sub_180926E70',
  '38': '0x1806e0647: jmp sub_180929D90',
  '40': '0x1806e0657: jmp sub_180929D00',
  '48': '0x1806e06a0: lea rax, qword_18103F880',
};
assert.equal(rtti.functions.length, 10);
for (const row of rtti.functions) {
  const pointerOffset = Number.parseInt(row.pointerFileOffset, 16);
  assert.equal(source.readBigUInt64LE(pointerOffset), BigInt(row.preferredVa));
  assert.equal(pointerOffset, offset(Number(BigInt(rtti.originalVtableVa) - base) + Number.parseInt(row.slotOffset, 16), 8));
  const slot = Number.parseInt(row.slotOffset, 16).toString(16).padStart(2, '0');
  await instructions('script-interface-slot-' + slot + (slot === '48' ? '-retry' : '') + '-instructions', [slotSnippets[slot]]);
}
await instructions('script-interface-map-core-op-a-retry-instructions', ['event_quest.xml', '0x180926eb6: call sub_180926ED0']);
await instructions('compiled-magic-damage-script-registration-instructions', [
  '0x180172f7f: movups xmm0, xmmword ptr cs:aLdf4aMobMdamag', 'LDF4a_Mob_MDamage',
  "0x180172f86: lea rax, const CLDF4a_Mob_MDamage::`vftable'", '0x180172f99: mov cs:qword_180F70800, rax',
  '0x180172faf: mov cs:qword_180F708A8, rax', '0x180172fe5: call sub_1806BF3E0']);
await instructions('compiled-script-method-a-instructions', ['0x1806bf100: retn 0']);
await instructions('compiled-script-method-b-instructions', ['0x1806bf0f0: xor eax, eax', '0x1806bf0f2: retn']);
const binding = await read('original-magic-damage-script-binding.json');
assert.equal(binding.targetSha256, expected);
assert.equal(binding.typeName, '.?AVCLDF4a_Mob_MDamage@@');
const name = Buffer.from(binding.scriptName + '\0', 'utf16le');
assert.equal(source.subarray(offset(Number.parseInt(binding.nameRva, 16), name.length), offset(Number.parseInt(binding.nameRva, 16), name.length) + name.length).toString('hex'), name.toString('hex'));
const leaOffset = offset(Number.parseInt(binding.constructorLeaRva, 16), 7);
assert.equal(source.subarray(leaOffset, leaOffset + 7).toString('hex'), binding.constructorLeaBytes);
assert.equal(Number.parseInt(binding.constructorLeaRva, 16) + 7 + source.readInt32LE(leaOffset + 3), Number.parseInt(binding.vtableRva, 16));
for (const row of binding.functions) assert.equal(source.readBigUInt64LE(Number.parseInt(row.pointerFileOffset, 16)), BigInt(row.preferredVa));
const report = { passed: true, targetSha256: expected, nativeTargetExecuted: false, wholeModuleComplete: false,
  verifiedAt: new Date().toISOString(), anchors, interfaceType: rtti.typeName, interfaceSlots: rtti.functions,
  compiledScript: binding,
  unknowns: ['Actual runtime external caller identity and any patched implementation', 'All compiled script parent-link consumers',
    'Runtime initialization and all compiled script behavior', 'Current authoritative PvP/damage formula'],
  subsequentStaticBinding: 'Game.dll NpcScriptMgr caller and shared ScriptDLL CMonster initialization are checked separately in game-script-binding-verification.json and script-descriptors-verification.json' };
await writeFile(path.join(root, 'script-interface-verification.json'), JSON.stringify(report, null, 2));
console.log(JSON.stringify({ passed: true, instructionAnchors: anchors.length, interfaceSlots: rtti.functions.length, compiledScriptSlots: binding.functions.length }));
