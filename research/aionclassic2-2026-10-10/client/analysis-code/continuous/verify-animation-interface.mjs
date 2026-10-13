import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const study = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const evidence = path.join(study, 'evidence/continuous/20261013-animation-interface');
const read = async file => JSON.parse(await readFile(path.join(evidence, file), 'utf8'));
const selected = await read('rea-selected-animation-interface.json');
const tables = await read('original-character-vtables.json');
const trials = await read('offline-animation-setter-experiments.json');
const gateTrials = await read('offline-attack-cache-gate-experiments.json');
const digests = {
  'Game.dll': '834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786',
  'CryEntitySystem.dll': 'd99a60818f27bbe7f50ebef6e4ba6026b25b6d062b60db3ad3ae0eace22f4b90',
  'CryAnimation.dll': '32f492dc373e22aa43647546b888e0420044b84a7039a40dc99f6e91b5a637ac',
};
const binaries = new Map();
for (const [name, digest] of Object.entries(digests)) {
  const file = name === 'Game.dll' ? path.join(study, 'samples', name)
    : path.join(study, 'client/programs/aion-bin64/bin64', name);
  const bytes = await readFile(file);
  assert.equal(createHash('sha256').update(bytes).digest('hex'), digest);
  binaries.set(name, bytes);
}
assert.equal(selected.samples.game, digests['Game.dll']);
assert.equal(selected.samples.entity, digests['CryEntitySystem.dll']);
assert.equal(selected.samples.animation, digests['CryAnimation.dll']);
assert.equal(selected.nativeGameExecuted, false);
assert.equal(tables.targetSha256, digests['CryAnimation.dll']);
assert.equal(trials.targetSha256, digests['CryAnimation.dll']);
assert.equal(trials.afterSha256, trials.targetSha256);
assert.equal(trials.nativeGameExecuted, false);
assert.equal(gateTrials.targetSha256, digests['Game.dll']);
assert.equal(gateTrials.afterSha256, gateTrials.targetSha256);
assert.equal(gateTrials.nativeGameExecuted, false);

function has(lines, required) {
  const body = lines.join('\n').toLowerCase();
  for (const line of required) assert.ok(body.includes(line.toLowerCase()), line);
}
has(selected.game.windows.characterAcquisition, ['0x180493a85: call qword ptr [rax+580h]',
  '0x180493a93: call qword ptr [r8+20h]', '0x180493a97: mov rsi, rax']);
has(selected.game.windows.attackAnimationRate, ['0x1804941ba: call sub_1804BC390',
  '0x1804941c8: movaps xmm9, xmm0']);
has(selected.game.windows.animationSetter, ['0x180494607: movaps xmm2, xmm9',
  '0x180494611: call qword ptr [rax+360h]']);
const entity = selected.entity.map(row => row.instructions);
has(entity[0], ['0x180017302: lea rax, [rcx+0E8h]']);
has(entity[1], ['0x180023dee: mov rax, [rcx+rax*8+218h]']);
const animation = selected.animation.map(row => row.instructions);
has(animation[0], ['0x180054e10: movss dword ptr [rcx+328h], xmm2',
  '0x180054e18: mov rcx, [rcx+318h]', '0x180054e1f: jmp sub_1800B0AD0']);
has(animation[1], ['0x1800b0ae2: cmp edx, 10h', '0x1800b0aee: comiss xmm6, xmm0',
  '0x1800b0aff: comiss xmm0, xmm6', '0x1800b0b67: movss dword ptr [rcx+rdi*4], xmm6']);
const entityTables = JSON.parse(await readFile(path.join(study,
  'evidence/continuous/20261013-entity-motion-interface/original-entity-motion-vtables.json'), 'utf8'));
const entityMain = entityTables.selectedTables.find(row => row.typeName === '.?AVCEntity@@' && row.subobjectOffset === 0);
const entityCharacter = entityTables.selectedTables.find(row => row.typeName === '.?AVCEntity@@' && row.subobjectOffset === 232);
assert.ok(entityMain && entityCharacter);
function verifySlot(bytes, table, slot, expected) {
  const row = table.functions.find(entry => entry.slotOffset === slot);
  assert.ok(row, slot);
  assert.equal(row.preferredVa, expected);
  assert.equal(bytes.readBigUInt64LE(Number.parseInt(row.pointerFileOffset, 16)), BigInt(expected));
}
verifySlot(binaries.get('CryEntitySystem.dll'), entityMain, '0x580', '0x180017300');
verifySlot(binaries.get('CryEntitySystem.dll'), entityCharacter, '0x20', '0x180023de0');
const charMain = tables.selectedTables.find(row => row.typeName === '.?AVCryCharInstance@@' && row.subobjectOffset === 0);
assert.ok(charMain);
verifySlot(binaries.get('CryAnimation.dll'), charMain, '0x360', '0x180054e10');
function sectionsOf(bytes) {
  const pe = bytes.readUInt32LE(0x3c);
  const optional = pe + 24;
  const count = bytes.readUInt16LE(pe + 6);
  const sectionBase = optional + bytes.readUInt16LE(pe + 20);
  return Array.from({ length: count }, (_, i) => {
    const at = sectionBase + i * 40;
    return { rva: bytes.readUInt32LE(at + 12), size: bytes.readUInt32LE(at + 16),
      raw: bytes.readUInt32LE(at + 20) };
  });
}
let checkedBytes = 0;
for (const [name, experiment] of [['CryAnimation.dll', trials], ['Game.dll', gateTrials]]) {
  const bytes = binaries.get(name);
  const sections = sectionsOf(bytes);
  for (const trial of experiment.trials) {
    for (const row of trial.trace) {
      const rva = Number.parseInt(row.rva, 16);
      const size = row.bytes.length / 2;
      const matches = sections.filter(section => section.rva <= rva && rva + size <= section.rva + section.size);
      assert.equal(matches.length, 1);
      const raw = matches[0].raw + rva - matches[0].rva;
      assert.equal(bytes.subarray(raw, raw + size).toString('hex'), row.bytes);
      checkedBytes += size;
    }
  }
}
assert.deepEqual(trials.trials.map(row => [row.stop, row.instanceSpeedSlot, row.layerSpeedSlot]), [
  ['accepted-return', 2, 2], ['accepted-return', 0, 0], ['rejected-log', -1, 1],
  ['rejected-log', 1000000, 1], ['rejected-log', 2, 1]]);
assert.deepEqual(gateTrials.trials.map(row => row.result), [
  'rejected-local-comparison', 'passed-local-comparison',
  'rejected-local-comparison', 'passed-local-comparison']);
const report = { passed: true, nativeGameExecuted: false, runtimeModificationVerified: false,
  sourceDigests: digests, originalPointerBindings: 3, selectedReaProcedures: 6,
  offlineTrials: trials.trials.length + gateTrials.trials.length, checkedOriginalInstructionBytes: checkedBytes,
  unknowns: ['Actual runtime animation class and layer selected for a player attack',
    'Real animation playback, local attack request frequency and server acceptance'] };
await writeFile(path.join(study, 'evidence/continuous/animation-interface-verification.json'), JSON.stringify(report, null, 2));
console.log(JSON.stringify(report));
