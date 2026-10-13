import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const study = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const root = path.join(study, 'evidence/continuous');
const session = '20261013-movement-action-speed';
const expected = '834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786';
const source = await readFile(path.join(study, 'samples/Game.dll'));
assert.equal(createHash('sha256').update(source).digest('hex'), expected);
const read = async file => JSON.parse(await readFile(path.join(root, session, file), 'utf8'));
const manifest = JSON.parse(await readFile(path.join(root, 'original-four-module-entries.json'), 'utf8'));
const meta = manifest.modules.find(row => row.sample === 'Game.dll');
function offset(rva, size) {
  const matches = meta.sections.filter(row => row.rva <= rva && rva + size <= row.rva + row.rawSize);
  assert.equal(matches.length, 1);
  return matches[0].fileOffset + rva - matches[0].rva;
}
const anchors = [];
async function instructions(file, snippets, directory = session, digest = expected) {
  const response = JSON.parse(await readFile(path.join(root, directory, file + '.mcp.json'), 'utf8'));
  assert.notEqual(response.result.isError, true);
  assert.equal(response.result.structuredContent.evidence.subject.digest.sha256, digest);
  const body = response.result.structuredContent.result.instructions.join('\n').toLowerCase();
  for (const snippet of snippets) assert.ok(body.includes(snippet.toLowerCase()), file + ': ' + snippet);
  anchors.push({ directory, file, targetSha256: digest, evidenceId: response.result.structuredContent.evidence_id, snippets });
}
await instructions('movement-speed-setter', ['0x18046046a: mulss xmm0, xmm6',
  '0x180460481: movss dword ptr [rcx+6CCh], xmm0', '0x180460489: movss dword ptr [rcx+38h], xmm6',
  '0x18046048e: movss dword ptr [rcx+6C8h], xmm6', '0x1804604b3: divss xmm0, xmm6',
  '0x1804604b7: movss dword ptr [rcx+6D0h], xmm0', '0x1804605ce: movss cs:dword_180D71CA0, xmm6']);
await instructions('animation-speed-ratio', ['0x1804bc5b9: movzx eax, word ptr [rbx+508h]',
  '0x1804bc5c9: movzx ecx, word ptr [rbx+50Ah]', '0x1804bc5ed: divss xmm6, xmm0',
  '0x1804bc733: mulss xmm6, dword ptr [rbx+4F4h]']);
await instructions('attack-action-time-gate', ['0x18006a0d2: call sub_18005D140',
  '0x18006a15e: movzx eax, cs:word_180D71BE0', '0x18006a165: add eax, [rsi+1C88h]',
  '0x18006a16b: cmp ebp, eax', '0x18006a16d: jbe loc_18006A358',
  '0x18006a1b1: call sub_18047CC70', '0x18006a350: mov [rsi+1C88h], ebp']);
await instructions('attack-time-adjustment-retry', ['0x18005d15d: mov r8d, [rbx+1C98h]',
  '0x18005d16c: cmp ecx, 1388h', '0x18005d1ac: movss dword ptr [rbx+1C94h], xmm0',
  '0x18005d348: movss dword ptr [rbx+1C94h], xmm0', '0x18005d35c: mov [rbx+1C88h], ecx']);
await instructions('movement-vector-limit', ['0x1804bbab2: mov rcx, [rbx+8]',
  '0x1804bbab9: call qword ptr [rax+178h]', '0x1804bbb3d: movss xmm3, dword ptr [rbx+6C8h]',
  '0x1804bbb52: minss xmm3, xmm1', '0x1804bbb56: divss xmm0, xmm1', '0x1804bbbad: call qword ptr [rax+20h]']);
await instructions('movement-vector-submit', ['0x1804befb4: mov rcx, [rbx+8]', '0x1804befcc: call qword ptr [rax+478h]']);
await instructions('player-action-dispatch', ['0x180061f98: mov eax, [rbx+14A8h]',
  '0x180061fa5: dec eax', '0x180061fc7: call sub_180042860', '0x180061fee: call sub_180046ED0']);
await instructions('player-normal-attack-action', ['0x180042869: mov eax, [rcx+14ACh]',
  '0x180042fee: mov rcx, rdi', '0x180042ff1: call sub_18006A0B0']);
await instructions('received-action-speed-sync', ['0x180430457: movss xmm9, dword ptr [r10+7]',
  '0x180430710: mov [rax+508h], bp', '0x180430717: mov [rax+50Ah], bx']);
await instructions('attack-event-time', ['0x18047cc2d: divss xmm6, xmm7']);
await instructions('attack-event-request-time-compose', ['0x18047ccb3: call sub_18047C940']);
const tableInstruction = offset(0x61fb8, 7);
assert.equal(source.subarray(tableInstruction, tableInstruction + 3).toString('hex'), '8b8c86');
const jumpTableRva = source.readInt32LE(tableInstruction + 3);
assert.equal(source.readUInt32LE(offset(jumpTableRva, 4)), 0x61fc4);
assert.equal(source.readUInt32LE(offset(jumpTableRva + 4, 4)), 0x61feb);
const tables = await read('original-speed-setter-vtables.json');
assert.equal(tables.targetSha256, expected);
const setterBindings = tables.functions.find(row => row.function === '0x180460440').bindings;
assert.ok(setterBindings.some(row => row.typeName === '.?AVPlayer@@' && row.slotOffset === '0x248'));
for (const row of setterBindings) assert.equal(source.readBigUInt64LE(Number.parseInt(row.pointerFileOffset, 16)), 0x180460440n);
const experiment = await read('offline-original-field-experiments.json');
assert.equal(experiment.targetSha256, expected);
assert.equal(experiment.afterSha256, expected);
assert.equal(experiment.nativeGameExecuted, false);
assert.equal(experiment.syntheticCpuInstructionsExecuted, true);
let checkedTraceInstructions = 0;
for (const trial of [...experiment.speedTrials, ...experiment.animationTrials, ...experiment.attackGateTrials]) {
  assert.equal(trial.instructionCount, trial.trace.length);
  for (const row of trial.trace) {
    const bytes = Buffer.from(row.bytes, 'hex');
    const raw = offset(Number.parseInt(row.rva, 16), bytes.length);
    assert.equal(source.subarray(raw, raw + bytes.length).toString('hex'), row.bytes);
    checkedTraceInstructions++;
  }
}
const speedNine = experiment.speedTrials.find(row => row.inputSpeed === 9).fieldsAfterOriginalSetterPrefix;
assert.equal(speedNine['0x6cc'], 81);
assert.ok(Math.abs(speedNine['0x6d0'] - 1 / 9) < 1e-8);
assert.deepEqual(experiment.animationTrials.map(row => row.resultMultiplier), [1, 2, 4, 1, 1]);
assert.deepEqual(experiment.attackGateTrials.map(row => row.localBranchPassed), [false, false, true, true, false]);
const entitySession = '20261013-entity-motion-interface';
const physicsSession = '20261013-physics-motion-interface';
const entityDigest = 'd99a60818f27bbe7f50ebef6e4ba6026b25b6d062b60db3ad3ae0eace22f4b90';
const physicsDigest = '7afd2f7080d8180888d47a790acb1e5ae31533ee260c6563e18661057cf7c38f';
await instructions('entity-motion-interface-slot', ['0x180017530: mov rax, [rcx+110h]',
  '0x18001753c: mov rax, [rcx+108h]'], entitySession, entityDigest);
await instructions('entity-direction-submit-slot', ['0x180007272: mov [rcx+518h], eax',
  '0x18000727b: mov [rcx+51Ch], eax', '0x180007284: mov [rcx+520h], eax'], entitySession, entityDigest);
await instructions('living-physical-status-slot', ['0x18006cad2: cmp eax, 2',
  '0x18006cdbe: movsd xmm0, qword ptr [rbx+178h]', '0x18006cdc6: movsd qword ptr [rdi+18h], xmm0',
  '0x18006cdd1: mov [rdi+20h], eax'], physicsSession, physicsDigest);
await instructions('living-physical-action-slot', ['0x18006d31e: cmp eax, 1',
  '0x18006d696: cmp eax, 3', '0x18006d6a1: movsd qword ptr [r14+178h], xmm0',
  '0x18006d6ae: mov [r14+180h], eax', '0x18006d7d2: mov dword ptr [r14+28Ch], 1'], physicsSession, physicsDigest);
const engineModules = new Map();
for (const [module, directory, digest, typeName, slots] of [
  ['CryEntitySystem.dll', entitySession, entityDigest, '.?AVCEntity@@', ['0x178', '0x478']],
  ['CryPhysics.dll', physicsSession, physicsDigest, '.?AVCLivingEntity@@', ['0x18', '0x20']],
]) {
  const bytes = await readFile(path.join(study, 'client/programs/aion-bin64/bin64', module));
  assert.equal(createHash('sha256').update(bytes).digest('hex'), digest);
  const tables = JSON.parse(await readFile(path.join(root, directory, 'original-entity-motion-vtables.json'), 'utf8'));
  assert.equal(tables.targetSha256, digest);
  const selected = tables.selectedTables.find(row => row.typeName === typeName && row.subobjectOffset === 0);
  assert.ok(selected);
  for (const slot of slots) {
    const row = selected.functions.find(row => row.slotOffset === slot);
    assert.equal(bytes.readBigUInt64LE(Number.parseInt(row.pointerFileOffset, 16)), BigInt(row.preferredVa));
  }
  engineModules.set(module, { bytes, sections: tables.sections });
}
engineModules.set('Game.dll', { bytes: source, sections: meta.sections });
const physicalExperiment = JSON.parse(await readFile(path.join(root, physicsSession, 'offline-move-vector-experiments.json'), 'utf8'));
assert.equal(physicalExperiment.nativeGameExecuted, false);
assert.equal(physicalExperiment.sourceDigests['Game.dll'], expected);
assert.equal(physicalExperiment.sourceDigests['CryPhysics.dll'], physicsDigest);
let checkedPhysicalInstructions = 0;
for (const trial of physicalExperiment.trials) {
  assert.equal(trial.requestType, 1);
  assert.equal(trial.requestMode, 3);
  assert.deepEqual(trial.requestVector, trial.livingEntityVector178_17c_180);
  for (const row of [...trial.gameTrace, ...trial.physicsTrace]) {
    const { bytes, sections } = engineModules.get(row.module);
    const rva = Number.parseInt(row.rva, 16);
    const length = row.bytes.length / 2;
    const matches = sections.filter(section => section.rva <= rva && rva + length <= section.rva + section.rawSize);
    assert.equal(matches.length, 1);
    const raw = matches[0].fileOffset + rva - matches[0].rva;
    assert.equal(bytes.subarray(raw, raw + length).toString('hex'), row.bytes);
    checkedPhysicalInstructions++;
  }
}
const report = { passed: true, targetSha256: expected, nativeGameExecuted: false, runtimeModificationVerified: false,
  verifiedAt: new Date().toISOString(), anchors, setterBindings, actionDispatch: { jumpTableRva: '0x' + jumpTableRva.toString(16),
    actionOneHandler: '0x180042860', actionTwoHandler: '0x180046ed0' },
  offlineExperiment: { speedTrials: experiment.speedTrials.length, animationTrials: experiment.animationTrials.length,
    gateTrials: experiment.attackGateTrials.length, checkedTraceInstructions,
    physicalVectorTrials: physicalExperiment.trials.length, checkedPhysicalInstructions },
  archivedEngineIdentities: { 'CryEntitySystem.dll': entityDigest, 'CryPhysics.dll': physicsDigest },
  unknowns: ['Runtime object/module addresses and any in-process patching', 'Final entity movement interfaces and coordinate integration',
    'Protected attack clock identity and units', 'Actual motion, request cadence and server acceptance after a change'] };
await writeFile(path.join(root, 'movement-action-speed-verification.json'), JSON.stringify(report, null, 2));
console.log(JSON.stringify({ passed: true, instructionAnchors: anchors.length, checkedTraceInstructions,
  checkedPhysicalInstructions, offlineTrials: experiment.speedTrials.length + experiment.animationTrials.length + experiment.attackGateTrials.length + physicalExperiment.trials.length }));
