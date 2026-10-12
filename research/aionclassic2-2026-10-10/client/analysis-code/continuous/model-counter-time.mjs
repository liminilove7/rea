import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const study = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const root = path.join(study, 'evidence/continuous');
const prefix = path.join(root, '20261012-session-a/state-owner-body-1804bca40');
const evidence = JSON.parse(await readFile(prefix + '.evidence.json', 'utf8'));
assert.equal(evidence.subject.digest.sha256, '834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786');
const instructions = JSON.parse(await readFile(prefix + '.normalized.json', 'utf8')).instructions;
for (const fragment of ['mulss xmm0, cs:dword_1808754A0', 'cvttss2si rax, xmm0',
  'sub edx, eax', 'jbe short loc_1804BCB1E', 'btr ecx, 7']) {
  assert.ok(instructions.some(line => line.includes(fragment)));
}
const initial = Math.trunc(Math.fround(Math.fround(3) * Math.fround(1000)));
const rows = [20, 60, 144].map(updatesPerSecond => {
  const suppliedSeconds = Math.fround(1 / updatesPerSecond);
  const scaledFloat = Math.fround(suppliedSeconds * Math.fround(1000));
  const integerDelta = Math.trunc(scaledFloat);
  assert.ok(integerDelta > 0);
  const requiredUpdates = Math.ceil(initial / integerDelta);
  return { hypotheticalUpdatesPerSecond: updatesPerSecond, suppliedSecondsFloat32: suppliedSeconds,
    scaledFloat32: scaledFloat, integerDelta, initialRemainder: initial, requiredUpdates,
    hypotheticalElapsedSeconds: requiredUpdates / updatesPerSecond };
});
assert.equal(rows[1].requiredUpdates, 188);
assert.equal(rows[2].requiredUpdates, 500);
await writeFile(path.join(root, 'counter-time-quantization-model.json'), JSON.stringify({
  kind: 'derived offline numerical illustration', targetExecuted: false, analysisComplete: false,
  sourceEvidenceId: evidence.evidence_id, rows,
  assumptions: ['Each update supplies the stated positive constant float32 duration.',
    'There is exactly one decrement per hypothetical update and no refresh or other reset.',
    'Duration is interpreted as seconds through the separately traced counter/frequency clock path.'],
  limitations: ['Actual game update cadence, smoothing, fixed step, refresh and server timing were not measured.',
    'These examples describe integer truncation; they are not observed gameplay window lengths.']
}, null, 2));
console.log(JSON.stringify({ rows }));
