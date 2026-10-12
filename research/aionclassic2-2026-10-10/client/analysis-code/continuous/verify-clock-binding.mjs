import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const study = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const root = path.join(study, 'evidence/continuous');
const expected = '8705aeef77411a28e178832f2f242128b0b018b9546f58878c9e69df8f4e9061';
const original = await readFile(path.join(study, 'samples/CrySystem.dll'));
assert.equal(createHash('sha256').update(original).digest('hex'), expected);
const anchors = [];
async function anchor(session, name, fragments) {
  const prefix = path.join(root, session, name);
  const normalized = JSON.parse(await readFile(prefix + '.normalized.json', 'utf8'));
  const response = JSON.parse(await readFile(prefix + '.mcp.json', 'utf8'));
  assert.notEqual(response.result.isError, true);
  assert.equal(response.result.structuredContent.evidence.subject.digest.sha256, expected);
  for (const fragment of fragments) assert.ok(normalized.instructions.some(line => line.includes(fragment)), `${name}: ${fragment}`);
  anchors.push({ session, name, evidenceId: response.result.structuredContent.evidence_id, fragments });
}
const bound = '20261012-cry-clock-bindings';
const timer = '20261012-cry-timer';
await anchor(bound, 'named-counter-error-producer-instructions', ['0x1800a07af: call sub_1806C6F75',
  '0x1800a07b5: test eax, eax', '0x1800a07b7: jz short loc_1800A07C9',
  '0x1800a07e4: lea rdx, aTimerQueryperf;']);
await anchor(bound, 'named-frequency-error-producer-instructions', ['0x1800a083a: call sub_1806BD0DA',
  '0x1800a0840: test eax, eax', '0x1800a0842: jz short loc_1800A0853',
  '0x1800a086e: lea rdx, aTimerQueryperf_0;']);
await anchor(timer, 'timer-frequency-initialization-instructions', ['0x18018a830: call sub_1806BD0DA',
  '0x18018a845: mov rax, [rsp+38h+arg_0]', '0x18018a84a: mov [rbx+20h], rax']);
await anchor(timer, 'timer-high-resolution-counter-instructions', ['0x18018b069: call sub_1806C6F75',
  '0x18018b06f: mov rax, [rsp+28h+arg_0]']);
await anchor(bound, 'timer-fallback-counter-retry-instructions', ['0x18018b084: call cs:qword_1801D0AB0',
  '0x18018b08a: mov eax, eax']);
const messages = JSON.parse(await readFile(path.join(root, bound, 'original-clock-error-messages.json'), 'utf8'));
assert.equal(messages.source_sha256, expected);
for (const message of messages.observations) {
  const offset = Number.parseInt(message.file_offset, 16);
  const end = original.indexOf(0, offset);
  assert.equal(original.subarray(offset, end).toString('ascii'), message.text);
}
const references = [
  { url: 'https://learn.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancefrequency', fact: 'Frequency output is counts per second.' },
  { url: 'https://learn.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancecounter', fact: 'Counter output is a 64-bit count.' },
];
await writeFile(path.join(root, 'clock-binding-verification.json'), JSON.stringify({ passed: true,
  targetSha256: expected, targetExecuted: false, analysisComplete: false, anchors, references,
  checks: ['CTimer and explicitly named failure branches call the same frequency and counter gateways',
    'Full diagnostic strings retain their original file locations and bytes',
    'Fallback counter remains an unresolved indirect pointer; no concrete API name assigned'],
  inference: 'Identifying the shared gateways as the named APIs yields seconds from counter delta divided by counts-per-second frequency.',
  limitations: ['The protected gateway final machine targets and actual game clock mode were not captured.',
    'Static binding and documented units do not establish current server timing or live wall-clock window length.']
}, null, 2));
console.log(JSON.stringify({ passed: true, anchoredResponses: anchors.length }));
