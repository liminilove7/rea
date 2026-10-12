import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const study = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const root = path.join(study, 'evidence/continuous');
const session = '20261012-aion-bootstrap';
const expected = '17c8de936526f119e16c1923ba5922d3a524698f04c01562fc878424653cda1e';
const source = await readFile(path.join(study, 'samples/Aion.bin'));
assert.equal(createHash('sha256').update(source).digest('hex'), expected);
const anchors = [];
async function instructions(file, snippets) {
  const response = JSON.parse(await readFile(path.join(root, session, file + '.mcp.json'), 'utf8'));
  assert.notEqual(response.result.isError, true);
  const evidence = response.result.structuredContent.evidence;
  assert.equal(evidence.subject.digest.sha256, expected);
  assert.equal(evidence.raw_result.metadata_before.imagebase, '0x140000000');
  const body = response.result.structuredContent.result.instructions.join('\n').toLowerCase();
  for (const snippet of snippets) assert.ok(body.includes(snippet.toLowerCase()), file + ': ' + snippet);
  anchors.push({ file, evidenceId: response.result.structuredContent.evidence_id, snippets });
}
await instructions('aion-original-bootstrap-entry-retry-instructions', [
  '0x1405ee000: jmp short loc_1405EE00A', '0x1405ee00a: jmp loc_1405F000F', '0x1405f000f: jmp sub_1405E2000']);
await instructions('aion-protection-bootstrap-next-instructions', ['0x1405e2003: call sub_1405E2009']);
await instructions('aion-protection-bootstrap-body-instructions', [
  '0x1405e2010: sub rax, 499000h', '0x1405e2016: sub rax, 7307BA8h',
  '0x1405e201c: add rax, 7307B9Fh', '0x1405e202a: mov ebx, 1000h',
  '0x1405e202f: push 6D21FE52h', '0x1405e2034: push 76145AC7h', '0x1405e2040: add rax, 14h']);
await instructions('aion-protection-bootstrap-page-transform-instructions', [
  '0x1405e205b: shr ecx, 2', '0x1405e2068: xor [rsi], eax', '0x1405e206a: add [rsi], ebx',
  '0x1405e206c: add rsi, 4', '0x1405e2070: dec ecx', '0x1405e2079: retn 20h']);
await instructions('aion-crysystem-loader-consumer-instructions', [
  '0x1400118c3: lea rcx, aCrysystemDll', 'CrySystem.dll', '0x1400118ca: call cs:qword_1400D3350',
  '0x1400119eb: lea rdx, aCreatesystemin', 'CreateSystemInterface', '0x1400119f5: call sub_140553F8A',
  '0x140011a21: call rax', '0x140011a23: mov cs:qword_140135920, rax',
  '0x140011b79: lea rax, aGameDll', 'Game.dll', '0x140011b80: mov [rsp+11E0h+var_1180], rax',
  '0x140011bb1: call qword ptr [rax]']);
const page = JSON.parse(await readFile(path.join(root, session, 'original-bootstrap-page-reproduction.json'), 'utf8'));
assert.equal(page.targetSha256, expected);
assert.equal(page.length, 4096);
assert.equal(page.targetRva, '0x149000');
assert.equal(page.continuationRva, '0x149014');
assert.equal(page.inverseRoundtripPassed, true);
assert.equal(page.binaryOutputWritten, false);
assert.equal(page.nativeTargetExecuted, false);
assert.equal(page.emulatedTargetInstructions, false);
const raw = source.subarray(Number.parseInt(page.targetFileOffset, 16), Number.parseInt(page.targetFileOffset, 16) + page.length);
assert.equal(createHash('sha256').update(raw).digest('hex'), page.originalPageSha256);
const transformed = Buffer.alloc(raw.length);
for (let position = 0; position < raw.length; position += 4) {
  const value = ((raw.readUInt32LE(position) ^ Number.parseInt(page.xorKey, 16)) + Number.parseInt(page.addKey, 16)) >>> 0;
  transformed.writeUInt32LE(value, position);
}
assert.equal(createHash('sha256').update(transformed).digest('hex'), page.transformedPageSha256);
const report = { passed: true, targetSha256: expected, nativeTargetExecuted: false, wholeModuleComplete: false,
  verifiedAt: new Date().toISOString(), anchors, originalPageReproduction: page,
  unknowns: ['Protected load/export lookup implementation and runtime resolved targets',
    'Actual loaded DLL file paths and runtime interface instance identity', 'Full protection reconstruction and complete original entry point'] };
await writeFile(path.join(root, 'bootstrap-verification.json'), JSON.stringify(report, null, 2));
console.log(JSON.stringify({ passed: true, instructionAnchors: anchors.length, reproducedPageBytes: page.length }));
