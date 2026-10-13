import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { access, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const study = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const root = path.join(study, 'evidence/continuous');
const expected = '834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786';
const original = await readFile(path.join(study, 'samples/Game.dll'));
assert.equal(createHash('sha256').update(original).digest('hex'), expected);
const anchors = [];
async function anchor(session, name, fragments) {
  const file = path.join(root, session, name);
  const result = JSON.parse(await readFile(file + '.normalized.json', 'utf8'));
  const response = JSON.parse(await readFile(file + '.mcp.json', 'utf8'));
  assert.notEqual(response.result.isError, true);
  assert.equal(response.result.structuredContent.evidence.subject.digest.sha256, expected);
  const lines = result.instructions;
  assert.ok(Array.isArray(lines));
  for (const fragment of fragments) assert.ok(lines.some(line => line.includes(fragment)), `${name}: ${fragment}`);
  anchors.push({ session, name, evidenceId: response.result.structuredContent.evidence_id, fragments });
  return lines;
}
const a = '20261012-session-a';
const b = '20261012-session-b';
await anchor(b, 'player-component-query-instructions', ['0x18001a4b0: cmp edx, 2',
  '0x18001a4b3: ja short loc_18001A4BB', '0x18001a4b5: mov [r8], rcx']);
await anchor(a, 'combat-result-handler-instructions', ['0x180430dc5: mov ecx, [rdx+0Eh]',
  '0x180430dd8: mov r15d, [rdx+8]', '0x180430df0: mov [rsp+3F20h+var_3EC0], ecx',
  '0x180431033: lea rax, [rsp+3F20h+var_3EC0]', '0x180431018: mov r9d, r15d',
  '0x18043106f: call qword ptr [r10+288h]']);
await anchor(a, 'combat-result-action-instructions', ['0x1804808c4: mov r12d, r9d',
  '0x18048092c: mov [rsi], r12d', '0x180480950: movups xmmword ptr [rsi+28h], xmm0',
  '0x180480b9e: lea rcx, [r14+1110h]']);
await anchor(a, 'counter-receive-a-instructions', ['0x1804730cf: mov edx, [rsi]',
  '0x18047312b: call sub_1804BF7A0', '0x1804735f7: lea r8, [rsi+28h]',
  '0x180473605: mov rdx, r12', '0x180473608: mov rcx, r13', '0x18047360b: call sub_180476770']);
await anchor(a, 'counter-state-source-instructions', ['0x18047679c: mov r14, r8',
  '0x1804767b5: mov rsi, rcx', '0x1804771c2: mov rcx, rsi',
  '0x1804771c5: call sub_1804BC8D0', '0x1804771ca: and dword ptr [r14], 0FFFFFE1Fh']);
await anchor(b, 'skill-target-result-queue-instructions', ['0x180481c2e: mov eax, [r14]',
  '0x180481c31: mov [rsi+8], eax', '0x180481c5a: movups xmm0, xmmword ptr [r14+34Ch]',
  '0x180481c62: movups xmmword ptr [r12], xmm0', '0x180481ee1: lea rcx, [r13+1128h]']);
await anchor(a, 'counter-receive-b-instructions', ['0x180473dbe: mov edx, [r14+8]',
  '0x180473e45: mov edx, 1', '0x180473e50: call qword ptr [r9+50h]',
  '0x1804744bf: lea r8, [r14+48h]', '0x1804744d9: mov rcx, r13', '0x1804744dc: call sub_180476770']);
await anchor(b, 'skill-success-record-consumer-instructions', ['0x1804818af: call sub_1804812F0',
  '0x1804818cb: movups xmmword ptr [rbp+1140h], xmm0']);
await anchor(b, 'skill-casting-tick-instructions', ['0x180047a69: call sub_1803503C0',
  '0x180047a7d: call sub_1804209E0', '0x180047aa6: call sub_18041FD80']);
await anchor(b, 'skill-packet-send-instructions', ['0x180420aaf: call sub_1804210E0',
  '0x180420abe: xor al, al']);
await anchor(b, 'skill-request-transport-instructions', ['"cannot start recording"',
  '0x18042118c: call sub_181251910', '0x1804211a1: call sub_181251910']);
await anchor(b, 'skill-request-fallback-send-instructions', ['0x18041fe50: call sub_1804477D0',
  '0x18041febe: call sub_1806A8642', '0x18041fec3: add [rbx+104B8h], edi']);
await anchor(b, 'socket-output-instructions', ['0x180447818: call qword ptr [rax+10h]',
  '0x18044781b: cmp eax, 0FFFFFFFFh', '0x180447820: movsxd rcx, eax',
  '0x180447823: sub ebx, eax', '0x180447825: add rdi, rcx']);
await anchor(b, 'skill-success-handler-instructions', ['0x1804319ff: call qword ptr [rax+2B8h]',
  '0x180431b26: call sub_1803B2500']);
await anchor(b, 'skill-state-success-local-instructions', ['0x180012753: call sub_180482530']);
await anchor(b, 'skill-state-success-base-instructions', ['0x1804826a4: xor edx, edx',
  '0x1804826a9: call qword ptr [rax+190h]', '0x1804826af: test r15b, 20h',
  '0x1804826b3: jz short loc_1804826C4', '0x1804826b8: mov edx, r12d',
  '0x1804826be: call qword ptr [rax+190h]']);
const writer = await anchor(b, 'chain-writer-body-1800570f0', ['[rcx+324h], edx',
  'call sub_181244AE3', '[rdi+328h], eax', 'call sub_1803B4680']);
assert.ok(writer.findIndex(line => line.includes('[rcx+324h], edx')) < writer.findIndex(line => line.includes('call sub_1803B4680')));
await anchor(a, 'combat-trigger-dispatch-instructions', ['0x1804a5b65: mov rax, [rbx];',
  '0x1804a5b68: add rdx, 58h', '0x1804a5b6f: call qword ptr [rax+260h]']);
await anchor(a, 'counter-generic-clear-instructions', ['0x180058cb7: jz loc_180058E9E',
  '0x180058e9e: mov eax, [rdx+4]', '0x180058ea1: not eax', '0x180058ea3: and [rbx+2ECh], eax']);
const tables = JSON.parse(await readFile(path.join(root, a, 'player-completion-vtable-original-pe.json'), 'utf8'));
// Confirm the specific originally observed pointer slots without assuming a full vtable extent.
assert.equal(original.readBigUInt64LE(0x841cd8 + 0x190), 0x1800570f0n);
assert.equal(original.readBigUInt64LE(0x841cd8 + 0x2b8), 0x180012720n);
assert.equal(original.readBigUInt64LE(0x841cd8 + 0x260), 0x180058ca0n);
assert.ok(tables);
const checkedReports = ['reports/AION持续分析.md', 'reports/AION对象身份与状态通知.md',
  'reports/AION脚本模块接口.md', 'reports/AION启动与模块装载.md', 'reports/AION移速动作与攻速修改研究.md', 'README.md', 'CONTINUE_TOMORROW.md'];
let checkedLocalLinks = 0;
for (const report of checkedReports) {
  const reportFile = path.join(study, report);
  const reportText = await readFile(reportFile, 'utf8');
  for (const match of reportText.matchAll(/\]\(([^)]+)\)/g)) {
    if (/^https?:/.test(match[1])) continue;
    await access(path.resolve(path.dirname(reportFile), match[1]));
    checkedLocalLinks++;
  }
}
await writeFile(path.join(root, 'call-flow-verification.json'), JSON.stringify({ passed: true,
  targetSha256: expected, targetExecuted: false, analysisComplete: false, anchors, checkedReports, checkedLocalLinks,
  checks: ['REA instruction anchors preserve target identity and the received-record object transfer',
    'Success notification branches distinguish reset, permitted chain update and cooldown',
    'Network output and local recording remain separate', 'Original Player slots and report evidence links verified'],
  limitations: ['Anchor checks are static evidence consistency checks, not game execution or server acceptance tests.',
    'No claim of exhaustive indirect call or field writer coverage.'] }, null, 2));
console.log(JSON.stringify({ passed: true, anchoredResponses: anchors.length }));
