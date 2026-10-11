import fs from 'node:fs';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
const root = 'D:/RVE/.codex/local/rea-aion-round9';
const digest = '834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786';
const read = file => JSON.parse(fs.readFileSync(root + '/' + file, 'utf8').replace(/^\uFEFF/, ''));
const checks = [];
function instruction(file, text) {
  assert.ok(read(file + '.normalized.json').instructions.includes(text), file + ': ' + text);
  checks.push({ file, text, evidenceId: read(file + '.evidence.json').data.evidence_id });
}
for (const [file, lines] of [
  ['skill-parser-insns', ['0x18053f7c6: call sub_18053C1B0', '0x18053f7cb: mov [rbp+1D50h+var_15F8], rax', '0x18053fd92: mov [rbp+1D50h+var_15C0], eax', '0x18053fdc2: mov [rbp+1D50h+var_15BC], eax', '0x18053fdf2: mov [rbp+1D50h+var_15B8], eax', '0x18053c7bf: lea rcx, [rbp+1D50h+var_1D60]', '0x18053c7c6: mov r8d, 7D8h']],
  ['mask-180057930-insns', ['0x18005793f: and eax, 0C0h', '0x180057947: cmp al, 0C0h', '0x180057954: mov dword ptr [rcx+19FCh], 1', '0x180057a2a: cmp edx, 0Fh', '0x180057a2d: jg loc_180057A44', '0x180057a44: cmp edx, 2Dh', '0x180057a47: mov eax, 2', '0x180057a4c: mov ecx, 4', '0x180057a51: cmovl eax, ecx', '0x180057a54: mov [rbx+19FCh], eax']],
  ['counter-body-180068810', ['0x180068831: sub eax, [rdi+1A04h]', '0x180068837: cmp eax, 566h', '0x18006883c: cmovb ebx, ecx', '0x180068849: sub edx, [rdi+1A0Ch]', '0x18006884f: cmp edx, 2CCh', '0x180068855: jbe loc_180068864']],
  ['attack-action-insns', ['0x180480d03: lea rcx, [rcx+34h]', '0x180480d07: or ebp, eax', '0x180480d2d: shr ebp, 4', '0x180480d6c: and edi, 1', '0x180480e6c: and edi, 6', '0x180480e71: mov [rsi+1A18h], edi', '0x180480e7d: mov [rsi+1A1Ch], eax']],
  ['check-368e50-insns', ['0x18036922d: call sub_180068810']],
  ['last-0b5630-insns', ['0x1800b5dc5: mov rax, [rcx+10h]', '0x1800b5dc9: mov r15d, [rax]', '0x1800b5fca: mov r8d, [rax]', '0x1800b5fcd: call sub_18006C750']],
  ['attack-received-insns', ['0x180430e70: mov eax, [rdx]', '0x180430e72: mov [r9-24h], eax']],
  ['ready-check-0', ['0x18028028b: call sub_18039D5D0', '0x180280298: lea rdx, aV4SkillSlotCon']],
]) for (const line of lines) instruction(file, line);
const raw = fs.readFileSync('F:/RVE-Workspace/cases/aionclassic2-2026-10-10/samples/Game.dll');
assert.equal(crypto.createHash('sha256').update(raw).digest('hex'), digest);
const supplementary = read('supplementary-next-candidates.json');
const parserNames = read('supplementary-parser-literal-names.json');
assert.equal(parserNames.names.find(x => x.instruction === '0x18053fd9d: lea rdx, aChainSkillProb').text, 'chain_skill_prob1');
assert.equal(parserNames.names.find(x => x.instruction === '0x18053fdcd: lea rdx, aChainSkillProb_0').text, 'chain_skill_prob2');
assert.deepEqual(supplementary.table.map(x => [x.text, x.value]), [['1',480],['all',480],['dodge',128],['parry',64],['block',32],['resist',256]]);
assert.deepEqual(supplementary.registry.map(x => x.mask), ['0x80','0x40','0x20']);
// Finite examples of the observed time-mask read; units are deliberately unnamed.
function mask(now, previous, previousAt, current, currentAt) {
  let value = previous && ((now - previousAt) >>> 0) < 1382 ? previous : 0;
  if (current && ((now - currentAt) >>> 0) > 716) value |= current;
  return value;
}
const cases = [
  [716,0,0,2,0,0], [717,0,0,2,0,2], [1381,4,0,0,0,4], [1382,4,0,0,0,0],
  [1000,4,0,2,0,6], [5,0,0,2,0xfffffff0,0], [0x300,0,0,2,0xfffffff0,2],
];
for (const [n,p,pt,c,ct,expected] of cases) assert.equal(mask(n,p,pt,c,ct), expected);
const directionCases = [[15,1],[16,4],[44,4],[45,2],[60,2]];
for (const [d,expected] of directionCases) assert.equal(d <= 15 ? 1 : d < 45 ? 4 : 2, expected);
const evidenceFiles = fs.readdirSync(root).filter(f => f.endsWith('.evidence.json'));
for (const file of evidenceFiles) {
  const data = read(file).data;
  assert.equal(data.subject.digest.sha256, digest);
  assert.equal(data.provider.id, 'ida');
}
const batches = fs.readdirSync(root).filter(f => /^batch-jobs-.*\.json$/.test(f)).map(file => ({file, ...read(file)}));
const requests = batches.flatMap(b => b.results);
const instructions = fs.readdirSync(root).filter(f => f.endsWith('.normalized.json')).flatMap(file => {
  const data = read(file); return data?.instructions ? [{ file, procedure: data.procedure.address, instructionCount: data.instructions.length }] : [];
});
const summary = {
  date: '2026-10-11', primaryWorkflow: 'REA 6.1.0 MCP -> IDA offline database', sampleSha256: digest,
  targetExecuted: false, requests: requests.length, success: requests.filter(x => !x.isError && !x.error).length,
  failed: requests.filter(x => x.isError || x.error), evidenceFiles: evidenceFiles.length,
  distinctInstructionEntrypoints: new Set(instructions.map(x => x.procedure)).size,
  checks, timeBoundaryExamples: cases, directionClassifierExamples: directionCases,
  supplementaryTable: supplementary.table, supplementaryRegistry: supplementary.registry,
  parserLiteralLocations: parserNames.names.length,
  findings: [
    {type:'observed', subject:'counter_skill name parser and record', rva:'0x53c1b0', field:'+0x768', boundary:'Original PE table lower-case block=32; capitalized XML value normalization is not established here.'},
    {type:'observed', subject:'direction-related classifier feeds time-mask state', writerRva:'0x57930', readerRva:'0x68810', boundary:'Not established as a shield-counter skill eligibility window; timing units unknown.'},
    {type:'observed', subject:'received hit numeric value reaches combat text formatter', chain:['0x430d20','0x0b5630','0x54f6f0'], boundary:'This display path does not establish the official backend PVP formula.'},
  ],
  unknowns: ['Current official backend calculations and RNG','Counter skill readiness and authoritative cast validation','PVP multiplier execution consumer','RandomMoveLoc reserved3 direction execution','Protected timing API and units','Complete unpacking and semantic coverage'],
  limitations: ['IDA adapter read_bytes unsupported; original PE data are supplementary','Empty search_strings results do not establish absence of UTF16 strings','Provider full function-body ranges unavailable','Current database patches/revision unknown; input hash alone does not prove pristine database'],
};
fs.writeFileSync(root + '/verification.json', JSON.stringify(summary,null,2));
console.log(JSON.stringify({ requests:summary.requests, success:summary.success, failed:summary.failed.length, evidenceFiles:summary.evidenceFiles, distinctInstructionEntrypoints:summary.distinctInstructionEntrypoints, instructionChecks:checks.length, examples:cases.length+directionCases.length }));
