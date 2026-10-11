// Original PE data and byte candidates only; REA establishes instruction semantics.
import fs from 'node:fs';
import crypto from 'node:crypto';
const root = 'D:/RVE/.codex/local/rea-aion-round9';
const sample = 'F:/RVE-Workspace/cases/aionclassic2-2026-10-10/samples/Game.dll';
const bytes = fs.readFileSync(sample);
const sha256 = crypto.createHash('sha256').update(bytes).digest('hex');
if (sha256 !== '834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786') throw Error('Sample mismatch');
const pe = bytes.readUInt32LE(0x3c), optional = pe + 24;
const base = bytes.readBigUInt64LE(optional + 24);
const sectionsAt = optional + bytes.readUInt16LE(pe + 20);
const sections = Array.from({ length: bytes.readUInt16LE(pe + 6) }, (_, i) => {
  const p = sectionsAt + 40 * i;
  return { rva: bytes.readUInt32LE(p + 12), size: bytes.readUInt32LE(p + 16), offset: bytes.readUInt32LE(p + 20), flags: bytes.readUInt32LE(p + 36) };
});
const hex = v => '0x' + v.toString(16);
function offset(rva) {
  const section = sections.find(s => rva >= s.rva && rva < s.rva + s.size);
  if (!section) throw Error('Unbacked RVA ' + hex(rva));
  return section.offset + rva - section.rva;
}
function wide(va) {
  const p = offset(Number(va - base));
  let end = p;
  while (end + 2 <= bytes.length && bytes.readUInt16LE(end)) end += 2;
  return bytes.toString('utf16le', p, end);
}
const table = Array.from({ length: 6 }, (_, i) => {
  const rva = 0x846b50 + 16 * i, p = offset(rva);
  return { slotRva: hex(rva), text: wide(bytes.readBigUInt64LE(p)), value: bytes.readUInt32LE(p + 8) };
});
const registry = Array.from({ length: 3 }, (_, i) => {
  const rva = 0x937128 + 24 * i, p = offset(rva);
  return { slotRva: hex(rva), bytes: bytes.subarray(p, p + 24).toString('hex'), mask: hex(bytes.readBigUInt64LE(p)), otherQwords: [hex(bytes.readBigUInt64LE(p + 8)), hex(bytes.readBigUInt64LE(p + 16))] };
});
if (process.argv.includes('--parser')) {
  const instructions = JSON.parse(fs.readFileSync(root + '/skill-parser-insns.normalized.json', 'utf8')).instructions;
  const names = [];
  for (const instruction of instructions) {
    if (!/lea rdx, a[A-Za-z_0-9]+$/.test(instruction)) continue;
    const va = BigInt(instruction.split(':')[0]), p = offset(Number(va - base));
    if (bytes.subarray(p,p+3).toString('hex') !== '488d15') continue;
    const dataVa = va + 7n + BigInt(bytes.readInt32LE(p+3));
    names.push({ instruction, sourceBytes:bytes.subarray(p,p+7).toString('hex'), dataVa:hex(dataVa), text:wide(dataVa) });
  }
  fs.writeFileSync(root + '/supplementary-parser-literal-names.json', JSON.stringify({ source:'REA instruction locations joined with original PE operand/data bytes; supplementary string resolution, not a complete semantic parser inventory.', sha256, names },null,2));
  console.log(JSON.stringify({ resolvedLiteralLeaCount:names.length, pvp:names.filter(x=>/pvp/i.test(x.text)), counter:names.filter(x=>/counter_skill|chain_skill_prob|chain_time/.test(x.text)) }));
  process.exit(0);
}
const fields = process.argv.includes('--next') ? [0x19fc, 0x3bc] : [0x768, 0x7a0, 0x7a4, 0x7a8, 0x1a00, 0x1a04, 0x1a08, 0x1a0c, 0x1a10, 0x1a14, 0x1a18, 0x1a1c];
const candidates = [];
for (const field of fields) {
  const pattern = Buffer.alloc(4); pattern.writeUInt32LE(field);
  for (const section of sections.filter(s => (s.flags & 0x20000000) !== 0)) {
    const chunk = bytes.subarray(section.offset, section.offset + section.size);
    let p = -1;
    while ((p = chunk.indexOf(pattern, p + 1)) !== -1) candidates.push({ field: hex(field), va: hex(base + BigInt(section.rva + p)), rva: hex(section.rva + p), precedingBytes: chunk.subarray(Math.max(0, p - 10), p + 5).toString('hex') });
  }
}
const next = process.argv.includes('--next');
const stem = next ? 'next' : 'counter';
fs.writeFileSync(root + '/supplementary-' + stem + '-candidates.json', JSON.stringify({ source: 'Original PE data and byte search; supplementary, not REA instruction semantics.', sha256, sections, table, registry, fields, candidates }, null, 2));
fs.writeFileSync(root + '/jobs-resolve-' + (next ? 'next' : 'counters') + '.json', JSON.stringify(candidates.map((c, i) => ({ file: stem + '-candidate-' + i, name: 'procedure_address', arguments: { procedure: c.va } })), null, 2));
console.log(JSON.stringify({ table, registry, candidates: candidates.length, fields }));
