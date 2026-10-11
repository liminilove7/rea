import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
const root = 'D:/RVE/.codex/local/aion-mechanics-report';
const local = 'D:/RVE/.codex/local';
fs.mkdirSync(root + '/evidence', { recursive: true });
const read = file => JSON.parse(fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, ''));
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const binary = local + '/aion-report-backup/binary';
const resources = read(binary + '/combat-resource-evidence.json');
const model = read(binary + '/aion19-server-model.json');
const attributes = read(binary + '/combat-attribute-table.json').entries;
const named = item => item.localized?.desc?.[0]?.body || item.raw.name;
const fields = ['id', 'name', 'quality', 'level', 'weapon_type', 'min_damage', 'max_damage', 'attack_delay', 'hit_accuracy', 'critical', 'parry', 'magical_skill_boost', 'magical_hit_accuracy', 'attack_range', 'bonus_attr1', 'bonus_attr2', 'bonus_attr3', 'bonus_attr4', 'bonus_attr5', 'bonus_attr6'];
const items = resources.speed_bonus_items.map(item => ({ ...Object.fromEntries([...new Set([...fields, ...Object.keys(item.raw).filter(k => k.startsWith('bonus_attr'))])].filter(k => item.raw[k] !== undefined).map(k => [k, item.raw[k]])), label: named(item), test: item.test_name_marker }));
const gods = resources.godstones.map(item => ({ id: item.raw.id, name: item.raw.name, label: named(item), p: Number(item.raw.proc_enchant_effect_occur_prob), left: item.raw.proc_enchant_effect_occur_left_prob === undefined ? null : Number(item.raw.proc_enchant_effect_occur_left_prob), skill: item.raw.proc_enchant_skill, description: item.localized?.desc_proc?.map(x => x.body).join(' / ') || '', test: item.test_name_marker }));
const source = 'F:/RVE-Workspace/sources/AionLightning-1.9-94fc8048/gameserver/src/org/openaion/gameserver/services/EnchantService.java';
const bytes = fs.readFileSync(source);
const sourceRelative = 'gameserver/src/org/openaion/gameserver/services/EnchantService.java';
const blob = crypto.createHash('sha1').update(Buffer.concat([Buffer.from('blob ' + bytes.length + '\0'), bytes])).digest('hex');
const manifest = read(local + '/aion19-source-manifest.json');
assert.equal(manifest.commit, model.emulator_commit);
assert.equal(manifest.files.find(x => x.path === sourceRelative).git_blob_sha1, blob);
const sourceText = bytes.toString('utf8');
const starts = [...sourceText.matchAll(/^\s*([A-Z0-9]+)\(\)\s*$/gm)];
const enchantStats = starts.map((match, i) => {
  const block = sourceText.slice(match.index, starts[i + 1]?.index ?? sourceText.length);
  return { name: match[1], line: sourceText.slice(0, match.index).split('\n').length, modifiers: [...block.matchAll(/StatEnum\.([A-Z_0-9]+),\s*(\d+)\s*\*\s*level,\s*false/g)].map(x => ({ stat: x[1], perLevel: Number(x[2]) })) };
});
assert.equal(enchantStats.find(x => x.name === 'DAGGER').modifiers.find(x => x.stat === 'MIN_DAMAGES').perLevel, 2);
assert.equal(enchantStats.find(x => x.name === 'DEF12').modifiers.find(x => x.stat === 'PHYSICAL_DEFENSE').perLevel, 6);
assert.ok(sourceText.includes('30 * (level-10)'));
const files = [
  [binary + '/aion19-server-model.json', 'server-model.json'],
  [binary + '/enchant-formula-evidence.json', 'enchant-client.json'],
  [binary + '/combat-attribute-table.json', 'attributes.json'],
  [binary + '/combat-resource-evidence.json', 'resources.json'],
  [binary + '/statup-bonus-evidence.json', 'item-encoding.json'],
  [local + '/AION_ANALYSIS.md', 'AION_ANALYSIS.md'],
  [local + '/rea-aion-round8/analysis-summary.json', 'rea-round8-summary.json'],
  [local + '/rea-aion-round8/verification.json', 'rea-round8-verification.json'],
  [local + '/rea-aion-round8/attack-consumer-5d2f7-insns.evidence.json', 'rea-attack-timer.json'],
  [local + '/rea-aion-round8/field-body-1804c1ee0.evidence.json', 'rea-movement.json'],
  [local + '/rea-aion-round8/session-cleanup.json', 'prior-session-cleanup.json'],
  [source, 'EnchantService.java']
];
files.push(
  [local + '/rea-aion-round9/REA_AION_ROUND9_20261011.md', 'REA_AION_ROUND9_20261011.md'],
  [local + '/rea-aion-round9/verification.json', 'rea-round9-verification.json'],
  [local + '/rea-aion-round9/skill-parser-insns.evidence.json', 'rea-counter-parser.json'],
  [local + '/rea-aion-round9/mask-180057930-insns.evidence.json', 'rea-direction-classifier.json'],
  [local + '/rea-aion-round9/last-0b5630-insns.evidence.json', 'rea-received-damage-text.json'],
  [local + '/rea-aion-round9/ready-check-0.evidence.json', 'rea-condition-skill-ui.json']
);
const copied = [];
for (const [from, to] of files) { const raw = fs.readFileSync(from); fs.writeFileSync(root + '/evidence/' + to, raw); copied.push({ file: to, sourcePath: from, sha256: hash(raw) }); }
const data = { date: '2026-10-11', sampleSha256: read(binary + '/enchant-formula-evidence.json').sha256, commit: model.emulator_commit, attributes, items, gods, weaponGroups: resources.weapon_groups.map(x => ({ type: x.weapon_type, records: x.records, testCount: x.test_name_marker_count, intervals: x.attack_delay_raw_distribution, ranges: x.attack_range_raw_distribution })), pvpSkills: resources.pvp_skills.filter(x => x.raw.pvp_damage_ratio !== undefined), counts: resources.counts, enchantStats, sourceAudit: { method: 'Auxiliary pinned-source reading; not new REA binary analysis.', path: sourceRelative, gitBlobSha1: blob, sha256: hash(bytes), verified: true }, evidence: copied };
data.cases = read(root + '/evidence/case-evidence.json');
assert.equal(data.cases.commit, data.commit);
fs.writeFileSync(root + '/evidence/report-data.json', JSON.stringify(data, null, 2));
let template = fs.readFileSync(root + '/report.template.html', 'utf8');
assert.equal(template.split('@@REPORT_DATA@@').length, 2);
template = template.replace('@@REPORT_DATA@@', JSON.stringify(data).replace(/</g, '\\u003c'));
template = template.replace('<a href="#scope"><b>01</b>', '<a href="#cases"><b>00</b>你的具体案例</a><a href="#scope"><b>01</b>');
template = template.replace('加入强化属性收益的固定源码核对，以及可直接操作的离线实验台。','加入塔爷强化、剑星对持盾角色和具体技能案例，以及可直接操作的离线实验台。');
template = template.replace('<section id="scope"', fs.readFileSync(root + '/case.fragment.html', 'utf8') + '\n<section id="scope"');
template = template.replace('<a href="#scope"><b>01</b>', '<a href="#round9"><b>续</b>REA 新证据</a><a href="#scope"><b>01</b>');
template = template.replace('<section id="scope"', fs.readFileSync(root + '/round9.fragment.html', 'utf8') + '\n<section id="scope"');
template = template.replace('</body>', '<script>' + fs.readFileSync(root + '/case-script.js', 'utf8') + '</script></body>');
fs.writeFileSync(root + '/AION机制分析报告.html', template);
console.log(JSON.stringify({ htmlBytes: Buffer.byteLength(template), equipmentEntries: items.length, godstones: gods.length, attributes: attributes.length, newSourceAudit: data.sourceAudit }));
