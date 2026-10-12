"""Collect source/resource facts before any fresh IDA analysis; no target execution."""
from pathlib import Path
import collections
import hashlib
import json
import xml.etree.ElementTree as ET

root = Path(__file__).resolve().parents[3]
resources = root / 'client/resources/decoded-analysis-resources'
skills_path = resources / 'Data/Skills/skills/client_skills.xml'
strings_path = resources / 'L10N/CHS/Data/Data/Strings/client_strings_skill.xml'
source = root / 'server/reference-source/AionLightning-94fc8048/gameserver'
server_skills_path = source / 'data/static_data/skills/skill_templates.xml'
binary = root / 'samples/Game.dll'
expected = '834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786'
assert hashlib.sha256(binary.read_bytes()).hexdigest() == expected
strings = {e.findtext('name'): e.findtext('body') for e in ET.parse(strings_path).getroot()}
server_skills = {e.get('skill_id'): e for e in ET.parse(server_skills_path).getroot()}
counter_skills = []
for e in ET.parse(skills_path).getroot():
    counter = e.findtext('counter_skill')
    if counter is None:
        continue
    fields = {key: e.findtext(key) for key in ('id', 'name', 'desc', 'counter_skill',
              'chain_time', 'chain_skill_prob1', 'chain_skill_prob2', 'required_leftweapon',
              'chain_category_name', 'chain_category_level', 'delay_time')}
    fields['localized_name'] = strings.get(fields['desc'])
    server = server_skills.get(fields['id'])
    fields['reference_server_template'] = dict(server.attrib) if server is not None else None
    fields['reference_server_startconditions'] = (ET.tostring(server.find('startconditions'), encoding='unicode')
        if server is not None and server.find('startconditions') is not None else None)
    counter_skills.append(fields)

terms = ('counter_skill', 'chain_skill_prob1', 'chain_skill_prob2')
suffixes = {'.java', '.xml', '.xsd', '.properties'}
hits = {term: [] for term in terms}
scanned = 0
for path in source.rglob('*'):
    if not path.is_file() or path.suffix not in suffixes:
        continue
    scanned += 1
    text = path.read_text(encoding='utf8', errors='replace')
    for term in terms:
        if term in text:
            hits[term].append(str(path.relative_to(source)))
identities = []
for path in [skills_path, strings_path, server_skills_path,
             source / 'src/org/openaion/gameserver/skill/model/Skill.java',
             source / 'src/org/openaion/gameserver/network/aion/serverpackets/SM_ATTACK.java']:
    identities.append({'path': str(path.relative_to(root)), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
report = {'date': '2026-10-12', 'stage': 'resource-and-reference-source-crosscheck',
    'fresh_ida_analysis': False, 'target_executed': False, 'game_dll_sha256': expected,
    'upstream_server_commit': '94fc8048e5fc198f000c0ca2176c65034c57cb39',
    'input_identities': identities, 'counter_skill_count': len(counter_skills),
    'counter_type_counts': dict(collections.Counter(s['counter_skill'] for s in counter_skills)),
    'counter_skills': counter_skills,
    'reference_source_search': {'extensions': sorted(suffixes), 'files_scanned': scanned, 'literal_hits': hits},
    'observations': [
        'The reference template for skill154 has chain_skill_prob=10; the current client has counter_skill=Block and chain_skill_prob2=10.',
        'Reference Skill.java consumes chain_skill_prob after effect processing to choose chainSuccess.',
        'Reference SM_ATTACK.java emits a counter mask from the first attack result only.',
    ],
    'unknowns': ['Current client Block/block comparison semantics',
        'Current client +0x7A8 execution consumer and authoritative server meaning',
        'Current client counter readiness consumption/reset chain',
        'Current official PVP settlement formula; fixed reference source is not that backend'],
}
output = root / 'evidence/round10/resource-crosscheck.json'
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf8')
print(json.dumps({'counter_skill_count': len(counter_skills), 'counter_type_counts': report['counter_type_counts'],
    'reference_files_scanned': scanned, 'reference_term_hit_counts': {term: len(paths) for term, paths in hits.items()},
    'fresh_ida_analysis': False}))
