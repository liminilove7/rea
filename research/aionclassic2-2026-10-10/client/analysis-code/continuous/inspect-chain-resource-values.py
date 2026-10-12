"""Inventory explicit chain fields without treating missing values as runtime observations."""
import hashlib
import json
import sys
from pathlib import Path
import xml.etree.ElementTree as ET

study = Path(__file__).resolve().parents[3]
source = study / 'client/resources/decoded-analysis-resources/Data/Skills/skills/client_skills.xml'
data = source.read_bytes()
root = ET.fromstring(data)
assert root.tag == 'skill_base_clients'
fields = ['id', 'name', 'counter_skill', 'chain_skill_prob1', 'chain_skill_prob2',
          'chain_time', 'chain_skill_name', 'chain_skill_priority']
records = []
for skill in root.findall('skill_base_client'):
    if skill.find('chain_skill_prob1') is None and skill.find('chain_skill_prob2') is None:
        continue
    records.append({field: skill.findtext(field) for field in fields})
result = {
    'source': str(source.relative_to(study)),
    'sourceSha256': hashlib.sha256(data).hexdigest(),
    'totalSkillRecords': len(root.findall('skill_base_client')),
    'recordsWithExplicitProbabilityField': len(records),
    'recordsWithExplicitProb1': sum(row['chain_skill_prob1'] is not None for row in records),
    'records': records,
    'targetExecuted': False,
    'limitations': ['Null means missing XML field; it is not a sampled runtime value.',
                   'Resource values do not establish authoritative server probabilities.'],
}
output = study / 'evidence/continuous/20261012-chain-value/chain-probability-resource-fields.json'
if '--check' in sys.argv[1:]:
    assert json.loads(output.read_text(encoding='utf-8')) == result
else:
    with output.open('x', encoding='utf-8', newline='\n') as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2)
print(json.dumps({key: result[key] for key in ['totalSkillRecords',
    'recordsWithExplicitProbabilityField', 'recordsWithExplicitProb1']}))
