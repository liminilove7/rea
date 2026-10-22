"""Read-only, format-aware joins of current TW item/skill resources.

No target execution. No probability scale or server formula is assumed.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import re
from pathlib import Path
import xml.etree.ElementTree as ET


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def records(path, record_tag):
    for _, node in ET.iterparse(path, events=('end',)):
        if node.tag != record_tag:
            continue
        data = {}
        for child in node:
            if child.tag in data:
                raise ValueError(f'Unexpected duplicate field: {path}: {child.tag}')
            data[child.tag] = ({'xml': ET.tostring(child, encoding='unicode')}
                               if len(child) else child.text)
        yield data
        node.clear()


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--resources', type=Path, required=True)
    p.add_argument('--output', type=Path, default=Path(__file__).parent)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=True)
    paths = {}
    for filename in ('client_items.xml', 'client_skills.xml'):
        matches = list(a.resources.rglob(filename))
        if len(matches) != 1:
            raise ValueError(f'Expected one {filename}, got {len(matches)}')
        paths[filename] = matches[0]
    sources = {name: {'relative_path': str(path.relative_to(a.resources)).replace('\\', '/'),
                      'bytes': path.stat().st_size, 'sha256': digest(path)}
               for name, path in paths.items()}
    skill_by_name = defaultdict(list)
    skill_count = 0
    for ordinal, data in enumerate(records(paths['client_skills.xml'], 'skill_base_client'), 1):
        skill_count += 1
        skill_by_name[data.get('name')].append({'record_ordinal': ordinal, 'fields': data})
    candidates = []
    item_count = 0
    for ordinal, data in enumerate(records(paths['client_items.xml'], 'client_item'), 1):
        item_count += 1
        if not any(k.startswith('proc_enchant_') for k in data):
            continue
        matches = skill_by_name.get(data.get('proc_enchant_skill'), [])
        candidates.append({
            'item_record_ordinal': ordinal,
            'item': data,
            'join': {'field': 'proc_enchant_skill', 'target_field': 'name',
                     'comparison': 'exact case-sensitive source string',
                     'status': 'resolved' if len(matches) == 1 else 'missing' if not matches else 'ambiguous',
                     'skill_records': matches},
        })
    for name, path in paths.items():
        if digest(path) != sources[name]['sha256']:
            raise ValueError(f'Source changed while parsing: {path}')
    linked = {m['fields']['name']: m for c in candidates for m in c['join']['skill_records']}
    unique_skill_effects = Counter()
    for m in linked.values():
        unique_skill_effects.update(v for k, v in m['fields'].items()
                                    if re.fullmatch(r'effect\d+_type', k))
    left_present = [c for c in candidates if 'proc_enchant_effect_occur_left_prob' in c['item']]
    ratio_counts = Counter()
    for c in left_present:
        d = c['item']; main = int(d['proc_enchant_effect_occur_prob']); left = int(d['proc_enchant_effect_occur_left_prob'])
        ratio_counts['both_zero' if main == left == 0 else 'exact_half' if 2 * left == main
                     else 'same' if left == main else 'integer_floor_half' if left == main // 2 else 'other'] += 1
    summary = {
        'scope': 'Current AION TW archived decoded XML only; not the older aionclassic2 case',
        'target_executed': False, 'memory_accessed': False, 'sources': sources,
        'coverage': {'item_records_examined': item_count, 'skill_records_examined': skill_count,
                     'proc_enchant_candidates': len(candidates),
                     'join_status_counts': dict(Counter(c['join']['status'] for c in candidates)),
                     'distinct_skill_reference_names': len({c['item'].get('proc_enchant_skill') for c in candidates}),
                     'distinct_linked_skills': len(linked),
                     'test_named_candidates': sum(c['item'].get('name', '').startswith('test') for c in candidates),
                     'left_probability_present': len(left_present),
                     'left_probability_absent': len(candidates) - len(left_present)},
        'raw_probability_histogram': dict(Counter(c['item'].get('proc_enchant_effect_occur_prob', '<absent>') for c in candidates)),
        'raw_left_probability_histogram': dict(Counter(c['item'].get('proc_enchant_effect_occur_left_prob', '<absent>') for c in candidates)),
        'left_to_main_raw_relationships': dict(ratio_counts),
        'linked_skill_effect_type_counts': dict(unique_skill_effects),
        'linked_skill_activation_counts': dict(Counter(m['fields'].get('activation_attribute', '<absent>') for m in linked.values())),
        'item_skill_level_counts': dict(Counter(c['item'].get('proc_enchant_skill_level', '<absent>') for c in candidates)),
        'representative_links': [c for c in candidates if c['item'].get('id') in
                                 ('168000028', '168000035', '168000037', '168000041',
                                  '168000076', '168000077', '168000117', '168000119')],
        'missing_links': [{'item_id': c['item'].get('id'), 'item_name': c['item'].get('name'),
                           'skill_name': c['item'].get('proc_enchant_skill')} for c in candidates if c['join']['status'] != 'resolved'],
        'unknowns': ['Probability denominator and presentation scale are not established by these XML files.',
                     'Absent left probability is not equivalent to zero or a proven default.',
                     'Matching client declarations do not establish server RNG, eligible attack events, cooldowns, resistance, immunity, or PvP scaling.',
                     'Effect reserved fields and duration units retain raw names/values until consumers are verified.',
                     'Test-named rows and archived declarations do not prove currently obtainable/live-enabled items.'],
        'binary_search_seeds': ['proc_enchant_effect_occur_prob', 'proc_enchant_effect_occur_left_prob',
                                'proc_enchant_skill', 'proc_enchant_skill_level', 'ProcATK_Instant',
                                'effect1_noresist', 'effect1_acc_mod2', 'effect1_critical_prob_mod2'],
    }
    def save(name, value):
        (a.output / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    save('summary.json', summary)
    save('item-skill-joins.json', {'sources': sources, 'records': candidates})
    print(json.dumps({k: v for k, v in summary.items() if k != 'representative_links'}, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
