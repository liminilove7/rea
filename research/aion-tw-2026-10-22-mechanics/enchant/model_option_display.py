"""Derive display columns for the observed option probability path; no availability claim."""
from pathlib import Path
import json,struct
OUT=Path(__file__).resolve().parent
f32=lambda x:struct.unpack('<f',struct.pack('<f',x))[0]
resource=json.loads((OUT/'enchant-current-evidence.json').read_text(encoding='utf8'))
rows=[]
for r in resource['option_matrix']:
    raw=[int(x) for x in r['raw_probabilities']]
    rows.append(dict(quality=r['quality'],resource_levels=[int(x) for x in r['levels']],caller_a3_for_match=[int(x)-1 for x in r['levels']],prob_raw=raw,display_percent_no_supplement=[f32(f32(x)*f32(.1)) for x in raw],sub_matter_count_raw=r['sub_matter_counts']))
names=['enchant-option-parser','enchant-option-formula','enchant-option-formula-insns','enchant-option-display','enchant-option-display-insns']
ev={n:json.loads((OUT.parent/'binary-evidence'/(n+'.evidence.json')).read_text(encoding='utf8'))['evidence_id'] for n in names}
data=dict(scope='current TW CLIENT option probability display; resource table plus current native parser/consumer/display evidence',target_sha256='b3043f0eaf225b3dc7ba320ac7671cc5b28cefbd637135943dc9e67c114ccae7',evidence=ev,formula='lookup quality, then level == a3+1 among six entries; missing match gives base=0; result=clamp(base+uint16(supplementRecord+0x19A),0,1000); displayed percent=float32(float32(result)*float32(0.1))',format='%g%%',matrix=rows,limitations=['Matrix assumes matching quality and a3=level-1, with supplement raw 0; not all cells are proven reachable.','a3 comes from caller-selected slot/count helper branches; ordinary +enhancement level is not established.','Zero cells are literal data; this helper adds supplement after a zero/missing match, but UI or server eligibility is separate.','sub_matter_count is parsed but not read by this probability function; count unit and payment logic remain separate.','Ordinary enhancer coefficient formula is separate and is not replaced by this matrix.','These are client display values; server probability, RNG and result checks remain unverified.'])
(OUT/'option-display-model.json').write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf8')
print(json.dumps(rows))
