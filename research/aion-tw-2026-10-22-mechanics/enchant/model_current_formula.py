"""Offline arithmetic model of current REA-observed CLIENT display formula, not server RNG."""
from pathlib import Path
import json,struct
OUT=Path(__file__).resolve().parent
K={1:60,2:40,3:30,4:20,5:15,6:10}
QUALITY={'junk':0,'common':1,'rare':2,'legend':3,'unique':4,'epic':5,'mythic':6,'divinity':7}
f32=lambda x:struct.unpack('<f',struct.pack('<f',x))[0]
def model(q,L,S,n,A):
    if not (0<=q<=255 and 0<=L<=255 and 0<=S<=255 and 1<=n<=256 and 0<=A<=65535):
        raise ValueError('Outside decoded argument field width scope')
    if n<=20 and q not in K:return 0
    if n>20:base=0
    else:
        product=K[q]*(S-L+10)
        raw=product if n<=10 else (abs(product)//2)*(1 if product>=0 else -1)
        base=max(0,min(800 if n<=10 else 500,raw))
    return max(0,min(1000,base+A))
resource=json.loads((OUT/'enchant-current-evidence.json').read_text(encoding='utf8'))
index={r['id']:r for r in resource['stone_id_range']+resource['representative_equipment']+resource['supplements']}
assert index['100000831']['level']=='55' and index['100000831']['quality']=='unique'
assert index['166100005']['sub_enchant_material_effect']=='150'
samples=[]
for S,n,A in [(55,1,0),(75,10,0),(85,10,0),(85,10,150),(85,11,0),(85,11,150),(105,11,150)]:
    assert index[str(166000000+S)]['level']==str(S)
    raw=model(4,55,S,n,A)
    samples.append(dict(target=dict(id='100000831',name='sword_n_u1_r_55a',quality='unique',quality_code=4,level=55),stone=dict(id=str(166000000+S),name=f'matter_enchant_{S}',level=S),next_stage=n,supplement=dict(id='166100005',name='sub_matter_u_15',raw=150) if A else None,raw_result=raw,client_display_numeric_float32=f32(f32(raw)*f32(.1)),classification='offline model, no runtime or server observation'))
edge=[]
for q,L,S,n,A in [(4,55,55,21,150),(7,55,55,10,150),(7,55,55,21,150),(5,55,44,11,150),(4,55,190,10,65535),(4,55,1,10,0)]:
    edge.append(dict(q=q,L=L,S=S,n=n,A=A,raw_result=model(q,L,S,n,A),online_reachability='unknown; these model branches are not an availability claim'))
evidence={name:json.loads((OUT.parent/'binary-evidence'/(file+'.evidence.json')).read_text(encoding='utf8'))['evidence_id'] for name,file in [('formula','enchant-formula-candidate-a'),('instructions','enchant-formula-insns'),('quality','quality-enum'),('display','enchant-prob-display'),('display_instructions','enchant-prob-display-insns'),('mode','enchant-mode')]}
out=dict(scope='current TW client numeric probability display only; no server equivalence',target_sha256='b3043f0eaf225b3dc7ba320ac7671cc5b28cefbd637135943dc9e67c114ccae7',evidence=evidence,quality_mapping=QUALITY,unknown_quality_label_fallback=1,coefficients=K,display_format='%g%%',display_numeric_unit='percent',examples=samples,edge_cases=edge)
(OUT/'current-formula-model.json').write_text(json.dumps(out,ensure_ascii=False,indent=2),encoding='utf8')
print(json.dumps(dict(examples=samples,edge_cases=edge),ensure_ascii=False))
