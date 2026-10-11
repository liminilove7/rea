"""Verify a pinned public source archive against GitHub's Git tree, then extract it."""
from pathlib import Path, PurePosixPath
import hashlib, json, zipfile, shutil, datetime

commit='94fc8048e5fc198f000c0ca2176c65034c57cb39'
sources=Path(r'F:\RVE-Workspace\sources')
archive=sources/f'AionLightning-{commit}.zip'
tree_file=sources/'AionLightning-94fc8048-tree.json'
target=sources/'AionLightning-1.9-94fc8048'
backup=Path(__file__).parent/'aion-report-backup'/'server-reference'
backup.mkdir(parents=True,exist_ok=True)
tree=json.loads(tree_file.read_text(encoding='utf-8'))
assert tree['sha']=='d727d727cd9cbbfccbed5cddcefc577f58791ffd'
assert tree['truncated'] is False
expected={e['path']:e for e in tree['tree'] if e['type']=='blob'}
assert not [e for e in tree['tree'] if e['type']=='commit'], 'Unresolved submodule'
prefix=f'AionLightning-{commit}/'
verified=[]
with zipfile.ZipFile(archive) as z:
    names={n.filename[len(prefix):]:n for n in z.infolist() if not n.is_dir()}
    assert len(names)==len([n for n in z.infolist() if not n.is_dir()]), 'Duplicate member'
    assert set(names)==set(expected), 'Archive/tree file set mismatch'
    for path,entry in expected.items():
        pp=PurePosixPath(path)
        assert not pp.is_absolute() and '..' not in pp.parts and '\\' not in path
        assert names[path].filename==prefix+path
        data=z.read(names[path])
        observed=hashlib.sha1(b'blob '+str(len(data)).encode('ascii')+b'\0'+data).hexdigest()
        assert observed==entry['sha'], path
        verified.append({'path':path,'bytes':len(data),'git_blob_sha1':observed})
    print(f'Archive verified: {len(verified)} files.',flush=True)
    target.mkdir(exist_ok=True)
    for path,member in names.items():
        destination=target.joinpath(*PurePosixPath(path).parts)
        destination.parent.mkdir(parents=True,exist_ok=True)
        data=z.read(member)
        if destination.exists():
            assert destination.read_bytes()==data, f'Existing file differs: {path}'
        else:
            destination.write_bytes(data)
        assert destination.read_bytes()==data, f'Extracted file differs: {path}'
    print('Extraction complete.',flush=True)

active=[e for e in verified if '.svn' not in PurePosixPath(e['path']).parts]
key_patterns=['README.md','gameserver/config/default.config','commons/src/org/openaion/commons/utils/Rnd.java']
key_names=['RandomMoveLocEffect.java','StatFunctions.java','PlayerGameStats.java','CreatureGameStats.java','Stat.java','RateModifier.java','CM_ATTACK.java','CM_MOVE.java','SM_EMOTION.java','SM_STATS_INFO.java','EnchantService.java','GodStone.java','CreatureController.java','PlayerController.java','AttackUtil.java','SM_ATTACK.java']
key=[e for e in active if e['path'] in key_patterns or PurePosixPath(e['path']).name in key_names]
for e in key:
    src=target/e['path']; dst=backup/'key-sources'/e['path']
    dst.parent.mkdir(parents=True,exist_ok=True)
    shutil.copy2(src,dst)
    assert src.read_bytes()==dst.read_bytes()

payload={'repository':'https://github.com/ZON3DEV/AionLightning','branch':'1.9.0','commit':commit,'tree_sha':tree['sha'],'verified_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'archive_modified_at':datetime.datetime.fromtimestamp(archive.stat().st_mtime,datetime.timezone.utc).isoformat(),'source_directory':str(target),'archive_path':str(archive),'archive_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'archive_bytes':archive.stat().st_size,'git_blob_checks_passed':len(verified),'extracted_files_readback_verified':len(verified),'active_files_excluding_svn':len(active),'java_files_excluding_svn':sum(e['path'].endswith('.java') for e in active),'total_uncompressed_bytes':sum(e['bytes'] for e in verified),'files':verified,'key_sources_backed_up':key,'scope':'Complete pinned archive matches upstream Git blob identities; extracted files reread and matched. Extraction only: no build scripts, bundled libraries, or server processes executed. Emulator implementation; compatibility with current AION Classic client and official server rules unverified.','previous_saved_materials':{'repository':'liminilove7/rea','branch':'docs/aion19-pvp-study-20261010','commit':'82ef9e4c57fed2ce8592cfce567c50b8d29a1e24','directory':'aion1.9','contents':'Study reports, models and source file hashes. README explicitly states third-party server source was not uploaded in that commit.'}}
serialized=json.dumps(payload,ensure_ascii=False,indent=2)
for dest in [sources/'AionLightning-1.9-source-manifest.json',backup/'source-manifest.json',Path(__file__).parent/'aion19-source-manifest.json']:
    dest.write_text(serialized,encoding='utf-8')
for dest in [backup/'verify_aion19_source.py',sources/'verify_aion19_source.py']:
    shutil.copy2(Path(__file__),dest)
print(json.dumps({k:v for k,v in payload.items() if k not in ['files','key_sources_backed_up']},ensure_ascii=False,indent=2))
