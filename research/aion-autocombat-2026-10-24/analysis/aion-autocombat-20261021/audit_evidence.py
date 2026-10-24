"""Index saved REA results and verify selected instructions against the original PE bytes.

This helper is not a decompiler, a REA provider, or evidence of executing a game function.
"""
import collections
import hashlib
import html
import json
import math
import pathlib
import struct

CASE=pathlib.Path(__file__).resolve().parent
OLD=CASE.parent/'aion-tw-20261019'

class PE:
    def __init__(self,path):
        self.path=path; self.data=path.read_bytes(); pe=struct.unpack_from('<I',self.data,0x3c)[0]
        if self.data[pe:pe+4]!=b'PE\0\0': raise ValueError('Not PE')
        optsize=struct.unpack_from('<H',self.data,pe+20)[0]
        self.base=struct.unpack_from('<Q',self.data,pe+24+24)[0]
        self.sections=[]
        for i in range(struct.unpack_from('<H',self.data,pe+6)[0]):
            off=pe+24+optsize+40*i
            vs,va,rs,rp=struct.unpack_from('<4I',self.data,off+8)
            self.sections.append((va,rs,rp))
    def at(self,rva,n):
        for va,size,raw in self.sections:
            if va<=rva and rva+n<=va+size: return self.data[raw+rva-va:raw+rva-va+n]
        raise ValueError(f'RVA {rva:#x} not entirely backed by file')

def main():
    game=PE(OLD/'samples/Game.dll')
    capture=json.loads((CASE/'entity-inventory-05.json').read_text('utf-8'))
    enginepath=next(x['path'] for x in capture['modules'] if x['name'].lower()=='cryentitysystem.dll')
    engine=PE(pathlib.Path(enginepath))
    evidence=[]
    for stem in ['seed-1-insns','seed-1-pseudo','message-dispatch-insns','message-dispatch-pseudo',
                 'attack-interval-access-insns','attack-controller-insns','move-consumer-4-insns',
                 'move-consumer-4-pseudo','runtime-20261019/engine-static/entity-get-insns',
                 'runtime-20261019/engine-static/container-get-insns']:
        p=OLD/(stem+'.evidence.json'); d=json.loads(p.read_text('utf-8-sig'))['data']
        evidence.append(dict(file=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest(),
                             evidence_id=d['evidence_id'],operation=d['operation'],subject=d['subject']))
    checks=[]
    def check(name,got,expected,rva):
        checks.append(dict(name=name,rva=hex(rva),observed=got,expected=expected,passed=got==expected))
    for rva,dest in [(0x1455f6,0x16d600),(0x7e0473,0x8c7a70),(0x7e03b6,0x13c9d0),
                     (0x7df3b4,0x7e6aa0),(0x7e02aa,0x7f6280),(0x7e0519,0x7ea340),
                     (0x16d701,0x8592e0),(0x16d88e,0x7cfbf0)]:
        raw=game.at(rva,5);check('direct E8 opcode',raw[0],0xe8,rva)
        target=rva+5+struct.unpack_from('<i',raw,1)[0]
        check('direct call target',hex(target),hex(dest),rva)
    for rva,opcode,target in [(0x16d62d,'0fb715',0x142264a),(0x16d63f,'488b0d',0xf25c68),
                             (0x16d6c3,'0fb715',0x142264a)]:
        raw=game.at(rva,7); check('RIP instruction opcode',raw[:3].hex(),opcode,rva)
        check('RIP data location',hex(rva+7+struct.unpack_from('<i',raw,3)[0]),hex(target),rva)
    check('target identifier load',game.at(0x16d77f,3).hex(),'8b472c',0x16d77f)
    check('engine container getter',engine.at(0x19190,8).hex(),'488b8180030000c3',0x19190)
    getter='84d27513f7818001000008040000488d812c0600007507488d81ec050000c3cc'
    check('engine position getter bytes',engine.at(0x78d0,32).hex(),getter,0x78d0)
    check('CharacterObject component query for type 0/1',game.at(0x8972f0,21).hex(),
          '83fa01760a49c7000000000032c0c3498908b001c3',0x8972f0)
    check('Player component query for type 0/1/2',game.at(0x11c950,21).hex(),
          '83fa027706498908b001c349c7000000000032c0c3',0x11c950)
    check('Game module identity',hashlib.sha256(game.data).hexdigest(),
          'b3043f0eaf225b3dc7ba320ac7671cc5b28cefbd637135943dc9e67c114ccae7',0)
    check('engine module identity',hashlib.sha256(engine.data).hexdigest(),
          'fbca87e5a639551bf7653d464e2863c49800e73c124ae4666ea9fb11d40bef7a',0)
    if not all(x['passed'] for x in checks):
        (CASE/'static-byte-checks.json').write_text(json.dumps(checks,indent=2),encoding='utf-8')
        raise ValueError('Static byte check failed; report not promoted')
    actors=[x for x in capture['entities'] if 'position_candidate' in x]
    player=next(x for x in actors if x['local_handle_match'])
    origin=player['position_candidate']['xyz']; rows=[]
    for x in actors:
        if not x.get('binding_unchanged_during_read'): continue
        rows.append(dict(handle=x['handle'],entity=x['entity'],container=x['container'],
                         name_candidate=x['name_utf16_at_42_candidate'],type_code=x['container_type_dword_20'],
                         identifier_candidate=x['identifier_dword_2c_candidate'],
                         position_candidate=x['position_candidate']['xyz'],
                         euclidean_distance_candidate=math.dist(origin,x['position_candidate']['xyz']),
                         attack_target_handle_match=x['attack_target_handle_match'],local=x['local_handle_match']))
    rows.sort(key=lambda x:x['euclidean_distance_candidate'])
    result=dict(new_rea_requests=0,source='Saved REA IDA Evidence + auxiliary read-only Win32 capture + PE byte verification',
                capture_file='entity-inventory-05.json',capture_sha256=hashlib.sha256((CASE/'entity-inventory-05.json').read_bytes()).hexdigest(),
                static_checks=checks,evidence=evidence,nearby_character_candidates=rows,
                target_field=dict(rva='0x142264a',type='uint16',status='Used as entity handle in confirmed ordinary attack path; UI A/B confirmation pending'),
                outgoing_ordinary_attack=dict(rva='0x16d600',caller='0x144f10',send_call_rva='0x16d88e',send_function_rva='0x7cfbf0',
                                              note='Ordinary attack path, not a validated arbitrary skill entry'),
                incoming_skill=dict(dispatcher_rva='0x7de880',message_code=33,registration='aSUseSkill',consumer_rva='0x8c7a70',
                                    note='Received server message; not a proactive client skill-send entry'),
                unknowns=['Hostility/faction and live/dead filters','Current/max health and level fields',
                          'Proactive skill activation function, all arguments, owning thread and request timing',
                          'UI target switch A/B verification and display distance semantics'],
                provider_block=dict(action='Copy offline database and start IDA/RPC',reason='blocked by policy',retried=False))
    (CASE/'entity-skill-findings.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    jobs=[]
    for label,rva in [('target-info',0x13c9d0),('npc-put',0x7e6aa0),('npc-target-change',0x7f6280),
                      ('skill-receive',0x8c7a70),('skill-success-receive',0x7ea340),
                      ('skill-record-lookup',0x754f40),('attack-animation-caller',0x8393f0),('send-buffer',0x7cfbf0)]:
        for suffix,tool in [('pseudo','procedure_pseudo_code'),('insns','read_function_instructions'),('callers','procedure_callers')]:
            jobs.append(dict(file=f'{label}-{suffix}',name=tool,arguments=dict(procedure=hex(0x180000000+rva))))
    (CASE/'pending-rea-jobs.json').write_text(json.dumps(jobs,indent=2),encoding='utf-8')
    esc=lambda x:html.escape(str(x))
    target=next((x for x in rows if x['attack_target_handle_match']),None)
    tbl=''.join('<tr>'+''.join(f'<td>{esc(v)}</td>' for v in [x['handle'],x['name_candidate'] or '未解析',
                x['type_code'],x['container'],x['entity'],f"{x['euclidean_distance_candidate']:.2f}",
                '本角色' if x['local'] else ('目标候选' if x['attack_target_handle_match'] else '')])+'</tr>' for x in rows[:30])
    count=len(capture['entities']); types=collections.Counter(x.get('container_rtti',{}).get('decorated_name','unknown') for x in capture['entities'])
    text=f'''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>实体与技能调用链 · 证据进展</title><style>body{{background:#101826;color:#e5ecf8;font:16px/1.7 system-ui;margin:auto;padding:36px;max-width:1160px}}h1,h2{{color:#82d9d0}}code{{color:#ffcf83}}section{{padding:22px;background:#1b283c;border-radius:12px;margin:20px 0}}table{{border-collapse:collapse;width:100%;font-size:14px}}td,th{{padding:8px;border-bottom:1px solid #40506b;text-align:left}}a{{color:#93c9ff}}.flow{{display:flex;flex-wrap:wrap;gap:12px;align-items:center}}.box{{background:#263b52;padding:14px;border:1px solid #568c9d;border-radius:8px}}.warn{{color:#ffd194}}small{{color:#aabbd1}}</style>
<h1>周围实体与技能调用链</h1><p>2026-10-21 · 当前版本 Game.dll · 仅只读采样</p>
<section><h2>这一轮取得了什么</h2><p>本次捕获 {count} 个实体，包含 {types['.?AVCharacterObject@@']} 个 CharacterObject、{types['.?AVPlayer@@']} 个 Player。实体包含场景物件；CharacterObject 也不能直接等同于敌对怪物。</p>
<p>采样目标句柄候选：<code>{esc(target['handle'] if target else '无匹配')}</code>；名称候选：<b>{esc(target['name_candidate'] if target else '无匹配')}</b>。当前 B = <code>{esc(capture['tree']['game_base'])}</code>；本角色 C = <code>{esc(player['container'])}</code>。</p><p>较早的第 3 次采样中，目标句柄为 65528、名称候选“森林光蟲”、计算距离约 5.44；后续第 5 次采样目标字段为 0。此变化不是受控的用户 A/B 目标确认。</p>
<p>{len(checks)} 项原始 PE 字节/调用目标/文件哈希核对通过。新 REA 请求为 0；本节重新索引已保存的 REA Evidence，运行时读取属于辅助 Win32 工具。没有执行技能、内存写入或自动按键。</p></section>
<section><h2>基地址 → 实体 → 属性</h2><div class="flow"><div class="box">Game.dll 基址 B<br>*(B + F25C68)</div>→<div class="box">管理器 +58 → 树头<br>树头 +8 → 根节点</div>→<div class="box">节点 +20：16 位句柄<br>节点 +28：实体 E</div>→<div class="box">*(E +380) = C<br>C +42：名称候选<br>C +2C：标识候选</div></div>
<p>以上偏移为十六进制。节点左右指针 +0 / +10，nil 标志 +19。当前角色句柄读取 <code>B+1422648</code>；普通攻击目标句柄读取 <code>B+142264A</code>。后者由 REA 指令 <code>16D62D</code>、<code>16D6C3</code> 交叉确认，但还需手动切换目标核对 UI。</p><p>Player 的组件查询为 <code>+11C950</code>，CharacterObject 为 <code>+8972F0</code>；原始字节核对表明，两者对组件类型 0 都返回自身。因此攻击路径读取的组件 <code>+2C</code> 可以与此处的对象 C 对应，仍保留标识语义的验证边界。</p>
<p>坐标候选通过实体虚表 +8 的 getter 定位：本版 CryEntitySystem.dll RVA <code>78D0</code>，参数为真时返回 <code>E+5EC</code>。坐标差计算与已保存 REA <code>88BDE0</code> 消费路径吻合；表中距离为三维欧氏距离，不能先验等同于 UI 的取整、碰撞半径或攻击距离。</p></section>
<section><h2>附近角色类对象：按坐标距离排列</h2><p>仅展示前 30 个；完整记录见 JSON。类型码 2、名称和距离属于候选解释，尚未建立敌我、死亡与可攻击性过滤。</p><div style="overflow:auto"><table><tr><th>句柄</th><th>名称候选</th><th>类型码</th><th>对象 C</th><th>实体 E</th><th>距离候选</th><th>备注</th></tr>{tbl}</table></div></section>
<section><h2>释放动作：区分主动请求与收到通知</h2><div class="flow"><div class="box">本地普通攻击更新<br>Game +144F10</div>→<div class="box">普通攻击请求路径<br>Game +16D600<br>目标句柄 → C+2C<br>检查时间间隔</div>→<div class="box">发送缓冲区函数<br>Game +7CFBF0<br>调用点 +16D88E</div></div>
<p>上面是有指令证据的普通攻击请求链。它不是通用技能释放入口，也没有在本轮直接调用验证。</p>
<div class="flow"><div class="box">服务器使用技能消息<br>名称注册 aSUseSkill / 33</div>→<div class="box">消息分发 +7DE880<br>调用点 +7E0473</div>→<div class="box">收到技能后的消费者<br>Game +8C7A70</div></div>
<p>消息读取偏移 +0 的 32 位值和 +4 的 16 位值；后者还会进入技能记录查询 <code>+754F40</code>。在未追通字段定义前，只记为角色标识/技能标识候选。成功通知路径为 case 43 → <code>+7EA340</code>。不能把收到通知函数当作主动施法函数。</p></section>
<section><h2>仍待追通</h2><p class="warn">当前/最大生命、等级、敌我与死亡状态还未定位验证；主动技能函数的参数、所属线程和请求条件仍未知。只有这些链条闭合，才适合实现以对象状态驱动的自动战斗。</p>
<ol><li>手动选择 A → B → 取消，核对 +142264A、名称与距离。</li><li>REA 追 +13C9D0 的目标信息写入，+7E6AA0 的 NPC 创建与对象标识映射。</li><li>追 +8C7A70 / +7EA340 与技能表 +754F40；沿快捷栏动作调用者追到真正的主动施法路径。</li><li>通过手动施放技能做只读前后对照，确认冷却、技能编号与目标一致，再设计执行适配。</li></ol>
<p>此前“复制离线数据库并启动 IDA/RPC”的自动审批被拒，理由仅 <code>blocked by policy</code>。本轮没有改写命令重试；因此新函数的反编译仍待 REA→IDA 会话恢复。已生成 24 条只读待执行请求。</p></section>
<p><a href="entity-skill-findings.json">分析结果与证据索引</a> · <a href="entity-inventory-05.json">原始只读捕获</a> · <a href="pending-rea-jobs.json">下一轮 REA 请求</a></p>
<small>地址只属于本次 PID/模块/对象绑定。重新登录、对象重建或版本变化后必须重新定位。顺序读取不是游戏原子快照；树遍历完成也不意味着所有信息字段已解析。</small></html>'''
    (CASE/'实体与技能调用链进展.html').write_text(text,encoding='utf-8')
    print(json.dumps(dict(checks=len(checks),passed=True,character_candidates=len(rows),target=target,
                          report=str(CASE/'实体与技能调用链进展.html')),ensure_ascii=False))

if __name__=='__main__': main()
